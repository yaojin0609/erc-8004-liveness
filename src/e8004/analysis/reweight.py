"""按 host 规模做事后分层回权（post-stratification）。

【为什么必须回权】
探测有单 host 上限 2,000：同一 host 强制 1 请求/3 秒串行，不设上限要 182 小时。
上限只削掉 14 个最大的 host（占全部 host 的 0.4%），但那 14 个持有 163,230 个
端点里的 111,843 个 —— **68% 的端点来自被抽样的 host**。

于是「已探测样本」被小 host 主导：evoevo.ai 有 36,413 个端点却只探了 2,000 个，
而某个只有 3 个端点的 host 全探了。直接拿
    L3 存活率 = 已探测里握手成功的 / 已探测总数
就等于把「一个端点的小 host」和「三万六千个端点的大 host」按相同权重平均，
而后者恰恰是少数运营商批量注册的产物 —— 两类的存活率没有理由相同。

【怎么回权】
把 host 当分层：在每个 host 内部，被探测的端点是该 host 全部端点的随机样本
（固定种子抽样），所以该 host 的存活率 p_h 可以无偏估计。再按该 host 的
真实端点数 N_h 加权求和：

    存活端点估计 = Σ_h N_h · p_h        （Σ_h N_h = 端点全集）

没被抽样的 host（占 99.6%）p_h 是全数观测，权重自然为 1，不引入额外方差。

【报告必须两个都给】
- 原始「占已探测」：不做任何外推，只描述样本本身，绝对可靠但不可外推
- 回权估计：对全集的估计，附上被抽样 host 的占比，读者自己判断可信度
不许只给一个。
"""

from __future__ import annotations

from decimal import Decimal

# 分层统计：每个 host 的端点总数、被探测数、各层通过数
_STRATA_SQL = """
WITH universe AS (
    -- 端点全集：漏斗认定「声明了可路由端点」的那批
    SELECT s.endpoint_host AS host,
           count(*)        AS n_total
    FROM service s
    WHERE s.is_routable AND s.endpoint_host IS NOT NULL
    GROUP BY 1
),
probed AS (
    -- 实际探到的端点，按层取该端点是否通过
    SELECT sv.endpoint_host                                   AS host,
           p.chain_id, p.agent_id, p.service_idx,
           max(CASE WHEN p.layer = 'dns'   AND p.outcome = 'ok' THEN 1 ELSE 0 END) AS dns_ok,
           max(CASE WHEN p.layer = 'tcp'   AND p.outcome = 'ok' THEN 1 ELSE 0 END) AS tcp_ok,
           max(CASE WHEN p.layer = 'http'  AND p.outcome = 'ok' THEN 1 ELSE 0 END) AS http_ok,
           max(CASE WHEN p.layer = 'proto' AND p.outcome = 'ok' THEN 1 ELSE 0 END) AS proto_ok
    FROM probe_attempt p
    JOIN service sv
      ON sv.chain_id = p.chain_id AND sv.agent_id = p.agent_id
     AND sv.service_idx = p.service_idx
    WHERE p.probe_round = ?
    GROUP BY 1, 2, 3, 4
)
SELECT u.host,
       u.n_total,
       count(pr.host)      AS n_probed,
       sum(pr.dns_ok)      AS dns_ok,
       sum(pr.tcp_ok)      AS tcp_ok,
       sum(pr.http_ok)     AS http_ok,
       sum(pr.proto_ok)    AS proto_ok
FROM universe u
LEFT JOIN probed pr ON pr.host = u.host
GROUP BY 1, 2
"""

LAYERS = ("dns_ok", "tcp_ok", "http_ok", "proto_ok")


def strata(conn, probe_round: int = 1) -> list[dict]:
    rows = conn.execute(_STRATA_SQL, [probe_round]).fetchall()
    cols = [d[0] for d in conn.description]
    return [dict(zip(cols, r)) for r in rows]


def reweight(conn, probe_round: int = 1) -> dict:
    """→ 每层的「原始样本比例」与「按 host 规模回权后的全集估计」。

    只对**探测过的 host** 做外推。一个 host 一个端点都没探到时，
    它的存活率无从估计 —— 那部分单独计入 `unprobed_endpoints`，
    绝不按整体均值填充（那等于凭空造数据）。
    """
    st = strata(conn, probe_round)
    covered = [s for s in st if (s["n_probed"] or 0) > 0]

    n_universe = sum(s["n_total"] for s in st)
    n_covered = sum(s["n_total"] for s in covered)
    n_probed = sum(s["n_probed"] or 0 for s in covered)
    n_sampled_hosts = sum(1 for s in covered if (s["n_probed"] or 0) < s["n_total"])

    out: dict = {
        "probe_round": probe_round,
        "endpoints_universe": n_universe,
        "endpoints_in_covered_hosts": n_covered,
        "endpoints_probed": n_probed,
        "endpoints_unprobed": n_universe - n_probed,
        "hosts_total": len(st),
        "hosts_covered": len(covered),
        "hosts_subsampled": n_sampled_hosts,
        "layers": {},
    }
    for layer in LAYERS:
        ok = sum(s[layer] or 0 for s in covered)
        # 原始：只描述样本，不外推
        raw = Decimal(ok) / Decimal(n_probed) if n_probed else Decimal(0)
        # 回权：Σ N_h · p_h，分母是【被覆盖 host 的端点全集】
        est = Decimal(0)
        for s in covered:
            p = Decimal(s[layer] or 0) / Decimal(s["n_probed"])
            est += Decimal(s["n_total"]) * p
        share = est / Decimal(n_covered) if n_covered else Decimal(0)
        out["layers"][layer] = {
            "ok_in_sample": ok,
            "raw_share": raw,
            "weighted_endpoints": est,
            "weighted_share": share,
        }
    return out


def host_pass_distribution(conn, probe_round: int = 1, min_probed: int = 5,
                           n_buckets: int = 10) -> dict:
    """每个 host 的协议层通过率分布。

    实测形态是**双峰**：host 要么几乎全通，要么几乎全不通，中间很空。
    这说明「能不能握手」基本是 host（= 运营商）的属性，而不是单个 agent 的属性 ——
    同一个 host 下成千上万个 agent 的探测结果高度一致，彼此几乎不提供额外信息。

    `min_probed` 过滤掉只探到零星几个端点的 host：3 个里通过 1 个算 33%，
    那是噪声不是形态。被过滤掉的 host 端点数很少，不影响结论，但会让
    分布图干净很多。过滤阈值必须在报告里写明。
    """
    st = [s for s in strata(conn, probe_round) if (s["n_probed"] or 0) >= min_probed]
    buckets = [{"lo": i / n_buckets, "hi": (i + 1) / n_buckets, "hosts": 0, "endpoints": 0}
               for i in range(n_buckets)]
    for s in st:
        p = float(s["proto_ok"] or 0) / s["n_probed"]
        idx = min(int(p * n_buckets), n_buckets - 1)
        buckets[idx]["hosts"] += 1
        buckets[idx]["endpoints"] += s["n_total"]

    n_hosts = sum(b["hosts"] for b in buckets)
    n_end = sum(b["endpoints"] for b in buckets)
    lo_b, hi_b = buckets[0], buckets[-1]
    extreme_hosts = lo_b["hosts"] + hi_b["hosts"]
    extreme_end = lo_b["endpoints"] + hi_b["endpoints"]
    return {
        "min_probed": min_probed,
        "hosts_considered": n_hosts,
        "endpoints_considered": n_end,
        "buckets": buckets,
        "extreme_hosts": extreme_hosts,
        "extreme_endpoints": extreme_end,
        "extreme_host_share": (extreme_hosts / n_hosts) if n_hosts else 0.0,
        "extreme_endpoint_share": (extreme_end / n_end) if n_end else 0.0,
        "near_zero_hosts": lo_b["hosts"],
        "near_zero_endpoints": lo_b["endpoints"],
        "near_full_hosts": hi_b["hosts"],
        "near_full_endpoints": hi_b["endpoints"],
    }


def largest_hosts(conn, probe_round: int = 1, limit: int = 12) -> list[dict]:
    """按端点规模排序的 host 及其通过率 —— 双峰形态最直观的证据。"""
    st = [s for s in strata(conn, probe_round) if (s["n_probed"] or 0) > 0]
    for s in st:
        s["proto_rate"] = Decimal(s["proto_ok"] or 0) / Decimal(s["n_probed"])
        s["sample_frac"] = Decimal(s["n_probed"]) / Decimal(s["n_total"])
    return sorted(st, key=lambda s: -s["n_total"])[:limit]


def top_subsampled_hosts(conn, probe_round: int = 1, limit: int = 10) -> list[dict]:
    """被抽样最狠的 host —— 回权结论对它们最敏感，报告里要点名。"""
    st = [s for s in strata(conn, probe_round) if (s["n_probed"] or 0) > 0]
    sub = [s for s in st if s["n_probed"] < s["n_total"]]
    for s in sub:
        s["sample_frac"] = Decimal(s["n_probed"]) / Decimal(s["n_total"])
        s["proto_rate"] = Decimal(s["proto_ok"] or 0) / Decimal(s["n_probed"])
    return sorted(sub, key=lambda s: -s["n_total"])[:limit]
