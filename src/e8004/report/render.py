"""T12 —— 报告渲染。

【表述纪律，代码层面强制】(CLAUDE.md 硬约束 17)
本模块的模板文案【不得出现】「假的」「僵尸」「9 成是」这类表述。
只输出「L3 存活率 X%」「其中 Y% 自我声明为不活跃」这类中性描述。
注册但无活性的合理原因必须在方法论章节显式列出。

模块底部有一个 FORBIDDEN_PHRASES 自检，单元测试会对渲染结果跑一遍。
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from ..stages.s08_funnel import LAYER_LABELS, cohort_table

FORBIDDEN_PHRASES = ("假的", "僵尸", "九成是", "9 成是", "全是骗子", "空气", "骗局")

# `other` 一档里各 error_detail 的性质。区分「对方的问题」和「我们自己的限制」，
# 前者才是关于 agent 存活的证据，后者只是本次扫描没测到。
_ERROR_NATURE = {
    "HostBlocked": "**本扫描器限速放弃**，非对方失败",
    "ConnectError": "对方 host 拒绝连接",
    "ReadError": "连接中断",
    "InvalidURL": "URI 本身不合法",
    "bad_cid": "IPFS CID 不合法",
}

METHODOLOGY = """
## 方法论与口径

### 口径定义

- **口径 A（链上注册数）**：各链 IdentityRegistry 上已铸造的 agent 总数。
  通过对 `ownerOf(agentId)` 做二分查找得到（agentId 从 0 顺序递增），
  等价于累计 mint 数，不去重、不排除已销毁。
- **口径 B（唯一主体数）**：按 agent card 的 `registrations[]` 双向声明跨链归并后的数量。

两套口径并列报告。各家公开数字互相矛盾的主要原因就是口径不同，
所以本报告不主张某一个数字「正确」，只主张自己的口径是明确的。

### 快照锚点

所有数字锚定在下表的区块高度上。三个月后用同一个 scanner 复跑可以精确对比。

### 「注册但无活性」的合理原因

以下情形都会表现为「链上有注册但探测不通」，它们**不等于**该注册无效：

1. 开发者试注册、测试用途
2. 早期占位，项目尚未上线
3. 服务临时下线或迁移
4. agent card 中 `active: false`，即**主动声明**当前不提供服务
5. 端点指向内网/本机地址，本就不面向公网

其中第 4、5 类在漏斗中**单独成支**，不计入「协议层握手失败」。

### 探测伦理

- 全局限速 ≤10 req/s，单一 host ≤1 请求/3 秒且最多 1 条并发连接，另有 per-IP 限速
- 只读探测：仅 GET / OPTIONS / MCP `initialize` / `tools/list`
- User-Agent 中标明研究用途并留联系邮箱；提供退出扫描名单
- 遇 429/503 退避并将该 host 移出本轮；每个端点每轮最多 2 次尝试

### 已知局限

"""


def _pct(n, d) -> str:
    return f"{100.0 * (n or 0) / max(1, d):.2f}%"


_LAYER_CN = {"dns_ok": "L3a DNS 可解析", "tcp_ok": "L3b TCP/TLS 可建连",
             "http_ok": "L3c HTTP 有响应", "proto_ok": "L3 协议层握手成功"}


_STABLE_CN = {"round1_ok": "第 1 轮通过", "round2_ok": "第 2 轮通过",
              "stable_ok": "**两轮均通过（L3-stable）**"}


def _render_stability(conn) -> str:
    """两轮对照：把「那一刻恰好在线」和「稳定可达」分开。

    这是整份报告里最该看的一张表 —— 单轮通过率无法排除临时故障，
    只有同一端点相隔 ≥48h 两次都通过才叫稳定。
    """
    from ..analysis.reweight import reweight_stable

    try:
        r = reweight_stable(conn)
    except Exception:  # noqa: BLE001
        return ""
    if not r["endpoints_probed"] or not r["layers"]["round2_ok"]["ok_in_sample"]:
        return ""

    o = ["\n### 四之二之二、两轮对照：稳定可达 vs 那一刻在线\n"]
    o.append("| 口径 | 样本内通过 | 占已探测 | 回权后估计 | 估计端点数 |")
    o.append("|---|---:|---:|---:|---:|")
    for k, label in _STABLE_CN.items():
        d = r["layers"][k]
        o.append(f"| {label} | {d['ok_in_sample']:,} | {100*float(d['raw_share']):.2f}% | "
                 f"{100*float(d['weighted_share']):.2f}% | {float(d['weighted_endpoints']):,.0f} |")
    o.append("")
    o.append(
        f"**持续率 {100*float(r['persistence']):.1f}%** —— 第 1 轮通过的端点里，"
        f"相隔 ≥48 小时后仍有这么多在第 2 轮通过。"
        "两轮的通过数几乎相同**且是同一批端点**（按端点逐个求交集，不是比较两轮的总数），"
        "说明端点的可达性是一个**稳定的二分状态**，而不是时通时不通。\n"
    )
    o.append(
        "> 这条对整份报告的可信度是关键的：单轮结果无法区分「服务稳定运行」与"
        "「探测那一刻恰好在线」。持续率接近 100% 意味着本快照的 L3 结论"
        "不是某个时刻的偶然采样。反过来说，它也意味着**未通过的端点同样稳定地未通过**，"
        "但这仍然不能推断原因（未上线 / 迁移 / 暂停 / 已下线），见下节。\n"
    )
    return "\n".join(o)


def _render_bimodal(conn, probe_round: int = 1) -> str:
    """存活率在 host 之间的分布形态。

    文案纪律（CLAUDE.md 硬约束 17）：只描述观察到的形态和它的统计含义，
    不推断动机、不给任何 host 或 agent 贴标签。「端点未响应」的原因可以是
    项目未上线、服务迁移、主动下线 —— 探测区分不了，报告就不许替读者断言。
    """
    from ..analysis.reweight import host_pass_distribution, largest_hosts

    try:
        d = host_pass_distribution(conn, probe_round)
        big = largest_hosts(conn, probe_round, limit=12)
    except Exception:  # noqa: BLE001
        return ""
    if not d["hosts_considered"] or not big:
        return ""

    o = ["\n### 四之三、存活率在 host 之间呈双峰分布\n"]
    o.append(
        f"把每个 host 的协议层通过率单独算出来（只统计本轮探到 ≥{d['min_probed']} 个端点的 "
        f"{d['hosts_considered']:,} 个 host，覆盖 {d['endpoints_considered']:,} 个端点），"
        "分布不是集中在中间，而是**压在两端**：\n"
    )
    peak = max(b["hosts"] for b in d["buckets"]) or 1
    o.append("| 该 host 的通过率 | host 数 | 覆盖端点数 | |")
    o.append("|---|---:|---:|---|")
    for b in d["buckets"]:
        bar = "█" * max(0, round(28 * b["hosts"] / peak))
        o.append(f"| {int(b['lo']*100)}–{int(b['hi']*100)}% | {b['hosts']:,} | "
                 f"{b['endpoints']:,} | `{bar}` |")
    o.append("")
    o.append(
        f"**{d['extreme_hosts']:,} 个 host（{100*d['extreme_host_share']:.1f}%）落在最两端的两档，"
        f"它们覆盖了 {100*d['extreme_endpoint_share']:.1f}% 的端点。**"
        f"其中通过率 ≥90% 的有 {d['near_full_hosts']:,} 个（{d['near_full_endpoints']:,} 个端点），"
        f"≤10% 的有 {d['near_zero_hosts']:,} 个（{d['near_zero_endpoints']:,} 个端点）。\n"
    )
    o.append("规模最大的 host 更能看出这个形态：\n")
    o.append("| host | 端点数 | 已探测 | 该 host 通过率 |")
    o.append("|---|---:|---:|---:|")
    for h in big:
        o.append(f"| `{h['host']}` | {h['n_total']:,} | {h['n_probed']:,} | "
                 f"{100*float(h['proto_rate']):.1f}% |")
    o.append("")
    o.append(
        "**这意味着「某个 agent 是否可握手」几乎不是该 agent 的独立属性，而是它所在 host 的属性。**"
        "同一个 host 下成千上万个身份的探测结果高度一致，彼此几乎不提供额外信息 —— "
        "所以「有多少身份可握手」这个问题，在数量级上等价于"
        "「哪些运营商的服务在快照时刻可达，以及各自注册了多少身份」。\n"
    )
    o.append(
        "> 需要与端点主机集中度一并读：端点在 host 上高度集中（见集中度一节），"
        "而 host 的通过率又是双峰的，两者叠加意味着**总体存活率对少数几个 host 的可达性极其敏感**。"
        "单次快照无法区分「服务已下线」与「项目尚未上线 / 正在迁移 / 主动暂停」，"
        "本报告不对任何 host 或身份作此推断；区分这些需要在不同时间点复跑同一个扫描器。\n"
    )
    return "\n".join(o)


def _render_reweight(conn, probe_round: int = 1) -> str:
    """按 host 规模回权后的 L3 估计。

    探测的单 host 上限只削少数几个巨型 host，但它们持有大部分端点，
    于是「占已探测」被小 host 主导。两个数都给，不许只给一个：
    原始值只描述样本（可靠但不可外推），回权值才是对全集的估计。
    """
    from ..analysis.reweight import reweight, top_subsampled_hosts

    try:
        r = reweight(conn, probe_round)
    except Exception:  # noqa: BLE001
        return ""
    if not r["endpoints_probed"]:
        return ""

    o = ["\n### 四之二、按 host 规模回权后的 L3 估计\n"]
    o.append(
        f"探测对 {r['hosts_subsampled']:,} 个 host 做了抽样（共 {r['hosts_covered']:,} 个 host "
        f"被探到，端点全集 {r['endpoints_universe']:,}，实际探测 {r['endpoints_probed']:,}）。"
        "少数巨型 host 持有大部分端点，直接用「占已探测」会被小 host 主导，"
        "所以按 host 分层回权：每个 host 内部抽样是随机的（固定种子），"
        "其存活率可无偏估计，再按该 host 的真实端点数加权。\n"
    )
    o.append("| 层 | 样本内通过 | 占已探测（不可外推）| 回权后估计 | 估计存活端点数 |")
    o.append("|---|---:|---:|---:|---:|")
    for k, label in _LAYER_CN.items():
        d = r["layers"][k]
        o.append(f"| {label} | {d['ok_in_sample']:,} | {100*float(d['raw_share']):.2f}% | "
                 f"**{100*float(d['weighted_share']):.2f}%** | {float(d['weighted_endpoints']):,.0f} |")
    o.append("")
    if r["endpoints_unprobed"]:
        o.append(
            f"> 回权分母是**被探到的 host** 所持的 {r['endpoints_in_covered_hosts']:,} 个端点。"
            f"另有 {r['endpoints_unprobed']:,} 个端点所在的 host 一个都没探到，"
            "它们的存活率无从估计，**不按整体均值填充**（那等于凭空造数据），单列在外。\n"
        )
    top = top_subsampled_hosts(conn, probe_round, limit=8)
    if top:
        o.append("被抽样最狠的 host —— 回权结论对它们最敏感：\n")
        o.append("| host | 端点总数 | 已探测 | 抽样比 | 该 host 协议层通过率 |")
        o.append("|---|---:|---:|---:|---:|")
        for h in top:
            o.append(f"| `{h['host']}` | {h['n_total']:,} | {h['n_probed']:,} | "
                     f"{100*float(h['sample_frac']):.1f}% | {100*float(h['proto_rate']):.1f}% |")
        o.append("")
    return "\n".join(o)


def render_markdown(conn, snapshot_id: str, *, limitations: list[str] | None = None) -> str:
    summary_row = conn.execute(
        """SELECT count(*) AS l0,
                  sum(l1_uri_resolved::INT), sum(l1s_schema_valid::INT), sum(l2_has_endpoint::INT),
                  sum(l3a_dns_ok::INT), sum(l3b_tcp_ok::INT), sum(l3c_http_ok::INT),
                  sum(l3_proto_ok::INT), sum(l3_stable::INT), sum(l4_third_party_fb::INT),
                  sum(l5_economic::INT), sum(declared_inactive::INT), sum(unroutable_endpoint::INT),
                  sum(probed::INT)
           FROM funnel WHERE snapshot_id = ?""",
        [snapshot_id],
    ).fetchone()
    keys = ["l0", "l1", "l1s", "l2", "l3a", "l3b", "l3c", "l3", "l3_stable", "l4", "l5",
            "declared_inactive", "unroutable", "probed"]
    S = {k: (v or 0) for k, v in zip(keys, summary_row)}
    l0 = max(1, S["l0"])

    out: list[str] = []
    out.append(f"# ERC-8004 注册身份活性报告（快照 {snapshot_id}）\n")
    out.append(f"生成时间：{datetime.now(UTC).isoformat()}\n")

    # ---- 人口普查
    #
    # 口径 A 以 agent_state 的实际读取行数为准，而不是 registry_census 的估算值。
    # 前者是「我们逐个读到的 agent」，后者是 ownerOf 二分的结果 —— 二分可能因为
    # Multicall 的 gas 掩蔽而偏小（BSC 就发生过），实读行数不会。
    census = conn.execute(
        """SELECT s.chain_id, count(*) AS n_read,
                  max(c.registered_total) AS n_census
           FROM agent_state s
           LEFT JOIN registry_census c ON c.chain_id = s.chain_id AND c.is_canonical
           WHERE s.snapshot_id = ?
           GROUP BY 1 ORDER BY 2 DESC""",
        [snapshot_id],
    ).fetchall()
    if census:
        out.append("\n## 一、链上人口普查（口径 A：链上已铸造的 agent 总数）\n")
        out.append("| chain_id | 实读 agent 数 | 二分估算 | 一致 |\n|---|---:|---:|---|")
        tot = 0
        for cid, n_read, n_census in census:
            same = "✓" if (n_census is None or n_census == n_read) else f"⚠ 差 {abs((n_census or 0) - n_read)}"
            out.append(f"| {cid} | {n_read:,} | {n_census or 0:,} | {same} |")
            tot += n_read
        out.append(f"| **合计** | **{tot:,}** | | |\n")
        out.append("> 口径 A 不去重、不排除已销毁。跨链去重后的「唯一主体数」见口径 B。\n")

    # ---- 漏斗
    probed = S.get("probed") or 0
    l2 = S.get("l2") or 0
    # L3 各层必须以【已探测】为分母。用 L0 做分母会被探测覆盖率稀释，
    # 直接被读成「存活率低」—— 这是最容易让整份报告作废的算错方式。
    probe_layers = {"l3a", "l3b", "l3c", "l3", "l3_stable"}
    out.append("\n## 二、活性漏斗\n")
    if probed < l2:
        out.append(
            f"> ⚠️ **本快照的探测覆盖率为 {probed:,}/{l2:,} = {_pct(probed, l2)}。**"
            f"L3 各层请只引用「占已探测」一列；「占 L0」列被覆盖率稀释，不代表存活率。\n"
        )
    # L3-stable 需要第 2 轮。没跑第 2 轮时它必然是 0，但那是【未测量】不是
    # 「0% 稳定存活」—— 表格里写 0 / 0.00% 会被直接读成后者，
    # 这正是本仓反复防的「把没测到报成不存在」。所以显式标为不可用。
    has_round2 = bool(conn.execute(
        "SELECT count(*) FROM probe_attempt WHERE probe_round = 2").fetchone()[0])
    out.append("| 层级 | 定义 | 存活数 | 占 L0 | 占已探测 |\n|---|---|---:|---:|---:|")
    for key, label in LAYER_LABELS:
        v = S.get(key) or 0
        if key == "l3_stable" and not has_round2:
            out.append(f"| {key.upper()} | {label} | 不可用 | — | — |")
            continue
        cond = _pct(v, probed) if (key in probe_layers and probed) else "—"
        out.append(f"| {key.upper()} | {label} | {v:,} | {_pct(v, l0)} | {cond} |")
    out.append("")
    if not has_round2:
        out.append(
            "> `L3-stable` 标为**不可用**而不是 0：它要求间隔 ≥48h 的两轮探测都通过，"
            "本快照只跑了第 1 轮。写成 0 会被读成「没有一个稳定存活」，"
            "而实际含义是「尚未测量」。\n"
        )
    out.append(
        f"\n单列旁支（**不计入 L3 失败**）：自我声明不活跃 {S['declared_inactive']:,} "
        f"（{_pct(S['declared_inactive'], l0)}），端点不可路由 {S['unroutable']:,} "
        f"（{_pct(S['unroutable'], l0)}）。\n"
    )

    # ---- 分链漏斗
    # 各链形态差异极大（实测 avalanche 仅 11.5% 的 agent 有 agentURI，
    # celo 是 99.7%）。只报合计会把这种差异抹平，读者会以为存在一个「平均的 agent」。
    per_chain = conn.execute(
        """SELECT chain_id, count(*) AS l0,
                  sum(l1_uri_resolved::INT), sum(l1s_schema_valid::INT),
                  sum(l2_has_endpoint::INT), sum(probed::INT), sum(l3_proto_ok::INT)
           FROM funnel WHERE snapshot_id = ?
           GROUP BY 1 ORDER BY 2 DESC""",
        [snapshot_id],
    ).fetchall()
    if len(per_chain) > 1:
        out.append("\n## 二之二、分链漏斗\n")
        out.append("| chain_id | L0 | L1 可解析 | L1 率 | L1s 合规率 | L2 有端点 | 已探测 | L3 |"
                   "\n|---|---:|---:|---:|---:|---:|---:|---:|")
        for cid, n0, n1, n1s, n2, npb, n3 in per_chain:
            out.append(
                f"| {cid} | {n0:,} | {n1 or 0:,} | {_pct(n1, n0)} | {_pct(n1s, n0)} | "
                f"{n2 or 0:,} | {npb or 0:,} | {n3 or 0:,} |"
            )
        out.append("")

    # ---- 失败分类学
    rows = conn.execute(
        "SELECT status, count(*) FROM uri_fetch GROUP BY 1 ORDER BY 2 DESC"
    ).fetchall()
    if rows:
        out.append("\n## 三、agentURI 抓取失败分类学\n")
        out.append("| status | 数量 | 占比 |\n|---|---:|---:|")
        tot = sum(r[1] for r in rows) or 1
        for st, n in rows:
            out.append(f"| `{st}` | {n:,} | {_pct(n, tot)} |")
        out.append("")

        # `other` 必须拆开：里面混着两类性质完全不同的东西 ——
        # 「对方的服务连不上」和「本扫描器自己的限速器放弃了」。
        # 后者不是对方的失败，混在一起报会把存活率报低。
        detail = conn.execute(
            """SELECT coalesce(error_detail, '(空)'), count(*)
               FROM uri_fetch WHERE status = 'other'
               GROUP BY 1 ORDER BY 2 DESC LIMIT 12"""
        ).fetchall()
        if detail:
            oth = sum(n for st, n in rows if st == "other") or 1
            out.append("`other` 一档的构成（性质差别很大，不可当作单一失败类型引用）：\n")
            out.append("| error_detail | 数量 | 占 `other` | 性质 |\n|---|---:|---:|---|")
            for d, n in detail:
                out.append(f"| `{d}` | {n:,} | {_pct(n, oth)} | {_ERROR_NATURE.get(d, '未分类')} |")
            out.append("")
            out.append(
                "> `HostBlocked` 是**本扫描器自己的限速器**在同一 host 连续受限后主动放弃，"
                "不代表该 agent 的元数据不可达；这些记录应读作「未取得有效尝试」而非「抓取失败」。\n"
            )

    # ---- 逐层探测衰减
    layers = conn.execute(
        """SELECT layer, outcome, count(*) FROM probe_attempt
           GROUP BY 1,2 ORDER BY 1,2"""
    ).fetchall()
    if layers:
        out.append("\n## 四、逐层探测衰减\n")
        out.append("| 层 | outcome | 数量 |\n|---|---|---:|")
        for lay, oc, n in layers:
            out.append(f"| {lay} | {oc} | {n:,} |")
        out.append("")
        out.append(_render_reweight(conn))
        out.append(_render_stability(conn))
        out.append(_render_bimodal(conn))

    # ---- 队列
    ch = cohort_table(conn, snapshot_id)
    if ch and not (len(ch) == 1 and ch[0][0] == "unknown"):
        # L3 列在探测覆盖率低的时候【每一行都会是 0.0%】，看上去像「全都死了」，
        # 其实只是没探测。这种时候不给出 L3 存活率列，只给 L1/L2 —— 那两列
        # 是全量的，本身就有结论价值（元数据可解析率随注册月份的变化）。
        pr = conn.execute(
            """SELECT sum(l2_has_endpoint::INT), sum(probed::INT)
               FROM funnel WHERE snapshot_id = ?""", [snapshot_id]
        ).fetchone()
        l3_usable = bool(pr and pr[0] and (pr[1] or 0) >= 0.5 * pr[0])
        out.append("\n## 五、注册队列存活率\n")
        if l3_usable:
            out.append("| 注册月份 | 注册数 | L1 | L1 率 | L2 | L2 率 | L3 | L3 存活率 |"
                       "\n|---|---:|---:|---:|---:|---:|---:|---:|")
            for m, n, l1, l2, l3 in ch:
                out.append(f"| {m} | {n:,} | {l1 or 0:,} | {_pct(l1, n)} | {l2 or 0:,} | "
                           f"{_pct(l2, n)} | {l3 or 0:,} | {_pct(l3, n)} |")
        else:
            out.append("| 注册月份 | 注册数 | L1 可解析 | L1 率 | L2 有端点 | L2 率 |"
                       "\n|---|---:|---:|---:|---:|---:|")
            for m, n, l1, l2, _l3 in ch:
                out.append(f"| {m} | {n:,} | {l1 or 0:,} | {_pct(l1, n)} | "
                           f"{l2 or 0:,} | {_pct(l2, n)} |")
            out.append(
                "\n> **本表不含 L3 列**：探测覆盖率不足，逐月的 L3 会全是 0.0%，"
                "那是未探测而不是未存活，列出来只会被误读。L1/L2 是全量口径，可以直接引用。\n"
            )
        out.append(
            "\n> 队列存活率是**增量**指标，比总存活率（存量指标）更能说明趋势。"
            "注意存在幸存者时间不对称：老队列有更多时间下线，新队列存活率天然偏高。"
            "消除这个偏差需要多次历史快照——这正是复跑同一个 scanner 的价值。\n"
        )
    else:
        out.append("\n## 五、注册队列存活率\n\n**不可用**：本次快照缺少注册时间戳"
                   "（需要 archive 节点扫历史日志）。\n")

    # ---- 快照锚点
    snaps = conn.execute(
        "SELECT chain_id, block_number, block_hash, block_timestamp FROM snapshot WHERE snapshot_id = ?",
        [snapshot_id],
    ).fetchall()
    out.append(METHODOLOGY)
    for lim in (limitations or []):
        out.append(f"- {lim}")
    out.append("\n### 快照锚点\n")
    out.append("| chain_id | block | block_hash | 时间 |\n|---|---:|---|---|")
    for cid, bn, bh, ts in snaps:
        out.append(f"| {cid} | {bn:,} | `{(bh or '')[:18]}…` | {ts} |")
    out.append("")

    text = "\n".join(out)
    check_wording(text)
    return text


def check_wording(text: str) -> None:
    """表述纪律自检。命中即抛错 —— 宁可不出报告，也不出会被正确攻击的表述。"""
    hits = [p for p in FORBIDDEN_PHRASES if p in text]
    if hits:
        raise ValueError(f"报告文案违反表述纪律，命中禁用表述: {hits}")


def write_report(conn, snapshot_id: str, root: Path | str, limitations=None) -> Path:
    text = render_markdown(conn, snapshot_id, limitations=limitations)
    out = Path(root) / "data" / "export" / f"report-{snapshot_id}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    return out
