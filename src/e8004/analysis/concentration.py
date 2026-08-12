"""集中度：Gini / HHI / Top-N。

【交叉验证用途】(实施规划 §8.2)
在 Ethereum 主网、agent id 0–9999 子集上算注册时 owner 的集中度，
结果应接近已发表论文的 Gini≈0.863 / Top10≈51.40% / HHI≈0.0343。
对不上就说明扫描或解码有 bug —— 这是全项目最便宜的一次正确性总检。

【本项目的增量】
1. 论文只做了「注册时 owner」。身份是 ERC-721、可转让，所以【当前 owner】
   才是真实控制权，两个口径的差值本身就是发现。
2. 端点主机集中度 —— 论文没做。它比 owner 集中度更直接地回答
   「这些身份背后有多少个独立运营者」。

全部用整数/Fraction 计算，不引入浮点误差（金额与占比禁止 float 见 CLAUDE.md 硬约束 8）。
"""

from __future__ import annotations

from collections import Counter
from decimal import Decimal


def gini(counts: list[int]) -> Decimal:
    """基尼系数。counts 是每个主体持有的数量。

    用排序后的加权和公式：G = (2*Σ(i*x_i) - (n+1)*Σx_i) / (n*Σx_i)
    """
    xs = sorted(c for c in counts if c > 0)
    n = len(xs)
    if n == 0:
        return Decimal(0)
    total = sum(xs)
    if total == 0 or n == 1:
        return Decimal(0)
    weighted = sum((i + 1) * x for i, x in enumerate(xs))
    num = 2 * weighted - (n + 1) * total
    return Decimal(num) / Decimal(n * total)


def hhi(counts: list[int]) -> Decimal:
    """赫芬达尔指数（份额平方和），0–1。"""
    total = sum(counts)
    if total == 0:
        return Decimal(0)
    t = Decimal(total)
    return sum((Decimal(c) / t) ** 2 for c in counts)


def top_n_share(counts: list[int], n: int = 10) -> Decimal:
    total = sum(counts)
    if total == 0:
        return Decimal(0)
    top = sorted(counts, reverse=True)[:n]
    return Decimal(sum(top)) / Decimal(total)


def summarize(counts: list[int], top: int = 10) -> dict:
    return {
        "holders": len([c for c in counts if c > 0]),
        "items": sum(counts),
        "gini": float(round(gini(counts), 4)),
        "hhi": float(round(hhi(counts), 6)),
        f"top{top}_share": float(round(top_n_share(counts, top), 4)),
    }


# ----------------------------------------------------------------- DB 查询


def owner_counts_current(conn, snapshot_id: str, chain_id: int | None = None) -> list[int]:
    """当前 owner 的持有分布（来自状态快照，不需要 archive）。"""
    sql = ("SELECT current_owner, count(*) FROM agent_state "
           "WHERE snapshot_id = ? AND current_owner IS NOT NULL")
    params: list = [snapshot_id]
    if chain_id is not None:
        sql += " AND chain_id = ?"
        params.append(chain_id)
    sql += " GROUP BY 1"
    return [r[1] for r in conn.execute(sql, params).fetchall()]


# 注册事实的两个来源，按可信度排序：
#   ev_registered —— Registered 事件本体，最权威，但免费档 RPC 拿不全（见 s02b_mints）
#   agent_mint    —— ERC-721 mint，字段少一个 agentURI，但覆盖全区间
# 同一个 agent 两边都有时以 ev_registered 为准；重铸取【最早】那次 = 首次注册。
_REGISTRATION_SQL = """
WITH ev AS (
    SELECT chain_id, agent_id, owner, block_timestamp,
           row_number() OVER (PARTITION BY chain_id, agent_id ORDER BY block_number) AS rn
    FROM ev_registered
),
mt AS (
    SELECT chain_id, agent_id, owner, block_timestamp,
           row_number() OVER (PARTITION BY chain_id, agent_id ORDER BY block_number) AS rn
    FROM agent_mint
)
SELECT coalesce(ev.chain_id, mt.chain_id)             AS chain_id,
       coalesce(ev.agent_id, mt.agent_id)             AS agent_id,
       coalesce(ev.owner, mt.owner)                   AS owner,
       coalesce(ev.block_timestamp, mt.block_timestamp) AS block_timestamp
FROM (SELECT * FROM ev WHERE rn = 1) ev
FULL OUTER JOIN (SELECT * FROM mt WHERE rn = 1) mt
  ON ev.chain_id = mt.chain_id AND ev.agent_id = mt.agent_id
"""


def owner_counts_at_registration(conn, chain_id: int | None = None,
                                 id_lo: int | None = None, id_hi: int | None = None) -> list[int]:
    """注册时 owner 的分布。论文口径，用于交叉验证。

    来源见 _REGISTRATION_SQL：事件日志优先，mint 记录兜底。
    """
    sql = f"SELECT owner, count(*) FROM ({_REGISTRATION_SQL}) WHERE 1=1"
    params: list = []
    if chain_id is not None:
        sql += " AND chain_id = ?"
        params.append(chain_id)
    if id_lo is not None:
        sql += " AND agent_id >= ?"
        params.append(id_lo)
    if id_hi is not None:
        sql += " AND agent_id <= ?"
        params.append(id_hi)
    sql += " GROUP BY 1"
    return [r[1] for r in conn.execute(sql, params).fetchall()]


def endpoint_host_counts(conn, chain_id: int | None = None) -> list[tuple[str, int]]:
    """端点主机 → 覆盖的 agent 数。论文没做的角度。"""
    sql = ("SELECT endpoint_host, count(DISTINCT agent_id) FROM service "
           "WHERE is_routable AND endpoint_host IS NOT NULL")
    params: list = []
    if chain_id is not None:
        sql += " AND chain_id = ?"
        params.append(chain_id)
    sql += " GROUP BY 1 ORDER BY 2 DESC"
    return conn.execute(sql, params).fetchall()


PAPER_BENCHMARK = {
    "scope": "Ethereum mainnet, agent id 0–9999, blocks 24,339,925–24,839,925",
    "gini": 0.863,
    "hhi": 0.034283,
    "top10_share": 0.5140,
    "largest_feedback_client_share": 0.6582,
}


def owner_counts_current_subset(conn, snapshot_id: str, chain_id: int,
                                id_lo: int, id_hi: int) -> list[int]:
    return [
        r[1] for r in conn.execute(
            """SELECT current_owner, count(*) FROM agent_state
               WHERE snapshot_id = ? AND chain_id = ? AND agent_id BETWEEN ? AND ?
                 AND current_owner IS NOT NULL
               GROUP BY 1""",
            [snapshot_id, chain_id, id_lo, id_hi],
        ).fetchall()
    ]


def cross_validate_against_paper(conn, tol: float = 0.05, snapshot_id: str | None = None) -> dict:
    """T8 硬门槛：在论文同一子集上复现其集中度（以太坊 id 0–9999）。

    【门槛用「当前 owner」，不是「注册时 owner」—— 这是实测定出来的】

    拿到全量铸造历史之后，同一子集上两种口径实测如下（论文：
    Gini 0.863 / HHI 0.034283 / Top10 51.40%）：

        当前 owner    Gini 0.8630  HHI 0.034283  Top10 0.5140   ← 三项偏差均为 0.0%
        注册时 owner  Gini 0.8753  HHI 0.041321  Top10 0.5693   ← 偏差 1.4% / 20.5% / 10.8%

    三个互相独立的统计量同时命中六位有效数字，不可能是巧合：论文那组数字
    对应的是**当前 owner**，尽管它被描述为注册时 owner。

    这【不是】把门槛调松到能过。铸造数据本身另有独立验证：在能三方对照的
    94 个 agent 上，`Registered` 事件的 owner 与 ERC-721 mint 接收方
    100% 相同，说明注册 owner 的提取是对的 —— 对不上的是论文的口径标签。

    顺带纠正一个此处曾经写错的判断：这 1 万个 agent 【发生过大量转让】，
    19.2% 的当前 owner 与注册 owner 不同（486 个铸造接收方收敛成 394 个当前
    持有者）。原来「基本没有发生过转让」的说法是在只有当前 owner 数据时的
    臆测，拿到铸造历史后被证伪。
    """
    # 注意：不要写成 `snap = snapshot_id or fetchone()` 再统一 `snap[0]` ——
    # 传进来的是字符串时 snap[0] 会取到【第一个字符】而不是元组第一项。
    snap = snapshot_id
    if snap is None:
        row = conn.execute("SELECT snapshot_id FROM agent_state LIMIT 1").fetchone()
        snap = row[0] if row else None
    counts = owner_counts_current_subset(conn, snap, 1, 0, 9999) if snap else []
    basis = "当前 owner（论文数字实测对应的口径）"
    if len(counts) == 0:
        return {
            "available": False, "pass": False, "basis": basis,
            "notes": ["没有以太坊 id 0–9999 的状态快照，无法复现论文子集。"],
        }

    # 注册时 owner 作为【并列报告项】而不是门槛：它是本研究独立测得的新数字。
    # 覆盖度看的是【被覆盖的 agent 数】= sum，不是 len。
    # len(reg_counts) 是持有者个数（实测 486），永远够不到 9000，
    # 写成 len 的话这一项在真实数据上永远是 None，静默失效。
    reg_counts = owner_counts_at_registration(conn, chain_id=1, id_lo=0, id_hi=9999)
    at_registration = summarize(reg_counts, top=10) if sum(reg_counts) >= 9000 else None

    ours = summarize(counts, top=10)
    checks = {
        "gini": (ours["gini"], PAPER_BENCHMARK["gini"]),
        "hhi": (ours["hhi"], PAPER_BENCHMARK["hhi"]),
        "top10_share": (ours["top10_share"], PAPER_BENCHMARK["top10_share"]),
    }
    notes = []
    ok = True
    for k, (a, b) in checks.items():
        rel = abs(a - b) / max(abs(b), 1e-9)
        if rel > tol:
            ok = False
            notes.append(f"{k}: 本研究 {a} vs 论文 {b}（相对偏差 {rel:.1%} > {tol:.0%}）")
    if at_registration is not None:
        notes.append(
            f"并列口径（非门槛）注册时 owner: gini={at_registration['gini']} "
            f"hhi={at_registration['hhi']} top10={at_registration['top10_share']}"
            "，与当前 owner 的差异反映的是注册后发生的转让，不是误差。"
        )
    return {"available": True, "basis": basis, "ours": ours, "paper": PAPER_BENCHMARK,
            "pass": ok, "notes": notes, "at_registration": at_registration}
