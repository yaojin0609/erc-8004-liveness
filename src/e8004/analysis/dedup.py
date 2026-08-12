"""跨链身份归并 —— 口径 B（唯一主体数）。

三档置信度分别产出，报告里全给，不要只给一个数（实施规划 §8.1）：

  strong  registrations[] 【双向】确认。A 的 card 声明了 B，且 B 的 card 也声明了 A。
          单向声明不算 —— 任何人都能在自己的 card 里声称是别人。
  medium  card 内容哈希相同 且 当前 owner 相同。
  weak    当前 owner 相同 且 card 的 name 相同。

各家公开数字互相矛盾的主要原因就是口径不同，所以这里不主张哪一档「正确」。
"""

from __future__ import annotations


class UnionFind:
    def __init__(self):
        self.parent: dict = {}

    def find(self, x):
        self.parent.setdefault(x, x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:  # 路径压缩
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra

    def groups(self) -> dict:
        out: dict = {}
        for k in list(self.parent):
            out.setdefault(self.find(k), []).append(k)
        return out


def _all_agents(conn, snapshot_id: str) -> list[tuple[int, int]]:
    return [
        (r[0], r[1])
        for r in conn.execute(
            "SELECT chain_id, agent_id FROM agent_state WHERE snapshot_id = ?", [snapshot_id]
        ).fetchall()
    ]


def build_clusters(conn, snapshot_id: str) -> dict:
    """→ {"strong": {(chain,agent): root}, "medium": {...}, "weak": {...}, "stats": {...}}"""
    agents = _all_agents(conn, snapshot_id)
    known = set(agents)

    # ---- strong：registrations[] 双向确认
    claims = conn.execute(
        """SELECT chain_id, agent_id, claimed_chain_id, claimed_agent_id
           FROM card_registration
           WHERE claimed_chain_id IS NOT NULL AND claimed_agent_id IS NOT NULL"""
    ).fetchall()
    claim_set = {((a, b), (c, d)) for a, b, c, d in claims}
    uf_strong = UnionFind()
    for node in agents:
        uf_strong.find(node)
    n_bidir = n_unidir = 0
    for src, dst in claim_set:
        if (dst, src) in claim_set:
            n_bidir += 1
            if src in known and dst in known:
                uf_strong.union(src, dst)
        else:
            n_unidir += 1

    # ---- medium：card 内容哈希 + 当前 owner 都相同
    uf_medium = UnionFind()
    for node in agents:
        uf_medium.find(node)
    rows = conn.execute(
        """SELECT c.content_sha256, s.current_owner, c.chain_id, c.agent_id
           FROM agent_card c
           JOIN agent_state s ON s.chain_id = c.chain_id AND s.agent_id = c.agent_id
                             AND s.snapshot_id = ?
           WHERE c.content_sha256 IS NOT NULL AND s.current_owner IS NOT NULL""",
        [snapshot_id],
    ).fetchall()
    buckets: dict = {}
    for sha, owner, cid, aid in rows:
        buckets.setdefault((sha, owner), []).append((cid, aid))
    for members in buckets.values():
        for m in members[1:]:
            uf_medium.union(members[0], m)

    # ---- weak：当前 owner + name 都相同
    uf_weak = UnionFind()
    for node in agents:
        uf_weak.find(node)
    rows = conn.execute(
        """SELECT s.current_owner, c.name, c.chain_id, c.agent_id
           FROM agent_card c
           JOIN agent_state s ON s.chain_id = c.chain_id AND s.agent_id = c.agent_id
                             AND s.snapshot_id = ?
           WHERE c.name IS NOT NULL AND c.name <> '' AND s.current_owner IS NOT NULL""",
        [snapshot_id],
    ).fetchall()
    buckets = {}
    for owner, name, cid, aid in rows:
        buckets.setdefault((owner, name), []).append((cid, aid))
    for members in buckets.values():
        for m in members[1:]:
            uf_weak.union(members[0], m)

    def n_clusters(uf: UnionFind) -> int:
        return len({uf.find(a) for a in agents}) if agents else 0

    return {
        "strong": uf_strong,
        "medium": uf_medium,
        "weak": uf_weak,
        "stats": {
            "registrations_total": len(agents),
            "unique_strong": n_clusters(uf_strong),
            "unique_medium": n_clusters(uf_medium),
            "unique_weak": n_clusters(uf_weak),
            "claims_bidirectional": n_bidir // 2,
            "claims_unidirectional_ignored": n_unidir,
        },
    }


def persist(conn, snapshot_id: str, clusters: dict, chunk: int = 20_000,
            root: str = ".") -> int:
    """把归并结果写入 identity_cluster。

    【必须用普通 INSERT，不要 INSERT OR REPLACE】
    表在前面已经清空，冲突不可能发生，但 OR REPLACE 会让 DuckDB 对
    39 万行【逐行】做主键冲突检查 —— 实测能跑到 55 分钟以上还没完。
    普通 INSERT + 分块，同样的数据只要几秒。

    清空用 DROP 重建而不是 DELETE，理由见 db.reset_derived。
    """
    from ..db import reset_derived

    agents = _all_agents(conn, snapshot_id)
    reset_derived(conn, ["identity_cluster"], root)
    st, md, wk = clusters["strong"], clusters["medium"], clusters["weak"]
    rows = [
        [cid, aid, "%d:%d" % st.find(n), "%d:%d" % md.find(n), "%d:%d" % wk.find(n)]
        for n in agents
        for cid, aid in (n,)
    ]
    for i in range(0, len(rows), chunk):
        conn.executemany("INSERT INTO identity_cluster VALUES (?,?,?,?,?)", rows[i:i + chunk])
    return len(rows)
