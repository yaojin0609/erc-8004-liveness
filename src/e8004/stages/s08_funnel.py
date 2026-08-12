"""T11 —— 漏斗物化。纯 SQL，无网络、无随机性。

同一份数据库跑两次，结果必须逐字节相同（DoD）。

L0 的来源优先用 agent_state（当前状态快照）而不是 ev_registered：
免费 RPC 拿不到完整历史日志，但当前状态是完整的。ev_registered 只在有
archive 节点时才是全量，那时它额外提供 reg_month（队列分析）。
"""

from __future__ import annotations

FUNNEL_SQL = """
CREATE OR REPLACE TEMP VIEW _l0 AS
SELECT s.chain_id, s.agent_id, s.snapshot_id,
       s.current_owner, s.token_uri, s.agent_wallet
FROM agent_state s
WHERE s.snapshot_id = ?;

-- 注册月份。两个来源：Registered 事件（权威，但免费档 RPC 拿不全）
-- 和 ERC-721 mint 记录（agent_mint，覆盖全区间，缺 agentURI 但队列分析不需要）。
-- 两边都没有才是 'unknown'，报告里写明队列分析在该口径下不可用，不能假装有。
-- 重铸取【最早】那次：min() 天然满足「首次注册才算注册」。
CREATE OR REPLACE TEMP VIEW _cohort AS
SELECT chain_id, agent_id,
       coalesce(strftime(min(block_timestamp), '%Y-%m'), 'unknown') AS reg_month
FROM (
    SELECT chain_id, agent_id, block_timestamp FROM ev_registered
    UNION ALL
    SELECT chain_id, agent_id, block_timestamp FROM agent_mint
)
GROUP BY 1, 2;

CREATE OR REPLACE TEMP VIEW _uri AS
SELECT l.chain_id, l.agent_id, f.status, f.content_sha256
FROM _l0 l
LEFT JOIN uri_fetch f ON f.uri_normalized = l.token_uri;

CREATE OR REPLACE TEMP VIEW _svc AS
SELECT chain_id, agent_id,
       count(*) AS n_services,
       sum(CASE WHEN is_routable THEN 1 ELSE 0 END) AS n_routable
FROM service GROUP BY 1, 2;

-- 逐层探测结果按 agent 聚合。任一 service 通过即该层通过。
CREATE OR REPLACE TEMP VIEW _probe AS
SELECT chain_id, agent_id,
       max(CASE WHEN layer='dns'   AND outcome='ok' THEN 1 ELSE 0 END) AS dns_ok,
       max(CASE WHEN layer='tcp'   AND outcome='ok' THEN 1 ELSE 0 END) AS tcp_ok,
       max(CASE WHEN layer='http'  AND outcome='ok' THEN 1 ELSE 0 END) AS http_ok,
       max(CASE WHEN layer='proto' AND outcome='ok' AND proto_ok      THEN 1 ELSE 0 END) AS proto_ok,
       max(CASE WHEN layer='proto' AND outcome='ok' AND proto_ok
                 AND probe_round=1 THEN 1 ELSE 0 END) AS proto_r1,
       max(CASE WHEN layer='proto' AND outcome='ok' AND proto_ok
                 AND probe_round=2 THEN 1 ELSE 0 END) AS proto_r2,
       max(CASE WHEN ip_class IN ('loopback','private','reserved') THEN 1 ELSE 0 END) AS unroutable_seen,
       1 AS probed
FROM probe_attempt GROUP BY 1, 2;

-- 非自评、未撤销的第三方反馈
CREATE OR REPLACE TEMP VIEW _fb AS
SELECT f.chain_id, f.agent_id, count(*) AS n_third_party
FROM ev_feedback f
LEFT JOIN feedback_selfloop sl
       ON sl.chain_id = f.chain_id AND sl.block_number = f.block_number
      AND sl.log_index = f.log_index
LEFT JOIN ev_feedback_revoked rv
       ON rv.chain_id = f.chain_id AND rv.agent_id = f.agent_id
      AND rv.client_address = f.client_address AND rv.feedback_index = f.feedback_index
WHERE rv.agent_id IS NULL AND coalesce(sl.is_self_review, FALSE) = FALSE
GROUP BY 1, 2;

DELETE FROM funnel WHERE snapshot_id = ?;

INSERT INTO funnel
SELECT
    l.chain_id,
    l.agent_id,
    l.snapshot_id,
    coalesce(c.reg_month, 'unknown')                                   AS reg_month,
    l.current_owner IS NOT NULL                                        AS l0_registered,
    coalesce(u.status = 'ok', FALSE)                                   AS l1_uri_resolved,
    coalesce(ac.schema_valid_strict, FALSE)                            AS l1s_schema_valid,
    coalesce(sv.n_routable > 0, FALSE)                                 AS l2_has_endpoint,
    coalesce(p.dns_ok = 1, FALSE)                                      AS l3a_dns_ok,
    coalesce(p.tcp_ok = 1, FALSE)                                      AS l3b_tcp_ok,
    coalesce(p.http_ok = 1, FALSE)                                     AS l3c_http_ok,
    coalesce(p.proto_ok = 1, FALSE)                                    AS l3_proto_ok,
    coalesce(p.proto_r1 = 1 AND p.proto_r2 = 1, FALSE)                 AS l3_stable,
    coalesce(fb.n_third_party > 0, FALSE)                              AS l4_third_party_fb,
    coalesce(aa.has_real_economic_tx, FALSE)                           AS l5_economic,
    -- 必须单列的两个旁支：绝不能并入 L3 失败
    coalesce(ac.active = FALSE, FALSE)                                 AS declared_inactive,
    coalesce(sv.n_services > 0 AND sv.n_routable = 0, FALSE)           AS unroutable_endpoint,
    coalesce(p.probed = 1, FALSE)                                      AS probed,
    coalesce(u.status = 'sampled_out', FALSE)                          AS uri_sampled_out
FROM _l0 l
LEFT JOIN _cohort    c  ON c.chain_id  = l.chain_id AND c.agent_id  = l.agent_id
LEFT JOIN _uri       u  ON u.chain_id  = l.chain_id AND u.agent_id  = l.agent_id
LEFT JOIN agent_card ac ON ac.chain_id = l.chain_id AND ac.agent_id = l.agent_id
LEFT JOIN _svc       sv ON sv.chain_id = l.chain_id AND sv.agent_id = l.agent_id
LEFT JOIN _probe     p  ON p.chain_id  = l.chain_id AND p.agent_id  = l.agent_id
LEFT JOIN _fb        fb ON fb.chain_id = l.chain_id AND fb.agent_id = l.agent_id
LEFT JOIN address_activity aa ON aa.chain_id = l.chain_id AND aa.address = l.agent_wallet;
"""

FUNNEL_SUMMARY_SQL = """
SELECT
  count(*)                                   AS l0,
  sum(l1_uri_resolved::INT)                  AS l1,
  sum(l1s_schema_valid::INT)                 AS l1s,
  sum(l2_has_endpoint::INT)                  AS l2,
  sum(l3a_dns_ok::INT)                       AS l3a,
  sum(l3b_tcp_ok::INT)                       AS l3b,
  sum(l3c_http_ok::INT)                      AS l3c,
  sum(l3_proto_ok::INT)                      AS l3,
  sum(l3_stable::INT)                        AS l3_stable,
  sum(l4_third_party_fb::INT)                AS l4,
  sum(l5_economic::INT)                      AS l5,
  sum(declared_inactive::INT)                AS declared_inactive,
  sum(unroutable_endpoint::INT)              AS unroutable,
  sum(probed::INT)                           AS probed,
  sum(uri_sampled_out::INT)                  AS uri_sampled_out
FROM funnel WHERE snapshot_id = ?
"""

LAYER_LABELS = [
    ("l0", "L0 链上注册存在"),
    ("l1", "L1 agentURI 可解析"),
    ("l1s", "L1s 严格符合 registration-v1"),
    ("l2", "L2 声明了可路由端点"),
    ("l3a", "L3a DNS 可解析"),
    ("l3b", "L3b TCP/TLS 可建连"),
    ("l3c", "L3c HTTP 有响应"),
    ("l3", "L3 协议层握手成功"),
    ("l3_stable", "L3-stable 两轮均通过"),
    ("l4", "L4 有非自评第三方反馈"),
    ("l5", "L5 有真实经济活动"),
]


_SNAPSHOT_RE = __import__("re").compile(r"^[A-Za-z0-9._-]{1,64}$")


def build_funnel(conn, snapshot_id: str, root: str = ".") -> dict:
    # DuckDB 不允许在 CREATE VIEW / CREATE TABLE 里用预处理参数
    # （"Unexpected prepared parameter. This type of statement can't be prepared!"），
    # 所以这里先严格校验 snapshot_id 再内联，而不是放宽成任意字符串拼接。
    if not _SNAPSHOT_RE.match(snapshot_id):
        raise ValueError(f"非法的 snapshot_id: {snapshot_id!r}（只允许字母数字和 . _ -）")

    # 表里只有这一个快照时改用 DROP 重建：39 万行的 DELETE 要逐行维护主键索引，
    # 半途被杀会把索引留成不一致状态，之后再 DELETE 就是 FATAL（详见 db.reset_derived）。
    # 有多个快照时必须保留 DELETE 语义 —— 不能把别的快照一起铲了。
    from ..db import reset_derived

    others = conn.execute(
        "SELECT count(*) FROM funnel WHERE snapshot_id <> ?", [snapshot_id]
    ).fetchone()[0]
    sql = FUNNEL_SQL
    if others == 0:
        reset_derived(conn, ["funnel"], root)
        sql = sql.replace("DELETE FROM funnel WHERE snapshot_id = ?;", "")
    sql = sql.replace("?", f"'{snapshot_id}'")
    for stmt in sql.split(";"):
        s = stmt.strip()
        if not s:
            continue
        conn.execute(s)
    row = conn.execute(FUNNEL_SUMMARY_SQL, [snapshot_id]).fetchone()
    cols = [d[0] for d in conn.description]
    return dict(zip(cols, row))


def cohort_table(conn, snapshot_id: str) -> list[tuple]:
    return conn.execute(
        """SELECT reg_month, count(*) AS registered,
                  sum(l1_uri_resolved::INT) AS l1,
                  sum(l2_has_endpoint::INT) AS l2,
                  sum(l3_proto_ok::INT)     AS l3
           FROM funnel WHERE snapshot_id = ?
           GROUP BY 1 ORDER BY 1""",
        [snapshot_id],
    ).fetchall()
