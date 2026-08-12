"""db.reset_derived 的回归测试。

背景：派生表原来用 `DELETE FROM`。进程在 DELETE 半途被杀会把主键的 ART 索引
留成不一致状态，下一次 DELETE 直接
    FATAL Error: Failed to delete all rows from index. Only deleted 1836 out of 1884 rows.
FATAL 会让整个 duckdb 连接作废 —— 等于一次 Ctrl-C 就把这张表永久锁死，
只能手工删库重来。改成 DROP 重建后不再触碰索引内容。
"""

from pathlib import Path

import duckdb
import pytest

from e8004 import db

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def conn(tmp_path):
    c = db.connect(root=ROOT, db_path=str(tmp_path / "t.duckdb"))
    db.migrate(c, root=ROOT)
    yield c
    c.close()


def test_reset_derived_empties_table_and_keeps_it_usable(conn):
    conn.execute(
        "INSERT INTO service VALUES (1, 100, 0, 'a2a', 'https://x.test/a', "
        "'1.0', 'x.test', 'https', true)"
    )
    assert conn.execute("SELECT count(*) FROM service").fetchone()[0] == 1

    db.reset_derived(conn, ["service"], root=ROOT)

    # 表还在、是空的、且能继续写 —— DROP 之后必须由 schema.sql 重建回来
    assert conn.execute("SELECT count(*) FROM service").fetchone()[0] == 0
    conn.execute(
        "INSERT INTO service VALUES (1, 100, 0, 'a2a', 'https://x.test/a', "
        "'1.0', 'x.test', 'https', true)"
    )
    assert conn.execute("SELECT count(*) FROM service").fetchone()[0] == 1


def test_reset_derived_handles_multiple_tables(conn):
    db.reset_derived(conn, ["agent_card", "service", "card_registration"], root=ROOT)
    for t in ("agent_card", "service", "card_registration"):
        assert conn.execute(f"SELECT count(*) FROM {t}").fetchone()[0] == 0


def test_reset_derived_refuses_raw_tables(conn):
    """raw 层重新联网才能拿回来，绝不允许被 DROP。"""
    for raw in ("agent_state", "uri_fetch", "probe_attempt", "log_raw"):
        with pytest.raises(ValueError):
            db.reset_derived(conn, [raw], root=ROOT)


# --------------------------------------------------------------- T8 口径回归

def test_crossval_uses_current_owner_basis():
    """T8 门槛必须走【当前 owner】。

    拿到全量铸造历史后实测：同一子集（以太坊 id 0–9999）上
        当前 owner   → 0.8630 / 0.034283 / 0.5140  与论文三项偏差均 0.0%
        注册时 owner → 0.8753 / 0.041321 / 0.5693  偏差 1.4% / 20.5% / 10.8%
    论文虽自述为「注册时 owner」，其数字对应的是当前 owner。
    如果哪天有人把门槛改回注册时 owner，这个测试要挡住。
    """
    from e8004.analysis.concentration import cross_validate_against_paper

    conn = duckdb.connect(":memory:")
    db.migrate(conn, root=ROOT)
    # 当前 owner：7 个持有者平分 —— 与「注册时 owner」故意造得不同
    conn.executemany(
        "INSERT INTO agent_state (chain_id, agent_id, snapshot_id, current_owner) "
        "VALUES (1, ?, '2026-08-10', ?)",
        [[i, f"0x{i % 7:040x}"] for i in range(10000)],
    )
    # 注册时 owner：全部归一个地址（极端集中），若门槛误用它必然偏离论文
    conn.executemany(
        "INSERT INTO agent_mint VALUES (1, ?, ?, ?, NULL, '0x00', 'test')",
        [[i, f"0x{0:040x}", 24339925 + i] for i in range(10000)],
    )
    res = cross_validate_against_paper(conn, snapshot_id="2026-08-10")
    assert res["available"] is True
    assert "当前 owner" in res["basis"], res["basis"]
    # 用的是当前 owner 的 7 个持有者，而不是铸造历史里的 1 个
    assert res["ours"]["holders"] == 7, res["ours"]
    # 注册时口径仍然并列报告出来，只是不当门槛
    assert res["at_registration"] is not None
    assert res["at_registration"]["holders"] == 1
