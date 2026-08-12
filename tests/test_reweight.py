"""按 host 规模回权的回归测试。

探测的单 host 上限只削 14 个最大的 host（占 host 数的 0.4%），
但那 14 个持有 68% 的端点。不回权就等于把「1 个端点的小 host」和
「36,413 个端点的大 host」按相同权重平均 —— 而后者正是少数运营商
批量注册的产物，两类存活率没有理由相同。
"""

from decimal import Decimal
from pathlib import Path

import duckdb
import pytest

from e8004 import db
from e8004.analysis.reweight import reweight, top_subsampled_hosts

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def conn():
    c = duckdb.connect(":memory:")
    db.migrate(c, root=ROOT)
    yield c
    c.close()


def _add(conn, host, n_total, probed_ok, probed_fail, start=0):
    """给 host 造 n_total 个端点，其中前 probed_ok+probed_fail 个被探测过。"""
    for i in range(n_total):
        aid = start + i
        conn.execute(
            "INSERT INTO service VALUES (1, ?, 0, 'a2a', ?, '1.0', ?, 'https', true)",
            [aid, f"https://{host}/{i}", host],
        )
    for i in range(probed_ok + probed_fail):
        aid = start + i
        outcome = "ok" if i < probed_ok else "fail"
        for layer, oc in (("dns", "ok"), ("tcp", "ok"), ("http", "ok"), ("proto", outcome)):
            conn.execute(
                "INSERT INTO probe_attempt (probe_round, chain_id, agent_id, service_idx,"
                " layer, outcome) VALUES (1, 1, ?, 0, ?, ?)", [aid, layer, oc])


def test_weighted_share_follows_big_host_not_sample_count(conn):
    """大 host 存活率低、小 host 存活率高时，回权结果必须偏向大 host。"""
    # 大 host：10,000 个端点，只探 100 个，全部失败
    _add(conn, "big.test", 10_000, probed_ok=0, probed_fail=100, start=0)
    # 100 个小 host：各 1 个端点，全探，全部成功
    for k in range(100):
        _add(conn, f"s{k}.test", 1, probed_ok=1, probed_fail=0, start=20_000 + k)

    r = reweight(conn, probe_round=1)
    proto = r["layers"]["proto_ok"]

    # 原始样本：200 个里 100 个成功 = 50%，被小 host 抬高了
    assert proto["raw_share"] == pytest.approx(Decimal("0.5"), abs=Decimal("0.01"))
    # 回权：10,000 个端点 0% + 100 个端点 100% → 约 1%
    assert proto["weighted_share"] < Decimal("0.02"), proto["weighted_share"]


def test_fully_probed_hosts_are_unchanged_by_reweighting(conn):
    """没有被抽样时，回权结果必须等于原始比例 —— 否则说明权重算错了。"""
    _add(conn, "a.test", 10, probed_ok=5, probed_fail=5, start=0)
    _add(conn, "b.test", 10, probed_ok=2, probed_fail=8, start=100)

    r = reweight(conn, probe_round=1)
    proto = r["layers"]["proto_ok"]
    assert proto["raw_share"] == proto["weighted_share"]
    assert r["hosts_subsampled"] == 0


def test_unprobed_hosts_are_excluded_not_imputed(conn):
    """一个端点都没探到的 host 不能按整体均值填充 —— 那是凭空造数据。"""
    _add(conn, "probed.test", 10, probed_ok=10, probed_fail=0, start=0)
    _add(conn, "never.test", 990, probed_ok=0, probed_fail=0, start=100)

    r = reweight(conn, probe_round=1)
    assert r["endpoints_universe"] == 1000
    assert r["endpoints_in_covered_hosts"] == 10      # 回权分母只含探到的 host
    assert r["endpoints_unprobed"] == 990
    assert r["hosts_covered"] == 1
    # 全通过的那个 host 回权后仍是 100%，没有被未探测的 990 稀释
    assert r["layers"]["proto_ok"]["weighted_share"] == Decimal(1)


def test_top_subsampled_hosts_reports_sampling_fraction(conn):
    _add(conn, "big.test", 5_000, probed_ok=1_000, probed_fail=1_000, start=0)
    _add(conn, "small.test", 5, probed_ok=5, probed_fail=0, start=90_000)

    top = top_subsampled_hosts(conn, probe_round=1)
    assert [h["host"] for h in top] == ["big.test"]      # 全探的不算被抽样
    assert top[0]["sample_frac"] == pytest.approx(Decimal("0.4"), abs=Decimal("0.001"))
    assert top[0]["proto_rate"] == pytest.approx(Decimal("0.5"), abs=Decimal("0.001"))
