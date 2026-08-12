"""agent card 解析与漏斗口径测试。"""

from __future__ import annotations

import json

import pytest

from e8004.fetch import classify_scheme, extract_cid, fetch_data_uri, normalize_uri
from e8004.report.render import FORBIDDEN_PHRASES, check_wording
from e8004.stages.s05_card_parse import REGISTRATION_V1_TYPE, parse_card

VALID = {
    "type": REGISTRATION_V1_TYPE,
    "name": "demo-agent",
    "description": "d",
    "services": [
        {"name": "A2A", "endpoint": "https://agent.example.com/a2a", "version": "0.3.0"},
        {"name": "MCP", "endpoint": "https://agent.example.com/mcp"},
    ],
    "active": True,
    "x402Support": True,
    "registrations": [{"agentId": 22, "agentRegistry": "eip155:1:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432"}],
    "supportedTrust": ["reputation"],
}


def test_valid_card():
    out = parse_card(json.dumps(VALID), 1, 22)
    c = out["card"]
    assert c["schema_valid_strict"] and c["parsed_lenient"]
    assert c["name"] == "demo-agent" and c["active"] is True and c["x402_support"] is True
    assert len(out["services"]) == 2
    assert all(s["is_routable"] for s in out["services"])
    assert out["registrations"][0]["claimed_chain_id"] == 1
    assert out["registrations"][0]["claimed_agent_id"] == 22


def test_missing_type_fails_strict_but_passes_lenient():
    doc = {**VALID}
    doc.pop("type")
    out = parse_card(json.dumps(doc), 1, 1)
    assert out["card"]["schema_valid_strict"] is False
    assert out["card"]["parsed_lenient"] is True
    assert "type" in out["card"]["schema_errors"]


def test_services_not_a_list():
    doc = {**VALID, "services": {"name": "A2A"}}
    out = parse_card(json.dumps(doc), 1, 2)
    assert out["card"]["schema_valid_strict"] is False
    assert out["services"] == []


def test_localhost_endpoint_marked_unroutable():
    """指向本机/内网的端点是「根本没打算对外服务」，必须能被单列出来。"""
    doc = {**VALID, "services": [
        {"name": "MCP", "endpoint": "http://localhost:3000/mcp"},
        {"name": "web", "endpoint": "http://192.168.1.10/"},
        {"name": "web", "endpoint": "https://real.example.com/"},
    ]}
    out = parse_card(json.dumps(doc), 1, 3)
    routable = [s["is_routable"] for s in out["services"]]
    assert routable == [False, False, True]


def test_malformed_json():
    out = parse_card(b"{not json", 1, 4)
    assert out["card"]["parsed_lenient"] is False
    assert "json_decode" in out["card"]["schema_errors"]


def test_data_uri_roundtrip():
    import base64

    payload = base64.b64encode(json.dumps(VALID).encode()).decode()
    uri = f"data:application/json;base64,{payload}"
    assert classify_scheme(uri) == "data"
    res = fetch_data_uri(uri)
    assert res.status == "ok" and res.body is not None
    out = parse_card(res.body, 1, 5)
    assert out["card"]["schema_valid_strict"]


def test_data_uri_not_json_is_classified_separately():
    res = fetch_data_uri("data:text/plain,hello")
    assert res.status == "not_json"  # 不是 ok，也不是失败 —— 单独一类


def test_ipfs_cid_with_and_without_path():
    assert extract_cid("ipfs://QmAbc123") == ("QmAbc123", "")
    assert extract_cid("ipfs://QmAbc123/card.json") == ("QmAbc123", "/card.json")
    assert extract_cid("https://example.com") is None


def test_normalize_uri_dedup():
    a = normalize_uri("HTTPS://Example.COM:443/card.json")
    b = normalize_uri("https://example.com/card.json")
    assert a == b


def test_report_wording_discipline():
    """报告文案纪律：命中禁用表述必须抛错，宁可不出报告。"""
    check_wording("L3 存活率 3.2%，其中 12% 自我声明为不活跃。")
    for phrase in FORBIDDEN_PHRASES:
        try:
            check_wording(f"结论：{phrase}")
        except ValueError:
            continue
        raise AssertionError(f"禁用表述 {phrase!r} 没有被拦下")


# ---------------------------------------------------------------- 集中度


def test_gini_semantics():
    """Gini 定义在【实际持有者】之上（论文口径亦然），0 持有者不计入。"""
    from e8004.analysis.concentration import gini, hhi, top_n_share

    assert abs(float(gini([1] * 100))) < 1e-9            # 完全平均
    assert abs(float(gini([7]))) < 1e-9                  # 单一持有者内部无不平等
    g = float(gini([1] * 99 + [901]))                    # 一个占 90%
    assert 0.85 < g < 0.95
    assert abs(float(hhi([50, 50])) - 0.5) < 1e-9
    assert abs(float(top_n_share([10, 5, 3, 2], 2)) - 0.75) < 1e-9


def test_dedup_requires_bidirectional_claim():
    """单向声明不能算强证据 —— 任何人都能在自己 card 里声称是别人。"""
    from e8004.analysis.dedup import UnionFind

    uf = UnionFind()
    uf.union((1, 5), (8453, 9))
    assert uf.find((1, 5)) == uf.find((8453, 9))
    assert uf.find((1, 5)) != uf.find((137, 3))


# ------------------------------------------------- 畸形 tokenURI 回归测试
#
# 实测事故：BSC agent #29573 的 tokenURI 是一段 JSON 片段
#   `"animal_kingdom": {   "kingdoms": 1, "phyla": 36 }`
# urlparse 是【惰性】的 —— 它本身不抛错，直到访问 .port 才把 ` {   "kingdoms": 1`
# 拿去转整数。当时 try 只包住 urlparse() 没包住属性访问，于是这一个值掀翻了
# 19.7 万个 URI 的抓取，而 run_full.sh 的 `|| true` 把失败吞了，
# 最终产出一份用 31% 数据算出来、却看起来完整的报告。

MALFORMED_URIS = [
    '"animal_kingdom": {   "kingdoms": 1, "phyla": 36 }',   # JSON 片段，含冒号
    "http://host:notaport/x",                                # 端口不是数字
    "https://host:99999/x",                                  # 端口越界
    "https://[::1:bad/x",                                    # 畸形 IPv6
    "eliza-cloud all-creation --animals=full-kingdoms",      # 带空格的自由文本
    ":",
    "://",
    "",
    "   ",
]


@pytest.mark.parametrize("bad", MALFORMED_URIS)
def test_parse_endpoint_never_raises(bad):
    """任何畸形输入都必须返回而不是抛异常 —— 一个坏值不能掀翻整轮抓取。"""
    from e8004.probe.layers import parse_endpoint

    host, port, scheme, is_lit = parse_endpoint(bad)
    assert host is None or isinstance(host, str)


@pytest.mark.parametrize("bad", MALFORMED_URIS)
def test_classify_and_normalize_never_raise(bad):
    from e8004.fetch import classify_scheme, normalize_uri

    assert isinstance(classify_scheme(bad), str)
    assert isinstance(normalize_uri(bad), str)


def test_parse_endpoint_still_works_on_valid():
    from e8004.probe.layers import parse_endpoint

    assert parse_endpoint("https://a.example.com:8443/x")[:3] == ("a.example.com", 8443, "https")
    assert parse_endpoint("example.org")[:3] == ("example.org", 443, "https")
    assert parse_endpoint("http://example.org/y")[:3] == ("example.org", 80, "http")


def test_crossval_accepts_explicit_snapshot_id():
    """回归：曾把传入的 snapshot_id 字符串当元组做 [0]，取到第一个字符。"""
    import duckdb

    from e8004.analysis.concentration import cross_validate_against_paper

    # 用【真实 DDL】而不是手搓的最小表：手搓的会随 schema 演进悄悄失真，
    # 上一次就是 _REGISTRATION_SQL 加了 block_timestamp 之后这里才炸。
    from pathlib import Path

    from e8004 import db

    conn = duckdb.connect(":memory:")
    db.migrate(conn, root=Path(__file__).resolve().parents[1])
    conn.executemany(
        "INSERT INTO agent_state (chain_id, agent_id, snapshot_id, current_owner) "
        "VALUES (1, ?, '2026-08-10', ?)",
        [[i, f"0x{i % 7:040x}"] for i in range(10000)],
    )
    res = cross_validate_against_paper(conn, snapshot_id="2026-08-10")
    assert res["available"] is True, res.get("notes")
    assert res["ours"]["items"] == 10000
