"""解码器测试。

最要紧的一条：`string indexed` 在 topic 里是 keccak 哈希，可读值必须取 data 段。
这个错了【不会报错】，只会静默产出垃圾数据 —— 所以必须有测试盯着。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from eth_abi.abi import encode
from eth_utils import keccak

from e8004.abi import EventRegistry, decode_log, is_dynamic_type, selector, topic0

ABIS = json.loads((Path(__file__).resolve().parents[1] / "config" / "abis.json").read_text("utf-8"))


def test_topic0_is_computed_not_hardcoded():
    # ERC-721 Transfer 的 topic0 是公开已知值，用它验证 keccak 路径正确
    assert topic0("Transfer(address,address,uint256)") == (
        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    )


def test_selector_known_values():
    assert selector("ownerOf(uint256)") == "0x6352211e"
    assert selector("tokenURI(uint256)") == "0xc87b56dd"
    assert selector("supportsInterface(bytes4)") == "0x01ffc9a7"


def test_is_dynamic_type():
    assert is_dynamic_type("string")
    assert is_dynamic_type("bytes")
    assert is_dynamic_type("uint256[]")
    assert not is_dynamic_type("bytes32")
    assert not is_dynamic_type("address")


def _registry() -> EventRegistry:
    return EventRegistry(ABIS)


def test_registered_decoding():
    ev = _registry().by_name["Registered"]
    owner = "0x" + "ab" * 20
    uri = "ipfs://QmTest"
    data = "0x" + encode(["string"], [uri]).hex()
    topics = [
        ev["topic0"],
        "0x" + (1234).to_bytes(32, "big").hex(),
        "0x" + bytes(12) .hex() + owner[2:],
    ]
    out = decode_log(ev, topics, data)
    assert out["agentId"] == 1234
    assert out["agentURI"] == uri
    assert out["owner"] == owner.lower()


def test_new_feedback_negative_value_and_decimals():
    """负值 int128 + 非零 valueDecimals + 非空 tag1 —— 三个最容易错的点一起测。"""
    ev = _registry().by_name["NewFeedback"]
    client = "0x" + "cd" * 20
    value = -12345          # int128 可以为负
    decimals = 6            # 非零
    tag1, tag2 = "quality", "latency"
    data = "0x" + encode(
        ["uint64", "int128", "uint8", "string", "string", "string", "string", "bytes32"],
        [7, value, decimals, tag1, tag2, "https://ep", "ipfs://fb", b"\x11" * 32],
    ).hex()
    topics = [
        ev["topic0"],
        "0x" + (99).to_bytes(32, "big").hex(),
        "0x" + bytes(12).hex() + client[2:],
        "0x" + keccak(text=tag1).hex(),      # string indexed = keccak 哈希
    ]
    out = decode_log(ev, topics, data)

    assert out["agentId"] == 99
    assert out["clientAddress"] == client.lower()
    assert out["value"] == value
    assert out["value"] < 0          # int128 必须能表示负数
    assert out["valueDecimals"] == decimals
    # 可读 tag 必须来自 data 段
    assert out["tag1"] == tag1
    assert out["tag2"] == tag2
    # indexed 的那个必须是哈希，且被显式标记，防止调用方误用
    assert out["indexedTag1"] == "0x" + keccak(text=tag1).hex()
    assert out["indexedTag1__hashed"] is True
    assert out["indexedTag1"] != out["tag1"]


def test_metadata_set_readable_key_comes_from_data():
    ev = _registry().by_name["MetadataSet"]
    key = "agentWallet"
    data = "0x" + encode(["string", "bytes"], [key, b"\x01\x02"]).hex()
    topics = [
        ev["topic0"],
        "0x" + (5).to_bytes(32, "big").hex(),
        "0x" + keccak(text=key).hex(),
    ]
    out = decode_log(ev, topics, data)
    assert out["metadataKey"] == key
    assert out["indexedMetadataKey"] == "0x" + keccak(text=key).hex()
    assert out["indexedMetadataKey__hashed"] is True


def test_topic_count_mismatch_raises():
    """abis.json 与实际部署的合约不一致时必须报错，不能静默解出垃圾。"""
    ev = _registry().by_name["Registered"]
    with pytest.raises(ValueError, match="abis.json"):
        decode_log(ev, [ev["topic0"]], "0x")


def test_all_events_have_at_most_three_indexed():
    """Solidity 非匿名事件最多 3 个 indexed。超了说明 abis.json 写错了。"""
    for contract in ("identity_registry", "reputation_registry", "validation_registry"):
        for ev in ABIS.get(contract, {}).get("events", []):
            n = sum(1 for i in ev["inputs"] if i.get("indexed"))
            assert n <= 3, f"{ev['name']} 有 {n} 个 indexed"


def test_signature_matches_inputs():
    """签名字符串的类型列表必须与 inputs 的类型逐一对应。"""
    for contract in ("identity_registry", "reputation_registry", "validation_registry"):
        for ev in ABIS.get(contract, {}).get("events", []):
            inner = ev["signature"][ev["signature"].index("(") + 1 : ev["signature"].rindex(")")]
            types = [t for t in inner.split(",") if t]
            assert types == [i["type"] for i in ev["inputs"]], ev["name"]
