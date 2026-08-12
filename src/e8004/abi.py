"""事件签名 → topic0，日志解码，函数编码。

三条硬约束（CLAUDE.md 6/7/9）在这里落地：
  * topic0 一律运行时 keccak 计算，禁止硬编码 hash
  * `string indexed` 在 topic 里是 keccak 哈希不是原文 —— 可读值必须取 data 段的
    非 indexed 同名字段。本模块把哈希值单独放进 `<name>` 并置 `<name>__hashed=True`，
    让调用方不可能误用（拿到的是 0x… 哈希串，不是想要的字符串）。
  * 地址一律小写。
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from eth_abi.abi import decode as abi_decode
from eth_abi.abi import encode as abi_encode
from eth_utils import keccak

# ABI 里被 indexed 时只存 keccak 哈希的类型（动态类型）
_DYNAMIC_PREFIXES = ("string", "bytes")  # bytes32 等定长在下面单独排除


def is_dynamic_type(t: str) -> bool:
    if t.endswith("]"):  # 任意数组
        return True
    if t == "bytes" or t == "string":
        return True
    if t.startswith("tuple"):
        return True
    return False


@lru_cache(maxsize=512)
def topic0(signature: str) -> str:
    """事件签名字符串 → topic0。例：Registered(uint256,string,address)"""
    return "0x" + keccak(text=signature).hex()


@lru_cache(maxsize=512)
def selector(signature: str) -> str:
    """函数签名字符串 → 4 字节选择器。例：ownerOf(uint256)"""
    return "0x" + keccak(text=signature).hex()[:8]


@lru_cache(maxsize=512)
def keccak_text(text: str) -> str:
    return "0x" + keccak(text=text).hex()


def _norm(value: Any, typ: str) -> Any:
    if typ == "address":
        return value.lower() if isinstance(value, str) else value
    if typ.startswith("bytes") and isinstance(value, (bytes, bytearray)):
        return "0x" + bytes(value).hex()
    return value


def decode_log(event: dict, topics: list[str], data: str) -> dict[str, Any]:
    """解码一条日志。

    event: config/abis.json 里的事件定义（含 inputs 的 name/type/indexed）
    topics: 含 topic0 的完整 topics 列表
    data: 0x 前缀的 data 段
    """
    inputs = event["inputs"]
    indexed = [i for i in inputs if i.get("indexed")]
    plain = [i for i in inputs if not i.get("indexed")]

    if len(topics) - 1 != len(indexed):
        raise ValueError(
            f"{event['name']}: topics 数量({len(topics) - 1})与 ABI indexed 数量({len(indexed)})不符。"
            f" abis.json 与实际部署的合约不一致 —— 见 T0-1"
        )

    out: dict[str, Any] = {}

    for pos, inp in enumerate(indexed):
        raw = topics[pos + 1]
        if is_dynamic_type(inp["type"]):
            # topic 里存的是 keccak(value)，原文不可恢复。
            out[inp["name"]] = raw.lower()
            out[inp["name"] + "__hashed"] = True
        else:
            (v,) = abi_decode([inp["type"]], bytes.fromhex(raw[2:]))
            out[inp["name"]] = _norm(v, inp["type"])

    if plain:
        payload = bytes.fromhex(data[2:]) if data and data != "0x" else b""
        values = abi_decode([i["type"] for i in plain], payload)
        for inp, v in zip(plain, values):
            out[inp["name"]] = _norm(v, inp["type"])

    return out


def encode_call(signature: str, arg_types: list[str], args: list[Any]) -> str:
    """构造 eth_call 的 data。"""
    body = abi_encode(arg_types, args).hex() if arg_types else ""
    return selector(signature) + body


def decode_result(types: list[str], hexdata: str) -> tuple:
    if not hexdata or hexdata == "0x":
        raise ValueError("空返回值（多半是 revert）")
    return abi_decode(types, bytes.fromhex(hexdata[2:]))


def types_of(signature: str) -> list[str]:
    """从签名里取参数类型列表。ownerOf(uint256) -> ['uint256']"""
    inner = signature[signature.index("(") + 1 : signature.rindex(")")]
    return [t for t in inner.split(",") if t]


class EventRegistry:
    """把 abis.json 编成 topic0 → 事件定义 的查找表。"""

    def __init__(self, abis: dict):
        self.by_topic: dict[str, dict] = {}
        self.by_name: dict[str, dict] = {}
        for contract in ("identity_registry", "reputation_registry", "validation_registry"):
            for ev in abis.get(contract, {}).get("events", []):
                t0 = topic0(ev["signature"])
                entry = {**ev, "contract": contract, "topic0": t0}
                self.by_topic[t0] = entry
                self.by_name[ev["name"]] = entry

    def topics_for(self, names: list[str] | None = None) -> list[str]:
        if names is None:
            return sorted(self.by_topic)
        return [self.by_name[n]["topic0"] for n in names]

    def decode(self, log: dict) -> tuple[dict | None, dict[str, Any] | None]:
        ev = self.by_topic.get(log["topics"][0].lower())
        if ev is None:
            return None, None
        return ev, decode_log(ev, log["topics"], log.get("data", "0x"))
