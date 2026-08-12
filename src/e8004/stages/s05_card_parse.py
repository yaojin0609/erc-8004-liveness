"""T4 —— agent card 解析（纯函数，随时可 DROP 重建）。

产出三张表：agent_card / service / card_registration。

两条口径同时记录：
  * schema_valid_strict —— 严格符合 registration-v1，报告 headline 用
  * parsed_lenient      —— 能拿到 name/services 就算，下游分析用
两个数都要出现在报告里，差值本身有信息量。
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any
from urllib.parse import urlparse

REGISTRATION_V1_TYPE = "https://eips.ethereum.org/EIPS/eip-8004#registration-v1"

KNOWN_SERVICE_NAMES = {"web", "a2a", "mcp", "oasf", "ens", "did", "email"}
KNOWN_TRUST = {"reputation", "crypto-economic", "tee-attestation"}

_CAIP2_RE = re.compile(r"^eip155:(\d+):(0x[0-9a-fA-F]{40})$")

# 保留/不可路由域名。指向这些的端点是「根本没打算对外服务」，
# 既不是「活」也不是「服务器挂了」，必须单列（实施规划 §7）。
_UNROUTABLE_HOSTS = {"localhost", "localhost.localdomain", "example.com", "example.org",
                     "example.net", "test", "invalid", "local"}

# 非 DNS 命名空间。这些【不是】「域名解析失败」，而是根本不走 DNS ——
# 混进 L3a 会系统性高估 DNS 失败率。
# .agent 不是有效 TLD（实测大量 agent card 用它），.eth/.crypto 等是链上命名。
_NON_DNS_TLDS = (".eth", ".crypto", ".nft", ".dao", ".x", ".wallet", ".bitcoin",
                 ".blockchain", ".onion", ".agent")


def _is_routable(host: str | None) -> bool:
    if not host:
        return False
    h = host.lower().rstrip(".")
    if h in _UNROUTABLE_HOSTS or h.endswith((".local", ".localhost", ".test",
                                            ".invalid", ".example")):
        return False
    if h.endswith(_NON_DNS_TLDS):
        return False
    try:
        ip = ipaddress.ip_address(h)
        return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
                    or ip.is_multicast or ip.is_unspecified)
    except ValueError:
        pass
    return "." in h  # 无点的裸主机名不是公网可路由的


def parse_endpoint_host(endpoint: str | None) -> tuple[str | None, str | None]:
    if not endpoint or not isinstance(endpoint, str):
        return None, None
    ep = endpoint.strip()
    if "://" not in ep:
        if ep.startswith("did:") or "@" in ep:
            return None, ep.split(":")[0] if ep.startswith("did:") else "mailto"
        ep = "https://" + ep
    try:
        u = urlparse(ep)
        return (u.hostname or None), (u.scheme or None)
    except ValueError:
        return None, None


def parse_caip2(value: Any) -> tuple[int | None, str | None]:
    if not isinstance(value, str):
        return None, None
    m = _CAIP2_RE.match(value.strip())
    if not m:
        return None, None
    return int(m.group(1)), m.group(2).lower()


def validate_strict(doc: dict) -> list[str]:
    """registration-v1 严格校验。返回错误列表，空表示通过。"""
    errs: list[str] = []
    if doc.get("type") != REGISTRATION_V1_TYPE:
        errs.append(f"type != registration-v1 (got {doc.get('type')!r})")
    if not isinstance(doc.get("name"), str) or not doc.get("name"):
        errs.append("name 缺失或非字符串")
    svcs = doc.get("services")
    if svcs is None:
        errs.append("services 缺失")
    elif not isinstance(svcs, list):
        errs.append("services 不是数组")
    else:
        for i, s in enumerate(svcs):
            if not isinstance(s, dict):
                errs.append(f"services[{i}] 不是对象")
                continue
            if not s.get("name"):
                errs.append(f"services[{i}].name 缺失")
            if not s.get("endpoint"):
                errs.append(f"services[{i}].endpoint 缺失")
    regs = doc.get("registrations")
    if regs is not None and not isinstance(regs, list):
        errs.append("registrations 不是数组")
    st = doc.get("supportedTrust")
    if st is not None and not isinstance(st, list):
        errs.append("supportedTrust 不是数组")
    return errs


def parse_card(raw: bytes | str, chain_id: int, agent_id: int, content_sha256: str | None = None) -> dict:
    """→ {"card": {...}, "services": [...], "registrations": [...]}"""
    base = {
        "chain_id": chain_id,
        "agent_id": agent_id,
        "content_sha256": content_sha256,
        "parsed_lenient": False,
        "schema_valid_strict": False,
        "schema_errors": None,
        "type_field": None,
        "name": None,
        "description": None,
        "image": None,
        "active": None,
        "x402_support": None,
        "supported_trust": None,
        "service_count": 0,
    }
    out: dict[str, Any] = {"card": base, "services": [], "registrations": []}

    try:
        doc = json.loads(raw)
    except Exception as e:  # noqa: BLE001
        base["schema_errors"] = json.dumps([f"json_decode:{type(e).__name__}"], ensure_ascii=False)
        return out
    if not isinstance(doc, dict):
        base["schema_errors"] = json.dumps(["顶层不是 JSON 对象"], ensure_ascii=False)
        return out

    errs = validate_strict(doc)
    base["schema_valid_strict"] = not errs
    base["schema_errors"] = json.dumps(errs, ensure_ascii=False) if errs else None
    base["type_field"] = doc.get("type") if isinstance(doc.get("type"), str) else None
    base["name"] = doc.get("name") if isinstance(doc.get("name"), str) else None
    base["description"] = doc.get("description") if isinstance(doc.get("description"), str) else None
    base["image"] = doc.get("image") if isinstance(doc.get("image"), str) else None
    base["active"] = doc.get("active") if isinstance(doc.get("active"), bool) else None
    base["x402_support"] = doc.get("x402Support") if isinstance(doc.get("x402Support"), bool) else None
    st = doc.get("supportedTrust")
    base["supported_trust"] = [s for s in st if isinstance(s, str)] if isinstance(st, list) else None

    svcs = doc.get("services")
    if isinstance(svcs, list):
        for i, s in enumerate(svcs):
            if not isinstance(s, dict):
                continue
            ep = s.get("endpoint")
            host, scheme = parse_endpoint_host(ep if isinstance(ep, str) else None)
            out["services"].append({
                "chain_id": chain_id,
                "agent_id": agent_id,
                "service_idx": i,
                "service_name": s.get("name") if isinstance(s.get("name"), str) else None,
                "endpoint": ep if isinstance(ep, str) else None,
                "version": s.get("version") if isinstance(s.get("version"), str) else None,
                "endpoint_host": host,
                "endpoint_scheme": scheme,
                "is_routable": _is_routable(host),
            })
    base["service_count"] = len(out["services"])

    # 能拿到 name 或至少一个 service 就算宽容解析成功
    base["parsed_lenient"] = bool(base["name"]) or base["service_count"] > 0

    regs = doc.get("registrations")
    if isinstance(regs, list):
        seen = set()
        for r in regs:
            if not isinstance(r, dict):
                continue
            cid, registry = parse_caip2(r.get("agentRegistry"))
            aid = r.get("agentId")
            if not isinstance(aid, int):
                try:
                    aid = int(str(aid))
                except (TypeError, ValueError):
                    aid = None
            key = (cid, aid)
            if cid is None or aid is None or key in seen:
                continue
            seen.add(key)
            out["registrations"].append({
                "chain_id": chain_id,
                "agent_id": agent_id,
                "claimed_chain_id": cid,
                "claimed_registry": registry,
                "claimed_agent_id": aid,
            })

    return out
