"""四层探测的各层实现：DNS / TCP / TLS / HTTP / 协议。

每层独立记录，这样才能报告【逐层衰减】而不只是一个终点通过率。
逐层衰减表是报告的核心图。
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import ssl
import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx

from .config import ProbeConfig


def _ms(t0: float) -> int:
    return int((time.monotonic() - t0) * 1000)


def classify_ip(value: str) -> str:
    """public / private / loopback / reserved。

    非 public 的端点是「根本没打算对外服务」，不是「服务器挂了」——
    这两者混为一谈会让整份报告的结论失真。
    """
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return "unknown"
    if ip.is_loopback:
        return "loopback"
    if ip.is_private or ip.is_link_local:
        return "private"
    if ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return "reserved"
    return "public"


def parse_endpoint(endpoint: str) -> tuple[str | None, int | None, str | None, bool]:
    """→ (host, port, scheme, host_is_ip_literal)"""
    ep = endpoint.strip()
    if "://" not in ep:
        ep = "https://" + ep
    # urlparse 是【惰性】的：它本身不校验，直到访问 .hostname / .port 才抛
    # ValueError。只把 try 包在 urlparse() 上是不够的 —— 实测 BSC 上有 agent 把
    # JSON 片段当 tokenURI（`"animal_kingdom": { "kingdoms": 1 ...`），urlparse
    # 把 ` {   "kingdoms": 1` 当成端口，一个畸形值就能掀翻整轮抓取。
    try:
        u = urlparse(ep)
        host = u.hostname
        scheme = u.scheme or "https"
        port = u.port or (443 if scheme == "https" else 80)
    except ValueError:
        return None, None, None, False
    if not host:
        return None, None, None, False
    is_literal = classify_ip(host) != "unknown"
    return host, port, scheme, is_literal


# ------------------------------------------------------------------------- DNS


async def probe_dns(host: str, cfg: ProbeConfig) -> dict:
    t0 = time.monotonic()
    lit = classify_ip(host)
    if lit != "unknown":
        # endpoint 直接写 IP 而不是域名 —— 单列一类
        return {
            "outcome": "ok",
            "elapsed_ms": 0,
            "resolved_ips": [host],
            "ip_class": "literal" if lit == "public" else lit,
            "error": None,
        }
    try:
        loop = asyncio.get_running_loop()
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP), timeout=cfg.dns_timeout_s
        )
        ips = sorted({i[4][0] for i in infos})
        if not ips:
            return {"outcome": "fail", "elapsed_ms": _ms(t0), "resolved_ips": [], "ip_class": None,
                    "error": "no_records"}
        classes = {classify_ip(i) for i in ips}
        # 有任何一个公网地址就算 public；全是私网/回环才归为不可路由
        ip_class = "public" if "public" in classes else sorted(classes)[0]
        return {"outcome": "ok", "elapsed_ms": _ms(t0), "resolved_ips": ips, "ip_class": ip_class, "error": None}
    except TimeoutError:
        return {"outcome": "fail", "elapsed_ms": _ms(t0), "resolved_ips": [], "ip_class": None, "error": "timeout"}
    except socket.gaierror as e:
        return {"outcome": "fail", "elapsed_ms": _ms(t0), "resolved_ips": [], "ip_class": None,
                "error": f"gaierror:{e.errno}"}
    except Exception as e:  # noqa: BLE001
        return {"outcome": "fail", "elapsed_ms": _ms(t0), "resolved_ips": [], "ip_class": None,
                "error": f"{type(e).__name__}"}


# ------------------------------------------------------------------- TCP / TLS


async def probe_tcp(host: str, port: int, cfg: ProbeConfig) -> dict:
    t0 = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=cfg.connect_timeout_s
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return {"outcome": "ok", "elapsed_ms": _ms(t0), "error": None}
    except TimeoutError:
        return {"outcome": "fail", "elapsed_ms": _ms(t0), "error": "connect_timeout"}
    except Exception as e:  # noqa: BLE001
        return {"outcome": "fail", "elapsed_ms": _ms(t0), "error": f"{type(e).__name__}"}


def _unverified_context() -> ssl.SSLContext:
    """真正不做校验的 TLS context（在 truststore 注入前构造，见 e8004/__init__.py）。"""
    try:
        from .. import UNVERIFIED_SSL_CONTEXT

        return UNVERIFIED_SSL_CONTEXT
    except ImportError:  # pragma: no cover
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx


def _cert_not_after(cert: dict | None) -> str | None:
    if not cert or "notAfter" not in cert:
        return None
    try:
        dt = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
        return dt.isoformat()
    except ValueError:
        return None


async def probe_tls(host: str, port: int, cfg: ProbeConfig) -> dict:
    """先做校验连接；失败则再做一次【不校验】连接纯粹用于分类。

    证书过期/自签/域名不匹配都【记录但不算 fail】—— 证书坏了的服务是活着的，
    把它算成死的是错的。
    """
    t0 = time.monotonic()
    ctx = ssl.create_default_context()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
            timeout=cfg.connect_timeout_s,
        )
        cert = writer.get_extra_info("peercert")
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return {"outcome": "ok", "elapsed_ms": _ms(t0), "tls_ok": True, "error_kind": None,
                "not_after": _cert_not_after(cert), "error": None}
    except ssl.SSLCertVerificationError as e:
        kind = _tls_error_kind(str(e))
    except TimeoutError:
        return {"outcome": "fail", "elapsed_ms": _ms(t0), "tls_ok": False, "error_kind": None,
                "not_after": None, "error": "timeout"}
    except Exception as e:  # noqa: BLE001
        return {"outcome": "fail", "elapsed_ms": _ms(t0), "tls_ok": False, "error_kind": None,
                "not_after": None, "error": f"{type(e).__name__}"}

    if not cfg.tls_classify_on_failure:
        return {"outcome": "ok", "elapsed_ms": _ms(t0), "tls_ok": False, "error_kind": kind,
                "not_after": None, "error": None}

    # 第二次：不校验，只为拿到证书做分类。outcome 仍是 ok —— 服务是活的。
    #
    # 必须用【注入前】的原始 SSLContext：truststore.inject_into_ssl() 会替换
    # ssl.SSLContext 类本身，接管所有实例，导致这次「不校验」的连接照样失败，
    # 于是证书过期的活服务被误判成死的 —— 正是本函数要避免的那个错误。
    lax = _unverified_context()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=lax, server_hostname=host),
            timeout=cfg.connect_timeout_s,
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return {"outcome": "ok", "elapsed_ms": _ms(t0), "tls_ok": False, "error_kind": kind,
                "not_after": None, "error": None}
    except Exception as e:  # noqa: BLE001
        return {"outcome": "fail", "elapsed_ms": _ms(t0), "tls_ok": False, "error_kind": kind,
                "not_after": None, "error": f"{type(e).__name__}"}


def _tls_error_kind(msg: str) -> str:
    """把证书校验失败归类。

    【必须同时认两套措辞】证书校验可能由 OpenSSL 做，也可能由 truststore 转交
    给系统验证器做（本仓用 truststore 走系统证书库）。两者文案完全不同：

        OpenSSL : "certificate verify failed: self-signed certificate"
        macOS   : "“*.badssl.com” certificate is not trusted"
        OpenSSL : "certificate has expired"          macOS: "certificate is expired"
        OpenSSL : "Hostname mismatch"                macOS: "certificate name does not match input"

    只按 OpenSSL 的写法匹配，在 macOS 上会把自签名/未知 CA 全归进 'other'，
    「证书有问题但服务活着」这条线就断了 —— 而那正是 L3 要区分的东西。
    """
    m = msg.lower()
    if "expired" in m or "has expired" in m:
        return "expired"
    if "self-signed" in m or "self signed" in m:
        return "self_signed"
    # macOS 的 "not trusted" 和 OpenSSL 的 "unable to get local issuer" 都无法
    # 区分「自签名」和「未知 CA」，所以单列一类，不硬塞进 self_signed 假装知道。
    if "not trusted" in m or "unable to get local issuer" in m or "unknown ca" in m:
        return "untrusted_ca"
    if ("hostname mismatch" in m or "doesn't match" in m or "not match" in m
            or "name does not match" in m):
        return "hostname_mismatch"
    if "revoked" in m:
        return "revoked"
    return "other"


# ------------------------------------------------------------------------ HTTP


async def probe_http(client: httpx.AsyncClient, url: str, cfg: ProbeConfig) -> dict:
    t0 = time.monotonic()
    try:
        r = await client.get(url, follow_redirects=True)
        body = r.content[: cfg.max_body_bytes]
        return {
            "outcome": "ok",
            "elapsed_ms": _ms(t0),
            "status": r.status_code,
            "server": r.headers.get("server"),
            "body_bytes": len(body),
            "error": None,
            "_body": body,
            "_final_url": str(r.url),
        }
    except httpx.TimeoutException:
        return {"outcome": "fail", "elapsed_ms": _ms(t0), "status": None, "server": None,
                "body_bytes": None, "error": "timeout"}
    except Exception as e:  # noqa: BLE001
        return {"outcome": "fail", "elapsed_ms": _ms(t0), "status": None, "server": None,
                "body_bytes": None, "error": f"{type(e).__name__}"}


# -------------------------------------------------------------------- 协议层


def _base(endpoint: str) -> str:
    u = urlparse(endpoint if "://" in endpoint else "https://" + endpoint)
    return urlunparse((u.scheme or "https", u.netloc, "", "", "", ""))


async def probe_a2a(client: httpx.AsyncClient, endpoint: str, cfg: ProbeConfig, limiter_ctx) -> dict:
    """A2A：拉 agent card。成功 = JSON 且含 name 且含 skills 或 capabilities。"""
    t0 = time.monotonic()
    root = _base(endpoint)
    last_err = None
    for path in cfg.a2a_card_paths:
        url = root.rstrip("/") + path
        try:
            async with limiter_ctx():
                r = await client.get(url, follow_redirects=True)
            if r.status_code != 200:
                last_err = f"http_{r.status_code}"
                continue
            doc = r.json()
            ok = isinstance(doc, dict) and "name" in doc and ("skills" in doc or "capabilities" in doc)
            return {
                "outcome": "ok" if ok else "fail",
                "elapsed_ms": _ms(t0),
                "kind": "a2a",
                "ok": ok,
                "version": doc.get("protocolVersion") or doc.get("version") if isinstance(doc, dict) else None,
                "server_name": doc.get("name") if isinstance(doc, dict) else None,
                "server_version": doc.get("version") if isinstance(doc, dict) else None,
                "tool_count": len(doc.get("skills", [])) if isinstance(doc, dict) else None,
                "capabilities": doc.get("capabilities") if isinstance(doc, dict) else None,
                "error": None if ok else "schema_mismatch",
                "_card_url": url,
            }
        except json.JSONDecodeError:
            last_err = "not_json"
        except Exception as e:  # noqa: BLE001
            last_err = type(e).__name__
    return {"outcome": "fail", "elapsed_ms": _ms(t0), "kind": "a2a", "ok": False, "version": None,
            "server_name": None, "server_version": None, "tool_count": None, "capabilities": None,
            "error": last_err or "unknown"}


async def probe_mcp(client: httpx.AsyncClient, endpoint: str, cfg: ProbeConfig, limiter_ctx) -> dict:
    """MCP：Streamable HTTP 的 initialize 握手，失败 fallback 到 SSE。

    只读调用：initialize → notifications/initialized → tools/list（可关）。
    「声称是 MCP agent 但暴露 0 个 tool」是极有价值的发现，所以 tools/list 值得那一次调用。
    """
    t0 = time.monotonic()
    init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": cfg.mcp_protocol_version,
            "capabilities": {},
            "clientInfo": {"name": "erc8004-research-scanner", "version": "1.0"},
        },
    }
    headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    try:
        async with limiter_ctx():
            r = await client.post(endpoint, json=init, headers=headers, follow_redirects=True)
        doc = _parse_maybe_sse(r)
        result = (doc or {}).get("result") if isinstance(doc, dict) else None
        if not result or "serverInfo" not in result:
            return {"outcome": "fail", "elapsed_ms": _ms(t0), "kind": "mcp_streamable", "ok": False,
                    "version": None, "server_name": None, "server_version": None, "tool_count": None,
                    "capabilities": None, "error": f"no_serverinfo_http_{r.status_code}"}
        info = result.get("serverInfo", {})
        out = {
            "outcome": "ok", "elapsed_ms": _ms(t0), "kind": "mcp_streamable", "ok": True,
            "version": result.get("protocolVersion"),
            "server_name": info.get("name"), "server_version": info.get("version"),
            "tool_count": None, "capabilities": result.get("capabilities"), "error": None,
        }
        if cfg.mcp_call_tools_list:
            sid = r.headers.get("mcp-session-id")
            h2 = dict(headers)
            if sid:
                h2["Mcp-Session-Id"] = sid
            try:
                async with limiter_ctx():
                    await client.post(
                        endpoint,
                        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                        headers=h2, follow_redirects=True,
                    )
                async with limiter_ctx():
                    r2 = await client.post(
                        endpoint,
                        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                        headers=h2, follow_redirects=True,
                    )
                d2 = _parse_maybe_sse(r2)
                tools = ((d2 or {}).get("result") or {}).get("tools")
                if isinstance(tools, list):
                    out["tool_count"] = len(tools)
            except Exception:  # noqa: BLE001
                pass
        return out
    except Exception as e:  # noqa: BLE001
        return {"outcome": "fail", "elapsed_ms": _ms(t0), "kind": "mcp_streamable", "ok": False,
                "version": None, "server_name": None, "server_version": None, "tool_count": None,
                "capabilities": None, "error": type(e).__name__}


def _parse_maybe_sse(r: httpx.Response) -> dict | None:
    """MCP Streamable HTTP 可能返回 application/json 或 text/event-stream。"""
    ctype = r.headers.get("content-type", "")
    text = r.text
    if "text/event-stream" in ctype:
        for line in text.splitlines():
            if line.startswith("data:"):
                try:
                    return json.loads(line[5:].strip())
                except json.JSONDecodeError:
                    continue
        return None
    try:
        return r.json()
    except Exception:  # noqa: BLE001
        return None


async def probe_web(http_layer: dict) -> dict:
    """web 端点：HTTP 2xx 即通过。"""
    st = http_layer.get("status")
    ok = st is not None and 200 <= st < 300
    return {
        "outcome": "ok" if ok else "fail",
        "elapsed_ms": 0,
        "kind": "web",
        "ok": ok,
        "version": None,
        "server_name": None,
        "server_version": None,
        "tool_count": None,
        "capabilities": None,
        "error": None if ok else f"http_{st}",
    }


def strip_private(d: dict[str, Any]) -> dict[str, Any]:
    """去掉 _ 开头的内部字段，得到符合输出契约的层结果。"""
    return {k: v for k, v in d.items() if not k.startswith("_")}
