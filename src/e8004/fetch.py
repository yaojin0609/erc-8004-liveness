"""URI 抓取：data: / https: / ipfs: / 其它。内容寻址落盘。

失败分类学（13 类）是本模块的【核心交付物】，不是副产品 —— 报告里
「元数据可解析率」那个杀手级数字就是这张表。原始思路稿只列了 4 类。

注意 not_json 与 schema_invalid 的分工：
  * not_json      在这里判定 —— 能不能 parse
  * schema_invalid 在 s05 判定 —— parse 了但符不符合 registration-v1
把两者并列在同一层是概念混淆。
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlparse

import httpx

STATUSES = (
    "ok", "unsupported_scheme", "dns_fail", "tls_fail", "conn_timeout", "read_timeout",
    "conn_error", "rate_limited", "http_404", "http_4xx", "http_5xx", "too_large",
    "not_json", "ipfs_unresolvable", "sampled_out", "other",
)

# data: URI 的参数可以有任意多个，且实测存在这些变体：
#   data:application/json;enc=gzip;level=6;base64,<payload>   ← gzip 压缩
#   data:application/json;utf8,%7B...                          ← 额外参数 + 百分号编码
#   data:application/json;base64 <payload>                     ← 用空格代替逗号（畸形但可救）
# 原来的 `^data:([^;,]*)(;base64)?,(.*)$` 只认最规范的一种，把能解析的元数据
# 当成 malformed 丢掉了。
_DATA_RE = re.compile(r"^data:([^,]*)[,\s](.*)$", re.DOTALL | re.IGNORECASE)
_CID_RE = re.compile(r"^(?:ipfs://)?(?:ipfs/)?([A-Za-z0-9]+)(/.*)?$")


@dataclass
class FetchResult:
    uri: str
    scheme_kind: str
    status: str
    http_status: int | None = None
    final_url: str | None = None
    gateway_used: str | None = None
    content_sha256: str | None = None
    content_bytes: int | None = None
    content_type: str | None = None
    elapsed_ms: int = 0
    attempt_count: int = 1
    error_detail: str | None = None
    body: bytes | None = None  # 不入库，仅供调用方落盘

    def to_row(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if k != "body"}
        d["uri_normalized"] = d.pop("uri")
        return d


def classify_scheme(uri: str) -> str:
    u = uri.strip()
    low = u.lower()
    if low.startswith("data:"):
        return "data"
    # 实测有 agent 把 JSON 直接塞进 tokenURI，不加 data: 前缀（BSC 上不少）。
    # 归成 unsupported_scheme 等于把【能解析的元数据】算成解析不了，会低估 L1。
    if u.startswith("{") and u.endswith("}"):
        return "inline_json"
    if low.startswith("ipfs://") or low.startswith("/ipfs/"):
        return "ipfs"
    # 实测大量 agent 直接写 `https://ipfs.io/ipfs/<cid>`。当成普通 https 主机的话
    # 会走「别人的服务器」那档 1 请求/3 秒（8 千个要 6.8 小时），而且该网关挂了
    # 也不会回退到别的网关 —— 它本质就是 IPFS，应当按 IPFS 处理。
    if "/ipfs/" in low and (low.startswith("http://") or low.startswith("https://")):
        return "ipfs"
    if low.startswith("ar://"):
        return "ar"
    if low.startswith("did:"):
        return "did"
    if low.startswith("http://") or low.startswith("https://"):
        return "https"
    if low.endswith(".eth"):
        return "ens"
    return "other"


def normalize_uri(uri: str) -> str:
    """规范化用于去重。大量 agent 共享同一个 URI —— 去重系数决定这一步跑 2h 还是 20h。"""
    u = uri.strip()
    if classify_scheme(u) in ("https",):
        # urlparse 对畸形 IPv6（如 `https://[::1:bad/x`）会直接抛 ValueError。
        # 本函数在 collect_uris 里对【每一个】URI 调用，抛出来就会在比抓取更早的
        # 阶段掀翻整轮 —— 规范化失败就退回原串，不值得为它中断。
        try:
            p = urlparse(u)
            scheme = p.scheme.lower()
            netloc = p.netloc.lower()
            path, query = p.path, p.query
        except ValueError:
            return u
        # 去掉默认端口
        if (scheme == "https" and netloc.endswith(":443")) or (scheme == "http" and netloc.endswith(":80")):
            netloc = netloc.rsplit(":", 1)[0]
        return f"{scheme}://{netloc}{path or '/'}" + (f"?{query}" if query else "")
    return u


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def blob_path(root: Path, sha: str) -> Path:
    return Path(root) / "data" / "raw" / sha[:2] / sha


def store_blob(root: Path, content: bytes) -> str:
    """内容寻址落盘，同内容不重复存。"""
    sha = sha256_hex(content)
    p = blob_path(root, sha)
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)
    return sha


def read_blob(root: Path, sha: str) -> bytes | None:
    p = blob_path(root, sha)
    return p.read_bytes() if p.exists() else None


# ------------------------------------------------------------------- data URI


def fetch_inline_json(uri: str) -> FetchResult:
    """tokenURI 里直接放 JSON（无 data: 前缀）。进程内解析，零网络。"""
    t0 = time.monotonic()
    content = uri.strip().encode("utf-8")
    status = "ok"
    try:
        json.loads(content)
    except Exception:  # noqa: BLE001
        status = "not_json"
    return FetchResult(
        uri, "inline_json", status,
        content_sha256=sha256_hex(content), content_bytes=len(content),
        content_type="application/json", elapsed_ms=int((time.monotonic() - t0) * 1000),
        body=content,
    )


def fetch_data_uri(uri: str) -> FetchResult:
    """进程内解析，零网络。先跑完这部分，立刻有产出。"""
    t0 = time.monotonic()
    m = _DATA_RE.match(uri.strip())
    if not m:
        return FetchResult(uri, "data", "other", error_detail="malformed_data_uri")
    header, payload = m.group(1), m.group(2)
    parts = [p.strip().lower() for p in header.split(";")]
    mediatype = parts[0] if parts else ""
    is_b64 = "base64" in parts
    is_gzip = any(p in ("enc=gzip", "gzip", "encoding=gzip") for p in parts)
    try:
        if is_b64:
            content = base64.b64decode(payload + "=" * (-len(payload) % 4))
        else:
            content = unquote(payload).encode("utf-8")
        if is_gzip:
            import gzip as _gz

            content = _gz.decompress(content)
    except Exception as e:  # noqa: BLE001
        return FetchResult(uri, "data", "other", error_detail=f"decode:{type(e).__name__}")

    status = "ok"
    try:
        json.loads(content)
    except Exception:  # noqa: BLE001
        status = "not_json"
    return FetchResult(
        uri, "data", status,
        content_sha256=sha256_hex(content), content_bytes=len(content),
        content_type=mediatype or None, elapsed_ms=int((time.monotonic() - t0) * 1000),
        body=content,
    )


# ------------------------------------------------------------------------ IPFS


def extract_cid(uri: str) -> tuple[str, str] | None:
    """支持三种形态：ipfs://<cid>、/ipfs/<cid>、https://<gateway>/ipfs/<cid>。
    后面都可再带 /path/file.json。"""
    u = uri.strip()
    low = u.lower()
    if low.startswith("ipfs://"):
        u = u[7:]
    elif low.startswith("/ipfs/"):
        u = u[6:]
    elif "/ipfs/" in low and (low.startswith("http://") or low.startswith("https://")):
        u = u[low.index("/ipfs/") + 6:]
    else:
        return None
    m = _CID_RE.match(u)
    if not m:
        return None
    return m.group(1), (m.group(2) or "")


# ------------------------------------------------------------------ HTTP 抓取


def _http_status_bucket(code: int) -> str:
    if code == 404:
        return "http_404"
    if 400 <= code < 500:
        return "http_4xx"
    if code >= 500:
        return "http_5xx"
    return "ok"


def _exc_status(e: Exception) -> tuple[str, str]:
    name = type(e).__name__
    if isinstance(e, httpx.ConnectTimeout):
        return "conn_timeout", name
    if isinstance(e, httpx.ReadTimeout):
        return "read_timeout", name
    if isinstance(e, httpx.TimeoutException):
        return "conn_timeout", name
    msg = str(e).lower()
    if isinstance(e, httpx.ConnectError):
        if "name or service not known" in msg or "nodename nor servname" in msg or "getaddrinfo" in msg:
            return "dns_fail", name
        if "certificate" in msg or "ssl" in msg:
            return "tls_fail", name
        return "conn_error", name   # 单列，不要塞进 other 桶
    if "certificate" in msg or "ssl" in msg:
        return "tls_fail", name
    return "other", name


async def fetch_http(
    client: httpx.AsyncClient, url: str, *, max_bytes: int, kind: str = "https",
    gateway: str | None = None,
) -> FetchResult:
    t0 = time.monotonic()
    try:
        r = await client.get(url, follow_redirects=True)
    except Exception as e:  # noqa: BLE001
        status, detail = _exc_status(e)
        return FetchResult(url, kind, status, error_detail=detail,
                           elapsed_ms=int((time.monotonic() - t0) * 1000), gateway_used=gateway)

    body = r.content
    too_large = len(body) > max_bytes
    if too_large:
        body = body[:max_bytes]

    bucket = _http_status_bucket(r.status_code)
    if bucket != "ok":
        return FetchResult(url, kind, bucket, http_status=r.status_code, final_url=str(r.url),
                           content_bytes=len(body), gateway_used=gateway,
                           elapsed_ms=int((time.monotonic() - t0) * 1000))
    if too_large:
        return FetchResult(url, kind, "too_large", http_status=r.status_code, final_url=str(r.url),
                           content_bytes=len(r.content), gateway_used=gateway,
                           elapsed_ms=int((time.monotonic() - t0) * 1000))

    status = "ok"
    try:
        json.loads(body)
    except Exception:  # noqa: BLE001
        status = "not_json"

    return FetchResult(
        url, kind, status, http_status=r.status_code, final_url=str(r.url),
        content_sha256=sha256_hex(body), content_bytes=len(body),
        content_type=r.headers.get("content-type"), gateway_used=gateway,
        elapsed_ms=int((time.monotonic() - t0) * 1000), body=body,
    )
