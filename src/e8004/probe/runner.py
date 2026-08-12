"""探测调度：按 host 分桶的并发模型 + 四层流水。

【为什么必须按 host 分桶】(实施规划 §5 Stage 06)
per-host 限速是 1 req/3s。如果直接起 N 个 worker 从一个全局队列取任务，同一个
host 的多个目标会被不同 worker 抢到，然后全都卡在 per-host 令牌上空等 ——
全局吞吐会塌成个位数。正确做法是：按 host 分桶，一个 worker 独占一个 host 的
所有目标并串行处理。
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx

from .config import ProbeConfig
from .layers import (
    parse_endpoint,
    probe_a2a,
    probe_dns,
    probe_http,
    probe_mcp,
    probe_tcp,
    probe_tls,
    probe_web,
    strip_private,
)
from .limiter import DualLimiter, HostBlocked

SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class ProbeTarget:
    endpoint: str
    declared_kind: str  # web | A2A | MCP | OASF | ENS | DID | email
    ref: str | None = None  # 调用方的关联键，原样回传


def _skeleton(target: ProbeTarget, host, port, scheme) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "ref": target.ref,
        "probed_at": datetime.now(UTC).isoformat(),
        "target": {
            "endpoint": target.endpoint,
            "declared_kind": target.declared_kind,
            "host": host,
            "port": port,
            "scheme": scheme,
        },
        "layers": {},
    }


def _skip(name: str, reason: str) -> dict:
    return {"outcome": "skip", "elapsed_ms": 0, "error": reason}


async def probe_one(
    target: ProbeTarget,
    cfg: ProbeConfig,
    limiter: DualLimiter,
    client: httpx.AsyncClient,
    lax_client: httpx.AsyncClient | None = None,
) -> dict:
    """单个端点的四层探测。只产出原始分层结果，【不下「是否算活」的结论】。"""
    host, port, scheme, _ = parse_endpoint(target.endpoint)
    out = _skeleton(target, host, port, scheme)
    L = out["layers"]

    if not host:
        L["dns"] = {"outcome": "fail", "elapsed_ms": 0, "resolved_ips": [], "ip_class": None,
                    "error": "unparseable_endpoint"}
        for k in ("tcp", "tls", "http", "proto"):
            L[k] = _skip(k, "no_host")
        return out

    if limiter.is_blocked(host):
        for k in ("dns", "tcp", "tls", "http", "proto"):
            L[k] = {"outcome": "blocked", "elapsed_ms": 0, "error": limiter.block_reason(host)}
        return out

    # ---- L3a DNS
    dns = await probe_dns(host, cfg)
    L["dns"] = dns
    if dns["outcome"] != "ok":
        for k in ("tcp", "tls", "http", "proto"):
            L[k] = _skip(k, "dns_failed")
        return out

    ip = dns["resolved_ips"][0] if dns["resolved_ips"] else None

    # 不可路由的端点不发包 —— 打自己的内网没有意义，而且可能误伤本机服务
    if dns["ip_class"] in ("loopback", "private", "reserved"):
        for k in ("tcp", "tls", "http", "proto"):
            L[k] = _skip(k, f"unroutable:{dns['ip_class']}")
        return out

    # ---- L3b TCP / TLS
    try:
        async with limiter.acquire(host, ip):
            L["tcp"] = await probe_tcp(host, port, cfg)
    except HostBlocked as e:
        L["tcp"] = {"outcome": "blocked", "elapsed_ms": 0, "error": e.reason}
    if L["tcp"]["outcome"] != "ok":
        for k in ("tls", "http", "proto"):
            L[k] = _skip(k, "tcp_failed")
        return out

    if scheme == "https":
        async with limiter.acquire(host, ip):
            L["tls"] = await probe_tls(host, port, cfg)
        if L["tls"]["outcome"] != "ok":
            for k in ("http", "proto"):
                L[k] = _skip(k, "tls_failed")
            return out
    else:
        L["tls"] = _skip("tls", "plain_http")

    # ---- L3c HTTP
    # 证书有问题但服务活着时（tls_ok=False 而 outcome=ok），HTTP 层必须改用不校验的
    # 客户端 —— 否则「证书过期的活服务」会在 HTTP 层再被判死一次，
    # 前面 TLS 层刻意不判死就白做了。
    use_lax = lax_client is not None and L["tls"].get("tls_ok") is False
    http_client = lax_client if use_lax else client
    async with limiter.acquire(host, ip):
        http_res = await probe_http(http_client, target.endpoint, cfg)
    L["http"] = strip_private(http_res)
    if use_lax:
        L["http"]["tls_verification_skipped"] = True

    if http_res.get("status") in (429, 503):
        limiter.block_host(host, f"http_{http_res['status']}")
        L["proto"] = {"outcome": "rate_limited", "elapsed_ms": 0, "error": "backed_off"}
        return out

    if http_res["outcome"] != "ok":
        L["proto"] = _skip("proto", "http_failed")
        return out

    # ---- L3d 协议层
    def limiter_ctx():
        return limiter.acquire(host, ip)

    kind = (target.declared_kind or "web").upper()
    if kind == "A2A":
        L["proto"] = strip_private(await probe_a2a(http_client, target.endpoint, cfg, limiter_ctx))
    elif kind == "MCP":
        L["proto"] = strip_private(await probe_mcp(http_client, target.endpoint, cfg, limiter_ctx))
    elif kind in ("WEB", "OASF"):
        L["proto"] = await probe_web(http_res)
    else:
        # ENS / DID / email 等非 HTTP 端点：不适用协议层探测
        L["proto"] = _skip("proto", f"no_protocol_probe_for:{kind}")

    return out


async def probe_many(
    targets: Iterable[ProbeTarget],
    config: ProbeConfig,
    on_result: Callable[[dict], Awaitable[None]] | None = None,
    limiter: DualLimiter | None = None,
) -> list[dict]:
    """按 host 分桶并发探测。

    on_result 是流式回调：全量探测跑几小时，结果必须边产生边落盘，
    不能攒在内存里等最后返回。
    """
    limiter = limiter or DualLimiter(
        global_rps=config.global_rps,
        per_host_interval_s=config.per_host_interval_s,
        per_host_concurrency=config.per_host_concurrency,
        per_ip_interval_s=config.per_ip_interval_s,
    )
    limiter.load_blocklist(config.blocklist)

    buckets: dict[str, list[ProbeTarget]] = defaultdict(list)
    for t in targets:
        host, *_ = parse_endpoint(t.endpoint)
        buckets[host or "<unparseable>"].append(t)

    results: list[dict] = []
    queue: asyncio.Queue = asyncio.Queue()
    for host, items in buckets.items():
        queue.put_nowait((host, items))

    # verify=False 让 httpx 自己去造 context，而 truststore 注入后那条路径同样被接管。
    # 直接把注入前造好的 context 传进去才真的不校验。
    def _mk(verify):
        if verify is False:
            try:
                from .. import UNVERIFIED_SSL_CONTEXT

                verify = UNVERIFIED_SSL_CONTEXT
            except ImportError:
                pass
        return httpx.AsyncClient(
            timeout=httpx.Timeout(config.total_timeout_s, connect=config.connect_timeout_s,
                                  read=config.read_timeout_s),
            headers={"User-Agent": config.user_agent},
            follow_redirects=False,
            verify=verify,
            limits=httpx.Limits(max_connections=config.host_workers * 2),
        )

    async with _mk(True) as client, _mk(False) as lax_client:

        async def worker():
            while True:
                try:
                    host, items = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                try:
                    for t in items:  # 同一 host 串行 —— per-host 限速的前提
                        res = await probe_one(t, config, limiter, client, lax_client)
                        results.append(res)
                        if on_result:
                            await on_result(res)
                finally:
                    queue.task_done()

        await asyncio.gather(*[worker() for _ in range(min(config.host_workers, max(1, len(buckets))))])

    return results


def dry_run_plan(targets: Iterable[ProbeTarget], config: ProbeConfig) -> dict:
    """--dry-run：打印将发起的请求总数与预计耗时。全量探测前必须先跑一次核对量级。"""
    buckets: dict[str, int] = defaultdict(int)
    kinds: dict[str, int] = defaultdict(int)
    for t in targets:
        host, *_ = parse_endpoint(t.endpoint)
        buckets[host or "<unparseable>"] += 1
        kinds[(t.declared_kind or "web").upper()] += 1

    # 每个目标的请求数：tcp + tls + http + 协议层（MCP 最多 3 次）
    per_target = {"MCP": 6, "A2A": 4, "WEB": 3, "OASF": 3}
    total_requests = sum(per_target.get(k, 3) * n for k, n in kinds.items())

    n_hosts = len(buckets)
    by_global = total_requests / max(config.global_rps, 1e-9)
    # per-host 串行：单个 host 的耗时 = 它的请求数 × 间隔；总耗时受最慢的桶约束
    max_host_targets = max(buckets.values()) if buckets else 0
    by_host = max_host_targets * 6 * config.per_host_interval_s
    parallel = max(by_global / max(1, min(config.host_workers, n_hosts)) * min(config.host_workers, n_hosts),
                   by_global)

    return {
        "targets": sum(buckets.values()),
        "unique_hosts": n_hosts,
        "by_kind": dict(kinds),
        "estimated_requests": total_requests,
        "eta_seconds_global_bound": round(by_global, 1),
        "eta_seconds_slowest_host": round(by_host, 1),
        "eta_seconds": round(max(parallel, by_host), 1),
        "top_hosts": sorted(buckets.items(), key=lambda kv: -kv[1])[:10],
    }
