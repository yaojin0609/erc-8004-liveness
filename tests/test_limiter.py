"""限速器实测。

【这几条是伦理红线的代码化，不能只靠 code review】(CLAUDE.md 硬约束 11)
起本地服务器记录到达时间戳，实测：
  * 同一 host 最小请求间隔 ≥ per_host_interval
  * 同一 host 最大并发 = 1
  * 多 host 并发时全局速率 ≤ global_rps
"""

from __future__ import annotations

import asyncio
import time

import pytest

from e8004.probe.limiter import DualLimiter, HostBlocked


async def _hit(limiter: DualLimiter, host: str, arrivals: list, live: dict, peak: dict, ip=None):
    async with limiter.acquire(host, ip):
        live[host] = live.get(host, 0) + 1
        peak[host] = max(peak.get(host, 0), live[host])
        arrivals.append((host, time.monotonic()))
        await asyncio.sleep(0.01)  # 模拟请求耗时
        live[host] -= 1


@pytest.mark.asyncio
async def test_per_host_interval_and_concurrency():
    """同一 host：最小间隔 ≥3s 是默认值，测试里用 0.2s 保持快速但语义相同。"""
    interval = 0.2
    limiter = DualLimiter(global_rps=1000, per_host_interval_s=interval, per_host_concurrency=1,
                          per_ip_interval_s=0.0)
    arrivals: list = []
    live: dict = {}
    peak: dict = {}

    await asyncio.gather(*[_hit(limiter, "a.example", arrivals, live, peak) for _ in range(6)])

    ts = sorted(t for _, t in arrivals)
    gaps = [b - a for a, b in zip(ts, ts[1:])]
    assert min(gaps) >= interval * 0.9, f"同一 host 出现了过密的请求: {gaps}"
    assert peak["a.example"] == 1, "同一 host 并发不是 1"


@pytest.mark.asyncio
async def test_global_rate_cap_across_many_hosts():
    """200 个不同 host 并发时，全局速率不得超过 global_rps。"""
    rps = 50.0
    n = 120
    limiter = DualLimiter(global_rps=rps, per_host_interval_s=0.0, per_host_concurrency=1,
                          per_ip_interval_s=0.0)
    arrivals: list = []
    live: dict = {}
    peak: dict = {}

    t0 = time.monotonic()
    await asyncio.gather(*[_hit(limiter, f"h{i}.example", arrivals, live, peak) for i in range(n)])
    elapsed = time.monotonic() - t0

    # 令牌桶初始有一桶容量，所以允许一个突发；用 (n - capacity)/rps 做下界
    lower_bound = (n - max(1.0, rps)) / rps
    assert elapsed >= lower_bound * 0.9, f"{n} 个请求只用了 {elapsed:.2f}s，超过了 {rps} rps"


@pytest.mark.asyncio
async def test_per_ip_limit_applies_across_distinct_hosts():
    """多个子域指向同一 IP 时，per-IP 限速必须生效 —— 只按 FQDN 限速等于没限。"""
    limiter = DualLimiter(global_rps=1000, per_host_interval_s=0.0, per_host_concurrency=1,
                          per_ip_interval_s=0.2)
    arrivals: list = []
    live: dict = {}
    peak: dict = {}

    await asyncio.gather(
        *[_hit(limiter, f"sub{i}.example", arrivals, live, peak, ip="203.0.113.9") for i in range(5)]
    )
    ts = sorted(t for _, t in arrivals)
    gaps = [b - a for a, b in zip(ts, ts[1:])]
    assert min(gaps) >= 0.18, f"同一 IP 的不同子域没有被限速: {gaps}"


@pytest.mark.asyncio
async def test_blocklist_raises_and_counts():
    limiter = DualLimiter()
    limiter.load_blocklist(["Blocked.Example"])
    assert limiter.is_blocked("blocked.example")
    with pytest.raises(HostBlocked):
        async with limiter.acquire("blocked.example"):
            pass
    assert limiter.stats["blocked_skips"] == 1


@pytest.mark.asyncio
async def test_block_host_after_429():
    limiter = DualLimiter()
    limiter.block_host("slow.example", "http_429")
    assert limiter.block_reason("slow.example") == "http_429"
