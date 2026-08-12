"""三层限速器。

【这是伦理红线的代码化，不是性能旋钮】(CLAUDE.md 硬约束 11)

  全局 rps        —— 你在聚合层面的礼貌度
  per-host 间隔   —— 真正重要的那个。只有全局限速的话，10 req/s 可以全砸在
                     同一台服务器上，那就是压测别人而不是做研究
  per-IP 间隔     —— 大量 agent 端点是同一台机器的不同子域，只按 FQDN 限速
                     等于没限。本项目预期正是这个场景

令牌桶用单调时钟，不做 sleep 累加。
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from contextlib import asynccontextmanager


class _Bucket:
    """单调时钟令牌桶。"""

    __slots__ = ("capacity", "last", "rate", "tokens")

    def __init__(self, rate: float, capacity: float | None = None):
        self.rate = rate
        self.capacity = capacity if capacity is not None else max(1.0, rate)
        self.tokens = self.capacity
        self.last = time.monotonic()

    def _refill(self) -> None:
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
        self.last = now

    def time_until_token(self) -> float:
        self._refill()
        if self.tokens >= 1.0:
            return 0.0
        return (1.0 - self.tokens) / self.rate

    def consume(self) -> None:
        self.tokens -= 1.0


class DualLimiter:
    """全局桶 + per-host 桶 + per-IP 桶 + per-host 并发信号量。

    调用方必须 `async with limiter.acquire(host, ip):` 才能发请求。
    """

    def __init__(
        self,
        global_rps: float = 10.0,
        per_host_interval_s: float = 3.0,
        per_host_concurrency: int = 1,
        per_ip_interval_s: float = 1.0,
        max_tracked_hosts: int = 200_000,
    ):
        self.global_bucket = _Bucket(global_rps)
        self.per_host_interval = per_host_interval_s
        self.per_ip_interval = per_ip_interval_s
        self.per_host_concurrency = per_host_concurrency
        self.max_tracked = max_tracked_hosts

        self._hosts: OrderedDict[str, _Bucket] = OrderedDict()
        self._ips: OrderedDict[str, _Bucket] = OrderedDict()
        self._sems: OrderedDict[str, asyncio.Semaphore] = OrderedDict()
        self._blocked: dict[str, str] = {}
        self._lock = asyncio.Lock()
        self.stats = {"acquired": 0, "blocked_skips": 0, "wait_total_s": 0.0}

    # ---------------------------------------------------------------- blocking

    def block_host(self, host: str, reason: str) -> None:
        self._blocked[host.lower()] = reason

    def is_blocked(self, host: str) -> bool:
        return host.lower() in self._blocked

    def block_reason(self, host: str) -> str | None:
        return self._blocked.get(host.lower())

    def load_blocklist(self, entries) -> None:
        for e in entries:
            self.block_host(e, "config/blocklist.txt")

    # ------------------------------------------------------------------ buckets

    def _lru(self, od: OrderedDict, key: str, factory):
        if key in od:
            od.move_to_end(key)
            return od[key]
        od[key] = factory()
        if len(od) > self.max_tracked:
            od.popitem(last=False)
        return od[key]

    def _host_bucket(self, host: str) -> _Bucket:
        return self._lru(self._hosts, host, lambda: _Bucket(1.0 / max(self.per_host_interval, 1e-9), 1.0))

    def _ip_bucket(self, ip: str) -> _Bucket:
        return self._lru(self._ips, ip, lambda: _Bucket(1.0 / max(self.per_ip_interval, 1e-9), 1.0))

    def _sem(self, host: str) -> asyncio.Semaphore:
        return self._lru(self._sems, host, lambda: asyncio.Semaphore(self.per_host_concurrency))

    # ------------------------------------------------------------------ acquire

    @asynccontextmanager
    async def acquire(self, host: str, ip: str | None = None):
        host = host.lower()
        if self.is_blocked(host):
            self.stats["blocked_skips"] += 1
            raise HostBlocked(host, self._blocked[host])

        sem = self._sem(host)
        async with sem:
            started = time.monotonic()
            while True:
                # 先拿 host/ip 令牌再拿全局令牌 —— 反过来会持着全局令牌空等，
                # 把全局吞吐拖垮。
                waits = [self._host_bucket(host).time_until_token()]
                if ip:
                    waits.append(self._ip_bucket(ip).time_until_token())
                w = max(waits)
                if w > 0:
                    await asyncio.sleep(w)
                    continue
                async with self._lock:
                    gw = self.global_bucket.time_until_token()
                    if gw <= 0:
                        self.global_bucket.consume()
                        self._host_bucket(host).consume()
                        if ip:
                            self._ip_bucket(ip).consume()
                        break
                await asyncio.sleep(gw)
            self.stats["wait_total_s"] += time.monotonic() - started
            self.stats["acquired"] += 1
            yield


class HostBlocked(Exception):
    def __init__(self, host: str, reason: str):
        self.host = host
        self.reason = reason
        super().__init__(f"{host} 在退出扫描名单中: {reason}")
