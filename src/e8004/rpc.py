"""JSON-RPC 客户端：重试、自适应区块步长、重组保护、部署区块二分查找。

调用方不感知步长收敛过程 —— get_logs_ranged 内部折半重试并把收敛值暴露在
`converged_range` 上，由 s02 回写 chain.max_log_range。
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import httpx
import structlog

log = structlog.get_logger(__name__)

# 「区块范围/结果集太大」——【折半重试有用】
_RANGE_HINTS = (
    "block range",
    "range is too",
    "range too",
    "query returned more than",
    "more than 10000 results",
    "response size",
    "result set too large",
    "exceed maximum block",
    "logs matched",
    "query timeout exceeded",
    "too many results",
)

# 「请求太频繁」——【折半重试没用，必须换端点 + 退避】
# 关键区分：BSC 公共节点返回的 `-32005: limit exceeded` 是速率限制，不是范围限制。
# 早先把两者混为一谈，导致把步长一路折半到 1 仍然失败然后抛出。
_RATE_HINTS = (
    "rate limit",
    "too many requests",
    "limit exceeded",
    "exceeded the quota",
    "request limit",
    "throttl",
    "capacity",
)


class RpcError(Exception):
    def __init__(self, code: int, message: str, method: str = ""):
        self.code = code
        self.message = message
        self.method = method
        super().__init__(f"[{method}] {code}: {message}")

    @property
    def _blob(self) -> str:
        return f"{self.message}".lower()

    @property
    def is_batch_too_large(self) -> bool:
        """批量调用条数超限。各家上限不同且不公布，只能按报错文本认。"""
        b = self._blob
        return ("in 1 batch" in b or "batch size" in b or "too many requests in batch" in b
                or "batch too large" in b or self.code == -32014)

    @property
    def is_range_error(self) -> bool:
        blob = self._blob
        if any(h in blob for h in _RANGE_HINTS):
            return True
        # -32005 两种含义都有人用：只有在措辞明确指向范围时才当范围错误
        return self.code == -32005 and any(w in blob for w in ("block", "range", "result"))

    @property
    def is_rate_limit(self) -> bool:
        if self.is_range_error:
            return False
        return any(h in self._blob for h in _RATE_HINTS) or self.code in (-32005, -32029, 429)


@dataclass
class LogBatch:
    from_block: int
    to_block: int
    logs: list[dict]


class RpcClient:
    """多端点轮转的 JSON-RPC 客户端。

    公共 RPC 会限流，而且不止用 429 —— publicnode 用 403，别家还有 -32029 之类。
    单端点客户端在全量扫描下必然中途死掉，所以端点是列表、失败即轮转。
    同时对每个端点做最小请求间隔：我们是研究项目，把免费 RPC 打爆和把别人的
    agent 端点打爆是同一个伦理问题。
    """

    def __init__(
        self,
        urls: str | list[str],
        *,
        user_agent: str,
        chain_id: int | None = None,
        max_retries: int = 4,
        timeout: float = 60.0,
        min_interval: float = 0.06,
    ):
        self.urls = [urls] if isinstance(urls, str) else list(urls)
        if not self.urls:
            raise ValueError("至少需要一个 RPC 端点")
        self.chain_id = chain_id
        # 至少把每个端点都试两轮 —— 公共 RPC 里常有个别永久性挂掉的（blockpi 会持续
        # 返 521），固定 4 次重试根本轮不到还活着的那个端点。
        self.max_retries = max(max_retries, len(self.urls) * 2)
        self.min_interval = min_interval
        self._idx = 0
        self._last_call: dict[str, float] = {}
        self._ts_chunk = 100      # 区块时间戳的批大小，撞到端点上限会自适应下调
        # 端点健康度：连续失败到阈值就隔离一段时间。
        # 只轮转不淘汰的话，坏端点会被反复转回来，把重试预算烧光。
        self._fails: dict[str, int] = {}
        self._quarantine_until: dict[str, float] = {}
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            headers={"Content-Type": "application/json", "User-Agent": user_agent},
            limits=httpx.Limits(max_connections=8),
        )
        self._id = 0
        self.converged_range: int | None = None

    QUARANTINE_AFTER = 3      # 连续失败几次后隔离
    QUARANTINE_SECONDS = 120  # 隔离多久

    @property
    def url(self) -> str:
        """挑一个未被隔离的端点；全被隔离时挑隔离期最早结束的那个。"""
        now = time.monotonic()
        n = len(self.urls)
        for k in range(n):
            u = self.urls[(self._idx + k) % n]
            if self._quarantine_until.get(u, 0.0) <= now:
                self._idx = (self._idx + k) % n
                return u
        return min(self.urls, key=lambda u: self._quarantine_until.get(u, 0.0))

    def _all_quarantined_for(self) -> float:
        """全部端点都在隔离期时，还要等多久才有一个可用。0 表示有可用端点。"""
        now = time.monotonic()
        soonest = min((self._quarantine_until.get(u, 0.0) for u in self.urls), default=0.0)
        return max(0.0, soonest - now)

    def _rotate(self, failed_url: str | None = None) -> None:
        if failed_url:
            self._fails[failed_url] = self._fails.get(failed_url, 0) + 1
            if self._fails[failed_url] >= self.QUARANTINE_AFTER:
                self._quarantine_until[failed_url] = time.monotonic() + self.QUARANTINE_SECONDS
                self._fails[failed_url] = 0
                log.debug("rpc_endpoint_quarantined", url=failed_url, seconds=self.QUARANTINE_SECONDS)
        self._idx += 1

    def _mark_ok(self, url: str) -> None:
        if url in self._fails:
            self._fails.pop(url, None)

    async def _pace(self, url: str) -> None:
        now = asyncio.get_running_loop().time()
        last = self._last_call.get(url, 0.0)
        wait = self.min_interval - (now - last)
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_call[url] = asyncio.get_running_loop().time()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.aclose()

    # ------------------------------------------------------------------ core

    async def call(self, method: str, params: list | None = None) -> Any:
        self._id += 1
        payload = {"jsonrpc": "2.0", "method": method, "params": params or [], "id": self._id}
        delay = 0.5
        last: Exception | None = None
        for attempt in range(self.max_retries):
            # 所有端点都在隔离期时【等它过去】，而不是继续硬撞。
            # 硬撞既拿不到数据，又是在给已经拒绝你的服务继续加压。
            wait_all = self._all_quarantined_for()
            if wait_all > 0:
                log.debug("rpc_all_endpoints_quarantined", wait_s=round(wait_all, 1))
                await asyncio.sleep(min(wait_all, 30.0))
            url = self.url
            await self._pace(url)
            try:
                r = await self._client.post(url, json=payload)
                # 429 是标准限流码，但 403 也被多家公共 RPC 当限流用（publicnode 就是），
                # 5xx 则是端点自己挂了（llamarpc 会返 521）。一律轮转端点 + 退避。
                if r.status_code in (403, 429) or r.status_code >= 500:
                    log.debug("rpc_endpoint_unavailable", url=url, status=r.status_code)
                    self._rotate(url)
                    last = httpx.HTTPStatusError(str(r.status_code), request=r.request, response=r)
                    await asyncio.sleep(min(delay, 8.0))
                    delay *= 1.6  # 端点多时别指数爆炸，轮转本身就是主要的缓解手段
                    continue
                # 400 要当【范围过大】处理，不能当普通传输错误。
                # 实测 celo 的公共 RPC 在窗口内日志太多时直接返 HTTP 400，
                # 而不是 JSON-RPC 的 range 错误码 —— 折半逻辑根本不会被触发，
                # 客户端把两个端点各重试几次后整条链直接崩（celo 9,766 个 agent 全丢）。
                # 交给上层折半；真的是请求格式错误的话，会一路折到最小步长后如实报错。
                if r.status_code == 400 and method == "eth_getLogs":
                    raise RpcError(-32000, "HTTP 400: block range too large", method)
                r.raise_for_status()
                body = r.json()
                if "error" in body:
                    err = RpcError(body["error"].get("code", 0), str(body["error"].get("message", "")), method)
                    if err.is_range_error:
                        raise err  # 交给上层折半，不在这里重试
                    last = err
                    if err.is_rate_limit:
                        # 速率限制：折半没用，换端点 + 退避
                        log.debug("rpc_rate_limited", url=url, msg=err.message[:60])
                        self._rotate(url)
                        await asyncio.sleep(delay)
                        delay *= 2
                        continue
                    if attempt == self.max_retries - 1:
                        raise err
                    self._rotate(url)
                else:
                    self._mark_ok(url)
                    return body["result"]
            except RpcError:
                raise
            except Exception as e:  # 网络层错误：换端点 + 退避重试
                last = e
                self._rotate(url)
            await asyncio.sleep(delay)
            delay *= 2
        raise last  # type: ignore[misc]

    async def batch(self, calls: list[tuple[str, list]]) -> list[Any]:
        """批量 JSON-RPC。返回顺序与入参一致；单条失败返回 RpcError 实例而不抛出。"""
        if not calls:
            return []
        payload = []
        for method, params in calls:
            self._id += 1
            payload.append({"jsonrpc": "2.0", "method": method, "params": params, "id": self._id})
        delay = 0.5
        for attempt in range(self.max_retries):
            url = self.url
            await self._pace(url)
            try:
                r = await self._client.post(url, json=payload)
                if r.status_code in (403, 429) or r.status_code >= 500:
                    self._rotate(url)
                    if attempt == self.max_retries - 1:
                        r.raise_for_status()
                    await asyncio.sleep(delay)
                    delay *= 2
                    continue
                r.raise_for_status()
                body = r.json()
                if isinstance(body, dict):  # 有些 RPC 对批量返回单个错误对象
                    raise RpcError(body.get("error", {}).get("code", 0), json.dumps(body)[:200], "batch")
                self._mark_ok(url)
                by_id = {item["id"]: item for item in body}
                out = []
                for item in payload:
                    got = by_id.get(item["id"], {})
                    if "error" in got:
                        out.append(RpcError(got["error"].get("code", 0), str(got["error"].get("message")), item["method"]))
                    else:
                        out.append(got.get("result"))
                return out
            except Exception:
                self._rotate(url)
                if attempt == self.max_retries - 1:
                    raise
                await asyncio.sleep(delay)
                delay *= 2
        return []

    # -------------------------------------------------------------- helpers

    async def block_number(self) -> int:
        return int(await self.call("eth_blockNumber"), 16)

    async def get_code(self, address: str, block: int | str = "latest") -> str:
        blk = hex(block) if isinstance(block, int) else block
        return await self.call("eth_getCode", [address, blk])

    async def eth_call(self, to: str, data: str, block: int | str = "latest") -> str:
        blk = hex(block) if isinstance(block, int) else block
        return await self.call("eth_call", [{"to": to, "data": data}, blk])

    async def get_storage_at(self, address: str, slot: str, block: int | str = "latest") -> str:
        blk = hex(block) if isinstance(block, int) else block
        return await self.call("eth_getStorageAt", [address, slot, blk])

    async def safe_head(self, confirmations: int, supports_finalized: bool) -> int:
        """扫描上界。一律用它，不用 latest（重组保护）。"""
        if supports_finalized:
            try:
                blk = await self.call("eth_getBlockByNumber", ["finalized", False])
                if blk and blk.get("number"):
                    return int(blk["number"], 16)
            except RpcError:
                # 只吞 RPC 层「不认识 finalized 标签」这一类错误。网络/TLS 错误必须
                # 冒出去 —— 在这里吞掉会把连不上伪装成「不支持 finalized」。
                log.warning("finalized_unsupported", url=self.url)
        return max(0, await self.block_number() - confirmations)

    async def get_block_timestamps(self, blocks: list[int]) -> dict[int, int]:
        """批量取区块时间戳。批大小遇到上限就自适应缩小。

        【为什么要自适应】各家 RPC 的 batch 上限差别很大且不公布：
        mainnet.base.org 只allow 10 个调用，超了直接 -32014 报错，
        整条链的扫描随之崩掉（实测 base 因此全军覆没一次）。
        固定 CHUNK 只要碰上更严格的端点就再挂一次，所以按错误信息回退。
        """
        out: dict[int, int] = {}
        chunk_size = self._ts_chunk
        i = 0
        while i < len(blocks):
            chunk = blocks[i : i + chunk_size]
            try:
                res = await self.batch([("eth_getBlockByNumber", [hex(b), False]) for b in chunk])
            except RpcError as e:
                if chunk_size > 1 and e.is_batch_too_large:
                    chunk_size = max(1, chunk_size // 4)
                    self._ts_chunk = chunk_size      # 记住，别每批都撞一次
                    log.info("batch_size_reduced", new_size=chunk_size, msg=e.message[:60])
                    continue
                raise
            for b, r in zip(chunk, res):
                if isinstance(r, dict) and r.get("timestamp"):
                    out[b] = int(r["timestamp"], 16)
            i += len(chunk)
        return out

    # --------------------------------------------------------- deploy block

    async def find_deploy_block(self, address: str, hi: int | None = None) -> int | None:
        """二分 eth_getCode 定位首个有代码的区块。约 25 次调用，需要 archive 节点。

        返回 None 表示该地址在链上没有代码。
        """
        if hi is None:
            hi = await self.block_number()
        if await self.get_code(address, hi) in ("0x", "0x0", ""):
            return None
        lo = 0
        # 先确认 archive 可用：查 0 号区块应返回空代码而不是报错
        try:
            await self.get_code(address, 0)
        except RpcError as e:
            raise RpcError(e.code, f"节点不支持历史查询（需要 archive 节点）: {e.message}", "eth_getCode")
        while lo < hi:
            mid = (lo + hi) // 2
            code = await self.get_code(address, mid)
            if code in ("0x", "0x0", ""):
                lo = mid + 1
            else:
                hi = mid
        return lo

    async def find_block_by_timestamp(self, target_ts: int, hi: int | None = None) -> int:
        """二分区块时间戳，定位 target_ts 之后的第一个区块。

        这是 find_deploy_block 的兜底：公共 RPC 多半不是 archive 节点，历史
        eth_getCode 会失败，但 eth_getBlockByNumber 所有节点都支持。
        约 25 次调用。
        """
        lo, hi = 0, hi if hi is not None else await self.block_number()
        while lo < hi:
            mid = (lo + hi) // 2
            blk = await self.call("eth_getBlockByNumber", [hex(mid), False])
            ts = int(blk["timestamp"], 16) if blk and blk.get("timestamp") else 0
            if ts < target_ts:
                lo = mid + 1
            else:
                hi = mid
        return lo

    async def find_first_log_block(
        self, address: str, topic: str, lo: int, hi: int, step: int = 10_000, max_calls: int = 400
    ) -> int | None:
        """从 lo 向前线性扫，返回首条匹配日志所在区块；没有则返回 None。

        为什么不二分：二分需要在 [lo, mid] 这种【超大区间】上查 eth_getLogs，而多数
        RPC 对 block range 有硬上限，一定会报 range error。之前那版在 range error
        时只放宽收敛精度却不改查询区间，会原地死循环 —— 线性扫虽然笨但有界且正确。

        调用次数上限 max_calls，超了返回 None（调用方退回时间戳兜底）。
        """
        cursor, calls = lo, 0
        while cursor <= hi and calls < max_calls:
            end = min(cursor + step - 1, hi)
            try:
                logs = await self.call(
                    "eth_getLogs",
                    [{"fromBlock": hex(cursor), "toBlock": hex(end), "address": address, "topics": [topic]}],
                )
                calls += 1
            except RpcError as e:
                if e.is_range_error and step > 1:
                    step = max(1, step // 2)
                    continue
                raise
            if logs:
                return min(int(x["blockNumber"], 16) for x in logs)
            cursor = end + 1
        return None

    # -------------------------------------------------- 端点完整性验证（关键）

    async def verify_endpoints_for_logs(
        self, address: str, topic: str, canary_block: int
    ) -> dict[str, str]:
        """把「对历史区间静默返回空」的端点找出来并永久禁用。

        【这是全项目最危险的一个 bug 类】
        rpc.flashbots.net 对超出其保留窗口的区块【不报错】，直接返回 `[]`。
        自适应步长涨到 5 万时 drpc 报范围错 → 轮转到 flashbots → flashbots 返回空 →
        扫描「成功」完成，87% 的区块扫出 0 条日志，数据被悄悄写坏。
        报错的端点是安全的，静默说谎的端点会毁掉整份报告。

        做法：拿一个【已知含有日志】的区块做金丝雀，逐个端点查它周围的窄区间。
        返回 0 条的端点就是在说谎，直接从本次运行的端点池里剔除。
        """
        verdicts: dict[str, str] = {}
        lo, hi = max(0, canary_block - 50), canary_block + 50
        alive: list[str] = []
        for u in list(self.urls):
            await self._pace(u)
            try:
                r = await self._client.post(
                    u,
                    json={
                        "jsonrpc": "2.0", "id": 1, "method": "eth_getLogs",
                        "params": [{"fromBlock": hex(lo), "toBlock": hex(hi),
                                    "address": address, "topics": [topic]}],
                    },
                )
                if r.status_code >= 400:
                    verdicts[u] = f"http_{r.status_code}"
                    alive.append(u)  # 报错是诚实的，保留
                    continue
                body = r.json()
                if "error" in body:
                    verdicts[u] = "errors_honestly"
                    alive.append(u)
                elif len(body.get("result", [])) == 0:
                    verdicts[u] = "SILENTLY_EMPTY"  # 说谎，剔除
                else:
                    verdicts[u] = f"ok:{len(body['result'])}"
                    alive.append(u)
            except Exception as e:  # noqa: BLE001
                verdicts[u] = f"exc:{type(e).__name__}"
                alive.append(u)

        liars = [u for u, v in verdicts.items() if v == "SILENTLY_EMPTY"]
        if liars:
            log.warning("rpc_endpoints_silently_empty", endpoints=liars)
            self.urls = alive or self.urls
            self._idx = 0
        return verdicts

    # ------------------------------------------------------------- getLogs

    async def get_logs_ranged(
        self,
        addresses: list[str],
        from_block: int,
        to_block: int,
        topics: list | None = None,
        start_range: int = 10_000,
        min_range: int = 1,
        max_range: int = 100_000,
    ) -> AsyncIterator[LogBatch]:
        """按自适应步长分段扫描。

        步长过大的错误在这里折半重试；连续 5 段成功则放大 1.5 倍。
        减到 min_range 仍失败则说明是真错误，抛出。
        """
        rng = max(min_range, min(start_range, max_range))
        cursor = from_block
        streak = 0
        while cursor <= to_block:
            end = min(cursor + rng - 1, to_block)
            params = [
                {
                    "fromBlock": hex(cursor),
                    "toBlock": hex(end),
                    "address": addresses if len(addresses) > 1 else addresses[0],
                    **({"topics": topics} if topics else {}),
                }
            ]
            try:
                logs = await self.call("eth_getLogs", params)
            except RpcError as e:
                if e.is_range_error and rng > min_range:
                    rng = max(min_range, rng // 2)
                    streak = 0
                    log.debug("range_halved", new_range=rng, at=cursor)
                    continue
                raise
            yield LogBatch(cursor, end, logs)
            cursor = end + 1
            streak += 1
            if streak >= 5 and rng < max_range:
                rng = min(max_range, int(rng * 1.5))
                streak = 0
            self.converged_range = rng
