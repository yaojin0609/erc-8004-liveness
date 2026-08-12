"""T2 —— 当前状态快照。Multicall3 批量读 ownerOf / tokenURI / getAgentWallet。

【为什么这个 stage 比日志扫描更重要】
本项目的核心问题「9.8 万个身份里有多少真活着」需要的四样东西 ——
agent 总数、owner、agentURI、agent wallet —— 全都是【当前状态】，
用 eth_call 就能读，不需要 archive 节点。

而免费公共 RPC 普遍不提供历史日志（publicnode 要 token、drpc 免费档不路由
archive、flashbots 只留约 9000 个区块且【静默返回空】）。所以：
  * 日志扫描给的是 registration 时间戳、反馈、转让历史（队列分析和 L4 需要）
  * 状态快照给的是 L0→L3 漏斗需要的一切

没有 archive key 时，本 stage 单独就能撑起整份报告的主体。

agent 总数用 ownerOf 二分：ERC-721 的 agentId 从 0 顺序递增，
「最大的不 revert 的 id」就是总数 - 1。约 17 次调用，任何节点都能跑。
"""

from __future__ import annotations

import asyncio

import structlog

from ..abi import decode_result, encode_call, selector
from ..config import ChainConfig, Config
from ..rpc import RpcClient, RpcError
from ..spool import Spool

log = structlog.get_logger(__name__)

STAGE = "snapshot-state"

MULTICALL3 = "0xca11bde05977b3631167028862be2a173976ca11"
AGGREGATE3 = "aggregate3((address,bool,bytes)[])"


def _encode_aggregate3(calls: list[tuple[str, bool, bytes]]) -> str:
    from eth_abi.abi import encode

    body = encode(["(address,bool,bytes)[]"], [calls]).hex()
    return selector(AGGREGATE3) + body


def _decode_aggregate3(raw: str) -> list[tuple[bool, bytes]]:
    return decode_result(["(bool,bytes)[]"], raw)[0]


async def _owner_of_ok(rpc: RpcClient, identity: str, agent_id: int) -> bool:
    """ownerOf 不 revert 即该 id 存在。已销毁的会 revert —— 二分上界因此可能偏小，
    所以最后还要用一次线性外推校正（见 count_agents）。"""
    try:
        raw = await rpc.eth_call(identity, encode_call("ownerOf(uint256)", ["uint256"], [agent_id]))
        return bool(raw and raw != "0x" and int(raw, 16) != 0)
    except RpcError:
        return False


async def _owner_of_many(rpc: RpcClient, identity: str, ids: list[int]) -> dict[int, bool]:
    """一次 Multicall3 批量测多个 id 的 ownerOf 是否成功（allowFailure=True）。"""
    target = bytes.fromhex(identity[2:])
    calls = [
        (target, True, bytes.fromhex(encode_call("ownerOf(uint256)", ["uint256"], [i])[2:]))
        for i in ids
    ]
    raw = await rpc.eth_call(MULTICALL3, _encode_aggregate3(calls))
    res = _decode_aggregate3(raw)
    out = {}
    for i, (ok, data) in zip(ids, res):
        out[i] = bool(ok and data and int.from_bytes(data[-20:], "big") != 0)
    return out


async def count_agents(rpc: RpcClient, identity: str, hi_guess: int = 1 << 24,
                       probe_width: int = 400) -> int:
    """→ 已铸造的 agent 总数（= 最大存在 id + 1）。不需要 archive 节点。

    【为什么用 Multicall3 而不是逐个 ownerOf 二分】
    朴素二分要 ~34 次【串行】RPC 调用。公共 RPC 一限流，每次都要退避重试，
    整条链能跑到几分钟甚至超时 —— 实测以太坊就卡在这里。
    改成一次 multicall 测几百个 id：指数段 1 次调用，之后每次调用把区间收敛
    probe_width 倍。总共约 3 次调用，抗限流能力天差地别。
    """
    # ---- 第 1 次调用：指数刻度，一次定位数量级
    powers = [0] + [1 << k for k in range(1, hi_guess.bit_length())]
    powers = [p for p in powers if p <= hi_guess]
    got = await _owner_of_many(rpc, identity, powers)
    if not got.get(0):
        return 0
    alive = [p for p in powers if got.get(p)]
    dead = [p for p in powers if not got.get(p)]
    lo = max(alive)
    hi = min(dead) if dead else hi_guess
    if hi <= lo:
        return lo + 1

    # ---- 后续调用：区间内等距取样，每次收敛 probe_width 倍
    for _ in range(24):
        if hi - lo <= 1:
            break
        step = max(1, (hi - lo) // probe_width)
        grid = list(range(lo + step, hi, step))[:probe_width]
        if not grid:
            break
        got = await _owner_of_many(rpc, identity, grid)
        alive = [i for i in grid if got.get(i)]
        dead = [i for i in grid if not got.get(i)]
        if alive:
            lo = max(lo, max(alive))
        if dead:
            hi = min(hi, min(dead))
        # 【不能在 step==1 时就 break】：grid 被 [:probe_width] 截断时并没有覆盖到 hi，
        # 提前退出会得到偏小的结果。让循环自己收敛到 hi-lo<=1。

    # ---- 边界校正（必须做）
    #
    # Multicall3 的 allowFailure=True 把两种情况返回成同一个 success=False：
    #   (a) token 不存在 —— 我们想要的信号
    #   (b) 内部调用 gas 不足 —— 批量太大时会发生，BSC 的 eth_call gas 上限尤其紧
    # 于是「批次靠后的 id」会被误判成不存在，二分提前收敛，总数偏小。
    # 实测 BSC 就栽在这里：算出 262,978，但 ownerOf(262,979) 明明成功。
    #
    # 用【小批量】沿边界向前试探来自我纠正：小批量不会触发 gas 上限。
    n = lo + 1
    for _ in range(200):
        probe = list(range(n, n + 20))
        got = await _owner_of_many(rpc, identity, probe)
        alive = [i for i in probe if got.get(i)]
        if not alive:
            break
        log.debug("count_boundary_extended", frm=n, to=max(alive) + 1)
        n = max(alive) + 1
    return n


async def read_state_batch(
    rpc: RpcClient, identity: str, ids: list[int], *, batch_size: int = 150
) -> list[dict]:
    """Multicall3 批量读三个字段。allowFailure=True —— 已销毁 agent 的 ownerOf 会
    revert，不能让整批失败。"""
    out: list[dict] = []
    target = bytes.fromhex(identity[2:])
    i = 0
    while i < len(ids):
        chunk = ids[i : i + batch_size]
        calls: list[tuple[bytes, bool, bytes]] = []
        for aid in chunk:
            calls.append((target, True, bytes.fromhex(encode_call("ownerOf(uint256)", ["uint256"], [aid])[2:])))
            calls.append((target, True, bytes.fromhex(encode_call("tokenURI(uint256)", ["uint256"], [aid])[2:])))
            calls.append(
                (target, True, bytes.fromhex(encode_call("getAgentWallet(uint256)", ["uint256"], [aid])[2:]))
            )
        try:
            raw = await rpc.eth_call(MULTICALL3, _encode_aggregate3(calls))
            results = _decode_aggregate3(raw)
        except (RpcError, ValueError) as e:
            if batch_size > 10:
                batch_size = max(10, batch_size // 2)
                log.debug("multicall_batch_halved", new=batch_size, err=str(e)[:60])
                continue
            raise
        for j, aid in enumerate(chunk):
            ok_o, data_o = results[j * 3]
            ok_u, data_u = results[j * 3 + 1]
            ok_w, data_w = results[j * 3 + 2]
            owner = uri = wallet = None
            if ok_o and data_o:
                try:
                    owner = decode_result(["address"], "0x" + data_o.hex())[0].lower()
                except Exception:  # noqa: BLE001
                    pass
            if ok_u and data_u:
                try:
                    uri = decode_result(["string"], "0x" + data_u.hex())[0]
                except Exception:  # noqa: BLE001
                    pass
            if ok_w and data_w:
                try:
                    w = decode_result(["address"], "0x" + data_w.hex())[0].lower()
                    wallet = w if int(w, 16) != 0 else None
                except Exception:  # noqa: BLE001
                    pass
            out.append({"agent_id": aid, "current_owner": owner, "token_uri": uri, "agent_wallet": wallet})
        i += batch_size
    return out


async def snapshot_chain(
    cfg: Config,
    chain: ChainConfig,
    snapshot_id: str,
    *,
    limit: int | None = None,
    start_id: int = 0,
    spool: Spool | None = None,
    progress=None,
) -> dict:
    reg = cfg.registries_for(chain)
    own = spool is None
    spool = spool or Spool(cfg.root, STAGE)
    stats: dict = {"chain": chain.name, "total_agents": 0, "read": 0, "alive": 0, "with_uri": 0,
                   "with_wallet": 0}

    async with RpcClient(chain.rpcs, user_agent=cfg.user_agent, chain_id=chain.chain_id) as rpc:
        head = await rpc.safe_head(chain.confirmations, chain.supports_finalized)
        blk = await rpc.call("eth_getBlockByNumber", [hex(head), False])
        stats["head"] = head
        stats["block_hash"] = blk.get("hash") if blk else None
        stats["block_timestamp"] = int(blk["timestamp"], 16) if blk and blk.get("timestamp") else None

        total = await count_agents(rpc, reg.identity)
        stats["total_agents"] = total
        if total == 0:
            if own:
                spool.close()
            return stats

        end = total if limit is None else min(total, start_id + limit)
        ids = list(range(start_id, end))
        CH = 600
        for k in range(0, len(ids), CH):
            rows = await read_state_batch(rpc, reg.identity, ids[k : k + CH])
            for r in rows:
                stats["read"] += 1
                if r["current_owner"]:
                    stats["alive"] += 1
                if r["token_uri"]:
                    stats["with_uri"] += 1
                if r["agent_wallet"]:
                    stats["with_wallet"] += 1
                spool.write(
                    "agent_state",
                    {
                        "agent_id": r["agent_id"],
                        "snapshot_id": snapshot_id,
                        "current_owner": r["current_owner"],
                        "agent_wallet": r["agent_wallet"],
                        "token_uri": r["token_uri"],
                    },
                    chain_id=chain.chain_id,
                )
            if progress:
                progress(stats["read"], len(ids), stats)

    if own:
        spool.close()
    stats["spool_file"] = str(spool.path)
    return stats


async def count_all_chains(
    cfg: Config, chains: list[ChainConfig], *, concurrency: int = 3, on_done=None
) -> list[dict]:
    """L0 人口普查：所有链的 agent 总数。每条链约 34 次调用，不需要 archive。

    这直接回答「9.8 万到底是多少、分布在哪」—— 而且【不需要任何付费 RPC】。

    并发要小：12 条链一起打公共 RPC 会触发全面退避，反而比串行还慢。
    """
    out = []
    sem = asyncio.Semaphore(concurrency)

    async def one(ch: ChainConfig):
        async with sem:
            try:
                async with RpcClient(ch.rpcs, user_agent=cfg.user_agent, chain_id=ch.chain_id) as rpc:
                    reg = cfg.registries_for(ch)
                    code = await rpc.get_code(reg.identity)
                    if code in ("0x", "0x0", ""):
                        r = {"chain": ch.name, "chain_id": ch.chain_id, "total": None, "note": "无合约"}
                    else:
                        n = await asyncio.wait_for(count_agents(rpc, reg.identity), timeout=600)
                        r = {"chain": ch.name, "chain_id": ch.chain_id, "total": n, "note": ""}
            except TimeoutError:
                r = {"chain": ch.name, "chain_id": ch.chain_id, "total": None, "note": "超时(600s)"}
            except Exception as e:  # noqa: BLE001
                r = {"chain": ch.name, "chain_id": ch.chain_id, "total": None,
                     "note": f"{type(e).__name__}: {str(e)[:40]}"}
            if on_done:
                on_done(r)
            return r

    for r in await asyncio.gather(*(one(c) for c in chains)):
        out.append(r)
    return out
