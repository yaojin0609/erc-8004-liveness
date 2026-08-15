"""T1/T2 —— 全量事件扫描。这是权威数据源。

写 spool JSONL，不直接写 DB（实施规划 §4）。扫完跑 `e8004 load scan-logs`。

解码陷阱（CLAUDE.md 硬约束 7）：`string indexed` 在 topic 里是 keccak 哈希。
abi.decode_log 把哈希值放进 `<name>` 并置 `<name>__hashed=True`，可读值一律取
data 段的非 indexed 同名字段（tag1 / metadataKey）。
"""

from __future__ import annotations

from datetime import UTC, datetime

import structlog

from ..abi import EventRegistry
from ..config import ChainConfig, Config
from ..rpc import RpcClient
from ..spool import Spool

log = structlog.get_logger(__name__)

STAGE = "scan-logs"

# 事件名 → 目标表 + 字段映射。解码结果的 key 来自 abis.json 的 inputs[].name。
EVENT_TABLES: dict[str, tuple[str, dict[str, str]]] = {
    "Registered": (
        "ev_registered",
        {"agentId": "agent_id", "agentURI": "agent_uri", "owner": "owner"},
    ),
    "URIUpdated": (
        "ev_uri_updated",
        {"agentId": "agent_id", "newURI": "new_uri", "updatedBy": "updated_by"},
    ),
    "MetadataSet": (
        "ev_metadata_set",
        {
            "agentId": "agent_id",
            "metadataKey": "metadata_key",
            "indexedMetadataKey": "metadata_key_hash",
            "metadataValue": "metadata_value",
        },
    ),
    "Transfer": (
        "ev_transfer",
        {"tokenId": "agent_id", "from": "from_addr", "to": "to_addr"},
    ),
    "NewFeedback": (
        "ev_feedback",
        {
            "agentId": "agent_id",
            "clientAddress": "client_address",
            "feedbackIndex": "feedback_index",
            "value": "value_raw",
            "valueDecimals": "value_decimals",
            "tag1": "tag1",
            "tag2": "tag2",
            "endpoint": "endpoint",
            "feedbackURI": "feedback_uri",
            "feedbackHash": "feedback_hash",
        },
    ),
    "FeedbackRevoked": (
        "ev_feedback_revoked",
        {"agentId": "agent_id", "clientAddress": "client_address", "feedbackIndex": "feedback_index"},
    ),
    "ResponseAppended": (
        "ev_response_appended",
        {
            "agentId": "agent_id",
            "clientAddress": "client_address",
            "feedbackIndex": "feedback_index",
            "responder": "responder",
            "responseURI": "response_uri",
            "responseHash": "response_hash",
        },
    ),
}

MAX_SAFE_ID = 2**63 - 1


def _check_agent_id(v: int, ctx: str) -> int:
    # CLAUDE.md 硬约束 10：超出 UBIGINT 必须抛错，不许静默截断
    if v > MAX_SAFE_ID:
        raise ValueError(f"{ctx}: agent_id {v} 超出 UBIGINT 范围，不能静默截断")
    return v


def _hexint(x: str) -> int:
    return int(x, 16)


async def _find_canary_block(rpc: RpcClient, identity: str, head: int, step: int,
                             start: int = 0, probes: int = 24) -> int | None:
    """找一个确实含有 Registered 日志的区块，用作端点完整性验证的金丝雀。

    【必须覆盖整个待扫区间，不能只看链头附近】
    原实现从 head 往回连扫 12 × step 就放弃。step 调大到 50,000 之后这只有
    60 万个区块 —— 而 scroll 的注册活动停在离链头 230 万个区块之前。
    结果是找不到金丝雀 → 跳过端点校验 → 一个静默返回空的端点畅通无阻，
    扫描「成功」产出 0 条日志（实测：scroll 报 0，重扫得 470）。

    改成在 [start, head] 上均匀取 probes 个窗口，从新到旧探。最坏 24 次调用，
    相对于随后要扫的成百上千次可以忽略。
    """
    from ..abi import topic0

    t = topic0("Registered(uint256,string,address)")
    span = max(0, head - start)
    stride = max(step, span // max(1, probes))
    cursor = head
    for _ in range(probes):
        lo = max(start, cursor - step)
        try:
            logs = await rpc.call(
                "eth_getLogs",
                [{"fromBlock": hex(lo), "toBlock": hex(cursor), "address": identity, "topics": [t]}],
            )
            if logs:
                return int(logs[0]["blockNumber"], 16)
        except Exception:  # noqa: BLE001
            pass
        cursor -= stride
        if cursor <= start:
            break
    return None


async def _token_zero_exists(rpc: RpcClient, identity: str) -> bool:
    """ownerOf(0) 能返回非零地址就说明这个注册表上确实铸过 token。

    用作「0 条日志」的反证：不依赖日志，走 eth_call，两条路互相独立。
    """
    from ..abi import selector

    data = "0x" + selector("ownerOf(uint256)").removeprefix("0x") + f"{0:064x}"
    try:
        r = await rpc.call("eth_call", [{"to": identity, "data": data}, "latest"])
    except Exception:  # noqa: BLE001
        return False       # revert = 该 token 不存在
    return bool(r) and r != "0x" and int(r[-40:], 16) != 0


async def scan_chain(
    cfg: Config,
    chain: ChainConfig,
    *,
    from_block: int | None = None,
    to_block: int | None = None,
    events: list[str] | None = None,
    spool: Spool | None = None,
    progress=None,
    registry_filter: str | None = None,
) -> dict:
    """扫描一条链。返回统计信息。

    `registry_filter` 限定只扫某一个注册表（'identity' / 'reputation'）。
    请求次数由【区块跨度】决定，不由日志条数决定，所以过滤合约不会减少请求数；
    但返回的日志少了，区块时间戳补全的工作量会成比例下降 —— BSC 有 26 万个
    agent，连 IdentityRegistry 一起扫会拉回海量已知数据（注册信息早已由
    scan-mints 拿到），只为了 L4 的话完全是浪费。
    """
    reg = cfg.registries_for(chain)
    registry = EventRegistry(cfg.abis)
    if registry_filter == "identity":
        addresses = [reg.identity]
    elif registry_filter == "reputation":
        if not reg.reputation:
            raise ValueError(f"{chain.name} 没有配置 ReputationRegistry 地址")
        addresses = [reg.reputation]
    else:
        addresses = reg.addresses()

    # Tier B 只做人口普查：Registered + Transfer（销毁判定需要）
    if events is None:
        events = list(EVENT_TABLES) if chain.tier == "A" else ["Registered", "Transfer"]
    wanted_topics = set(registry.topics_for(events))

    own = spool is None
    spool = spool or Spool(cfg.root, STAGE)
    stats = {"chain": chain.name, "logs": 0, "decoded": 0, "unknown_topic": 0, "by_event": {}}

    async with RpcClient(chain.rpcs_for_logs, user_agent=cfg.user_agent, chain_id=chain.chain_id) as rpc:
        head = to_block or await rpc.safe_head(chain.confirmations, chain.supports_finalized)
        start = from_block if from_block is not None else (chain.deploy_block or 0)
        stats["from_block"], stats["to_block"] = start, head

        # ---- 开扫前先做端点完整性验证 ----
        # 找一个已知含有 Registered 日志的区块当金丝雀，把「静默返回空」的端点剔除。
        # 不做这一步，扫描会「成功」地产出一份 87% 是空的数据集。
        canary = await _find_canary_block(rpc, reg.identity, head, chain.max_log_range, start)
        if canary is not None:
            verdicts = await rpc.verify_endpoints_for_logs(
                reg.identity, EventRegistry(cfg.abis).by_name["Registered"]["topic0"], canary
            )
            stats["endpoint_verdicts"] = verdicts
            liars = [u for u, v in verdicts.items() if v == "SILENTLY_EMPTY"]
            if liars:
                log.warning("silently_empty_endpoints_removed", endpoints=liars)
            if not rpc.urls:
                raise RuntimeError("所有 RPC 端点都无法可信地返回日志，拒绝产出可能不完整的数据")
        else:
            stats["endpoint_verdicts"] = {"_": "no_canary_found"}

        ts_cache: dict[int, int] = {}
        pending_ts: set[int] = set()
        buffered: list[tuple[str, dict, int]] = []

        async def flush_ts():
            """区块时间戳批量补齐 —— 队列分析(§8.4)靠它，必须有。"""
            nonlocal buffered, pending_ts
            if pending_ts:
                ts_cache.update(await rpc.get_block_timestamps(sorted(pending_ts)))
                pending_ts = set()
            for table, rec, blk in buffered:
                ts = ts_cache.get(blk)
                if ts is not None:
                    rec["block_timestamp"] = datetime.fromtimestamp(ts, UTC).isoformat()
                spool.write(table, rec, chain_id=chain.chain_id)
            buffered = []

        # max_range 不许超过配置值：早先设成 5 倍，导致步长涨到 5 万后 drpc 报范围错、
        # 轮转到会静默返回空的端点。配置里的值是【各家 RPC 的硬上限】，不是起点。
        async for batch in rpc.get_logs_ranged(
            addresses, start, head, start_range=chain.max_log_range, max_range=chain.max_log_range
        ):
            for lg in batch.logs:
                stats["logs"] += 1
                blk = _hexint(lg["blockNumber"])

                # raw 层：原封不动落盘，永不覆盖
                spool.write(
                    "log_raw",
                    {
                        "block_number": blk,
                        "block_hash": lg["blockHash"],
                        "tx_hash": lg["transactionHash"],
                        "tx_index": _hexint(lg["transactionIndex"]),
                        "log_index": _hexint(lg["logIndex"]),
                        "address": lg["address"].lower(),
                        "topic0": lg["topics"][0].lower(),
                        "topic1": lg["topics"][1].lower() if len(lg["topics"]) > 1 else None,
                        "topic2": lg["topics"][2].lower() if len(lg["topics"]) > 2 else None,
                        "topic3": lg["topics"][3].lower() if len(lg["topics"]) > 3 else None,
                        "data": lg.get("data", "0x"),
                        "removed": bool(lg.get("removed", False)),
                    },
                    chain_id=chain.chain_id,
                )

                if lg["topics"][0].lower() not in wanted_topics:
                    stats["unknown_topic"] += 1
                    continue

                ev, decoded = registry.decode(lg)
                if ev is None or decoded is None:
                    stats["unknown_topic"] += 1
                    continue

                table, field_map = EVENT_TABLES[ev["name"]]
                rec: dict = {
                    "block_number": blk,
                    "log_index": _hexint(lg["logIndex"]),
                }
                if table in ("ev_registered", "ev_feedback"):
                    rec["tx_hash"] = lg["transactionHash"]
                for src, dst in field_map.items():
                    val = decoded.get(src)
                    if dst == "agent_id" and isinstance(val, int):
                        val = _check_agent_id(val, f"{chain.name}@{blk}")
                    rec[dst] = val

                # 定点数还原：Decimal 语义，禁止 float（CLAUDE.md 硬约束 8）。
                # 这里只落原始 int128 + decimals，value_real 由 SQL 用 DECIMAL 算。
                if table == "ev_feedback":
                    rec["value_raw"] = int(decoded["value"])

                buffered.append((table, rec, blk))
                pending_ts.add(blk)
                stats["decoded"] += 1
                stats["by_event"][ev["name"]] = stats["by_event"].get(ev["name"], 0) + 1

            if len(buffered) >= 2000:
                await flush_ts()
            if progress:
                progress(batch.to_block, head, stats)

        await flush_ts()
        stats["converged_range"] = rpc.converged_range

        # ---- 收尾不变量：「0 条日志」必须是被证明的，不能是默认的 ----
        # 金丝雀校验有可能整个被跳过（找不到金丝雀时），所以不能只靠它。
        # 链上确实存在 token 却一条日志都没扫到，只可能是端点在静默说谎 ——
        # 这时候【必须报错】，不许安安静静地返回一份空数据集。
        # 【只在扫 IdentityRegistry 时成立】反证用的是 ownerOf(0)，那是身份注册表的
        # 状态。只扫 ReputationRegistry 时「0 条日志」完全可能是真的 ——
        # 那条链上就是没人留过反馈 —— 这时候报错是误杀。
        if stats["logs"] == 0 and registry_filter != "reputation":
            exists = await _token_zero_exists(rpc, reg.identity)
            if exists:
                raise RuntimeError(
                    f"{chain.name}: 扫描区间 [{start:,}, {head:,}] 一条日志都没有，"
                    f"但 ownerOf(0) 能返回持有者 —— 说明 token 存在而端点没给日志。"
                    "拒绝产出这份空数据集。换端点或缩小 max_log_range 后重试。"
                )
            log.info("zero_logs_confirmed", chain=chain.name,
                     note="ownerOf(0) 也不存在，0 条日志是真的")

    if own:
        spool.close()
    stats["spool_file"] = str(spool.path)
    return stats


async def census_registry(cfg: Config, chain: ChainConfig, label: str, address: str, canonical: bool) -> dict:
    """轻量普查：某个注册表全历史有多少次 Registered。

    用于量化「有多少注册落在那组死的平行注册表上」—— 各家统计数字打架的原因之一。
    """
    from ..abi import topic0
    from .s01_bootstrap import inspect_address

    sig_topic = topic0("Registered(uint256,string,address)")
    async with RpcClient(chain.rpcs_for_logs, user_agent=cfg.user_agent, chain_id=chain.chain_id) as rpc:
        head = await rpc.safe_head(chain.confirmations, chain.supports_finalized)
        info = await inspect_address(rpc, label, address, head=head, probe_window=1)
        out = {
            "chain_id": chain.chain_id,
            "registry": address.lower(),
            "label": label,
            "is_canonical": canonical,
            "implementation": info.implementation,
            "is_erc721": info.is_erc721,
            "registered_total": 0,
            "first_block": None,
            "last_block": None,
        }
        if not info.has_code:
            return out
        start = chain.deploy_block or 0
        total, first, last = 0, None, None
        async for batch in rpc.get_logs_ranged(
            [address], start, head, [sig_topic], start_range=chain.max_log_range,
            max_range=chain.max_log_range,
        ):
            for lg in batch.logs:
                b = int(lg["blockNumber"], 16)
                total += 1
                first = b if first is None else min(first, b)
                last = b if last is None else max(last, b)
        out.update(registered_total=total, first_block=first, last_block=last)
        return out
