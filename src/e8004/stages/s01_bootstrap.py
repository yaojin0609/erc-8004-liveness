"""T0 —— 地址验证 + 部署区块发现。

把「扫错合约」这个能毁掉整个项目的风险在第一天消灭掉。

诊断模式（--diagnose）会对一组候选地址逐个做身份鉴定并统计近期活跃度，
用于回答「同一条链上出现多个 0x8004 前缀合约时该扫哪个」。
"""

from __future__ import annotations

from dataclasses import dataclass, field

import structlog

from ..abi import decode_result, encode_call, topic0
from ..config import ChainConfig, Config
from ..rpc import RpcClient, RpcError

log = structlog.get_logger(__name__)

# ERC-1967 implementation slot = keccak256("eip1967.proxy.implementation") - 1
ERC1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
ERC721_INTERFACE_ID = "0x80ac58cd"

REGISTERED_SIG = "Registered(uint256,string,address)"


@dataclass
class AddressReport:
    label: str
    address: str
    has_code: bool = False
    code_size: int = 0
    implementation: str | None = None
    name: str | None = None
    symbol: str | None = None
    is_erc721: bool | None = None
    identity_registry: str | None = None  # getIdentityRegistry() 的返回值
    deploy_block: int | None = None
    recent_registered: int | None = None  # 近期 Registered 事件数，用于判断哪个在真正被用
    notes: list[str] = field(default_factory=list)

    @property
    def kind(self) -> str:
        if not self.has_code:
            return "no-code"
        if self.is_erc721:
            return "identity"
        if self.identity_registry:
            return "reputation/validation"
        return "unknown"


async def _read_impl(rpc: RpcClient, addr: str) -> str | None:
    try:
        raw = await rpc.get_storage_at(addr, ERC1967_IMPL_SLOT)
        if raw and int(raw, 16) != 0:
            return "0x" + raw[-40:]
    except RpcError:
        pass
    return None


async def _try_call(rpc: RpcClient, addr: str, signature: str, out_types: list[str]):
    try:
        raw = await rpc.eth_call(addr, encode_call(signature, [], []))
        return decode_result(out_types, raw)[0]
    except (RpcError, ValueError, Exception):
        return None


async def inspect_address(rpc: RpcClient, label: str, addr: str, *, head: int, probe_window: int = 100_000) -> AddressReport:
    rep = AddressReport(label=label, address=addr.lower())

    code = await rpc.get_code(addr)
    rep.has_code = code not in ("0x", "0x0", "")
    if not rep.has_code:
        return rep
    rep.code_size = (len(code) - 2) // 2
    rep.implementation = await _read_impl(rpc, addr)
    if rep.implementation:
        rep.notes.append("ERC-1967 代理 —— 扫 proxy 地址是对的")

    # ERC-721 身份鉴定
    try:
        raw = await rpc.eth_call(
            addr, encode_call("supportsInterface(bytes4)", ["bytes4"], [bytes.fromhex(ERC721_INTERFACE_ID[2:])])
        )
        rep.is_erc721 = bool(int(raw, 16))
    except Exception:
        rep.is_erc721 = False

    if rep.is_erc721:
        rep.name = await _try_call(rpc, addr, "name()", ["string"])
        rep.symbol = await _try_call(rpc, addr, "symbol()", ["string"])
    else:
        ident = await _try_call(rpc, addr, "getIdentityRegistry()", ["address"])
        if ident and int(ident, 16) != 0:
            rep.identity_registry = ident.lower()

    # 近期活跃度：谁在被真正使用。这是区分「多个同类合约」的决定性证据。
    if rep.is_erc721:
        try:
            logs = await rpc.call(
                "eth_getLogs",
                [
                    {
                        "fromBlock": hex(max(0, head - probe_window)),
                        "toBlock": hex(head),
                        "address": addr,
                        "topics": [topic0(REGISTERED_SIG)],
                    }
                ],
            )
            rep.recent_registered = len(logs)
        except RpcError as e:
            rep.notes.append(f"近期活跃度探测失败: {e.message[:60]}")

    return rep


# ERC-8004 主网上线日 2026-01-29。用 2026-01-01 做地板，留一个月余量。
# 不要用更早的日期：BSC 出块 0.75s，多退一年就是多扫 4000 万个空区块。
LAUNCH_TS_FLOOR = 1767225600  # 2026-01-01 UTC


async def find_deploy_block(rpc: RpcClient, addr: str, head: int) -> tuple[int | None, str | None]:
    """返回 (deploy_block, 说明)。

    三级降级 —— 公共 RPC 多半不是 archive 节点，不能因此卡住：
      1. eth_getCode 二分（最准，需要 archive）
      2. 时间戳二分到 2025-01-01，再在其后二分首条 Registered 日志（只需 eth_getLogs）
      3. 都失败则返回 None，由调用方决定从 0 还是从配置值开始扫
    """
    try:
        blk = await rpc.find_deploy_block(addr, hi=head)
        if blk is not None:
            return blk, None
    except (RpcError, Exception):
        pass

    try:
        # 时间戳二分：约 25 次调用，有界。所有节点都支持 eth_getBlockByNumber。
        floor = await rpc.find_block_by_timestamp(LAUNCH_TS_FLOOR, hi=head)
        # 再往前推到「第一次真的有人注册」。粗步长线性扫，调用次数有上限，
        # 找不到就退回 floor —— 对出块快的链（BSC 0.75s）这一步能省掉几千次扫描调用。
        first = await rpc.find_first_log_block(
            addr, topic0(REGISTERED_SIG), floor, head, step=100_000, max_calls=300
        )
        if first is not None:
            return first, "非 archive 节点：用首条 Registered 日志所在区块作为扫描起点"
        return floor, "非 archive 节点：用 2026-01-01 的区块兜底（该窗口内未找到 Registered）"
    except Exception as e:  # noqa: BLE001
        return None, f"部署区块定位失败: {type(e).__name__}: {str(e)[:70]}"


async def diagnose_chain(cfg: Config, chain: ChainConfig, candidates: dict[str, str], *, deploy_block: bool = False):
    """对一组候选地址做身份鉴定。返回 (head, [AddressReport])。"""
    async with RpcClient(chain.rpcs, user_agent=cfg.user_agent, chain_id=chain.chain_id) as rpc:
        head = await rpc.safe_head(chain.confirmations, chain.supports_finalized)
        reports = []
        for label, addr in candidates.items():
            rep = await inspect_address(rpc, label, addr, head=head)
            if deploy_block and rep.has_code:
                blk, why = await find_deploy_block(rpc, addr, head)
                rep.deploy_block = blk
                if why:
                    rep.notes.append(why)
            reports.append(rep)
        return head, reports


async def bootstrap_chain(cfg: Config, chain: ChainConfig, *, with_deploy_block: bool = True) -> dict:
    """按 config 里配置的地址做正式验证，产出可写入 chain 表的结果。"""
    reg = cfg.registries_for(chain)
    # errors = 地址搞错了，必须停下来查；warnings = 降级但可继续（如非 archive 节点）
    result: dict = {"chain_id": chain.chain_id, "name": chain.name, "verified": False,
                    "errors": [], "warnings": []}

    async with RpcClient(chain.rpcs, user_agent=cfg.user_agent, chain_id=chain.chain_id) as rpc:
        head = await rpc.safe_head(chain.confirmations, chain.supports_finalized)
        result["head"] = head

        ident = await inspect_address(rpc, "identity", reg.identity, head=head)
        if not ident.has_code:
            result["errors"].append(f"IdentityRegistry {reg.identity} 在 chain {chain.chain_id} 上没有代码")
        elif not ident.is_erc721:
            result["errors"].append(f"IdentityRegistry {reg.identity} 的 supportsInterface(ERC721) 不为 true")
        result["identity"] = ident

        if reg.reputation:
            rep = await inspect_address(rpc, "reputation", reg.reputation, head=head)
            # 硬校验：getIdentityRegistry() 必须逐字节等于配置的 IdentityRegistry
            if rep.has_code and rep.identity_registry and rep.identity_registry != reg.identity:
                result["errors"].append(
                    f"ReputationRegistry.getIdentityRegistry() = {rep.identity_registry}，"
                    f"与配置的 IdentityRegistry {reg.identity} 不一致 —— 地址搞错了"
                )
            result["reputation"] = rep

        if reg.validation:
            val = await inspect_address(rpc, "validation", reg.validation, head=head)
            result["validation"] = val

        if with_deploy_block and ident.has_code and chain.deploy_block is None:
            blk, why = await find_deploy_block(rpc, reg.identity, head)
            result["deploy_block"] = blk
            if why:
                # 部署区块定位不准不影响「地址是否正确」，归 warning，不阻塞
                result["warnings"].append(why)
        else:
            result["deploy_block"] = chain.deploy_block

        result["verified"] = not result["errors"]
        return result
