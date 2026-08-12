"""T1b —— 铸造（注册）历史。网络出口 A'，写 spool。

【为什么存在这个 stage】
Alchemy 免费档把 `eth_getLogs` 砍到 **10 个区块**跨度：

    Under the Free tier plan, you can make eth_getLogs requests with up to a
    10 block range.

以太坊注册表部署至今约 139 万个区块 → 13.9 万次请求，BSC 更离谱。走事件日志
拿全量注册历史这条路在免费档下是走不通的。

`alchemy_getAssetTransfers` 不受这个限制：一次查询接受 `0x0 → latest`，
按 pageKey 翻页，每页 1000 条。ERC-721 的 mint（from = 零地址）就是注册，
返回里带 blockNum / tokenId / blockTimestamp / to —— 正好是队列分析
（注册月份）和「注册时 owner」需要的全部字段。约 378 次请求覆盖 95.8% 的身份。

它【不带 agentURI】，所以结果写 `agent_mint` 而不是 `ev_registered`，
理由见 schema.sql 里那张表的注释。

断点续跑：游标存 pageKey。杀掉重跑从上次那一页继续，不重扫已完成的页。
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

import structlog

from ..config import ChainConfig, Config
from ..rpc import RpcClient
from ..spool import Spool

log = structlog.get_logger(__name__)

STAGE = "scan-mints"
SOURCE = "alchemy_asset_transfers"
ZERO = "0x0000000000000000000000000000000000000000"
PAGE = 1000  # getAssetTransfers 的每页上限

_ALCHEMY_RE = re.compile(r"^https://([a-z0-9-]+)\.g\.alchemy\.com/", re.I)


class NotSupported(RuntimeError):
    """这条链没配 Alchemy 端点 —— getAssetTransfers 是 Alchemy 的扩展方法。"""


def alchemy_url(chain: ChainConfig) -> str:
    for u in chain.rpcs:
        if _ALCHEMY_RE.match(u):
            return u
    raise NotSupported(
        f"{chain.name} 没有 Alchemy 端点。alchemy_getAssetTransfers 是 Alchemy 扩展方法，"
        "公共 RPC 不提供。这条链的注册时间需要另一条路径（Etherscan V2 等）。"
    )


def _ts(raw: str | None):
    """'2026-01-29T10:31:11.000Z' → naive UTC datetime，与其它表的 TIMESTAMP 对齐。"""
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(UTC).replace(tzinfo=None)
    except ValueError:
        return None


def _agent_id(raw: str | None) -> int | None:
    """tokenId 是十六进制字符串。

    硬约束 10：超出 2^63-1 必须抛错，不许静默截断 —— agent_id 列是 UBIGINT，
    悄悄回绕会让整份队列分析对不上号。
    """
    if raw is None:
        return None
    v = int(raw, 16)
    if v > 2**63 - 1:
        raise ValueError(f"agent_id {v} 超出 2^63-1，拒绝截断")
    return v


async def scan_mints(cfg: Config, chain: ChainConfig, spool: Spool,
                     start_page_key: str | None = None,
                     on_page=None) -> dict:
    """拉一条链的全部 mint。返回 {'mints': n, 'pages': n, 'page_key': 最后游标}。

    page_key 为 None 表示扫完了。中途被杀就拿上一次返回的 page_key 续跑。
    """
    url = alchemy_url(chain)
    reg = cfg.registries_for(chain).identity
    client = RpcClient(url, user_agent=cfg.user_agent, chain_id=chain.chain_id)
    params: dict = {
        "fromBlock": "0x0",
        "toBlock": "latest",
        "contractAddresses": [reg.lower()],
        "category": ["erc721"],
        "fromAddress": ZERO,          # from = 零地址 → mint → 注册
        "withMetadata": True,
        "excludeZeroValue": False,
        "order": "asc",               # 稳定顺序，续跑才有意义
        "maxCount": hex(PAGE),
    }
    n = pages = 0
    page_key = start_page_key
    try:
        while True:
            p = dict(params)
            if page_key:
                p["pageKey"] = page_key
            res = await client.call("alchemy_getAssetTransfers", [p])
            transfers = res.get("transfers") or []
            for t in transfers:
                aid = _agent_id(t.get("tokenId"))
                if aid is None:
                    continue
                spool.write("agent_mint", {
                    "chain_id": chain.chain_id,
                    "agent_id": aid,
                    # 硬约束 9：地址一律小写
                    "owner": (t.get("to") or "").lower(),
                    "block_number": int(t["blockNum"], 16),
                    "block_timestamp": _ts((t.get("metadata") or {}).get("blockTimestamp")),
                    "tx_hash": (t.get("hash") or "").lower(),
                    "source": SOURCE,
                }, chain_id=chain.chain_id)
                n += 1
            pages += 1
            page_key = res.get("pageKey")
            if on_page:
                on_page(pages, n, page_key)
            log.info("mints_page", chain=chain.name, page=pages, mints=n, more=bool(page_key))
            if not page_key:
                break
    finally:
        await client.aclose()
    return {"mints": n, "pages": pages, "page_key": page_key}
