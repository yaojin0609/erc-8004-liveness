"""T3 —— agentURI 抓取。唯一网络出口 A。

核心优化：按【规范化 URI】去重，不是按 agent 去重。大量 agent 共享同一个 URI，
去重系数直接决定这一步是跑 2 小时还是 20 小时 —— 所以先把它打印出来看一眼。

data: URI 进程内解析、零网络，先跑完这部分立刻有产出。
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import structlog

from ..config import Config
from ..fetch import (
    classify_scheme,
    extract_cid,
    fetch_data_uri,
    fetch_http,
    fetch_inline_json,
    normalize_uri,
    store_blob,
)
from ..probe.layers import parse_endpoint
from ..probe.limiter import DualLimiter
from ..spool import Spool

log = structlog.get_logger(__name__)

STAGE = "fetch-uri"

# 每个 agent 的当前 URI。
#
# 【来源优先级】agent_state.token_uri（当前状态，来自 eth_call）优先于日志推导。
# 免费 RPC 拿不到完整历史日志，但 tokenURI() 是当前状态、总是完整的。
# 日志只在有 archive 节点时才是全量，那时它作为补充（覆盖 agent_state 没扫到的 id）。
CURRENT_URI_SQL = """
WITH latest_update AS (
    SELECT chain_id, agent_id, new_uri,
           row_number() OVER (PARTITION BY chain_id, agent_id
                              ORDER BY block_number DESC, log_index DESC) AS rn
    FROM ev_uri_updated
),
from_logs AS (
    SELECT r.chain_id, r.agent_id, coalesce(u.new_uri, r.agent_uri) AS uri
    FROM ev_registered r
    LEFT JOIN latest_update u
           ON u.chain_id = r.chain_id AND u.agent_id = r.agent_id AND u.rn = 1
),
from_state AS (
    SELECT chain_id, agent_id, token_uri AS uri FROM agent_state
),
merged AS (
    SELECT chain_id, agent_id, uri FROM from_state
    UNION
    SELECT l.chain_id, l.agent_id, l.uri FROM from_logs l
    WHERE NOT EXISTS (
        SELECT 1 FROM from_state s
        WHERE s.chain_id = l.chain_id AND s.agent_id = l.agent_id
    )
)
SELECT chain_id, agent_id, uri FROM merged
WHERE uri IS NOT NULL AND uri <> ''
"""


def apply_host_cap(todo: list[str], cap: int, seed: int) -> tuple[list[str], list[str]]:
    """把单主机 URI 数超过 cap 的部分抽样掉。

    → (要抓的, 被抽样排除的)

    【为什么抽样而不是全抓】实测一家 metadata API 持有 4.9 万个待抓 URI 且已在
    返回连接超时。对一台扛不住的服务器再打 12 小时既不礼貌、统计上也没必要 ——
    8,000 的样本对该层比例估计已是 ±1.1%（95% 置信）。
    被排除的显式记为 status='sampled_out'，【不是失败也不是未抓】，
    报告必须把这一层单独算并给出置信区间。
    """
    import random

    by_host: dict[str, list[str]] = {}
    for u in todo:
        if classify_scheme(u) == "https":
            h, _, _, _ = parse_endpoint(u)
            by_host.setdefault((h or "?").lower(), []).append(u)
        else:
            by_host.setdefault("<non-https>", []).append(u)

    keep: list[str] = []
    dropped: list[str] = []
    for host, items in by_host.items():
        if host == "<non-https>" or len(items) <= cap:
            keep.extend(items)
            continue
        rnd = random.Random(f"{seed}:{host}")      # 固定种子，复跑抽到同一批
        idx = list(range(len(items)))
        rnd.shuffle(idx)
        chosen = set(idx[:cap])
        keep.extend(items[i] for i in sorted(chosen))
        dropped.extend(items[i] for i in range(len(items)) if i not in chosen)
        log.info("host_sampled", host=host, total=len(items), kept=cap, dropped=len(items) - cap)
    return keep, dropped


def collect_uris(conn, chain_id: int | None = None) -> tuple[list[str], dict]:
    """→ (待抓取的规范化 URI 列表, 统计)"""
    sql = CURRENT_URI_SQL
    params: list = []
    if chain_id is not None:
        sql += " AND chain_id = ?"
        params.append(chain_id)
    rows = conn.execute(sql, params).fetchall()

    norm_to_raw: dict[str, str] = {}
    for _cid, _aid, uri in rows:
        n = normalize_uri(uri)
        norm_to_raw.setdefault(n, uri)

    done = set()
    try:
        done = {r[0] for r in conn.execute("SELECT uri_normalized FROM uri_fetch").fetchall()}
    except Exception:  # noqa: BLE001
        pass

    todo = [u for u in norm_to_raw if u not in done]
    by_scheme: dict[str, int] = {}
    for u in norm_to_raw:
        k = classify_scheme(u)
        by_scheme[k] = by_scheme.get(k, 0) + 1

    stats = {
        "agents": len(rows),
        "distinct_uris": len(norm_to_raw),
        "dedup_factor": round(len(rows) / max(1, len(norm_to_raw)), 2),
        "already_fetched": len(done),
        "todo": len(todo),
        "by_scheme": by_scheme,
    }
    return todo, stats


async def probe_gateways(gateways: list[str], user_agent: str, timeout: float = 4.0) -> list[str]:
    """开抓前先测一遍网关，把连不上的剔除。

    配置里第一个网关是本机 Kubo（没有它 9 万个 CID 会被公共网关限流打死）。
    但机器上没跑 Kubo 时，每个 CID 都会先撞一次本地失败，白白吃掉
    max_gateways_per_cid 的三分之一预算。
    """
    alive: list[str] = []
    async with httpx.AsyncClient(timeout=timeout, headers={"User-Agent": user_agent}) as c:
        for gw in gateways:
            # 用一个众所周知一定存在的 CID（IPFS 空目录）做探针
            url = gw.rstrip("/") + "/QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn"
            try:
                r = await c.get(url, follow_redirects=True)
                if r.status_code < 500:
                    alive.append(gw)
                else:
                    log.warning("ipfs_gateway_unhealthy", gateway=gw, status=r.status_code)
            except Exception as e:  # noqa: BLE001
                log.warning("ipfs_gateway_unreachable", gateway=gw, err=type(e).__name__)
    return alive


async def fetch_all(
    cfg: Config,
    uris: list[str],
    *,
    sampled_out: list[str] | None = None,
    spool: Spool | None = None,
    progress=None,
) -> dict:
    root = Path(cfg.root)
    scan = cfg.scan
    gateways: list[str] = scan.get("ipfs", {}).get("gateways", [])
    max_gw = int(scan.get("ipfs", {}).get("max_gateways_per_cid", 3))
    max_bytes = int(scan.get("fetch", {}).get("max_body_bytes", 1_048_576))
    limits = scan.get("limits", {})

    own = spool is None
    spool = spool or Spool(root, STAGE)
    # 两套限速，因为对象性质不同：
    #   limiter    —— 打【别人的 agent 服务器】。1 请求/3 秒是礼貌红线，不许放宽。
    #   gw_limiter —— 打【公共 IPFS 网关】。它们是为高吞吐设计的基础设施，
    #                 按 3 秒/请求会让 9 万个 CID 跑上 40 小时，而且并不会让谁更舒服。
    #                 用 config 里本来就有的 per_gateway_rps。
    limiter = DualLimiter(
        global_rps=float(limits.get("global_rps", 10.0)),
        per_host_interval_s=float(limits.get("per_host_interval_s", 3.0)),
        per_host_concurrency=int(limits.get("per_host_concurrency", 1)),
        per_ip_interval_s=float(limits.get("per_ip_interval_s", 1.0)),
    )
    limiter.load_blocklist(cfg.blocklist)

    # ---- 第三套限速：批量元数据平台（见 config/scan.toml [fetch_tiering]）
    tier = scan.get("fetch_tiering", {})
    bulk_threshold = int(tier.get("bulk_host_threshold", 50))
    bulk_rps = float(tier.get("bulk_host_rps", 2.0))
    host_counts: dict[str, int] = {}
    for u in uris:
        if classify_scheme(u) == "https":
            h, _, _, _ = parse_endpoint(u)
            if h:
                host_counts[h.lower()] = host_counts.get(h.lower(), 0) + 1
    bulk_hosts = {h for h, n in host_counts.items() if n >= bulk_threshold}
    bulk_limiter = DualLimiter(
        global_rps=float(limits.get("global_rps", 10.0)) * 2,
        per_host_interval_s=1.0 / max(bulk_rps, 0.1),
        per_host_concurrency=max(2, int(bulk_rps)),
        per_ip_interval_s=0.0,
    )
    bulk_limiter.load_blocklist(cfg.blocklist)
    if bulk_hosts:
        log.info("bulk_metadata_hosts", n=len(bulk_hosts),
                 top=sorted(bulk_hosts, key=lambda h: -host_counts[h])[:5])

    gw_rps = float(scan.get("ipfs", {}).get("per_gateway_rps", 5.0))
    gw_limiter = DualLimiter(
        global_rps=gw_rps * max(1, len(gateways)),
        per_host_interval_s=1.0 / max(gw_rps, 0.1),
        per_host_concurrency=max(2, int(gw_rps)),
        per_ip_interval_s=0.0,
    )
    gw_limiter.load_blocklist(cfg.blocklist)
    gateway_hosts = set()
    for g in gateways:
        h, _, _, _ = parse_endpoint(g)
        if h:
            gateway_hosts.add(h.lower())

    # 只在确实有 ipfs URI 时才做网关健康探测
    if any(classify_scheme(u) == "ipfs" for u in uris):
        healthy = await probe_gateways(gateways, cfg.user_agent)
        if healthy and healthy != gateways:
            log.info("ipfs_gateways_filtered", kept=len(healthy), dropped=len(gateways) - len(healthy))
            gateways = healthy
            gateway_hosts = set()
            for g in gateways:
                h, _, _, _ = parse_endpoint(g)
                if h:
                    gateway_hosts.add(h.lower())

    counts: dict[str, int] = {}
    done = 0

    def record(res, uri_norm: str):
        nonlocal done
        row = res.to_row()
        row["uri_normalized"] = uri_norm
        if res.body is not None and res.content_sha256:
            store_blob(root, res.body)
        spool.write("uri_fetch", row)
        counts[res.status] = counts.get(res.status, 0) + 1
        done += 1
        if progress and done % 200 == 0:
            progress(done, len(uris), counts)

    # ---- 第 0 批：被抽样排除的，直接记状态，零网络
    for u in (sampled_out or []):
        spool.write("uri_fetch", {
            "uri_normalized": u, "scheme_kind": classify_scheme(u),
            "status": "sampled_out", "error_detail": "host_cap",
            "attempt_count": 0,          # 零次尝试 —— 语义上就是没抓，不是抓失败
            "elapsed_ms": 0,
        })
        counts["sampled_out"] = counts.get("sampled_out", 0) + 1
        done += 1

    # ---- 第一批：零网络的（data: 与裸 JSON），先做完，立刻有产出
    for u in uris:
        k = classify_scheme(u)
        if k == "data":
            record(fetch_data_uri(u), u)
        elif k == "inline_json":
            record(fetch_inline_json(u), u)

    # ---- 第二批：网络抓取
    net_uris = [u for u in uris if classify_scheme(u) not in ("data", "inline_json")]
    timeouts = scan.get("timeouts", {})
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(float(timeouts.get("total_s", 30.0)),
                              connect=float(timeouts.get("connect_s", 10.0)),
                              read=float(timeouts.get("read_s", 10.0))),
        headers={"User-Agent": cfg.user_agent},
        follow_redirects=False,
        limits=httpx.Limits(max_connections=64),
    ) as client:

        async def handle(u: str):
            kind = classify_scheme(u)
            if kind == "https":
                host, _, _, _ = parse_endpoint(u)
                hl = (host or "").lower()
                lim = bulk_limiter if hl in bulk_hosts else limiter
                try:
                    async with lim.acquire(host or "?"):
                        res = await fetch_http(client, u, max_bytes=max_bytes, kind="https")
                    # 对方说停就停：429/503 立刻拉黑该主机，两档都一样
                    if res.http_status in (429, 503):
                        lim.block_host(hl, f"http_{res.http_status}")
                        limiter.block_host(hl, f"http_{res.http_status}")
                except Exception as e:  # noqa: BLE001
                    from ..fetch import FetchResult
                    from ..probe.limiter import HostBlocked

                    # HostBlocked = 我们主动退避（该 host 返回过 429/503 或在退出名单里），
                    # 不是「抓取失败」。混进 other 桶会把自己的克制记成对方的问题。
                    st = "rate_limited" if isinstance(e, HostBlocked) else "other"
                    res = FetchResult(u, "https", st, error_detail=type(e).__name__)
                record(res, u)
                return

            if kind == "ipfs":
                from ..fetch import FetchResult

                cid_path = extract_cid(u)
                if not cid_path:
                    record(FetchResult(u, "ipfs", "other", error_detail="bad_cid"), u)
                    return
                cid, path = cid_path
                last = None
                for gw in gateways[:max_gw]:
                    url = gw.rstrip("/") + "/" + cid + path
                    host, _, _, _ = parse_endpoint(url)
                    lim = gw_limiter if (host or "").lower() in gateway_hosts else limiter
                    try:
                        async with lim.acquire(host or "?"):
                            res = await fetch_http(client, url, max_bytes=max_bytes, kind="ipfs", gateway=gw)
                    except Exception as e:  # noqa: BLE001
                        res = FetchResult(u, "ipfs", "other", error_detail=type(e).__name__, gateway_used=gw)
                    if res.status == "ok":
                        record(res, u)
                        return
                    last = res
                if last is None:
                    last = FetchResult(u, "ipfs", "ipfs_unresolvable", error_detail="no_gateway")
                last.status = "ipfs_unresolvable" if last.status != "not_json" else "not_json"
                record(last, u)
                return

            # ar:// / did: / ENS / 其它：单独归类，不塞进「失败」桶
            from ..fetch import FetchResult

            record(FetchResult(u, kind, "unsupported_scheme"), u)

        # 【必须按 host 分桶】——和探测器同一个道理（实施规划 §5 Stage 06）。
        # 直接 gather 全部 URI 的话，占比最大的那台主机（实测一家占 56%）会把
        # 全局并发信号量吃光，其余几百台主机全部饿死，总吞吐塌成单主机速率。
        # 正确做法：一个 worker 独占一个 host 的队列并串行处理，多个 host 并行。
        buckets: dict[str, list[str]] = {}
        for u in net_uris:
            try:
                k = classify_scheme(u)
                if k == "ipfs":
                    key = "<ipfs>"      # IPFS 走网关，按网关限速，不按原始 host
                else:
                    h, _, _, _ = parse_endpoint(u)
                    key = (h or "?").lower()
            except Exception:  # noqa: BLE001
                key = "?"
            buckets.setdefault(key, []).append(u)

        queue: asyncio.Queue = asyncio.Queue()
        for key, items in buckets.items():
            if key == "<ipfs>":
                # IPFS 桶可以高并发：限速由 gw_limiter 按网关强制，不是按 CID
                chunk = max(1, len(items) // 24)
                for i in range(0, len(items), chunk):
                    queue.put_nowait(items[i:i + chunk])
            else:
                queue.put_nowait(items)

        n_workers = min(160, max(1, queue.qsize()))

        async def worker():
            while True:
                try:
                    items = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                try:
                    for u in items:
                        # 单个畸形 URI 不许掀翻整轮抓取。实测一个把 JSON 片段
                        # 当 tokenURI 的 agent 就让 19.7 万个 URI 只抓完 31%，
                        # 而 run_full.sh 的 `|| true` 把失败吞了，
                        # 最后产出一份「看起来完整」的报告 —— 这比抓取失败危险得多。
                        try:
                            await handle(u)
                        except Exception as e:  # noqa: BLE001
                            from ..fetch import FetchResult
                            record(FetchResult(u, classify_scheme(u), "other",
                                               error_detail=f"handler:{type(e).__name__}"), u)
                finally:
                    queue.task_done()

        await asyncio.gather(*[worker() for _ in range(n_workers)])

    if own:
        spool.close()
    return {"fetched": done, "by_status": counts, "spool_file": str(spool.path)}
