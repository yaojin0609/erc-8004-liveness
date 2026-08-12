"""T6 —— 活性探测 stage。DB ↔ e8004.probe 库之间的适配层。

库本身不许 import duckdb（CLAUDE.md 硬约束 3），所以「从 service 表取目标」
和「把结果写 spool」这两件事都在这里做，不在库里做。

只写 probe_attempt 原始记录，【不做「是否算活」的判定】—— 判定在 s08_funnel
用 SQL 做，口径改了能立刻重算，不用重新骚扰别人的服务器。
"""

from __future__ import annotations

import structlog

from ..config import Config
from ..probe import ProbeConfig, ProbeTarget, probe_many
from ..probe.layers import parse_endpoint
from ..probe.runner import dry_run_plan
from ..spool import Spool

log = structlog.get_logger(__name__)

STAGE = "probe"

TARGETS_SQL = """
SELECT s.chain_id, s.agent_id, s.service_idx, s.service_name, s.endpoint
FROM service s
WHERE s.is_routable
  AND s.endpoint IS NOT NULL
  AND s.endpoint <> ''
ORDER BY s.endpoint_host, s.chain_id, s.agent_id
"""


def load_targets(conn, limit: int | None = None, chain_id: int | None = None) -> list[ProbeTarget]:
    sql = TARGETS_SQL
    params: list = []
    if chain_id is not None:
        sql = sql.replace("WHERE s.is_routable", "WHERE s.is_routable AND s.chain_id = ?")
        params.append(chain_id)
    if limit:
        sql += f" LIMIT {int(limit)}"
    rows = conn.execute(sql, params).fetchall()
    return [
        ProbeTarget(endpoint=r[4], declared_kind=r[3] or "web", ref=f"{r[0]}:{r[1]}:{r[2]}")
        for r in rows
    ]


def apply_target_host_cap(targets: list[ProbeTarget], cap: int,
                          seed: int) -> tuple[list[ProbeTarget], list[ProbeTarget]]:
    """把单 host 目标数超过 cap 的部分抽样掉。→ (要探的, 被抽样排除的)

    【为什么必须有这个上限】同一 host 强制 1 请求/3 秒串行（硬约束 11），
    所以总耗时不由目标总数决定，而由【最大的那个 host】决定。实测全量 dry-run：
    163,230 个目标里 evoevo.ai 一家占 36,413 个 → 36,413 × 6 × 3s = 182 小时，
    而全局 10 req/s 的下限只有 18 小时。也就是 7.6 天里 90% 的时间在等一个 host。

    上限 2,000 时只有 14/3,492 个 host 被抽样，其余 3,478 个仍是全量探测；
    单 host 抽 2,000 个样本对该 host 的比例估计已是约 ±1%。
    被排除的显式记为 sampled_out，**既不是探测失败也不是不活跃**，
    报告必须按 host 规模回权，不能直接把它们并进分母。
    """
    import random

    by_host: dict[str, list[ProbeTarget]] = {}
    for t in targets:
        host, *_ = parse_endpoint(t.endpoint)
        by_host.setdefault((host or "?").lower(), []).append(t)

    keep: list[ProbeTarget] = []
    dropped: list[ProbeTarget] = []
    for host, items in by_host.items():
        if len(items) <= cap:
            keep.extend(items)
            continue
        rnd = random.Random(f"{seed}:{host}")     # 固定种子，复跑抽到同一批
        idx = list(range(len(items)))
        rnd.shuffle(idx)
        chosen = set(idx[:cap])
        keep.extend(items[i] for i in sorted(chosen))
        dropped.extend(items[i] for i in range(len(items)) if i not in chosen)
        log.info("probe_host_sampled", host=host, total=len(items),
                 kept=cap, dropped=len(items) - cap)
    return keep, dropped


def make_probe_config(cfg: Config) -> ProbeConfig:
    return ProbeConfig.from_toml(cfg.scan, cfg.user_agent, cfg.blocklist)


def plan(cfg: Config, targets: list[ProbeTarget]) -> dict:
    return dry_run_plan(targets, make_probe_config(cfg))


def _row_from_result(res: dict, probe_round: int) -> list[dict]:
    """probe 输出 schema v1.0 → probe_attempt 表的逐层行。"""
    ref = res.get("ref") or ""
    try:
        chain_id, agent_id, service_idx = (int(x) for x in ref.split(":"))
    except ValueError:
        return []
    rows = []
    for layer, d in res["layers"].items():
        row = {
            "probe_round": probe_round,
            "chain_id": chain_id,
            "agent_id": agent_id,
            "service_idx": service_idx,
            "layer": layer,
            "outcome": d.get("outcome"),
            "elapsed_ms": d.get("elapsed_ms"),
            "error_detail": d.get("error"),
            "probed_at": res.get("probed_at"),
        }
        if layer == "dns":
            row["resolved_ips"] = d.get("resolved_ips")
            row["ip_class"] = d.get("ip_class")
        elif layer == "tls":
            row["tls_ok"] = d.get("tls_ok")
            row["tls_error_kind"] = d.get("error_kind")
            row["tls_not_after"] = d.get("not_after")
        elif layer == "http":
            row["http_status"] = d.get("status")
            row["server_header"] = d.get("server")
            row["body_bytes"] = d.get("body_bytes")
        elif layer == "proto":
            row["proto_kind"] = d.get("kind")
            row["proto_ok"] = d.get("ok")
            row["proto_version"] = d.get("version")
            row["server_name"] = d.get("server_name")
            row["server_version"] = d.get("server_version")
            row["tool_count"] = d.get("tool_count")
            caps = d.get("capabilities")
            if caps is not None:
                import json as _j

                row["capabilities_json"] = _j.dumps(caps, ensure_ascii=False)[:4000]
        rows.append(row)
    return rows


async def run_probe(
    cfg: Config, targets: list[ProbeTarget], probe_round: int, *, spool: Spool | None = None, progress=None
) -> dict:
    own = spool is None
    spool = spool or Spool(cfg.root, STAGE)
    pcfg = make_probe_config(cfg)
    stats = {"targets": len(targets), "done": 0, "by_proto_outcome": {}}

    async def on_result(res: dict):
        for row in _row_from_result(res, probe_round):
            spool.write("probe_attempt", row)
        stats["done"] += 1
        o = res["layers"].get("proto", {}).get("outcome", "?")
        stats["by_proto_outcome"][o] = stats["by_proto_outcome"].get(o, 0) + 1
        if progress and stats["done"] % 50 == 0:
            progress(stats["done"], len(targets), stats)

    await probe_many(targets, pcfg, on_result=on_result)
    if own:
        spool.close()
    stats["spool_file"] = str(spool.path)
    return stats
