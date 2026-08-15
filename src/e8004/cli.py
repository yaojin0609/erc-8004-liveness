"""e8004 命令行入口。命令面见 docs/接口契约.md §1。

退出码：0 成功 / 1 一般错误 / 2 配置错误 / 3 DoD 断言失败。
`run-all` 和 CI 靠退出码 3 强制停下，而不是靠人自觉。
"""

from __future__ import annotations

import asyncio
import json as jsonlib
import logging
from pathlib import Path

import structlog
import typer
from rich.console import Console
from rich.table import Table

from . import db as dbm
from .config import Config, ConfigError, load_config

app = typer.Typer(add_completion=False, help="ERC-8004 注册身份活性扫描器")
console = Console()

EXIT_CONFIG = 2
EXIT_DOD = 3

_state: dict = {"root": ".", "db": None}


def _setup_logging(level: str) -> None:
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, level.upper(), logging.INFO)),
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="%H:%M:%S"),
            structlog.dev.ConsoleRenderer(),
        ],
    )


@app.callback()
def main(
    config_dir: str = typer.Option(".", "--root", help="仓库根目录"),
    db_path: str = typer.Option(None, "--db", help="DuckDB 路径"),
    log_level: str = typer.Option("info", "--log-level"),
):
    _state["root"] = config_dir
    _state["db"] = db_path
    _setup_logging(log_level)


def _cfg(require_identity: bool = True) -> Config:
    try:
        return load_config(_state["root"], require_identity=require_identity)
    except ConfigError as e:
        console.print(f"[red]配置错误:[/red] {e}")
        raise typer.Exit(EXIT_CONFIG)


def _conn(read_only: bool = False):
    conn = dbm.connect(_state["root"], _state["db"], read_only=read_only)
    if not read_only:
        dbm.migrate(conn, _state["root"])
    return conn


# ============================================================== status


@app.command()
def status(json_out: bool = typer.Option(False, "--json")):
    """每次坐下来先跑这个：上次跑到哪、下一步干嘛。"""
    cfg = _cfg(require_identity=False)
    root = Path(_state["root"])
    dbfile = Path(_state["db"] or (root / dbm.DEFAULT_DB))

    info: dict = {"db": str(dbfile), "db_exists": dbfile.exists(), "chains": [], "spool": [], "next": []}

    # spool 待入库
    spool_root = root / "data" / "spool"
    if spool_root.is_dir():
        for stage_dir in sorted(spool_root.iterdir()):
            if not stage_dir.is_dir():
                continue
            files = list(stage_dir.glob("*.jsonl"))
            if files:
                lines = sum(sum(1 for _ in open(f, encoding="utf-8")) for f in files)
                info["spool"].append({"stage": stage_dir.name, "files": len(files), "rows": lines})

    if dbfile.exists():
        conn = dbm.connect(root, _state["db"], read_only=True)
        try:
            for ch in cfg.active_chains():
                row = conn.execute(
                    "SELECT verified_at, deploy_block FROM chain WHERE chain_id = ?", [ch.chain_id]
                ).fetchone()
                cur = dbm.get_cursor(conn, "scan-logs", ch.chain_id)
                n_reg = dbm.scalar(
                    conn, "SELECT count(*) FROM ev_registered WHERE chain_id = ?", [ch.chain_id]
                )
                info["chains"].append(
                    {
                        "name": ch.name,
                        "tier": ch.tier,
                        "bootstrap": "verified" if row and row[0] else "未验证",
                        "scan_cursor": cur,
                        "registered": n_reg or 0,
                    }
                )
            info["probe_rounds"] = conn.execute(
                "SELECT probe_round, count(*) FROM probe_attempt GROUP BY 1 ORDER BY 1"
            ).fetchall()
        finally:
            conn.close()
    else:
        info["chains"] = [{"name": c.name, "tier": c.tier, "bootstrap": "无数据库"} for c in cfg.active_chains()]

    # 下一步建议 —— 必须是可直接复制执行的命令
    if not dbfile.exists() or not any(c.get("bootstrap") == "verified" for c in info["chains"]):
        info["next"].append("e8004 bootstrap")
    for s in info["spool"]:
        info["next"].append(f"e8004 load {s['stage']}")
    for c in info["chains"]:
        if c.get("bootstrap") == "verified" and not c.get("registered"):
            info["next"].append(f"e8004 scan-logs --chain {c['name']}")
    if not info["next"]:
        info["next"].append("e8004 fetch-uri")

    if json_out:
        console.print_json(jsonlib.dumps(info, default=str))
        return

    console.print(f"[bold]db:[/bold] {info['db']} {'' if info['db_exists'] else '[dim](尚未创建)[/dim]'}")
    t = Table("CHAIN", "TIER", "BOOTSTRAP", "SCAN CURSOR", "REGISTERED")
    for c in info["chains"]:
        t.add_row(c["name"], c["tier"], str(c.get("bootstrap")), str(c.get("scan_cursor") or "—"), str(c.get("registered", "—")))
    console.print(t)
    if info["spool"]:
        console.print("\n[bold]SPOOL 待入库[/bold]")
        for s in info["spool"]:
            console.print(f"  {s['stage']}: {s['files']} 个文件 / {s['rows']:,} 行")
    console.print("\n[bold]下一步[/bold]")
    for n in dict.fromkeys(info["next"]):
        console.print(f"  {n}")


# ============================================================== diagnose


@app.command()
def diagnose(chain: str = typer.Option(None, "--chain"), deploy_block: bool = typer.Option(False, "--deploy-block")):
    """对所有候选 0x8004 地址做身份鉴定：同一条链上多个注册表时该扫哪个。"""
    from .stages.s01_bootstrap import diagnose_chain

    cfg = _cfg()
    chains = [cfg.chain(chain)] if chain else cfg.active_chains()

    async def run():
        for ch in chains:
            try:
                head, reports = await diagnose_chain(cfg, ch, cfg.candidates, deploy_block=deploy_block)
            except Exception as e:  # noqa: BLE001
                console.print(f"[red]{ch.name}: {type(e).__name__}: {e}[/red]")
                continue
            console.print(f"\n[bold]{ch.name}[/bold] (chain_id={ch.chain_id}) head={head:,}")
            t = Table("候选", "类型", "implementation", "name", "近期 Registered", "deploy_block")
            for r in reports:
                t.add_row(
                    r.label,
                    r.kind,
                    (r.implementation or "—")[:12],
                    r.name or (r.identity_registry or "—")[:12],
                    "—" if r.recent_registered is None else str(r.recent_registered),
                    str(r.deploy_block or "—"),
                )
            console.print(t)

    asyncio.run(run())


# ============================================================== bootstrap


@app.command()
def bootstrap(chain: str = typer.Option(None, "--chain"), all_chains: bool = typer.Option(False, "--all")):
    """T0：地址验证 + 部署区块发现。写入 chain 表。"""
    from .stages.s01_bootstrap import bootstrap_chain

    cfg = _cfg()
    chains = [cfg.chain(chain)] if chain else cfg.active_chains(None if all_chains else "A")
    conn = _conn()
    failures = 0

    async def run():
        nonlocal failures
        for ch in chains:
            try:
                res = await bootstrap_chain(cfg, ch)
            except Exception as e:  # noqa: BLE001
                console.print(f"[red]✗ {ch.name}: {type(e).__name__}: {e}[/red]")
                failures += 1
                continue
            reg = cfg.registries_for(ch)
            conn.execute(
                """INSERT OR REPLACE INTO chain
                   (chain_id, name, tier, is_testnet, identity_registry, reputation_registry,
                    validation_registry, deploy_block, confirmations, supports_finalized,
                    max_log_range, verified_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?, CASE WHEN ? THEN now() ELSE NULL END)""",
                [
                    ch.chain_id, ch.name, ch.tier, ch.is_testnet, reg.identity, reg.reputation,
                    reg.validation or None, res.get("deploy_block"), ch.confirmations,
                    ch.supports_finalized, ch.max_log_range, res["verified"],
                ],
            )
            mark = "[green]✓[/green]" if res["verified"] else "[red]✗[/red]"
            console.print(f"{mark} {ch.name}: head={res['head']:,} deploy_block={res.get('deploy_block')}")
            for e in res["errors"]:
                console.print(f"    [red]错误 {e}[/red]")
            for w in res.get("warnings", []):
                console.print(f"    [yellow]降级 {w}[/yellow]")
            if not res["verified"]:
                failures += 1

    asyncio.run(run())
    conn.close()
    if failures:
        console.print(f"\n[red]{failures} 条链未通过验证[/red]")
        raise typer.Exit(EXIT_DOD)


# ============================================================== scan-logs


@app.command("scan-logs")
def scan_logs(
    chain: str = typer.Option(..., "--chain"),
    from_block: int = typer.Option(None, "--from-block"),
    to_block: int = typer.Option(None, "--to-block"),
    resume: bool = typer.Option(True, "--resume/--no-resume"),
    registry: str = typer.Option(None, "--registry",
                                 help="只扫某个注册表：identity | reputation。"
                                      "留空则两个都扫"),
):
    """T1/T2：全量事件扫描。写 spool，扫完跑 `e8004 load scan-logs`。"""
    from .stages.s02_logs import STAGE, scan_chain

    cfg = _cfg()
    ch = cfg.chain(chain)
    conn = _conn()

    start = from_block
    if start is None and resume:
        cur = dbm.get_cursor(conn, STAGE, ch.chain_id)
        if cur:
            start = int(cur) + 1
            console.print(f"[dim]从游标续跑: {start:,}[/dim]")
    if start is None:
        row = conn.execute("SELECT deploy_block FROM chain WHERE chain_id = ?", [ch.chain_id]).fetchone()
        start = (row[0] if row and row[0] else None) or ch.deploy_block or 0
    conn.close()

    last_report = [0]

    def progress(done: int, head: int, stats: dict):
        pct = 100.0 * (done - start) / max(1, head - start)
        if done - last_report[0] > 200_000 or pct >= 100:
            console.print(f"  [dim]{pct:5.1f}%  block {done:,}/{head:,}  logs={stats['logs']:,}[/dim]")
            last_report[0] = done

    async def run():
        return await scan_chain(cfg, ch, from_block=start, to_block=to_block,
                                progress=progress, registry_filter=registry)

    stats = asyncio.run(run())
    console.print(f"\n[green]✓[/green] {ch.name}: {stats['logs']:,} 条日志 / 解码 {stats['decoded']:,}")
    for k, v in sorted(stats["by_event"].items()):
        console.print(f"    {k}: {v:,}")
    console.print(f"  spool: {stats['spool_file']}")

    conn = _conn()
    dbm.set_cursor(conn, STAGE, ch.chain_id, stats["to_block"])
    conn.close()
    console.print(f"\n下一步:  e8004 load {STAGE}")


# ============================================================== census


@app.command()
def census(chain: str = typer.Option(None, "--chain")):
    """平行注册表普查：有多少注册落在那组死的注册表上。"""
    from .stages.s02_logs import census_registry

    cfg = _cfg()
    chains = [cfg.chain(chain)] if chain else cfg.active_chains("A")
    conn = _conn()

    async def run():
        for ch in chains:
            for label, addr in cfg.candidates.items():
                canonical = addr in (cfg.registries.identity, cfg.registries.reputation)
                if "identity" not in label:
                    continue
                try:
                    row = await census_registry(cfg, ch, label, addr, canonical)
                except Exception as e:  # noqa: BLE001
                    console.print(f"[red]{ch.name}/{label}: {e}[/red]")
                    continue
                conn.execute(
                    """INSERT OR REPLACE INTO registry_census
                       (chain_id, registry, label, is_canonical, implementation, is_erc721,
                        registered_total, first_block, last_block, measured_at)
                       VALUES (?,?,?,?,?,?,?,?,?, now())""",
                    [row["chain_id"], row["registry"], row["label"], row["is_canonical"],
                     row["implementation"], row["is_erc721"], row["registered_total"],
                     row["first_block"], row["last_block"]],
                )
                console.print(
                    f"  {ch.name:10s} {label:12s} {'canonical' if canonical else 'parallel ':10s} "
                    f"Registered={row['registered_total']:,}"
                )

    asyncio.run(run())
    conn.close()


# ============================================================== count / snapshot


@app.command("count-agents")
def count_agents_cmd(
    all_chains: bool = typer.Option(True, "--all/--tier-a"),
    chain: str = typer.Option(None, "--chain", help="只数这一条链（重试被限流的链时用）"),
):
    """L0 人口普查：每条链的 agent 总数。ownerOf 二分，每条链约 17 次调用，不需要 archive。"""
    from .stages.s03_state import count_all_chains

    cfg = _cfg()
    if chain:
        chains = [cfg.chain(chain)]
    else:
        chains = cfg.active_chains() if all_chains else cfg.active_chains("A")
    def on_done(r):
        v = f"{r['total']:,}" if r["total"] is not None else f"— ({r['note']})"
        console.print(f"  [dim]{r['chain']:12s} {v}[/dim]")

    rows = asyncio.run(count_all_chains(cfg, chains, on_done=on_done))

    t = Table("CHAIN", "CHAIN_ID", "AGENTS", "备注")
    total = 0
    for r in sorted(rows, key=lambda x: -(x["total"] or 0)):
        t.add_row(r["chain"], str(r["chain_id"]), f"{r['total']:,}" if r["total"] is not None else "—", r["note"])
        total += r["total"] or 0
    console.print(t)
    console.print(f"\n[bold]合计: {total:,}[/bold]  （口径 A：链上注册数，未跨链去重）")

    conn = _conn()
    for r in rows:
        if r["total"] is None:
            continue
        conn.execute(
            """INSERT OR REPLACE INTO registry_census
               (chain_id, registry, label, is_canonical, registered_total, measured_at)
               VALUES (?,?,?,?,?, now())""",
            [r["chain_id"], cfg.registries.identity, "identity_canonical", True, r["total"]],
        )
    conn.close()


@app.command("snapshot-state")
def snapshot_state(
    chain: str = typer.Option(..., "--chain"),
    snapshot: str = typer.Option(..., "--snapshot"),
    limit: int = typer.Option(None, "--limit"),
    start_id: int = typer.Option(0, "--start-id"),
):
    """T2：Multicall3 批量读 ownerOf/tokenURI/getAgentWallet。不需要 archive 节点。"""
    from .stages.s03_state import STAGE, snapshot_chain

    cfg = _cfg()
    ch = cfg.chain(chain)
    last = [0]

    def progress(done: int, total: int, st: dict):
        if done - last[0] >= 3000 or done == total:
            console.print(f"  [dim]{done:,}/{total:,}  存活={st['alive']:,} 有URI={st['with_uri']:,}[/dim]")
            last[0] = done

    stats = asyncio.run(snapshot_chain(cfg, ch, snapshot, limit=limit, start_id=start_id, progress=progress))
    console.print(
        f"\n[green]✓[/green] {ch.name}: 总量 {stats['total_agents']:,}，读取 {stats['read']:,}，"
        f"存活 {stats['alive']:,}，有 URI {stats['with_uri']:,}，有 wallet {stats['with_wallet']:,}"
    )
    conn = _conn()
    # snapshot 表对 chain 有外键。快照本身不依赖 bootstrap 的结果，
    # 所以这里先补一行最小的 chain 记录（verified_at 留空表示尚未做地址验证）。
    reg = cfg.registries_for(ch)
    conn.execute(
        """INSERT OR IGNORE INTO chain
           (chain_id, name, tier, is_testnet, identity_registry, reputation_registry,
            validation_registry, confirmations, supports_finalized, max_log_range)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        [ch.chain_id, ch.name, ch.tier, ch.is_testnet, reg.identity, reg.reputation,
         reg.validation or None, ch.confirmations, ch.supports_finalized, ch.max_log_range],
    )
    if stats.get("block_hash"):
        conn.execute(
            """INSERT OR REPLACE INTO snapshot (snapshot_id, chain_id, block_number, block_hash,
                                                block_timestamp, created_at)
               VALUES (?,?,?,?, to_timestamp(?), now())""",
            [snapshot, ch.chain_id, stats["head"], stats["block_hash"], stats["block_timestamp"]],
        )
    dbm.set_cursor(conn, STAGE, ch.chain_id, stats["read"])
    conn.close()
    console.print(f"下一步:  e8004 load {STAGE}")


# ============================================================== load


@app.command("verify-coverage")
def verify_coverage(strict: bool = typer.Option(False, "--strict",
                                                help="有缺口就以非零码退出，可挂进流水线当门槛")):
    """核对注册记录的完整性。纯 SQL，不碰网络。

    【为什么需要这个】RPC 端点静默丢日志已经在本仓发生三次：flashbots 对历史区间
    返空、scroll 端点校验被跳过、celo 返回 200 + 截断的结果集。三次都是「看起来
    成功了」。共同点是**扫描自己发现不了**。

    这里用一条数据本身的性质来兜底：agentId 从 0 顺序递增，所以
      1) 注册记录的 agent_id 应当从 0 连续到最大值，缺号即丢数据；
      2) 有注册时间的 agent 数应当等于普查数。
    两条都不依赖 RPC 是否诚实。
    """
    conn = _conn()
    rows = conn.execute("""
        WITH reg AS (
            SELECT chain_id, agent_id FROM ev_registered
            UNION
            SELECT chain_id, agent_id FROM agent_mint
        )
        SELECT s.chain_id,
               count(*)                       AS census,
               count(DISTINCT r.agent_id)     AS known,
               max(s.agent_id)                AS max_id
        FROM agent_state s
        LEFT JOIN reg r ON r.chain_id = s.chain_id AND r.agent_id = s.agent_id
        GROUP BY 1 ORDER BY 2 DESC
    """).fetchall()

    t = Table("chain", "普查", "有注册记录", "缺口", "最大 agent_id", "结论")
    bad = 0
    for cid, census, known, max_id in rows:
        gap = census - known
        if gap > 0:
            bad += 1
        t.add_row(str(cid), f"{census:,}", f"{known:,}", f"{gap:,}", f"{max_id:,}",
                  "[green]完整[/green]" if gap <= 0 else f"[red]缺 {100*gap/census:.1f}%[/red]")
    console.print(t)

    if bad:
        console.print(
            f"\n[red]{bad} 条链的注册记录不完整。[/red]这通常【不是】链上真的没有，"
            "而是 RPC 端点静默丢了日志（返空或截断）。"
            "对应链调小 max_log_range 后重扫，别直接引用当前数字。"
        )
    else:
        console.print("\n[green]✓[/green] 所有链的注册记录数与普查数一致")
    conn.close()
    if bad and strict:
        raise typer.Exit(EXIT_DOD)


@app.command("scan-mints")
def scan_mints_cmd(
    chain: str = typer.Option(None, "--chain", help="留空则扫所有配了 Alchemy 端点的链"),
    resume: bool = typer.Option(True, "--resume/--no-resume"),
):
    """T1b：注册（mint）历史。绕开免费档 eth_getLogs 的 10 区块限制。

    写 spool，扫完跑 `e8004 load scan-mints`。
    """
    from .stages.s02b_mints import STAGE, NotSupported, scan_mints
    from .spool import Spool

    cfg = _cfg()
    root = Path(_state["root"])
    chains = [cfg.chain(chain)] if chain else [c for c in cfg.chains if c.active]

    conn = _conn()
    cursors = {c.chain_id: (dbm.get_cursor(conn, STAGE, c.chain_id) if resume else None)
               for c in chains}
    conn.close()

    skipped: list[str] = []
    for ch in chains:
        cur = cursors.get(ch.chain_id)
        # 游标 'done' 表示上次已扫完，不要再敲一遍别人的 API
        if cur == "done":
            console.print(f"[dim]{ch.name}: 已完成，跳过（--no-resume 可强制重扫）[/dim]")
            continue
        try:
            with Spool(root, STAGE) as sp:
                def on_page(pages: int, n: int, page_key, _ch=ch):
                    if pages % 20 == 0:
                        console.print(f"  [dim]{_ch.name}: {pages} 页 / {n:,} 条[/dim]")

                stats = asyncio.run(scan_mints(cfg, ch, sp, start_page_key=cur, on_page=on_page))
                spool_path = sp.path
        except NotSupported as e:
            skipped.append(f"{ch.name}: {e}")
            continue
        # 游标必须在 spool 落盘【之后】写，否则进程在中间挂掉会跳过没入库的页
        conn = _conn()
        dbm.set_cursor(conn, STAGE, ch.chain_id, stats["page_key"] or "done")
        conn.close()
        console.print(f"[green]✓[/green] {ch.name}: {stats['mints']:,} 条 mint / "
                      f"{stats['pages']} 页 → {spool_path.name}")
    for s in skipped:
        console.print(f"[yellow]跳过 {s}[/yellow]")


@app.command()
def load(stage: str = typer.Argument(..., help="scan-logs / scan-mints / fetch-uri / probe ...")):
    """把 spool JSONL 入库。幂等。"""
    conn = _conn()
    counts = dbm.load_spool(conn, _state["root"], stage)
    conn.close()
    if not counts:
        console.print(f"[yellow]{stage}: 没有待入库的 spool 文件[/yellow]")
        return
    for table, n in sorted(counts.items()):
        console.print(f"  {table}: {n:,} 行")
    console.print("[green]✓[/green] 入库完成")


# ============================================================== fetch-uri / parse / probe / funnel


@app.command("fetch-uri")
def fetch_uri(
    chain: str = typer.Option(None, "--chain"),
    limit: int = typer.Option(None, "--limit"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    retry_status: str = typer.Option(None, "--retry-status",
                                     help="重跑指定 status 的记录（逗号分隔），如 other,conn_error"),
    retry_scheme: str = typer.Option(None, "--retry-scheme",
                                     help="配合 --retry-status 限定 scheme_kind，如 data"),
    retry_like: str = typer.Option(None, "--retry-like",
                                   help="配合 --retry-status 限定 URI 的 SQL LIKE 模式，"
                                        "如 %/ipfs/%（只重跑被误判成普通 https 的网关 URL）"),
):
    """T3：agentURI 抓取。唯一网络出口 A。写 spool。"""
    from .stages.s04_uri_fetch import STAGE, apply_host_cap, collect_uris, fetch_all

    cfg = _cfg()
    conn = _conn()
    chain_id = cfg.chain(chain).chain_id if chain else None

    if retry_status:
        # 解析器修好之后重跑受影响的记录：删掉旧行，它们就会重新进入 todo。
        # 比如 data: URI 的 gzip / utf8 / 空格分隔变体原来被当成 malformed 丢掉了。
        sts = [x.strip() for x in retry_status.split(",") if x.strip()]
        q = "DELETE FROM uri_fetch WHERE status IN ({})".format(",".join("?" for _ in sts))
        params: list = list(sts)
        if retry_scheme:
            q += " AND scheme_kind = ?"
            params.append(retry_scheme)
        if retry_like:
            # 分类器修好之后，老记录里的 scheme_kind 是【按旧代码】写的，
            # 用它没法圈出「本该是 ipfs 却被记成 https」的那批。按 URI 形态圈。
            q += " AND uri_normalized LIKE ?"
            params.append(retry_like)
        # 【--dry-run 绝不能落盘】硬约束要求全量抓取前先跑 dry-run 核对量级，
        # 如果 dry-run 自己把行删了，照规矩办事的人反而丢数据。
        # 放进事务里算完再回滚：既拿到真实的待抓数量，又不改库。
        conn.execute("BEGIN TRANSACTION")
        before = conn.execute("SELECT count(*) FROM uri_fetch").fetchone()[0]
        conn.execute(q, params)
        after = conn.execute("SELECT count(*) FROM uri_fetch").fetchone()[0]
        n_cleared = before - after

    todo, stats = collect_uris(conn, chain_id)
    if retry_status:
        conn.execute("ROLLBACK" if dry_run else "COMMIT")
        verb = "将清除" if dry_run else "清除"
        console.print(f"[cyan]重跑：{verb} {n_cleared:,} 条旧记录[/cyan]")
    conn.close()

    console.print(
        f"agent {stats['agents']:,} → 去重后 URI {stats['distinct_uris']:,} "
        f"[bold](去重系数 {stats['dedup_factor']}×)[/bold]，待抓 {stats['todo']:,}"
    )
    for k, v in sorted(stats["by_scheme"].items(), key=lambda kv: -kv[1]):
        console.print(f"    {k}: {v:,}")
    if dry_run:
        return
    tier = cfg.scan.get("fetch_tiering", {})
    cap = int(tier.get("max_uris_per_host", 8000))
    todo, sampled_out = apply_host_cap(todo, cap, int(tier.get("sample_seed", 8004)))
    if sampled_out:
        console.print(
            f"[yellow]单主机上限 {cap:,}：{len(sampled_out):,} 个 URI 抽样排除"
            f"（记为 sampled_out，不是失败）[/yellow]"
        )
    if limit:
        todo = todo[:limit]
    if not todo and not sampled_out:
        console.print("[yellow]没有待抓取的 URI[/yellow]")
        return

    last = [0]

    def progress(done, total, counts):
        if done - last[0] >= 500:
            console.print(f"  [dim]{done:,}/{total:,}  {dict(sorted(counts.items()))}[/dim]")
            last[0] = done

    res = asyncio.run(fetch_all(cfg, todo, sampled_out=sampled_out, progress=progress))
    console.print(f"\n[green]✓[/green] 抓取 {res['fetched']:,}")
    for k, v in sorted(res["by_status"].items(), key=lambda kv: -kv[1]):
        console.print(f"    {k}: {v:,}")
    console.print(f"\n下一步:  e8004 load {STAGE}")


@app.command("parse-cards")
def parse_cards(snapshot: str = typer.Option(None, "--snapshot")):
    """T4：blob → agent_card / service / card_registration。纯函数，可重跑。"""
    from .fetch import read_blob
    from .stages.s05_card_parse import parse_card

    cfg = _cfg(require_identity=False)
    conn = _conn()
    root = Path(_state["root"])

    sql = """
    SELECT s.chain_id, s.agent_id, f.content_sha256
    FROM agent_state s
    JOIN uri_fetch f ON f.uri_normalized = s.token_uri
    WHERE f.status IN ('ok','not_json') AND f.content_sha256 IS NOT NULL
    """
    params: list = []
    if snapshot:
        sql += " AND s.snapshot_id = ?"
        params.append(snapshot)
    rows = conn.execute(sql, params).fetchall()
    console.print(f"待解析 {len(rows):,} 个 agent card")

    dbm.reset_derived(conn, ["agent_card", "service", "card_registration"], root)

    n_strict = n_lenient = n_svc = n_reg = n_missing = 0
    CH = 5000
    buf_card: list = []
    buf_svc: list = []
    buf_reg: list = []

    def flush():
        # 【批量插入，不要逐行】39 万张 card × 3 张表 = 上百万次单行 INSERT，
        # DuckDB 逐行插入在这个量级会慢到不可接受。
        if buf_card:
            conn.executemany(
                "INSERT OR REPLACE INTO agent_card VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", buf_card)
            buf_card.clear()
        if buf_svc:
            conn.executemany("INSERT OR REPLACE INTO service VALUES (?,?,?,?,?,?,?,?,?)", buf_svc)
            buf_svc.clear()
        if buf_reg:
            conn.executemany("INSERT OR REPLACE INTO card_registration VALUES (?,?,?,?,?)", buf_reg)
            buf_reg.clear()

    for i, (chain_id, agent_id, sha) in enumerate(rows):
        raw = read_blob(root, sha)
        if raw is None:
            n_missing += 1
            continue
        out = parse_card(raw, chain_id, agent_id, sha)
        c = out["card"]
        n_strict += bool(c["schema_valid_strict"])
        n_lenient += bool(c["parsed_lenient"])
        buf_card.append([
            c["chain_id"], c["agent_id"], c["content_sha256"], c["parsed_lenient"],
            c["schema_valid_strict"], c["schema_errors"], c["type_field"], c["name"],
            c["description"], c["image"], c["active"], c["x402_support"],
            c["supported_trust"], c["service_count"]])
        for sv in out["services"]:
            buf_svc.append([sv["chain_id"], sv["agent_id"], sv["service_idx"], sv["service_name"],
                            sv["endpoint"], sv["version"], sv["endpoint_host"],
                            sv["endpoint_scheme"], sv["is_routable"]])
            n_svc += 1
        for r in out["registrations"]:
            buf_reg.append([r["chain_id"], r["agent_id"], r["claimed_chain_id"],
                            r["claimed_registry"], r["claimed_agent_id"]])
            n_reg += 1
        if len(buf_card) >= CH:
            flush()
            if (i + 1) % 50000 == 0:
                console.print(f"  [dim]{i + 1:,}/{len(rows):,}[/dim]")
    flush()
    if n_missing:
        console.print(f"  [yellow]{n_missing:,} 个 blob 缺失（uri_fetch 记了 sha 但文件不在）[/yellow]")

    total = max(1, len(rows))
    console.print(
        f"[green]✓[/green] 严格合规 {n_strict:,} ({100*n_strict/total:.1f}%)，"
        f"宽容解析 {n_lenient:,} ({100*n_lenient/total:.1f}%)，"
        f"service {n_svc:,}，跨链声明 {n_reg:,}"
    )
    t = Table("service_name", "数量", "可路由")
    for name, n, r in conn.execute(
        "SELECT coalesce(service_name,'(null)'), count(*), sum(is_routable::INT) FROM service GROUP BY 1 ORDER BY 2 DESC"
    ).fetchall():
        t.add_row(str(name), f"{n:,}", f"{r or 0:,}")
    console.print(t)
    conn.close()


@app.command()
def probe(
    probe_round: int = typer.Option(1, "--round"),
    limit: int = typer.Option(None, "--limit"),
    chain: str = typer.Option(None, "--chain"),
    dry_run: bool = typer.Option(False, "--dry-run"),
):
    """T6：四层活性探测。全量前必须先 --dry-run 核对量级。"""
    from .stages.s06_probe import STAGE, apply_target_host_cap, load_targets, plan, run_probe

    cfg = _cfg()
    conn = _conn()
    targets = load_targets(conn, limit, cfg.chain(chain).chain_id if chain else None)
    conn.close()

    # 单 host 上限：耗时由最大的 host 决定（1 请求/3 秒串行），不是由目标总数决定。
    # 必须在 plan() 【之前】应用，否则 --dry-run 报的是没上限的量级，核对就白核对了。
    pcfg = cfg.scan.get("probe", {})
    cap = int(pcfg.get("max_targets_per_host", 0) or 0)
    sampled_out: list = []
    if cap > 0:
        before = len(targets)
        targets, sampled_out = apply_target_host_cap(
            targets, cap, int(pcfg.get("sample_seed", 8004)))
        if sampled_out:
            console.print(
                f"[yellow]单 host 上限 {cap:,}：{len(sampled_out):,} 个目标抽样排除"
                f"（{before:,} → {len(targets):,}），记为 sampled_out，不是失败[/yellow]"
            )

    p = plan(cfg, targets)
    console.print(
        f"目标 {p['targets']:,}，唯一 host {p['unique_hosts']:,}，"
        f"预计请求 {p['estimated_requests']:,}，预计耗时 {p['eta_seconds'] / 60:.1f} 分钟"
    )
    console.print(f"  按类型: {p['by_kind']}")
    console.print(f"  目标最多的 host: {p['top_hosts'][:5]}")
    if dry_run:
        console.print("\n[yellow]--dry-run：未发起任何请求[/yellow]")
        return
    if not targets:
        console.print("[yellow]没有可探测的目标[/yellow]")
        return

    last = [0]

    def progress(done, total, st):
        if done - last[0] >= 100:
            console.print(f"  [dim]{done:,}/{total:,}  proto: {st['by_proto_outcome']}[/dim]")
            last[0] = done

    res = asyncio.run(run_probe(cfg, targets, probe_round, progress=progress))
    console.print(f"\n[green]✓[/green] 探测 {res['done']:,}，协议层结果 {res['by_proto_outcome']}")
    console.print(f"下一步:  e8004 load {STAGE}")


@app.command()
def funnel(snapshot: str = typer.Option(..., "--snapshot")):
    """T11：漏斗物化。纯 SQL，同一份 DB 跑两次结果必须一致。"""
    from .stages.s08_funnel import LAYER_LABELS, build_funnel, cohort_table

    _cfg(require_identity=False)
    conn = _conn()

    # 【覆盖率安全阀】L1 的分母是「所有声明了 agentURI 的 agent」。
    # 如果抓取没跑完，L1 率会被稀释成一个偏低的假数字，而报告看起来完全正常 ——
    # 实测就发生过：一个畸形 tokenURI 让抓取只完成 31%，报告照常产出。
    cov = conn.execute(
        """SELECT count(DISTINCT s.token_uri),
                  count(DISTINCT CASE WHEN f.uri_normalized IS NOT NULL THEN s.token_uri END)
           FROM agent_state s
           LEFT JOIN uri_fetch f ON f.uri_normalized = s.token_uri
           WHERE s.snapshot_id = ? AND s.token_uri IS NOT NULL AND s.token_uri <> ''""",
        [snapshot],
    ).fetchone()
    n_uri, n_fetched = cov[0] or 0, cov[1] or 0

    summary = build_funnel(conn, snapshot, root=_state["root"])
    l0 = max(1, summary["l0"] or 0)

    probed = summary.get("probed") or 0
    l2 = summary.get("l2") or 0
    sampled = summary.get("uri_sampled_out") or 0
    # L1/L1s/L2 的分母要剔除被主动抽样排除的 agent —— 把「我们没抓」
    # 算成「它没有元数据」是系统性低估。
    l0_eff = max(1, l0 - sampled)
    meta_layers = {"l1", "l1s", "l2"}
    # L3 各层的分母是【被探测过的 agent】，不是 L0 —— 否则探测覆盖率不足会
    # 直接被读成「存活率低」。同时把覆盖率明确打出来。
    probe_layers = {"l3a", "l3b", "l3c", "l3", "l3_stable"}
    t = Table("层级", "定义", "存活数", "占 L0", "占有效分母")
    for key, label in LAYER_LABELS:
        v = summary.get(key) or 0
        if key in probe_layers and probed:
            cond = f"{100 * v / probed:.1f}% (已探测)"
        elif key in meta_layers:
            cond = f"{100 * v / l0_eff:.2f}%"
        else:
            cond = "—"
        t.add_row(key.upper(), label, f"{v:,}", f"{100 * v / l0:.2f}%", cond)
    console.print(t)
    if sampled:
        console.print(
            f"\n[cyan]单主机上限抽样排除 {sampled:,} 个 agent[/cyan]（既非失败也非未抓）。"
            f"L1/L1s/L2 的「占有效分母」列已剔除它们，分母 = {l0_eff:,}。"
        )
    # 覆盖率分档：99% 以上属于正常残差（新注册、规范化边界），不该和
    # 「抓取中断只完成 31%」用同一种措辞 —— 过度告警会让真正的告警失去意义。
    pct = 100 * n_fetched / max(1, n_uri)
    if pct < 99.0:
        console.print(
            f"\n[red]⚠ URI 抓取覆盖率 {n_fetched:,}/{n_uri:,} = {pct:.1f}%[/red]"
            " —— L1/L1s/L2 全部被稀释，【不可引用】。先跑 `e8004 fetch-uri` 补齐再重算。"
        )
    elif n_fetched < n_uri:
        console.print(
            f"\n[dim]URI 抓取覆盖率 {n_fetched:,}/{n_uri:,} = {pct:.2f}%"
            f"（缺 {n_uri - n_fetched:,} 个，属正常残差，不影响结论）[/dim]"
        )
    if probed < l2:
        console.print(
            f"\n[yellow]⚠ 探测覆盖率 {probed:,}/{l2:,} = {100 * probed / max(1, l2):.1f}%[/yellow]"
            "  —— L3 各层的「占 L0」列被覆盖率稀释，请只引用「占已探测」列。"
        )
    console.print(
        f"\n旁支（不计入 L3 失败）: 自我声明不活跃 {summary['declared_inactive']:,}，"
        f"端点不可路由 {summary['unroutable']:,}"
    )

    rows = cohort_table(conn, snapshot)
    if rows and not (len(rows) == 1 and rows[0][0] == "unknown"):
        ct = Table("注册月份", "注册数", "L1", "L2", "L3", "L3 存活率")
        for m, n, l1, l2, l3 in rows:
            ct.add_row(m, f"{n:,}", f"{l1 or 0:,}", f"{l2 or 0:,}", f"{l3 or 0:,}",
                       f"{100 * (l3 or 0) / max(1, n):.1f}%")
        console.print(ct)
    else:
        console.print("[yellow]队列分析不可用：缺少注册时间戳（需要 archive 节点扫历史日志）[/yellow]")
    conn.close()


@app.command()
def analyze(
    what: str = typer.Argument("all", help="concentration | dedup | hosts | crossval | all"),
    snapshot: str = typer.Option(..., "--snapshot"),
    persist: bool = typer.Option(False, "--persist/--no-persist",
                                 help="把逐个 agent 的归并结果写入 identity_cluster（39 万行约 4 分钟）"),
):
    """集中度 / 跨链去重 / 端点主机集中度 / 论文交叉验证。纯函数，不碰网络。"""
    from .analysis import concentration as conc
    from .analysis import dedup as dd

    _cfg(require_identity=False)
    conn = _conn()

    if what in ("concentration", "all"):
        console.print("\n[bold]所有权集中度[/bold]")
        t = Table("口径", "主体数", "身份数", "Gini", "HHI", "Top10 份额")
        cur = conc.owner_counts_current(conn, snapshot)
        if cur:
            r = conc.summarize(cur)
            t.add_row("当前 owner（全链）", f"{r['holders']:,}", f"{r['items']:,}",
                      f"{r['gini']:.4f}", f"{r['hhi']:.6f}", f"{100*r['top10_share']:.2f}%")
        reg = conc.owner_counts_at_registration(conn)
        if reg:
            r = conc.summarize(reg)
            t.add_row("注册时 owner（全链）", f"{r['holders']:,}", f"{r['items']:,}",
                      f"{r['gini']:.4f}", f"{r['hhi']:.6f}", f"{100*r['top10_share']:.2f}%")
        console.print(t)

    if what in ("hosts", "all"):
        rows = conc.endpoint_host_counts(conn)
        if rows:
            total = sum(n for _, n in rows)
            console.print("\n[bold]端点主机集中度[/bold]（论文未做的角度）")
            t = Table("host", "覆盖 agent 数", "占比")
            for h, n in rows[:10]:
                t.add_row(str(h), f"{n:,}", f"{100*n/max(1,total):.1f}%")
            console.print(t)
            r = conc.summarize([n for _, n in rows])
            top2 = sum(n for _, n in rows[:2])
            console.print(f"  主机 Gini={r['gini']:.4f}  前 2 个 host 覆盖 {100*top2/max(1,total):.1f}%")

    if what in ("dedup", "all"):
        cl = dd.build_clusters(conn, snapshot)
        st = cl["stats"]
        if persist:
            dd.persist(conn, snapshot, cl, root=_state["root"])
        console.print("\n[bold]跨链去重（口径 B）[/bold]")
        t = Table("置信度", "唯一主体数", "相对口径 A 压缩")
        a = st["registrations_total"]
        for k, label in (("unique_strong", "strong（registrations 双向确认）"),
                         ("unique_medium", "medium（card 哈希 + owner 相同）"),
                         ("unique_weak", "weak（owner + name 相同）")):
            v = st[k]
            t.add_row(label, f"{v:,}", f"{100*(1-v/max(1,a)):.1f}%")
        console.print(t)
        console.print(f"  口径 A（链上注册数）= {a:,}")
        console.print(f"  双向确认的跨链声明 {st['claims_bidirectional']:,} 组；"
                      f"单向声明 {st['claims_unidirectional_ignored']:,} 条【已忽略】"
                      "（任何人都能在自己 card 里声称是别人）")

    if what in ("crossval", "all"):
        res = conc.cross_validate_against_paper(conn, snapshot_id=snapshot)
        console.print("\n[bold]T8 交叉验证（对照已发表论文）[/bold]")
        if not res["available"]:
            for n in res["notes"]:
                console.print(f"  [yellow]不可用: {n}[/yellow]")
        else:
            o, p = res["ours"], res["paper"]
            console.print(f"  口径: {res['basis']}")
            t = Table("指标", "本研究", "论文", "结论")
            for k in ("gini", "hhi", "top10_share"):
                ok = abs(o[k] - p[k]) / max(abs(p[k]), 1e-9) <= 0.05
                t.add_row(k, f"{o[k]}", f"{p[k]}", "[green]一致[/green]" if ok else "[red]不一致[/red]")
            console.print(t)
            if not res["pass"]:
                for n in res["notes"]:
                    console.print(f"  [red]{n}[/red]")
                conn.close()
                raise typer.Exit(EXIT_DOD)
            # 门槛过了也要把并列口径打出来：注册时 owner 与当前 owner 的差
            # 就是「注册后发生了多少转让」，那是结论的一部分，不是调试信息。
            reg = res.get("at_registration")
            if reg:
                console.print(
                    f"  [dim]并列口径 注册时 owner: gini={reg['gini']} hhi={reg['hhi']} "
                    f"top10={reg['top10_share']}（主体数 {reg['holders']:,}）—— "
                    f"与当前 owner 的差异是注册后的转让，不是误差[/dim]"
                )
    conn.close()


@app.command()
def report(snapshot: str = typer.Option(..., "--snapshot")):
    """T12：渲染 Markdown 报告。文案纪律由 report.render.check_wording 强制。"""
    from .report.render import write_report

    _cfg(require_identity=False)
    conn = _conn()
    lims: list[str] = []
    row = conn.execute(
        "SELECT sum(l2_has_endpoint::INT), sum(probed::INT) FROM funnel WHERE snapshot_id = ?",
        [snapshot],
    ).fetchone()
    if row and row[0] and (row[1] or 0) < row[0]:
        lims.append(
            f"**探测覆盖率 {row[1] or 0:,}/{row[0]:,} = {100 * (row[1] or 0) / row[0]:.1f}%**。"
            "L3 各层的比率以【已探测】为分母；以 L0 为分母的列会被覆盖率稀释，不可直接引用。"
        )
    cov = conn.execute(
        """SELECT count(DISTINCT s.token_uri),
                  count(DISTINCT CASE WHEN f.uri_normalized IS NOT NULL THEN s.token_uri END)
           FROM agent_state s
           LEFT JOIN uri_fetch f ON f.uri_normalized = s.token_uri
           WHERE s.snapshot_id = ? AND s.token_uri IS NOT NULL AND s.token_uri <> ''""",
        [snapshot],
    ).fetchone()
    if cov and cov[0]:
        _p = 100 * (cov[1] or 0) / cov[0]
        if _p < 99.0:
            lims.append(
                f"**agentURI 抓取覆盖率仅 {cov[1] or 0:,}/{cov[0]:,} = {_p:.1f}%，"
                "L1/L1s/L2 三层被稀释，不可引用。**"
            )
        elif (cov[1] or 0) < cov[0]:
            lims.append(
                f"agentURI 抓取覆盖率 {cov[1] or 0:,}/{cov[0]:,} = {_p:.2f}%"
                f"（缺 {cov[0] - (cov[1] or 0):,} 个，属正常残差）。"
            )
    smp = conn.execute(
        "SELECT sum(uri_sampled_out::INT), count(*) FROM funnel WHERE snapshot_id = ?", [snapshot]
    ).fetchone()
    if smp and smp[0]:
        lims.append(
            f"**单主机抓取上限抽样**：{smp[0]:,} 个 agent 的 agentURI 因集中在少数主机而被"
            f"抽样排除（固定随机种子，可复现）。L1/L1s/L2 的分母已剔除它们"
            f"（有效分母 {smp[1] - smp[0]:,}）。被排除的记为 `sampled_out`，"
            "既不是抓取失败也不是「没有元数据」。"
        )
    if not conn.execute("SELECT count(*) FROM ev_registered").fetchone()[0]:
        lims.append("缺少历史日志（需要 archive 节点），因此没有注册时间戳、反馈与转让历史："
                    "队列分析、L4、L5 在本快照下不可用。")
    n2 = conn.execute("SELECT count(*) FROM probe_attempt WHERE probe_round = 2").fetchone()[0]
    if not n2:
        lims.append("只做了第 1 轮探测。L3-stable（两轮均通过）需要间隔 ≥48h 的第 2 轮。")
    # L4/L5 只在【扫到了 ReputationRegistry 日志】的链上可测。
    # 不写清楚的话，1,668 / 392,258 = 0.43% 会被读成全量比例，
    # 而实际分母只有那几条链 —— 又一次覆盖率稀释。
    fb_chains = [r[0] for r in conn.execute(
        "SELECT DISTINCT chain_id FROM ev_feedback ORDER BY 1").fetchall()]
    if fb_chains:
        row = conn.execute(
            "SELECT count(*) FROM agent_state WHERE snapshot_id = ? AND chain_id IN "
            "({})".format(",".join("?" for _ in fb_chains)),
            [snapshot, *fb_chains],
        ).fetchone()
        n_cov = row[0] if row else 0
        tot = conn.execute(
            "SELECT count(*) FROM agent_state WHERE snapshot_id = ?", [snapshot]).fetchone()[0]
        lims.append(
            f"**L4/L5 只覆盖 {len(fb_chains)} 条链的 {n_cov:,} 个 agent"
            f"（占全量 {100 * n_cov / max(1, tot):.1f}%）**：反馈事件要扫 ReputationRegistry 的"
            "历史日志，而只有部分链的公共 RPC 能提供。L4 的比例**必须以这些链为分母**，"
            "以 L0 全量为分母会严重低估。其余链尚未扫描，不等于其上没有反馈。"
        )
    ipfs_bad = conn.execute(
        "SELECT count(*) FROM uri_fetch WHERE status = 'ipfs_unresolvable'"
    ).fetchone()[0]
    if ipfs_bad:
        # 抓取前会做网关健康检查，连不上的网关会被剔除。本次实测只有 2/5 可达，
        # 这是【扫描机器所在网络】的属性，不是这些 CID 在 IPFS 上不存在。
        lims.append(
            f"`ipfs_unresolvable` {ipfs_bad:,} 条依赖扫描机可达的 IPFS 网关数量。"
            "抓取前的网关健康检查会剔除连不上的网关，可达网关变少会抬高这个数字 —— "
            "它是**本次扫描环境**下的解析失败，不等于该 CID 在 IPFS 上不存在。"
        )
    out = write_report(conn, snapshot, _state["root"], limitations=lims)
    conn.close()
    console.print(f"[green]✓[/green] 报告已写入 {out}")


# ============================================================== dump-fixtures


@app.command("dump-fixtures")
def dump_fixtures(
    chain: str = typer.Option("ethereum", "--chain"),
    count: int = typer.Option(5, "--count"),
    events: str = typer.Option("Registered,NewFeedback,MetadataSet,Transfer", "--events"),
):
    """取真实链上 payload 做解码 fixture（接口契约 §6）。解决测试的先有鸡问题。"""
    from .abi import EventRegistry
    from .rpc import RpcClient

    cfg = _cfg()
    ch = cfg.chain(chain)
    reg = EventRegistry(cfg.abis)
    want = [e.strip() for e in events.split(",")]
    outdir = Path(_state["root"]) / "tests" / "fixtures" / "logs"
    outdir.mkdir(parents=True, exist_ok=True)

    async def run():
        async with RpcClient(ch.rpcs, user_agent=cfg.user_agent, chain_id=ch.chain_id) as rpc:
            head = await rpc.safe_head(ch.confirmations, ch.supports_finalized)
            addrs = cfg.registries_for(ch).addresses()
            found: dict[str, list] = {e: [] for e in want}
            window, cursor = 50_000, head
            while cursor > (ch.deploy_block or 0) and any(len(v) < count for v in found.values()):
                lo = max(ch.deploy_block or 0, cursor - window)
                try:
                    logs = await rpc.call(
                        "eth_getLogs",
                        [{"fromBlock": hex(lo), "toBlock": hex(cursor), "address": addrs}],
                    )
                except Exception:  # noqa: BLE001
                    window //= 2
                    if window < 500:
                        break
                    continue
                for lg in logs:
                    ev = reg.by_topic.get(lg["topics"][0].lower())
                    if ev and ev["name"] in found and len(found[ev["name"]]) < count:
                        found[ev["name"]].append(lg)
                cursor = lo - 1
            for name, logs in found.items():
                if not logs:
                    console.print(f"  [yellow]{name}: 0 条[/yellow]")
                    continue
                p = outdir / f"{ch.chain_id}_{name}.json"
                p.write_text(jsonlib.dumps(logs, indent=2), encoding="utf-8")
                console.print(f"  [green]✓[/green] {name}: {len(logs)} 条 → {p}")

    asyncio.run(run())


if __name__ == "__main__":
    app()
