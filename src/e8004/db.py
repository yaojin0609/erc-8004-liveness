"""DuckDB 连接、migration、spool 入库、stage 游标。

入库必须幂等：同一批 JSONL 重放两次，表里行数不变（靠主键 + INSERT OR REPLACE）。
入库后不删除 JSONL —— 它是 raw 层的一部分，跟数据集一起发布。
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

import duckdb
import structlog

log = structlog.get_logger(__name__)

DEFAULT_DB = "data/e8004.duckdb"
SCHEMA_PATH = "docs/schema.sql"
CHUNK = 5_000


def connect(root: Path | str = ".", db_path: str | None = None, read_only: bool = False):
    root = Path(root)
    path = Path(db_path or (root / DEFAULT_DB))
    path.parent.mkdir(parents=True, exist_ok=True)
    if read_only and not path.exists():
        raise FileNotFoundError(f"数据库不存在: {path}")
    return duckdb.connect(str(path), read_only=read_only)


# 派生表：完全是上游数据的纯函数，可随时 DROP 重建。
# schema 变了就重建它们 —— CREATE TABLE IF NOT EXISTS 不会给已存在的表加列，
# 结果是「表有 18 列但要插 19 个值」这种在流水线跑到最后一步才炸的错误。
DERIVED_TABLES = (
    "funnel", "agent_card", "service", "card_registration",
    "identity_cluster", "feedback_selfloop",
)


def reset_derived(conn, tables: Sequence[str], root: Path | str = ".") -> None:
    """清空派生表：DROP 重建，不要 DELETE。

    DELETE 要逐行维护主键 ART 索引，进程被杀在半途会把索引留成不一致状态，
    下次 DELETE 直接 `FATAL Error: Failed to delete all rows from index`
    —— 而 FATAL 会让整个连接作废，等于一次 kill 就锁死这张表。
    DROP 不碰索引内容，且在 39 万行量级上快一个数量级。
    """
    for table in tables:
        if table not in DERIVED_TABLES:
            raise ValueError(f"{table} 不是派生表，不许 DROP")
        conn.execute(f"DROP TABLE IF EXISTS {table}")
    conn.execute((Path(root) / SCHEMA_PATH).read_text("utf-8"))


def _ddl_columns(sql: str, table: str) -> list[str] | None:
    """在临时内存库里建一次表，拿到 DDL 期望的列名。"""
    import duckdb as _d

    tmp = _d.connect(":memory:")
    try:
        tmp.execute(sql)
        return [r[0] for r in tmp.execute(f"DESCRIBE {table}").fetchall()]
    except Exception:  # noqa: BLE001
        return None
    finally:
        tmp.close()


def migrate(conn, root: Path | str = ".") -> None:
    """执行 docs/schema.sql（全部 CREATE ... IF NOT EXISTS，幂等）。

    附带处理派生表的 schema 漂移：列不一致就 DROP 重建（数据可由上游重算）。
    raw 层的表【不会】被动到 —— 那些数据重新联网才能拿回来。
    """
    sql = (Path(root) / SCHEMA_PATH).read_text("utf-8")
    for table in DERIVED_TABLES:
        try:
            have = [r[0] for r in conn.execute(f"DESCRIBE {table}").fetchall()]
        except Exception:  # noqa: BLE001
            continue  # 表还不存在，下面的 CREATE 会建
        want = _ddl_columns(sql, table)
        if want and have != want:
            log.warning("derived_table_rebuilt", table=table,
                        added=[c for c in want if c not in have],
                        removed=[c for c in have if c not in want])
            conn.execute(f"DROP TABLE {table}")
    conn.execute(sql)


# --------------------------------------------------------------------- cursors


def get_cursor(conn, stage: str, chain_id: int) -> str | None:
    row = conn.execute(
        "SELECT cursor FROM stage_cursor WHERE stage = ? AND chain_id = ?", [stage, chain_id]
    ).fetchone()
    return row[0] if row else None


def set_cursor(conn, stage: str, chain_id: int, cursor: str | int) -> None:
    conn.execute(
        """INSERT OR REPLACE INTO stage_cursor (stage, chain_id, cursor, updated_at)
           VALUES (?, ?, ?, now())""",
        [stage, chain_id, str(cursor)],
    )


# ------------------------------------------------------------------ spool load


def _column_types(conn, table: str) -> dict[str, str]:
    rows = conn.execute(f"DESCRIBE {table}").fetchall()
    return {r[0]: r[1].upper() for r in rows}


def _coerce(value: Any, coltype: str) -> Any:
    if value is None:
        return None
    if coltype.startswith("BLOB"):
        if isinstance(value, str):
            return bytes.fromhex(value.removeprefix("0x"))
        return value
    if coltype.startswith("VARCHAR[") or coltype.endswith("[]"):
        return list(value) if isinstance(value, (list, tuple)) else [value]
    if coltype.startswith("HUGEINT") or coltype.startswith("BIGINT") or coltype.startswith("UBIGINT"):
        return int(value) if isinstance(value, str) else value
    return value


def load_spool(conn, root: Path | str, stage: str, delete_after: bool = False) -> dict[str, int]:
    """把 data/spool/<stage>/*.jsonl 入库。按主键 upsert，幂等。

    入库成功的文件【移到 loaded/ 子目录】而不是删除 —— JSONL 是 raw 层的一部分，
    要跟数据集一起发布。不移走的话，每次 load 都会重扫全部历史文件：
    12 条链的循环里最后一次要重复处理前面所有链的 39 万行，总工作量退化成 O(n²)。

    最后一行 JSON 解析失败（进程被杀导致的截断）直接丢弃并告警，不报错退出。
    """
    spool_dir = Path(root) / "data" / "spool" / stage
    if not spool_dir.is_dir():
        return {}

    files = sorted(spool_dir.glob("*.jsonl"))
    counts: dict[str, int] = {}
    schema_cache: dict[str, dict[str, str]] = {}

    for fp in files:
        buckets: dict[str, list[dict]] = {}
        truncated = 0
        with open(fp, encoding="utf-8") as fh:
            lines = fh.readlines()
        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                if i == len(lines) - 1:
                    truncated += 1
                    continue
                raise
            table = rec.pop("_table", None)
            if table is None:
                raise ValueError(f"{fp}: 记录缺少 _table 字段")
            for k in ("_stage", "_run_id", "_seq"):
                rec.pop(k, None)
            chain_id = rec.pop("_chain_id", None)
            if chain_id is not None and "chain_id" not in rec:
                rec["chain_id"] = chain_id
            buckets.setdefault(table, []).append(rec)

        if truncated:
            log.warning("spool_truncated_line_dropped", file=str(fp), n=truncated)

        for table, rows in buckets.items():
            if table not in schema_cache:
                schema_cache[table] = _column_types(conn, table)
            types = schema_cache[table]

            # 【按字段集合分组】同一张表里不同来源的记录可能字段不全
            # （sampled_out 的行就只写了几个字段）。整批共用一个列清单的话，
            # 缺字段的行会被插入 NULL，撞上 NOT NULL 约束让【整批】失败。
            shapes: dict[frozenset, list[dict]] = {}
            for r in rows:
                shapes.setdefault(frozenset(k for k in r if k in types), []).append(r)

            for shape, group in shapes.items():
                cols = [c for c in types if c in shape]
                if not cols:
                    continue
                placeholders = ", ".join("?" for _ in cols)
                sql = f"INSERT OR REPLACE INTO {table} ({', '.join(cols)}) VALUES ({placeholders})"
                payload = [[_coerce(r.get(c), types[c]) for c in cols] for r in group]
                for i in range(0, len(payload), CHUNK):
                    conn.executemany(sql, payload[i : i + CHUNK])
            counts[table] = counts.get(table, 0) + len(rows)

        if delete_after:
            fp.unlink()
        else:
            done_dir = fp.parent / "loaded"
            done_dir.mkdir(exist_ok=True)
            fp.rename(done_dir / fp.name)

    return counts


# ---------------------------------------------------------------- small utils


def scalar(conn, sql: str, params: Iterable | None = None):
    row = conn.execute(sql, list(params or [])).fetchone()
    return row[0] if row else None


def table_count(conn, table: str, where: str = "") -> int:
    try:
        return scalar(conn, f"SELECT count(*) FROM {table} {where}") or 0
    except duckdb.CatalogException:
        return 0
