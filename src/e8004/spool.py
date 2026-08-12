"""网络 stage 的落盘缓冲。

DuckDB 一个文件同时只允许一个进程持有写锁 —— 写锁存在时别的进程连只读都打不开。
这跟「长任务夜里挂着跑、白天开 duckdb 翻数据」的工作方式直接冲突（实施规划 §4）。
所以网络 stage 一律先写 JSONL，再由 `e8004 load` 短暂持锁入库。

附带好处：进程被杀时已完成部分完好无损，断点续跑粒度从「整个 stage」降到「单条记录」。
"""

from __future__ import annotations

import json
import os
import time
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any


class Spool:
    def __init__(self, root: Path, stage: str, run_id: str | None = None, flush_every_n: int = 500):
        self.stage = stage
        self.run_id = run_id or time.strftime("%Y%m%d-%H%M%S")
        self.dir = Path(root) / "data" / "spool" / stage
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / f"{self.run_id}.jsonl"
        self._fh = open(self.path, "a", encoding="utf-8")
        self._n = 0
        self._seq = 0
        self.flush_every_n = flush_every_n

    def write(self, table: str, record: dict[str, Any], chain_id: int | None = None) -> None:
        self._seq += 1
        payload = {
            "_stage": self.stage,
            "_table": table,
            "_run_id": self.run_id,
            "_seq": self._seq,
            **({"_chain_id": chain_id} if chain_id is not None else {}),
            **record,
        }
        self._fh.write(json.dumps(payload, ensure_ascii=False, default=_default) + "\n")
        self._n += 1
        if self._n % self.flush_every_n == 0:
            self._fh.flush()
            os.fsync(self._fh.fileno())

    @property
    def count(self) -> int:
        return self._n

    def close(self) -> None:
        if not self._fh.closed:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _default(o: Any):
    if isinstance(o, (bytes, bytearray)):
        return "0x" + bytes(o).hex()
    # datetime 落成 ISO 字符串：DuckDB 入库时会自己转成 TIMESTAMP。
    # 不在这里兜住的话，每个新 stage 都得自己记得 .isoformat()，
    # 忘一次就是跑到一半才炸的 TypeError。
    if isinstance(o, (datetime, date)):
        return o.isoformat()
    if isinstance(o, Decimal):
        return str(o)  # 硬约束 8：金额/评分禁止 float，字符串过一手保精度
    raise TypeError(f"不可序列化: {type(o)}")
