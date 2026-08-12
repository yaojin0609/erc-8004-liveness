"""e8004.probe —— 独立可发布的端点活性探测库。

【库边界，不许破】(CLAUDE.md 硬约束 3)
  * 不许 import duckdb、不许 import 本仓任何 stage 模块、不许读 config/chains.toml
  * 依赖只允许 httpx / aiodns / 标准库
  * 验收：`python -c "import e8004.probe"` 在没装 duckdb 的干净环境里必须成功

【输出契约】见 docs/接口契约.md §3。schema_version = "1.0"。
  刻意【没有】verdict / live 字段 —— 「是否算活」由消费方判定。探测器一旦开始
  下结论，raw/derived 分离就破了，判定口径也没法事后重算。
"""

from .config import ProbeConfig
from .limiter import DualLimiter
from .runner import ProbeTarget, probe_many, probe_one

SCHEMA_VERSION = "1.0"

__all__ = ["SCHEMA_VERSION", "DualLimiter", "ProbeConfig", "ProbeTarget", "probe_many", "probe_one"]
