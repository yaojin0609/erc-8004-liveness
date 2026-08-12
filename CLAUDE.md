# ERC-8004 全量注册身份分析 —— 开发指引

**开发前必须按顺序读完 `docs/` 下这四份文件，不许跳过直接写代码。**

| 顺序 | 文件 | 作用 |
|---|---|---|
| 1 | [docs/实施规划.md](docs/实施规划.md) | **主规格**。架构、技术栈、各 stage 行为规格、算法 |
| 2 | [docs/接口契约.md](docs/接口契约.md) | CLI 命令面、模块签名、probe 输出 schema、status 格式 |
| 3 | [docs/schema.sql](docs/schema.sql) | DuckDB 建表 DDL，可直接执行 |
| 4 | [docs/开发排期与验收.md](docs/开发排期与验收.md) | ticket 拆分、优先级、**每个 ticket 的 DoD** |

`docs/ERC-8004注册操作步骤.md` 是最初的思路稿，**其中有四处事实错误已在 实施规划 §1 修正**。读它只为理解意图，不要按它实现。

---

## 硬约束（违反任何一条都算实现错误）

### 架构

1. **只有 4 个 stage 可以访问网络**：`s02_logs`、`s04_uri_fetch`、`s06_probe`、`s07_wallet_flow`（含 `s07b_feedback_file`）。所有解析、判定、统计必须是纯函数，只读数据库。
2. **网络 stage 不直接写 DuckDB**，先写 `data/spool/<stage>/<run_id>.jsonl`，再由 `e8004 load <stage>` 入库。DuckDB 单写者锁会让通宵任务和你的查询互斥。见 实施规划 §4。
3. **`e8004.probe` 必须能在没有 duckdb 的环境里 `import`**。它是要独立发布的库，不许依赖本仓表结构。这条边界破了，三个月后第二阶段就是重写而不是扩展。
4. **一切以 `snapshot_id` 为键**。扫描/查询一律不用 `latest`。
5. 每个 stage **幂等 + 可断点续跑**，游标写 `stage_cursor` 表。

### 数据正确性

6. **事件 topic0 一律由签名字符串在运行时 keccak 计算，禁止硬编码 hash。**
7. **`string indexed` 参数在 topic 里是 keccak 哈希，不是原文。** 可读值必须取 data 段的非 indexed 同名字段（`NewFeedback.tag1`、`MetadataSet.metadataKey`）。
8. **金额与评分全链路禁止 float。** `int128` 用 Python `int` / DuckDB `HUGEINT`，还原值用 `decimal.Decimal` / `DECIMAL(38,18)`。
9. **地址一律小写存储**，写入前 `.lower()`，禁止 checksum 大小写混存。
10. `agent_id` 解码超出 `2^63-1` 必须抛错，不许静默截断。

### 探测伦理（这几条是红线，不是建议）

11. 全局 ≤10 req/s，**per-host 1 req/3s 且同 host 最多 1 并发**，另加 per-IP 限速。
12. 只读：只允许 GET / OPTIONS / MCP `initialize` / `tools/list`。**禁止任何写操作、认证尝试、POST 业务接口。**
13. 每个请求必须带 User-Agent（含仓库 URL 和联系邮箱），每次请求前检查 `config/blocklist.txt`。
14. 429/503 → 指数退避；同 host 累计 3 次 → 拉黑并记为 `rate_limited`（不是 `fail`）。
15. 每端点每轮最多 2 次尝试。**全量探测前必须先跑 `--dry-run` 核对量级。**
16. **探测器只输出原始分层结果，不输出「是否算活」的判定。** 判定在 `s08_funnel` 用 SQL 做。

### 报告表述

17. `report/render.py` 的模板文案**不得出现**「假的」「僵尸」「9 成是」这类表述。只输出「L3 存活率 X%」「其中 Y% 自我声明为不活跃」这类中性描述。

---

## 工作流程

- **每个 ticket 完成后，逐条核对 开发排期与验收.md 里的 DoD。DoD 没过不许进下一个 ticket。**
- **T8（交叉验证）是硬门槛**：在 Ethereum 主网 agent id 0–9999 子集上，**当前 owner** 的 Gini 应 = 0.863、HHI = 0.034283、Top10 = 51.40%。对不上就停下来查扫描/解码 bug，不许「差不多就往下走」。

  ⚠️ **本条曾写作「注册时 owner」，是错的**（2026-08-11 拿到全量铸造历史后实测纠正）。
  同一子集两种口径实测：

  | 口径 | Gini | HHI | Top10 | 与论文偏差 |
  |---|---|---|---|---|
  | **当前 owner** | 0.8630 | 0.034283 | 0.5140 | **0.0% / 0.0% / 0.0%** |
  | 注册时 owner | 0.8753 | 0.041321 | 0.5693 | 1.4% / 20.5% / 10.8% |

  三个互相独立的统计量同时命中六位有效数字，不是巧合 —— 论文那组数字虽被描述为
  「注册时 owner」，实际对应的是当前 owner。铸造数据本身另有独立验证：在能三方
  对照的 94 个 agent 上，`Registered` 事件的 owner 与 ERC-721 mint 接收方 100% 相同。
  另：这 1 万个 agent 发生过大量转让（19.2% 易主，486 个铸造接收方收敛成 394 个
  当前持有者），所以两种口径本就不该相等。区块区间 24,339,925–24,839,925 对
  id 0–9999 是恒真条件（实测这批全部落在 24,339,925–24,342,223），不构成额外约束。
- 优先级 P0 > P1 > P2，见 开发排期与验收.md §2。排期告急时按文档里的顺序砍，**绝不砍**：T5 的限速实测、T6 的第二轮探测、T8 的交叉验证。
- 每写完一个 stage，实测一次「杀进程再重启能否续跑」。

## 环境

- Python 3.12，`uv` 管依赖，包名 `e8004`。
- 密钥走 `.env`（`ALCHEMY_API_KEY` / `ETHERSCAN_API_KEY` / `SCANNER_CONTACT_EMAIL` / `SCANNER_REPO_URL`），**`.env` 必须在 `.gitignore` 里**，仓库提供 `.env.example`。
- 配置在 `config/`：`chains.toml`（链与地址）、`scan.toml`（限速与网关）、`abis.json`（事件与函数 ABI）、`blocklist.txt`（退出扫描名单）。
- 数据在 `data/`，**整个 `data/` 目录不入 git**（只有 `data/export/` 的产物单独发布）。
