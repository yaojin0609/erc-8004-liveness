# ERC-8004 注册身份活性扫描器

一个可复跑的扫描器，回答一个问题：**链上注册的 ERC-8004 agent 身份里，有多少是真的活着的？**

> ### 📄 [**报告：39 万个 ERC-8004 身份，有多少是真活着的**](REPORT.md)
>
> 快照 2026-08-10，12 条链全量。**392,258** 个注册身份里，21.3% 声明了可路由的
> 服务端点；已探测的身份中 **47.6%** 的端点在相隔 48 小时的两次探测中都完成了
> 协议层握手（按主机规模回权到全集估计 **38.6%**）。第 1 轮通过的端点里
> **99.6%** 在 48 小时后仍然通过 —— 可达性是稳定状态，不是抽样噪声。
>
> 最反直觉的一条：**存活是运营商的属性，不是身份的属性。**
> 端点主机 Gini **0.9633**，而所有权 Gini 只有 0.318。
>
> 另有一篇不依赖本协议语境的技术记录：
> [**链上索引的静默数据损坏：八次「看起来成功了」**](docs/silent-data-corruption.md)
> （English: [Silent data corruption in blockchain indexing](docs/silent-data-corruption.en.md)）

产出是一张漏斗表 —— 从「链上注册了」一层层筛到「服务端点真的能握手」，
每一层的存活率就是结论的骨架。

## 与现有 explorer 的区别

现有的 ERC-8004 浏览器回答「**链上注册了什么**」。本项目回答「**那些注册是否对应
真实可用的服务**」—— 对声明的服务端点做两轮（间隔 ≥48 小时）协议层探测，
按主机规模做分层回权，并用独立路径做跨链完整性对账。

各项目公布的口径实测对比（2026-08-16 现场核对，除本项目为 08-10 快照）：

| | 公布 agent 总数 | 链 | 是否探测端点 | 「可用」的判据 | 方法论/代码 |
|---|---:|---:|---|---|---|
| [8004scan](https://8004scan.io) | 416,188 | 28 | 否 | — | 未公开 |
| [RNWY](https://rnwy.com) | 236,197（已评分） | 多链 | 否<sup>1</sup> | — | [方法论页](https://rnwy.com/methodology)详尽，代码未公开 |
| [agentscan](https://agentscan.info) | 443,242 | 22 | **是** | HTTP 状态码 < 500<sup>2</sup> | 未定义 |
| **本项目** | 392,258 | 12 | **是** | **协议层握手**<sup>3</sup>，两轮取交集 | MIT，代码 + 数据集 |

<sup>1</sup> RNWY 的信任分完全基于链上数据（评价者钱包画像、女巫检测、持有历史）。
其方法论中唯一涉及 endpoint 的是「元数据里的 endpoint 格式是否合法」，不含可达性。

<sup>2</sup> 实测其 `/api/endpoint-health/quick-stats` 返回样本：77 个端点中 17 个
返回 **404 但被标为 `is_healthy: true`**；样本 `checked_at` 跨 2026-02 至 2026-07，
近六周无新检查。其公布的 `endpoint_health_rate` 为 67.3%。

<sup>3</sup> A2A：取回并解析 agent card；MCP：`initialize` + `tools/list` 返回合法响应。
判据差异本身就解释了 67.3% 与 38.6% 的差距 —— **不同的问题，不同的答案。**

**总数差异不是谁算错了，是口径不同**，但有一处差异可以被独立复核：本项目 08-10 的
快照在全部 12 条共有链上都**不小于**其他索引今天的实时数字。以太坊上任何人可以
用两次 `eth_call` 核对 ——

```bash
# ownerOf(30454) 与 ownerOf(49503) 都返回持有者 ⇒ 以太坊至少有 49,504 个 token
cast call 0x8004A169FB4a3325136EB29fA0ceB6D2e539a432 "ownerOf(uint256)(address)" 49503
```

这正是本仓 [`verify-coverage`](#verify-coverage为什么它是门槛而不是可选项) 门槛
所针对的那类问题：**索引静默漏数据，而漏的那部分自己不会报错。**
反过来，以太坊的 `NewFeedback` 总数两边都是 **3,215，逐条吻合** —— 口径一致时结果就一致。

## 这是什么 / 不是什么

- **是**：一个只读的研究性扫描器 + 可复现的数据集 + 一份公开报告。
- **不是**：排行榜、评分服务、或对任何具体 agent 的评价。

报告刻意**不**把「注册了但没活性」等同于「无效」。开发者试注册、早期占位、
项目未上线、以及 agent card 里主动声明 `active: false`，都会表现为「探测不通」。
漏斗里这些情形单独成支。

## 扫描者身份与退出方式

本扫描器的所有出站请求都带如下 User-Agent：

```
ERC8004-Research-Scanner/1.0 (+https://github.com/yaojin0609/erc-8004-liveness; yaojin_pd@outlook.com)
```

**不希望被扫描**：把你的域名发到 <yaojin_pd@outlook.com>，或直接提 PR 加进
[`config/blocklist.txt`](config/blocklist.txt)。名单在每次请求前检查，立即生效。

探测约束（代码层面强制，见 [`src/e8004/probe/limiter.py`](src/e8004/probe/limiter.py)）：

- 全局 ≤10 req/s；**单一 host ≤1 请求/3 秒，且最多 1 条并发连接**；另有 per-IP 限速
- 只读：仅 GET / OPTIONS / MCP `initialize` / `tools/list`
- 遇 429/503 退避并将该 host 移出本轮；每个端点每轮最多 2 次尝试

## 快速开始

```bash
uv sync
cp .env.example .env      # 填 SCANNER_CONTACT_EMAIL / SCANNER_REPO_URL（必填）
                          # 有 ALCHEMY_API_KEY 更好，见下节

uv run e8004 status               # 任何时候：上次跑到哪、下一步干嘛
uv run e8004 diagnose             # 候选注册表地址身份鉴定
uv run e8004 count-agents         # L0 人口普查：每条链多少个 agent
uv run e8004 bootstrap            # 地址验证 + 部署区块

uv run e8004 snapshot-state --chain arbitrum --snapshot 2026-08-10
uv run e8004 load snapshot-state

uv run e8004 scan-mints           # 注册历史：Alchemy 链（见下节「注册时间」）
uv run e8004 load scan-mints
uv run e8004 scan-logs --chain celo   # 其余链走公共 RPC
uv run e8004 load scan-logs
uv run e8004 verify-coverage      # 【门槛】注册记录数必须等于普查数

uv run e8004 fetch-uri            # agentURI 抓取（网络出口 A）
uv run e8004 load fetch-uri
uv run e8004 parse-cards
uv run e8004 probe --dry-run      # 全量探测前【必须】先核对量级
uv run e8004 probe --round 1
uv run e8004 load probe
uv run e8004 funnel --snapshot 2026-08-10
uv run e8004 report --snapshot 2026-08-10
```

或者一条命令跑完除探测以外的全部：`./run_full.sh 2026-08-10`。
探测刻意不在脚本里 —— 它要敲第三方服务器，必须由人显式发起。

### `verify-coverage`：为什么它是门槛而不是可选项

**RPC 端点静默丢日志，在本仓发生过多次，每次都「看起来成功了」：**

| 链 | 表现 | 真相 |
|---|---|---|
| ethereum | 扫描正常完成 | `rpc.flashbots.net` 对历史区间返 `[]`，87% 是空的 |
| scroll | `✓ 0 条日志` | 金丝雀够不到活动区间 → 端点校验**整个被跳过** |
| celo | `✓` 但少 19.6% | 返回 **HTTP 200 + 截断的结果集**，重查同一区间就有 |

共同点是**扫描自己发现不了**。所以对账不能依赖 RPC 是否诚实，只能用数据本身的性质：
`agentId` 从 0 顺序递增 ⇒ 有注册记录的 agent 数必须等于普查数。
纯 SQL，不碰网络，`--strict` 可挂进流水线当门槛。

完整的八次实录、各自的成因与修复、以及各链公共 RPC 的实测端点清单，见
[**docs/silent-data-corruption.md**](docs/silent-data-corruption.md)。

### 关于注册时间：两条路径

没有一条路能覆盖全部 12 条链：

- **`scan-mints`**（ethereum / base / bsc / arbitrum / polygon）：用 Alchemy 的
  `alchemy_getAssetTransfers` 一次查全区间、翻页取回。**因为 Alchemy 免费档把
  `eth_getLogs` 砍到 10 个区块跨度** —— 以太坊一条链就要 13.9 万次请求，
  走事件日志在免费档下不可行。代价是拿不到 `agentURI`，所以结果写
  `agent_mint` 而不是 `ev_registered`（往事件表里填 `''` 凑格式 = 造假数据）。
- **`scan-logs`**（其余 7 条链）：公共 RPC 扫 `Registered` 事件本体，含 `agentURI`。
  各链实测的跨度上限写在 `config/chains.toml` 里，**celo 必须用 2000**，
  调大会触发静默截断。

## 关于 RPC：一个必须先讲清楚的坑

**免费公共 RPC 拿不到 ERC-8004 的完整历史日志。** 实测（2026-08-10，以太坊主网）：

| 端点 | 历史区间 `eth_getLogs` |
|---|---|
| `ethereum-rpc.publicnode.com` | 报错 `Archive requests require a personal token` |
| `eth.drpc.org` | 报错 `ranges over 10000 blocks are not supported on free plan` |
| `rpc.flashbots.net` | **静默返回 `[]`** ⚠️ |

第三种最危险：它不报错，扫描会「成功」完成并产出一份大部分是空的数据集。
本仓在开扫前会做**端点完整性验证**（`verify_endpoints_for_logs`）：拿一个已知
含日志的区块做金丝雀，把静默说谎的端点从端点池里剔除。

**但这不改变结论：要完整的历史日志，就得有 archive 节点。** 配 `ALCHEMY_API_KEY`
即可，`config/chains.toml` 里已经把它排在每条链端点列表的第一位。

### 没有 archive key 也能跑的部分

漏斗的主体不依赖历史日志。agent 总数、owner、agentURI、agent wallet
**全都是当前状态**，用 `eth_call` 就能读：

- `count-agents`：对 `ownerOf(agentId)` 做二分（agentId 从 0 顺序递增），
  每条链约 34 次调用就能得到该链的 agent 总数
- `snapshot-state`：Multicall3 批量读 `ownerOf` / `tokenURI` / `getAgentWallet`

有 archive 时才额外获得：注册时间戳（→ 队列分析）、反馈历史（→ L4）、
转让历史（→ 当前 owner 与注册 owner 的对比）。

## ⚠️ 运行环境会影响 TLS 层结论

如果扫描机器处在**做 TLS 拦截的网络**里（企业代理、某些本地安全软件），会有两个后果：

1. 普通 HTTPS 请求会 `CERTIFICATE_VERIFY_FAILED`。本仓用 `truststore` 走系统证书库
   解决 —— 仍然是**正常校验**，只是信任源换成系统钥匙串，不要改成 `verify=False`。
2. **拦截代理通常拒绝转发上游证书无效的连接。** 于是「证书过期但服务活着」的端点
   会被记成 TLS 失败，而不是本仓设计的「记录证书问题、但不判死」。

第 2 条会**系统性低估 L3 存活率**。跑正式扫描前先自检：

```bash
uv run python -c "
import asyncio, e8004
from e8004.probe import ProbeConfig, ProbeTarget, probe_many
cfg = ProbeConfig(user_agent='selftest', global_rps=2, per_host_interval_s=1)
urls = ['https://self-signed.badssl.com/', 'https://expired.badssl.com/',
        'https://wrong.host.badssl.com/', 'https://badssl.com/']
for r in asyncio.run(probe_many([ProbeTarget(u,'web') for u in urls], cfg)):
    print(r['target']['endpoint'], r['layers']['tls']['outcome'],
          r['layers']['tls']['error_kind'], r['layers']['http']['status'])
"
```

**判据只有一条：四个全部 `outcome='ok'` 且拿到 HTTP 200。** 证书坏的那三个也必须
是 `ok` —— 「证书有问题」和「服务死了」是两回事，本仓只记录前者、不据此判死。
任何一个是 `fail`，说明所在网络在拦截，**应换一台机器跑探测**，或在报告里标注该偏差。

`error_kind` 的取值**依平台而不同**，不要拿它当判据：证书校验可能由 OpenSSL 做，
也可能由 truststore 转交系统验证器做，两者措辞完全不同（macOS 说
`certificate is not trusted`，OpenSSL 说 `self-signed certificate`）。
自签名证书在 macOS 上归为 `untrusted_ca` 而不是 `self_signed`，因为系统验证器
根本不区分「自签名」和「未知 CA」—— 归成 `self_signed` 等于假装知道。
见 [`tests/test_tls_kind.py`](tests/test_tls_kind.py)。

> 本快照（2026-08-10）的扫描机**通过了自检**：四个全部 `ok` + HTTP 200，
> 因此报告中的 L3 不含 TLS 拦截偏差。

## 口径

两套并列，都报告，不主张哪个「正确」：

- **口径 A（链上注册数）**：各链已铸造的 agent 总数（累计 mint，不去重、不排除销毁）
- **口径 B（唯一主体数）**：按 agent card 的 `registrations[]` 双向声明跨链归并后的数量

各家公开数字互相矛盾的主要原因就是口径不同。本仓的立场是把自己的口径写死并公开。

## 实测结果速览（快照 2026-08-10，12 条链）

| 指标 | 数值 |
|---|---:|
| 口径 A：链上注册身份总数 | **392,258** |
| 口径 B：跨链去重后（最宽判据） | 380,710（仅压缩 2.9%） |
| 不同 owner 地址数 | 265,921 |
| 所有权 Gini（全量，当前 owner） | **0.318** |
| 所有权 Gini（论文子集：以太坊 id 0–9999，当前 owner） | **0.863**（与已发表论文逐位吻合）|
| 同一子集，**注册时** owner | 0.8753（本研究独立测得，19.2% 已易主）|
| 端点主机 Gini | **0.9633**（前 2 个 host 覆盖 42.9%）|
| 注册身份总数（含注册时间） | 376,916 条铸造记录，2026-01-29 → 2026-08-11 |

两条值得单独说的：

1. **BSC 一条链就占 67%**（262,999 个），按约 1,800/天增长。各家公布的总数在
   15 万到 44 万之间，量级一致、口径不同 —— 见上文「与现有 explorer 的区别」。
   本仓不主张自己的数字「正确」，只主张口径写死且可复跑核对。
2. **所有权分散但端点极度集中。** 注册身份的人很多（26.6 万个地址），真正在跑服务的
   运营者极少。已发表论文在以太坊早期 1 万个样本上得到的 Gini 0.863，本流水线能
   精确复现（这也是正确性验证），但同样的指标在全量上是 0.318 —— **那个结论不能外推。**

## 已知的链上事实

`e8004 diagnose` 的实测结论（2026-08-10）：

存在**两组完全平行**的注册表部署，且两组在同一批链上都有代码：

| 组 | IdentityRegistry | ReputationRegistry | 状态 |
|---|---|---|---|
| A | `0x8004a169…` | `0x8004baa1…` | 以太坊近 10 万区块有 104 次 Registered，**在用** |
| B | `0x8004a818…` | `0x8004b663…` | 以太坊同一个 implementation 但 0 次 Registered；BSC 上是完全不同的合约 |

主流水线只扫 A 组。B 组走 `registry_census` 做轻量普查 —— 「有多少注册落在了
那组不活跃的注册表上」本身就是各家数字打架的原因之一。

## 文档

| 文件 | 内容 |
|---|---|
| [**REPORT.md**](REPORT.md) | **报告正文**（手写，面向读者） |
| [data/export/report-2026-08-10.md](data/export/report-2026-08-10.md) | 逐层数据报告（流水线生成，每次复跑重写） |
| [CLAUDE.md](CLAUDE.md) | 开发入口：阅读顺序 + 硬约束清单 |
| [docs/实施规划.md](docs/实施规划.md) | 架构、技术栈、各 stage 行为规格、算法 |
| [docs/接口契约.md](docs/接口契约.md) | CLI 命令面、库边界、probe 输出 schema |
| [docs/schema.sql](docs/schema.sql) | DuckDB 建表 DDL |
| [docs/开发排期与验收.md](docs/开发排期与验收.md) | ticket 拆分与 DoD |
| [docs/silent-data-corruption.md](docs/silent-data-corruption.md) | **八次「看起来成功了」的数据损坏实录**：成因、修复、以及各链公共 RPC 的实测端点清单 |
| [docs/silent-data-corruption.en.md](docs/silent-data-corruption.en.md) | English version of the above |

## 架构要点

- **raw / derived 强制分离**：只有 4 个 stage 碰网络，它们只把原始响应落盘；
  所有判定与统计是纯函数，可无限重跑而不再骚扰任何人的服务器。
- **网络 stage 先写 JSONL 再入库**：DuckDB 一个文件只允许一个进程持有写锁，
  长任务直连数据库会把「夜里挂着跑、白天查数据」这个工作方式堵死。
- **`e8004.probe` 是独立可发布的库**：不 import duckdb、不依赖本仓表结构，
  输出带 `schema_version`。探测器**不输出**「是否算活」的判定 —— 那是消费方的事，
  口径改了要能重算历史。

## 复跑承诺：2026-11-10

**本项目将在 2026-11-10（快照 + 3 个月）用同一套代码复跑一次，并公布对比结果。**

这不是路线图上的一句客套。单次快照分不清「已下线」和「从未上线」——
只有第二次快照能把这两者分开，而第二次快照需要第一次作为锚点。
复跑时**不修改判定逻辑**，只升级代码依赖；若判据必须改动，会同时给出两套口径的数字。

快照锚定在各链的具体区块高度上（见数据报告末尾），任何人都可以用同一个
`snapshot_id` 复算历史，不需要重新扫描。

## 许可

MIT。数据集另行发布并标注快照区块高度。
