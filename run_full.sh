#!/usr/bin/env bash
# 全量跑：L0 普查 → 状态快照 → 注册历史 → 完整性核对 → URI 抓取
#         → card 解析 → 漏斗 → 报告
#
# 探测（probe）【不在这里】—— 它要打第三方服务器，必须先把 UA 里的仓库 URL
# 换成真实存在的地址，再由人显式发起。见 README「扫描者身份与退出方式」。
#
# 用法: ./run_full.sh <snapshot_id>
set -uo pipefail
SNAP="${1:-$(date +%Y-%m-%d)}"
export PATH="/opt/homebrew/bin:$PATH" UV_SYSTEM_CERTS=1 PYTHONUNBUFFERED=1

CHAINS=(ethereum celo gnosis avalanche arbitrum optimism base bsc polygon mantle linea scroll)

log() { echo "[$(date +%H:%M:%S)] $*"; }

log "===== 阶段 1/5: L0 人口普查 ====="
for c in "${CHAINS[@]}"; do
  # 逐条跑而不是并发：并发会让公共 RPC 全面退避，反而更慢
  uv run e8004 count-agents --chain "$c" 2>&1 | grep -E "^  [a-z]" || true
done

log "===== 阶段 2/5: 当前状态快照（ownerOf / tokenURI / getAgentWallet）====="
for c in "${CHAINS[@]}"; do
  log "--- $c ---"
  uv run e8004 snapshot-state --chain "$c" --snapshot "$SNAP" 2>&1 | grep -E "✓|总量|Error|error" | tail -3 || true
  uv run e8004 load snapshot-state 2>&1 | tail -1 || true
done

log "===== 阶段 3/7: 注册历史（注册时间 + 注册时 owner）====="
# 两条路径，因为没有一条能覆盖全部 12 条链：
#   scan-mints  Alchemy 的 alchemy_getAssetTransfers，一次查全区间。
#               免费档 eth_getLogs 被砍到 10 个区块跨度（以太坊一条链就要
#               13.9 万次请求），走事件日志这条路在免费档下不可行。
#   scan-logs   其余链用公共 RPC 扫 Registered 事件（跨度上限 2k–50k，
#               各链实测值写在 chains.toml 里）。拿到的是事件本体，含 agentURI。
uv run e8004 scan-mints 2>&1 | grep -E "✓|跳过" || true
uv run e8004 load scan-mints 2>&1 | tail -2 || true
for c in celo gnosis avalanche optimism mantle linea scroll; do
  uv run e8004 scan-logs --chain "$c" 2>&1 | grep -E "✓|Error" | tail -2 || true
done
uv run e8004 load scan-logs 2>&1 | tail -3 || true

log "===== 阶段 4/7: 注册记录完整性核对（门槛）====="
# 【不要加 || true】RPC 端点静默丢日志在本仓发生过三次（返空 / 被跳过校验 /
# 200+截断），三次都是「看起来成功了」。这一步用 agent_id 连续性与普查对账，
# 不依赖 RPC 是否诚实。对不上就停，别拿残缺数据往下算。
if ! uv run e8004 verify-coverage --strict 2>&1 | tail -20; then
  log "!! 注册记录不完整。对应链调小 max_log_range 后重扫，别引用当前数字"
  exit 1
fi

log "===== 阶段 5/7: agentURI 抓取 ====="
# 【不要用 || true 吞掉失败】：一个畸形 tokenURI 曾让抓取只完成 31%，
# 而 `|| true` 让流水线带着残缺数据继续跑完并产出「看起来完整」的报告。
# 宁可停在这里，也不要产出一份错的。
set -o pipefail
if ! uv run e8004 fetch-uri 2>&1 | tail -15; then
  log "!! 抓取失败，停止。修掉再重跑（已抓部分在 data/spool/fetch-uri/ 里，不会丢）"
  exit 1
fi
uv run e8004 load fetch-uri 2>&1 | tail -2

log "===== 阶段 6/7: agent card 解析 ====="
uv run e8004 parse-cards 2>&1 | grep -E "严格合规" || true

log "===== 阶段 7/7: 漏斗 + 报告 ====="
uv run e8004 funnel --snapshot "$SNAP" 2>&1 | tail -25 || true
uv run e8004 report --snapshot "$SNAP" 2>&1 | tail -2 || true

log "===== 完成 ====="
uv run e8004 status 2>&1 | tail -20 || true
