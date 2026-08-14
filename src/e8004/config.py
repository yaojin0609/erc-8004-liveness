"""配置加载：chains.toml / scan.toml / abis.json / .env

约定见 docs/接口契约.md §7。${VAR} 占位符从环境变量展开；
SCANNER_CONTACT_EMAIL 与 SCANNER_REPO_URL 缺失时直接拒绝启动 —— 不许匿名扫描
（CLAUDE.md 硬约束 13）。
"""

from __future__ import annotations

import json
import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

_ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")


class ConfigError(Exception):
    """配置错误 —— CLI 以退出码 2 结束。"""


def _expand(value: str) -> str:
    def sub(m: re.Match[str]) -> str:
        key = m.group(1)
        val = os.environ.get(key)
        if val is None or val == "":
            raise ConfigError(f"环境变量 {key} 未设置（配置里引用了 ${{{key}}}）。见 .env.example")
        return val

    return _ENV_RE.sub(sub, value)


def _expand_deep(obj):
    if isinstance(obj, str):
        return _expand(obj)
    if isinstance(obj, list):
        return [_expand_deep(o) for o in obj]
    if isinstance(obj, dict):
        return {k: _expand_deep(v) for k, v in obj.items()}
    return obj


@dataclass(frozen=True)
class ChainConfig:
    name: str
    chain_id: int
    tier: str  # "A" | "B" | "off"
    rpcs: tuple[str, ...]  # 多端点轮转：公共 RPC 会限流，单端点跑不完全量扫描
    confirmations: int = 12
    supports_finalized: bool = True
    max_log_range: int = 10_000
    deploy_block: int | None = None
    is_testnet: bool = False
    # 日志扫描【专用】端点。留空则用 rpcs。
    #
    # 【为什么要单独一份】能做 eth_call 的端点未必能做 eth_getLogs，而且失败方式
    # 是「静默地把扫描拖垮」而不是报错：Alchemy 免费档把 getLogs 砍到 10 个区块，
    # 客户端会把它当成范围过大而不断折半，一路折到 10 区块然后以那个粒度爬完
    # 139 万个区块。放进 rpcs 的轮转池里，只要轮到它就会拖垮整轮扫描。
    # 所以扫日志时用实测能拿历史日志的那几个端点，别让轮转碰运气。
    log_rpcs: tuple[str, ...] = ()

    @property
    def rpcs_for_logs(self) -> tuple[str, ...]:
        return self.log_rpcs or self.rpcs

    @property
    def active(self) -> bool:
        return self.tier in ("A", "B")


@dataclass(frozen=True)
class Registries:
    identity: str
    reputation: str
    validation: str  # 空字符串表示未部署/未发现，全流程跳过

    def addresses(self) -> list[str]:
        return [a for a in (self.identity, self.reputation, self.validation) if a]


@dataclass
class Config:
    root: Path
    chains: list[ChainConfig]
    registries: Registries
    candidates: dict[str, str]  # 诊断用：所有已知的 0x8004 前缀地址
    multicall3: str
    erc721_interface_id: str
    scan: dict
    abis: dict
    blocklist: set[str] = field(default_factory=set)

    # ---- 便捷访问 ----
    def chain(self, name_or_id: str | int) -> ChainConfig:
        for c in self.chains:
            if c.name == name_or_id or c.chain_id == name_or_id:
                return c
        raise ConfigError(f"未知的链: {name_or_id}")

    def active_chains(self, tier: str | None = None) -> list[ChainConfig]:
        return [c for c in self.chains if c.active and (tier is None or c.tier == tier)]

    def registries_for(self, chain: ChainConfig) -> Registries:
        # 链上实测：主网与测试网并非各用一组地址，所有链共用同一组确定性部署地址。
        # 保留这个方法是为了将来真出现分化时只改一处。
        return self.registries

    @property
    def user_agent(self) -> str:
        return _expand(self.scan["identity"]["user_agent"])

    def event_defs(self, contract: str) -> list[dict]:
        return self.abis.get(contract, {}).get("events", [])

    def all_event_defs(self) -> list[dict]:
        out = []
        for key in ("identity_registry", "reputation_registry", "validation_registry"):
            for ev in self.event_defs(key):
                out.append({**ev, "_contract": key})
        return out


def load_config(root: Path | str = ".", require_identity: bool = True) -> Config:
    root = Path(root).resolve()
    load_dotenv(root / ".env")

    cfg_dir = root / "config"
    if not cfg_dir.is_dir():
        raise ConfigError(f"找不到配置目录 {cfg_dir}")

    chains_raw = tomllib.loads((cfg_dir / "chains.toml").read_text("utf-8"))
    scan_raw = tomllib.loads((cfg_dir / "scan.toml").read_text("utf-8"))
    abis = json.loads((cfg_dir / "abis.json").read_text("utf-8"))

    # 扫描者身份：缺失即拒绝启动。这是伦理红线，不是可选项。
    if require_identity:
        for key in ("SCANNER_CONTACT_EMAIL", "SCANNER_REPO_URL"):
            if not os.environ.get(key):
                raise ConfigError(
                    f"{key} 未设置。扫描者身份是探测伦理的一部分，不许匿名扫描。见 .env.example"
                )

    reg = chains_raw["registries"]
    common = chains_raw["common"]

    chains: list[ChainConfig] = []
    for c in chains_raw.get("chain", []):
        raw_eps = c.get("rpcs") or ([c["rpc"]] if "rpc" in c else [])
        rpcs: list[str] = []
        for ep in raw_eps:
            try:
                rpcs.append(_expand(ep))
            except ConfigError:
                # 该端点引用的 key 没配 —— 丢掉这个端点，不要因此让整条链或整个程序死掉
                continue
        log_rpcs: list[str] = []
        for ep in c.get("log_rpcs") or []:
            try:
                log_rpcs.append(_expand(ep))
            except ConfigError:
                continue
        tier = c.get("tier", "off")
        if not rpcs and tier != "off":
            tier = "off"  # 一个可用端点都没有，只能关掉
        chains.append(
            ChainConfig(
                name=c["name"],
                chain_id=int(c["chain_id"]),
                tier=tier,
                rpcs=tuple(rpcs),
                confirmations=int(c.get("confirmations", 12)),
                supports_finalized=bool(c.get("supports_finalized", True)),
                max_log_range=int(c.get("max_log_range", 10_000)),
                deploy_block=c.get("deploy_block"),
                is_testnet=bool(c.get("is_testnet", False)),
                log_rpcs=tuple(log_rpcs),
            )
        )

    blocklist: set[str] = set()
    bl_path = root / scan_raw["identity"].get("blocklist_file", "config/blocklist.txt")
    if not bl_path.is_absolute():
        bl_path = root / bl_path
    if bl_path.exists():
        for line in bl_path.read_text("utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                blocklist.add(line.lower())

    return Config(
        root=root,
        chains=chains,
        registries=Registries(
            identity=reg["identity"].lower(),
            reputation=reg["reputation"].lower(),
            validation=reg.get("validation", "").lower(),
        ),
        candidates={k: v.lower() for k, v in reg.get("candidates", {}).items()},
        multicall3=common["multicall3"].lower(),
        erc721_interface_id=common["erc721_interface_id"],
        scan=_expand_deep_safe(scan_raw),
        abis=abis,
        blocklist=blocklist,
    )


def _expand_deep_safe(obj):
    """scan.toml 里的 ${} 延后到使用时展开（user_agent 走 Config.user_agent）。"""
    return obj
