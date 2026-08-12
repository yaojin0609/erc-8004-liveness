"""探测配置。纯 dataclass，不读本仓的 config/ —— 库边界要求（CLAUDE.md 硬约束 3）。"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ProbeConfig:
    # 身份：缺失即拒绝启动，不许匿名扫描
    user_agent: str

    # 限速（伦理红线的参数化）
    global_rps: float = 10.0
    per_host_interval_s: float = 3.0
    per_host_concurrency: int = 1
    per_ip_interval_s: float = 1.0
    host_workers: int = 200

    # 超时
    dns_timeout_s: float = 5.0
    connect_timeout_s: float = 10.0
    read_timeout_s: float = 10.0
    total_timeout_s: float = 30.0

    # 重试与退避
    max_attempts_per_target: int = 2
    backoff_base_s: float = 2.0
    host_blocklist_after_429: int = 3

    # 抓取上限
    max_body_bytes: int = 1_048_576

    # 协议层
    a2a_card_paths: tuple[str, ...] = (
        "/.well-known/agent-card.json",
        "/.well-known/agent.json",
    )
    mcp_protocol_version: str = "2025-06-18"
    mcp_call_tools_list: bool = True
    mcp_transports: tuple[str, ...] = ("streamable_http", "sse")

    # TLS 失败后再做一次不校验连接，纯粹用于分类。证书过期的服务是活着的。
    tls_classify_on_failure: bool = True

    blocklist: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_toml(cls, scan: dict, user_agent: str, blocklist=()) -> ProbeConfig:
        """从 config/scan.toml 的 dict 构造。这是【调用方】的适配层，不是库依赖。"""
        lim = scan.get("limits", {})
        to = scan.get("timeouts", {})
        fetch = scan.get("fetch", {})
        pr = scan.get("probe", {})
        return cls(
            user_agent=user_agent,
            global_rps=lim.get("global_rps", 10.0),
            per_host_interval_s=lim.get("per_host_interval_s", 3.0),
            per_host_concurrency=lim.get("per_host_concurrency", 1),
            per_ip_interval_s=lim.get("per_ip_interval_s", 1.0),
            host_workers=lim.get("host_workers", 200),
            dns_timeout_s=to.get("dns_s", 5.0),
            connect_timeout_s=to.get("connect_s", 10.0),
            read_timeout_s=to.get("read_s", 10.0),
            total_timeout_s=to.get("total_s", 30.0),
            max_attempts_per_target=lim.get("max_attempts_per_target", 2),
            backoff_base_s=lim.get("backoff_base_s", 2.0),
            host_blocklist_after_429=lim.get("host_blocklist_after_429", 3),
            max_body_bytes=fetch.get("max_body_bytes", 1_048_576),
            a2a_card_paths=tuple(pr.get("a2a_card_paths", cls.a2a_card_paths)),
            mcp_protocol_version=pr.get("mcp_protocol_version", "2025-06-18"),
            mcp_call_tools_list=pr.get("mcp_call_tools_list", True),
            mcp_transports=tuple(pr.get("mcp_transports", ("streamable_http", "sse"))),
            tls_classify_on_failure=pr.get("tls_classify_on_failure", True),
            blocklist=frozenset(blocklist),
        )
