-- ERC-8004 全量分析 —— DuckDB Schema
-- 约定：
--   * 所有地址统一小写 0x 前缀 hex，存 VARCHAR(42)。写入前必须 .lower()，禁止存 checksum 大小写混合。
--   * 所有 hash（tx/block/topic）统一小写 0x 前缀 hex。
--   * agent_id 是 uint256，实践中从 0 递增，存 UBIGINT；解码时超出 2^63-1 必须抛错，不得静默截断。
--   * 金额/评分一律 HUGEINT(=int128) 存原始值 + DECIMAL 存还原值，禁止 DOUBLE。
--   * raw 层表 append-only；derived 层表可 DROP 重建。
--   * 所有网络 stage 的表都带 fetched_at / probed_at，保证可追溯。

------------------------------------------------------------------------------
-- 0. 元数据层：链配置与快照锚点
------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS chain (
    chain_id              BIGINT       PRIMARY KEY,
    name                  VARCHAR      NOT NULL,
    tier                  VARCHAR      NOT NULL,   -- 'A' 全量深度 | 'B' 仅人口普查
    is_testnet            BOOLEAN      NOT NULL DEFAULT FALSE,
    identity_registry     VARCHAR(42)  NOT NULL,
    reputation_registry   VARCHAR(42),
    validation_registry   VARCHAR(42),             -- 允许 NULL：官方 README 未列出，见 T0-2
    deploy_block          UBIGINT,                 -- Stage 01 二分查找结果
    confirmations         INTEGER      NOT NULL DEFAULT 12,
    supports_finalized    BOOLEAN      NOT NULL DEFAULT TRUE,
    max_log_range         UBIGINT      NOT NULL DEFAULT 10000,  -- 自适应收敛值，Stage 02 回写
    verified_at           TIMESTAMP                -- 通过 supportsInterface/getIdentityRegistry 校验的时间
);

-- 快照清单：所有分析以此为准。扫描/查询一律不用 'latest'。
CREATE TABLE IF NOT EXISTS snapshot (
    snapshot_id           VARCHAR      NOT NULL,   -- 如 '2026-08-20'
    chain_id              BIGINT       NOT NULL REFERENCES chain(chain_id),
    block_number          UBIGINT      NOT NULL,
    block_hash            VARCHAR(66)  NOT NULL,
    block_timestamp       TIMESTAMP    NOT NULL,
    created_at            TIMESTAMP    NOT NULL DEFAULT now(),
    PRIMARY KEY (snapshot_id, chain_id)
);

-- 平行注册表普查。
--
-- 链上实测发现（2026-08-10）：存在【两组完全平行】的注册表部署。
--   A 组 0x8004a169 / 0x8004baa1  —— Ethereum 上近 10 万区块有 104 次 Registered，是活的
--   B 组 0x8004a818 / 0x8004b663  —— Ethereum 上同一个 implementation 但 0 次 Registered；
--                                   BSC 上甚至是完全不同的合约（impl 0xd53de688，非 ERC-721）
--
-- 主流水线只跑 A 组（口径单一、不会误 join）。B 组走这张表做轻量普查 ——
-- 「有多少注册落在了那组死的注册表上」直接解释了各家统计数字打架的一部分原因。
CREATE TABLE IF NOT EXISTS registry_census (
    chain_id              BIGINT       NOT NULL,
    registry              VARCHAR(42)  NOT NULL,
    label                 VARCHAR      NOT NULL,   -- 'identity_a' | 'identity_b' | ...
    is_canonical          BOOLEAN      NOT NULL,   -- 是否主流水线扫描的那组
    implementation        VARCHAR(42),             -- ERC-1967 slot 读出的实现地址
    is_erc721             BOOLEAN,
    registered_total      UBIGINT,                 -- 全历史 Registered 事件数
    first_block           UBIGINT,
    last_block            UBIGINT,
    measured_at           TIMESTAMP    NOT NULL DEFAULT now(),
    PRIMARY KEY (chain_id, registry)
);

-- 断点续跑游标。每个 stage 每条链一行。
CREATE TABLE IF NOT EXISTS stage_cursor (
    stage                 VARCHAR      NOT NULL,
    chain_id              BIGINT       NOT NULL,
    cursor                VARCHAR      NOT NULL,   -- 语义由 stage 自定义（区块号 / URI 游标 / round 号）
    updated_at            TIMESTAMP    NOT NULL DEFAULT now(),
    PRIMARY KEY (stage, chain_id)
);

------------------------------------------------------------------------------
-- 1. RAW 层：链上日志（append-only，永不 UPDATE）
------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS log_raw (
    chain_id              BIGINT       NOT NULL,
    block_number          UBIGINT      NOT NULL,
    block_hash            VARCHAR(66)  NOT NULL,   -- 重组检测用
    block_timestamp       TIMESTAMP,
    tx_hash               VARCHAR(66)  NOT NULL,
    tx_index              INTEGER      NOT NULL,
    log_index             INTEGER      NOT NULL,
    address               VARCHAR(42)  NOT NULL,
    topic0                VARCHAR(66)  NOT NULL,
    topic1                VARCHAR(66),
    topic2                VARCHAR(66),
    topic3                VARCHAR(66),
    data                  BLOB         NOT NULL,
    removed               BOOLEAN      NOT NULL DEFAULT FALSE,
    PRIMARY KEY (chain_id, block_number, log_index)
);
CREATE INDEX IF NOT EXISTS idx_log_raw_topic0 ON log_raw(chain_id, topic0);

------------------------------------------------------------------------------
-- 2. 解码层：Identity Registry
------------------------------------------------------------------------------

-- event Registered(uint256 indexed agentId, string agentURI, address indexed owner)
CREATE TABLE IF NOT EXISTS ev_registered (
    chain_id              BIGINT       NOT NULL,
    agent_id              UBIGINT      NOT NULL,
    agent_uri             VARCHAR      NOT NULL,
    owner                 VARCHAR(42)  NOT NULL,   -- 注册时 owner，非当前 owner
    block_number          UBIGINT      NOT NULL,
    block_timestamp       TIMESTAMP,
    tx_hash               VARCHAR(66)  NOT NULL,
    log_index             INTEGER      NOT NULL,
    PRIMARY KEY (chain_id, block_number, log_index)   -- 与其它事件表保持同一套日志身份
);
CREATE INDEX IF NOT EXISTS idx_registered_agent ON ev_registered(chain_id, agent_id);
CREATE INDEX IF NOT EXISTS idx_registered_owner ON ev_registered(owner);

-- event URIUpdated(uint256 indexed agentId, string newURI, address indexed updatedBy)
CREATE TABLE IF NOT EXISTS ev_uri_updated (
    chain_id              BIGINT       NOT NULL,
    agent_id              UBIGINT      NOT NULL,
    new_uri               VARCHAR      NOT NULL,
    updated_by            VARCHAR(42)  NOT NULL,
    block_number          UBIGINT      NOT NULL,
    log_index             INTEGER      NOT NULL,
    PRIMARY KEY (chain_id, block_number, log_index)
);

-- event MetadataSet(uint256 indexed agentId, string indexed indexedMetadataKey,
--                   string metadataKey, bytes metadataValue)
-- 注意：indexedMetadataKey 是 keccak 哈希，可读 key 取非 indexed 的 metadata_key。
CREATE TABLE IF NOT EXISTS ev_metadata_set (
    chain_id              BIGINT       NOT NULL,
    agent_id              UBIGINT      NOT NULL,
    metadata_key          VARCHAR      NOT NULL,   -- 可读值，来自 data 段
    metadata_key_hash     VARCHAR(66)  NOT NULL,   -- topic 里的 keccak 值，保留备查
    metadata_value        BLOB         NOT NULL,
    block_number          UBIGINT      NOT NULL,
    log_index             INTEGER      NOT NULL,
    PRIMARY KEY (chain_id, block_number, log_index)
);

-- ERC-721 Transfer：推导当前 owner 必需。mint 时 from = 0x0，burn 时 to = 0x0。
CREATE TABLE IF NOT EXISTS ev_transfer (
    chain_id              BIGINT       NOT NULL,
    agent_id              UBIGINT      NOT NULL,
    from_addr             VARCHAR(42)  NOT NULL,
    to_addr               VARCHAR(42)  NOT NULL,
    block_number          UBIGINT      NOT NULL,
    log_index             INTEGER      NOT NULL,
    PRIMARY KEY (chain_id, block_number, log_index)
);

-- 铸造（= 注册）记录，来源是 alchemy_getAssetTransfers 而不是事件日志。
--
-- 【为什么不并进 ev_registered】Alchemy 免费档的 eth_getLogs 只允许 10 个区块
-- 跨度（以太坊一条链就要 13.9 万次请求），拿不到 Registered 事件。
-- getAssetTransfers 能一次查全区间，但它返回的是 ERC-721 转账，
-- 【没有 agentURI】—— 而 ev_registered.agent_uri 是事件本体的一部分。
-- 往事件表里填 '' 凑格式，等于让以后每个查 ev_registered.agent_uri 的人拿到假数据。
-- 所以单独成表，provenance 显式记在 source 列上，消费方自己决定要不要用。
CREATE TABLE IF NOT EXISTS agent_mint (
    chain_id              BIGINT       NOT NULL,
    agent_id              UBIGINT      NOT NULL,
    owner                 VARCHAR(42)  NOT NULL,   -- 铸造接收方 = 注册时 owner
    block_number          UBIGINT      NOT NULL,
    block_timestamp       TIMESTAMP,
    tx_hash               VARCHAR(66)  NOT NULL,
    source                VARCHAR      NOT NULL,   -- 'alchemy_asset_transfers' | 'etherscan_v2' | ...
    -- 【PK 带 block_number】同一个 agent_id 可能被 mint 两次（销毁后重铸）。
    -- 实测 polygon 有 610 条 mint 但当前只有 608 个 agent。
    -- 按 (chain_id, agent_id) 做 PK 会让重铸把首次注册【覆盖掉】，
    -- 队列分析的注册月份就会偏晚。raw 层留全量，「哪次算注册」交给派生层取 min()。
    PRIMARY KEY (chain_id, agent_id, block_number)
);
CREATE INDEX IF NOT EXISTS idx_mint_owner ON agent_mint(owner);
CREATE INDEX IF NOT EXISTS idx_mint_ts ON agent_mint(chain_id, block_timestamp);

------------------------------------------------------------------------------
-- 3. 解码层：Reputation / Validation Registry
------------------------------------------------------------------------------

-- event NewFeedback(uint256 indexed agentId, address indexed clientAddress, uint64 feedbackIndex,
--   int128 value, uint8 valueDecimals, string indexed indexedTag1, string tag1, string tag2,
--   string endpoint, string feedbackURI, bytes32 feedbackHash)
CREATE TABLE IF NOT EXISTS ev_feedback (
    chain_id              BIGINT       NOT NULL,
    agent_id              UBIGINT      NOT NULL,
    client_address        VARCHAR(42)  NOT NULL,
    feedback_index        UBIGINT      NOT NULL,
    value_raw             HUGEINT      NOT NULL,   -- int128 原始值，可为负
    value_decimals        UTINYINT     NOT NULL,   -- 0..18
    value_real            DECIMAL(38,18),          -- = value_raw / 10^value_decimals，禁止用 float 算
    tag1                  VARCHAR,                 -- 可读值，来自 data 段（非 indexed）
    tag2                  VARCHAR,
    endpoint              VARCHAR,
    feedback_uri          VARCHAR,                 -- 链下评价文件，L4 额外证据
    feedback_hash         VARCHAR(66),
    tx_hash               VARCHAR(66)  NOT NULL,
    tx_from               VARCHAR(42),             -- Stage 07 回填，用于 T4 代付 gas 判定
    block_number          UBIGINT      NOT NULL,
    block_timestamp       TIMESTAMP,
    log_index             INTEGER      NOT NULL,
    PRIMARY KEY (chain_id, block_number, log_index)
);
CREATE INDEX IF NOT EXISTS idx_feedback_agent  ON ev_feedback(chain_id, agent_id);
CREATE INDEX IF NOT EXISTS idx_feedback_client ON ev_feedback(client_address);

CREATE TABLE IF NOT EXISTS ev_feedback_revoked (
    chain_id              BIGINT       NOT NULL,
    agent_id              UBIGINT      NOT NULL,
    client_address        VARCHAR(42)  NOT NULL,
    feedback_index        UBIGINT      NOT NULL,
    block_number          UBIGINT      NOT NULL,
    log_index             INTEGER      NOT NULL,
    PRIMARY KEY (chain_id, block_number, log_index)
);

CREATE TABLE IF NOT EXISTS ev_response_appended (
    chain_id              BIGINT       NOT NULL,
    agent_id              UBIGINT      NOT NULL,
    client_address        VARCHAR(42)  NOT NULL,
    feedback_index        UBIGINT      NOT NULL,
    responder             VARCHAR(42)  NOT NULL,
    response_uri          VARCHAR,
    response_hash         VARCHAR(66),
    block_number          UBIGINT      NOT NULL,
    log_index             INTEGER      NOT NULL,
    PRIMARY KEY (chain_id, block_number, log_index)
);

-- 可选层：validation_registry 为 NULL 时整表为空，不阻塞主线。
CREATE TABLE IF NOT EXISTS ev_validation (
    chain_id              BIGINT       NOT NULL,
    kind                  VARCHAR      NOT NULL,   -- 'request' | 'response'
    validator_address     VARCHAR(42)  NOT NULL,
    agent_id              UBIGINT      NOT NULL,
    request_hash          VARCHAR(66)  NOT NULL,
    response              UTINYINT,                -- 0..100，仅 kind='response'
    uri                   VARCHAR,
    tag                   VARCHAR,
    block_number          UBIGINT      NOT NULL,
    log_index             INTEGER      NOT NULL,
    PRIMARY KEY (chain_id, block_number, log_index)
);

------------------------------------------------------------------------------
-- 4. 状态快照层（Stage 03，multicall 读取）
------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS agent_state (
    chain_id              BIGINT       NOT NULL,
    agent_id              UBIGINT      NOT NULL,
    snapshot_id           VARCHAR      NOT NULL,
    current_owner         VARCHAR(42),             -- ownerOf()，NULL 表示已销毁
    agent_wallet          VARCHAR(42),             -- getAgentWallet()，L5 关键
    token_uri             VARCHAR,                 -- tokenURI()
    owner_matches_logs    BOOLEAN,                 -- 与 Transfer 推导值一致？不一致说明扫漏日志，必须告警
    uri_matches_logs      BOOLEAN,
    PRIMARY KEY (chain_id, agent_id, snapshot_id)
);

------------------------------------------------------------------------------
-- 5. URI 抓取层（Stage 04，网络出口 A）
------------------------------------------------------------------------------

-- 按「规范化 URI」去重，不是按 agent。去重系数决定这一步跑 2h 还是 20h。
CREATE TABLE IF NOT EXISTS uri_fetch (
    uri_normalized        VARCHAR      PRIMARY KEY,
    scheme_kind           VARCHAR      NOT NULL,   -- 'data' | 'https' | 'ipfs' | 'ar' | 'did' | 'ens' | 'other'
    status                VARCHAR      NOT NULL,   -- 见下方 CHECK 注释
    http_status           INTEGER,
    final_url             VARCHAR,                 -- 重定向后的最终 URL
    gateway_used          VARCHAR,                 -- IPFS 走了哪个网关
    content_sha256        VARCHAR(64),             -- 指向 data/raw/<sha[:2]>/<sha>
    content_bytes         INTEGER,
    content_type          VARCHAR,
    elapsed_ms            INTEGER,
    attempt_count         INTEGER      NOT NULL DEFAULT 1,
    error_detail          VARCHAR,
    fetched_at            TIMESTAMP    NOT NULL DEFAULT now()
);
-- status 取值（失败分类学，本 stage 的核心交付物）：
--   ok | unsupported_scheme | dns_fail | tls_fail | conn_timeout | read_timeout
--   | http_404 | http_4xx | http_5xx | too_large | not_json | ipfs_unresolvable | other
-- 注意：not_json 在本层判定（能否 parse）；schema_invalid 在 Stage 05 判定（parse 后是否合规）。

------------------------------------------------------------------------------
-- 5b. 链下反馈文件层（Stage 07b，网络出口 D）
--     复用 uri_fetch 的抓取器与限速器，只换 URI 来源与解析器。
--     这张表测量的是「声称付过钱」与「真的付过钱」之间的差额 —— 既是报告发现，
--     也是后续「支付凭证 × 声誉绑定」产品的市场规模测量。
------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS feedback_file (
    feedback_uri          VARCHAR      PRIMARY KEY,
    status                VARCHAR      NOT NULL,   -- 与 uri_fetch.status 同一套分类学
    content_sha256        VARCHAR(64),
    -- 解析出的声明值
    declared_value_raw    HUGEINT,
    declared_value_dec    UTINYINT,
    declared_tag1         VARCHAR,
    declared_endpoint     VARCHAR,
    mcp_tool              VARCHAR,                 -- mcp.tool
    a2a_skills            VARCHAR[],               -- a2a.skills
    -- proofOfPayment：本表的核心
    has_proof_of_payment  BOOLEAN      NOT NULL DEFAULT FALSE,
    pop_chain_id          BIGINT,
    pop_tx_hash           VARCHAR(66),
    pop_from              VARCHAR(42),
    pop_to                VARCHAR(42),
    -- 链上核验（eth_getTransactionByHash）：声称 vs 真实
    pop_tx_exists         BOOLEAN,                 -- 这笔交易真的存在吗
    pop_parties_match     BOOLEAN,                 -- 收付方真的匹配吗
    pop_verified          BOOLEAN,                 -- = pop_tx_exists AND pop_parties_match
    -- 完整性交叉检查：链下文件的 value 与链上事件的 value 是否一致
    value_matches_onchain BOOLEAN,                 -- 不一致本身就是一个数据完整性发现
    fetched_at            TIMESTAMP    NOT NULL DEFAULT now()
);

------------------------------------------------------------------------------
-- 6. Card 解析层（Stage 05，纯函数，可随时 DROP 重建）
------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS agent_card (
    chain_id              BIGINT       NOT NULL,
    agent_id              UBIGINT      NOT NULL,
    content_sha256        VARCHAR(64),
    parsed_lenient        BOOLEAN      NOT NULL,   -- 能解析出 name/services 即可，下游分析用
    schema_valid_strict   BOOLEAN      NOT NULL,   -- 严格符合 registration-v1，报告 headline 用
    schema_errors         VARCHAR,                 -- JSON 数组字符串
    type_field            VARCHAR,                 -- 应为 https://eips.ethereum.org/EIPS/eip-8004#registration-v1
    name                  VARCHAR,
    description           VARCHAR,
    image                 VARCHAR,
    active                BOOLEAN,                 -- NULL = 未声明；FALSE = 自我声明不活跃，必须单列成支
    x402_support          BOOLEAN,
    supported_trust       VARCHAR[],               -- reputation | crypto-economic | tee-attestation
    service_count         INTEGER      NOT NULL DEFAULT 0,
    PRIMARY KEY (chain_id, agent_id)
);

-- services[] 展开。这张表是 Stage 06 探测的输入。
CREATE TABLE IF NOT EXISTS service (
    chain_id              BIGINT       NOT NULL,
    agent_id              UBIGINT      NOT NULL,
    service_idx           INTEGER      NOT NULL,
    service_name          VARCHAR,                 -- web | A2A | MCP | OASF | ENS | DID | email
    endpoint              VARCHAR,
    version               VARCHAR,
    endpoint_host         VARCHAR,                 -- 解析出的 FQDN，限速分桶键
    endpoint_scheme       VARCHAR,
    is_routable           BOOLEAN,                 -- FALSE = localhost / RFC1918 / 保留域名，L2 判定用
    PRIMARY KEY (chain_id, agent_id, service_idx)
);
CREATE INDEX IF NOT EXISTS idx_service_host ON service(endpoint_host);

-- registrations[] 展开：agent 自我声明的跨链身份，去重的强证据。
CREATE TABLE IF NOT EXISTS card_registration (
    chain_id              BIGINT       NOT NULL,   -- 声明来源所在链
    agent_id              UBIGINT      NOT NULL,   -- 声明来源 agent
    claimed_chain_id      BIGINT,                  -- 从 CAIP-2 'eip155:1:0x...' 解析
    claimed_registry      VARCHAR(42),
    claimed_agent_id      UBIGINT,
    PRIMARY KEY (chain_id, agent_id, claimed_chain_id, claimed_agent_id)
);

------------------------------------------------------------------------------
-- 7. 活性探测层（Stage 06，网络出口 B）
------------------------------------------------------------------------------

-- 原始探测记录，不做「是否算活」的判定 —— 判定在 Stage 08 用 SQL 做，口径可随时改并重算。
CREATE TABLE IF NOT EXISTS probe_attempt (
    probe_round           INTEGER      NOT NULL,   -- 1 | 2，两轮间隔 ≥48h
    chain_id              BIGINT       NOT NULL,
    agent_id              UBIGINT      NOT NULL,
    service_idx           INTEGER      NOT NULL,
    layer                 VARCHAR      NOT NULL,   -- 'dns' | 'tcp' | 'tls' | 'http' | 'proto'
    outcome               VARCHAR      NOT NULL,   -- 'ok' | 'fail' | 'skip' | 'rate_limited' | 'blocked'
    -- DNS 层
    resolved_ips          VARCHAR[],
    ip_class              VARCHAR,                 -- 'public' | 'private' | 'loopback' | 'literal' | 'reserved'
    -- TLS 层：证书问题分别记录，且不算 fail
    tls_ok                BOOLEAN,
    tls_error_kind        VARCHAR,                 -- 'expired' | 'self_signed' | 'hostname_mismatch' | 'other'
    tls_not_after         TIMESTAMP,
    -- HTTP 层
    http_status           INTEGER,
    server_header         VARCHAR,
    body_bytes            INTEGER,
    -- 协议层
    proto_kind            VARCHAR,                 -- 'a2a' | 'mcp_streamable' | 'mcp_sse' | 'web'
    proto_ok              BOOLEAN,
    proto_version         VARCHAR,
    server_name           VARCHAR,
    server_version        VARCHAR,
    tool_count            INTEGER,                 -- MCP tools/list 结果；「声称 MCP 但 0 个 tool」是有价值的发现
    capabilities_json     VARCHAR,
    --
    elapsed_ms            INTEGER,
    error_detail          VARCHAR,
    probed_at             TIMESTAMP    NOT NULL DEFAULT now(),
    PRIMARY KEY (probe_round, chain_id, agent_id, service_idx, layer)
);

------------------------------------------------------------------------------
-- 8. 钱包/资金层（Stage 07，网络出口 C）
------------------------------------------------------------------------------

-- 只对到达 L2 的 agent 相关地址跑，否则 API 预算烧穿。
CREATE TABLE IF NOT EXISTS address_funding (
    chain_id              BIGINT       NOT NULL,
    address               VARCHAR(42)  NOT NULL,
    role                  VARCHAR      NOT NULL,   -- 'owner' | 'agent_wallet' | 'feedback_client'
    first_funder          VARCHAR(42),             -- 首笔有 value 的入账来源，Sybil 最硬信号
    first_funding_tx      VARCHAR(66),
    first_funding_ts      TIMESTAMP,
    first_funding_wei     HUGEINT,
    lookup_status         VARCHAR      NOT NULL,   -- 'ok' | 'no_incoming' | 'api_error' | 'skipped'
    fetched_at            TIMESTAMP    NOT NULL DEFAULT now(),
    PRIMARY KEY (chain_id, address, role)
);

CREATE TABLE IF NOT EXISTS address_activity (
    chain_id              BIGINT       NOT NULL,
    address               VARCHAR(42)  NOT NULL,
    native_tx_count       INTEGER,
    erc20_tx_count        INTEGER,
    -- 「真实经济活动」：非 gas、非注册交易本身、且对手方不在同一资金簇内
    has_real_economic_tx  BOOLEAN,
    distinct_counterparties INTEGER,
    last_activity_ts      TIMESTAMP,
    lookup_status         VARCHAR      NOT NULL,
    fetched_at            TIMESTAMP    NOT NULL DEFAULT now(),
    PRIMARY KEY (chain_id, address)
);

------------------------------------------------------------------------------
-- 9. DERIVED 层（Stage 08，纯 SQL，同一份 DB 跑两次结果必须完全一致）
------------------------------------------------------------------------------

-- 跨链身份归并。三档置信度分别产出，报告里全给，不要只给一个数。
CREATE TABLE IF NOT EXISTS identity_cluster (
    chain_id              BIGINT       NOT NULL,
    agent_id              UBIGINT      NOT NULL,
    cluster_strong        VARCHAR,                 -- registrations[] 双向确认
    cluster_medium        VARCHAR,                 -- card content_sha256 相同 且 owner 相同
    cluster_weak          VARCHAR,                 -- owner 相同 且 name 相同
    PRIMARY KEY (chain_id, agent_id)
);

-- 自评闭环分层标记（T1..T5），挂在每条反馈上。
CREATE TABLE IF NOT EXISTS feedback_selfloop (
    chain_id              BIGINT       NOT NULL,
    block_number          UBIGINT      NOT NULL,
    log_index             INTEGER      NOT NULL,
    t1_client_is_owner    BOOLEAN      NOT NULL DEFAULT FALSE,
    t2_client_is_wallet   BOOLEAN      NOT NULL DEFAULT FALSE,
    t3_same_funder        BOOLEAN      NOT NULL DEFAULT FALSE,
    t4_owner_paid_gas     BOOLEAN      NOT NULL DEFAULT FALSE,
    t5_reciprocal_cycle   BOOLEAN      NOT NULL DEFAULT FALSE,  -- 单独报告，不计入「自评」
    is_self_review        BOOLEAN      NOT NULL DEFAULT FALSE,  -- = t1 OR t2 OR t3 OR t4
    PRIMARY KEY (chain_id, block_number, log_index)
);

-- 漏斗主表：每个 (chain, agent) 一行，每层一个布尔列。报告的那张表由此 GROUP BY 得出。
CREATE TABLE IF NOT EXISTS funnel (
    chain_id              BIGINT       NOT NULL,
    agent_id              UBIGINT      NOT NULL,
    snapshot_id           VARCHAR      NOT NULL,
    -- 注册队列：从单次快照里免费拿到时间序列。决策门 S2 信号的来源，见 实施规划 §8.4。
    -- 队列存活率（增量指标）比总存活率（存量指标）重要得多 —— 后者被上线初期的投机注册永久污染。
    reg_month             VARCHAR      NOT NULL,   -- date_trunc('month', ev_registered.block_timestamp)
    l0_registered         BOOLEAN      NOT NULL,   -- 链上存在且未销毁
    l1_uri_resolved       BOOLEAN      NOT NULL,   -- agentURI 取回且能 parse
    l1s_schema_valid      BOOLEAN      NOT NULL,   -- 严格符合 registration-v1
    l2_has_endpoint       BOOLEAN      NOT NULL,   -- services[] 非空且至少一个可路由
    l3a_dns_ok            BOOLEAN      NOT NULL,
    l3b_tcp_ok            BOOLEAN      NOT NULL,
    l3c_http_ok           BOOLEAN      NOT NULL,
    l3_proto_ok           BOOLEAN      NOT NULL,   -- 任一 service 协议握手成功
    l3_stable             BOOLEAN      NOT NULL,   -- 两轮均达 L3
    l4_third_party_fb     BOOLEAN      NOT NULL,   -- 至少一条非自评、未撤销的反馈
    l5_economic           BOOLEAN      NOT NULL,   -- 真实经济活动
    -- 必须单列的旁支，绝不能并入 L3 失败
    declared_inactive     BOOLEAN      NOT NULL,   -- card 里 active: false —— 这是诚实，不是「死」
    unroutable_endpoint   BOOLEAN      NOT NULL,   -- localhost / 私网 —— 「根本没打算对外服务」
    -- 【口径安全阀】该 agent 本轮是否真的被探测过。
    -- 没有它，「尚未探测」会和「探测了但没通过」混成一个数，
    -- L3 存活率会被探测覆盖率稀释 —— 这是最容易让整份报告作废的算错方式。
    -- L3 各层的比率必须以 probed 为分母，并同时公开覆盖率。
    probed                BOOLEAN      NOT NULL DEFAULT FALSE,
    -- 该 agent 的 URI 被单主机上限抽样排除（status='sampled_out'）。
    -- 【既不是失败也不是未抓】：它必须从 L1 的分母里剔除，否则会把
    -- 「我们主动没抓」算成「它没有元数据」，系统性低估 L1。
    uri_sampled_out       BOOLEAN      NOT NULL DEFAULT FALSE,
    PRIMARY KEY (chain_id, agent_id, snapshot_id)
);
