# 新 SN 测试计划

> 配套设计：[BNS-签名边界改造-EVM-TX-TODO.md](BNS-签名边界改造-EVM-TX-TODO.md)、[SN-Auth.md](SN-Auth.md)、[SN-DeviceInfo-DB.md](SN-DeviceInfo-DB.md)、[SN-BNS-Contoller.md](SN-BNS-Contoller.md)、[新SN核心流程整理.md](新SN核心流程整理.md)。
>
> 本计划按"分层独立测试 → 整体集成测试"组织，与目标架构的线性分层一致：
> `BNS(合约) <-> BNS-Indexer <-> BNS-Server <-> BNS-Client <-> BNS-Controller`。
> 每一层先各自闭环验证（mock/in-process 上下游），再在 §5 的 DV 环境里跑通真链路。

## 0. 总览

| # | 测试对象 | 类型 | 运行方式 | 是否需要活节点 |
| --- | --- | --- | --- | --- |
| 1 | BNS 合约 `Bns.sol` | Solidity 单测 + 不变量 | `forge test` | 否（forge 内置 EVM） |
| 2.1 | `bns-evm` | Rust 单测（编解码/签名） | `cargo test -p bns-evm` | 否 |
| 2.2 | `bns-indexer` | Rust 单测（投影/游标/同步） | `cargo test -p bns-indexer` | 否（mock RPC） |
| 2.3 | `bns-server` | Rust 单测（处理器/转发/禁用旧写） | `cargo test -p bns-server` | 否（mock RPC） |
| 2.4 | `bns-client` / Controller | Rust 单测（构造/签名/控制策略） | `cargo test -p bns-client` | 否（in-process registry） |
| 3 | `sn_auth` | Rust 单测（账号/PKX/session/zone_info） | `cargo test -p cyfs-sn sn_auth` | 否 |
| 4 | `sn_device_info` | Rust 单测（状态机/IP 规则/endpoint） | `cargo test -p cyfs-sn sn_device_info` | 否 |
| 5 | 全链路 | DV 集成测试 | 一键脚本拉起 anvil→部署→indexer→server→client | 是（真 anvil 私链） |

**分层测试原则**：
- 每一层的独立测试用**桩（mock/in-process）**替代相邻层，只验证本层契约（输入→输出、错误码、边界）。
- §5 的集成测试**不重复**单元测试覆盖过的逻辑分支，只验证"跨层协议拼接 + 真 EVM 暴露的问题"（selector/packing/revert/event topic/nonce/reorg-confirmations）。
- 所有测试必须可在 CI 上**无外部依赖**跑通 §1–§4；§5 依赖 Foundry（anvil/forge），单独标记并允许在缺 Foundry 时跳过。

---

## 1. 智能合约独立测试（`forge test`）

工程：`src/apps/bns`（Foundry，solc 0.8.24 / via_ir / optimizer / evm_version=paris）。
现状：[test/Bns.t.sol](../src/apps/bns/test/Bns.t.sol) 已有 6 个用例。本节是在其基础上的**补全计划**。

### 1.1 已覆盖（回归基线，保持绿）
- `testRegisterAndPublishInlineDocument` — 注册 + inline 文档发布
- `testStaleNameSeqRejectsPublish` — guard / nameSeq 冲突拒绝
- `testControllerCanOnlyPublishAllowedDocType` — controller docType scope 限制
- `testBnsAuthorityKeyTakesOverFromAssetOwner` — BNS 授权密钥接管 assetOwner
- `testRevokeCurrentVersionKeepsCurrentPointerRevoked` — 撤销当前版本
- 链上 smoke：[script/Smoke.s.sol](../src/apps/bns/script/Smoke.s.sol)

### 1.2 访问控制 / 签名边界（核心，必须补）
本次改造的核心约定是"合约只信 `msg.sender`，`CallAuthority` 仅作 role/kid 提示"。需逐函数验证 `_authenticateExpectedPrincipal`（[Bns.sol:1541](../src/apps/bns/src/Bns.sol:1541)）：

> 已实现：[test/BnsAccessControl.t.sol](../src/apps/bns/test/BnsAccessControl.t.sol)（12 例，全绿）。
- [x] `CallAuthority.actor` 解析地址 == `msg.sender` → 通过；!= `msg.sender` → revert（用 `vm.prank` 改变 sender，CallAuthority 不变）。
- [x] role=Owner 时由非 owner 地址提交 → revert；role=Controller 时由未登记 controller 地址提交 → revert。
- [x] 授权密钥（authority key）地址 == `msg.sender` 才能写；过期/被移除的 key → revert。
- [x] `setNameOwner` / `transferName` 后旧 owner 立即丧失写权限、新 owner 获得写权限。
- [x] `_authorizeOwner`（[Bns.sol:1526](../src/apps/bns/src/Bns.sol:1526)）与 `_authorizeUpdate`（[Bns.sol:1487](../src/apps/bns/src/Bns.sol:1487)）的 effectiveOwner 解析在"BNS authority key 接管"场景下一致。

### 1.3 Controller 策略位掩码（逐 permission）
对 `ControllerRule.permissions` 的每一位单独建用例（已实现：[test/BnsControllerPolicy.t.sol](../src/apps/bns/test/BnsControllerPolicy.t.sol)，8 例全绿）：
- [x] `PUBLISH_DOCUMENT` / `REVOKE_DOCUMENT` / `SET_PAYMENT` / `SET_ALIAS` / `SET_NAMESPACE` — 有该位可写、无该位 revert。
- [x] docType scope 不匹配 → revert（已有 1 例，补全各 docType）。
- [x] 有效期窗口：未生效 / 已过期 → revert；窗口内 → 通过。
- [x] controller 只能 publish 非 owner-scoped 文档，不能写 owner 级文档（对应 client 侧 `sn_controller_cannot_publish_owner_scoped_device_doc`）。

### 1.4 MutationGuard / 防重放
已实现：[test/BnsGuardReplay.t.sol](../src/apps/bns/test/BnsGuardReplay.t.sol)（6 例全绿）。
- [x] `expectedNameSeq` 匹配/不匹配（已有 1 例）+ `expectedParentNameSeq` 父序号校验（[Bns.sol:1639](../src/apps/bns/src/Bns.sol:1639)）。
- [x] `_hashDocumentState` / `_commitEvent` 混入 `block.chainid` + `address(this)`：同 calldata 在不同 chainid / 不同合约地址下产生不同 logRoot（用 `vm.chainId` + `snapshotState`/`revertToState` 隔离验证 chainid 与 address 两个维度）。
- [x] 顺序提交时 `seq` / `previousLogRoot` / `logRoot` 链式连续（`ProtocolEvent`，[Bns.sol:322](../src/apps/bns/src/Bns.sol:322)）。

### 1.5 文档与大对象
已实现：[test/BnsDocument.t.sol](../src/apps/bns/test/BnsDocument.t.sol)（6 例全绿）。
- [x] inline 文档：`sha256(inlineDocument) == contentHash` 成立才接受，篡改 hash → revert。
- [x] inline 上限 `MAX_INLINE_DOCUMENT = 4KB`（[Bns.sol:258](../src/apps/bns/src/Bns.sol:258)）：恰好 4KB 通过，超出走 `DocumentRef`（uri+hash）。
- [x] `revokeDocument` 后 `getDocumentVersion` / `resolveDocument` 行为（当前指针 revoked、历史版本仍可查）。

### 1.6 生命周期与命名空间
已实现：[test/BnsLifecycle.t.sol](../src/apps/bns/test/BnsLifecycle.t.sol)（10 例全绿）。
- [x] `registerName` / `bootstrapName` / `renewName`（到期前后续期）/ `releaseName`（释放后 tombstone 拒绝写，对应 indexer 侧 `released_and_tombstoned_names_reject_state_writes`）。
- [x] `releaseName` 不能破坏 active semantic owner 图（indexer 侧 `release_name_rejects_breaking_active_semantic_owner_graph`，`registry.rs` `release_name` → `validate_owner_graph_with`）。> 注：合约 `releaseName` 不做 owner-graph 校验，该约束在 indexer 侧实现并已测。
- [x] `setNamespacePolicy` 读写（`allowDelegatedSubnames`/`namespacePolicyHash` 落库 + 事件）。> 注：合约未在子名注册路径硬性 gate `allowDelegatedSubnames`，准入约束目前仅记录策略哈希。
- [x] `setDidAlias` / `setPaymentTarget` / `resolvePaymentTarget` 读写一致。
- [x] `publishLogCheckpoint` → `latestCheckpoint` 覆盖语义（checkpoint 记录其提交事件之前的 logRoot/lastSeq）。

### 1.7 事件断言（供索引器消费）
已实现：[test/BnsEvents.t.sol](../src/apps/bns/test/BnsEvents.t.sol)（13 例全绿）。
- [x] 每个写操作 `emit` 的专用事件 + 统一 `ProtocolEvent` 字段（name/docType/version/actor/contentHash）均用 `vm.expectEmit` 精确断言 topic 与 data。这是 indexer 解码的契约源头，必须钉死。> 注：含不可复算字段（documentStateHash/authorityRoot）的事件用 `checkData=false` 钉死 indexed topics，派生字段另经 state 读校验。

### 1.8 fuzz / invariant（可选增强）
已实现：[test/BnsFuzz.t.sol](../src/apps/bns/test/BnsFuzz.t.sol)（3 fuzz + 3 invariant，全绿）。
- [x] fuzz `expectedNameSeq`、authority key 地址、permissions 位组合。
- [x] invariant：经 `BnsHandler` 有界驱动，任意写序列后 `globalEventSeq == 已提交事件数`、`currentLogRoot` 非零且推进、pool 内每个 name 读 API 自洽（`seq` 单调、logRoot 链不断裂）。

**通过标准**：`forge test -vvv` 全绿；新增用例覆盖每个写函数的"授权通过 / 授权失败 / guard 失败 / 事件正确"四象限。

---

## 2. BNS Rust 组件独立测试

### 2.1 `bns-evm`（ABI 绑定 + TX 构造/签名）
现状：[tests/abi_tx.rs](../src/components/bns-evm/tests/abi_tx.rs) 已有 round-trip 用例。
> 已实现：[tests/evm_components.rs](../src/components/bns-evm/tests/evm_components.rs)（25 例，全绿）。

- [x] **calldata round-trip**：覆盖 register/publish/revoke/setControllerPolicy/setDidAlias/setPaymentTarget/setNamespacePolicy/release/transfer/setNameOwner/renewName 各写函数 encode→decode 一致；`CallAuthority` / `MutationGuard` / `RegisterOptions` / `Principal` packing 一致。
- [x] **chainAccountPrincipal 编码**：地址按 20 字节、bnsName 按 utf-8 名字字节编码，往返后仍是 20 字节裸地址（`chain_account_principal_encodes_address_as_20_bytes`）。
- [x] **TX 构造**：`build_eip1559_contract_tx` 产出 EIP-1559 字段正确（maxFeePerGas/maxPriorityFee/gasLimit/nonce/chainId/to/value=0、access_list 空、input==encoded call）。
- [x] **签名与 signer 恢复**：`sign_eip1559_tx` → 独立 `decode_signed_eip1559` → 恢复 signer 地址 == key 地址；不同 key 恢复不同 signer。
- [x] **event 解码**：用 sol! 绑定 encode 的 `ProtocolEvent` / `DocumentPublished` / `NameRegistered` 字节验证 `decode_bns_event` 字段一致。
- [x] **call 解码**：`decode_bns_call` 从 calldata 还原 authority / controller rule 入参（indexer 补全时依赖）。
- [x] **边界/错误**：截断 calldata、未知 selector、空 calldata、坏 raw TX、错误 chainId（签名 hash 不同）→ 明确错误而非 panic。

运行：`cargo test -p bns-evm`，无需节点。

### 2.2 `bns-indexer`（事件索引器）
现状：[tests/sync_config.rs](../src/components/bns-indexer/tests/sync_config.rs)、[tests/evm_projection.rs](../src/components/bns-indexer/tests/evm_projection.rs)、[tests/centralized_registry.rs](../src/components/bns-indexer/tests/centralized_registry.rs)。
> 已实现 mock JSON-RPC 套件：[tests/sync_mock_rpc.rs](../src/components/bns-indexer/tests/sync_mock_rpc.rs)（8 例，全绿；内置进程内 `MockEthRpc`，按方法名/selector 返回预置 JSON）。

**投影正确性（projection_for_record，[sync.rs:280](../src/components/bns-indexer/src/sync.rs:280)）**：
- [x] **混合投影策略**：`sync_projects_document_published_via_mixed_eth_call_strategy` —— DocumentPublished 事件只定位 name/doc，随后 `eth_call`（`queryNameState`/`getDocumentVersion`）拉权威态，验证投影=最新快照（nameSeq 取自 eth_call 而非事件回放）。
- [x] authority key / controller rule 通过 `decode_bns_call`（按 tx hash 缓存）补全：`sync_backfills_controller_rules_from_decoded_call`（ControllerPolicyUpdated 事件不带 rules，经 `eth_getTransactionByHash` + decode 补全）。
- [x] 其余 docType（authority set+keys / alias / checkpoint）逐类投影字段补全（`sync_projects_authority_set_and_keys_via_mixed_strategy`：getAuthoritySet 拉 set + decode `updateAuthorityKeys` 补 key；`sync_projects_did_alias_via_eth_call`：getAlias 拉 alias）。

**同步器（sync_once，[sync.rs:164](../src/components/bns-indexer/src/sync.rs:164)）**，用 mock JSON-RPC：
- [x] chain_id 校验：链上 chainId 与配置不符 → 拒绝同步（`sync_rejects_chain_id_mismatch`）。
- [x] confirmations 回退：未达 `confirmations` 的块不被同步（`sync_respects_confirmations_rollback`）。
- [x] `max_block_span` 分片：大区间被切成多次 `eth_getLogs`，游标按 span 推进（`sync_shards_large_range_by_max_block_span_and_advances_cursor`）。
- [x] 游标推进 + 幂等：追平后重复调用不再 `eth_getLogs`、不重投影（`sync_is_idempotent_when_already_caught_up`）。
- [x] **source 隔离**（sync_config）+ **合约重部署从 0 重放**：换合约地址即换 source，新 source 从 `start_block` 重放、旧游标不串扰（`redeploy_to_new_contract_uses_isolated_source_cursor`）。
- [x] 事件+投影同一 `store.transact` 原子落库：中段失败 → 整批回滚（`event_and_projection_share_atomic_transaction_rollback`）。

**EventLog / Checkpoint**：
- [x] `EventLogRecord` 由 `seq`/`previousLogRoot`/`logRoot` 派生写入 `bns_events`（混合投影测试内断言 `list_events` 的 seq/event_type/log_root；另有 evm_projection 基线）。
- [x] `LogCheckpointPublished` → `eth_call latestCheckpoint` → `put_checkpoint` 的 `ON CONFLICT(last_seq)` 覆盖（`sync_projects_log_checkpoint_and_overwrites_on_last_seq_conflict`：同 lastSeq、新 logRoot/issuedAt → UPDATE 覆盖而非新增行）。

**registry 回归**：保留 `centralized_registry.rs` 全部用例为回归（状态机下线前的语义基线）。

运行：`cargo test -p bns-indexer`，mock RPC 无需活节点。

### 2.3 `bns-server`（标准智能合约处理器）
现状：逻辑在 [bns-server/src/lib.rs](../src/components/bns-server/src/lib.rs)（`BnsContractServerHandler` / `submit_raw_tx` / `BnsContractServerRpcHandler`），已有 lib 内 in-module 测试。
> 新建 tests 目录：[tests/contract_server.rs](../src/components/bns-server/tests/contract_server.rs)（10 例，全绿；内存 SQLite 投影 + 复用型 `MockEthRpc`）。

- [x] **写路径 `tx.submit_raw`**：合法 raw TX hex → 转发 `eth_sendRawTransaction`（mock 断言收到的 raw 字节一致），返回 tx hash；非法 hex / 空 → 明确错误。
- [x] **不解释 payload / 不鉴权**：构造一段非合法签名 TX 的"垃圾"字节，server 仍原样转发（`submit_raw_tx_does_not_parse_or_authenticate_payload`）。
- [x] **旧写 RPC 禁用**：直接 handler 调用 → `UNSUPPORTED_OPERATION`；RPC 层 `name.register` / `document.publish` / `controller.set_policy` → `UnknownMethod`（不路由旧写）。
- [x] **读路径**：`query_name_state` / `resolve_document` 查 SQLite 投影，envelope（`ok`/`result`）包装正确。
- [x] **RPC 路由**：`METHOD_SUBMIT_RAW_TX` 与别名 `submit_raw_tx` 都命中；未知 method → `UnknownMethod`。

运行：`cargo test -p bns-server`，用内存/临时 SQLite 投影 + mock eth RPC。

### 2.4 `bns-client`（薄封装）与 `bns-controller`（前置签名）
现状：[tests/rpc_and_controller.rs](../src/components/bns-client/tests/rpc_and_controller.rs) 已较充分（in-process registry）。
> 补全 EVM 提交链路：[tests/evm_submit_chain.rs](../src/components/bns-client/tests/evm_submit_chain.rs)（5 例，全绿；捕获型 mock `BnsIndexerApi` server + mock eth RPC，无活节点）。

**Standard Client（无私钥）**：
- [x] `build_calldata` / `build_unsigned_tx`（`evm_standard_client_builds_unsigned_contract_tx`）：unsigned TX 字段供外部签名。
- [x] 入参为外部已签 raw TX → 经 server `submit_raw` 提交（`controller_auto_nonce_signs_and_submits_via_bns_server`，对接 §2.3 的 mock server，断言 server 收到的 raw 字节可恢复出 signer）。
- [x] Standard client `submit_raw_tx` 直接转发 `eth_sendRawTransaction`，原样 raw 字节（`standard_client_submit_raw_tx_forwards_to_chain_rpc`）；读路径走 in-process / kRPC 索引器（rpc_and_controller 覆盖）。

**Controller Client（托管私钥，自动签名）**：
- [x] 自动 nonce（链上 `eth_getTransactionCount`）→ chainId/to/gas → ABI 编码 → 签名 → 提交全链（`controller_auto_nonce_signs_and_submits_via_bns_server` / `controller_with_explicit_chain_rpc_submitter_uses_chain`）。
- [x] **控制策略边界**（已有多例，保持）：高风险 docType scope 拒绝、controller 不能写 owner-scoped 文档、docType scope denial 映射、bootstrap 安装 controller policy。
- [x] **DNS TXT 幂等**（已有 `sn_controller_upserts_dns_txt_with_idempotency` / `removes_last_dns_txt_record_by_publishing_empty_rrset`）：保持。
- [x] **stale guard 错误码透传**（已有 `bns_client_preserves_stale_guard_error_codes`）：合约 guard revert → client 保留原始错误码。
- [x] **EVM 模式多步 zone bind**（已有 `evm_mode_rejects_multi_step_zone_bind_without_submission`）：保持。
- [x] **nonce 管理（基础）**：连续两笔写 nonce 递增（`controller_increments_nonce_across_consecutive_writes`）、提交失败回退重查（`controller_resets_cached_nonce_after_submission_failure`）。> 增强项（并发冲突、可选等待回执确认上链）仍待设计 §4 落地。
- [ ] **迁移项**（设计 §4 TODO → 落地后补）：`sn_bns_controller.rs` 从手工拼 `CallAuthority` 切到"构造 op → Controller 自动签名"后，验证不再产生 `CallAuthority` 写 RPC。
- [x] **幂等元数据**：`SqliteSnBnsWriteRequestStore` 的 `evm_chain_id`/`evm_nonce`/`evm_tx_hash`/`evm_raw_tx` 写入与按 `request_id` 去重（[tests/sn_bns_store.rs](../src/components/bns-client/tests/sn_bns_store.rs)：evm 元数据 round-trip；同 request_id 第二次 `put` 走 `ON CONFLICT(request_id) DO UPDATE` 原地 upsert，`created_at` 保留证明非新增行）。

运行：`cargo test -p bns-client`。

---

## 3. SN-Auth 单元测试（`cyfs-sn::sn_auth`）

现状：[sn_auth.rs:2385](../src/components/cyfs-sn/src/sn_auth.rs:2385) 的 `mod tests` 已补全至 17 例（4 例基线 + 13 例新增，覆盖 §3.1–§3.4 DB 层，全绿）。本节按设计文档目标补全 DB 层与（阶段二落地后的）RPC 层。

### 3.1 账号与凭证（DB 层）
- [x] 激活码：生成 32 位、charset 受限且唯一、`check_active_code`（存在且未用 / 未知 → false）、注册后事务内置 `used=1`、二次使用被拒（`test_activation_code_generation_and_single_use`）。
- [x] `register_user_v2` 事务性：`users`+`user_auth_v2`+`zone_info`+激活码标记一致写入（`test_register_user_v2_writes_consistent_rows`）；命名锁下同激活码并发注册只成功一个（`test_register_user_v2_concurrent_single_success`）。
- [x] 密码：PBKDF2-sha256-100000、16B salt(hex)、32B hash(hex)；`verify_password` 正确/错误；同密码不同 salt → 不同 hash；不存明文；不支持算法被拒（`test_password_pbkdf2_hash_and_verify`，调用 `sn_v2_auth::{hash_password,verify_password}`）。
- [x] 用户状态机：`set_user_state` active/suspended/deleted/banned 落库；置非 active 时自动撤销该用户 session、active 不撤销（`test_set_user_state_revokes_sessions`，[sn_auth.rs:1378](../src/components/cyfs-sn/src/sn_auth.rs:1378)）。

### 3.2 session（account_sessions）
- [x] `create_account_session` / `get_account_session`（未知 → None）/ `revoke_account_session` / `revoke_user_sessions`（只计活跃、跨用户隔离、幂等返回 0）语义（`test_account_session_lifecycle_and_counts`）。
- [x] **阶段二接线后**：签发路径写 session（`auth.rs build_auth_success_response` → `create_account_session`）、校验路径查 session 状态（`sn_authority::validate_account_session`）、`auth.logout` 撤销生效（`test_sn_v2_api` 内 logout 后旧 access token → `SNV2:1007`）、冻结用户后旧 token 立即失效（`test_sn_v2_phase_two_security_regressions`：`set_user_state(Suspended)` → `auth.me` → `SNV2:1007`）。
- [x] token：`sub=username`、`aud=sn-v2`/`sn-v2-refresh`、access 1h / refresh 24h 过期、`jti` 存在（`test_sn_v2_phase_two_security_regressions` 解码 access/refresh JWT 断言 sub/aud/jti/exp 间隔 ~23h）。> 注：`kid` 仍以 `jti` 承载会话标识，未单列 claim。

### 3.3 user_domain + PKX proof
- [x] `canonical_user_domain`：去 `*.` 前缀、小写、去尾点、空/仅点 → None（`test_user_domain_helpers_are_stable`）。
- [x] 冲突检查：同域名 / 祖先域名 / 子域名被不同用户历史绑定 → `Conflict`，本人子域名允许（`test_domain_conflict_rules`）。
- [x] PKX 状态机：`create_pkx_binding` 写 `pending_pkx` 并返回固定 `pkx_record_name`/`pkx`（重入幂等）；`verify_pkx_binding` TXT 匹配 → `active`；`unbind_user_domain` → `revoked`；history 保留（`test_pkx_binding_state_transitions_and_history`）。
- [x] `txt_matches_pkx` / `pkx_record_name` / `pkx_value` helper 的稳定性（同输入恒等，无 nonce/exp；空源被拒）（`test_user_domain_helpers_are_stable`）。
- [x] `get_user_by_domain`：active binding 最长匹配 + legacy `users.user_domain` 回退（`test_get_user_by_domain_longest_match_and_legacy_fallback`）。
- [x] **绕过风险回归**：`zone.bind_config` 传未经 PKX 校验的 `user_domain` → `SNV2:1015 invalid_domain`（`zone.rs ensure_verified_user_domain`；`test_sn_v2_phase_two_security_regressions`）；PKX RPC handler + DNS TXT 端到端可达（`test_sn_v2_api`：`domain.begin_verify` → `domain.verify`(txt_records) → `zone.bind_config` 成功）。> 注：`register_user_with_owner_key` 直接置 `active` 的 legacy DB 路径未经 RPC 暴露，留观察。

### 3.4 zone_info
- [x] `get_zone_info`（缺行从 `users` backfill、未知用户返默认）/ `update_zone_info`（patch 只改传入字段、users 缓存同步）（`test_zone_info_patch_only_changes_given_fields` / `test_get_zone_info_backfills_from_users`）。
- [x] `update_zone_relay_sn`：按 zone/bns_name/username 命中或缺行插入写 `relay_sn`；空参数 → `InvalidInput`（`test_update_zone_relay_sn_paths`）。
- [x] **self_cert 权限**：裸 access token（无 `device_did`）置 `self_cert=true` → `SNV2:1013 device_permission_denied`（`user.rs set_self_cert` → `ensure_owned_device`；`test_sn_v2_phase_two_security_regressions`）；正向路径经受信 device（`dns.add_record has_cert` / 拥有的 device）驱动 `update_user_self_cert`（`test_sn_v2_api` 内 `query.resolve_hostname` 命中 `self_cert=true`）。> 注：当前 gate 为「拥有该 device」，ACME 成功/证书校验驱动与审计事件仍待补。

### 3.5 RPC 层（`sn_authority` 已落地）
> 端到端 RPC 覆盖：[sn_server.rs](../src/components/cyfs-sn/src/sn_server.rs) 内 `test_sn_v2_api`（进程内 HTTP + kRPC 客户端，全绿）。
- [x] `auth.register/login/refresh/logout/me`、`user.bind_owner_key/get_owner_key/get_profile`、`zone.get/bind_config`、`dns.add_record/remove_record`、`admin.clear_state_by_active_code`、`domain.begin_verify/verify`、`device.register/list`、`did.set/get_document`、`query.*` 经 `handle_namespaced_rpc_call` 路由并断言 envelope/错误码（`test_sn_v2_api`）。
- [x] 统一鉴权上下文：`AuthContext::{Owner,Controller,Device,SnUser}`（[sn_authority.rs](../src/components/cyfs-sn/src/sn_authority.rs)）产出与边界——SN access token 跨用户 → `CrossUserAccessDenied`；裸 token 不能置 self_cert/未校验域名（`test_sn_v2_phase_two_security_regressions`）。
- [ ] 注册流程与 `sn_bns_controller` 串联：`request_id` 幂等、"BNS name 已存在但本地未完成"的恢复流程。> 依赖 §2.4 迁移项（controller 切 EVM 自动签名）落地，见 §5.2 SN 业务级集成。

运行：`cargo test -p cyfs-sn sn_auth`（DB 层用 `tempfile` SQLite 夹具 `new_test_db`）。

---

## 4. SN-DeviceInfo 单元测试（`cyfs-sn::sn_device_info`）

现状：组件已实现（`SnDeviceInfoDB` trait + 4 表 + 11 接口，[sn_device_info.rs](../src/components/cyfs-sn/src/sn_device_info.rs)）。
> 已实现 `mod tests`（[sn_device_info.rs](../src/components/cyfs-sn/src/sn_device_info.rs) 内 `#[cfg(test)] mod tests`，23 例全绿；`tempfile` SQLite 夹具 `temp_db` + 原始 DB 内省 helper `event_types`/`scalar_i64`，覆盖 §4.1–§4.5）。

### 4.1 索引与重绑（device_index）
- [x] `upsert_device_index`：新 DID 创建；同 DID 同 `(zone,device_name)` 更新 role；同 DID 但 `(zone,device_name)` 变化 → `Conflict`（要求 rebind）；新 `(zone,device_name)` 已被他 DID 占用 → `Conflict`（`test_upsert_device_index_create_update_and_conflicts`）。
- [x] `rebind_device_index`：DID 不存在 → `NotFound`；目标 `(zone,device_name)` 冲突 → `Conflict`；成功保留 runtime/endpoint + 记 `rebound` 事件（`test_rebind_not_found_conflict_and_preserves_runtime`）。
- [x] `remove_device_index`：删 runtime/endpoint/index，保留 `device_state_events`（`test_remove_device_index_keeps_events`）。
- [x] 唯一约束：`did` 唯一、`(zone,device_name)` 唯一（`test_unique_constraints`）。

### 4.2 运行态写入（update_device_state）
- [x] DID 不存在 → `NotFound`（`test_update_device_state_not_found`）。
- [x] **stale 拒绝**：`report_seq` 明显旧于当前 → 拒绝 + `report_rejected` 事件 + `StaleReport` 错误语义（`test_stale_report_rejected_records_event`）。
- [x] **blocked 保护**：blocked 设备普通上报不改回 online + `report_rejected`；仅 `unblock_device` 可恢复（`test_blocked_device_rejects_report_only_unblock_recovers`）。
- [x] `expires_at = now + ttl`；endpoint upsert；首次上线记 `online`、endpoint 变化记 `endpoint_changed`（`test_update_device_state_expiry_and_events`）。
- [x] `from_ip`（上游观察）与设备自报 `reported_ip`/`reported_ips` 分开保存（`test_from_ip_and_reported_ip_stored_separately`）。

### 4.3 IP / endpoint 规则
- [x] 公网 IP 过滤（`is_public_ipv4`/`is_public_ipv6`）：排除 RFC1918、loopback、link-local、multicast、unspecified；ULA/link-local/loopback IPv6 排除；公网 v4/v6 进 `public_ips`（`test_is_public_ipv4_rules` / `test_is_public_ipv6_rules`）。
- [x] wan/lan 分类（`classify_ips`）：私网进 `private_ips` 不进 DNS 视图；`is_wan_device` 计算（`test_classify_ips_wan_lan`）。
- [x] endpoint 排序（`endpoint_sort_key`）：active 优先于 stale/failed/disabled；priority 小优先；public < relay < private < loopback < unknown（`test_endpoint_sort_key_ordering`）。
- [x] 过期 / disabled endpoint 不进 active 列表；disabled 仅显式 enable/replace 恢复（`test_expired_and_disabled_endpoints_excluded`）。

### 4.4 查询视图与状态迁移
- [x] `get_device_state` / `get_device_state_by_name`：过期时先落库 `stale` 再返回视图，不返回过期/disabled endpoint（`test_get_device_state_marks_stale_on_expiry`）。
- [x] `list_zone_devices`：state 过滤 + 分页（`test_list_zone_devices_filter_and_pagination`）。
- [x] `mark_device_offline`：state→offline、active endpoint→stale、记 `offline`（`test_mark_device_offline_event_and_endpoints`）。
- [x] `block_device`/`unblock_device`：block→blocked+禁用 endpoint；unblock→offline 等下次上报；事件正确（`test_block_unblock_events_and_endpoints`）。
- [x] `expire_devices`：`expires_at<now` 且 `online` → `stale`，过期 endpoint→stale，批量大小生效（`test_expire_devices_batch_size`）。

### 4.5 错误语义
- [x] `InvalidInput`（空 DID/zone/device_name、非法 IP/endpoint/TTL/枚举）、`NotFound`、`Conflict`、`StaleReport`、`Blocked`、`DBError`(=StorageError) 各有用例（`test_invalid_input_errors` / `test_db_error_on_closed_pool`，其余错误码散见 §4.1–§4.2 用例）。

### 4.6 阶段二（落地后补）
- [x] **remote 模式**：本地 service 与 remote client 暴露**同一组接口**，同一批用例参数化跑两遍（local / remote）结果一致（[tests/sn_device_info_remote.rs](../src/components/cyfs-sn/tests/sn_device_info_remote.rs)：`local_and_remote_clients_agree_on_same_batch` 用经真实 S2S 编解码的 loopback —— 序列化 → `SnDeviceInfoDbRpcHandler::handle_rpc_call` → envelope 反序列化 —— 与直连 DB 对同一批 index/rebind/上报/stale/block/expire/错误码用例结果逐条相等；`production_remote_wrapper_exposes_same_trait` 钉死 `RemoteSnDeviceInfoDB` in-process 包装）。> 发现：真 KRPC 传输下 `SnDeviceInfoDbRpcEnvelope::into_result` 无法还原 `Ok(None)`（`success(None)` 序列化成 `result:null` → 反序列化丢失 `Some(None)` → 误判 "missing result"），导致远端查不存在设备返回 `RemoteError` 而非 `Ok(None)`——loopback 按 `null→None` 还原回避；生产 client 需修。健康检查接口/连接超时仍待加。
- [ ] 生产调用方驱动（`sync_device_online_state` 真填 `from_ip`/`nat_type`/`report_seq`，`device_role` 不再硬编码）后的端到端字段流。

运行：`cargo test -p cyfs-sn sn_device_info`（DB 层）+ `cargo test -p cyfs-sn --test sn_device_info_remote`（local/remote 一致性）。

---

## 5. DV 集成测试环境（端到端）

目标：在一个开发验证（DV）环境里跑通真链路
`BNS(合约) <-> BNS-Indexer <-> BNS-Server <-> BNS-Client <-> BNS-Controller`，
覆盖设计 §9 标注"未开始"的端到端项：`alloy-node-bindings` 拉起 anvil → 部署 `Bns.sol` → Controller Client 提交 → `sync_once` 同步 → 读 API 命中。

### 5.1 一键启动环境（新建 / resume）

> 已实现：[scripts/dv-up.sh](../src/apps/bns/scripts/dv-up.sh) + [scripts/dv-down.sh](../src/apps/bns/scripts/dv-down.sh)，配套开发用守护/驱动二进制 [bns-server/src/bin/bns_dv.rs](../src/components/bns-server/src/bin/bns_dv.rs)（`bns-dv serve` = indexer 轮询 `sync_once` + BNS-Server 读投影/写转发，共享一份 SQLite，WAL 并发）。已验证 `--fresh → resume` 全流程（合约地址与 indexer 游标延续，链状态不复位）。

新增脚本 `src/apps/bns/scripts/dv-up.sh`（编排现有 [anvil.sh](../src/apps/bns/scripts/anvil.sh) + [deploy.sh](../src/apps/bns/scripts/deploy.sh)），语义：

```
dv-up.sh [--fresh | --resume] [--keep-running]
```

- **`--fresh`（新环境）**：删除 `var/anvil-state.json` 与 `deployments/anvil.local.json` 及 indexer SQLite，重新：
  1. 起 anvil（确定性助记词、chainId=31337、block-time=1、`--disable-code-size-limit`、`--state var/anvil-state.json` 持久化）。
  2. `deploy.sh` 部署 `Bns.sol` → 写 `deployments/anvil.local.json`（合约地址）。
  3. 起 BNS-Indexer + BNS-Server（同一个 `bns-dv serve` 进程：indexer 轮询 `sync_once`，source=`evm:anvil-local:31337:{contract}`，游标从 0；server 读查投影、写转发 `eth_sendRawTransaction`，监听内部端口）。
  4. 生成 `dv-env.json`（rpc endpoint / chainId / 合约地址 / server url / indexer db 路径 / 部署者私钥来源 / 部署块高 / PID 文件），供测试脚本与 `SNServerConfig.bns_evm` 读取。
- **`--resume`（恢复环境）**：复用已存在的 `anvil-state.json`（anvil `--state` 自动加载）+ 已部署合约地址 + indexer 已有游标继续同步。校验：链上 chainId/合约地址与 `dv-env.json` 一致，否则报错要求 `--fresh`。
- **`--keep-running`**：前台保活供手工调试；否则各服务以 PID 文件后台托管，配套 `dv-down.sh` 清理。
- **健康门控**：脚本在每步后轮询就绪（anvil `eth_chainId`、合约 `eth_getCode != 0x`、indexer 游标 ≥ 部署块、server 读接口返回）才进入下一步，全部就绪打印 `dv-env.json` 路径。

> 说明：anvil `--state` 已天然支持持久化/恢复；脚本的职责是把"合约地址 + indexer 游标 + server 配置"这三份派生状态与 anvil state 对齐，使 resume 不产生 source 漂移。

### 5.2 运行测试脚本

两种驱动方式，二选一或都做：

**(A) Rust e2e（推荐，进 CI 可控）**——已实现 [tests/e2e_anvil.rs](../src/components/bns-client/tests/e2e_anvil.rs)（6 例，装有 Foundry 时全绿）。在测试进程内用 `std::process` 拉起 `anvil`（依赖无关，等价于 `alloy-node-bindings`）+ `forge create` 部署 `Bns.sol`（不依赖 5.1 脚本，自包含），`#[ignore]` 默认跳过、`--ignored` 显式运行，`anvil`/`forge` 缺失时优雅跳过。覆盖：
- [x] **写读闭环**：Controller Client 注册 name → `publishDocument`(inline) → `sync_once` → 读投影命中，且投影 == 链上 `eth_call` 权威态（`e2e_write_read_closed_loop_matches_onchain_truth`）。
- [x] **签名边界（真 EVM）**：托管私钥签名时 `msg.sender` == 私钥地址 → 通过；构造 `CallAuthority.actor` != signer 的 TX → 链上 revert（receipt status 0 + `eth_call` 模拟回传错误），投影不变（`e2e_signing_boundary_actor_mismatch_reverts_onchain`）。
- [x] **selector / packing / event topic**：真 EVM 接受 client 编码 calldata 并 emit 事件，indexer 解码后投影与 §1.7/§2.1 一致（由写读闭环用例隐式钉死）。
- [x] **nonce / 重放**：连续两笔写 nonce 递增；重放同一已上链 raw TX → 链上拒绝；chainId 不匹配的 TX → 拒绝（`e2e_nonce_replay_and_chain_id_rejection`）。
- [x] **confirmations / 同步推进**：未达 confirmations 不投影，挖够块后投影命中；游标单调推进（`e2e_confirmations_gate_and_cursor_advance`）。
- [x] **重部署从 0 重放**（设计 §9 未测项）：换合约地址（新 source）→ indexer 从 `start_block` 重放 → 投影与链上等价（`e2e_redeploy_uses_isolated_source_and_replays_from_zero`）。
- [x] **controller 策略真链路**：controller 只能 publish 授权 docType，越权 docType → 链上 revert（`e2e_controller_policy_scopes_doc_types_on_chain`）。

**(B) 脚本化冒烟**——已实现 [scripts/dv-smoke.sh](../src/apps/bns/scripts/dv-smoke.sh)：读 5.1 的 `dv-env.json`，用 `bns-dv smoke` 经 BNS-Server 跑
注册 → 发布(inline) → 等待 indexer 投影 → 经 server 读命中 的最小路径，打印每步耗时与结果，作为"环境是否健康"的快速门禁（对应已有 [Smoke.s.sol](../src/apps/bns/script/Smoke.s.sol) 的链上版，本脚本是跨全分层版）。默认 name 带时间戳，便于 `--resume` 后重复冒烟并验证游标增量投影（不从 0 重放）。

**SN 业务级集成（阶段二，待 `sn_bns_controller` 切 EVM 后）**：
- [ ] `sn_auth.register` → `sn_bns_controller` 提交 BNS 注册 TX（owner_config + controller policy）→ indexer 投影 → `sn_resolver` 读到 BNS 文档，串成幂等流程（`request_id`），验证一致性要求（无"本地成功 BNS 未创建"窗口）。

### 5.3 集成测试通过标准
- [x] 5.2(A) 全部 `--ignored` 用例在装有 Foundry 的机器上绿（`cargo test -p bns-client --test e2e_anvil -- --ignored`，6/6 通过）。
- [x] `dv-up.sh --fresh` 后 `dv-smoke.sh` 通过；`dv-down.sh` 再 `dv-up.sh --resume` 后 smoke 仍通过且 indexer 游标延续（不从 0 重放，合约地址与链状态续用）。
- 集成层只断言"跨层拼接 + 真 EVM 行为"，不重复 §1–§4 的分支覆盖。

---

## 6. 执行与 CI 编排

建议分三档：

1. **快测（每次提交 / PR 必跑，无外部依赖）**：
   `forge test`（§1）+ `cargo test -p bns-evm -p bns-indexer -p bns-server -p bns-client`（§2）+ `cargo test -p cyfs-sn sn_auth sn_device_info`（§3/§4）。
2. **集成（nightly / 手动 / 带 Foundry 的 runner）**：
   `cargo test -p bns-client --test e2e_anvil -- --ignored`（§5.2A）+ `dv-up.sh --fresh && dv-smoke.sh && dv-down.sh && dv-up.sh --resume && dv-smoke.sh`（§5.1/5.2B）。
3. **覆盖率 / fuzz（周期性）**：合约 fuzz/invariant（§1.8）、Rust `cargo llvm-cov` 报告。

**门禁原则**：档 1 必须始终绿且无活节点依赖；档 2 缺 Foundry 时跳过而非失败；任何新增写函数 / 新事件 / 新 docType 必须同时补 §1.7 事件断言 + §2.1 解码 + 至少一条 §5 端到端路径。

---

## 7. 缺口与依赖（与设计 TODO 对齐）

下列测试项依赖设计文档中"阶段二/待实现"落地后才能转正，当前先建桩或标 `#[ignore]`：

- `sn_authority` 统一鉴权上下文（SN-Auth §3.5）——未实现，RPC 层鉴权用例先挂起。
- `sn_bns_controller` 从 `CallAuthority` 切 EVM TX（设计 §4/§7）——切换后补 §2.4 迁移项 + §5.2 SN 业务级集成。
- indexer 常驻循环 / `eth_subscribe` / reorg 回滚（设计 §5）——当前只测 `sync_once` 轮询；reorg 用例待 reorg 检测落地。
- `sn_device_info` remote 模式 + 健康检查（SN-DeviceInfo §4.6）——补 local/remote 参数化双跑。
- 合约 EIP-170 拆分（设计 §2/§10）——拆分后需补"facet/module 边界"合约测试。
