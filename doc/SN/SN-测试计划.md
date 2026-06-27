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
- [ ] `releaseName` 不能破坏 active semantic owner 图（对应 indexer 侧 `release_name_rejects_breaking_active_semantic_owner_graph`）。> 注：当前合约 `releaseName` 不做 owner-graph 校验，此约束在 indexer 侧实现，留待 §2.2。
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
现状：[tests/abi_tx.rs](../src/components/bns-evm/tests/abi_tx.rs) 已有 round-trip 用例。补全：

- [ ] **calldata round-trip**（已有）：扩到每个写函数 `sol!` 绑定的 encode→decode 一致；`EvmCallAuthority` / `EvmMutationGuard` / `EvmRegisterOptions` 等结构 packing 一致。
- [ ] **chainAccountPrincipal 编码**：地址按 20 字节、bnsName 按规范编码（对应 client 侧 `evm_register_call_encodes_chain_account_principal_as_address_bytes`）。
- [ ] **TX 构造**：`build_tx(call, nonce, chainId, to, gas)` 产出 EIP-1559 字段正确（maxFeePerGas/maxPriorityFee/gasLimit/nonce/chainId/to/value=0）。
- [ ] **签名与 signer 恢复**：`sign(tx, key)` → 独立解码 raw TX → 恢复 signer 地址 == key 地址（防"签了但 sender 不对"）。
- [ ] **event 解码**：用 §1.7 钉死的事件字节，验证 `decode_bns_event` 解出的 `ProtocolEvent` + 专用事件字段一致。
- [ ] **call 解码**：`decode_bns_call` 从 calldata 还原入参（indexer 补全 authority key / controller rule 时依赖）。
- [ ] **边界/错误**：截断 calldata、未知 selector、错误 chainId → 明确错误而非 panic。

运行：`cargo test -p bns-evm`，无需节点。

### 2.2 `bns-indexer`（事件索引器）
现状：[tests/sync_config.rs](../src/components/bns-indexer/tests/sync_config.rs)、[tests/evm_projection.rs](../src/components/bns-indexer/tests/evm_projection.rs)、[tests/centralized_registry.rs](../src/components/bns-indexer/tests/centralized_registry.rs)。

**投影正确性（projection_for_record，[sync.rs:280](../src/components/bns-indexer/src/sync.rs:280)）**：
- [ ] 每类事件 → SQLite 投影（names / documents / authority set+keys / controller policy / alias / checkpoint）字段正确（已有 evm_projection 基线，逐 docType 补全）。
- [ ] **混合投影策略**：事件只定位"哪个 name/doc 变了"，随后 `eth_call`（`queryNameState`/`getDocumentVersion`/`getAuthoritySet`/`getAlias`/`latestCheckpoint`）拉当前权威态——用 **mock eth_call** 注入返回，验证投影=最新快照而非逐条回放。
- [ ] authority key / controller rule 通过 `decode_bns_call`（按 tx hash 缓存）补全事件未携带入参。

**同步器（sync_once，[sync.rs:164](../src/components/bns-indexer/src/sync.rs:164)）**，用 mock JSON-RPC：
- [ ] chain_id 校验：链上 chainId 与配置不符 → 拒绝同步。
- [ ] confirmations 回退：最新块按 `confirmations` 回退后才同步。
- [ ] `max_block_span` 分片：大区间被切成多次 `eth_getLogs`。
- [ ] 游标推进：`bns_indexer_cursors` 的 last-synced-block 单调推进；重复调用幂等（不重投影已处理日志）。
- [ ] **source 隔离**（已有 sync_config）：`source_id = evm:{network}:{chainId}:{contract}`，换合约地址即换 source。
- [ ] **合约重部署从 0 重放一致性**（设计 §9 待测项）：旧 source 游标不串扰，新 source 从 `start_block` 重放后投影等价于一次性同步。
- [ ] 事件+投影同一 `store.transact` 原子落库：mock 在写投影中段失败 → 整批回滚，游标不前进。

**EventLog / Checkpoint**：
- [ ] `EventLogRecord` 由 `seq`/`previousLogRoot`/`logRoot` 派生写入 `bns_events`（`put_event_record`）。
- [ ] `LogCheckpointPublished` → `eth_call latestCheckpoint` → `put_checkpoint` 的 `ON CONFLICT(last_seq)` 覆盖。

**registry 回归**：保留 `centralized_registry.rs` 全部用例为回归（状态机下线前的语义基线）。

运行：`cargo test -p bns-indexer`，mock RPC 无需活节点。
> 建议：引入一个 `MockEthRpc`（按方法名返回预置 JSON）测试夹具，集中给 indexer/server 复用。

### 2.3 `bns-server`（标准智能合约处理器）
现状：逻辑在 [bns-server/src/lib.rs](../src/components/bns-server/src/lib.rs)（`BnsContractServerHandler` / `submit_raw_tx` / `BnsContractServerRpcHandler`），当前**无 tests 目录**，需新建 `tests/`。

- [ ] **写路径 `tx.submit_raw`**：合法 raw TX hex → 解码 → 转发 `eth_sendRawTransaction`（mock RPC 断言收到的 raw 字节一致），返回 tx hash；非法 hex / 空 → 明确错误。
- [ ] **不解释 payload / 不鉴权**：server 不解析 calldata、不校验签名（鉴权在合约 `msg.sender`）——构造一个签名无效的 raw TX，server 仍原样转发（拒绝在链上发生）。
- [ ] **旧写 RPC 禁用**：`name.register` / `document.publish` / `controller.set_policy` 等旧 `CallAuthority` 写方法返回 `UNSUPPORTED_OPERATION`（`unsupported_call`，[lib.rs:84](../src/components/bns-server/src/lib.rs:84)）。
- [ ] **读路径**：`query_name_state` / `resolve_owner` / `resolve_document` / `get_authority_*` / `list_events` / `latest_checkpoint` 后端查 SQLite 投影，envelope 包装正确（`rpc_envelope_response`）。
- [ ] **RPC 路由**：`METHOD_SUBMIT_RAW_TX` 与别名 `submit_raw_tx` 都命中；未知 method → 错误码正确。

运行：`cargo test -p bns-server`，用内存/临时 SQLite 投影 + mock eth RPC。

### 2.4 `bns-client`（薄封装）与 `bns-controller`（前置签名）
现状：[tests/rpc_and_controller.rs](../src/components/bns-client/tests/rpc_and_controller.rs) 已较充分（in-process registry）。补全围绕 EVM 迁移：

**Standard Client（无私钥）**：
- [ ] `build_calldata` / `build_unsigned_tx`（已有 `evm_standard_client_builds_unsigned_contract_tx`）：unsigned TX 字段供外部签名。
- [ ] 入参为外部已签 raw TX → 经 server `submit_raw` 提交（与 §2.3 对接，可用 mock server）。
- [ ] 读路径转发索引器查询。

**Controller Client（托管私钥，自动签名）**：
- [ ] 自动 nonce → chainId/to/gas → ABI 编码 → 签名 → 提交全链（已有 `static_evm_key_manager_signs_tx_for_authority_context`）。
- [ ] **控制策略边界**（已有多例，保持）：高风险 docType scope 拒绝、controller 不能写 owner-scoped 文档、docType scope denial 映射、bootstrap 安装 controller policy。
- [ ] **DNS TXT 幂等**（已有 `sn_controller_upserts_dns_txt_with_idempotency` / `removes_last_dns_txt_record_by_publishing_empty_rrset`）：保持。
- [ ] **stale guard 错误码透传**（已有 `bns_client_preserves_stale_guard_error_codes`）：合约 guard revert → client 保留原始错误码。
- [ ] **EVM 模式多步 zone bind**（已有 `evm_mode_rejects_multi_step_zone_bind_without_submission`）：保持。
- [ ] **nonce 管理增强**（设计 §4 待实现 → 待测）：失败回退重查、并发冲突、可选等待回执确认上链。
- [ ] **迁移项**（设计 §4 TODO → 落地后补）：`sn_bns_controller.rs` 从手工拼 `CallAuthority` 切到"构造 op → Controller 自动签名"后，验证不再产生 `CallAuthority` 写 RPC。
- [ ] **幂等元数据**：`SnBnsWriteRequestStore` 的 `evm_chain_id`/`evm_nonce`/`evm_tx_hash`/`evm_raw_tx` 写入与去重（同 request_id 不重复提交）。

运行：`cargo test -p bns-client`。

---

## 3. SN-Auth 单元测试（`cyfs-sn::sn_auth`）

现状：[sn_auth.rs:2385](../src/components/cyfs-sn/src/sn_auth.rs:2385) 的 `mod tests` 已有 4 例（激活码+V2、PKX 冲突、zone_info patch+session 撤销、clear_state）。本节按设计文档目标补全 DB 层与（阶段二落地后的）RPC 层。

### 3.1 账号与凭证（DB 层）
- [ ] 激活码：生成 32 位、`check_active_code`（存在且未用）、注册后事务内置 `used=1`、二次使用被拒。
- [ ] `register_user_v2` 事务性（已有基线）：`users`+`user_auth_v2`+`zone_info`+激活码标记一致写入；命名锁下并发同名注册只成功一个。
- [ ] 密码：PBKDF2-sha256-100000、16B salt、hash hex；`verify_password` 正确/错误；服务端不存明文。
- [ ] 用户状态机：`set_user_state` active/suspended/deleted/banned；置非 active 时自动撤销该用户 session（[sn_auth.rs:1378](../src/components/cyfs-sn/src/sn_auth.rs:1378)）。

### 3.2 session（account_sessions）
- [ ] `create_account_session` / `get_account_session` / `revoke_account_session` / `revoke_user_sessions` 语义（DB 层已有）。
- [ ] **阶段二接线后**：签发路径写 session、校验路径查 session 状态、`auth.logout` 撤销生效、冻结用户后旧 token 立即失效（覆盖设计指出的"建好未接线死代码"）。
- [ ] token：`sub=username`、`aud=sn-v2`/`sn-v2-refresh`、access 1h / refresh 24h 过期；阶段二补 `kid` / `jti`。

### 3.3 user_domain + PKX proof
- [ ] `canonical_user_domain`：去 `*.` 前缀、小写、去尾点。
- [ ] 冲突检查（已有基线）：同域名 / 祖先域名 / 子域名被不同用户历史绑定 → 拒绝。
- [ ] PKX 状态机：`create_pkx_binding` 写 `pending_pkx` 并返回固定 `pkx_record_name`/`pkx`；`verify_pkx_binding` TXT 匹配 → `active`；`unbind_user_domain` → `revoked`；history 保留。
- [ ] `txt_matches_pkx` / `pkx_record_name` / `pkx_value` helper 的稳定性（同输入恒等，无 nonce/exp）。
- [ ] `get_user_by_domain`：active binding 最长匹配 + legacy `users.user_domain` 回退。
- [ ] **绕过风险回归（阶段二修复后转正）**：`zone.bind_config` / `register_user_with_owner_key` 不再能无 proof 置 `active`；PKX RPC handler + DNS TXT 查询接线后端到端可达。

### 3.4 zone_info
- [ ] `get_zone_info` / `update_zone_info`（patch 语义，只改传入字段）/ 从 `users` backfill。
- [ ] `update_zone_relay_sn` 只允许 relay 管理路径写 `relay_sn`。
- [ ] **self_cert 权限（阶段二修复后）**：裸 access token 不能置 `self_cert=true`；仅 ACME 成功 / 证书校验 / 受信 device 上报驱动；来源与审计事件记录。

### 3.5 RPC 层（阶段二 `sn_authority` 落地后）
- [ ] `auth.register/login/refresh/logout/me`、`user.bind_owner_key/get_owner_key/get_profile`、`zone.get/bind_config`、`dns.add_record/remove_record/list_records`、`admin.clear_state_by_active_code`。
- [ ] 统一鉴权上下文：`Owner(name)` / `Controller(name,scope)` / `Device(zone,device,did)` / `SnUser(username)` 的产出与边界（SN access token ≠ BNS owner）。
- [ ] 注册流程与 `sn_bns_controller` 串联：`request_id` 幂等、"BNS name 已存在但本地未完成"的恢复流程、绝不出现"本地成功但 BNS 未创建却误认有 owner 权"的状态。

运行：`cargo test -p cyfs-sn sn_auth`（DB 层用 `tempfile` SQLite 夹具 `new_test_db`）。

---

## 4. SN-DeviceInfo 单元测试（`cyfs-sn::sn_device_info`）

现状：组件已实现（`SnDeviceInfoDB` trait + 4 表 + 11 接口，[sn_device_info.rs](../src/components/cyfs-sn/src/sn_device_info.rs)），**尚无独立测试**，需新建 `mod tests`（用临时 SQLite）。

### 4.1 索引与重绑（device_index）
- [ ] `upsert_device_index`：新 DID 创建；同 DID 同 `(zone,device_name)` 更新 role；同 DID 但 `(zone,device_name)` 变化 → `Conflict`（要求 rebind）；新 `(zone,device_name)` 已被他 DID 占用 → `Conflict`。
- [ ] `rebind_device_index`：DID 不存在 → `NotFound`；目标 `(zone,device_name)` 冲突 → `Conflict`；成功保留 runtime/endpoint + 记 `rebound` 事件。
- [ ] `remove_device_index`：删 runtime/endpoint/index，保留 `device_state_events`。
- [ ] 唯一约束：`did` 唯一、`(zone,device_name)` 唯一。

### 4.2 运行态写入（update_device_state）
- [ ] DID 不存在 → `NotFound`。
- [ ] **stale 拒绝**：`report_seq` 明显旧于当前 → 拒绝 + `report_rejected` 事件 + `StaleReport` 错误语义。
- [ ] **blocked 保护**：blocked 设备普通上报不改回 online + `report_rejected`；仅 `unblock_device` 可恢复。
- [ ] `expires_at = now + ttl`；endpoint upsert；首次上线记 `online`、endpoint 变化记 `endpoint_changed`。
- [ ] `from_ip`（上游观察）与设备自报 `reported_ip`/`reported_ips` 分开保存。

### 4.3 IP / endpoint 规则
- [ ] 公网 IP 过滤（`is_public_ipv4`/`is_public_ipv6`）：排除 RFC1918、loopback、link-local、multicast、unspecified；ULA/link-local/loopback IPv6 排除；公网 v4/v6 进 `public_ips`。
- [ ] wan/lan 分类（`classify_ips`）：私网进 `private_ips` 不进 DNS 视图；`is_wan_device` 计算。
- [ ] endpoint 排序（`endpoint_sort_key`）：active 优先于 stale/failed/disabled；priority 小优先；public < relay < private < loopback < unknown。
- [ ] 过期 / disabled endpoint 不进 active 列表；disabled 仅显式 enable/replace 恢复。

### 4.4 查询视图与状态迁移
- [ ] `get_device_state` / `get_device_state_by_name`：过期时先落库 `stale` 再返回视图，不返回过期/disabled endpoint。
- [ ] `list_zone_devices`：state 过滤 + 分页。
- [ ] `mark_device_offline`：state→offline、active endpoint→stale、记 `offline`。
- [ ] `block_device`/`unblock_device`：block→blocked+禁用 endpoint；unblock→offline 等下次上报；事件正确。
- [ ] `expire_devices`：`expires_at<now` 且 `online` → `stale`，过期 endpoint→stale，批量大小生效。

### 4.5 错误语义
- [ ] `InvalidInput`（空 DID/zone/device_name、非法 IP/endpoint/TTL/枚举）、`NotFound`、`Conflict`、`StaleReport`、`Blocked`、`DBError`(=StorageError) 各有用例。

### 4.6 阶段二（落地后补）
- [ ] **remote 模式**：本地 service 与 remote client 暴露**同一组接口**，同一批用例参数化跑两遍（local / remote）结果一致；健康检查接口；连接/请求超时。
- [ ] 生产调用方驱动（`sync_device_online_state` 真填 `from_ip`/`nat_type`/`report_seq`，`device_role` 不再硬编码）后的端到端字段流。

运行：`cargo test -p cyfs-sn sn_device_info`。

---

## 5. DV 集成测试环境（端到端）

目标：在一个开发验证（DV）环境里跑通真链路
`BNS(合约) <-> BNS-Indexer <-> BNS-Server <-> BNS-Client <-> BNS-Controller`，
覆盖设计 §9 标注"未开始"的端到端项：`alloy-node-bindings` 拉起 anvil → 部署 `Bns.sol` → Controller Client 提交 → `sync_once` 同步 → 读 API 命中。

### 5.1 一键启动环境（新建 / resume）

新增脚本 `src/apps/bns/scripts/dv-up.sh`（编排现有 [anvil.sh](../src/apps/bns/scripts/anvil.sh) + [deploy.sh](../src/apps/bns/scripts/deploy.sh)），语义：

```
dv-up.sh [--fresh | --resume] [--keep-running]
```

- **`--fresh`（新环境）**：删除 `var/anvil-state.json` 与 `deployments/anvil.local.json` 及 indexer SQLite，重新：
  1. 起 anvil（确定性助记词、chainId=31337、block-time=1、`--disable-code-size-limit`、`--state var/anvil-state.json` 持久化）。
  2. `deploy.sh` 部署 `Bns.sol` → 写 `deployments/anvil.local.json`（合约地址）。
  3. 起 BNS-Indexer（轮询 `sync_once` 调度器，source=`evm:anvil:31337:{contract}`，游标从 0）。
  4. 起 BNS-Server（读查投影、写转发 `eth_sendRawTransaction`），监听内部端口。
  5. 生成 `dv-env.json`（rpc endpoint / chainId / 合约地址 / server 端口 / indexer db 路径 / 托管私钥来源 / 部署块高），供测试脚本与 `SNServerConfig.bns_evm` 读取。
- **`--resume`（恢复环境）**：复用已存在的 `anvil-state.json`（anvil `--state` 自动加载）+ 已部署合约地址 + indexer 已有游标继续同步。校验：链上 chainId/合约地址与 `dv-env.json` 一致，否则报错要求 `--fresh`。
- **`--keep-running`**：前台保活供手工调试；否则各服务以 PID 文件后台托管，配套 `dv-down.sh` 清理。
- **健康门控**：脚本在每步后轮询就绪（anvil `eth_chainId`、合约 `eth_getCode != 0x`、indexer 游标 ≥ 部署块、server 读接口返回）才进入下一步，全部就绪打印 `dv-env.json` 路径。

> 说明：anvil `--state` 已天然支持持久化/恢复；脚本的职责是把"合约地址 + indexer 游标 + server 配置"这三份派生状态与 anvil state 对齐，使 resume 不产生 source 漂移。

### 5.2 运行测试脚本

两种驱动方式，二选一或都做：

**(A) Rust e2e（推荐，进 CI 可控）**——新增 `src/components/bns-client/tests/e2e_anvil.rs`，用 `alloy-node-bindings` 在测试进程内拉起 anvil + 部署（不依赖 5.1 脚本，自包含），`#[ignore]` 默认跳过、`--ignored` 显式运行，并按 `which anvil/forge` 缺失时优雅跳过。覆盖：
- [ ] **写读闭环**：Controller Client 注册 name → `publishDocument`(inline) → 触发 `sync_once` → Server 读 `resolveDocument` 命中，内容/版本一致。
- [ ] **签名边界（真 EVM）**：Controller 用托管私钥签名，链上 `msg.sender` == 私钥地址 → 通过；构造一个 `CallAuthority.actor` != signer 的 TX → 链上 revert，错误码透传到 client。
- [ ] **selector / packing / event topic**：只有真 EVM 暴露的问题——calldata selector、参数 packing、revert reason、event topic 与 §1.7/§2.1 断言一致。
- [ ] **nonce / 重放**：连续两笔写 nonce 递增；重放同一 raw TX → 链上拒绝；chainId 不匹配的 TX → 拒绝（设计 §9 防重放待补项）。
- [ ] **confirmations / 同步推进**：写入后未达 confirmations 时 indexer 不投影，达到后投影命中；游标单调推进。
- [ ] **重部署从 0 重放**（设计 §9 未测项）：换合约地址（新 source）→ indexer 从 `start_block` 重放 → 投影与首次等价。
- [ ] **controller 策略真链路**：controller 只能 publish 授权 docType，越权 docType → 链上 revert。

**(B) 脚本化冒烟**——`src/apps/bns/scripts/dv-smoke.sh`：在 5.1 环境上用 client CLI / curl 跑
注册 → 发布 → 等待同步 → 读命中 的最小路径，打印每步耗时与结果，作为"环境是否健康"的快速门禁（对应已有 [Smoke.s.sol](../src/apps/bns/script/Smoke.s.sol) 的链上版，本脚本是跨全分层版）。

**SN 业务级集成（阶段二，待 `sn_bns_controller` 切 EVM 后）**：
- [ ] `sn_auth.register` → `sn_bns_controller` 提交 BNS 注册 TX（owner_config + controller policy）→ indexer 投影 → `sn_resolver` 读到 BNS 文档，串成幂等流程（`request_id`），验证一致性要求（无"本地成功 BNS 未创建"窗口）。

### 5.3 集成测试通过标准
- 5.2(A) 全部 `--ignored` 用例在装有 Foundry 的机器上绿。
- `dv-up.sh --fresh` 后 `dv-smoke.sh` 通过；`dv-down.sh` 再 `dv-up.sh --resume` 后 smoke 仍通过且 indexer 游标延续（不从 0 重放）。
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
