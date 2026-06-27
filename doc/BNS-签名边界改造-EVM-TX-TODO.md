# BNS 改造 TODO（一步到位：私链 + 真合约 + 真索引器）

> **方向**：不再用 Rust 状态机 + SQLite 模拟 BNS 逻辑。第一天就上 **本地私链 + 第一版 BNS 合约（Solidity）**，
> 合约是状态的**唯一权威源**；`bns-indexer` 从第一天起就是一个**真正的事件索引器**（只读、不持有业务逻辑）。
> 目标是**在真实业务中尽早把 BNS ABI 跑稳**——selector / 参数 packing / revert / event topic 这些只有真 EVM 才暴露的问题，越早撞到越好。

---

## 实现现状（2026-06-27）

第一阶段（私链环境 + 合约）已落地，代码在 **`src/apps/bns`**（Foundry 工程，非原计划的 `contracts/`）。
EVM 客户端基础层与索引器事件投影已部分落地；SN/BNS Server 写路径仍未完全切到 EVM。

| 模块 | 状态 | 说明 |
| --- | --- | --- |
| 私链环境（Anvil 脚本） | ✅ 已完成 | [scripts/anvil.sh](../src/apps/bns/scripts/anvil.sh) / [scripts/deploy.sh](../src/apps/bns/scripts/deploy.sh) |
| BNS 合约 `Bns.sol` | ✅ 已完成（**超出原计划范围**） | 一次性实现了**完整闭环接口**，而非计划中的"先 5 个核心写操作"，见 [src/Bns.sol](../src/apps/bns/src/Bns.sol) |
| `forge test` 合约单测 | ✅ 已完成 | 6 个用例，覆盖鉴权 / guard / 文档 / 事件，见 [test/Bns.t.sol](../src/apps/bns/test/Bns.t.sol) |
| 链上 smoke 流程 | ✅ 已完成 | [script/Smoke.s.sol](../src/apps/bns/script/Smoke.s.sol)：部署 → registerName → publishDocument → resolveDocument |
| `bns-evm` crate（alloy 绑定 + TX 构造/签名） | ✅ 基础已完成 | 新增 [src/components/bns-evm](../src/components/bns-evm)：`sol!` ABI 绑定、calldata/event 解码、EIP-1559 TX 构造/签名、JSON-RPC helper、round-trip 测试 |
| Standard / Controller 客户端 | 🟡 基础已完成，SN 迁移未完成 | `src/components/bns-client` 新增 EVM Standard/Controller client、raw TX 提交、unsigned TX helper、托管私钥签名；`sn_bns_controller.rs` 尚未切换到 EVM 提交流程 |
| `bns-indexer` → 事件索引器 | 🟡 事件投影基础已完成 | 新增合约事件解码/投影与 `EventLogRecord` 写入；`CentralizedBnsRegistry` 状态机和完整读投影仍未下线 |
| BNS Server 读/写路径改造 | ❌ 未开始 | 仍走旧 RPC |
| SN EVM 配置 | 🟡 配置结构已完成，运行链路未切换 | `SNServerConfig` 新增 `bns_evm` RPC/chainId/合约地址/gas/私钥来源字段；旧 `CallAuthority` 路径仍保留 |

### 与原计划的两处关键偏差（需注意）

1. **合约范围一次到顶，而非渐进式**：合约不是"先跑通 5 个写操作"，而是把**整套闭环接口**（注册 / 续期 / 转移 / owner / 释放 / 命名空间策略 / 授权密钥 / controller 策略 / 文档发布撤销 / 别名 / 支付目标 / 日志检查点 + 全部读 API）放进**单个 `Bns.sol`**。
   - 代价：字节码**超过公链 EIP-170 大小上限**，私链脚本用 `--disable-code-size-limit` 绕过；上公链前需拆分 facet/module（README 已注明）。

2. **`CallAuthority` 被保留在 ABI 中，但不被信任**：原计划是"删掉 `CallAuthority`，纯靠 `msg.sender`"。实际实现是：函数签名**仍接收 `CallAuthority` 入参**（用于区分 role=Owner/Controller 与选择 `kid`），但合约**只信任 `msg.sender`**——
   `_authenticateExpectedPrincipal`（[Bns.sol:1541](../src/apps/bns/src/Bns.sol:1541)）要求 `CallAuthority.actor` 解析出的地址 / 授权密钥地址 **必须等于 `msg.sender`**。即"签名边界"已经做到合约只认节点恢复出的 sender，但 ABI 形状暂未清理。

---

## 0. 目标架构

```
                       ┌─ 写：签名 EVM TX ─> eth_sendRawTransaction ─┐
[ Controller Client ]  │  托管私钥，自动构造/签名/提交                │
[ Standard Client   ]  │  薄封装，入参=已签名 raw TX，仅 ABI 编码     │
                       └──────────────────────────────────────────────┘
                                          │
                                          ▼
                              [ 私链 Anvil ]  ← 跑 Bns.sol（权威状态 + 访问控制 + emit event）
                                          │  合约 emit 事件
                                          ▼
[ BNS Server ]  = 索引器查询 API（kRPC/HTTP）＋（可选）写代理
[ BNS Indexer ] = 监听合约 event → 解码 → 建查询索引（只读投影）；EventLog/Checkpoint 由链上日志派生
```

**本质变化**：
- 权威源：`Rust 状态机` → **`Bns.sol` 合约**。✅ 合约侧已成立（链上 `_names`/`_documents`/`_authoritySets` 等即权威状态）。
- `bns-indexer`：`状态机+存储` → **事件索引器**。🟡 已有合约事件解码/投影基础，完整同步器与读投影仍待完成。
- `bns-server`：`状态机 HTTP 包装` → **索引器查询 API + 可选写代理**。❌ 尚未改造。
- 鉴权：不再由 server 端 `ecrecover` 或信任传入的 `CallAuthority`；**节点恢复 sender，合约用 `msg.sender` 做 `require` 访问控制**——✅ 合约侧已成立（`CallAuthority` 仅作 role/kid 提示，地址必须 == `msg.sender`）。Rust 客户端侧已能构造/签名 EVM TX，但 SN/BNS Server 写路径尚未完全迁移。

## 1. 私链环境（Anvil）✅ 已完成

- [x] 引入 **Foundry**：`forge`（写/编译/测合约）+ `anvil`（私链）。README 含安装指引。
- [x] 起链脚本 [scripts/anvil.sh](../src/apps/bns/scripts/anvil.sh)：`--state var/anvil-state.json`（持久化）、`--block-time 1`、固定助记词 `test test ... junk`（确定性账户）、`--chain-id 31337`、`--disable-code-size-limit`。
- [x] 部署脚本 [scripts/deploy.sh](../src/apps/bns/scripts/deploy.sh)：`forge build` + `forge create src/Bns.sol:Bns`，输出到 `deployments/anvil.local.json`。
- [x] "随时可改"工作流：改 `Bns.sol` → `forge build` → 重新部署。**中心化测试环境，零迁移负担**。
- [ ] 集成测试用 `alloy-node-bindings` 从 Rust 里自动拉起 anvil + 部署合约 + 跑端到端。
- [x] 配置项进 Rust 侧：链 RPC endpoint、chainId、合约地址、controller 私钥来源字段已进入 `SNServerConfig.bns_evm`。
- [ ] 删掉旧的裸 `CallAuthority` 字段/路径，并把 SN 写请求真正切到 EVM Controller Client。

## 2. BNS 合约（Solidity）✅ 已完成（范围超出原计划）

> 实际实现没有停在"第一版 5 个核心操作"，而是把完整闭环接口一次性写进 [src/Bns.sol](../src/apps/bns/src/Bns.sol)（约 1976 行）。
> foundry 配置：solc `0.8.24`、`optimizer`、`via_ir`、`evm_version = paris`（[foundry.toml](../src/apps/bns/foundry.toml)）。

- [x] 写操作（**远超**原计划的 5 个）：
  - [x] `registerName`（[Bns.sol:620](../src/apps/bns/src/Bns.sol:620)）
  - [x] `bootstrapName`（[Bns.sol:631](../src/apps/bns/src/Bns.sol:631)）— 原计划"第二批"，已实现
  - [x] `renewName`（[Bns.sol:699](../src/apps/bns/src/Bns.sol:699)）
  - [x] `transferName`（[Bns.sol:730](../src/apps/bns/src/Bns.sol:730)）
  - [x] `setNameOwner`（[Bns.sol:793](../src/apps/bns/src/Bns.sol:793)）
  - [x] `releaseName`（[Bns.sol:839](../src/apps/bns/src/Bns.sol:839)）
  - [x] `setNamespacePolicy`（[Bns.sol:861](../src/apps/bns/src/Bns.sol:861)）
  - [x] `updateAuthorityKeys`（[Bns.sol:896](../src/apps/bns/src/Bns.sol:896)）
  - [x] `rotateAuthorityAndOwnerDocument`（[Bns.sol:911](../src/apps/bns/src/Bns.sol:911)）
  - [x] `publishDocument`（[Bns.sol:931](../src/apps/bns/src/Bns.sol:931)）
  - [x] `revokeDocument`（[Bns.sol:980](../src/apps/bns/src/Bns.sol:980)）
  - [x] `setControllerPolicy`（[Bns.sol:1030](../src/apps/bns/src/Bns.sol:1030)）
  - [x] `setDidAlias`（[Bns.sol:1045](../src/apps/bns/src/Bns.sol:1045)）
  - [x] `setPaymentTarget`（[Bns.sol:1080](../src/apps/bns/src/Bns.sol:1080)）
  - [x] `publishLogCheckpoint`（[Bns.sol:1140](../src/apps/bns/src/Bns.sol:1140)）
- [x] 读 API：`queryNameState` / `resolveOwner` / `isStandardTransferEnabled` / `getAuthoritySet` / `getAuthorityKey` / `resolveDocument` / `getDocumentVersion` / `getAlias` / `getPurchaseContext` / `resolvePaymentTarget` / `latestCheckpoint` / `chainAccountPrincipal` / `bnsNamePrincipal`。
- [x] 访问控制基于 `msg.sender`：`_authorizeOwner`（[Bns.sol:1526](../src/apps/bns/src/Bns.sol:1526)）解析 effectiveOwner 后要求其地址 == `msg.sender`；controller 操作在 `_authorizeUpdate`（[Bns.sol:1487](../src/apps/bns/src/Bns.sol:1487)）中按 controller policy 的 `permissions` 位掩码 + docType 匹配 + 有效期校验，并要求登记的 controller 地址 == `msg.sender`。
- [x] **合约级 controller 策略**：`ControllerRule[]`（`permissions` 含 `PUBLISH_DOCUMENT` / `REVOKE_DOCUMENT` / `SET_PAYMENT` / `SET_ALIAS` / `SET_NAMESPACE`），含 docType scope 与有效期窗口。映射现有 `ControllerRule`/controller policy 概念。
- [x] 每个写操作 `emit` 专用事件 **＋** 统一的 `ProtocolEvent(seq, eventType, actor, previousLogRoot, logRoot)`（[Bns.sol:322](../src/apps/bns/src/Bns.sol:322)）；字段含 name/docType/version/actor/contentHash 等，可直接供索引器消费。
- [x] 大对象走 `DocumentRef`：inline 上限 `MAX_INLINE_DOCUMENT = 4KB`（[Bns.sol:258](../src/apps/bns/src/Bns.sol:258)），inline 必须 `sha256(inlineDocument) == contentHash`；非 inline 走 `uri` + hash 引用。
- [x] `MutationGuard`（`expectedNameSeq` + `expectedParentNameSeq`）作为参数进合约，`_checkGuard`（[Bns.sol:1639](../src/apps/bns/src/Bns.sol:1639)）`require(nameSeq == expected)`；`_hashDocumentState` / `_commitEvent` 均混入 `block.chainid` + `address(this)` 防跨部署重放。
- [x] `forge test` 写 Solidity 单测，覆盖鉴权 / guard / 文档 / 事件（见 §9）。
- [ ] **上公链前的拆分**：当前单合约字节码超过 EIP-170 上限，仅私链 `--disable-code-size-limit` 可部署。上公链需拆 facet/module 或把读 helper 移出写合约。（README 已注明，留作后续。）

## 3. `bns-evm` crate（ABI 绑定 + TX 构造/签名）✅ 基础已完成

> 所有 EVM/密码学依赖收敛到这一层。`sol!` 一份定义同时充当合约接口与客户端编码器，ABI 漂移编译期即报错。
> **现状**：已新增 `src/components/bns-evm`。该 crate 从 Foundry 产物生成类型安全绑定，并提供 EIP-1559 TX 构造、签名、raw TX 解码、JSON-RPC 与事件解码基础能力。

- [x] 新建 crate `bns-evm`，引入 alloy：`alloy-primitives`、`alloy-sol-types`、`alloy-consensus`、`alloy-rlp`、`alloy-signer-local`；JSON-RPC helper 先用 `reqwest` 直连节点。
- [x] 用 `sol!(Bns, "out/Bns.sol/Bns.json")` 生成类型安全绑定（calldata 编码 + event 解码一份搞定）。
- [x] 封装：`build_tx(call, nonce, chainId, to, gas) -> TxEip1559`、`sign(tx, key) -> RawTx`、`decode_bns_event` / `decode_bns_call` helper。
- [x] round-trip 测试：calldata 编/解码一致；独立解码自己签的 TX，恢复出的 signer 地址一致。
- [ ] 后续补 `alloy-node-bindings`/自动部署合约的端到端测试。

## 4. 两个客户端 🟡 基础已完成，SN 写路径迁移未完成

> **现状**：`src/components/bns-client` 已新增 EVM Standard/Controller client。旧的 `sn_bns_controller.rs` 仍保留旧 RPC/`CallAuthority` 流程，尚未切换到 EVM TX。

- [x] **Standard Client**（薄封装，无私钥）：入参为**已签名 raw TX 字节**，`eth_sendRawTransaction` 提交；另提供 `build_calldata`/`build_unsigned_tx` helper 给外部签名方。读走索引器。
- [x] **Controller Client**（托管私钥，自动签名）：持 secp256k1 私钥，自动查 nonce → 填 chainId/to/gas → ABI 编码 → 签名 → 提交。
  - [ ] 迁移 `sn_bns_controller.rs`：删掉手工拼 `CallAuthority`，改为构造 op → Controller Client 自动签名提交。
  - [x] 幂等元数据：`SnBnsWriteRequestStore` 增加 `evm_chain_id` / `evm_nonce` / `evm_tx_hash` / `evm_raw_tx` 字段，避免后续迁移时重复提交信息丢失。
  - [x] nonce 管理基础：Controller Client 本地缓存 pending nonce。
  - [ ] nonce 管理增强：失败回退重查、并发冲突处理、可选等待回执确认上链。

## 5. `bns-indexer` = 真正的事件索引器 🟡 事件投影基础已完成

> 状态权威在合约；indexer 只**读链、建索引、供查询**，不再有任何 mutation/validate 逻辑。
> **现状**：已新增合约事件解码/投影模块，可把 `ProtocolEvent` 与专用合约事件配对为 `EventLogRecord` 并写入 SQLite；`CentralizedBnsRegistry` 状态机（[registry.rs](../src/components/bns-indexer/src/registry.rs)）和完整读投影仍保留。

- [ ] **删除/下线**现有状态机写路径：`registry.rs` 的 mutation、`validate_actor_key`、`authorize_owner_*`、以及作为入参的 `CallAuthority`。
- [ ] 同步器：`eth_subscribe`(logs) / 轮询 `eth_getLogs`，从指定起始块拉合约事件，用 `bns-evm` 的 event 绑定解码。
- [x] 合约事件解码/投影基础：用 `bns-evm` event 绑定解码日志，将 `ProtocolEvent` 与专用事件投影为现有 `RegistryEvent` / `EventLogRecord`。
- [ ] 重建完整索引投影：复用现有 SQLite schema 作为**只读投影表**（names / documents / authority / controller policy 等），由事件回放写入；不再是权威存储。
- [ ] 同步进度 / reorg 处理（私链一般无 reorg，但保留 last-synced-block 游标，便于合约重部署后从 0 重放）。
- [x] `EventLogRecord` 基础写入：由链上 `ProtocolEvent` 的 `seq` / `previousLogRoot` / `logRoot` 派生并写入 `bns_events`。
- [ ] `LogCheckpoint` 完整对齐：合约已有 `globalEventSeq`（全局事件序）、`currentLogRoot`（链式哈希）、`publishLogCheckpoint`，索引器还需补同步/查询链路。
- [ ] 保留现有**读 API**（query_name_state / resolve_owner / resolve_document / get_authority_* / list_events / latest_checkpoint），实现改为查索引投影。

## 6. BNS Server = 查询 API（+ 可选写代理）❌ 未开始

- [ ] 写路径决策（开放问题）：客户端**直连链 RPC** 提交 TX，还是经 **BNS Server 代理**？建议先直连，server 专注读。
- [ ] 读路径：保留 kRPC/HTTP 读接口，后端改为查索引器投影。
- [ ] 删除旧的"传入 CallAuthority"写 RPC 方法。

## 7. 身份与授权（合约侧 ✅ / Rust 侧 🟡）

- [x] 身份 = 以太坊地址（合约见 `msg.sender`）。合约 `_authenticateExpectedPrincipal` 已要求恢复出的地址 == `msg.sender`。
- [x] `AuthorityKey` 承载 secp256k1 公钥/地址（合约 `keyData` 解析为 20/32 字节地址），授权集投影由 `updateAuthorityKeys` 事件维护（`authoritySeq` / `authorityRoot` / `activeKeyCount`）。
- [x] owner / controller 校验全部在合约 `require` 里完成。
- [x] Rust 客户端侧已能构造并签名 EIP-1559 TX；节点负责恢复 signer 并作为合约 `msg.sender`。
- [ ] SN/BNS Server 写路径仍需从旧 `CallAuthority` RPC 切到 EVM TX 提交。

## 8. 下一步：内嵌 revm（中心化生产形态，可选/后置）

- [ ] 把 revm 当库嵌进 BNS Server，进程内执行 `Bns.sol` 字节码，`Database` trait 背后接持久化（可仍用 SQLite 存 EVM state）。去掉独立节点 / JSON-RPC 跳数，确定性更强、可快照回滚。
- [ ] 与外挂 anvil 共享同一份合约与 `bns-evm` 绑定，切换成本低。

## 9. 测试与验证

- [x] `forge test`：[test/Bns.t.sol](../src/apps/bns/test/Bns.t.sol) 6 个用例：
  - `testRegisterAndPublishInlineDocument`（注册 + inline 文档发布）
  - `testStaleNameSeqRejectsPublish`（guard / nameSeq 冲突拒绝）
  - `testControllerCanOnlyPublishAllowedDocType`（controller scope 限制）
  - `testBnsAuthorityKeyTakesOverFromAssetOwner`（BNS 授权密钥接管 assetOwner）
  - `testRevokeCurrentVersionKeepsCurrentPointerRevoked`（撤销当前版本）
- [x] 链上 smoke：[script/Smoke.s.sol](../src/apps/bns/script/Smoke.s.sol) 部署 → registerName → publishDocument → resolveDocument。
- [x] `bns-evm` calldata/TX round-trip + 独立 signer 恢复交叉验证。
- [x] `bns-client` EVM call 转换与 unsigned TX 构造测试。
- [x] `bns-indexer` 合约事件投影与 SQLite event 写入测试。
- [ ] 端到端集成：`alloy-node-bindings` 拉起 anvil → 部署 `Bns.sol` → Controller Client 提交 → 索引器同步 → 读 API 命中。**未开始**。
- [ ] 防重放/隔离：合约侧已含 `block.chainid`+`address(this)` 隔离与 guard；nonce 重放 / chainId 不匹配的 TX 级测试待 §3/§4 落地后补。
- [ ] 合约重部署 → 索引器从 0 重放一致性。**未开始**（依赖 §5）。

## 10. 收尾

- [ ] 移除 `bns-indexer` 的状态机写逻辑与 `CentralizedBnsRegistry` 权威语义（降级为索引投影或删除）。
- [ ] 更新 `doc/BNS 智能合约接口设计.md`、SN 文档：权威源=合约、indexer=事件索引器、两客户端模型。
- [x] `SNServerConfig` 新增链 RPC / chainId / 合约地址 / controller 私钥来源 / gas 配置字段。
- [ ] 去掉裸 `CallAuthority` 配置/写路径，并接入 Controller Client。
- [ ] （新增）清理合约 ABI：评估是否从写函数签名中**移除 `CallAuthority` 入参**（目前保留作 role/kid 提示，但身份只认 `msg.sender`），统一签名边界语义。
- [ ] （新增）公链化：拆分单合约以满足 EIP-170。

---

### 待用户拍板的开放问题（部分已由实现确定）

1. TX 类型 **EIP-1559** 还是 legacy？— **已按 EIP-1559 基础实现**（`bns-evm`）。
2. 写路径：客户端**直连链 RPC** 还是经 **BNS Server 代理**？（建议先直连）— **未定**。
3. chainId 与合约地址如何分配/配置？— 私链已**默认 chainId = 31337**（`anvil.sh`，可经 `ANVIL_CHAIN_ID` 覆盖），合约地址由 `deploy.sh` 写入 `deployments/anvil.local.json`；Rust 侧已有 `SNServerConfig.bns_evm` 配置结构，生产分发方式仍待定。
4. controller 托管私钥存放方式（配置 / KMS / 环境变量）？— Rust 配置结构已预留环境变量 / 文件 / inline 字段；实际加载与 SN 写路径接入仍待完成。
5. gas 字段：接受并忽略，还是强制 0？— `bns-evm`/`SNServerConfig.bns_evm` 已按 EIP-1559 gas 字段处理；具体生产策略仍需按部署环境确定。
6. 第一批合约函数范围 — **已确定并超额完成**：实现直接覆盖了**全部闭环写操作 + 读 API**（见 §2），而非"先 register + publish"。
7. （新增）单合约字节码超过 EIP-170：公链部署前的拆分策略（facet/module）？
8. （新增）是否最终从 ABI 移除 `CallAuthority` 入参，纯靠 `msg.sender`？
