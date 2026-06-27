# BNS 改造 TODO（一步到位：私链 + 真合约 + 真索引器）

> **方向**：不再用 Rust 状态机 + SQLite 模拟 BNS 逻辑。第一天就上 **本地私链 + 第一版 BNS 合约（Solidity）**，
> 合约是状态的**唯一权威源**；`bns-indexer` 从第一天起就是一个**真正的事件索引器**（只读、不持有业务逻辑）。
> 目标是**在真实业务中尽早把 BNS ABI 跑稳**——selector / 参数 packing / revert / event topic 这些只有真 EVM 才暴露的问题，越早撞到越好。

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
- 权威源：`Rust 状态机` → **`Bns.sol` 合约**。
- `bns-indexer`：`状态机+存储` → **事件索引器**（订阅 log、建索引、提供读查询）。
- `bns-server`：`状态机 HTTP 包装` → **索引器查询 API + 可选写代理**。
- 鉴权：不再由 server 端 `ecrecover` 或信任传入的 `CallAuthority`；**节点恢复 sender，合约用 `msg.sender` 做 `require` 访问控制**——天然就是合约语义。

## 1. 私链环境（Anvil）

- [ ] 引入 **Foundry**（`foundryup`）：`forge`（写/编译/测合约）+ `anvil`（私链）。
- [ ] 起链脚本：`anvil --state .anvil-state.json`（持久化）/ `--block-time 1` 或即时出块；固定助记词产出确定性账户。
- [ ] "随时可改"工作流：改 `Bns.sol` → `forge build` → 重新部署 → 索引器从 block 0 重新同步。**中心化测试环境，零迁移负担**。
- [ ] 集成测试用 `alloy-node-bindings` 从 Rust 里自动拉起 anvil + 部署合约 + 跑端到端。
- [ ] 配置项：链 RPC endpoint、chainId、合约地址、controller 私钥来源（进 `SNServerConfig`，删掉旧的裸 `CallAuthority` 字段）。

## 2. 第一版 BNS 合约（Solidity）

> 在 anvil 环境下写合约，工程师压力很小：随便改、随便重部署。先把核心写操作 + event 跑通。

- [ ] `forge init contracts/`，写 `Bns.sol`。第一版只需覆盖核心操作（对应现有 `BnsWriteOperation`，[sn_bns_controller.rs:26](src/components/bns-client/src/sn_bns_controller.rs:26)）：
  - [ ] `registerName(...)`
  - [ ] `publishDocument(...)`
  - [ ] `revokeDocument(...)`
  - [ ] `setControllerPolicy(...)`
  - [ ] `updateAuthorityKeys(...)`
  - [ ] `bootstrapName(...)`（可放第二批）
- [ ] 访问控制用 `msg.sender`：owner 操作 `require(msg.sender == owner)`；controller 操作校验 controller policy 中登记的地址 + 允许的 doc 类型（沿用 `allowed_controller_doc_types` 语义，默认 DNS_TXT / RELAY_ASSIGNMENT）。
- [ ] **合约级可选 controller 密钥**：每个 name 可设一个可选 controller 地址做日常自动操作（= Controller Client 私钥地址），映射现有 `ControllerRule`/controller policy 概念。
- [ ] 为每个写操作 `emit` 事件（索引器的数据源），字段对齐现有 `EventLogRecord`（[model.rs:843](src/components/bns-indexer/src/model.rs:843)）：name、doc_type、version、seq/blockNumber、actor、内容 hash 等。
- [ ] 大对象（document 内容）传 `bytes`/hash 引用，避免 calldata 过大（沿用 inline document 上限语义）。
- [ ] `MutationGuard`（[model.rs:261](src/components/bns-indexer/src/model.rs:261)，乐观并发前置）作为参数进合约，`require(name_seq == expected)`；与账户 nonce 区分职责（nonce 防 TX 重放，guard 防状态过期，chainId/合约地址防跨部署重放）。
- [ ] `forge test` 写 Solidity 单测（跑在 revm 上，极快），覆盖鉴权 / guard / 事件正确性。

## 3. `bns-evm` crate（ABI 绑定 + TX 构造/签名）

> 所有 EVM/密码学依赖收敛到这一层。`sol!` 一份定义同时充当合约接口与客户端编码器，ABI 漂移编译期即报错。

- [ ] 新建 crate `bns-evm`，引入 alloy：`alloy-primitives`、`alloy-sol-types`（`sol!` 吃 `Bns.sol`）、`alloy-consensus`+`alloy-rlp`（EIP-1559 TX）、`alloy-signer-local`（secp256k1 签名，仅 Controller 用）、`alloy-provider`（连 anvil）。
- [ ] 用 `sol!(#[sol(rpc)] Bns, "out/Bns.sol/Bns.json")` 生成类型安全绑定（calldata 编码 + event 解码一份搞定）。
- [ ] 封装：`build_tx(op, nonce, chainId, to, gas) -> UnsignedTx`、`sign(tx, key) -> RawTx`、event 解码 helper。
- [ ] round-trip 测试：calldata 编/解码一致；用独立 alloy 解码自己签的 TX，ecrecover 地址一致。

## 4. 两个客户端

- [ ] **Standard Client**（薄封装，无私钥）：入参为**已签名 raw TX 字节**，`eth_sendRawTransaction` 提交；另提供 `build_calldata`/`build_unsigned_tx` helper 给外部签名方。读走索引器。
- [ ] **Controller Client**（托管私钥，自动签名）：持 secp256k1 私钥，自动查 nonce → 填 chainId/to/gas → ABI 编码 → 签名 → 提交。SN 用这个。
  - [ ] 迁移 `sn_bns_controller.rs`：删掉手工拼 `CallAuthority`（[sn_bns_controller.rs:288](src/components/bns-client/src/sn_bns_controller.rs:288)），改为构造 op → Controller Client 自动签名提交。
  - [ ] 复用幂等：`SnBnsWriteRequestStore`（[sn_bns_controller.rs:198](src/components/bns-client/src/sn_bns_controller.rs:198)）记录 `request_id → (nonce, tx_hash)`，避免重复提交 / nonce 冲突。
  - [ ] nonce 管理：本地缓存 + 失败回退重查 + 并发处理；可选等待回执确认上链。

## 5. `bns-indexer` = 真正的事件索引器（第一天就是）

> 状态权威在合约；indexer 只**读链、建索引、供查询**，不再有任何 mutation/validate 逻辑。

- [ ] **删除/下线**现有状态机写路径：`registry.rs` 的 mutation、`validate_actor_key`（[registry.rs:1278](src/components/bns-indexer/src/registry.rs:1278)）、`authorize_owner_*`、以及作为入参的 `CallAuthority`（[model.rs:229](src/components/bns-indexer/src/model.rs:229)）。
- [ ] 同步器：`eth_subscribe`(logs) / 轮询 `eth_getLogs`，从指定起始块拉合约事件，用 `bns-evm` 的 event 绑定解码。
- [ ] 重建索引投影：复用现有 SQLite schema（[sqlite.rs](src/components/bns-indexer/src/sqlite.rs)）作为**只读投影表**（names / documents / authority / controller policy 等），由事件回放写入；不再是权威存储。
- [ ] 同步进度 / reorg 处理（私链一般无 reorg，但保留 last-synced-block 游标，便于合约重部署后从 0 重放）。
- [ ] `EventLogRecord` / `LogCheckpoint`（[model.rs:718](src/components/bns-indexer/src/model.rs:718)）由链上 log + 区块派生：seq=全局事件序、log_root 可用区块/日志哈希，checkpoint 关联 blockNumber/blockHash。
- [ ] 保留现有**读 API**（query_name_state / resolve_owner / resolve_document / get_authority_* / list_events / latest_checkpoint），实现改为查索引投影。

## 6. BNS Server = 查询 API（+ 可选写代理）

- [ ] 写路径决策（开放问题）：客户端**直连链 RPC** 提交 TX，还是经 **BNS Server 代理**（便于鉴权/限流/隐藏链端点）？建议先直连，server 专注读。
- [ ] 读路径：保留 kRPC/HTTP 读接口（[rpc.rs:419](src/components/bns-client/src/rpc.rs:419) 起的 `BnsIndexerClient` 读方法），后端改为查索引器投影。
- [ ] 删除旧的"传入 CallAuthority"写 RPC 方法（[rpc.rs:878](src/components/bns-client/src/rpc.rs:878) 起）。

## 7. 身份与授权

- [ ] 身份 = 以太坊地址（节点 ecrecover 出 sender，合约见 `msg.sender`）。
- [ ] `AuthorityKey`（[model.rs:268](src/components/bns-indexer/src/model.rs:268)）承载 secp256k1 公钥/地址，`verification_method = EcdsaSecp256k1`；索引器据事件维护授权集投影。
- [ ] owner / controller 校验全部在合约 `require` 里完成，server/indexer 不做鉴权。

## 8. 下一步：内嵌 revm（中心化生产形态，可选/后置）

- [ ] 把 revm 当库嵌进 BNS Server，进程内执行 `Bns.sol` 字节码，`Database` trait 背后接持久化（可仍用 SQLite 存 EVM state）。去掉独立节点 / JSON-RPC 跳数，确定性更强、可快照回滚。
- [ ] 与外挂 anvil 共享同一份合约与 `bns-evm` 绑定，切换成本低。

## 9. 测试与验证

- [ ] `forge test`：合约鉴权 / guard / 事件单测。
- [ ] `bns-evm` calldata/TX round-trip + 独立 ecrecover 交叉验证。
- [ ] 端到端集成：`alloy-node-bindings` 拉起 anvil → 部署 `Bns.sol` → Controller Client 提交 → 索引器同步 → 读 API 命中。
- [ ] 防重放/隔离：nonce 重放拒绝、chainId 不匹配拒绝、guard 冲突。
- [ ] 合约重部署 → 索引器从 0 重放一致性。

## 10. 收尾

- [ ] 移除 `bns-indexer` 的状态机写逻辑与 `CentralizedBnsRegistry` 权威语义（降级为索引投影或删除）。
- [ ] 更新 `doc/BNS 智能合约接口设计.md`、SN 文档：权威源=合约、indexer=事件索引器、两客户端模型。
- [ ] `SNServerConfig` 增删：去掉裸 `CallAuthority`，新增 链 RPC / chainId / 合约地址 / controller 私钥来源。

---

### 待用户拍板的开放问题
1. TX 类型 **EIP-1559** 还是 legacy？（建议 1559）
2. 写路径：客户端**直连链 RPC** 还是经 **BNS Server 代理**？（建议先直连）
3. chainId 与合约地址如何分配/配置（每部署一套）？
4. controller 托管私钥存放方式（配置 / KMS / 环境变量）？
5. gas 字段：接受并忽略，还是强制 0？
6. 第一批合约函数范围：先 `registerName` + `publishDocument` 跑通，还是一次把 5 个写操作都上？
