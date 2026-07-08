# SN BNS Proxy TODO

本文记录 SN 侧 BNS proxy 写链改造。目标是让没有 gas 的用户也能通过 SN 完成 BNS name 初始化和受限 document 发布；SN 负责构造、签名和投递 EVM TX，BNS 的最终权威状态仍以合约和 `bns-indexer` 投影为准。

## 实施状态（2026-07-08，已完成）

代码落点（`src/components/cyfs-sn/`）：

- `src/sn_bns_signer.rs` — `SnBnsTxSigner` 签名保管库（多 key、白名单校验：chain id /
  contract / method selector / operation×doc_type / gas 上限，未知一律拒签；Debug 全部
  redact 私钥）。对 bns-client 的插入点是既有 `BnsEvmKeyManager` trait，由
  `BoundControllerKeyManager` 按 controller 绑定实现——因此没有另发明新 trait，
  「`SnBnsTxSigner` trait」以 vault + bound key manager 的组合落地。
- `src/sn_bns_proxy.rs` — `SnBnsProxy` 编排器：每把 controller key 一个
  `SnBnsController` 实例（controllerPolicy / controller authority 天然锚定实例
  principal）、`sn_bns_controller_bindings` 持久化绑定（sqlite，与
  `sn_bns_write_requests` 同库）、审计日志。分配策略用 **带权重 rendezvous hashing**
  （优于草案的 `hash % N`：增删 controller 只迁移落到新节点的用户；`weight: 0` 表示
  排水，不接新用户但既有绑定继续可用）。
- `src/api/bns_proxy.rs` — `/kapi/sn/bns-proxy` RPC handler；所有参数
  `deny_unknown_fields`（客户端塞 `controller_address` 直接 InvalidParams）。
- `auth.register` 接线在 `src/api/auth.rs`；配置/路由/工厂在 `src/sn_server.rs`
  （`SNBnsProxyConfig`、`SnRpcPath::BnsProxy`、`build_bns_proxy`）。

与草案的差异：

- 配置块里不重复 chain 参数：`bns_evm` 继续承载 rpc_endpoint/chain_id/contract/gas
  上限，`bns_proxy` 只加 controllers / allowed_operations / require_user_asset_owner /
  enabled。草案中的 `bns_indexer_url`/`tx_submit_url` 即既有顶层 `bns_indexer_url`
  （读 + guard）与 `bns_evm.rpc_endpoint`（TX 投递）。
- `require_user_asset_owner` 缺省：配置了 `bns_proxy` 块 → **true**（生产语义）；
  纯旧配置（仅 `bns_evm.controller_private_key*`）→ false，保持 devtest 兼容，此时
  asset_owner 缺省回落为**该用户绑定 controller** 的地址。
- internal/admin 方法（`bns.publish_relay_assignment` / `bns.register_name_bootstrap`）
  与 `admin.clear_state_by_active_code` 同机制：钉在 InternalRoot(`/`)，外部
  `/kapi/sn/bns-proxy` HTTP 路径不可达。
- 绑定表在 SN 本地 sqlite（与 `sn_bns_write_requests` 账本同文件）；db_type=postgres
  时同样落本地（与写请求账本现状一致）。多实例 SN 共享 postgres 部署时，绑定表
  需要共享盘或后续挪到 provider 侧——单独议题，不在本次范围。

测试：`cargo test -p cyfs-sn`（单元 + RPC 集成，见 `sn_bns_signer.rs` /
`sn_bns_proxy.rs` 测试模块与 `sn_server.rs` 的 `test_sn_bns_proxy_*`）；真链
e2e `cargo test -p cyfs-sn --test e2e_sn_bns_proxy -- --ignored`（需 Foundry，
已在 anvil 上跑通完整验收链路，含 owner 清空 policy 后 controller 再写 revert）。

## 背景结论

- BNS 合约层支持 SN 代付 gas 注册 name：root name 的 `registerName` 使用 `AuthorityRole.None`，`assetOwner` 可以填用户 EVM 地址，`msg.sender` 可以是 SN signer。
- 所有权可以仍归用户：root name 未设置 semantic owner 时，effective owner 回落到 `assetOwner`。
- 注册时可以在一个原子 TX 内设置 `controllerPolicy` 和 `initialDocuments`，用于初始化 SN controller 权限和必要 BNS documents。
- 用户后续有 gas 后，可以用自己的 owner EVM 地址调用 `setControllerPolicy(name, [], 0x0, ownerAuthority, guard)` 清空 SN controller 权限，完成从 SN 托管流程退出。
- 当前 SN 已有 `SnBnsController` 和 `bns_evm` 配置，但它假设单 controller 较多，且 `auth.register` 缺少“用户 asset owner + 多 controller + 初始 documents + proxy API”完整接线。

## 目标

1. SN 增加独立 EVM 签名组件，业务逻辑不能直接接触私钥。
2. 签名组件支持多把 controller key，并提供按用户名选择 controller 地址的能力。
3. 注册 SN 用户时，把用户 BNS name 的 `assetOwner` 设置为用户上传的 owner EVM 地址，把 controller policy 设置为分配给该用户的 SN controller 地址。
4. SN 提供一组 BNS proxy RPC：用户调用 SN，SN 构造白名单内 TX，请签名组件签名，投递链上，返回 TX 信息。
5. SN 不等待最终上链确认；客户端自行根据返回的 `tx_hash` / `raw_tx` 判断 TX 是否成功上链。

## 非目标

- 不把 SN 登录 token 等价为 BNS owner 权限。
- 不允许业务层传任意 calldata 给签名组件签名。
- 不做通用 `/kapi/bns` 替代品；BNS proxy 只覆盖 SN 产品路径需要的有限 TX 类型。
- 不在 SN 运行态缓存里伪造 BNS 权威状态；SN resolver 仍从 `bns-indexer` 读取最终状态。

## 设计边界

### EVM 签名组件

新增 SN 内部组件，建议命名为 `SnEvmSigner` / `SnBnsTxSigner`。

职责：

- 加载多把 EVM signer 配置：`controller_id`、`address`、私钥来源、chain/contract 限制。
- 对外只暴露按业务类型签名的方法，不暴露私钥和任意 calldata 签名能力。
- 根据 `username` 返回分配的 controller address。
- 构造或校验待签 TX 的 operation 类型、contract address、chain id、method selector、authority actor、gas 参数上限。
- 使用 nonce manager 管理同一 signer 的并发 nonce。

禁止：

- 业务模块读取明文私钥。
- 外部 RPC 直接提交 raw calldata 给签名组件。
- 签名组件为未知 contract、未知 chain、未知 method selector 签名。

配置草案：

```yaml
bns_proxy:
  enabled: true
  rpc_path: /kapi/sn/bns-proxy
  bns_indexer_url: http://127.0.0.1:18080/kapi/bns
  tx_submit_url: http://127.0.0.1:18080/kapi/bns
  evm:
    chain_id: 31337
    contract_address: "0x..."
    gas_limit: 3000000
    max_fee_per_gas: 1000000000
    max_priority_fee_per_gas: 100000000
  controllers:
    - id: controller-a
      address: "0x..."
      private_key_env: SN_BNS_CONTROLLER_A_KEY
      weight: 1
    - id: controller-b
      address: "0x..."
      private_key_file: /etc/cyfs_gateway/controller-b.key
      weight: 1
  allowed_operations:
    - register_name_bootstrap
    - publish_dns_txt
    - publish_relay_assignment
```

兼容旧配置：

- 现有 `bns_write_enabled` / `bns_evm.controller_private_key*` 可先映射成单 controller 配置。
- 新代码不要继续假设 `SNServer` 只有一个 `sn_controller_principal`。

### 用户到 controller 的映射

新增持久化映射，避免 controller 轮换或扩容后同一用户漂移。

建议表：

```sql
CREATE TABLE IF NOT EXISTS sn_bns_controller_bindings (
    username TEXT PRIMARY KEY,
    controller_id TEXT NOT NULL,
    controller_address TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
```

行为：

- 注册用户前，按稳定策略选择 controller，例如 hash(username) + 可用 controller 列表。
- 选择结果写入 DB；后续所有 proxy 写操作都使用该 controller。
- API/内部方法提供 `controller_for_user(username) -> { controller_id, address }`。
- controller 下线时不能静默重分配已有用户；需要明确迁移流程。

## 注册流程改造

`auth.register` 参数需要明确用户 owner EVM 地址。

建议参数：

```json
{
  "name": "alice",
  "pwd_hash": "...",
  "active_code": "...",
  "request_id": "optional-idempotency-key",
  "asset_owner": "0x用户EVM地址",
  "owner_config": {},
  "initial_documents": {
    "zone": {},
    "boot": {},
    "dns_txt": []
  }
}
```

要求：

- `asset_owner` 必填。除 devtest 外，不再默认使用 SN controller 地址作为 asset owner。
- SN 选择并持久化用户 controller。
- 构造 `registerName`：
  - `assetOwner = asset_owner`
  - `authority = CallAuthority::public()`
  - `controllerPolicy` 中 actor 为用户绑定的 controller address
  - `initialDocuments` 包含 `owner` document 和业务要求的初始 documents
- SN signer 签名并提交 TX。
- `auth.register` 返回 access token，同时返回 BNS TX 信息。

返回草案：

```json
{
  "code": 0,
  "access_token": "...",
  "refresh_token": "...",
  "need_bind_owner_key": false,
  "bns": {
    "request_id": "sn:register:alice",
    "operation": "register_name_bootstrap",
    "name": "alice",
    "controller_address": "0x...",
    "asset_owner": "0x...",
    "chain_id": 31337,
    "tx_hash": "0x...",
    "raw_tx": "0x...",
    "nonce": 12,
    "status": "submitted"
  }
}
```

失败处理：

- BNS TX 构造/签名/提交失败时，默认不创建本地 SN 用户，避免本地账号和 BNS name 不一致。
- 如需兼容“先本地注册，后恢复 BNS”，必须落 `sn_bns_write_requests` 并提供恢复任务；不要把半成功状态藏在内存里。
- 同一 `request_id` 重试必须幂等；payload 不同则返回 conflict。

## BNS Proxy RPC

建议新增路径：`/kapi/sn/bns-proxy`。不要复活旧 `/kapi/sn/bns` 语义；旧路径已经在文档中标记迁出 SN。

通用调用链：

```text
client -> sn-bns-proxy-rpc
       -> 鉴权/业务校验/读取当前 BNS version
       -> 构造受限 TX 请求
       -> EVM 签名组件签名
       -> 投递 TX
       -> 返回 tx_hash/raw_tx/nonce
```

通用返回：

```json
{
  "code": 0,
  "operation": "publish_dns_txt",
  "name": "alice",
  "controller_address": "0x...",
  "chain_id": 31337,
  "nonce": 13,
  "tx_hash": "0x...",
  "raw_tx": "0x...",
  "status": "submitted"
}
```

### `bns.register_name_bootstrap`

用于注册阶段以外的恢复/重放，不建议普通客户端直接使用。

参数：

- `request_id`
- `name`
- `asset_owner`
- `owner_config`
- `initial_documents`

权限：

- 未注册本地用户恢复流程或内部 admin 流程。
- 普通用户不应能为任意 name 调用。

### `bns.publish_dns_txt`

用途：通过用户绑定的 SN controller 发布 `dns_txt` document。

参数：

```json
{
  "request_id": "dns-alice-1",
  "name": "alice",
  "mode": "add",
  "ttl": 600,
  "value": "..."
}
```

权限：

- 需要 SN access token。
- `name` 必须等于 token 所属用户名。
- controller policy 必须允许该用户 controller 写 `dns_txt`。

### `bns.publish_relay_assignment`

用途：SN 内部发布 relay assignment。是否开放给普通用户需要单独评审。

权限：

- 默认 internal/admin only。

### `bns.publish_document`

不建议第一阶段提供通用方法。若必须提供，只允许 `allowed_doc_types` 白名单内 doc type，且服务端按 doc type 做 schema 校验。

禁止：

- 第一阶段不允许用户通过 controller 写 `owner`、`zone`、`boot`、`device_mini_doc`，除非对应产品流程和退出机制已经评审清楚。
- 不允许传入任意 `CallAuthority`；authority 必须由服务端根据用户 controller 生成。

## 签名组件允许的 TX 类型

第一阶段最小白名单：

- `registerName` with bootstrap fields
- `publishDocument` for `dns_txt`
- `publishDocument` for `relay_assignment`（internal/admin only）

第二阶段再评审：

- `applyMutations` for docs-only batch
- `zone` / `boot` 初始化
- `device_mini_doc`

注意：合约层 `applyMutations` 中如果包含 owner document、authority update 或 owner policy，会进入 owner-only 路径，不能用 controller authority 代发。注册时的 `initialDocuments` 是初始化路径，不等同于后续 controller 可任意写 high-risk doc type。

## 安全要求

- 私钥只存在签名组件配置和内存中，不进入 RPC handler、日志、DB、错误信息。
- 所有 EVM 地址必须规范化为 checksum/lowercase 内部格式并校验长度。
- `asset_owner` 必须是用户上传的 EVM 地址；生产环境不允许默认使用 SN controller 地址。
- `controller_address` 必须来自 SN 内部映射，不能由客户端指定。
- 构造 TX 前读取当前 BNS version/name seq，设置 guard；stale guard 返回给客户端重试。
- 返回 raw TX 可以用于客户端观测，但不能让客户端提交任意 raw TX 给 SN 签名。
- 记录审计日志：username、operation、name、doc_type、controller_id、controller_address、tx_hash、nonce、request_id、payload_hash。

## 数据结构

新增或复用 `sn_bns_write_requests`，至少包含：

- `request_id`
- `username`
- `operation`
- `name`
- `doc_type`
- `payload_hash`
- `controller_id`
- `controller_address`
- `chain_id`
- `nonce`
- `tx_hash`
- `raw_tx`
- `state`: `pending | submitted | failed`
- `error_code`
- `error_message`
- `created_at`
- `updated_at`

说明：

- proxy 返回 `submitted` 即表示 SN 已投递 TX，不表示链上成功。
- 如果后续增加 receipt 追踪，应作为异步观测状态，不阻塞 RPC 返回。

## 实施步骤

### 1. 配置与 signer 抽象

- [x] 在 `SNServerConfig` 增加 `bns_proxy` 配置块。
- [x] 建立多 controller config 结构和校验逻辑。
- [x] 新增 `SnBnsTxSigner` trait，只暴露白名单 operation 的签名接口。
- [x] 接入 nonce manager，覆盖同一 controller 并发签名。
- [x] 兼容旧单 controller `bns_evm` 配置。

### 2. controller 分配与持久化

- [x] 新增 `sn_bns_controller_bindings` 表。
- [x] 实现 `assign_controller_for_user(username)`。
- [x] 实现 `controller_for_user(username)`。
- [x] 注册流程写入绑定；已存在绑定不得静默覆盖。

### 3. 注册接线

- [x] `auth.register` 生产模式要求 `asset_owner`。
- [x] 注册时使用用户 `asset_owner`，不再默认 SN controller 地址。
- [x] 构造带 `controllerPolicy` 和 `initialDocuments` 的 `registerName`。
- [x] 返回 BNS TX 信息。
- [x] 失败时不落本地用户，或显式落可恢复 pending 状态。

### 4. Proxy RPC

- [x] 新增 `/kapi/sn/bns-proxy` 路由。
- [x] 增加 `bns.publish_dns_txt`。
- [x] 增加 internal/admin `bns.publish_relay_assignment`。
- [x] 明确拒绝未知 operation、未知 doc type、跨用户 name。
- [x] 所有成功响应返回 tx 信息，不等待 receipt。

### 5. 读侧与缓存

- [x] proxy 写入成功投递后只做 cache invalidation，不直接更新 BNS 权威状态缓存。
- [x] resolver 继续通过 `bns-indexer` 读取最终状态。
- [x] stale/indexer 未同步时，客户端应看到“TX submitted but state not projected yet”的正常窗口。

### 6. 测试

- [x] 单元测试：signer 拒绝未知 method selector / contract / chain id。
- [x] 单元测试：业务层无法读取私钥。
- [x] 单元测试：同一用户 controller 分配稳定。
- [x] 单元测试：不同用户可分配到不同 controller。
- [x] 单元测试：注册请求生成 `assetOwner = 用户地址`、`controllerPolicy.actor = 分配 controller`。
- [x] 单元测试：`asset_owner` 缺失在生产配置下失败。
- [x] RPC 测试：`bns.publish_dns_txt` 返回 `submitted` tx，不等待 receipt。
- [x] RPC 测试：跨用户 name 被拒绝。
- [x] RPC 测试：客户端不能指定 controller address。
- [x] 真链路 ignored e2e：注册 -> wait receipt -> indexer sync -> owner 是用户地址 -> controller 可写 `dns_txt` -> 用户 owner 清空 controller policy -> controller 再写失败。

## 验收标准

- 用户只提供 owner EVM 地址，不提供 gas，即可通过 SN 完成 BNS name bootstrap。
- 链上 `NameState.assetOwner` 是用户地址。
- 链上 controller policy 指向 SN 为该用户分配的 controller 地址。
- 注册时必要 documents 已作为初始文档发布，或明确记录哪些文档后续由 proxy 发布。
- BNS proxy 只返回 TX 提交结果，不假装链上成功。
- 用户用自己的 owner 地址发起 `setControllerPolicy` 清空 rules 后，SN controller 不能再发布该用户受保护 doc type。

