# SN-BNS-Controller

`sn_bns_controller` 是 SN 写入 BNS Registry 的封装层。它把 SN 侧已经完成的业务鉴权、owner 签名校验、设备签名校验和自动化任务，转换成 `bns-indexer` 可执行的 `CallAuthority + MutationGuard + DocumentUpdate` 调用。

当本文和当前实现冲突时，以 `doc/SN/新SN核心流程整理.md` 和 `doc/BNS 智能合约接口设计.md` 的设计语义为准；当前 `cyfs-sn` / `bns-indexer` 实现只作为第一版落地路径和迁移参考。

文件名中保留了历史拼写 `Contoller`，模块名和文档正文统一使用 `sn_bns_controller` / `SN-BNS-Controller`。

## 设计定位

`sn_bns_controller` 负责：

- 封装所有 SN 发起的 BNS 写操作。
- 创建 BNS name 时同步写入初始 owner 文档、SN controller key / controller policy。
- 发布 BNS `owner`、`zone`、`boot`、`device_mini_doc`、`dns_txt`、`relay_assignment` 等文档。
- 把 `sn_authority` 输出的权限上下文转换为 BNS `CallAuthority`。
- 维护 BNS 写操作的 `expected_name_seq`、`expected_version`、幂等记录和重试策略。
- 把 BNS 错误映射为 SN API 错误码。
- 约束 SN controller key 只能写被授权的低风险 doc type。
- 为 `sn_auth`、`sn_device_info`、`sn_resolver` 提供统一的 BNS 写入结果和版本信息。

`sn_bns_controller` 不负责：

- 账号密码、登录 token、激活码和 user_domain proof，这些属于 `sn_auth`。
- 设备在线态、IP、from_ip、NAT 状态和 endpoint，这些属于 `sn_device_info`。
- DNS / DID / relay 查询合成，这些属于 `sn_resolver`。
- relay 节点调度和 keep_tunnel 准入，这些属于 `sn_relay_manager`。
- 重复解析 HTTP token、RPC session 或设备 token，这些属于 `sn_authority`。
- 绕过 BNS owner/controller policy 做本地强写。

核心原则：

- BNS 是权威状态，SN 本地 DB 只缓存运行态和兼容数据。
- SN 可以作为 owner 授权请求的提交者，但不能把 SN 登录态等同于 BNS owner。
- SN controller key 是受限自动化权限，只能写 policy 明确允许的 doc type。
- 新提交的文档内容、controller 字段或 owner 字段不能授权本次调用。

## 与 BNS Registry 的关系

`bns-indexer` 当前已经提供下面的核心能力：

- `register_name(name, asset_owner, RegisterOptions, initial_documents, authority, guard)`
- `publish_document(name, DocumentUpdate, authority, guard)`
- `revoke_document(name, doc_type, from_version, to_version, reason_hash, authority, guard)`
- `set_controller_policy(name, Vec<ControllerRule>, policy_hash, authority, guard)`
- `update_authority_keys(name, Vec<AuthorityKeyUpdate>, authority, guard)`
- `resolve_document`、`query_name_state`、`get_authority_set` 等 view 接口。

`sn_bns_controller` 不应重新实现 Registry 状态机，而是调用这些接口，并补足 SN 侧需要的编排能力：

- 注册流程的幂等和恢复。
- 多个 BNS 写操作之间的业务原子性。
- 文档 schema 校验和 canonical JSON 编码。
- SN controller policy 的固定模板。
- 与 SN 本地 DB 的一致性边界。

目标形态中，BNS 侧需要提供一个原子 bootstrap 接口，或者 `sn_bns_controller` 需要在同一 BNS store transaction 中执行注册批处理。原因是当前 `register_name` 只能原子创建 name 和初始文档，不能同时写 authority key 与 controller policy；如果用多个公开调用串起来，中途失败会留下已注册但未授权 SN controller 的半成品状态。

目标 bootstrap 等价操作：

1. `register_name`
2. 发布初始 `owner` 文档。
3. 写入 owner authority keys。
4. 必要时把 `semantic_owner` 切到本 name 或指定 authority name。
5. 写入 SN controller policy。
6. 返回 `name_seq`、初始文档版本、authority root、controller policy hash。

当前中心化实现落地时可以先增加 `CentralizedBnsRegistry::bootstrap_name(...)` 或 `apply_registry_batch(...)`，不要在 SN 业务层用多个无事务公开调用模拟原子注册。

## 权限模型

### 权限上下文

`sn_authority` 输出统一权限上下文，`sn_bns_controller` 只消费结果：

| 权限上下文 | 可转换的 BNS 调用 | 说明 |
| --- | --- | --- |
| `Owner(name)` | `CallAuthority::owner(...)` | 必须证明 actor 是更新前 BNS effective owner。 |
| `Controller(name, doc_type_scope)` | `CallAuthority::controller(...)` | 必须命中 BNS controller policy。 |
| `Device(zone, device_name, did)` | 默认不能直接写 BNS | 只能更新在线态；如需写 BNS，必须有单独 device controller rule。 |
| `SnUser(username)` | 默认不能直接写 BNS | 只代表 SN 本地账号登录。 |

`SnUser(username)` 可以发起流程，但流程中涉及 BNS 写入时，还必须补充 owner 签名、SN controller 授权或明确的 device controller 授权。

### Owner 写入

Owner 级写入适用于：

- 注册 BNS name。
- 写入或替换 `owner` 文档。
- 写入 `zone`、`boot`。
- 注册或替换 `device_mini_doc`。
- 更新 authority key。
- 更新 controller policy。
- 设置 alias、migration、payment 等高风险状态。

转换规则：

- 如果 BNS effective owner 是 `ChainAccount`，当前 `bns-indexer` 只检查 actor 值，`kid` 可以为空；RPC/签名验证必须在 adapter 或 `sn_authority` 中完成。
- 如果 BNS effective owner 是 `BnsName(x)`，必须提供 `kid`，并且该 key 是 `x` authority set 中当前有效的 authentication key。
- `MutationGuard.expected_name_seq` 必须来自更新前的 `NameState.name_seq`。

### SN controller 写入

SN controller 只用于自动化、低风险、可审计的文档更新，例如：

- `dns_txt`: ACME DNS challenge、BNS 域名 TXT 记录、可由 SN 自动维护的 proof TXT。
- `relay_assignment`: 低频 relay 分配结果或可审计调度文档。

第一版不允许 SN controller 写：

- `owner`
- `zone`
- `boot`
- `device_mini_doc`
- `payment`
- alias / migration
- authority key
- controller policy

推荐 controller policy：

| doc_type | permissions | 说明 |
| --- | --- | --- |
| `dns_txt` | `publish_document` | 通过发布新版本维护完整 TXT RRset。 |
| `dns_txt` | `revoke_document` 可选 | 只在需要整体吊销历史版本时启用；删除单条 TXT 应发布新 RRset。 |
| `relay_assignment` | `publish_document` | 写低频、可审计的 relay 分配结果。 |

不要使用 `doc_type = ""` 的通配 controller rule 授权 SN。当前 `ControllerRule` 支持空 doc_type 表示通配，但 SN bootstrap 必须禁止给 SN controller 配置通配规则。

### Device controller 写入

默认不启用 device controller。

如果后续允许设备私钥写自己的 `device_mini_doc`，必须满足：

- controller rule 的 actor 能唯一映射到该设备 DID 或设备 authority name。
- rule 的 `doc_type` 只能是设备相关文档。
- 约束中必须绑定 `zone + device_name + did`，避免设备写其它设备。
- 当前 `bns-indexer` 的 `constraint_hash` 只保存 hash，不执行约束；因此第一版即使写入 hash，也必须由 `sn_bns_controller` 在提交前执行约束校验。

## 核心对象

### SnBnsControllerConfig

目标字段：

- `registry`: BNS registry client 或 `CentralizedBnsRegistry` 引用。
- `sn_controller_principal`: SN controller 的 BNS `Principal`。
- `sn_controller_kid`: SN controller key id。controller 是 `ChainAccount` 时可为空。
- `sn_controller_key_ref`: 本地 KMS / keystore 引用，不直接暴露私钥。
- `allowed_controller_doc_types`: 允许 SN controller 自动写入的 doc type allowlist。
- `max_inline_document_size`: 默认跟随 BNS `MAX_INLINE_DOCUMENT = 4 KiB`。
- `write_retry_limit`: stale version/name seq 的有限重试次数。
- `idempotency_ttl`: 幂等记录保留时间。

### BnsWriteIntent

`sn_bns_controller` 内部使用的写入意图：

- `request_id`: 幂等 key。注册、文档发布和自动化任务都必须有。
- `operation`: `register_name | publish_document | revoke_document | set_controller_policy | update_authority_keys | bootstrap_name`。
- `name`: canonical BNS name，不带 `did:bns:`。
- `doc_type`: 文档操作时必填。
- `authority_context`: `Owner(...)` 或 `Controller(...)`。
- `expected_name_seq`
- `expected_document_version`
- `payload_hash`: canonical payload 的 sha256。
- `deadline`: 可选，防止长期排队请求被错误执行。

### BnsWriteReceipt

写入成功后返回：

- `request_id`
- `name`
- `operation`
- `name_seq`
- `doc_type`
- `document_version`
- `content_hash`
- `document_state_hash`
- `authority_seq`
- `authority_root`
- `controller_policy_hash`
- `created_or_reused`: 表示本次是新写入还是幂等命中旧结果。

调用方必须保存必要的版本信息：

- `sn_auth.zone_info.source_version` 保存 `zone` / `boot` 版本。
- `sn_device_info.device_identity_ref.mini_doc_version` 保存设备文档版本。
- ACME / DNS 任务保存 `dns_txt` 文档版本和 content hash，方便清理和排障。

### 幂等记录

建议本地表：

```sql
CREATE TABLE IF NOT EXISTS sn_bns_write_requests (
    request_id TEXT PRIMARY KEY,
    operation TEXT NOT NULL,
    name TEXT NOT NULL,
    doc_type TEXT NULL,
    payload_hash TEXT NOT NULL,
    state TEXT NOT NULL,
    result_json TEXT NULL,
    error_code TEXT NULL,
    error_message TEXT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
```

规则：

- 同一 `request_id` + 相同 `payload_hash` 已成功时，直接返回旧 receipt。
- 同一 `request_id` + 不同 `payload_hash` 必须拒绝，返回幂等冲突。
- `pending` 记录超时后可以由后台恢复或人工处理，但不能静默重用不同 payload。
- BNS 已成功、本地记录未成功写入时，恢复流程通过查询 BNS state 补齐 receipt。

## BNS 文档类型与 schema

### `owner`

用途：保存 OwnerConfig / user profile 的权威文档引用或短文档。

权限：

- 注册 bootstrap 时写入。
- 后续只能 owner 写。
- SN controller 不能写。

内容：

- 小于 4 KiB 时可使用 `DocumentRef::inline(canonical_json)`。
- 更大时使用外部 URI + `content_hash`，例如 CYFS object、IPFS、HTTPS 或后续 repo provider。

### `zone`

用途：ZoneConfig 权威文档。

权限：

- owner 写。
- SN 可以作为提交者，但必须携带 owner 授权结果。
- SN controller 不能写。

Resolver 依赖：

- `gateway_ips` 如果存在，DNS A/AAAA 优先使用它。
- gateway device 的权威身份应来自 `zone` 或 `boot`，不能长期写死为 `ood1`。

### `boot`

用途：ZoneBootConfig 权威文档。

权限：

- owner 写。
- 通常和 `zone` 成对更新。
- SN controller 不能写。

一致性：

- `bind_zone` 应尽量在一个 BNS batch 内同时发布 `zone` 和 `boot`。
- 如果第一版只能顺序发布，必须用同一个 `request_id` 派生子 key，并在本地记录部分成功状态。

### `device_mini_doc`

用途：设备身份和基础配置的权威文档。

当前 BNS 文档主键是 `(name, doc_type)`，没有独立 document path。第一版推荐使用聚合文档：

```json
{
  "version": 1,
  "devices": {
    "ood1": {
      "did": "did:dev:...",
      "role": "gateway",
      "mini_config_jwt": "...",
      "content_hash": "0x..."
    }
  }
}
```

规则：

- doc_type 固定为 `device_mini_doc`。
- 内容按 `device_name` 聚合，发布新设备时读取当前版本、合并、发布新版本。
- `expected_version` 必须匹配当前 `device_mini_doc` 版本。
- 设备多、文档超过 4 KiB 后，应改为外部文档引用，或把每个设备注册为二级 BNS name，例如 `ood1.alice`，并在该 name 下发布 `device_mini_doc`。

权限：

- 默认 owner 写。
- 兼容当前 `cyfs-sn` 的 `mini_config_jwt` 校验：SN 可以校验该 JWT 是否由 owner key 签发，但只有当该签名能被映射为当前 BNS owner 授权时，才能作为 owner 写入 BNS。
- SN 登录 token 本身不能替代 owner 授权。

### `dns_txt`

用途：BNS name 对应的 TXT RRset。

当前 `bns-indexer::dns_document` 已有 helper：

- `DNS_TXT_DOC_TYPE = "dns_txt"`
- `add_txt_record(current, ttl, value)`
- `txt_records_from_document(state)`
- `txt_records_update(expected_version, records)`

第一版沿用该 schema：

```json
[
  { "ttl": 600, "value": "v=spf1 include:_spf.example.net -all" },
  { "ttl": 60, "value": "_acme-challenge=..." }
]
```

规则：

- `dns_txt` 表示该 BNS name 自身的 TXT RRset。
- 添加或删除单条 TXT 都通过发布完整新 RRset 实现，不直接修改历史版本。
- SN controller 可以写 `dns_txt`，但只能写 allowlist 内的 name，且必须先完成 SN 侧业务校验，例如 ACME challenge 属于该用户/zone。
- 非 BNS `user_domain` 的 DNS proof 仍属于 `sn_auth`，不要强行写入 BNS 作为传统 DNS owner 的替代证明。

### `relay_assignment`

用途：低频、可审计的 zone -> relay 分配文档。

内容示例：

```json
{
  "relay_sn": "sn-relay-1",
  "assigned_at": 1710000000,
  "reason": "auto",
  "policy_hash": "0x..."
}
```

规则：

- `sn_relay_manager` 仍然保存实时 relay 健康状态和调度状态。
- `sn_auth.zone_info.relay_sn` 可以缓存当前分配结果。
- BNS `relay_assignment` 只保存需要被 resolver 或审计方看到的低频分配结果。
- SN controller 可以写，但不能用它改变 owner、zone、boot 或 device identity。

## 对外接口

下面是目标接口语义，具体 Rust trait 可按现有 crate 结构调整。

### bootstrap_name

输入：

- `request_id`
- `name`
- `asset_owner`
- `register_options`
- `owner_config`
- `owner_authority_keys`
- `sn_controller_policy`
- `initial_documents`
- 注册许可上下文，例如 active_code 校验结果或 registrar policy 结果。

输出：

- `BnsWriteReceipt`
- 初始文档版本集合。

行为：

1. 规范化 `name`。
2. 校验注册许可和 payload hash。
3. 构造初始 `owner` document。
4. 构造 SN controller rule，只允许明确 doc type。
5. 在 BNS 侧执行原子 bootstrap。
6. 写入幂等成功记录。

### publish_owner_document

输入：

- `request_id`
- `name`
- `owner_config`
- `authority_context = Owner(name)`

行为：

- 读取当前 `owner` 文档版本。
- 构造 `DocumentUpdate(doc_type="owner", expected_version=current_version)`。
- 使用 owner authority 发布。
- SN controller 不允许调用。

### bind_zone_documents

输入：

- `request_id`
- `name`
- `zone_config`
- `boot_config`
- `authority_context = Owner(name)`

行为：

- 校验 `zone_config` / `boot_config` schema。
- 校验文档签名与当前 owner authority 一致。
- 读取 `NameState.name_seq` 和当前 `zone` / `boot` 版本。
- 发布 `zone` 和 `boot`。
- 返回两个文档版本。

### publish_device_mini_doc

输入：

- `request_id`
- `name`
- `device_name`
- `did`
- `device_mini_doc`
- `authority_context = Owner(name)`，或显式 device controller。

行为：

- 校验 `did`、`device_name`、公钥和 mini doc 内容一致。
- 读取当前聚合 `device_mini_doc`。
- 合并或替换对应 `device_name` 项。
- 发布新 `device_mini_doc` 版本。
- 返回版本和 content hash，供 `sn_device_info` 写入本地索引。

### upsert_dns_txt

输入：

- `request_id`
- `name`
- `ttl`
- `value`
- `mode = add | remove | replace`
- `authority_context = Controller(name, dns_txt)` 或 `Owner(name)`。

行为：

- 读取当前 `dns_txt`。
- 使用 `dns_document` helper 解析 records。
- add 时去重，remove 时删除匹配值，replace 时替换整个 RRset。
- 发布新版本。
- 遇到 `STALE_DOCUMENT_VERSION` 时有限重试：重新读取、重新合并、再次提交。

### publish_relay_assignment

输入：

- `request_id`
- `name`
- `relay_assignment`
- `authority_context = Controller(name, relay_assignment)` 或 `Owner(name)`。

行为：

- 校验 relay id 来自 `sn_relay_manager` 的有效节点。
- 发布新 `relay_assignment`。
- 成功后由调用方更新本地 `zone_info.relay_sn` 缓存。

## 核心流程

### 注册 SN 用户和 BNS name

目标输入来自 `sn_api_gateway`：

- `username`
- `password` 或 password credential。
- `active_code`
- `owner public keys`
- `owner_config`
- `request_id`

流程：

1. `sn_auth` 校验 username、active_code、本地账号不存在。
2. `sn_authority` 或注册 adapter 校验 owner key 格式和注册签名。
3. `sn_bns_controller.bootstrap_name` 创建 BNS name、owner 文档、authority key、SN controller policy。
4. BNS 成功后，`sn_auth.register_user_v2` 在本地事务中写入账号和密码凭证。
5. 返回登录 token、BNS name 状态和 `need_bind_owner_key=false` 或实际 owner key 状态。

一致性要求：

- `request_id` 必填。
- BNS bootstrap 成功但 `sn_auth` 写入失败时，账号进入恢复流程：再次注册同一 `request_id` 应补齐本地账号；不同 payload 必须拒绝。
- `sn_auth` 不得在 BNS bootstrap 失败时创建 active 账号并声称拥有 BNS name。

当前实现差异：

- `cyfs-sn` V2 `auth.register` 只写本地 `users` 和 `user_auth_v2`。
- 新实现应在 `register_user_v2` 之前调用 `sn_bns_controller.bootstrap_name`。
- 当前返回的 `need_bind_owner_key=true` 是兼容状态；目标流程中 owner key 应随 BNS bootstrap 一起完成。

### bind zone

目标输入：

- `zone_config`
- `zone_boot_config`
- owner 授权。

流程：

1. `sn_authority` 输出 `Owner(name)`。
2. `sn_bns_controller` 校验两个文档的 schema、签名、zone name 和 BNS name 一致。
3. 发布 BNS `zone`。
4. 发布 BNS `boot`。
5. 成功后，`sn_auth.zone_info` 只缓存运行态字段和 BNS source version，不再把 `zone_config` 当权威存储。

当前实现差异：

- `zone.bind_config` 目前只写 `users.zone_config`，并依赖 `users.public_key`。
- 目标实现中 `users.zone_config` 只能作为迁移缓存或 UI fallback，权威数据来自 BNS。

### 注册设备

目标输入：

- `zone`
- `device_name`
- `did`
- `device_mini_doc` / `mini_config_jwt`
- 设备在线上报信息。
- owner 授权或明确 device controller 授权。

流程：

1. `sn_authority` 校验 owner、SN session + owner 签名，或 device token。
2. `sn_bns_controller` 校验 mini doc 与 `did`、`zone`、`device_name` 一致。
3. 发布或更新 BNS `device_mini_doc`。
4. `sn_device_info` 写入 `device_identity_ref` 和初始 `device_runtime_info`。
5. 返回设备身份版本和当前在线态。

一致性要求：

- 如果本地在线态先写入，必须使用 `pending_bns_publish` 状态；BNS 发布失败时不能让 resolver 把该设备当成权威 gateway。
- 推荐 BNS 发布成功后再激活本地 identity ref。
- Device 私钥默认只能更新在线态，不能替换 `device_mini_doc`。

当前实现差异：

- `device.register` 目前校验 `mini_config_jwt` 后写本地 `devices` 表。
- 新实现应把 `mini_config_jwt` 作为 BNS `device_mini_doc` 输入，成功后再写本地 runtime cache。

### ACME / DNS TXT 写入

目标输入：

- `name`
- `txt_value`
- `ttl`
- ACME challenge 上下文。

流程：

1. `sn_acme_client` 请求写入 TXT。
2. `sn_authority` 为 SN 自动任务输出 `Controller(name, dns_txt)`。
3. `sn_bns_controller.upsert_dns_txt` 使用 SN controller key 发布新 `dns_txt`。
4. DNS Server 经 `sn_resolver` 读取 BNS `dns_txt` 并返回 TXT answer。
5. ACME 完成后可发布新版本删除 challenge TXT。
6. 证书状态写回 `sn_auth.zone_info.self_cert`。

注意：

- `self_cert` 是本地运行态，不写入 BNS。
- 删除 TXT 不应 revoke 整个 `dns_txt` 历史；应发布新的 RRset。
- 自定义 `user_domain` 的传统 DNS proof 仍由 `sn_auth` 管理，不能把 BNS TXT 当成传统域名 owner 证明。

### relay assignment 写入

目标输入：

- `name`
- `relay_sn`
- 调度原因和 policy hash。

流程：

1. `sn_relay_manager` 计算或人工指定分配结果。
2. `sn_authority` 输出 `Controller(name, relay_assignment)`。
3. `sn_bns_controller.publish_relay_assignment` 发布低频分配文档。
4. `sn_auth.zone_info.relay_sn` 缓存当前结果。
5. relay 节点运行时状态仍由 `sn_relay_manager` 管理。

## 并发、重试和一致性

### version guard

每次写 BNS 前必须读取：

- `NameState.name_seq`
- 当前 `(name, doc_type)` 的 `DocumentState.version`
- 必要时读取 parent name seq。

发布文档时：

- `MutationGuard.expected_name_seq = 当前 name_seq`
- `DocumentUpdate.expected_version = 当前文档版本，缺失则为 0`

遇到 stale 错误：

- `STALE_DOCUMENT_VERSION`: 重新读取文档，重新计算 payload；如果业务语义仍成立，有限重试。
- `STALE_NAME_SEQ`: 重新读取 name state；如果 owner/controller policy 未改变且 payload 仍成立，有限重试。
- 超过重试次数后返回冲突，让调用方重新发起。

### 本地锁

为了减少写冲突，`sn_bns_controller` 可以在 SN 进程内加轻量锁：

- 注册和 name 级操作按 `name` 加锁。
- 文档更新按 `(name, doc_type)` 加锁。
- 该锁只优化本进程并发，不能替代 BNS version guard。

### BNS 与本地 DB 顺序

推荐顺序：

- 权威身份和文档：先 BNS 成功，再写本地缓存。
- 纯运行态：先本地写，必要时异步发布低频 BNS 文档。
- 注册：BNS bootstrap 成功后再创建 active 本地账号；失败恢复由幂等记录处理。

不得出现的状态：

- 本地账号 active，但 BNS name 未创建，且 API 告诉用户已拥有 BNS owner 权限。
- 本地 device identity active，但 BNS `device_mini_doc` 未发布。
- SN controller policy 缺失时仍执行 ACME 自动写 TXT。

## 错误映射

`sn_bns_controller` 应保留 BNS 原始错误码，并映射为 SN API 可理解的错误。

| BNS error code | SN 语义 |
| --- | --- |
| `INVALID_NAME` | username / BNS name 非法。 |
| `NAME_ALREADY_EXISTS` | BNS name 已存在；注册流程进入恢复或返回冲突。 |
| `NAME_NOT_FOUND` | BNS name 不存在；本地账号可能需要修复。 |
| `DOCUMENT_NOT_FOUND` | 文档不存在；读取场景返回 not found，写入场景可按 version 0 创建。 |
| `STALE_NAME_SEQ` | 并发冲突；可重试或返回 409。 |
| `STALE_DOCUMENT_VERSION` | 文档并发冲突；读改写流程可重试。 |
| `NOT_EFFECTIVE_OWNER` | owner 授权无效或已轮换。 |
| `CONTROLLER_SCOPE_DENIED` | SN controller policy 缺失或 doc type 未授权。 |
| `INVALID_KID` | authority key 不存在、过期或用途不匹配。 |
| `INLINE_DOCUMENT_TOO_LARGE` | 应改用外部 DocumentRef 或缩小文档。 |
| `OWNER_GRAPH_CYCLE` / `NO_CONCRETE_SIGNER` / `OWNER_GRAPH_TOO_DEEP` | owner 图非法，必须拒绝。 |

SN API 响应中建议包含：

- `code`: SN 兼容错误码。
- `bns_code`: BNS 原始错误码。
- `name`
- `doc_type`
- `expected` / `actual`，用于 stale 错误排障。

## 当前实现映射

### `cyfs-sn`

当前实现中需要迁移到 `sn_bns_controller` 的写入点：

- `v2/auth.rs::auth.register`: 从只写本地账号，改为先 bootstrap BNS name。
- `v2/zone.rs::zone.bind_config`: 从写 `users.zone_config`，改为发布 BNS `zone` / `boot`，本地只缓存运行态。
- `v2/device.rs::device.register`: 从写本地 `devices.mini_config_jwt`，改为发布 BNS `device_mini_doc` 后写本地在线态。
- `v2/dns.rs::dns.add_record/remove_record`: BNS name 的 TXT 记录改为发布 `dns_txt`；传统 `user_domain` 记录继续走 `sn_auth`，直到 domain proof 和传统 DNS owner 机制完成。
- `v2/did.rs::did.set_document`: 对标准 doc type 应改为 BNS `publish_document`；本地 `did_documents` 只保留兼容缓存或非权威草稿。

### `bns-indexer`

当前可直接复用：

- `DocumentRef::inline`
- `default_document_update`
- `dns_document` helper
- `controller_rule`
- `policy_hash_from_rules`
- `MutationGuard`
- `CallAuthority`
- `ControllerRule::permits`

当前缺口：

- 注册时缺少 authority key + controller policy 的原子 bootstrap。
- `constraint_hash` 尚未执行约束校验，SN 侧必须自己校验。
- `dns_document` 只有 add helper，删除 / replace RRset 需要补 helper 或在 SN 侧解析后构造完整 update。
- 文档 schema helper 还只有 `dns_txt`，`zone`、`boot`、`device_mini_doc` 需要补 canonical encoder / validator。

## 第一版落地步骤

1. 在 `bns-indexer` 增加 bootstrap/batch 接口，保证注册、初始文档、authority key、controller policy 原子提交。
2. 新建 `sn_bns_controller` 模块，封装 registry client、幂等表、错误映射和版本重试。
3. 增加 `zone`、`boot`、`device_mini_doc`、`dns_txt` 文档 schema helper。
4. 在 `auth.register` 中接入 `bootstrap_name`。
5. 在 `zone.bind_config` 中接入 `bind_zone_documents`。
6. 在 `device.register` 中接入 `publish_device_mini_doc`，并把本地设备记录降级为 runtime cache。
7. 在 ACME / DNS TXT 流程中接入 `upsert_dns_txt`。
8. 给 SN controller policy 加固定 allowlist，禁止 wildcard controller。
9. 增加 admin / repair 命令，用于修复 BNS 已成功但本地 DB 未完成的注册。

## 测试要求

`bns-indexer` 层：

- controller policy 只能允许指定 doc type。
- SN controller 不能发布 `owner`、`zone`、`boot`、`device_mini_doc`。
- owner 可以发布所有文档。
- stale `expected_version` / `expected_name_seq` 会被拒绝。
- bootstrap 注册要么完全成功，要么不留下半成品 policy。

`sn_bns_controller` 层：

- 同一 `request_id` 重放返回同一 receipt。
- 同一 `request_id` 不同 payload 返回幂等冲突。
- `dns_txt` add/remove 在并发 stale 后能有限重试并保持去重。
- BNS `CONTROLLER_SCOPE_DENIED` 映射为 SN 权限错误。
- BNS 成功、本地幂等记录丢失时可以通过查询 BNS state 恢复。

端到端：

- 注册用户后能在 BNS 查询到 name、owner 文档和 SN controller policy。
- bind zone 后 resolver 从 BNS `zone` / `boot` 解析 gateway device。
- 注册设备后 `sn_device_info` 缓存带有 BNS `device_mini_doc` 版本。
- ACME 写入 TXT 后 DNS 查询能返回 BNS `dns_txt`。
