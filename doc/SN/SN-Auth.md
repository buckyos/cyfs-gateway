# SN-Auth

`sn_auth` 是 SN 的账号与低频用户状态模块。它负责 SN 本地账号体系、登录态、`sn_user <-> user_domain` 绑定关系，以及不适合放入 BNS 权威文档的 `zone_info` 运行态。

当本文和当前实现冲突时，以 `doc/SN/新SN核心流程整理.md` 中的设计意图为准；当前实现只作为差距对照，不作为兼容约束。本版本是 breaking change，不要求兼容旧 RPC alias、旧 token 语义或旧 `user_domain` 绑定方式。

## 设计定位

`sn_auth` 负责：

- 用户名、密码凭证、激活码和登录 token。
- `sn_user` 的本地状态，例如 active、suspended、deleted、banned。
- `sn_user <-> user_domain` 的绑定关系、历史冲突检查和 PKX proof 状态。
- `zone_info` 中的本地运行态，例如 `self_cert`、当前 `relay_sn` 分配结果、历史实现中的 `sn_ips`。
- 为 `sn_authority` 提供 SN 登录 token 的签发和校验基础。
- 为 `sn_resolver` 提供非 BNS 域名到 `sn_user` 的映射。
- 为 SN Admin 提供激活码管理、传统账号冻结、密码恢复等本地账号能力。

`sn_auth` 不负责：

- BNS name、owner key、controller key、controller policy 的权威状态。
- 发布 BNS `zone`、`boot`、`device_mini_doc`、`dns_txt` 文档。
- 设备在线态、device IP、NAT 状态和 keep-alive 状态。
- relay 节点健康状态和 zone -> relay 调度决策。
- 把 SN 登录 token 提升为 BNS owner 权限。

这些能力分别属于 `bns-indexer`、`sn_bns_controller`、`sn_device_info`、`sn_relay_manager` 和 `sn_authority`。

## 权限原则

SN Auth 的核心权限边界是：

- SN 登录 token 只代表 `SnUser(username)`。
- `SnUser(username)` 可用于 UI 管理、账号资料、低风险本地状态查询和发起需要二次授权的流程。
- `SnUser(username)` 不天然等价于 BNS owner。
- 涉及 BNS owner 权限的操作，必须由 owner ETH 私钥、BNS authority key，或 BNS controller policy 授权的 SN controller key 完成。
- device 私钥签名 token 只能得到 `Device(zone, device_name, did)` 权限，默认不能写 BNS owner 级状态。
- 账号恢复、密码找回、激活码清理只能恢复 SN 登录能力，不能绕过 BNS owner key。

`sn_authority` 应统一验证 token 和签名，并输出权限上下文。业务模块不应散落解析 token。`sn_auth` 只负责签发/存储 SN 用户会话和提供账号资料。

## 核心对象

### sn_user

`sn_user` 是 SN 本地账号。`username` 同时通常映射到 BNS name，但 BNS name 的权威所有权仍在 BNS。

目标字段：

- `username`: 规范化后的唯一用户名。
- `state`: `active | suspended | deleted | banned`。
- `bns_name`: 绑定的 BNS name，默认等于 `username`。
- `activation_code`: 注册或测试清理使用的许可码。
- `owner_key_ref`: 本地缓存的 owner public key 或 key id，仅用于 UI 状态和签名校验辅助。
- `created_at` / `updated_at` / `last_login_at`。

当前实现映射：

- `src/components/cyfs-sn/src/sn_auth.rs:294-308` 的 `users` 表已含全部目标字段：`username`、`state`、`bns_name`、`public_key`、`activation_code`、`owner_key_ref`、`zone_config`、`self_cert`、`user_domain`、`sn_ips`、`created_at`、`updated_at`、`last_login_at`。
- `state` 枚举（active/suspended/deleted/banned）已建模（sn_auth.rs:21-53）。
- `public_key` 当前存 JWK 字符串，未来应视为本地缓存，不作为 BNS authority 的最终来源。
- 待实现（阶段二）：`owner_key_ref` 列虽已建，但所有 insert 路径都置 NULL，从不写入（sn_auth.rs:1041、1206）；`public_key` 仍是事实上的 owner key 来源。

### password_credential

密码凭证属于 SN 本地账号体系。

目标字段：

- `username`
- `password_hash`
- `password_salt`
- `password_algo`
- `created_at`
- `updated_at`
- `last_login_at`

当前实现（阶段一已完成）：

- `user_auth_v2` 表保存上述全部字段（sn_auth.rs:316-324）。
- V2 使用 `pbkdf2-sha256-100000`，salt 为 16 字节随机值，hash 为 32 字节结果的 hex（sn_v2_auth.rs:16-17、97-101、195-210）。

服务端不得存储明文密码。RPC 参数名里历史上使用 `pwd_hash`，但当前 V2 实际会把该值再次 PBKDF2 后保存（register/login 直接把 `pwd_hash` 喂给 `hash_password`/`verify_password`，auth.rs:71、116）；后续接口命名应澄清为 `password` 或明确客户端预哈希语义，避免“双 hash”语义不清。

### account_session

SN 登录态是 `SnUser(username)` 的证明。

目标字段和约束：

- `sub`: username。
- `aud`: access token 使用 `sn-v2`，refresh token 使用 `sn-v2-refresh`。
- `exp`: access token 短期有效，refresh token 较长有效。
- `kid`: token signing key id，便于后续 key rotation。
- `session_id` 或 `jti`: 便于 logout、撤销和审计。

当前实现：

- `SnV2AuthManager` 使用 Ed25519 key 签发 JWT，`sub`=username、`aud`=`sn-v2`/`sn-v2-refresh`、`exp`（sn_v2_auth.rs:12-15、70-94、146-176）。
- access token 默认 1 小时，refresh token 默认 24 小时。
- token key 存在 `sn_v2_token_key/private_key.pem` 和 `public_key.json`。
- 阶段一已完成：`account_sessions` 撤销表已建（sn_auth.rs:383-402），`create_account_session`/`revoke_account_session`/`revoke_user_sessions`/`get_account_session` 方法已实现（sn_auth.rs:2043-2136），`set_user_state` 置非 active 时自动撤销该用户 session（sn_auth.rs:1378-1380）。
- 待实现（阶段二）：token 不含 `kid` 和 `session_id`/`jti`；签发路径（`build_auth_success_response`，auth.rs:12-29）从不调用 `create_account_session`，校验路径（sn_v2_auth.rs:88-94、178-193）也从不检查 session 状态，因此撤销表目前是“建好但未接线”的死代码；`auth.logout` 仍是空操作（auth.rs:148）。

### user_domain

`user_domain` 是传统 DNS 域名到 `sn_user` 的绑定关系，暂归 `sn_auth` 管理。

目标字段：

- `domain`: 规范化域名，去掉尾部 `.`，统一小写。
- `owner`: 绑定的 `sn_user`。
- `state`: `pending_pkx | active | revoked | rejected`。
- `pkx`: 期望在传统 DNS 中看到的 `PKX(sn_user.pkx)`。
- `pkx_record_name`: 按 PKX 规范计算出的 DNS TXT name。
- `verified_at`
- `created_at` / `updated_at`

PKX 是 `user_domain` 唯一的证明方法。它不是一次性随机挑战，也不需要 nonce 或过期时间。用户参与一次，在传统 DNS 中写入稳定的 PKX 记录；SN 后续接管该域名 DNS 基础设施后，也继续写入同一个 PKX，因此绑定证明不会因为挑战记录切换带来解析抖动。

当前实现映射（阶段一已完成）：

- 已新增独立 `user_domain_bindings` 表，含 `domain`、`owner`、`state`、`pkx`、`pkx_record_name`、`verified_at`、`created_at`、`updated_at`，state 取值 `pending_pkx | active | revoked`（sn_auth.rs:342-355、13-15）。
- `users.user_domain` 仍保存当前绑定域名（作兼容缓存）。
- `user_domain_history` 保存历史绑定，用于冲突检查（sn_auth.rs:331-339）。
- `canonical_user_domain` 会去掉 `*.` 前缀、小写、去尾点（sn_auth.rs:443-455）。
- 冲突检查会阻止同一域名、祖先域名、子域名被不同用户历史绑定（sn_auth.rs:695-757）。
- `pending_pkx` 状态已持久化；PKX 计算与 TXT 比对的 DB 层逻辑已实现（`pkx_record_name`/`pkx_value`/`txt_matches_pkx`，sn_auth.rs:457-473；`create_pkx_binding`/`verify_pkx_binding`，sn_auth.rs:1616-1840）。

待实现（阶段二）：

- PKX proof 仅在 DB 层实现，`create_pkx_binding`/`verify_pkx_binding` 没有任何 RPC handler 调用，`verify_pkx_binding` 的 `txt_records` 参数也没有 DNS TXT 查询接线，端到端不可达。
- `PKX(sn_user.pkx)` 的输入仍来自本地 `users.public_key`（或未写入的 `owner_key_ref`），尚未对接 BNS owner_config / authority key。

### zone_info

`zone_info` 是 SN 本地运行态缓存，不是 BNS 权威文档。

目标字段：

- `username` / `bns_name`
- `zone`: zone name 或 DID。
- `relay_sn`: 当前分配的 relay SN。
- `self_cert`: 当前是否有可用自签/ACME 证书。
- `cert_checked_at` / `cert_expires_at`
- `sn_ips`: 历史实现中的 SN IP 列表，迁移期可作为数据来源。
- `source_version`: 从 BNS `zone`/`boot` 更新缓存时使用的版本信息。
- `updated_at`

当前实现映射（阶段一已完成）：

- 已新增独立 `zone_info` 表，含全部目标字段 `username`、`bns_name`、`zone`、`relay_sn`、`self_cert`、`cert_checked_at`、`cert_expires_at`、`sn_ips`、`source_version`、`updated_at`（sn_auth.rs:365-380）。
- `get_zone_info`/`update_zone_info`（patch 语义）与从 `users` 回填的 backfill 已实现（sn_auth.rs:1883-2014、548-600）。
- 兼容期 `update_zone_info` 仍会把 `zone`/`self_cert`/`sn_ips` 双写回 `users` 表（sn_auth.rs:1993-2008）。
- `users.zone_config` 当前仍保存旧 `zone_config`/boot JWT。目标架构中，`zone` 和 `boot` 应进入 BNS 文档，`sn_auth` 只保存必要运行态缓存。

## 数据归属

属于 `sn_auth` 的数据：

- 激活码及使用状态。
- SN 用户、密码凭证、登录态元数据。
- 用户状态、传统账号恢复状态、冻结/解冻状态。
- `user_domain` 绑定、历史冲突记录和 PKX proof 状态。
- `zone_info` 本地运行态，例如 `self_cert`、`relay_sn`、`sn_ips`。

不属于 `sn_auth` 的数据：

- BNS owner/controller authority key。
- BNS controller policy。
- BNS `zone`、`boot`、`device_mini_doc`、`dns_txt` 文档。
- 设备在线态和可达 IP。
- relay 健康状态和调度策略。

## 注册流程

### 注册 SN 用户和 BNS owner

目标输入：

- `username`
- owner public keys，至少包含 BNS/ETH owner key 和后续文档签名所需 key。
- `owner_config`
- `password` 或明确约定的 password credential。
- `active_code`
- `request_id`，作为注册幂等 key。

目标流程：

1. `sn_auth` 规范化并校验 `username`。
2. `sn_auth` 检查 `active_code` 未使用。
3. `sn_auth` 检查本地账号不存在。
4. `sn_bns_controller` 调用 `bns-indexer.register` 创建 BNS name。
5. BNS 创建阶段同步发布 owner_config，并设置 SN controller key 和受限 controller policy。
6. BNS 注册成功后，`sn_auth.register` 在一个本地事务中写入 `sn_user`、`password_credential`，并标记激活码已使用。
7. 返回 access token、refresh token 和 BNS name 状态。

一致性要求：

- BNS 注册请求必须有幂等 key。
- `sn_auth` 本地写入必须是事务性的。
- 如果 BNS name 已存在但 `sn_auth` 未完成，应进入明确恢复流程：继续补齐本地账号，或由 admin 标记人工处理。
- 不能出现本地账号注册成功但 BNS name 未创建、且系统误认为用户拥有 BNS owner 权限的状态。

当前实现：

- 阶段一已完成：`register_user_v2` 在命名锁下用事务完成 `users`、`user_auth_v2`、`zone_info`、`activation_codes.used` 的一致写入（sn_auth.rs:989-1091），返回 access+refresh token 并提示 `need_bind_owner_key=true`（auth.rs:89）。
- 待实现（阶段二）：V2 `auth.register` 只写本地 DB，没有调用 `sn_bns_controller` / `bns-indexer.register`（`bns_indexer_url` 只接入了 resolver 读路径，sn_server.rs:688-693），没有 `request_id` 幂等 key，也没有“BNS name 已存在但本地未完成”的恢复流程。

### public key 注册

当前实现中的 `user.register_by_public_key` / `register_user` 支持：

- `user_name`
- `public_key`
- `active_code`
- 可选 `zone_config`
- 可选 `user_domain`

该路径不作为新版本目标接口保留。新架构中，注册 BNS owner 必须走完整的 BNS 注册流程；`public_key` 本地写入不能替代 BNS authority key。

## 登录流程

目标输入：

- `username`
- `password`

目标流程：

1. 规范化 `username`。
2. 查询 `password_credential`。
3. 校验用户存在且状态为 `active`。
4. 校验密码。
5. 更新 `last_login_at`。
6. 签发 access token 和 refresh token。
7. 返回 `need_bind_owner_key`、profile 摘要和必要的 BNS name 状态。

当前实现：

- 阶段一已完成：V2 `auth.login` 不再依赖 `active_code`。`LoginReq.active_code` 已改为可选且 login 分支从不读取它，只做用户 active 校验 + 密码校验 + 更新 `last_login_at`（auth.rs:91-133，common.rs:39-45）。`need_bind_owner_key` 由 `public_key` 是否为空推导。
- 待实现（阶段二）：`auth.logout` 仍未撤销 token；撤销表已建但签发/校验路径未接线（见 account_session 小节）。目标实现应支持基于 `session_id`/`jti` 的撤销，至少能撤销 refresh token。

## owner key 绑定

`user.bind_owner_key` 当前把 JWK public key 写入 `users.public_key`。

目标语义：

- 首次绑定 owner key 可以作为注册后补齐资料流程的一部分。
- 绑定后的 key 用于客户端签名校验和 UI 状态展示。
- BNS authority key 的权威来源必须是 BNS，不是 `users.public_key`。
- owner key rotation 必须走 BNS authority/controller 机制，不能只更新 `users.public_key`。

当前接口可继续保留，但涉及 BNS 文档写入时必须通过 `sn_authority` 得到 `Owner(name)` 或 `Controller(name, doc_type_scope)`。

## bind zone

目标输入：

- `zone_config`
- `zone_boot_config`
- owner 签名，或可由 `sn_authority` 映射为 owner authority 的 token。

目标流程：

1. `sn_authority` 校验 owner 权限。
2. `sn_bns_controller` 校验 `zone_config` 和 `zone_boot_config` 的签名与内容一致性。
3. 发布 BNS `zone` document。
4. 发布 BNS `boot` document。
5. 根据 zone/boot 内容更新 `sn_auth.zone_info` 中的运行态缓存。

`sn_auth` 在该流程中只负责最后一步的本地运行态缓存更新，不负责判断 BNS owner 权限，也不直接发布 BNS 文档。

当前实现差异（待实现项归阶段二）：

- V2 `zone.bind_config` 要求 SN access token 和本地 `public_key` 已绑定，然后直接更新 zone_info/`users.zone_config`（zone.rs:31-53）。这里的“owner”只是本地 `public_key`，不是 BNS authority。
- 旧 `bind_zone_config` 使用 owner public key 验证 RPCSessionToken（sn_server.rs:1114-1132 等），但校验仍偏简化。
- 绕过风险（阶段二待修）：`zone.bind_config` 仍可同时写 `user_domain` 且不强制 PKX proof，`update_user_domain` 直接把 binding 置 `active`（zone.rs:46-52，sn_auth.rs:1418-1519）；`register_user_with_owner_key` 同样无证明就插入 `active` binding（sn_auth.rs:1240-1263）。
- 当前没有发布 BNS `zone` / `boot` 文档。
- 当前 `zone_config` 字段应视为历史 boot JWT 字段，目标上应由 BNS 权威文档替代。

## user_domain 绑定和 PKX proof

`user_domain` 用于把非 BNS 的传统 DNS 域名绑定到 `sn_user`。该绑定属于 `sn_auth`，但必须证明传统 DNS owner 同意绑定。

### 绑定输入

- `username`
- `domain`
- 当前登录态 `SnUser(username)`

### 目标流程

1. 规范化 `domain`：去尾点、小写、去掉可选 `*.` 前缀得到 canonical domain。
2. 检查 `sn_user` 存在且状态为 `active`。
3. 检查历史冲突：
   - 同一 canonical domain 已被其他用户绑定过，拒绝。
   - canonical domain 的祖先域名已被其他用户绑定过，拒绝。
   - canonical domain 的子域名已被其他用户绑定过，拒绝。
4. 计算期望的 `PKX(sn_user.pkx)`。
5. 进入 `pending_pkx` 状态，并返回固定的 `pkx_record_name` 和 `pkx`。
6. 用户在传统 DNS 中发布该 PKX TXT 记录。
7. SN 查询 DNS TXT 并校验：
   - TXT 出现在 PKX 规范要求的 DNS name。
   - TXT 值等于当前 `sn_user` 的 `PKX(sn_user.pkx)`。
8. 校验成功后，把 `user_domain.owner = sn_user`，状态改为 `active`。
9. 写入 `user_domain_history`，用于后续冲突检查和审计。

### PKX 记录格式

PKX 记录格式只由一个统一 helper 生成和解析。`sn_auth` 不支持额外证明类型，不支持用户自定义证明载荷，不支持 nonce/exp 变种。

```text
<PKX(sn_user.pkx)>
```

`PKX(sn_user.pkx)` 的具体编码应由统一 helper 生成，不能由不同模块重复实现。当前实现中最接近的输入是 `users.public_key` JWK；目标上应来自 BNS owner_config 或 BNS authority key 对应的公开身份。

PKX 记录是稳定状态，不是临时验证状态。SN 接管 DNS 基础设施后，仍应继续发布同一条 PKX 记录；这样从用户自管 DNS 迁移到 SN 托管 DNS 时，不需要替换 proof，也不会引入解析行为抖动。

### 解绑语义

解绑只取消当前 `users.user_domain` 或 `user_domain.active` 状态，不应默认删除 `user_domain_history`。历史记录用于阻止域名和子域名在不同用户之间被反复抢占。

如果未来需要域名转让，应设计显式 transfer 流程，并要求旧 owner 和新 owner 都完成授权或管理员介入。

### 当前实现差异

阶段一已完成：

- `update_user_domain` 已有全局锁和历史冲突检查（sn_auth.rs:1418-1519）。
- `user_domain_history` 已记录 canonical domain 和 owner。
- `pending_pkx` 状态与 PKX TXT 校验的 DB 层逻辑已实现：`create_pkx_binding` 写 `pending_pkx`、`verify_pkx_binding` 比对 TXT 后置 `active`、`unbind_user_domain` 置 `revoked`（sn_auth.rs:1616-1881）。
- `get_user_by_domain` 已按 active binding 最长匹配 + legacy `users.user_domain` 回退查询 owner（sn_auth.rs:1327-1367）。

待实现（阶段二）：

- PKX proof 没有 RPC handler，也没有 DNS TXT 查询接线，端到端不可达。
- V2 `zone.bind_config` 与 `register_user_with_owner_key` 仍可不经 proof 把 `user_domain` 置 active（绕过风险，见 bind zone 小节）。

## user DNS records

当前实现有 `user_dns_records`，用于保存用户域名下的 DNS 记录：

- `(owner, domain, record_type)` 唯一。
- `add_user_domain` 用 upsert 写入 record 和 ttl。
- `remove_user_domain` 删除指定 record type。
- `dns.add_record` / `dns.remove_record` 会检查 domain 是否属于当前用户可管理范围。

目标边界：

- `user_domain` 绑定关系仍属于 `sn_auth`。
- DNS 查询合成属于 `sn_resolver`。
- 对 BNS 域名的 `dns_txt` 发布应由 `sn_bns_controller` 使用 SN controller key 写 BNS 文档。
- 对传统 `user_domain` 的本地辅助记录可以继续放在 SN 本地 DB，但必须基于 active PKX 绑定授权。

域名授权规则：

- 如果用户已完成 active PKX 绑定，只能管理该 domain 或其子域名。
- 如果没有 active `user_domain`，不能通过 `user_domain` 路径管理传统 DNS 域名。
- 默认 BNS/web3 命名空间不属于传统 `user_domain` 证明范围，应走 BNS `dns_txt` 或其他 BNS 文档流程。
- ACME challenge 记录应只允许写入符合该用户域名边界的 `_acme-challenge.*`，不能借设备 token 写入任意域名。

## zone_info 更新

`zone_info` 是运行态缓存，典型更新来源：

- bind zone 成功后，从 BNS `zone`/`boot` 文档同步基础缓存。
- `sn_relay_manager` 调整 zone -> relay 分配后写入 `relay_sn`。
- `sn_acme_client` 完成证书签发后写入 `self_cert=true` 和证书时间。
- 证书校验失败或证书过期巡检时写入 `self_cert=false`。

权限要求：

- `self_cert` 不能仅因客户端声明就永久置 true；应由 ACME 成功结果、证书有效性校验或受信任 device 上报驱动。
- device 上报 `self_cert` 时，必须由 `sn_authority` 校验 device token，得到 `Device(zone, device_name, did)`。
- `relay_sn` 应由 `sn_relay_manager` 写入，用户 session token 不能直接设置。

当前实现：

- 阶段一已完成：`update_zone_info` 提供 patch 写入，`update_user_self_cert` 走该统一入口（sn_auth.rs:1407-1416、1916-2014）。
- 待实现（阶段二，绕过风险）：`user.set_self_cert` V2 用裸 access token 即可把 `self_cert` 置 true（user.rs:59-67），`dns.add_record` / `dns.remove_record` 在 `has_cert=true` 时同样置 true（dns.rs:88-93、121-127），均无证书校验或可信 device 证明。
- 旧 `set_user_self_cert` 支持 device-signed token，会按 (user, device_name) 解析设备并用设备 DID 的 ed25519 key 校验 token 签名（sn_server.rs:2209-2232），但只产生本地效果，不产生 `Device(zone,device,did)` 上下文。
- 目标实现应把这些入口收敛到 `sn_authority + update_zone_info`，并记录审计事件。

## Admin 能力

### 激活码

目标能力：

- 生成激活码。
- 查询未使用激活码。
- 禁用或回收激活码。
- 审计激活码发放和使用。

当前实现（阶段一已完成）：

- `sn_auth.rs` 生成 32 位字母数字激活码（sn_auth.rs:417-425、857-883）。
- `check_active_code` 判断 code 存在且未使用（sn_auth.rs:885-893）。
- `register_user_v2` 成功后在事务内标记 `used=1`（sn_auth.rs:1080）。
- `clear_state_by_active_code` 可事务化删除该激活码关联用户、设备、DNS 记录、DID 文档、session、binding、zone_info 并重置激活码（sn_auth.rs:895-987）。

`clear_state_by_active_code` 更像测试/运维清理接口，不应作为普通产品能力暴露给终端用户。

### 传统账号安全

属于 `sn_auth` 的传统账号安全能力包括：

- change password。
- password reset。
- 账号冻结/解冻。
- 登录失败次数、限流和风险控制。
- session 撤销。

这些能力只影响 SN 登录能力，不影响 BNS owner 权限。

当前实现状态：阶段一仅实现账号冻结/解冻（`set_user_state`，sn_auth.rs:1369-1382，并在置非 active 时触发 session 撤销）。待实现（阶段二）：change password、password reset、登录失败次数/限流/风控均缺失；session 撤销表已建但未接线（见 account_session 小节）。

## 对外查询

`sn_auth` 应提供给其他模块的查询能力：

- 根据 username 获取 SN 用户基础资料。
- 根据 username 获取当前 `zone_info`。
- 根据 `user_domain` 或其子域名找到 owner `sn_user`。
- 查询某用户可管理的传统 DNS records。
- 校验 active code 是否可用。
- 校验/刷新 SN session token。

`sn_resolver` 消费这些能力时，应把 `sn_auth` 返回的结果与 BNS 文档、`sn_device_info` 在线态、`sn_relay_manager` 分配关系合成最终解析结果。`sn_auth` 不直接承担 DNS resolver。

## API 建议

模块内部 API 可以按以下方向收敛：

```rust
trait SnAuthStore {
    async fn check_active_code(&self, code: &str) -> Result<bool>;
    async fn register_user(&self, req: RegisterSnUserRequest) -> Result<RegisterSnUserResult>;
    async fn get_user(&self, username: &str) -> Result<Option<SnUser>>;
    async fn get_user_by_domain(&self, domain: &str) -> Result<Option<SnUser>>;
    async fn set_user_state(&self, username: &str, state: UserState) -> Result<()>;

    async fn get_password_credential(&self, username: &str) -> Result<Option<PasswordCredential>>;
    async fn update_password_credential(&self, username: &str, credential: PasswordCredential) -> Result<()>;
    async fn update_last_login(&self, username: &str, ts: u64) -> Result<()>;

    async fn create_pkx_binding(&self, username: &str, domain: &str) -> Result<PkxBindingChallenge>;
    async fn verify_pkx_binding(&self, username: &str, domain: &str) -> Result<DomainBinding>;
    async fn unbind_user_domain(&self, username: &str, domain: &str) -> Result<()>;

    async fn get_zone_info(&self, username: &str) -> Result<Option<ZoneInfo>>;
    async fn update_zone_info(&self, username: &str, patch: ZoneInfoPatch) -> Result<()>;
}
```

RPC 层可以使用 breaking API，不要求保留旧 method alias。内部不应让每个 handler 自己解析权限：

- `auth.register`
- `auth.login`
- `auth.refresh`
- `auth.logout`
- `auth.me`
- `user.bind_owner_key`
- `user.get_owner_key`
- `user.get_profile`
- `zone.get`
- `zone.bind_config`
- `dns.add_record`
- `dns.remove_record`
- `dns.list_records`
- `admin.clear_state_by_active_code`

其中 `zone.bind_config`、BNS DNS TXT 写入、owner key rotation 等涉及 BNS 权限的接口，必须先经 `sn_authority` 和 `sn_bns_controller`。

## 当前实现对照

### 阶段一已完成（数据层 / 状态机重写）

`src/components/cyfs-sn/src/sn_auth.rs` 已实现：

- `SnAuthDB` trait（sn_auth.rs:144-247）。
- SQLite 初始化 `activation_codes`、`users`、`user_auth_v2`、`user_domain_history`、`user_domain_bindings`、`zone_info`、`account_sessions`（sn_auth.rs:282-408）。
- 32 位随机激活码生成、查询、写入（sn_auth.rs:417-425、835-893）。
- `register_user_v2` 事务化注册（含 zone_info 写入与激活码标记，sn_auth.rs:989-1091）。
- `create_v2_auth`、`get_user_info`、`get_user_by_domain`、`get_v2_auth`、`update_v2_last_login`、`set_user_state`。
- PKX 状态机 DB 层：`create_pkx_binding`/`verify_pkx_binding`/`unbind_user_domain` + 冲突历史检查（sn_auth.rs:1616-1881、695-757）。
- 独立 `zone_info`：`get_zone_info`/`update_zone_info`/`update_zone_relay_sn` + backfill（sn_auth.rs:1883-2041、548-600）。
- `account_sessions` 撤销表方法：`create_account_session`/`revoke_account_session`/`revoke_user_sessions`/`get_account_session`（sn_auth.rs:2043-2136）。
- `clear_state_by_active_code`，包含可选清理旧 `devices`、`user_dns_records`、`did_documents`（sn_auth.rs:895-987）。

相关实现分散在：

- `src/components/cyfs-sn/src/sn_v2_auth.rs`: 密码 PBKDF2、Ed25519 JWT 签发/校验。
- `src/components/cyfs-sn/src/api/common.rs`: username/public key 规范化、token 解析 helper。
- `src/components/cyfs-sn/src/api/auth.rs`: `auth.*` RPC。
- `src/components/cyfs-sn/src/api/zone.rs`: `zone.get`、`zone.bind_config`。
- `src/components/cyfs-sn/src/api/user.rs`: owner key、profile、self_cert。
- `src/components/cyfs-sn/src/api/dns.rs`: user DNS records。
- `src/components/cyfs-sn/src/sn_server.rs`: RPC 路由、旧 alias 兼容、device-signed token 校验。
- `src/components/cyfs-sn/src/sqlite_db.rs`: 兼容期 `SnDB` SQLite 实现，包含 devices、DNS records、DID documents。

### 阶段二待实现（主要差距）

- 没有 `sn_authority` 统一鉴权上下文模块：不存在 `AuthContext`/`Owner(name)`/`Controller(name,scope)`/`Device(zone,device,did)`/`SnUser(username)` 类型，各 handler 仍各自解析 token（V2 走 `require_account_username`→`verify_access_token`，common.rs:332-341；旧接口各自 `RPCSessionToken::from_string(...).verify_by_key(...)`，sn_server.rs:1114-1132 等）。
- 注册流程还没有和 `sn_bns_controller` / `bns-indexer.register` 串成一个幂等流程（无 `request_id`，无 BNS owner 创建/恢复）。
- PKX proof 在 DB 层已实现但无 RPC handler、无 DNS TXT 查询接线，端到端不可达。
- 绕过风险：`zone.bind_config` / `register_user_with_owner_key` 仍能不经 proof 把 `user_domain` 置 active；`self_cert` 可被裸 access token（含 `dns.*` 的 `has_cert=true`）置 true。
- owner 权限仍是“本地 `public_key` = owner”，不是 BNS authority；`owner_key_ref` 列从不写入。
- `auth.logout` 与 session 撤销表已建但未接线（签发/校验路径不写也不查 `account_sessions`）。
- 传统账号安全大多缺失：change password、password reset、登录失败限流/风控未实现。
- `zone.bind_config` 还没有发布 BNS `zone` / `boot` 文档。

## 迁移步骤

阶段一已完成：

1. ~~引入明确的 `zone_info` 数据结构~~：已落地独立 `zone_info` 表（sn_auth.rs:365-380）。
2. ~~为 `user_domain` 增加 PKX 绑定表和 PKX TXT 校验流程~~：DB 层已实现 `user_domain_bindings` + PKX 状态机（sn_auth.rs:342-355、1616-1881），仅缺 RPC/DNS 接线。
3. ~~调整 `auth.login`，去掉普通登录对 `active_code` 的依赖~~：已完成（auth.rs:91-133）。

阶段二待办：

4. 给 PKX 绑定加 RPC handler 与 DNS TXT 查询接线，使端到端可达；并堵住 `zone.bind_config` / `register_user_with_owner_key` 无证明置 active 的绕过。
5. 把 session 签发/校验接到 `account_sessions`，使 `auth.logout` 和账号冻结立即生效。
6. 把 `zone.bind_config` 拆成 owner authority 校验、BNS document 发布、`zone_info` 缓存更新三段。
7. 引入 `sn_authority` 统一鉴权上下文，把 BNS 修改类请求统一接入，禁止业务 handler 自行把 SN access token 当 owner token 使用。
8. 把 `self_cert` 更新入口收敛为可信 ACME/device 上报 + 证书校验，并记录来源和审计日志。
9. 补齐传统账号安全（change password、reset、限流），并写入 `owner_key_ref`。
10. 删除旧 RPC method alias 或让旧 alias 显式失败，内部只走新的 authority 和 store API。
