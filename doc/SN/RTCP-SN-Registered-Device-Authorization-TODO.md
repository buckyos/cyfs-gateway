# SN 集群 Zone Resolver 完成 RTCP 设备准入 TODO

状态：TODO（RTCP v3 Known Owner 消费侧已完成；SN Zone Resolver、AuthDB Owner 投影与
Phase 2 登记授权待完成；2026-07-24 重新校准）

校准基线：

- `cyfs-gateway` 当前锁定 `buckyos-base` commit
  `c5b7f8dc7861dd7cbb5f3e238e1d235209098da8`；
- [`doc/rtcp/RTCP-Authoritative-Peer-Key-Resolution-TODO.md`](../rtcp/RTCP-Authoritative-Peer-Key-Resolution-TODO.md)
  的 RTCP v3 安全收口已经完成：入站具名身份固定使用 `LocalAndZone`，`known_owner`
  关系档位、identity trust 传递、后台 authority 确认和否定踢除均已落地；
- `gateway` 已把 RTCP 迁移到新的 resolve / verify API；
- GitHub PR [#166](https://github.com/buckyos/cyfs-gateway/pull/166) 尝试在
  `deviceinfo.resolve_ood_by_did` 中从 scoped device document 的任意 key 字段重建
  `did:dev`。该方向仍不应合并。

基础库和 RTCP v3 已经解决了“如何安全验证并消费一份外部 `device_doc_jwt`”。本 TODO
不再负责设计 RTCP 的 Known Owner 消费策略，也不再要求在 `buckyos-base` 重新实现一套
device document verifier；剩余工作主要是：

- `cyfs-sn` 提供可信的 internal Zone Resolver 服务和部署；
- 将 `SnAuthDB` 中满足条件的用户按需投影为 Zone scope 的 Known Owner 材料；
- SN 业务授权只检查已验证 semantic DID 对应的登记关系，不再解析文档 key 重建身份；
- 补齐 SN → `name-client` → RTCP 的跨组件契约测试和可观测性。

## 1. 新基础库已经确定的语义

### 1.1 `name-lib` 的 document revision

- JWT 形式的 `DeviceDocument` 必须能得到 `iat`：直接携带 `iat`，或由
  `exp - DEFAULT_EXPIRE_TIME` 推导。
- `version_seq` 已退出验证、排序和 replay guard 语义；它只是兼容扩展字段，不能再作为
  current document 判断依据。
- document revision 统一为：

  ```text
  DocumentRevision { iat, content_hash }
  ```

- resolver wire 的 `documentVersion` 现在表示当前发布文档的 `iat`。同一 `iat`、不同
  content hash 是稳定冲突，不是“任选一个最新版本”。

### 1.2 `name-client` 的三段式 API

旧的 `verify_did_document_jwt` 单入口已经拆分为：

1. `build_verify_context`：按来源策略取得只读 trust snapshot；
2. `verify_did_document`：纯同步验证，不联网、不写 cache；
3. `resolve_verify_and_cache_did_document`：调用方明确要求时才写 verified cache。

RTCP 使用的 typed wrapper 是：

```rust
resolve_and_verify_device_document_jwt(
    did,
    jwt,
    &ResolveVerifyOptions,
)
```

默认 verification purpose 是 `VerifyPurpose::AuthSubject`。验证成功返回
`DeviceDocument + VerifiedDidDocument`，后者已经区分：

- `subject_did`、`structural_owner`、`authority_owner`；
- `expected_owner`、`declared_owner`、`authz_owner`；
- `ValidityEvidence`；
- `LocalFreshness` 和 `AuthorityFreshness`。

### 1.3 Zone snapshot 不等于 method authority receipt

`ResolveSourcePolicy` 已明确区分：

- `LocalOnly`：只读 Host 本地可信状态；
- `LocalAndZone`：允许查询 Zone Resolver，但不访问 method authority；
- `RemoteAuthority`：显式查询 method authority；
- `BestAvailable`：按 Zone → Host → method authority 的正常证据面取得最佳结果。

Internal Zone Resolver 是 Zone/集群级共享 cache 或 control-plane snapshot。它可以提供：

- Zone scope 的 latest-known baseline；
- owner binding 和可信 OwnerDocument 材料；
- Active/Missing/Revoked/Tombstoned 等 Zone 状态；
- `documentVersion`、`docHash`、`checkedAt`、`validUntil` 等本地 freshness 证据。

但 ZoneHit 不能产生 `AuthorityFreshness::Current`。只有本次显式 method authority resolve
且 receipt 能绑定候选 body/hash 时，才是 authority-current。后续配置和日志不得继续把
“Zone 已知最新”与“method authority 全局当前”混为一个 `anchored` 布尔值。

### 1.4 RTCP v3 已完成的 `known_owner` 契约

RTCP 入站具名身份固定使用 `VerifyPurpose::AuthSubject` 和 `LocalAndZone`。当前
`named_min_relation: known_owner` 的通过条件是：

```text
verified.usable_as_authz_subject
&& verified.authz_owner.is_some()
&& verified.validity.owner_document_source.is_some()
```

RTCP 只消费 `name-client` 验证后的 `authz_owner` 和 OwnerDocument evidence，不信任
candidate/claim 自声明的 owner。同步握手不访问 method authority；可信 Host/Zone snapshot
可在握手后触发有预算的后台 authority 确认，并把 trust 单向升级为
`MethodAuthorityCurrent`。

`known_owner` 是关系准入条件，`TrustedZoneSnapshot` 是证据来源等级，二者是正交维度。
SN 3180 通常会让一次成功验证同时满足二者，但文档和代码不得把它们合并为同一个状态。

### 1.5 `SnAuthDB` 用户投影为 Known Owner 的边界

Internal Zone Resolver 可以把 SN 控制面认可的 AuthDB 用户按需投影为 OwnerDocument。
无需为了初版增加 `list_users` 或把全表复制到另一份缓存；收到 Owner DID 查询后使用
`get_user_info` 点查即可。

“AuthDB 中存在用户记录”本身不等于 Known Owner。投影至少要求：

```text
user.state == Active
&& Owner DID 能唯一映射到该用户
&& 存在合法、可解析的 Owner Public Key
&& 能构造完整 OwnerDocument
```

- `Active + 有效 Owner Key`：返回 Zone scope `Active` OwnerDocument；
- `Active + 未绑定 Owner Key`：不是 Known Owner，返回明确 Missing/未就绪语义，不能合成
  虚假 key；
- `Suspended` / `Banned`：返回 `Revoked`；
- `Deleted`：返回 `Tombstoned`；
- AuthDB、BNS/indexer 或其它依赖不可用：返回 unknown/5xx，不能伪装成 Missing 或 Active。

AuthDB `users.public_key` 可作为 SN internal control-plane snapshot 的本地 Owner Key
材料，但不会因此成为 `did:web` / `did:bns` method authority receipt；BNS authority
材料可用时仍应保留其来源和优先级。

## 2. 目标身份与准入模型

```text
Hello.device_doc_jwt
  -> resolve/build VerifyContextSnapshot
  -> pure verify candidate document
       subject_did     = 已验证 semantic DID
       authz_owner     = authority/Zone binding 或 method 结构规则确定的 owner
       validity        = owner binding、owner document、签名和负状态证据
       local freshness = 相对 Host/Zone latest-known 的 revision 关系
       authority       = Current / NotCurrent / Unavailable / NotChecked
  -> DeviceDocument::get_default_key()
  -> 验 tunnel token，证明持有 device authentication key
  -> canonical did:dev 仅用于 nonce、tunnel key/reuse 和确定性通信
  -> process-chain 用 semantic DID 查询 SN 登记状态和业务权限
```

准入必须分别回答四个问题：

1. **Validity**：candidate 的 id/type、expected owner、owner signature 和 owner replay guard
   是否成立，是否命中 terminal negative state；
2. **Freshness**：candidate 是否旧于或冲突于选定 Host/Zone baseline；若策略要求全局当前，
   是否有 `AuthorityFreshness::Current`；
3. **Possession**：Hello tunnel token 是否由该 DeviceDocument 的 `#main_key` 验证；
4. **Authorization**：semantic DID 是否有有效的 SN 登记关系，且未被 banned/revoked。

公网 relay 的具名身份必须通过 RTCP v3 的 `LocalAndZone` 验证和配置的关系档位。验证
unavailable 时不存在 self-declared logical identity 回落；即使显式配置
`anonymous: allow`，也只能降级为不携带 owner/zone 的 `KeyDid`。部署若要求“全局发布状态
当前”，由后台或出站路径显式使用
`RemoteAuthority + FreshnessRequirement::RequireAuthorityCurrent`，不能把 ZoneHit 当成
替代品。

## 3. 非目标和禁止做法

- 不合并 PR #166 的 `device_did_from_document` 方向。
- 不遍历任意 `verificationMethod[].publicKeyJwk.x` 推导业务授权身份。
- 不把 scoped document 的 `id` 改写为 `did:dev`。
- 不在 `deviceinfo.resolve_ood_by_did` 中重新解析 Hello document 或重新选择 authentication
  key。
- 不把 anonymous OOD lookup 成功当作 Hello document 已验证的替代品。
- 不让 Public supplement resolver 冒充 internal Zone Resolver 或 method authority。
- 不把 `CacheStatus::ZoneHit`、`BodyEvidence::Anchored` 或 `Published` cache 单独解释成
  `AuthorityFreshness::Current`。
- 不再新增或比较 `version_seq`；anti-rollback 使用 `iat + content_hash`。
- 不重新引入 self-declared document fallback 或 observed cache 写入路径。
- `anonymous: allow` 只允许按已证明持有的 key 降级为 `KeyDid`，不得携带或授权
  self-declared owner/zone。
- 不把 Known Owner 等同于 Registered Device；前者只证明 owner-backed identity，后者仍由
  Phase 2 登记状态和 process-chain 业务策略决定。

## 4. 实施任务

### A. 完成 SN internal Zone Resolver 服务面

现有基础：

- [x] 已有 `SnDidResolverProfile::{PublicSupplement, InternalZoneResolver}` 和共享查询核心。
- [x] 已能按 `Accept: application/did-resolution` 返回 DID Resolution envelope。
- [x] Internal profile 已能标记 `documentStatus: active`，并保留 `did:web` semantic identity
  与 `canonicalZone` metadata。
- [x] 已有 `did:web` owner document 合成及 BNS/DeviceInfo/compatibility reader。
- [x] `SnAuthDB` 已有 `get_user_info` / `get_user_by_domain` 点查能力，`SnResolver` 已能在
  BNS owner 缺失时从 `users.public_key` 生成 legacy owner key 材料。
- [x] `SnDidResolver` 已能从 BNS owner config / effective owner key 合成
  `OwnerDocument`。

剩余任务：

- [ ] 增加独立 internal listener，默认 endpoint 为 `http://127.0.0.1:3180`：

  ```text
  GET /1.0/identifiers/{did}?type={doc_type}
  ```

- [ ] listener 必须固定使用 `SnDidResolverProfile::InternalZoneResolver`；当前公开 HTTP route
  仍固定为 `PublicSupplement`，不能直接当成 3180 服务复用。
- [ ] 增加 AuthDB Known Owner projection：
  - `did:bns:<username>?type=owner` 按 username 点查 `SnAuthDB`；
  - 为 SN 管理的固定 host suffix 增加
    `did:web:<username>.<sn-host>?type=owner -> <username>` 的显式映射，不能把任意
    `did:web` hostname 当成 AuthDB username；
  - 只允许 `UserState::Active` 且具有合法 Owner Key 的用户返回 Active
    OwnerDocument；
  - BNS authority owner config/key 可用时保留其优先级和 provenance；回落
    `users.public_key` 时明确标记为 SN AuthDB control-plane snapshot。
- [ ] 把 AuthDB 状态映射为 resolver 状态：`Suspended/Banned -> Revoked`、
  `Deleted -> Tombstoned`、未绑定 key -> Missing/未就绪、依赖故障 -> unknown/5xx。
  当前 Internal profile 对所有成功解析统一标记 Active，不能直接作为最终实现。
- [ ] 初版使用 AuthDB 点查，不要求增加全量 `list_users`。如果后续需要跨进程主动预热和
  快速失效，再增加分页 owner snapshot / revision change feed；它不是 3180 上线前置。
- [ ] 支持 `DidDocType::Device` 对应的 `type=device`。当前 SN scoped resolver 仍主要使用
  `doc` / `info`；迁移期可把 `doc` 保留为别名，但 response 的 canonical `docType` 必须是
  `device`。
- [ ] internal endpoint 默认返回 DID Resolution envelope；同时兼容客户端显式发送
  `Accept: application/did-resolution`。
- [ ] Active device/owner 回答至少提供：
  - `documentStatus`；
  - `docType`；
  - `effectiveOwner`（尤其是没有 structural owner 的 `did:web`）；
  - `documentVersion`，值为 document `iat`；
  - `docHash`，使用基础库 `document_content_hash` 的同一编码契约；
  - `checkedAt`、`validUntil`；
  - 可选 `authoritySeq`；
  - 诊断字段 `source`、`canonicalZone`、`resolverRole`。
- [ ] `authoritySeq` 只能表达 SN/Zone snapshot 自己的排序或 generation；不能让客户端据此
  产生 method-authority receipt。
- [ ] Missing、Revoked、Tombstoned 必须以 envelope metadata 明确返回；裸 404 表示 unknown，
  依赖故障返回 unknown/5xx，不能伪装成 Missing 或 Active。
- [ ] Active 回答必须返回当前完整 device document，或返回与当前 document 严格绑定的
  `docHash`。不能只返回临时合成的 `did:dev`。
- [ ] internal resolver 内部如调用 `name-client`，必须使用
  `ResolvePolicy::without_zone_resolver()` 防止 3180 自递归。
- [ ] loopback 部署默认无需公网认证；跨主机集群必须绑定内网地址并使用 mTLS、cluster token
  或等价网络 ACL，禁止直接暴露公网。

### B. 收口 `buckyos-base` Zone/verification 契约

已由锁定的 `buckyos-base` 基线完成：

- [x] `resolve_and_verify_did_document_jwt` /
  `resolve_and_verify_device_document_jwt` 组合入口。
- [x] `ResolveVerifyOptions { purpose, policy }` 与四档 `ResolveSourcePolicy`。
- [x] `VerifyContextSnapshot` + 纯 `verify_did_document`，resolve / verify / cache 写入分离。
- [x] expected owner 只来自 authority/Zone binding 或 structural rule，不来自 payload。
- [x] `VerifiedDidDocument` 返回 validity、local freshness、authority freshness 和 authz owner。
- [x] Revoked/Tombstoned 为 `VerifyError::RejectedByNegativeState`；Missing/Expired/Migrated
  作为非 terminal freshness 事实保留给调用方策略。
- [x] Zone response 的 `documentStatus`、`documentVersion`、`effectiveOwner`、`authoritySeq`、
  `docHash`、`checkedAt`、`validUntil` 已能进入 `PublishedState` / Zone snapshot。
- [x] owner document lookup 可以命中 Zone Resolver；server 自递归可按调用关闭 Zone fast path。
- [x] `version_seq` 已退出，revision 使用 `iat + content_hash`。

仍需在 `buckyos-base` 收尾：

- [ ] `ZoneResolverClient` 请求显式发送 DID Resolution envelope 的 `Accept` header。当前客户端
  已能解析 envelope，但 HTTP 请求本身尚未发送该 header；不能依赖每个 server 都默认返回
  envelope。
- [ ] 增加与 SN 3180 实际响应契约一致的跨组件测试，覆盖 `type=device`、metadata 大小写/
  命名、JWT string body 和 JSON body。
- [ ] 明确测试 ZoneHit 只产生 `LocalTrustScope::Zone` + `AuthorityFreshness::NotChecked`，不会
  因 `documentStatus=active`、`authoritySeq` 或 `BodyEvidence::Anchored` 升格成 Current。

### C. RTCP v3 Known Owner 消费侧（已完成）

本节已由
[`RTCP-Authoritative-Peer-Key-Resolution-TODO.md`](../rtcp/RTCP-Authoritative-Peer-Key-Resolution-TODO.md)
完成，后续以该文档和 [`doc/rtcp/rtcp.md`](../rtcp/rtcp.md) 为当前实现真值：

- [x] 入站具名身份固定使用
  `resolve_and_verify_device_document_jwt(VerifyPurpose::AuthSubject)` 和
  `LocalAndZone`，握手同步路径不访问 method authority。
- [x] `named_min_relation` 已支持 `same_zone | known_owner | any`；`known_owner` 只检查
  `usable_as_authz_subject`、`authz_owner` 和可信 OwnerDocument evidence。
- [x] RTCP 不信任 claim/payload 自声明 owner，使用 `verified.subject_did` 和
  `verified.authz_owner`。
- [x] tunnel token 使用 `DeviceDocument::get_default_key()` 做持钥证明，canonical
  `did:dev` 只用于 key identity、tunnel key/reuse 和确定性通信。
- [x] trust 已随 tunnel endpoint 和 per-stream process-chain 传递，当前枚举为
  `DnsTxtBootstrap | KeyDid | TrustedHostSnapshot | TrustedZoneSnapshot |
  MethodAuthorityCurrent`。
- [x] terminal typed rejection、local older/conflict、authority
  DifferentDocument/Superseded 均硬拒绝；verified cache 只在持钥证明、key confirmation
  和 listener 授权后提交。
- [x] self-declared/observed fallback 已删除。验证 unavailable 时，
  `anonymous: allow` 最多降级为不携带 owner/zone 的 `KeyDid`。
- [x] 后台 authority 确认已有 singleflight、限速、负缓存、并发和超时预算；确认成功
  单向升级 `MethodAuthorityCurrent`，确定性否定会踢除 tunnel。

因此，RTCP 不再是本 TODO 的实现阻塞项。SN 3180 只需严格提供符合契约的 Zone snapshot；
跨组件联调仍在本 TODO 的测试范围内。

### D. SN 登记状态查询只做 Phase 2 业务授权

文件：

- `src/components/cyfs-sn/src/sn_server.rs`
- `src/components/cyfs-sn/src/api/device.rs`

- [ ] `deviceinfo.resolve_ood_by_did` 接收 RTCP Phase 1 已验证的 semantic DID 后，直接复用
  `registered_device_key_from_did` 和登记 binding 查询 OOD/state。
- [ ] 删除 `canonical_device_did_from_scoped_did`、`device_did_from_document` 及相关测试；
  Phase 2 不重新解析 document，也不重新选择 authentication key。
- [ ] scoped DID 能定位已登记设备时，返回登记记录中的 canonical `did:dev`、owner/zone、
  state、`self_cert`；设备不存在、binding 冲突或 banned/revoked 时明确失败。
- [ ] 保留 raw `did:dev` 的 legacy 精确查询能力；它表示已登记 key device，不自动授予
  BNS/Web owner 权限。
- [ ] process-chain 的 SN 准入规则必须同时检查 RTCP evidence level 与登记状态，不能只因
  `resolve_ood_by_did` 查到记录就接受 `KeyDid` 或其它不满足策略的 identity trust。

### E. 部署与可观测性

- [ ] web3 gateway 单机配置启动本地 3180 internal listener。
- [ ] split relay 配置显式设置 Zone Resolver endpoint 和短 timeout；每个 RTCP relay 优先
  使用本地 sidecar/in-process resolver。
- [ ] readiness 覆盖 3180：至少验证一个 owner doc 和一个 registered device doc 能返回
  Active、effectiveOwner、iat/docHash 和可用 body。
- [ ] rollout 顺序：RTCP v3 / `buckyos-base` 已完成，下一步先发布 3180 服务并完成
  readiness，再把需要接受外部 SN 用户的 relay 配置为
  `inbound_admission.named_min_relation: known_owner`；默认 `same_zone` 的部署不应被
  静默放宽。
- [ ] 日志至少区分：
  `method_authority_current`、`trusted_zone_snapshot`、`trusted_host_snapshot`、`key_did`、
  `older_than_latest`、`same_iat_conflict`、`different_document`、`negative_state`。
- [ ] metrics 记录 Zone latency/hit/unknown/negative、各 trust level 的 RTCP accept/reject 和
  freshness rejection；不得记录完整 JWT/token。

## 5. 必须增加的测试

### SN Internal Zone Resolver

- [ ] `Active + 有效 Owner Key` 的 AuthDB 用户通过
  `did:bns:<username>?type=owner` 返回完整 OwnerDocument、Active 和 Zone provenance。
- [ ] `did:web:<username>.<sn-host>?type=owner` 只在命中受控 suffix 和合法 username 时
  映射到同一 AuthDB 用户，并保持请求的 `did:web` semantic identity。
- [ ] Active 但未绑定 Owner Key 的用户不成为 Known Owner；Suspended/Banned 返回
  Revoked，Deleted 返回 Tombstoned，AuthDB 故障返回 unknown/5xx。
- [ ] `did:bns:ood1.alice?type=device` 返回完整 device document、Active、effectiveOwner、
  `documentVersion == document.iat` 和匹配的 docHash。
- [ ] `did:web:ood1.example.com?type=device` 保持 web semantic DID，effectiveOwner 为
  `did:web:example.com`，canonical BNS zone 只放 metadata。
- [ ] Missing、Revoked、Tombstoned 和 BNS/indexer 故障分别产生明确状态或 unknown。
- [ ] 裸 404 是 unknown；带 `documentStatus=missing` 的 404 是 Zone 明确负回答。
- [ ] internal listener 不暴露 Public profile，resolver 内部不递归请求自身 3180。

### `buckyos-base` verification contract

- [x] `LocalAndZone` 命中完整 Active evidence：validity 成功，local freshness 为 Zone scope，
  authority freshness 仍是 NotChecked。
- [x] candidate 比 Zone baseline 旧：`OlderThanLatestKnown`；同 iat 不同 hash：
  `ConflictAtSameRevision`。
- [x] `RemoteAuthority` 的 body/hash 与 candidate 相同：`AuthorityFreshness::Current`；不同：
  `DifferentDocument` 或 `Superseded`。
- [x] effectiveOwner 与 declared owner 不同：`OwnerMismatch`；detached owner 用于 AuthSubject
  时：`DetachedOwnerRejected`。
- [x] Zone Revoked/Tombstoned：`RejectedByNegativeState`；Zone unknown 可继续其它允许来源。
- [x] `resolve_and_verify_*` 验证成功不写 cache；显式 cache API 才写入。
- [x] 只有 `iat`、没有 `version_seq` 的合法 DeviceDocument JWT 可验证；缺少可推导 iat 的
  JWT 被拒绝。

上述基础库契约已完成；本 TODO 仍需补 SN 3180 真实 HTTP response 的跨组件测试，不能只用
mock provider 代替。

### RTCP / SN 安全回归

- [ ] registered device 经可信 Zone snapshot 验证后成功 keep-tunnel，process-chain 看到
  semantic source DID、可信 owner 和 `TrustedZoneSnapshot`，并通过
  `named_min_relation: known_owner`。
- [x] method authority body/hash 绑定成功时产生 `MethodAuthorityCurrent`。
- [x] 攻击者用自己的 key/owner 签文档但声明其它 semantic DID/owner：RTCP validity
  验证拒绝，且没有 self-declared 回落。
- [x] Zone unavailable：`anonymous: reject` 拒绝；显式 `anonymous: allow` 最多产生
  `KeyDid`，且没有 owner/zone 授权字段。
- [x] 多 verification method 且 `#main_key` 不在第一项时，RTCP 仍只使用
  `DeviceDocument::get_default_key()` 验 tunnel token。
- [ ] SN Phase 2 不读取 `verificationMethod`，只用已验证 semantic DID 的 zone/device binding
  查询登记状态。
- [x] raw `did:dev` key identity 保持可连接，tunnel reuse key 不回退成 semantic DID，且
  不自动获得 owner/zone 权限。
- [ ] Known Owner 但未登记的设备：Phase 1 可以建立符合关系档位的 identity，Phase 2 /
  process-chain 必须拒绝需要 registered-device 权限的业务访问。

推荐 smoke：

```bash
cd src
cargo test -p cyfs-sn internal_zone_resolver -- --nocapture --test-threads=1
cargo test -p cyfs-gateway-lib rtcp_zone_verified -- --nocapture --test-threads=1
```

另在 `buckyos-base` 执行 `name-client` 的 verify context、Zone Resolver 和 freshness policy
测试。

## 6. 验收标准

- SN 集群内部存在可用且受保护的 Zone Resolver endpoint，默认本地地址为
  `127.0.0.1:3180`，不依赖设备自己的公网 HTTPS 服务已启动。
- AuthDB 中 `Active + 有效 Owner Key` 的用户可按需成为 Zone scope Known Owner；空 key、
  Suspended/Banned/Deleted 和依赖故障不会被错误标记为 Active。
- RTCP Hello 中的完整 DeviceDocument 能通过基础库统一入口完成 expected owner、owner
  signature、negative state、local/authority freshness 分层验证。
- Zone snapshot 与 method authority receipt 在结果、配置、日志和 metrics 中始终可区分。
- 权威/Zone 验证成功后，权限系统使用 semantic DID；canonical `did:dev` 只用于持钥证明和
  tunnel 确定性标识。
- Public SN relay 不存在 self-declared logical identity fallback；`KeyDid` 不携带或自动获得
  owner/zone 权限。
- SN OOD/登记状态查询不再手工解析 document key；PR #166 所修场景通过“RTCP Phase 1
  验证 + SN Phase 2 registration lookup”自然完成。
- 合法 `did:bns`、`did:web` registered device 可正常 keep-tunnel；伪造同一 semantic DID
  但不持有相应 document authentication key 的连接必须被拒绝。
