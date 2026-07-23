# SN 集群 Zone Resolver 完成 RTCP 设备准入 TODO

状态：TODO（已按 2026-07 `name-lib` / `name-client` 验证基础库重构重新校准）

校准基线：

- `cyfs-gateway` 当前锁定 `buckyos-base` commit
  `c5b7f8dc7861dd7cbb5f3e238e1d235209098da8`；
- gateway commit `06c33570` 已把 RTCP 迁移到新的 resolve / verify API；
- GitHub PR [#166](https://github.com/buckyos/cyfs-gateway/pull/166) 尝试在
  `deviceinfo.resolve_ood_by_did` 中从 scoped device document 的任意 key 字段重建
  `did:dev`。该方向仍不应合并。

这次基础库重构已经解决了“如何验证一份外部 `device_doc_jwt`”的通用能力。本 TODO
不再要求在 `buckyos-base` 重新实现一套 device document verifier；剩余工作主要是：

- `cyfs-gateway` 为 SN/relay 提供可信的 internal Zone Resolver 服务和部署；
- RTCP 对新验证结果应用明确的 freshness / admission policy，并把 evidence level 传给
  process-chain；
- SN 业务授权只检查已验证 semantic DID 对应的登记关系，不再解析文档 key 重建身份；
- 补齐跨仓库契约测试和可观测性。

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

公网 relay 至少必须要求可信 Zone snapshot 或 method authority evidence，绝不能把
self-declared fallback 的 owner/zone 当作授权主体。部署若要求“全局发布状态当前”，必须显式
选择 `RemoteAuthority + FreshnessRequirement::RequireAuthorityCurrent`，不能把 ZoneHit 当成
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
- 不允许公网 relay 在验证证据不可用时静默用 self-declared owner 获得 owner/zone 权限。
- 离线 LAN 可以显式允许 fallback，但必须与公网默认策略隔离，并向业务层暴露 trust level。

## 4. 实施任务

### A. 完成 SN internal Zone Resolver 服务面

现有基础：

- [x] 已有 `SnDidResolverProfile::{PublicSupplement, InternalZoneResolver}` 和共享查询核心。
- [x] 已能按 `Accept: application/did-resolution` 返回 DID Resolution envelope。
- [x] Internal profile 已能标记 `documentStatus: active`，并保留 `did:web` semantic identity
  与 `canonicalZone` metadata。
- [x] 已有 `did:web` owner document 合成及 BNS/DeviceInfo/compatibility reader。

剩余任务：

- [ ] 增加独立 internal listener，默认 endpoint 为 `http://127.0.0.1:3180`：

  ```text
  GET /1.0/identifiers/{did}?type={doc_type}
  ```

- [ ] listener 必须固定使用 `SnDidResolverProfile::InternalZoneResolver`；当前公开 HTTP route
  仍固定为 `PublicSupplement`，不能直接当成 3180 服务复用。
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

### C. RTCP 应用明确的 evidence / freshness policy

当前已完成：

- [x] RTCP 已调用 `resolve_and_verify_device_document_jwt`，不再在主路径自行拼
  `payload.owner -> resolve_auth_key`。
- [x] 主路径使用 `verified.subject_did` 作为 semantic `source_device_id`，使用
  `verified.authz_owner` 作为可信 owner。
- [x] tunnel token 使用返回 `DeviceDocument::get_default_key()` 验证，canonical `did:dev`
  只用于持钥和 tunnel 内部标识。
- [x] RTCP 已对 terminal typed rejection、local older/conflict、authority
  DifferentDocument/Superseded 做硬拒绝。
- [x] verified cache 写入已推迟到 tunnel-token 持钥证明和 listener 授权通过之后。

剩余任务：

- [ ] 为 `VerifiedSourceDevice` 增加可传递到 process-chain 的 evidence level，至少区分：

  ```rust
  enum RtcpIdentityTrust {
      MethodAuthorityCurrent,
      ZoneVerified,
      HostVerified,
      SelfDeclaredFallback,
      KeyDid,
  }
  ```

  具体值必须由 `VerifiedDidDocument.validity` 和 `freshness` 推导，不能只根据“组合 API
  返回 Ok”判断。
- [ ] 用基础库 `evaluate_freshness` + `FreshnessRequirement` 代替 RTCP 当前手写的部分枚举
  匹配，避免遗漏新增 freshness 状态或 scope 不匹配。
- [ ] 增加清晰配置，避免继续使用含义模糊的 `authoritative` 单布尔值。建议至少提供：
  - `authority_current`：`RemoteAuthority` + `RequireAuthorityCurrent`；
  - `zone_or_authority`：接受可信 Zone baseline 或 Authority Current，不接受 fallback；
  - `allow_fallback`：只用于显式离线/首次组网场景。
- [ ] web3 gateway / 公网 SN relay 默认至少使用 `zone_or_authority`；需要全局当前保证的部署
  显式使用 `authority_current`。
- [ ] self-declared fallback 不得填充可授权的 `source_device_owner` / `source_zone_did`，或必须
  保证所有授权策略先检查 `RtcpIdentityTrust`。仅记录 JWT 自声明字段时要使用单独的
  untrusted/observed 命名。
- [ ] `AuthorityFreshness::Unavailable`、`NotChecked`、`ActiveUnanchored` 和非 terminal
  `NotCurrent::NegativeStatus` 的接受方式必须由配置决定，不能隐式落入同一成功档位。
- [ ] 保留 `allow_fallback` 时，只允许 `ResolveVerifyError` 中真正的 unavailable/missing
  dependency 进入 fallback；`VerifyError` 的 definite rejection 永远不得回落。

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
  `resolve_ood_by_did` 查到记录就接受 self-declared logical identity。

### E. 部署与可观测性

- [ ] web3 gateway 单机配置启动本地 3180 internal listener。
- [ ] split relay 配置显式设置 Zone Resolver endpoint 和短 timeout；每个 RTCP relay 优先
  使用本地 sidecar/in-process resolver。
- [ ] readiness 覆盖 3180：至少验证一个 owner doc 和一个 registered device doc 能返回
  Active、effectiveOwner、iat/docHash 和可用 body。
- [ ] rollout 顺序：先升级 `buckyos-base` 和 3180 服务，再开启
  `zone_or_authority`，最后按部署能力选择 `authority_current`。
- [ ] 日志至少区分：
  `authority_current`、`zone_verified`、`host_verified`、`self_declared_fallback`、
  `older_than_latest`、`same_iat_conflict`、`different_document`、`negative_state`。
- [ ] metrics 记录 Zone latency/hit/unknown/negative、各 trust level 的 RTCP accept/reject 和
  freshness rejection；不得记录完整 JWT/token。

## 5. 必须增加的测试

### SN Internal Zone Resolver

- [ ] `did:bns:ood1.alice?type=device` 返回完整 device document、Active、effectiveOwner、
  `documentVersion == document.iat` 和匹配的 docHash。
- [ ] `did:web:ood1.example.com?type=device` 保持 web semantic DID，effectiveOwner 为
  `did:web:example.com`，canonical BNS zone 只放 metadata。
- [ ] Missing、Revoked、Tombstoned 和 BNS/indexer 故障分别产生明确状态或 unknown。
- [ ] 裸 404 是 unknown；带 `documentStatus=missing` 的 404 是 Zone 明确负回答。
- [ ] internal listener 不暴露 Public profile，resolver 内部不递归请求自身 3180。

### `buckyos-base` verification contract

- [ ] `LocalAndZone` 命中完整 Active evidence：validity 成功，local freshness 为 Zone scope，
  authority freshness 仍是 NotChecked。
- [ ] candidate 比 Zone baseline 旧：`OlderThanLatestKnown`；同 iat 不同 hash：
  `ConflictAtSameRevision`。
- [ ] `RemoteAuthority` 的 body/hash 与 candidate 相同：`AuthorityFreshness::Current`；不同：
  `DifferentDocument` 或 `Superseded`。
- [ ] effectiveOwner 与 declared owner 不同：`OwnerMismatch`；detached owner 用于 AuthSubject
  时：`DetachedOwnerRejected`。
- [ ] Zone Revoked/Tombstoned：`RejectedByNegativeState`；Zone unknown 可继续其他来源。
- [ ] `resolve_and_verify_*` 验证成功不写 cache；显式 cache API 才写入。
- [ ] 只有 `iat`、没有 `version_seq` 的合法 DeviceDocument JWT 可验证；缺少可推导 iat 的
  JWT 被拒绝。

### RTCP / SN 安全回归

- [ ] registered device 经可信 Zone snapshot 验证后成功 keep-tunnel，process-chain 看到
  semantic source DID、可信 owner 和 `ZoneVerified`。
- [ ] method authority body/hash 绑定成功时产生 `MethodAuthorityCurrent`。
- [ ] 攻击者用自己的 key/owner 签文档，但声明已登记 semantic DID：validity 或登记授权必须
  拒绝。
- [ ] Zone unavailable：`zone_or_authority` 拒绝；显式 `allow_fallback` 只产生
  `SelfDeclaredFallback`，且没有 owner/zone 授权字段。
- [ ] 多 verification method 且 `#main_key` 不在第一项时，RTCP 仍只使用
  `DeviceDocument::get_default_key()` 验 tunnel token。
- [ ] SN Phase 2 不读取 `verificationMethod`，只用已验证 semantic DID 的 zone/device binding
  查询登记状态。
- [ ] raw `did:dev` legacy device 保持可连接，tunnel reuse key 不回退成 semantic DID。

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
- RTCP Hello 中的完整 DeviceDocument 能通过基础库统一入口完成 expected owner、owner
  signature、negative state、local/authority freshness 分层验证。
- Zone snapshot 与 method authority receipt 在结果、配置、日志和 metrics 中始终可区分。
- 权威/Zone 验证成功后，权限系统使用 semantic DID；canonical `did:dev` 只用于持钥证明和
  tunnel 确定性标识。
- Public SN relay 不接受 self-declared fallback 的 owner/zone 权限。
- SN OOD/登记状态查询不再手工解析 document key；PR #166 所修场景通过“RTCP Phase 1
  验证 + SN Phase 2 registration lookup”自然完成。
- 合法 `did:bns`、`did:web` registered device 可正常 keep-tunnel；伪造同一 semantic DID
  但不持有相应 document authentication key 的连接必须被拒绝。
