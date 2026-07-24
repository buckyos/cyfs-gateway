# RTCP 权威 Peer Key 解析收口 TODO

状态：TODO

适用基线：

- `cyfs-gateway` 当前 RTCP v2 实现；
- `buckyos-base` / `name-client` commit
  `c5b7f8dc7861dd7cbb5f3e238e1d235209098da8`；
- Beta2.2 是 breaking-change 版本，本 TODO 默认选择安全默认值，不保留隐式兼容降级。

相关文档：

- [`doc/rtcp/rtcp.md`](rtcp.md)
- [`doc/SN/RTCP-SN-Registered-Device-Authorization-TODO.md`](../SN/RTCP-SN-Registered-Device-Authorization-TODO.md)

## 1. Review 结论

收到的改进意见成立，而且是身份认证边界问题，不只是解析顺序优化。

当前出站/目标身份路径
`RTcpInner::resolve_handshake_identity()` 对 `did:web` 的实际顺序是：

1. 先调用 `resolve_handshake_identity_by_web_name_info()` 读取普通 DNS TXT；
2. TXT 中先遍历 `DEV=`，对 JWT 只做 **without verify** 解码并提取 `x`；
3. 再遍历 `PKX=`，直接把值构造成 `did:dev`；
4. 任一项能导出 Ed25519 key 就立即返回；
5. 只有 TXT 未给出可用 key 时才调用 `resolve_ed25519_exchange_key()`；
6. DID Document 解析失败后，又会再尝试一次相同 TXT fallback。

`doc/rtcp/rtcp.md` §5.2 当前写的是 “DID Document first，失败后 TXT fallback”，与上述
实现顺序相反；在代码收口前不能把该段文档当作现状。

因此，即使 `https://<domain>/.well-known/did.json` 已经正确发布，RTCP 仍可能优先采用
未认证 DNS TXT 中的设备 key。这个 key 随后用于：

- 生成 canonical remote `did:dev` 和 tunnel reuse key；
- 确定 `Hello.tunnel_token.to`；
- 验证 responder 的 `HelloAck.ack_token`。

这使普通 DNS 数据事实上进入了 peer authentication trust anchor，违背了
`did:web` 由 HTTPS 域名控制权锚定身份的语义。

另有两点需要纳入同一次收口：

1. 接收侧逻辑 DID 的 `device_doc_jwt` 在权威验证 unavailable 时，目前会回落到
   `verify_source_device_doc_self_declared()`。如果目标契约是“逻辑设备公钥必须来自可信
   authority/Zone 结果”，这条路径也必须默认关闭，而不能只修出站 TXT 顺序。
2. 直接调用现有 `resolve_ed25519_exchange_key()` 虽能消除“TXT first”，但它内部使用
   `ResolvePolicy::default()`（`BestAvailable`），可能命中 Zone、本机 in-TTL cache 或 method
   authority，并且只返回 `[u8; 32]`，调用方无法知道来源与 freshness。它适合
   “最佳可信结果”，不能被日志或策略误报为“本次取得 method-authority current receipt”。

### 1.1 `did:web` 最小部署判断

无需运行完整动态 Web 服务。对 RTCP 默认目标 Zone 的解析，只要静态 HTTPS 提供：

```text
https://<domain>/.well-known/did.json
```

并且该 `ZoneDocument` 含默认 zone gateway 及其可用 exchange/authentication key，
`resolve_ed25519_exchange_key()` 就能取得 RTCP 所需 Ed25519 key。只有调用方还要分别解析
OwnerDocument、DeviceDocument 等类型时，才需要同目录的 `owner.json`、`device.json`
或对应 resolver API。

### 1.2 身份类型边界

- `did:dev:<pkx>` 是 key DID，公钥内嵌在 DID 中，持钥证明成立后是自认证身份；它不需要
  HTTPS/BNS authority，但也不能自动获得某个 zone/owner 的业务权限。
- `did:web:*` 的权威发布面是 canonical HTTPS endpoint。
- `did:bns:*` 的权威发布面是 BNS authority/resolver；Web/DNS 只能作为候选或补充源，
  不能冒充 BNS authority。
- DNS A/AAAA 仍可用于可达地址解析；本 TODO 禁止的是把未经认证的 TXT `DEV/PKX`
  当作长期身份 key，而不是禁止 DNS 参与寻址。

## 2. 目标安全契约

RTCP 必须把“取回一个 key”和“确认这个 key 的信任来源”分开建模。

对于逻辑 DID，默认契约为：

```text
logical DID
  -> 按 DID method 解析可信文档/发布状态
  -> 从合格的 ZoneDocument 或 DeviceDocument 选择协议规定的默认 key
  -> 得到 canonical did:dev
  -> 用该 key 验 Hello/HelloAck 持钥证明
  -> 只有同时满足解析证据要求和持钥证明，peer authentication 才成功
```

硬性要求：

- 默认 fail-closed：权威/可信 Zone 结果 unavailable、missing、invalid、revoked、冲突或
  freshness 不满足时，握手失败。
- 不得因为权威文档 schema 错误、缺字段或超时而自动改信普通 DNS TXT。
- 权威结果与 TXT 冲突时，永远使用权威结果；不得做 first-win 或“多数票”。
- DNS TXT fallback 必须由 RTCP stack 配置显式开启，且结果必须标记为 non-authoritative。
- non-authoritative 身份不得填充可授权的 owner/zone 字段，也不得通过公网 SN/relay 的
  默认准入策略。
- 日志、process-chain 变量和 metrics 必须保留 trust/provenance；不能在提取出
  canonical `did:dev` 后丢失来源。

## 3. 配置与类型设计

不要新增含义模糊的单一 `authoritative: bool`。建议把解析来源要求与兼容 fallback 分开：

```yaml
stacks:
  rtcp:
    protocol: rtcp
    peer_identity:
      requirement: authority_current # authority_current | trusted_snapshot
      dns_txt_bootstrap: false
      inbound_self_declared_fallback: false
```

建议语义：

- `authority_current`：对逻辑 DID 使用 `RemoteAuthority`，本次必须取得 method authority
  的当前判断；默认值。
- `trusted_snapshot`：允许未过期且有可信来源的 Host/Zone/Published cache 结果，但绝不接受
  observed/unverified/TXT；用于明确需要离线容错的受控部署。
- `dns_txt_bootstrap: true`：仅在权威解析 unavailable 时允许旧 `DEV/PKX` 路径；它不改变
  `requirement` 的含义，返回的 trust 必须是 `DnsTxtBootstrap`。
- `inbound_self_declared_fallback: true`：仅保留给显式离线/首次组网场景；公网部署不得开启。

内部结果至少应携带：

```rust
enum RtcpPeerKeyTrust {
    KeyDid,
    MethodAuthorityCurrent,
    TrustedHostSnapshot,
    TrustedZoneSnapshot,
    DnsTxtBootstrap,
    SelfDeclaredDocument,
}

struct ResolvedRtcpPeerKey {
    semantic_did: DID,
    canonical_dev_did: DID,
    ed25519_pk_der: [u8; 32],
    trust: RtcpPeerKeyTrust,
    resolver_id: Option<String>,
}
```

`DnsTxtBootstrap` 和 `SelfDeclaredDocument` 必须被视为 non-authoritative。若继续允许它们进入
握手，process-chain 必须先检查 trust，再决定是否授予任何业务访问。

## 4. 实施任务

### A. 立即消除 TXT-first

- [ ] 删除 `resolve_handshake_identity()` 开头的 `did:web` TXT 预解析。
- [ ] 默认先走 DID method 解析；解析成功后不得再查询 TXT。
- [ ] DID 解析失败时默认直接返回错误。
- [ ] 只有 `dns_txt_bootstrap: true` 时才调用
  `resolve_handshake_identity_by_web_name_info()`。
- [ ] fallback 日志明确输出 `non-authoritative DNS TXT bootstrap`，不得写成普通
  “resolve success”。
- [ ] `DEV=` 若保留兼容支持，不得再让 “JWT without verify 后取 `x`” 看起来像完成了
  document verification；函数、类型和日志都应标明它只是在解析 bootstrap hint。

### B. 增加带 provenance 的 exchange-key API

现有 `resolve_ed25519_exchange_key()` 丢弃 `ResolvedDocument.resolution_metadata`，无法实现
严格 policy 和可观测性。二选一：

- [ ] 在 `name-client` 增加
  `resolve_ed25519_exchange_key_ex(did, policy) -> ResolvedExchangeKey`，返回 key、文档解析
  metadata、freshness/authority 证据；推荐方案。
- [ ] 或 RTCP 直接调用 `resolve_did_ex()`，按统一的 ZoneDocument/DeviceDocument key 选择
  API 提取 exchange key；禁止在 RTCP 内复制一套容易漂移的 key-selection 规则。

严格模式必须使用 `ResolveSourcePolicy::RemoteAuthority`，不能把一次
`BestAvailable` 成功笼统记录为 authority-current。`trusted_snapshot` 模式则必须检查
返回 evidence/cache status，拒绝 `ObservedFallback`、`NeedProof` 未完成验证以及 stale
结果。

### C. 收口接收侧逻辑身份

- [ ] 为 `resolve_source_device_info()` 注入相同的 peer identity policy。
- [ ] 权威验证 unavailable 时，默认不调用
  `verify_source_device_doc_self_declared()`。
- [ ] 保留显式 fallback 时，返回 `SelfDeclaredDocument` trust，并清空/隔离
  `source_device_owner`、`source_zone_did` 等可授权字段。
- [ ] `did:dev` 无文档路径继续支持 `KeyDid`，但上层策略必须明确决定匿名 key identity
  可以访问哪些服务。
- [ ] 与
  [`RTCP-SN-Registered-Device-Authorization-TODO.md`](../SN/RTCP-SN-Registered-Device-Authorization-TODO.md)
  的 `RtcpIdentityTrust` 收敛为同一类型，避免出站 key provenance 与入站授权 evidence
  各自定义一套不兼容枚举。

### D. 接通配置

- [ ] 给 `RtcpStackConfig`、`RtcpStackBuilder`、`RTcp` / `RTcpInner` 增加 policy。
- [ ] 配置反序列化默认值必须是 fail-closed。
- [ ] 更新 `src/rootfs/etc/cyfs_gateway.yaml` 示例，明确两个 fallback 都默认关闭。
- [ ] 对旧配置不做静默兼容；Beta2.2 启动日志应提示 TXT bootstrap 行为已改变。
- [ ] web3 gateway、公网 SN/relay 配置不得开启两个 fallback。

### E. 文档与可观测性

- [ ] 修正 `doc/rtcp/rtcp.md` §5.2，使“当前实现”与实际代码一致，并描述 authority policy。
- [ ] 修正 §5.3：权威验证与 self-declared fallback 是不同 trust level，后者不再默认启用。
- [ ] 记录 resolver method、trust level、cache/freshness 结果和 fallback 原因；不得记录完整
  JWT、`DEV=` 或 token。
- [ ] metrics 至少区分 authority/Zone/Host/key-DID/TXT/self-declared 的成功与拒绝次数。

## 5. 必须增加/更新的测试

- [ ] `did:web` 同时存在合法 HTTPS ZoneDocument 与冲突 TXT：必须采用 HTTPS 文档 key。
- [ ] HTTPS authority unavailable 且 fallback 默认关闭：必须失败。
- [ ] HTTPS 返回 malformed/缺字段文档，同时 TXT 合法：默认仍必须失败。
- [ ] 显式开启 TXT bootstrap 后，authority unavailable 才可使用 TXT，结果 trust 为
  `DnsTxtBootstrap`。
- [ ] authority 明确 Missing/Revoked/Tombstoned 时，即使开启 TXT bootstrap 也不得回退；
  fallback 只处理真正的 unavailable，不覆盖权威负回答。
- [ ] `did:bns` 使用 BNS authority 解析；DNS TXT 冲突不能覆盖 BNS 结果。
- [ ] `did:dev` 从 DID 自身取得 key，不发起 Web/BNS/TXT 查询，trust 为 `KeyDid`。
- [ ] `authority_current` 不接受 Zone/cache 命中冒充 current receipt。
- [ ] `trusted_snapshot` 只接受允许的未过期可信 evidence，拒绝 observed/unverified/stale。
- [ ] 入站逻辑 DID 的权威验证 unavailable：默认拒绝；显式 fallback 时只能得到
  `SelfDeclaredDocument`，不能获得可信 owner/zone。
- [ ] 更新当前依赖 TXT cache 的
  `web_target_token_uses_resolved_dev_identity`、alias/tunnel-key 测试，改用可控的 method
  authority/ZoneDocument fixture；另保留独立 bootstrap compatibility 测试。
- [ ] 配置测试覆盖默认值、两个显式 fallback、非法枚举和值的错误提示。

## 6. 发布顺序

1. 先为所有生产 `did:web` 身份发布静态 `/.well-known/did.json`，并验证其中默认 gateway
   key 与 RTCP 实际私钥一致；按需发布 `owner.json` / `device.json`。
2. 不提供 HTTPS 的身份迁移到 `did:bns`，确认 BNS resolver/indexer readiness。
3. 发布带 provenance 的 resolver API 与 RTCP policy/config。
4. 切换 RTCP 默认值为 `authority_current`、关闭两个 fallback。
5. 观察 authority unavailable、schema error、key mismatch 指标；只对受控 bootstrap 环境
   局部开启兼容开关，不做全局回滚。
6. 稳定后评估删除 TXT `DEV/PKX` 身份解析代码，仅保留 DNS 的地址/服务发现职责。

## 7. 验收标准

- 当 HTTPS/BNS 权威文档与 DNS TXT 冲突时，RTCP 最终使用的 Ed25519 key 必须来自权威结果。
- 权威结果不可用或不合格时，默认不能建立逻辑 DID tunnel。
- 任何 TXT/self-declared 兼容结果都有显式配置、显式 non-authoritative trust 和可观测记录。
- 公网 SN/relay 的授权链不能消费 non-authoritative owner/zone。
- `did:dev` 匿名/自认证能力保持可用，但不会被误报为 `did:web`/`did:bns` 权威身份。
- tunnel key、Hello/HelloAck 验签和 process-chain 看到的 identity provenance 来自同一次
  解析决策，不出现“握手用一个 key、授权相信另一个来源”的分裂。
