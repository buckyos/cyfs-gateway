# RTCP Peer Identity、Tunnel 与 Stream 安全收口 TODO

状态：TODO（合并权威 Peer Key 解析与 RTCP v2 review）

适用基线：

- `cyfs-gateway` 当前 RTCP v2 实现；
- `buckyos-base` / `name-client` commit
  `c5b7f8dc7861dd7cbb5f3e238e1d235209098da8`；
- Beta2.2 是 breaking-change 版本，本 TODO 默认选择安全默认值，不保留隐式兼容降级。

相关文档：

- [`doc/rtcp/rtcp.md`](rtcp.md)
- [`doc/rtcp/rtcp_v2_review.md`](rtcp_v2_review.md)
- [`doc/SN/RTCP-SN-Registered-Device-Authorization-TODO.md`](../SN/RTCP-SN-Registered-Device-Authorization-TODO.md)

本文档是上述 review 的统一实施入口。`rtcp_v2_review.md` 保留 review 原文和历史上下文，
本文档只记录按当前 HEAD 复核后仍需执行的决策、代码任务、测试和验收标准。实施时不得把
review 中已经过时的认证行为重新带回代码。

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

### 1.3 合并 RTCP v2 review 后的当前结论

以下问题已按当前 HEAD 复核，仍然成立，必须纳入同一次收口：

1. **重复 tunnel 的拒绝理由已经失效。** v2 的双方每次握手都生成新的 ephemeral
   X25519 key 和 nonce，完成 key-confirmation 的新 tunnel 不会与旧 tunnel 复用同一组
   `(aes_key, iv)`。当前 `RTcpTunnelMap::on_new_tunnel()` 仍沿用 v1 的 key/nonce-reuse
   理由拒绝相同 tunnel key，可能让僵尸 tunnel 阻塞合法重连。
2. **liveness 不能可靠清理僵尸 tunnel。** `RTcpTunnel::run()` 没有协议级 idle/liveness
   判定；TCP socket 未配置 keepalive；`Tunnel::ping()` 丢弃 `send_package()` 错误并始终
   返回 `Ok(())`，而 keep-tunnel 路径也不等待 `Pong`。因此 keep-tunnel 不能作为可靠的
   活性证明。
3. **inbound `ROpen` 无配额且不校验方向。** `Open` 有 64 槽 semaphore，`ROpen`
   则在读循环中直接 spawn，每条请求都能触发地址解析、并发拨号和 `HelloStream`。
4. **未认证入口缺少完整的资源和边界保护。** `read_package()` 在检查最小包长和
   `json_pos` 上界前执行索引/切片，畸形首包可触发 panic；首包读取没有 deadline，accept
   后的未认证 task 也没有全局并发上限。`device_doc_jwt` 权威查询发生在准入前，同样必须
   计入握手时间和资源预算。
5. **部分安全相关明文字段没有绑定到握手。** `Hello.my_port` 不在签名 token 或 HKDF
   上下文中，链路攻击者可以篡改回连端口。修复时应统一盘点所有安全相关 Hello 字段，
   而不是只特判一个字段。
6. **密钥和记录生命周期没有上限。** tunnel 控制流和所有业务 stream 共用 tunnel AES
   key，业务 stream 只替换 base IV；没有 per-stream key separation、记录/字节预算或
   tunnel rekey/轮换策略。
7. **若干低优先级协议取舍未被正式记录。** 包括无 authenticated close、明文
   `HelloStream` 可被抢占 waiter、Datagram 长度无协议上限、Hello/HelloAck 暴露身份
   元数据、Hello + `device_doc_jwt` 受 u16 包长限制。

当前实现中已经成立、不得回退的事实：

- `RevokedByOwnerPolicy`、`RejectedByNegativeState` 是确定性硬拒绝；
- 本地 older/conflict 和 authority `DifferentDocument` / `Superseded` 会被 freshness
  policy 拒绝；
- DEV-based tunnel key 已落地，bootstrap-backed key 带 transport URL 后缀；
- v2 tunnel 建立以 HelloAck/HelloAckConfirm key-confirmation 完成为成功边界。

review 中“明确吊销仍会进入 self-declared fallback”的描述已经过时。后续修改必须保留
上述 typed rejection 和 anti-rollback 行为；本 TODO 要关闭的是 **Unavailable 类默认
fallback**，不是重新合并所有失败类型。

### 1.4 文档与现有线协议的已确认偏差

这些偏差需要在代码决策完成后一次修正，不能继续用“目标语义”冒充当前实现：

- `StreamPurpose` 当前通过 Serde 序列化为 `"Stream"` / `"Datagram"`，不是文档中的
  `0` / `1`；
- 无 `device_doc_jwt` 的逻辑 `from_id` 会被拒绝，只有 `did:dev` 能走无文档路径；
- device document id、Hello/ack token 的部分 from/to 校验仍是字符串比较；只有部分
  `did:web` target 路径会解析别名，不是完整 canonical DEV 比较；
- direct reconnect 当前以 TCP connect 成功选出 winner，`HelloStream` 失败不会恢复其余
  attempt；成功 RTT 记录为 `MeasurementLayer::Tcp`，失败 attempt 无法完整回写；
- reconnect 使用的是 tunnel 发起侧保存的 remote stack port；文档不能笼统写成
  `Hello.my_port`；
- nonce cache 上限是 16K **条目**，不是 16 KiB；
- `did:web` 当前实现是 TXT-first，而不是文档所写 DID Document first；
- identity 文件实际使用 `device.jwt` / `device_doc.jwt` / `did.json`，不是
  `device.doc.jwt`；
- AEAD nonce base 实际是 `SHA-256(label || base_iv)`；
- JWT `exp` 只提供过期上界；当前 token 没有 `iat` / `nbf`，文档所写
  `[exp-leeway, exp+leeway]` 不是验证器实际建立的双边窗口；
- `doc/rtcp/rtcp.md` 尚未说明每条 stream 的 process-chain 授权点和可见字段。

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

### 2.1 Tunnel 生命周期契约

- 相同 tunnel key 的新连接只有在身份验证、key-confirmation、listener 授权和需要的
  freshness/cache commit 全部成功后，才有资格替换旧 tunnel。
- 替换必须在 map 内原子完成：插入新 tunnel 时返回旧 tunnel，锁外关闭旧 tunnel。
- 每个 tunnel 必须有不可复用的 generation/id；`run()` 退出时只能执行
  `remove_if_current(tunnel_key, generation)`，旧 tunnel 绝不能删除后来替换进去的新值。
- `close()` 必须唤醒或终止阻塞中的读循环，并使所有后续写、Open/ROpen waiter 和
  Pong waiter 快速失败。
- keep-tunnel 的健康判断必须等待匹配的 `Pong`；仅仅成功写入本地 TCP buffer 不算远端
  存活。
- 连续 liveness 失败后应 close + conditional remove，让下一轮重建；TCP keepalive 只能
  作为补充，不能替代协议级 Ping/Pong。

### 2.2 未认证入口与资源契约

- 当前控制包头固定为 8 字节；本协议版本必须要求 `len >= 8` 且 `json_pos == 8`。如果
  未来需要扩展头部，应先增加明确版本，不允许当前解析器宽松猜测。
- 所有基于远端长度/偏移的访问必须使用 checked arithmetic 和安全切片，任何畸形输入都
  返回 `InvalidData`，不得 panic。
- 首包、身份解析、HelloAck/HelloAckConfirm 必须共享一个有上界的握手 deadline。
- listener 必须有全局 pending-handshake semaphore；按 IP 的速率限制、短期负缓存和日志
  抑制作为纵深防护，避免随机 owner/doc JWT 放大外部 authority 查询。
- nonce cache 是 replay/DoS 的纵深防护，不是 v2 密钥安全边界；文档必须说明 16K 条目、
  淘汰策略和多实例限制。

### 2.3 Stream 建立与授权契约

- `Open` 和 `ROpen` 必须共享或分别拥有明确的 per-tunnel pending-build 配额；permit
  必须在 spawn/解析/拨号之前获取，并在失败、超时和成功交接后释放。
- 当前角色模型下，只有 `can_direct == false` 的一端接收 `Open`，只有
  `can_direct == true` 的一端接收 `ROpen`；错误方向返回明确拒绝码，不得继续拨号。
- 每 peer 需要速率限制，避免已认证但低权限的对端把 RTCP 当连接放大器。
- tunnel 认证只确定“是谁”；每条 stream 的 process-chain 必须在看到
  `source_did`/`real_source_did`、identity trust、`dest_host`、`dest_port`、purpose 后
  决定“能访问什么”。文档和测试必须覆盖这个授权边界。

### 2.4 密钥与记录生命周期契约

- 业务 stream 使用 HKDF 从 tunnel secret 和规范化 stream context 派生独立 key/IV；
  context 至少绑定 stream id、purpose 和协议版本。
- stream id 必须在所属 tunnel 生命周期内唯一；不能只依赖随机碰撞概率，也不能允许重复
  waiter 静默覆盖。
- tunnel 控制流和业务 stream 都要定义最大记录数、最大累计字节数或最大存活时间。达到
  预算后通过建立新 tunnel 轮换，不在第一版引入复杂的原地 KeyUpdate 状态机。
- 记录层必须为 seq 溢出和预算耗尽提供可观察的专用错误。
- authenticated close、HelloStream 绑定证明和身份元数据隐私作为协议决策项显式记录；
  若本轮不实现，也必须标为 accepted risk，而不是保持未定义。

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
    liveness:
      ping_interval_secs: 30
      pong_timeout_secs: 10
      max_missed_pongs: 3
    limits:
      max_pending_handshakes: 256
      max_pending_stream_builds_per_tunnel: 64
      max_datagram_bytes: 65507
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

`liveness` / `limits` 的具体默认值在实现前通过负载测试确认；这里的数值是配置形态示例，
不是已经批准的生产参数。无论最终是否全部暴露成配置，代码中都必须有保守且有界的默认值。

### 3.1 线协议决策

本轮开始编码前先冻结以下决策并写入 golden wire tests：

1. **`purpose` 保留当前实际上线格式。** 默认选择继续发送字符串 `"Stream"` /
   `"Datagram"`，修正文档并拒绝把 Rust enum 判别值误认为 Serde 线值。如果确实要改成
   数字，必须使用显式序列化实现并视为协议升级，不能只加 `#[repr]`。
2. **绑定安全相关 Hello 字段。** 新 token claim 至少加入 `my_port`（或统一命名的
   `listen_port`），接收端验证 claim 与 Hello body 一致。`from_id`、`to_id` 等冗余字段
   也要有唯一、明确的 signed source of truth。
3. **增加签发时间和最大寿命约束。** token 增加 `iat`，验证 `iat` 的允许时钟偏差、
   `exp >= iat`、`exp - iat <= MAX_TOKEN_LIFETIME`，同时保留 nonce cache 到
   `exp + leeway`。
4. **per-stream KDF 是不兼容变更。** 如果本轮启用 per-stream key/IV 派生，Hello/ack
   audience 或显式 protocol version 必须升级，让新旧节点在握手阶段清晰失败，不能等到
   第一条业务密文才表现为 AEAD 错误。
5. **HelloStream 绑定证明。** 至少评估
   `MAC(stream_binding_key, stream_id || role || tunnel_generation)`；若本轮不实现，记录
   “知道 stream id 的链路内攻击者可抢占 waiter，影响限于 DoS”的 accepted risk。
6. **Datagram 上限。** 线上长度仍可保留 u32，但发送和接收必须共同执行
   `MAX_RTCP_DATAGRAM_BYTES`；forwarder 不得继续硬编码 5 KiB 缓冲导致对端合法大包直接
   终止整条 stream。

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

### F. 加固控制包解析和未认证握手入口

- [ ] 重写 `RTcpTunnelPackage::read_package()` 的长度处理：
  - 使用 checked subtraction；
  - `len < 8` 返回 `InvalidData`；
  - 当前版本要求 `json_pos == 8`；
  - `json_pos > len`、不足 cmd/seq、空或无效 JSON 全部返回 `InvalidData`；
  - 删除所有由远端长度控制的直接索引、unchecked range 和 `unwrap()`。
- [ ] 首包读取加入 deadline；慢连接超时后 shutdown。
- [ ] 为 accept 后、完成 tunnel 注册前的所有未认证握手增加全局 semaphore。
- [ ] handshake deadline 覆盖 source document 解析、authority I/O、HelloAck 写入和
  HelloAckConfirm 等待，而不是只包住最后两步。
- [ ] 评估按 source IP 的 token bucket、authority 查询负缓存和重复错误日志抑制。
- [ ] 为 parser 建 fuzz target/property test；任意字节输入只能返回 package/error，不能
  panic、无限等待或产生超上限分配。

### G. 实现 tunnel 原子替换和可靠 liveness

- [ ] 给 `RTcpTunnel` 增加 generation/id；map value 必须能比较具体实例。
- [ ] 将 `on_new_tunnel()` 改为 key-confirmation 和授权成功后的原子 replace，并返回旧
  tunnel；锁外调用旧 tunnel `close()`。
- [ ] 增加 `remove_if_current(key, generation)`，替换所有无条件 `remove_tunnel(key)`。
- [ ] `close()` 主动：
  - 设置 closed/cancel 状态；
  - shutdown bearing stream；
  - 失败所有 Open/ROpen/Pong waiter；
  - 终止或唤醒 pending stream-build task；
  - 保证 `run()` 在有界时间内退出。
- [ ] 修复 `Tunnel::ping()`：传播 `send_package()` 错误，不得无条件 `Ok(())`。
- [ ] keep-tunnel 改用带 seq 的 `ping_rtt()` 或等价 Ping/Pong，按配置 timeout 和连续失败
  次数 close + conditional remove。
- [ ] direct TCP socket 配置平台允许的 keepalive，作为 NAT/内核级补充。
- [ ] 新旧 tunnel 的替换日志记录 key、generation、原因和存活时长，不记录密钥材料。

### H. 统一 Open/ROpen 配额、方向和失败语义

- [ ] 在 `process_package()` spawn `ROpen` task 之前获取 pending-build permit。
- [ ] 明确配额是 Open/ROpen 共用还是各自独立；默认建议共用，防止交替请求绕过总上限。
- [ ] `Open` 只允许在 `can_direct == false` 的 tunnel 端处理；`ROpen` 只允许在
  `can_direct == true` 的 tunnel 端处理。
- [ ] 增加 per-peer 请求速率限制和突发上限。
- [ ] permit 覆盖地址解析、拨号、HelloStream 和 listener 交接，在所有 early return /
  timeout / cancelled 路径释放。
- [ ] 扩展 `OpenResp` / `ROpenResp` 错误码，至少区分 quota、wrong-direction、
  reconnect-failed、timeout、authorization-rejected；未知错误码仍安全失败。
- [ ] 重复 stream id 必须显式拒绝，`new_wait_stream()` 不得覆盖已有 waiter。

### I. 让 reconnect winner 与 RTT 语义一致

- [ ] 把 direct reconnect 的单个 attempt 扩展为“TCP connect + HelloStream 写入成功”；
  只有完整成功的 attempt 才能成为 winner。
- [ ] 某个 candidate TCP 成功但 HelloStream 失败时，继续等待/启动其他 candidate，不能
  提前取消整场竞速。
- [ ] 成功 RTT 从 attempt 启动计到 HelloStream 写入完成，记录
  `MeasurementLayer::Application`。
- [ ] 失败 attempt 尽可能记录 `Refused` / `Unreachable` / `Timeout`；若拿不到
  `local_addr`，扩展 name-client API 或明确记录“无法归档”，不能用 debug 日志冒充回写。
- [ ] 文档明确 standard Open/ROpen 的 reconnect 都由原 tunnel 发起侧执行，端口来自其
  remote stack endpoint；`Hello.my_port` 的实际消费场景单独说明。

### J. 绑定 Hello 字段并规范 token 时间窗口

- [ ] 按 §3.1 将 `my_port`/`listen_port` 加入签名 claim，验证 claim/body 一致。
- [ ] 盘点 Hello/HelloAck 中所有明文且影响路由、身份、keying、tunnel reuse 的字段；
  要么纳入签名 claim/HKDF context，要么删除冗余副本。
- [ ] token 增加 `iat`，实施最大寿命和 future-skew 检查。
- [ ] HKDF context 同时区分 semantic DID 与 canonical DEV DID，双方采用同一规范化规则；
  不再让文档宣称 canonical、代码却混入未经说明的 host-name 字符串。
- [ ] 如果 claim/KDF 改动造成不兼容，按 §3.1 升级 audience/protocol version，并增加明确
  的新旧版本拒绝测试。

### K. 实现业务 stream key separation 和使用预算

- [ ] 定义 stream KDF：

  ```text
  stream_key = HKDF-Expand(tunnel_secret,
      "rtcp stream key" || protocol_version || stream_id || purpose)
  stream_iv = HKDF-Expand(tunnel_secret,
      "rtcp stream iv"  || protocol_version || stream_id || purpose)
  ```

- [ ] 双方验证 stream id 是规范的 16-byte 值并在 tunnel 内唯一后，才构造加密 stream。
- [ ] 控制 tunnel 和业务 stream 分别维护 record/byte counters 与预算。
- [ ] 达到预算或最大 tunnel age 时建立替代 tunnel；复用 §G 的原子替换，不在旧 key 下
  继续开新 stream。
- [ ] 明确预算耗尽、seq 溢出和 KDF 输入错误的错误码、metrics 和日志。
- [ ] 评估 authenticated close record；若延期，记录“至少一条认证记录后 FIN 被当正常
  EOF，尾部截断无法与正常关闭区分”的 accepted risk。

### L. 修正文档真值并补 per-stream 授权章节

- [ ] `doc/rtcp/rtcp.md` 的每个相关段落明确标记“当前实现”或“目标语义”，不得混写。
- [ ] §4.5 按 golden wire decision 修正 `purpose` 示例和值域。
- [ ] §5.2/§5.3 按 authority/provenance 实现重写，并保留 typed revocation/freshness 拒绝。
- [ ] §5.4/§5.5 写清 semantic/canonical DID、stream KDF、实际
  `SHA-256(label || base_iv)` 和 key/record budget。
- [ ] §6/§8/§10 修正 tunnel key、`my_port`、reconnect winner、端口来源和 RTT layer。
- [ ] §12.1 使用 identity manager 实际文件名和探测顺序。
- [ ] 把 nonce cache 单位改为条目，写明淘汰、多实例和“纵深防护”定位。
- [ ] 将 §14 已落地历史移回对应正文；§14 只保留未完成 TODO 和 accepted risks。
- [ ] 新增 per-stream 授权章节，列出 process-chain 可见的 identity trust、
  `real_source_did`/`source_did`、连接来源、dest host/port、protocol/purpose 和拒绝语义。
- [ ] 修复文首本机绝对路径链接，并补 `aes_stream.rs`、`stream_helper.rs` 实现入口。

## 5. 必须增加/更新的测试

### 5.1 Peer identity 与 provenance

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

### 5.2 未认证入口和 parser

- [ ] 表驱动覆盖 `len = 0..=9`、截断 cmd/seq、`json_pos < 8`、`json_pos > len`、超长和
  非法 JSON；除合法 HelloStream 特例外都应得到确定的 `InvalidData`，不能 panic。
- [ ] 首包只发送 0/1 字节后停住：在 handshake deadline 内断开并释放 semaphore。
- [ ] 并发连接超过 pending-handshake 上限：多余连接快速拒绝，accept loop 和既有 tunnel
  仍可服务。
- [ ] 随机 owner / `device_doc_jwt` authority 查询超时：受统一 deadline、并发上限和负
  缓存约束。
- [ ] fuzz 至少覆盖 `read_package()`、Hello/HelloAck JSON 和 token claim 边界。

### 5.3 Tunnel 替换和 liveness

- [ ] 已有 tunnel A 时，完成全新 v2 握手的 tunnel B 原子替换 A；B 使用不同 session
  key/IV，A 被 close。
- [ ] A 的 `run()` 在 B 注册后退出，不得把 B 从 map 删除。
- [ ] 未完成 key-confirmation、listener 拒绝或 freshness commit 失败的新 tunnel 不得替换
  A。
- [ ] `ping()` 写失败必须向调用者返回错误。
- [ ] 只写成功但收不到匹配 Pong：达到连续失败阈值后 close/remove 并允许重建。
- [ ] 模拟 NAT black-hole/半开连接：在配置的 liveness 上界内恢复，不依赖操作系统默认
  TCP 超时。
- [ ] 并发两个新 tunnel 抢同一 key：最终 map 中恰好一个 current generation，所有 loser
  都关闭且不能删除 winner。

### 5.4 Open/ROpen、reconnect 与授权

- [ ] inbound `Open` 和 `ROpen` 分别/合计达到配额时，下一条请求收到明确 quota 错误，
  不启动额外拨号 task。
- [ ] 在错误 tunnel 角色上发送 Open/ROpen：返回 wrong-direction，不触发 DNS、connect
  或 listener。
- [ ] 高频交替 Open/ROpen 不能绕过总配额或 per-peer rate limit。
- [ ] 重复 stream id 不能覆盖 waiter；迟到 HelloStream 被关闭。
- [ ] candidate A TCP connect 成功但 HelloStream 写失败、candidate B 完整成功：B 获胜。
- [ ] reconnect 成功只记录 Application RTT；失败 candidate 的 outcome 与最终错误一致。
- [ ] per-stream process-chain 能看到可信 identity/provenance 与目标字段，并能在建立业务
  转发前拒绝无权限 dest host/port。

### 5.5 线协议、KDF 与 Datagram

- [ ] 保存 Hello、HelloAck、Open、ROpen 的 golden bytes/JSON，锁定 `purpose`、字段名、
  claim 和 protocol version。
- [ ] 篡改 Hello body 的 `my_port`/`listen_port`，token/body mismatch 必须在任何回连前
  拒绝。
- [ ] 缺失/未来 `iat`、`exp < iat`、寿命超限、允许 skew 边界分别有测试。
- [ ] 相同 tunnel secret 下不同 stream id 或 purpose 派生不同 key/IV；双方对同一 context
  派生完全一致。
- [ ] 重复 stream id、非法长度和非 hex 值在 KDF 前拒绝。
- [ ] record/byte/tunnel-age 预算触发轮换；旧 tunnel 不再接受新 stream。
- [ ] Datagram 等于上限成功，上限 + 1 在发送端和接收端都返回专用错误且不破坏后续协议
  framing。
- [ ] 新旧 protocol version/audience 组合在握手阶段明确失败，不出现首条业务 AEAD 才失败。

## 6. 发布顺序

### Phase 0：冻结决策和测试基线

1. 确认 §3.1 的 `purpose`、token claim、`iat`、protocol version、stream KDF 和 Datagram
   上限决策。
2. 先补当前 v2 golden wire tests 和已知 bug 的失败测试；测试必须能在修复前稳定复现，
   不能只靠人工日志判断。
3. 建立 parser fuzz target 和 tunnel replacement generation 模型。

### Phase 1：先落地不依赖 resolver API 的资源/生命周期修复

1. 完成 §F parser、首包 deadline 和 pending-handshake 上限。
2. 完成 §G tunnel generation、conditional remove、ping 错误传播和 Pong liveness。
3. 完成 §H Open/ROpen 配额、方向、重复 stream id 和取消清理。
4. 完成 §I reconnect 完整 winner 与 RTT 口径。

这一阶段不得改变已经上线的密钥派生或线值；可以独立回归资源安全和重连自愈。

### Phase 2：准备并切换权威身份解析

1. 先为所有生产 `did:web` 身份发布静态 `/.well-known/did.json`，并验证其中默认 gateway
   key 与 RTCP 实际私钥一致；按需发布 `owner.json` / `device.json`。
2. 不提供 HTTPS 的身份迁移到 `did:bns`，确认 BNS resolver/indexer readiness。
3. 发布带 provenance 的 resolver API 与 RTCP policy/config。
4. 切换 RTCP 默认值为 `authority_current`、关闭两个 fallback。
5. 观察 authority unavailable、schema error、key mismatch 指标；只对受控 bootstrap 环境
   局部开启兼容开关，不做全局回滚。

### Phase 3：原子发布不兼容协议变更

1. 同时发布 §J 的 signed Hello 字段/`iat` 和 §K 的 per-stream KDF/预算。
2. 升级 audience 或 protocol version；两端必须同步升级，不允许静默兼容。
3. 先灰度 direct tunnel，再覆盖 bootstrap/relay/keep-tunnel 和 Datagram。
4. 旧版本失败必须发生在握手阶段，并有可区分的版本错误指标。

### Phase 4：文档收口和兼容代码退场

1. 完成 §L，并把 `doc/rtcp/rtcp.md` 作为当前协议真值重新核对一遍。
2. 稳定后评估删除 TXT `DEV/PKX` 身份解析代码，仅保留 DNS 的地址/服务发现职责。
3. 决定 authenticated close、HelloStream MAC 和身份隐私是否进入下一协议版本；未实现项
   转成有 owner/里程碑的 accepted-risk TODO。

## 7. 验收标准

- 当 HTTPS/BNS 权威文档与 DNS TXT 冲突时，RTCP 最终使用的 Ed25519 key 必须来自权威结果。
- 权威结果不可用或不合格时，默认不能建立逻辑 DID tunnel。
- 任何 TXT/self-declared 兼容结果都有显式配置、显式 non-authoritative trust 和可观测记录。
- 公网 SN/relay 的授权链不能消费 non-authoritative owner/zone。
- `did:dev` 匿名/自认证能力保持可用，但不会被误报为 `did:web`/`did:bns` 权威身份。
- tunnel key、Hello/HelloAck 验签和 process-chain 看到的 identity provenance 来自同一次
  解析决策，不出现“握手用一个 key、授权相信另一个来源”的分裂。
- 任意未认证控制包输入都不能 panic 或产生无界 task、等待、网络查询和内存分配。
- NAT 半开、对端崩溃或替换竞态下，合法新 tunnel 能在配置的 liveness 上界内替换旧值；
  旧 generation 退出绝不会删除新 tunnel。
- Open/ROpen 的并发量和速率始终有界，错误方向不触发出站连接。
- reconnect 只有完成 HelloStream 才计为成功，RTT layer、失败 outcome 与文档一致。
- 所有安全相关 Hello 字段都能追溯到签名 claim/HKDF binding 或明确的非安全用途；
  `my_port` 不再可被无检测篡改。
- 每条业务 stream 有独立 key/IV，stream id 唯一，tunnel/stream 都有明确 key-use budget。
- 线协议 golden tests、parser fuzz、并发替换/配额测试和正常 RTCP 集成测试全部通过。
- `doc/rtcp/rtcp.md` 不再混写“当前实现”和“目标语义”，并完整说明 per-stream 授权边界。

最低验证命令：

```bash
cd src
cargo test -p cyfs-gateway-lib --lib rtcp::rtcp::tests:: -- --test-threads=1
cargo test -p cyfs-gateway-lib --lib aes_stream::tests:: -- --test-threads=1
cargo test -p cyfs-gateway-lib --lib stack::rtcp_stack::tests:: -- --test-threads=1
cargo test -- --test-threads=1
```

涉及 `name-client` API 或 lockfile 更新时，还必须在固定的 `buckyos-base` commit 上跑对应
resolver/verification 测试，并把新 commit 写回本文“适用基线”；禁止只跟随 branch 而不锁定
验收版本。
