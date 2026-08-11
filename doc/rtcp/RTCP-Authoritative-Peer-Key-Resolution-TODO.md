# RTCP Peer Identity、Tunnel 与 Stream 安全收口 TODO

状态：**v3 安全收口 DONE（2026-07-24）；逻辑名字与 canonical DEV DID 一一绑定
follow-up DONE（2026-07-24）**

本轮已完成的实现收口：

- 出站 peer key 改为 DID method authority / 严格可信快照优先；普通 DNS TXT 只在
  `dns_txt_bootstrap: true` 且 authority 真正不可用时作为带
  `DnsTxtBootstrap` provenance 的非权威启动提示；
- 入站按 I1–I3 重排为“纯解析/预过滤 → 持钥证明 → `LocalAndZone` 验证 → listener
  授权 → 延迟缓存提交”，删除 self-declared/observed fallback，并加入后台
  authority singleflight 确认、升档和否定踢除；
- 配置默认 fail-closed，旧 fallback 字段和未实现枚举启动即报错；安全配置变更要求
  stack 重启；
- 控制包 parser、首包 deadline、握手/源 IP/stream 配额、Open/ROpen 方向和错误码、
  reconnect winner、TCP keepalive、Ping/Pong liveness、Datagram 上限全部收口；
- 线协议升级为 v3，Hello 签名绑定 semantic/canonical target、`listen_port`、
  `iat`/`exp`；session HKDF 同时绑定 semantic/canonical DID，业务 stream 使用独立
  key/IV 和使用预算；
- identity provenance、canonical DID、purpose 与目标字段已进入 tunnel endpoint 和
  per-stream process-chain；[`rtcp.md`](rtcp.md) 已重写为当前实现真值。
- 入站 `known_owner` 关系档位已接通：只消费 name-client 验证后的 `authz_owner` 与
  OwnerDocument evidence，不信任 claim owner，也不在握手路径增加 method-authority
  外联。

清单状态已按当前代码回填：

- `[x]` 表示已经落地并验证（含 v3 收口与“一一绑定” follow-up）；
- `Deferred` 表示已完成取舍、但明确不属于本轮发布阻塞项，不能解释成已实现。

原清单中依赖未来上游 API 的 `NotProvenRegressed` 类型收编、仓库当前不存在承载面的
metrics backend，以及 authenticated close / HelloStream MAC 不作为本次发布阻塞项：
前两项继续使用本地 typed freshness 匹配与不含密钥材料的结构化日志，后两项已在
`rtcp.md` “Accepted risks” 中明确记录。parser 使用有界 property-style 单测覆盖任意
短输入；仓库未新增 `cargo-fuzz` workspace。

本 TODO 启动时的适用基线：

- `cyfs-gateway` 当时的 RTCP v2 实现；
- `buckyos-base` / `name-client` commit
  `c5b7f8dc7861dd7cbb5f3e238e1d235209098da8`；
- Beta2.2 是 breaking-change 版本，本 TODO 默认选择安全默认值，不保留隐式兼容降级。

相关文档：

- [`doc/rtcp/rtcp.md`](rtcp.md)
- [`doc/rtcp/rtcp_v2_review.md`](rtcp_v2_review.md)
- [`doc/rtcp/rtcp on new tunnel 身份验证.txt`](rtcp%20on%20new%20tunnel%20身份验证.txt)
  （入站具名 from 准入的**规范伪代码**：不变量 I1–I3、既定决策 D1–D3、握手①–⑪与后台
  权威确认全流程；同名 `.drawio` 是配套流程图。§2.5/§C 是它在本 TODO 的落地入口，
  两者冲突时以该文为准）
- [`doc/rtcp/RTCP-New-Tunnel-Replaces-Old-TODO.md`](RTCP-New-Tunnel-Replaces-Old-TODO.md)
  （已完成：§G 依赖的入站 tunnel 原子替换、`instance_id`、compare-and-remove 与
  close fail-fast）
- [`doc/SN/RTCP-SN-Registered-Device-Authorization-TODO.md`](../SN/RTCP-SN-Registered-Device-Authorization-TODO.md)

本文档曾是上述 review 的统一实施入口。以下正文保留任务启动时按 HEAD 复核的决策、
代码任务、测试和验收标准，作为 v3 收口的审计轨迹；当前实现真值以文首完成记录及
`rtcp.md` 为准。后续维护不得把 review 中已经过时的认证行为重新带回代码。

## Follow-up：逻辑名字与 canonical DEV DID 一一绑定（DONE 2026-07-24）

本 follow-up 不改变 RTCP v3 的 tunnel 可用性定义，也没有修改线协议。目标是补齐
身份模型的本地仲裁：对 `did:web` / `did:bns` 等具名设备，只接受一个逻辑名字与一个
canonical `did:dev` 的一一绑定。直接使用同一 `did:dev` 寻址不算第二个逻辑名字，仍应
与该设备的具名寻址复用同一设备 tunnel。

实现真值见 [`rtcp.md`](rtcp.md) §3.1/§3.4/§5：`RTcpTunnelMapState` 增加
`binding_by_canonical_dev` 反向唯一性索引与 `binding_by_instance` 实例绑定表；
入站在 `replace_authenticated_inbound` 的提交序列内做绑定门与 same-version 冲突门，
握手路径另有 rejection-only 预检查；出站 `acquire_outbound` /
`register_outbound_if_absent` 在复用与注册前仲裁具名绑定（DeviceDocument 与 DNS TXT
bootstrap 名字参与绑定；zone 目标与裸 `did:dev` 不参与）；权威否定
`close_verified_identity` 连同出站具名绑定实例一并踢除。

目标语义：

- 一个逻辑名字在任一时刻只绑定 authority/name-client 已验证的 current canonical
  `did:dev`；
- 一个 canonical `did:dev` 在任一时刻只属于一个已验证逻辑名字，不能被两个不同逻辑
  名字当作两个授权主体复用；
- 同一逻辑名字出现更高版本的已验证 DeviceDocument 时，新版本优先，并关闭旧 revision /
  旧 canonical key 下的 tunnel；
- same-version 不同内容属于冲突，必须 fail closed，不能让两个绑定同时保持 current；
- 裸 `did:dev` 的 key identity 不自动获得具名身份的 owner/zone 权限。

任务启动时与上述目标不一致、现已收口的事实：

- `RTcpInner::format_tunnel_key()` 只使用双方 canonical DEV DID（以及可选 bootstrap URL）。
  这一点保持不变：一一绑定不改 tunnel key 形态，仲裁在 tunnel map 的绑定索引层完成；
- `RTcpTunnelMap` 原来只有 `logical DID -> tunnel instances` 二级索引，现已补上
  `canonical DEV DID -> logical DID` 反向唯一性索引（`binding_by_canonical_dev`）；
- 原 `test_rtcp_multiple_names_to_same_dev_share_key_by_design` 断言两个不同逻辑名字
  共享 tunnel，已改写为 `test_rtcp_second_logical_name_to_same_dev_is_rejected`
  冲突拒绝测试；
- 同一逻辑名字按 `DocumentRevision` 踢除严格旧 revision 的路径复用既有
  verified-cache CAS、提交锁和逻辑 DID 二级索引，未另造版本判断规则；踢除时在同一
  临界区释放旧 canonical key 的反向绑定。

实施任务：

- [x] 在 verified identity 仲裁中增加 canonical DEV DID 到逻辑名字的反向绑定；绑定检查、
      verified-cache commit、主 tunnel map 和两个方向的索引更新必须在同一提交序列中完成。
      （`VerifiedTunnelIdentity` 携带 `canonical_dev_did`；仲裁在
      `authenticated_commit_lock` + map 临界区内完成。）
- [x] 出站解析在复用已有 canonical tunnel 前检查已验证名字绑定；不同逻辑名字命中同一
      canonical DEV DID 时明确拒绝，不能静默复用先建立的 tunnel。
      （`acquire_outbound` / `register_outbound_if_absent` 双检查；具名复用会把绑定
      落到被复用实例上；zone 目标与裸 `did:dev` 不构成设备名绑定。）
- [x] 入站具名 tunnel 在 listener 授权和发布前执行相同的一一绑定检查；冲突连接不得替换
      已存在的合法 tunnel。（握手路径 rejection-only 预检查 + 发布时在提交序列内的
      权威绑定门，拒绝发生在 primary insert 之前。）
- [x] 同一逻辑名字的更高版本 DeviceDocument 继续使用 name-client 的 revision/CAS 结果
      淘汰旧绑定；same-version 内容冲突按 definite rejection 处理。
      （CAS `RejectedConflict` 拒绝 + map 内 same-version 门兜底；原“keep both”
      错误分支已删除。）
- [x] 保留“逻辑名字与其 canonical `did:dev` 直接寻址共享设备 tunnel”的行为，并增加测试
      区分 direct key DID 与第二个逻辑名字。
- [x] 将 `test_rtcp_multiple_names_to_same_dev_share_key_by_design` 改为冲突拒绝测试，并补充
      出站复用、入站并发、换钥升级、same-version conflict 和清理索引的覆盖。
      （新增/改写：`test_rtcp_second_logical_name_to_same_dev_is_rejected`、
      `inbound_second_logical_name_for_same_canonical_dev_is_rejected`、
      `concurrent_conflicting_names_admit_exactly_one_binding`、
      `same_revision_conflicting_content_is_rejected_fail_closed`、
      `outbound_binding_arbitrates_reuse_and_cleanup`、
      `named_reuse_of_unbound_tunnel_records_binding`、
      `closed_instances_do_not_defend_a_binding`、
      `outbound_binding_blocks_conflicting_inbound_name`、
      `authority_negative_also_closes_outbound_bound_tunnels`，并扩展换钥升级与
      authority-negative 清理测试的绑定断言。）
- [x] 实现完成后把一一绑定不变量及更高版本 DeviceDocument 优先规则写入 `rtcp.md`。
      （§3.1 不变量与绑定生命周期、§3.4 入站步骤、§5 替换资格、§10 出站名字迁移的
      既定取舍。）

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
   `verify_source_device_doc_self_declared()`。按 §2.5 决策 D3，这条路径将被整体删除
   （不是默认关闭），Unavailable 降级改由 `anonymous` 档位决定，而不能只修出站 TXT
   顺序。
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

### 1.3 合并 RTCP v2 review 后的结论（任务启动时快照）

以下文字保留任务启动时的复核结果。第 2–7 条已经在本轮 v3 收口中处理；它们不是当前
未完成项，完成状态见 §4 的 `[x]` 清单。

1. **已修复（2026-07-24，commit 736a7178）：重复 tunnel 拒绝已改为原子替换。** 入站
   连接在完整认证、anti-replay、key-confirmation、listener 准入和设备文档提交全部成功
   后，按 canonical key 以 last-accepted-wins 原子替换旧 tunnel；`instance_id` +
   `remove_if_current` 保证旧实例延迟退出不能删除新实例。实施与测试记录见
   [RTCP-New-Tunnel-Replaces-Old-TODO.md](RTCP-New-Tunnel-Replaces-Old-TODO.md)。
   本条不再是待办；后续 liveness 也已在 §G 完成。
2. **liveness 仍不能可靠清理僵尸 tunnel。** `RTcpTunnel::run()` 没有协议级 idle/liveness
   判定；TCP socket 未配置 keepalive。`Tunnel::ping()` 已改为传播 `send_package()`
   错误，带 seq 并等待匹配 `Pong` 的 `ping_rtt()` 也已存在并被 prober 使用，但
   keep-tunnel 路径（`rtcp_stack.rs` 的 `start_keep_tunnel`）仍调用不等 `Pong` 的
   `ping()`——写入本地 TCP buffer 成功即记为 reachable。替换修复后 NAT 半开不再阻塞
   合法重连（新连接会踢掉僵尸），但僵尸 tunnel 的主动检测和清理仍缺失。
3. **inbound `ROpen` 无配额且不校验方向。** `Open` 有 64 槽 semaphore，`ROpen`
   则在读循环中直接 spawn，每条请求都能触发地址解析、并发拨号和 `HelloStream`。
4. **未认证入口缺少完整的资源和边界保护。** `read_package()` 在检查最小包长和
   `json_pos` 上界前执行索引/切片，畸形首包可触发 panic；首包读取没有 deadline，accept
   后的未认证 task 也没有全局并发上限。`device_doc_jwt` 的文档验证当前以
   `ResolveVerifyOptions::default()`（`BestAvailable`）在握手同步路径执行且先于持钥
   证明，任意构造的输入即可触发 method-authority 查询。按 §2.5 不变量 I1，收口方向
   是把权威 I/O 全部移出握手（`LocalAndZone` + 后台一次性确认），而不是仅把它计入
   握手预算。
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
- v2 tunnel 建立以 HelloAck/HelloAckConfirm key-confirmation 完成为成功边界；
- 入站 tunnel 已实现 last-accepted-wins 原子替换：`replace_authenticated_inbound`
  在 map 临界区内同步标记旧实例 closed，锁外完成 waiter 清理和 shutdown；清理一律走
  `remove_if_current`（按 `instance_id` compare-and-remove）；closed tunnel 的
  ping/open/datagram 以 `BrokenPipe` 快速失败；出站保持 first-wins 的
  `register_outbound_if_absent`；
- 入站具名验证第 1 级已走 name-client `resolve_and_verify_device_document_jwt`
  （AuthSubject），owner 只取 `verified.authz_owner`，不用 payload 自声明；
  `is_definite_verify_rejection` 已实现设计 `is_definite` 的 Definite 集合
  （Definite 拒 / 其余降级；当前降级仍指向 self-declared fallback，待 §C 按 D3 删除）；
- verified cache 提交已推迟到持钥证明、key-confirmation、listener 授权全部成功之后
  （设计第⑩步），verify 本身不隐式写缓存，攻击者不能只靠提交一份文档推进 high-water；
- 按逻辑 DID 的二级索引与 superseded-revision 踢除已落地（设计第⑪步，
  `CacheWriteOutcome` 是 revision 并发仲裁点；实现与测试见
  [RTCP-New-Tunnel-Replaces-Old-TODO.md](RTCP-New-Tunnel-Replaces-Old-TODO.md)
  「按逻辑 DID 踢除与 tunnel map 二级索引」一节）。

review 中“明确吊销仍会进入 self-declared fallback”的描述已经过时。后续修改必须保留
上述 typed rejection 和 anti-rollback 行为。Unavailable 类默认 fallback 的关闭方式已由
§2.5 决策 D3 定稿：**整体删除 self-declared 回落路径**（含 `add_observed_cache` 观察
写入），Unavailable 时的唯一降级是 `anonymous` 档位控制的 key 身份准入，不是重新合并
所有失败类型，也不是加一个开关保留旧路径。

### 1.4 文档与当时线协议的已确认偏差（任务启动时快照）

以下偏差均已在 v3 代码或 `rtcp.md` 中修正，列表作为变更依据保留：

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
- `did:web` 当时实现是 TXT-first，而不是文档所写 DID Document first；
- identity 文件实际使用 `device.jwt` / `device_doc.jwt` / `did.json`，不是
  `device.doc.jwt`；
- AEAD nonce base 实际是 `SHA-256(label || base_iv)`；
- JWT `exp` 只提供过期上界；当前 token 没有 `iat` / `nbf`，文档所写
  `[exp-leeway, exp+leeway]` 不是验证器实际建立的双边窗口；
- 当时的 `doc/rtcp/rtcp.md` 尚未说明每条 stream 的 process-chain 授权点和可见字段。

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
  freshness 不满足时，握手失败。入站侧唯一例外见 §2.5 D3：验证 Unavailable（非 Definite
  否定）且 `anonymous: allow` 时可降级为匿名 key 身份准入——这不算逻辑 DID 认证成功，
  不得携带 owner/zone。
- 不得因为权威文档 schema 错误、缺字段或超时而自动改信普通 DNS TXT。
- 权威结果与 TXT 冲突时，永远使用权威结果；不得做 first-win 或“多数票”。
- DNS TXT fallback 必须由 RTCP stack 配置显式开启，且结果必须标记为 non-authoritative。
- non-authoritative 身份不得填充可授权的 owner/zone 字段，也不得通过公网 SN/relay 的
  默认准入策略。
- 日志、process-chain 变量和 metrics 必须保留 trust/provenance；不能在提取出
  canonical `did:dev` 后丢失来源。

### 2.1 Tunnel 生命周期契约

已落地（2026-07-24，不得回退；实现与测试见
[RTCP-New-Tunnel-Replaces-Old-TODO.md](RTCP-New-Tunnel-Replaces-Old-TODO.md)）：

- 相同 tunnel key 的新连接只有在身份验证、key-confirmation、listener 授权和需要的
  freshness/cache commit 全部成功后，才有资格替换旧 tunnel。
- 替换在 map 内原子完成：插入新 tunnel 时返回旧 tunnel，旧实例在临界区内同步标记
  closed，锁外完成 waiter 清理和 transport shutdown。
- 每个 tunnel 有进程内唯一 `instance_id`；`run()` 退出时只执行
  `remove_if_current(tunnel_key, instance)`，旧 tunnel 绝不能删除后来替换进去的新值。
- `close()` 幂等，唤醒或终止阻塞中的读循环，并使所有后续写、Open/ROpen waiter 和
  Pong waiter 快速失败。

本轮已完成：

- keep-tunnel 的健康判断等待匹配的 `Pong`；仅仅成功写入本地 TCP buffer 不算远端存活。
- 连续 liveness 失败后 close + conditional remove，让下一轮重建；TCP keepalive 只作为
  补充，不替代协议级 Ping/Pong。

### 2.2 未认证入口与资源契约

- 当前控制包头固定为 8 字节；本协议版本必须要求 `len >= 8` 且 `json_pos == 8`。如果
  未来需要扩展头部，应先增加明确版本，不允许当前解析器宽松猜测。
- 所有基于远端长度/偏移的访问必须使用 checked arithmetic 和安全切片，任何畸形输入都
  返回 `InvalidData`，不得 panic。
- 首包、身份解析、HelloAck/HelloAckConfirm 必须共享一个有上界的握手 deadline。
- listener 必须有全局 pending-handshake semaphore；按 IP 的速率限制和日志抑制作为
  纵深防护。“随机 owner/doc JWT 放大外部 authority 查询”由 §2.5 I1/I2 结构性消除
  （握手零外网，外联只发生在有闸门有预算的后台确认），不依赖这里的限速兜底；限速
  兜底仍保留，用于本地 CPU/连接资源。
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

### 2.5 入站具名 from 准入契约（设计已定稿）

规范流程见
[`doc/rtcp/rtcp on new tunnel 身份验证.txt`](rtcp%20on%20new%20tunnel%20身份验证.txt)
（步骤①–⑪伪代码，基于 name-lib 上游 API；范围是具名 from = 逻辑 DID +
`device_document_jwt`。`did:dev` 匿名路径、包解析/资源边界仍由本文 §F 约束）。
实现与 review 按以下三条不变量验收：

- **I1 握手零外网。** 匿名/任意构造的输入在握手同步路径零外网 I/O，最多消耗一次
  本地 ed25519 验签。步骤顺序必须是：parse-only 解码 → `claim.id`/`from_id` 绑定 →
  claim 预过滤（纯字符串比较，只用于拒、永不用于信）→ 持钥证明
  `verify_tunnel_token` → `resolve_and_verify_device_document_jwt`。文档验证固定
  使用全流程唯一一份 `admission_policy`（`source = LocalAndZone`、
  `allow_stale_cache = true`、`allow_unverified_cache_when_unavailable = false`、
  `allow_self_signed_when_missing = false`），结构上不碰 method authority；其中
  zone-resolver 是 zone 内基础设施（有界目的地、可限速），不构成对外放大。
- **I2 外联有闸门、有预算。** 全流程唯一可能外联外网的是每身份一次的后台权威确认
  `confirm_authority_binding`，只能由“信任库内 owner 真实签名过的文档”（已通过
  第⑤步）触发，并受 singleflight + 限速 + 负缓存 + 全局并发上限 + 超时约束。
  总外网读 ≤ 活跃具名身份数（same_zone 栈 ≈ zone 设备数），与握手频率、攻击流量
  无关。
- **I3 rtcp 不重复实现验证。** rtcp 只拥有两块逻辑：持钥证明（协议签名，含
  aud/nonce/iat-exp，见 §F/§J）+ 策略映射（档位/时机）。文档真伪、owner 锚定
  （`expected_owner` 绝不来自 payload 自声明）、valid_iat 防回滚、时效三态全部由
  name-lib 一次调用判定。

既定决策（实现时不得“顺手”偏离）：

- **D1 不做后台定时器重验吊销。** 吊销传播依赖两条路：a) 新文档随新握手到达 →
  第⑪步按逻辑 DID 踢旧 revision（已落地）；b) 第⑨步每身份一次的后台权威确认。
  Accepted risk：吊销后，合法设备若不再连接本节点，本节点上已建立的旧 tunnel 不会
  被发现。这是显式接受的风险，实现时不得隐式“顺手修复”。
- **D2 关系档位实现 `same_zone | known_owner | any`。** `known_owner` 要求
  `AuthSubject` 验证结果可用于授权、`authz_owner` 非空且带可信 OwnerDocument evidence；
  `same_owner` / `unknown_owner_escalation=budgeted` 仍只预留枚举值，配置了未实现值必须
  启动报错，不得静默接受。
- **D3 没有 self-declared 回落路径。** 离线/首次组网的可用性来自预置信任材料
  （`set_local_authority_override` / 预置 verified cache），不来自验证放松。验证
  Unavailable（MissingDependency / Resolve 不可达，即“本地评估不了 ≠ 假”）时的
  唯一降级是 `anonymous: allow` 下按 key 身份准入：canonical_dev 来自已通过持钥
  证明的候选 key，未验证声明仅供观测/日志，不填 owner/zone、不进任何授权判断。

trust 档位在 tunnel 生命周期内允许单向升级：握手按证据映射（如
`TrustedZoneSnapshot`），第⑨步后台权威确认通过（`RequireAuthorityCurrent`）后升为
`MethodAuthorityCurrent` 并 `add_verified_cache` 落盘，使该身份后续握手在本地直接
命中最高档；权威否定（AuthorityNotCurrent / Definite）则踢除 tunnel 并写负缓存；
不可达 ≠ 否定，有限退避后放弃，档位保持快照级不变。

## 3. 配置与类型设计

不要新增含义模糊的单一 `authoritative: bool`。建议把解析来源要求与兼容 fallback 分开：

```yaml
stacks:
  rtcp:
    protocol: rtcp
    # 出站/目标身份解析（§A/§B 的收口对象）
    peer_identity:
      requirement: authority_current # authority_current | trusted_snapshot
      dns_txt_bootstrap: false
    # 入站具名准入（§2.5/§C；字段对应设计文档的 SecurityConfig）
    inbound_admission:
      anonymous: reject              # allow | reject：具名验证 Unavailable 时能否降级为 key 身份
      named_min_relation: same_zone  # same_zone | known_owner | any；其余值配置即报错（D2）
      authority_reconfirm_max_age: unlimited # 权威确认复用期；懒检查，无后台定时器（D1）
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
  的当前判断；默认值。**只约束出站/目标身份解析**：入站握手期文档验证固定使用 §2.5 的
  `admission_policy`（`LocalAndZone`），不消费 `requirement`；入站的权威确认由第⑨步
  后台任务完成，不在握手同步路径。
- `trusted_snapshot`：允许未过期且有可信来源的 Host/Zone/Published cache 结果，但绝不接受
  observed/unverified/TXT；用于明确需要离线容错的受控部署。
- `dns_txt_bootstrap: true`：仅在权威解析 unavailable 时允许旧 `DEV/PKX` 路径；它不改变
  `requirement` 的含义，返回的 trust 必须是 `DnsTxtBootstrap`。
- 原 `inbound_self_declared_fallback` 开关随 D3 一并取消：self-declared 路径不是
  “默认关闭”，而是**不存在**，也不允许用配置重新引入。Unavailable 降级语义完全由
  `anonymous` 承担。
- `inbound_admission` 三个字段的语义见 §2.5；`named_min_relation` 的档位判断只消费
  第⑤步输出（`authz_owner` + 验签文档的 `zone_did`），claim 预过滤只拒不信。

内部结果至少应携带：

```rust
enum RtcpPeerKeyTrust {
    KeyDid,
    MethodAuthorityCurrent,
    TrustedHostSnapshot,
    TrustedZoneSnapshot,
    DnsTxtBootstrap,
}

struct ResolvedRtcpPeerKey {
    semantic_did: DID,
    canonical_dev_did: DID,
    ed25519_pk_der: [u8; 32],
    trust: RtcpPeerKeyTrust,
    resolver_id: Option<String>,
}
```

原 `SelfDeclaredDocument` 变体随 D3 删除——没有产生它的代码路径就不该有这个档位。
`DnsTxtBootstrap` 仅出站 TXT bootstrap 使用，必须被视为 non-authoritative；若允许它
进入握手，process-chain 必须先检查 trust，再决定是否授予任何业务访问。
`MethodAuthorityCurrent` 除出站 `RemoteAuthority` 解析外，还可由第⑨步后台确认对已
准入 tunnel **升级**得到（§2.5）；trust 档位必须随 tunnel 记录且升级可观测。

`liveness` / `limits` 的具体默认值在实现前通过负载测试确认；这里的数值是配置形态示例，
不是已经批准的生产参数。无论最终是否全部暴露成配置，代码中都必须有保守且有界的默认值。

### 3.1 线协议决策

本轮开始编码前先冻结以下决策；已落地的 wire/contract 测试状态见 §5.5，完整 golden
corpus 的扩充按该节 Deferred 处理：

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

- [x] 删除 `resolve_handshake_identity()` 开头的 `did:web` TXT 预解析。
- [x] 默认先走 DID method 解析；解析成功后不得再查询 TXT。
- [x] DID 解析失败时默认直接返回错误。
- [x] 只有 `dns_txt_bootstrap: true` 时才调用
  `resolve_handshake_identity_by_web_name_info()`。
- [x] fallback 日志明确输出 `non-authoritative DNS TXT bootstrap`，不得写成普通
  “resolve success”。
- [x] `DEV=` 若保留兼容支持，不得再让 “JWT without verify 后取 `x`” 看起来像完成了
  document verification；函数、类型和日志都应标明它只是在解析 bootstrap hint。

### B. 增加带 provenance 的 exchange-key API

现有 `resolve_ed25519_exchange_key()` 丢弃 `ResolvedDocument.resolution_metadata`，无法实现
严格 policy 和可观测性。二选一：

- **未采用（已由下一项替代）：** 在 `name-client` 增加
  `resolve_ed25519_exchange_key_ex(did, policy) -> ResolvedExchangeKey`，返回 key、文档解析
  metadata、freshness/authority 证据；推荐方案。
- [x] 或 RTCP 直接调用 `resolve_did_ex()`，按统一的 ZoneDocument/DeviceDocument key 选择
  API 提取 exchange key；禁止在 RTCP 内复制一套容易漂移的 key-selection 规则。

严格模式必须使用 `ResolveSourcePolicy::RemoteAuthority`，不能把一次
`BestAvailable` 成功笼统记录为 authority-current。`trusted_snapshot` 模式则必须检查
返回 evidence/cache status，拒绝 `ObservedFallback`、`NeedProof` 未完成验证以及 stale
结果。

### C. 收口接收侧逻辑身份（按《rtcp on new tunnel 身份验证.txt》①–⑪实施）

已落地（2026-07-24 按 HEAD 复核，不得回退）：

- [x] 第⑤步组合动词：`resolve_and_verify_device_document_jwt`（AuthSubject），owner
      只取 `verified.authz_owner`；`subject_did` 与 `from_id` 的绑定校验存在（当前在
      verify 成功后做，位置随下面的重排任务前移）。
- [x] `is_definite_verify_rejection` 实现设计 `is_definite` 的 Definite 集合
      （InvalidDocument / DocumentIdMismatch / OwnerMismatch / DetachedOwnerRejected /
      SignatureRejected / RevokedByOwnerPolicy / RejectedByNegativeState）。
- [x] 第⑥步 freshness“只拒确证回归”：本地 OlderThanLatestKnown /
      ConflictAtSameRevision + authority NotCurrent(DifferentDocument | Superseded)。
- [x] 第⑩步延迟缓存提交：`PendingVerifiedCacheEntry` 在持钥证明、key-confirmation、
      listener 授权全部成功后才 `add_verified_cache`。
- [x] 第⑪步按逻辑 DID 踢旧 revision：二级索引 + `CacheWriteOutcome` 仲裁（见
      [RTCP-New-Tunnel-Replaces-Old-TODO.md](RTCP-New-Tunnel-Replaces-Old-TODO.md)）。

完成记录：

- [x] **按①–⑤重排握手顺序（I1）。** parse-only 解码取 claim → `claim.id == from_id`
      绑定 → claim 预过滤（`same_zone` 时 `claim.owner != my_owner_did` 直接拒；纯
      字符串比较，只拒不信）→ `verify_tunnel_token`（用 claim 候选 key，
      `canonical_dev = did_dev(candidate_key)`）→ 第⑤步文档验证。当前实现已按该顺序
      执行，文档验证不会先于持钥证明。
- [x] **固定 `admission_policy` 替换 `ResolveVerifyOptions::default()`。**
      `LocalAndZone` + `allow_stale_cache = true`，其余兜底全关（§2.5 I1）；全流程
      唯一一份，任何地方不得另配解析策略。锁定的 name-client commit 已含
      `ResolveSourcePolicy::{LocalAndZone, RemoteAuthority}`，无需等上游。
- [x] **删除 `verify_source_device_doc_self_declared()` 及其 `add_observed_cache`
      写入（D3）。** 非 Definite 失败（MissingDependency / Resolve 不可达）改为：
      `anonymous: allow` 时按 `KeyDid` 准入（canonical_dev 来自已通过持钥证明的候选
      key；未验证声明仅观测/日志，不填 owner/zone、不进授权判断），
      `anonymous: reject` 时拒绝。
- [x] **新增 `inbound_admission`（SecurityConfig）并接入 stack 配置**：`anonymous` /
      `named_min_relation` / `authority_reconfirm_max_age`；D2：未实现枚举值必须
      启动报错。
- [x] **实现第⑦步关系档位**：`same_zone` 校验 `verified.authz_owner ==
      my_owner_did` 且验签文档 `zone_did == my_zone_did`（zone_did 取自 owner 背书的
      文档，zone 只随 owner）；`known_owner` 校验 `usable_as_authz_subject`、
      `authz_owner` 与 OwnerDocument evidence；信任判断只看第⑤步输出，不看 claim。
      LocalAnchor（`my_owner_did` / `my_zone_did`）启动时装好，来源是预置信任材料（D3）。
- [x] **第⑧步 trust 档位随 tunnel 记录**（按证据映射，如 `TrustedZoneSnapshot`），
      供 process-chain / on_new_tunnel 授权消费；tunnel endpoint 与 per-stream
      process-chain 均携带 trust/canonical DID。
- [x] **实现第⑨步后台 `confirm_authority_binding`（I2 的唯一外联点）**：懒触发
      （`IdentityState[did].authority_confirmed_at` 缺失或超过
      `authority_reconfirm_max_age`）；singleflight + 负缓存 + 按 from_did/source_ip
      限速 + 全局并发额度 + 超时预算；用 `admission_policy 改 source =
      RemoteAuthority` 的同一组合动词一次调用，同时暴露 owner_document 型与
      device_document 型吊销（这是不手写 `resolve_device_document` 的原因）。通过
      （`RequireAuthorityCurrent`）→ 记录确认时间、tunnel 升档
      `MethodAuthorityCurrent`、`add_verified_cache` 落盘；AuthorityNotCurrent /
      Definite 否定 → 踢除 tunnel、写负缓存，并经第⑪步逻辑 DID 索引批量 close 该
      DID 全部旧实例（索引入口已预留，见 New-Tunnel TODO 第 5 条）；不可达 → 有限
      退避后放弃，档位保持快照级不变（不可达 ≠ 否定）。
- **Deferred（等待上游类型，不阻塞 v3）：freshness 收编。** 已向上游提议
      `FreshnessRequirement::NotProvenRegressed`
      （现状只有 NotOlderThanLocalLatest / AnyValid / RequireAuthorityCurrent，前者
      会误杀离线/首见、后者连权威否定都不看）；上游落地后整体换用并删除本地
      `freshness_rejection` 匹配，落地前保持现状。
- **Deferred（等待上游归类，不阻塞 v3）：`OwnerBindingUnavailable`。** 其注释语义是
      “权威已回答的确定性
      缺失”，应属 Definite；确认前按现状归入降级类。
- [x] `did:dev` 无文档路径继续支持 `KeyDid`，但上层策略必须明确决定匿名 key identity
  可以访问哪些服务。
- **Deferred（跨 TODO 类型收敛）：** 与
  [`RTCP-SN-Registered-Device-Authorization-TODO.md`](../SN/RTCP-SN-Registered-Device-Authorization-TODO.md)
  的 `RtcpIdentityTrust` 收敛为同一类型，避免出站 key provenance 与入站授权 evidence
  各自定义一套不兼容枚举。

### D. 接通配置

- [x] 给 `RtcpStackConfig`、`RtcpStackBuilder`、`RTcp` / `RTcpInner` 增加
  `peer_identity`（出站）与 `inbound_admission`（入站 SecurityConfig）两组 policy。
- [x] 配置反序列化默认值必须是 fail-closed（入站默认 `anonymous: reject`、
  `named_min_relation: same_zone`）；D2：未实现枚举值启动报错，不得静默接受。
- [x] 更新 `src/rootfs/etc/cyfs_gateway.yaml` 示例，明确 TXT bootstrap 默认关闭、
  self-declared 路径已不存在。
- [x] 对旧配置不做静默兼容；Beta2.2 启动日志应提示 TXT bootstrap 与入站 fallback
  行为已改变；出现已删除的 `inbound_self_declared_fallback` 键时启动报错。
- [x] web3 gateway、公网 SN/relay 配置不得开启 `dns_txt_bootstrap`；其
  `anonymous` 档位按各自准入需求显式声明，不依赖默认值。

### E. 文档与可观测性

- [x] 修正 `doc/rtcp/rtcp.md` §5.2，使“当前实现”与实际代码一致，并描述 authority policy。
- [x] 修正 §5.3：按 §2.5 重写入站验证——self-declared fallback 已删除（D3），改为
  固定 `admission_policy` + `anonymous` 档位降级 + 第⑨步后台权威确认与档位升级。
- [x] 记录 resolver method、trust level、cache/freshness 结果和降级/踢除原因；不得记录
  完整 JWT、`DEV=` 或 token。
- **Deferred（仓库暂无 metrics backend）：** metrics 至少区分
  authority/Zone/Host/key-DID/TXT 的成功与拒绝次数，以及入站
  `anonymous` 降级次数、后台确认的通过/否定/不可达与档位升级次数（I2 预算可观测：
  外联次数应 ≤ 活跃具名身份数）。

### F. 加固控制包解析和未认证握手入口

- [x] 重写 `RTcpTunnelPackage::read_package()` 的长度处理：
  - 使用 checked subtraction；
  - `len < 8` 返回 `InvalidData`；
  - 当前版本要求 `json_pos == 8`；
  - `json_pos > len`、不足 cmd/seq、空或无效 JSON 全部返回 `InvalidData`；
  - 删除所有由远端长度控制的直接索引、unchecked range 和 `unwrap()`。
- [x] 首包读取加入 deadline；慢连接超时后 shutdown。
- [x] 为 accept 后、完成 tunnel 注册前的所有未认证握手增加全局 semaphore。
- [x] handshake deadline 覆盖 Hello 解析、§C ①–⑤ 的文档验证（`LocalAndZone` 含
  zone-resolver 调用）、HelloAck 写入和 HelloAckConfirm 等待，而不是只包住最后两步。
  §C 落地后握手路径不再有 method-authority I/O（I1），但 zone 内调用仍须在 deadline
  之内。
- [x] 评估按 source IP 的 token bucket 和重复错误日志抑制（本地资源纵深防护）。
  authority 查询的 singleflight/负缓存/限速属于第⑨步后台确认的 I2 预算（§C），
  不再是握手入口的职责。
- [x] 为 parser 增加有界 property-style test；任意短字节输入只能返回 package/error，
  不能 panic、无限等待或产生超上限分配。独立 `cargo-fuzz` workspace 延期，见 §5.2。

### G. 实现 tunnel 原子替换和可靠 liveness

原子替换部分已于 2026-07-24（commit 736a7178）完成，实现与测试记录见
[RTCP-New-Tunnel-Replaces-Old-TODO.md](RTCP-New-Tunnel-Replaces-Old-TODO.md)：

- [x] 给 `RTcpTunnel` 增加 generation/id；map value 必须能比较具体实例。
      （落地为进程内唯一 `instance_id` + `is_same_instance`。）
- [x] 将 `on_new_tunnel()` 改为 key-confirmation 和授权成功后的原子 replace，并返回旧
  tunnel；锁外调用旧 tunnel `close()`。（落地为 `replace_authenticated_inbound`，旧实例
  在临界区内先 `mark_closed`；出站保持 first-wins 的 `register_outbound_if_absent`。）
- [x] 增加 `remove_if_current(key, generation)`，替换所有无条件 `remove_tunnel(key)`。
- [x] `close()` 主动：
  - 设置 closed/cancel 状态；
  - shutdown bearing stream；
  - 失败所有 Open/ROpen/Pong waiter；
  - 终止或唤醒 pending stream-build task；
  - 保证 `run()` 在有界时间内退出（`close_notify` 唤醒读循环）。
- [x] 修复 `Tunnel::ping()`：传播 `send_package()` 错误，不得无条件 `Ok(())`。

已完成的 liveness 工作：

- [x] keep-tunnel 改用带 seq 的 `ping_rtt()` 或等价 Ping/Pong，按配置 timeout 和连续失败
  次数 close + conditional remove；`start_keep_tunnel` 已等待匹配 Pong。
- [x] direct TCP socket 配置平台允许的 keepalive，作为 NAT/内核级补充。
- [x] 替换/清理日志补充原因和旧实例存活时长（tunnel key 与新旧 `instance_id` 已记录），
  不记录密钥材料。

### H. 统一 Open/ROpen 配额、方向和失败语义

- [x] 在 `process_package()` spawn `ROpen` task 之前获取 pending-build permit。
- [x] 明确配额是 Open/ROpen 共用还是各自独立；默认建议共用，防止交替请求绕过总上限。
- [x] `Open` 只允许在 `can_direct == false` 的 tunnel 端处理；`ROpen` 只允许在
  `can_direct == true` 的 tunnel 端处理。
- [x] 增加 per-peer 请求速率限制和突发上限。
- [x] permit 覆盖地址解析、拨号、HelloStream 和 listener 交接，在所有 early return /
  timeout / cancelled 路径释放。
- [x] 扩展 `OpenResp` / `ROpenResp` 错误码，至少区分 quota、wrong-direction、
  reconnect-failed、timeout、authorization-rejected；未知错误码仍安全失败。
- [x] 重复 stream id 必须显式拒绝，`new_wait_stream()` 不得覆盖已有 waiter。

### I. 让 reconnect winner 与 RTT 语义一致

- [x] 把 direct reconnect 的单个 attempt 扩展为“TCP connect + HelloStream 写入成功”；
  只有完整成功的 attempt 才能成为 winner。
- [x] 某个 candidate TCP 成功但 HelloStream 失败时，继续等待/启动其他 candidate，不能
  提前取消整场竞速。
- [x] 成功 RTT 从 attempt 启动计到 HelloStream 写入完成，记录
  `MeasurementLayer::Application`。
- [x] 失败 attempt 尽可能记录 `Refused` / `Unreachable` / `Timeout`；若拿不到
  `local_addr`，扩展 name-client API 或明确记录“无法归档”，不能用 debug 日志冒充回写。
- [x] 文档明确 standard Open/ROpen 的 reconnect 都由原 tunnel 发起侧执行，端口来自其
  remote stack endpoint；`Hello.my_port` 的实际消费场景单独说明。

### J. 绑定 Hello 字段并规范 token 时间窗口

- [x] 按 §3.1 将 `my_port`/`listen_port` 加入签名 claim，验证 claim/body 一致。
- [x] 盘点 Hello/HelloAck 中所有明文且影响路由、身份、keying、tunnel reuse 的字段；
  要么纳入签名 claim/HKDF context，要么删除冗余副本。
- [x] token 增加 `iat`，实施最大寿命和 future-skew 检查。
- [x] HKDF context 同时区分 semantic DID 与 canonical DEV DID，双方采用同一规范化规则；
  不再让文档宣称 canonical、代码却混入未经说明的 host-name 字符串。
- [x] 如果 claim/KDF 改动造成不兼容，按 §3.1 升级 audience/protocol version，并增加明确
  的新旧版本拒绝测试。

### K. 实现业务 stream key separation 和使用预算

- [x] 定义 stream KDF：

  ```text
  stream_key = HKDF-Expand(tunnel_secret,
      "rtcp stream key" || protocol_version || stream_id || purpose)
  stream_iv = HKDF-Expand(tunnel_secret,
      "rtcp stream iv"  || protocol_version || stream_id || purpose)
  ```

- [x] 双方验证 stream id 是规范的 16-byte 值并在 tunnel 内唯一后，才构造加密 stream。
- [x] 控制 tunnel 和业务 stream 分别维护 record/byte counters 与预算。
- [x] 达到预算或最大 tunnel age 后，旧 tunnel 不再接受新 stream；后续正常建链复用
  §G 的原子替换。主动、提前建立替代 tunnel 属于后续轮换增强，不阻塞 v3。
- [x] 明确预算耗尽、seq 溢出和 KDF 输入错误的错误与日志；metrics 随 §E 的 backend
  工作延期。
- [x] 评估 authenticated close record；若延期，记录“至少一条认证记录后 FIN 被当正常
  EOF，尾部截断无法与正常关闭区分”的 accepted risk。

### L. 修正文档真值并补 per-stream 授权章节

- [x] `doc/rtcp/rtcp.md` 的每个相关段落明确标记“当前实现”或“目标语义”，不得混写。
- [x] §4.5 按 golden wire decision 修正 `purpose` 示例和值域。
- [x] §5.2/§5.3 按 authority/provenance 实现重写，并保留 typed revocation/freshness 拒绝。
- [x] §5.4/§5.5 写清 semantic/canonical DID、stream KDF、实际
  `SHA-256(label || base_iv)` 和 key/record budget。
- [x] §6/§8/§10 修正 tunnel key、`my_port`、reconnect winner、端口来源和 RTT layer。
- [x] §12.1 使用 identity manager 实际文件名和探测顺序。
- [x] 把 nonce cache 单位改为条目，写明淘汰、多实例和“纵深防护”定位。
- [x] 将 §14 已落地历史移回对应正文；§14 只保留未完成 TODO 和 accepted risks。
- [x] 新增 per-stream 授权章节，列出 process-chain 可见的 identity trust、
  `real_source_did`/`source_did`、连接来源、dest host/port、protocol/purpose 和拒绝语义。
- [x] 修复文首本机绝对路径链接，并补 `aes_stream.rs`、`stream_helper.rs` 实现入口。

## 5. 测试验收状态

### 5.1 Peer identity 与 provenance

- [x] `did:web` 同时存在合法 HTTPS ZoneDocument 与冲突 TXT：必须采用 HTTPS 文档 key。
- [x] HTTPS authority unavailable 且 fallback 默认关闭：必须失败。
- [x] HTTPS 返回 malformed/缺字段文档，同时 TXT 合法：默认仍必须失败。
- [x] 显式开启 TXT bootstrap 后，authority unavailable 才可使用 TXT，结果 trust 为
  `DnsTxtBootstrap`。
- [x] authority 明确 Missing/Revoked/Tombstoned 时，即使开启 TXT bootstrap 也不得回退；
  fallback 只处理真正的 unavailable，不覆盖权威负回答。
- [x] `did:bns` 使用 BNS authority 解析；DNS TXT 冲突不能覆盖 BNS 结果。
- [x] `did:dev` 从 DID 自身取得 key，不发起 Web/BNS/TXT 查询，trust 为 `KeyDid`。
- [x] `authority_current` 不接受 Zone/cache 命中冒充 current receipt。
- [x] `trusted_snapshot` 只接受允许的未过期可信 evidence，拒绝 observed/unverified/stale。

入站具名准入（对应 §2.5/§C；部分 Definite/freshness 拒绝测试已存在于
`rtcp::rtcp::tests`，重排后需保持通过）：

- [x] I1 断言：匿名/任意构造的 Hello（含随机 owner/JWT）在握手同步路径零外网 I/O
  （mock resolver 断言无 method-authority 调用），最多一次本地 ed25519 验签。
- [x] 顺序与预过滤：`claim.id != from_id` 在任何解析前拒绝；`same_zone` 下异 owner
  claim 被第③步预过滤拒绝且不触发文档验证；`verify_tunnel_token` 失败不触发文档
  验证。
- [x] Definite 否定（Revoked / NegativeState / OwnerMismatch / Superseded 等）：拒绝
  握手，不存在任何 self-declared 回落路径（函数已删除）。
- [x] 非 Definite（MissingDependency / Resolve 不可达）：`anonymous: reject` 拒绝；
  `anonymous: allow` 降级为 `KeyDid` 准入，未验证声明不填 owner/zone、不进授权
  判断，且降级不触发任何联网。
- [x] 第⑦步档位：`authz_owner != my_owner_did` 或文档 `zone_did != my_zone_did`
  拒绝；第③步预过滤通过但第⑤步输出不符也必须拒绝（信任判断只看⑤输出）。
- [x] D2 配置校验：`known_owner` 可反序列化并进入关系校验；配置未实现枚举值（如
  `same_owner`）启动报错。
- [x] 第⑨步后台确认：同身份并发握手只触发一次外联（singleflight + 负缓存）；确认
  通过后 tunnel 升档 `MethodAuthorityCurrent`，该身份后续握手在第⑤步本地命中最高
  档；AuthorityNotCurrent / Definite 否定踢除 tunnel、写负缓存，并经逻辑 DID 索引
  批量 close 同 DID 旧实例；不可达仅退避放弃，档位不变、不踢除。
- [x] 第⑩步：仅提交文档而未完成持钥证明/key-confirmation/listener 授权，不得推进
  verified-cache high-water（verify 无隐式写入）。
- [x] 更新当前依赖 TXT cache 的
  `web_target_token_uses_resolved_dev_identity`、alias/tunnel-key 测试，改用可控的 method
  authority/ZoneDocument fixture；另保留独立 bootstrap compatibility 测试。
- [x] 配置测试覆盖默认值、`dns_txt_bootstrap` 显式开启、`inbound_admission` 三字段、
  非法/未实现枚举（D2）和已删除 `inbound_self_declared_fallback` 键的启动报错提示。

### 5.2 未认证入口和 parser

- [x] 表驱动覆盖 `len = 0..=9`、截断 cmd/seq、`json_pos < 8`、`json_pos > len`、超长和
  非法 JSON；除合法 HelloStream 特例外都应得到确定的 `InvalidData`，不能 panic。
- [x] 首包只发送 0/1 字节后停住：在 handshake deadline 内断开并释放 semaphore。
- [x] 并发连接超过 pending-handshake 上限：多余连接快速拒绝，accept loop 和既有 tunnel
  仍可服务。
- [x] 随机 owner / `device_doc_jwt` 在握手路径不触发任何 authority 查询（I1，与 §5.1
  的 mock resolver 断言呼应）；zone-resolver 慢或不可达时握手受统一 deadline 约束；
  后台确认的超时/并发/负缓存已在 §5.1 覆盖。
- **Deferred（测试工具增强）：** 当前以有界 property-style parser 测试覆盖任意短输入，
  未新增 `cargo-fuzz` workspace；后续 fuzz corpus 应继续覆盖 `read_package()`、
  Hello/HelloAck JSON 和 token claim 边界。

### 5.3 Tunnel 替换和 liveness

已由替换修复覆盖（`rtcp::rtcp::tests`，2026-07-24 全量通过）：

- [x] 已有 tunnel A 时，完成全新 v3 握手的 tunnel B 原子替换 A；B 使用不同 session
  key/IV，A 被 close。
- [x] A 的 `run()` 在 B 注册后退出，不得把 B 从 map 删除。
- [x] listener 拒绝或 Hello/nonce 重放的新连接不得替换 A。（freshness commit 失败在
  代码路径上位于 tunnel 构造之前，结构上到不了替换点，无独立测试。）
- [x] `ping()` 写失败必须向调用者返回错误。（closed tunnel 的 fail-fast 已测；真实
  socket 写失败路径随 liveness 工作一并覆盖。）
- [x] 并发两个新 tunnel 抢同一 key：最终 map 中恰好一个 current generation，所有 loser
  都关闭且不能删除 winner。

当前 liveness 验证状态：

- [x] 只写成功但收不到匹配 Pong：达到连续失败阈值后 close/remove 并允许重建。
- **Deferred（环境型集成测试）：** 模拟 NAT black-hole/半开连接并验证在配置的
  liveness 上界内恢复；当前单测覆盖连续 missed-Pong 判定，代码路径执行
  close + conditional remove。

### 5.4 Open/ROpen、reconnect 与授权

- [x] inbound `Open` 和 `ROpen` 分别/合计达到配额时，下一条请求收到明确 quota 错误，
  不启动额外拨号 task。
- [x] 在错误 tunnel 角色上发送 Open/ROpen：返回 wrong-direction，不触发 DNS、connect
  或 listener。
- [x] 高频交替 Open/ROpen 不能绕过总配额或 per-peer rate limit。
- [x] 重复 stream id 不能覆盖 waiter；迟到 HelloStream 被关闭。
- [x] candidate A TCP connect 成功但 HelloStream 写失败、candidate B 完整成功：B 获胜。
- [x] reconnect 成功只记录 Application RTT；失败 candidate 的 outcome 与最终错误一致。
- [x] per-stream process-chain 能看到可信 identity/provenance 与目标字段，并能在建立业务
  转发前拒绝无权限 dest host/port。

### 5.5 线协议、KDF 与 Datagram

- **Deferred（golden corpus 扩充）：** 当前 Open wire golden 与 Hello/HelloAck token
  contract 测试已锁定 `purpose`、关键 claim 和 v3 audience；完整保存
  Hello、HelloAck、Open、ROpen golden bytes/JSON 留作测试增强。
- [x] 篡改 Hello body 的 `my_port`/`listen_port`，token/body mismatch 必须在任何回连前
  拒绝。
- [x] 缺失/未来 `iat`、`exp < iat`、寿命超限、允许 skew 边界分别有测试。
- [x] 相同 tunnel secret 下不同 stream id 或 purpose 派生不同 key/IV；双方对同一 context
  派生完全一致。
- [x] 重复 stream id、非法长度和非 hex 值在 KDF 前拒绝。
- [x] record/byte/tunnel-age 预算触发安全失败，达到最大 tunnel age 后旧 tunnel 不再接受
  新 stream；主动预建替代 tunnel 作为后续轮换增强。
- [x] Datagram 等于上限成功，上限 + 1 在发送端和接收端都返回专用错误且不破坏后续协议
  framing。
- [x] 新旧 protocol version/audience 组合在握手阶段明确失败，不出现首条业务 AEAD 才失败。

## 6. 已执行的发布顺序（历史记录）

### Phase 0：冻结决策和测试基线

1. 确认 §3.1 的 `purpose`、token claim、`iat`、protocol version、stream KDF 和 Datagram
   上限决策。
2. 先补当时 v2 的 wire/contract tests 和已知 bug 的失败测试；测试必须能在修复前稳定复现，
   不能只靠人工日志判断。
3. 建立 parser property-style test 和 tunnel replacement generation 模型；独立
   `cargo-fuzz` workspace 按前述 Deferred 处理。

### Phase 1：先落地不依赖 resolver API 的资源/生命周期修复

1. 完成 §F parser、首包 deadline 和 pending-handshake 上限。
2. §G 的 tunnel generation、conditional remove、原子替换和 ping 错误传播已完成
   （2026-07-24，commit 736a7178）；keep-tunnel Pong liveness 与 TCP keepalive 随后
   也已完成。
3. 完成 §H Open/ROpen 配额、方向、重复 stream id 和取消清理。
4. 完成 §I reconnect 完整 winner 与 RTT 口径。

这一阶段不得改变已经上线的密钥派生或线值；可以独立回归资源安全和重连自愈。

### Phase 2：准备并切换权威身份解析

1. 先为所有生产 `did:web` 身份发布静态 `/.well-known/did.json`，并验证其中默认 gateway
   key 与 RTCP 实际私钥一致；按需发布 `owner.json` / `device.json`。
2. 不提供 HTTPS 的身份迁移到 `did:bns`，确认 BNS resolver/indexer readiness。
3. 发布带 provenance 的 resolver API 与 RTCP policy/config。
4. 切换出站默认值为 `authority_current`、关闭 `dns_txt_bootstrap`。
5. 入站按 §C 切换：重排①–⑤、固定 `admission_policy`（LocalAndZone）、删除
   self-declared 路径（D3）、接入 `inbound_admission` 配置与第⑦步档位。除
   `NotProvenRegressed` 收编外不依赖新上游 API（锁定 commit 已含
   LocalAndZone / RemoteAuthority / set_local_authority_override），可与出站切换
   并行；受影响部署需先按 D3 预置信任材料。
6. 启用第⑨步后台 `confirm_authority_binding` 与档位升级/否定踢除，观察 I2 预算
   指标（外联次数应 ≤ 活跃具名身份数）。
7. 观察 authority unavailable、schema error、key mismatch 指标；只对受控 bootstrap 环境
   局部开启 `dns_txt_bootstrap`，不做全局回滚；入站不存在可回滚的 self-declared 开关。

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
- 任何 TXT 兼容结果都有显式配置、显式 non-authoritative trust 和可观测记录；
  self-declared 验证路径在代码中不存在（D3），不能靠配置恢复。
- 公网 SN/relay 的授权链不能消费 non-authoritative owner/zone。
- 入站按 §2.5 三条不变量验收：I1——匿名/任意构造输入在握手同步路径零外网 I/O、最多
  一次本地 ed25519 验签；I2——外联仅由后台 `confirm_authority_binding` 发起、只能被
  “信任库 owner 真实签名过的文档”触发、受 singleflight/负缓存/限速/并发/超时约束，
  总外网读 ≤ 活跃具名身份数；I3——文档真伪、owner 锚定、valid_iat 防回滚、时效三态
  只由 name-lib 判定，rtcp 不出现第二套实现。
- trust 档位随 tunnel 记录且只能由权威确认单向升级；权威否定踢除 + 负缓存 + 经逻辑
  DID 索引批量清理；不可达不降档、不踢除。D1 的 accepted risk（吊销后不再连接的
  设备，其存量 tunnel 不被发现）保持显式记录，未被隐式“修复”。
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
