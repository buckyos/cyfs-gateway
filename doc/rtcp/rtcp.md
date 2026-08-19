# RTCP v4 协议与实现

RTCP（Reverse TCP）是 `cyfs-gateway` 的私有 tunnel 协议，不是 RFC 中的
Real-time Transport Control Protocol。本文只描述当前 Beta2.2 实现；历史 v2/v3 设计和
review 结论见 [RTCP Authoritative Peer Key Resolution](RTCP-Authoritative-Peer-Key-Resolution-TODO.md)。

实现入口：

- `src/components/cyfs-gateway-lib/src/rtcp/package.rs`：线包与严格解析；
- `src/components/cyfs-gateway-lib/src/rtcp/rtcp.rs`：身份、握手、tunnel、Open/ROpen；
- `src/components/cyfs-gateway-lib/src/aes_stream.rs`：AEAD 记录层；
- `src/components/cyfs-gateway-lib/src/rtcp/stream_helper.rs`：HelloStream waiter；
- `src/components/cyfs-gateway-lib/src/rtcp/datagram.rs`：Datagram framing；
- `src/components/cyfs-gateway-lib/src/stack/rtcp_stack.rs`：配置和 process-chain 授权。

配置示例见 [cyfs_gateway.yaml](../../src/rootfs/etc/cyfs_gateway.yaml)，tunnel 准入示例见
[rtcp_on_new_tunnel_hook_point_example.md](rtcp_on_new_tunnel_hook_point_example.md)。
已有域名和 HTTPS 服务、希望增加 RTCP 的节点可直接参考
[HTTPS + RTCP 过渡节点快速部署](rtcp_https_transition_quickstart.md)。

## 1. 连接模型

RTCP 使用两类承载：

- tunnel：长连接控制通道，承载 `Hello`、`Ping`、`Open`、`ROpen` 等控制包；
- stream leg：每个 TCP/Datagram 业务流独占的新承载，完成 HelloStream 绑定后使用
  per-stream key 加密。

主动建立 tunnel 的一端 `can_direct = true`，接收 `ROpen`；被动接收 tunnel 的一端
`can_direct = false`，接收 `Open`。错误方向会返回明确错误码，且不做解析或拨号。

Tunnel 建立与业务 stream 建立是两个独立成功边界：

- responder 验证 `HelloAckConfirm`、通过 listener 准入并完成 tunnel map 仲裁后，发送
  AEAD `TunnelResult { accepted, reason }`；
- initiator 只有收到匹配握手 seq 的 `accepted=true` 后，才发布并返回本地 tunnel；
- listener、verified-cache 或 map 仲裁拒绝通过 `accepted=false` 明确返回，initiator
  不再把 responder 未接纳的连接误判为成功；
- tunnel 可用只表示 RTCP 控制通道已经完成 Hello/密钥确认，不承诺后续任意一次
  `Open` / `ROpen` 成功。每次业务流仍要独立经过方向、配额、授权、解析、拨号和
  HelloStream 交接。

Tunnel URL：

```text
rtcp://<did>[:port]/<target>
rtcp://<percent-encoded-bootstrap-url>@<did>[:port]/<target>
```

端口省略时使用 `2980`。带 bootstrap URL 的 tunnel 和后续 stream leg 都重放同一类
bootstrap transport，不会错误地退回裸 TCP。

## 2. 线协议

### 2.1 控制包

```text
0               2 3   4               8
+---------------+---+---+---------------+--------------...
| len(u16, BE)  |jp |cmd| seq(u32, BE)  | JSON body
+---------------+---+---+---------------+--------------...
```

- `len` 包含 2 字节长度字段，最大 65535；
- v4 固定要求 `len >= 8`、`json_pos == 8`；
- JSON 必须非空、UTF-8 合法并能反序列化为对应包体；
- 所有偏移都使用 checked arithmetic 和安全切片，畸形输入返回 `InvalidData`；
- listener 对完整未认证握手使用统一 deadline 和全局 pending-handshake semaphore。

命令字：

| cmd | 名称 | 用途 |
| --- | --- | --- |
| 1 | `Hello` | 发起 tunnel |
| 2 | `HelloAck` | responder 身份和临时 key 确认 |
| 3 / 4 | `Ping` / `Pong` | 带 seq 的 liveness/RTT |
| 5 / 6 | `ROpen` / `ROpenResp` | 请求对端回连 stream leg |
| 7 / 8 | `Open` / `OpenResp` | 准备接收本端新建的 stream leg |
| 9 | `HelloAckConfirm` | AEAD challenge echo |
| 10 | `TunnelResult` | responder 最终准入/仲裁结果 |

### 2.2 HelloStream

新 stream leg 的首包不是 JSON：

```text
+---------------+----------------------------------------+
| 0x0000        | stream_id (32-byte hexadecimal ASCII)  |
+---------------+----------------------------------------+
```

发送端和接收端都要求 stream id 恰好是规范的 16 字节值的 32 位十六进制编码。
stream id 在 tunnel 生命周期内唯一；重复值不会覆盖 waiter，而会被明确拒绝。

### 2.3 Open/ROpen 包体

```json
{
  "streamid": "00112233445566778899aabbccddeeff",
  "purpose": "Stream",
  "dest_port": 443,
  "dest_host": "service.example"
}
```

`purpose` 的线上值是 Serde 字符串 `"Stream"` / `"Datagram"`，不是 Rust enum 判别值
`0` / `1`。缺省为 `"Stream"`。

响应码：

| code | 含义 |
| --- | --- |
| 0 | success |
| 1 | quota exhausted |
| 2 | reconnect failed |
| 3 | wrong direction |
| 4 | timeout |
| 5 | authorization rejected |
| 6 | invalid stream id |
| 7 | duplicate stream id |
| 8 | rate limited |

未知非零码一律按安全失败处理。

## 3. v4 身份与握手

### 3.1 身份表示

RTCP 同时保留：

- semantic DID：调用方请求或 Hello 声明的逻辑 DID；
- canonical device DID：从实际 Ed25519 key 得到的 `did:dev`；
- trust provenance：
  `key_did`、`method_authority_current`、`trusted_host_snapshot`、
  `trusted_zone_snapshot` 或 `dns_txt_bootstrap`。

canonical DID 用于 tunnel key 和持钥证明；semantic DID 与 canonical DID 一起进入
session HKDF。trust 不会在 canonical 化后丢失，并暴露给 process-chain。

当前 tunnel 复用键只使用 canonical device identity 和承载路径：

```text
direct:    <local-canonical-dev-did>_<remote-canonical-dev-did>
bootstrap: <local-canonical-dev-did>_<remote-canonical-dev-did>|bootstrap=<url>
```

因此同一逻辑名字和它的裸 `did:dev` 寻址会复用同一设备 tunnel。

在 tunnel key 之上，tunnel map 维护“逻辑名字 `<->` canonical DEV DID”的一一绑定
仲裁（当前实现）：

- 任一时刻一个 canonical DEV DID 至多属于一个已验证逻辑名字。反向唯一性索引
  （canonical DEV DID -> logical DID）与既有 logical DID 二级索引一起维护；绑定检查、
  verified-cache commit、主 tunnel map 与两个方向的索引更新在同一提交序列
  （commit lock + map 临界区）内完成。
- 出站：具名目标在复用或新建 canonical tunnel 前检查已验证名字绑定；不同逻辑名字
  命中同一 canonical DEV DID 时明确拒绝（`one-to-one name binding` 错误），不静默
  复用先建立的 tunnel。参与绑定的是设备名（DeviceDocument 解析）与 DNS TXT
  bootstrap 名字；zone 目标（ZoneDocument 委托默认 gateway）是 zone 寻址不是第二个
  设备名，不参与设备名绑定；裸 `did:dev` 寻址不算逻辑名字。
- 入站：具名 from 在文档验证后、HelloAck/listener 授权前有 rejection-only 预检查，
  发布时在提交序列内做权威仲裁；同一 canonical tunnel key 在当前实例存活期间采用
  first-accepted-wins，重复连接被明确拒绝，只有已关闭实例允许被新连接替换。
- 同一逻辑名字提交更高 `DocumentRevision` 时，已验证二级索引会关闭严格更旧
  revision / 旧 canonical key 下的 tunnel，并在同一临界区释放旧 canonical DEV DID
  的反向绑定；版本仲裁使用 name-client 的 verified-cache CAS 结果，不由 RTCP 自行
  比较文档内容。same-iat 不同 content 属于 same-version 冲突：CAS 以
  `RejectedConflict` 拒绝，map 内还有 fail-closed 的同版本门兜底，不允许两个绑定
  同时保持 current。
- 绑定随实例生命周期清理：实例退出（`remove_if_current`）、被替换、被 supersede 或
  权威否定（`close_verified_identity`，含出站具名绑定实例）都会同时清理两个方向的
  索引；全部实例已关闭的 stale 绑定不再守住名字，会在下一次仲裁时被剪除。
- 裸 `did:dev` 的 key identity 不因共享设备 tunnel 获得具名身份的 owner/zone 权限。

### 3.2 出站 peer key 解析

默认配置：

```yaml
peer_identity:
  requirement: authority_current
  dns_txt_bootstrap: false
```

- `did:dev`：直接从 DID 取 key，不做 Web/BNS/TXT 查询，trust 为 `KeyDid`；
- `authority_current`：固定使用 `RemoteAuthority`，结果必须带 anchored authority
  evidence，trust 为 `MethodAuthorityCurrent`；
- `trusted_snapshot`：固定使用 `LocalAndZone`，只接受非 stale、非 observed 且通过可信
  proof 的 Host/Zone 快照；
- 普通 DNS TXT 永远不先于 DID method authority。

只有显式开启 `dns_txt_bootstrap`，并且 authority 真正不可达时，`did:web` 才会解析旧
`DEV=` / `PKX=` hint。该路径不会把 DEV JWT 的 parse-only 解码称作文档验证，trust 固定为
`DnsTxtBootstrap`，日志明确标注 non-authoritative。authority 的 missing、schema
错误、revoked、tombstoned、冲突或其它确定性否定不允许回退。

### 3.3 Hello 与签名 token

Hello：

```json
{
  "from_id": "did:web:initiator.example",
  "to_id": "did:web:responder.example",
  "my_port": 2980,
  "tunnel_token": "<EdDSA JWT>",
  "device_doc_jwt": "<optional owner-signed DeviceDocument JWT>"
}
```

Hello token v4 payload：

```json
{
  "aud": "buckyos-rtcp-v4-hello",
  "to": "responder.example",
  "canonical_to": "did:dev:<resolved-responder-key>",
  "from": "initiator.example",
  "listen_port": 2980,
  "xpub": "<32-byte ephemeral X25519 key, hex>",
  "iat": 1711111111,
  "exp": 1711111171,
  "nonce": "<16-byte random, hex>"
}
```

接收端要求：

- `aud` 精确等于 v4 audience；v2/v3 在握手阶段失败；
- signed `from` 与 `Hello.from_id` 的规范 host form 一致；
- signed semantic `to` 与 `Hello.to_id` 一致；
- signed `canonical_to` 等于本 stack 从私钥导出的 canonical `did:dev`；
- signed `listen_port == Hello.my_port`；
- `exp >= iat`、寿命不超过 60 秒、`iat` 不超过当前时间加 60 秒 clock skew；
- `xpub` 恰好 32 字节，nonce 恰好 16 字节。

nonce cache 以 `(canonical source did:dev, nonce)` 为键，最多 16K **条目**，保留到
`exp + leeway`。满载时淘汰最早到期项。它是进程内、单实例的 replay/DoS 纵深防护，
不是跨集群防重放服务。

HelloAck token 使用 `buckyos-rtcp-v4-ack`，带同样的 `iat`/`exp`/`nonce`，并用
`peer_xpub` 绑定本次 Hello。`HelloAckConfirm` 是第一条 AEAD 记录，echo responder
challenge。responder 成功解密 Confirm 后执行 listener、verified-cache 和 tunnel map
仲裁，并以 `TunnelResult` 返回最终结果。initiator 必须收到 `accepted=true` 才能发布
tunnel；`accepted=false` 的 `reason` 作为建链错误返回。最终结果发送失败或发送任务被
取消时，responder 会条件删除并关闭刚发布的候选实例。

### 3.4 入站具名准入

具名 `from_id + device_doc_jwt` 的同步握手顺序固定为：

1. parse-only 解码 token claim；
2. `claim.from` 与 `Hello.from_id` 绑定；
3. parse-only 解码 DeviceDocument，校验 `document.id == from_id`；`same_zone` 时只用
   claim owner 做拒绝型预过滤；
4. 使用候选 document key 验证 Hello token 持钥证明；
5. 使用唯一 admission policy 调用 name-client
   `resolve_and_verify_device_document_jwt`：
   `LocalAndZone`、`allow_stale_cache=true`、unverified/self-signed fallback 全关；
6. 拒绝 local older/conflict 和 authority NotCurrent；
7. 关系档位只消费验证结果：
   - `same_zone` 要求 `authz_owner` 与本机 owner 相同，且 owner 背书文档中的
     `zone_did` 与本机 zone 相同；
   - `known_owner` 要求结果可作为 `AuthSubject` 授权、`authz_owner` 非空，并带可信
     OwnerDocument evidence；
   - `any` 不增加关系约束，但仍必须先完成上述 name-client 文档验证；
8. 文档验证成功后、HelloAck 之前做一一绑定预检查（rejection-only）：candidate
   canonical DEV DID 已绑定到其它已验证逻辑名字时直接拒绝；
9. 将 trust、canonical DID、owner/zone（只有验证成功时）交给 listener；
10. 持钥证明、key confirmation、listener 授权都成功后才提交 verified cache 并注册
    tunnel；注册前在同一提交序列内做权威的一一绑定、first-accepted-wins 与
    same-version 冲突仲裁（§3.1）；
11. responder 发送最终 `TunnelResult`。只有结果成功送达并且 `accepted=true`，双方才把
    本次握手视为 tunnel 建立成功。

同步路径不访问 method authority。self-declared 验证和 observed cache 写入路径不存在。
验证 unavailable 时，默认 `anonymous: reject`；显式 `anonymous: allow` 只按已证明持有的
candidate key 降级为 `KeyDid`，不携带 owner/zone，不写授权缓存。

可信 Host/Zone snapshot 接纳后，可触发每逻辑身份 singleflight 的后台
`RemoteAuthority` 确认。任务有全局并发额度、超时与结果缓存：

- authority current：写 verified cache，并把该 DID 的 tunnel 单向升级为
  `MethodAuthorityCurrent`；
- authority 证明候选文档是 `DifferentDocument` 或 `Superseded`，或验证返回
  definite rejection：写 RTCP 负结果状态，并通过逻辑 DID 二级索引关闭该身份的
  tunnel；
- authority 对未发布设备文档返回 `NegativeStatus(Missing/Expired/Migrated)`：保留
  Host/Zone snapshot trust，但不升级为 `MethodAuthorityCurrent`；
- unavailable/timeout：保留原 snapshot trust，不踢 tunnel。

`authority_reconfirm_max_age: unlimited` 表示每进程生命周期只确认一次；有限秒数使用懒
检查，不启动后台定时吊销扫描。

## 4. 密钥派生与记录层

### 4.1 Tunnel session key

双方各生成一次性 X25519 key。以下 `||` 表示原始字节串拼接，字符串使用签名 claim 中
双方实际校验过的 UTF-8 字节；canonical DID 使用 `DID::to_string()` 的结果，xpub 和
nonce 使用 token 中双方共同看到的十六进制字符串：

```text
shared = X25519(my_ephemeral_secret, peer_ephemeral_public)
PRK = HKDF-Extract-SHA256(salt = None, IKM = shared)

ctx = "|" || initiator_semantic_did
          || "|" || responder_semantic_did
          || "|" || initiator_canonical_dev_did
          || "|" || responder_canonical_dev_did
          || "|" || initiator_xpub_hex
          || "|" || responder_xpub_hex
          || "|" || initiator_nonce_hex
          || "|" || responder_nonce_hex

control_key = HKDF-Expand-SHA256(
  PRK, "buckyos-rtcp-v4 aes256-key" || ctx, 32)
control_iv = HKDF-Expand-SHA256(
  PRK, "buckyos-rtcp-v4 iv-salt" || ctx, 16)
```

`control_key` / `control_iv` 用于 tunnel 控制通道。当前实现不会把 ECDH `PRK` 作为独立
exporter secret 保留；后续 per-stream KDF 以 `control_key` 作为输入。因此逻辑身份、
实际 key、角色或握手实例任何一项不同都会得到不同控制通道和业务流密钥。

### 4.2 Per-stream key

业务 stream 不直接使用控制通道 AES key。stream id 必须先解码为 16 字节；version 和
purpose 都是单字节，其中 `version = 4`、`Stream = 0`、`Datagram = 1`：

```text
stream_PRK = HKDF-Extract-SHA256(salt = None, IKM = control_key)
stream_ctx = 0x04 || stream_id_raw_16_bytes || purpose_u8

stream_key = HKDF-Expand-SHA256(
  stream_PRK, "buckyos-rtcp stream key|" || stream_ctx, 32)
stream_iv = HKDF-Expand-SHA256(
  stream_PRK, "buckyos-rtcp stream iv|" || stream_ctx, 16)
```

非法或重复 stream id 在 KDF 前拒绝。不同 id、purpose 或版本派生不同 key/IV。

### 4.3 AEAD record

控制通道与业务 stream 都使用 AES-256-GCM：

```text
+-------------+------------------------+
| len u16 BE  | ciphertext || tag(16)  |
+-------------+------------------------+
```

- `len` 等于 `ciphertext length + 16-byte tag`，不包含自身的 2 字节；合法范围是
  `16..=16400`；
- 单记录明文最大 16 KiB，较大的上层写入拆成多条记录；
- GCM 不使用 additional authenticated data，2 字节 `len` 不在 tag 覆盖范围内；篡改
  framing 会导致认证失败、截断或连接关闭，不能产生通过认证的伪造明文；
- 每个方向的 `seq` 从 `0` 开始，成功消费一条记录后加一，以 8 字节大端序 XOR 到
  nonce base 的低 8 字节；
- `nonce_A = first12(SHA-256("rtcp-aead-nonce/A" || base_iv))`，
  `nonce_B = first12(SHA-256("rtcp-aead-nonce/B" || base_iv))`；
- underlying transport initiator（发送明文 Hello/HelloStream 的一端）写方向使用 A、
  读方向使用 B；responder 写方向使用 B、读方向使用 A。

控制 tunnel 的 `base_iv` 是 `control_iv`；业务 stream 的 `base_iv` 是对应
`stream_iv`。年龄预算从本端创建该 `EncryptedStream` 时开始计时，不依赖双方墙上时钟。

key-use 预算：

| 类型 | 每方向最大记录 | 每方向最大明文字节 | 最大年龄 |
| --- | ---: | ---: | ---: |
| control tunnel | 2^24 | 4 GiB | 24 h |
| business stream | 2^20 | 1 GiB | 24 h |

预算耗尽、年龄耗尽和 seq 溢出返回可区分错误。tunnel 到达 24 小时后不再建立新 stream；
由后续建链替换旧实例，不实现原地 KeyUpdate。

## 5. Tunnel 生命周期与 liveness

入站 tunnel 在完整认证后按 canonical key 执行 first-accepted-wins 仲裁：

- 每个实例有进程内唯一 `instance_id`；
- 当前实例存活时，新候选收到 `accepted=false` 并关闭；当前实例已关闭时才允许替换，
  旧实例在 map 临界区内标记 closed，锁外清 waiter 和 shutdown；
- run loop 退出只执行 `remove_if_current(key, instance)`，并同时清理该实例的
  一一绑定索引；
- 同逻辑 DID 的更新 revision 通过二级索引关闭旧 revision；
- 替换资格受 §3.1 一一绑定约束：不同逻辑名字命中同一 canonical key 的连接在注册前
  被拒绝。

出站 `create_tunnel` 按 canonical tunnel key 执行 single-flight；并发调用等待同一个
creator，随后复用已发布的 winner，不再各自发起完整握手。最终注册仍保持 first-wins
兜底，loser 关闭并复用 winner；具名目标复用前先过一一绑定仲裁。

`keep_tunnel` 使用带 seq 的 `ping_rtt()`，只有匹配 Pong 才算成功。配置的连续失败次数达到
阈值后 close + conditional remove，下一轮重新建链。direct accept、初始 connect 和
reconnect TCP socket 同时启用平台支持的 TCP keepalive（30 秒 idle、10 秒 interval）；
TCP keepalive 只是协议级 Ping/Pong 的补充。

## 6. Open、ROpen 与 reconnect

Open/ROpen 在每个 tunnel 上共享：

- pending build semaphore；
- token-bucket 请求速率与 burst；
- tunnel 生命周期内的 stream-id 集合。

permit 在 spawn、解析、拨号和 HelloStream 交接前取得，并覆盖整个 build 生命周期。
重复 id、quota、速率或错误方向都会在拨号前失败。

direct reconnect 的竞速 attempt 是“TCP connect + TCP keepalive + HelloStream 写入”。
只有完整写出 HelloStream 才能成为 winner；某 candidate connect 成功但写失败时继续其它
candidate。成功 RTT 从 attempt 启动计到 HelloStream 写完，记录为
`MeasurementLayer::Application`。失败尽量记录 Refused/Unreachable/Timeout；没有
`local_addr` 的 connect 失败只能安全记录日志，因为当前 addr-rtt API 需要 local IP。

standard Open/ROpen 的 reconnect 均由原 tunnel 发起侧建立，使用发起侧保存的 remote
stack endpoint；Hello 的 `my_port` 只在对端构造该 endpoint 时消费，并由签名
`listen_port` 保护。

## 7. Datagram

Datagram 在加密 stream 内使用：

```text
len(u32, BE) || datagram bytes
```

发送、接收和 forwarder 的协议上限统一为 `65507` 字节；上限加一会在读取 payload 前或
发送 framing 前失败，不会按声明长度分配无界内存。它仍是 stream 上的消息模拟，不保留
原生 UDP 的丢包/乱序语义。

## 8. Per-stream 授权

Tunnel authentication 只回答“对端是谁”，不会自动授权目标服务。每条 stream/datagram
在转发前都经过 process-chain；可见字段包括：

- `real_source_did`、`source_did`、`source_device_id`；
- `source_canonical_device_id`；
- `source_identity_trust`；
- `conn_source_ip` / `conn_source_port`；
- PROXY protocol 恢复后的 `real_source_ip` / `real_source_port` 和有效
  `source_ip` / `source_port`；
- `dest_host`、`dest_port`、`protocol`；
- `stream_purpose`（`stream` 或 `datagram`）。

策略应先检查 `source_identity_trust`，再决定某类身份能否访问指定 host/port。尤其
`dns_txt_bootstrap` 与 anonymous `key_did` 不得继承具名 owner/zone 权限。拒绝发生在
业务转发之前。

`on_new_tunnel_hook_point` 看到同一套 semantic/canonical/trust 来源信息。listener 拒绝的
新连接不能替换已存在 tunnel。

## 9. 配置

```yaml
stacks:
  secure_rtcp:
    protocol: rtcp
    bind: 0.0.0.0:2980
    identity: did:web:device.example
    peer_identity:
      requirement: authority_current
      dns_txt_bootstrap: false
    inbound_admission:
      anonymous: reject
      named_min_relation: same_zone
      authority_reconfirm_max_age: unlimited
    liveness:
      ping_interval_secs: 30
      pong_timeout_secs: 10
      max_missed_pongs: 3
    limits:
      max_pending_handshakes: 256
      handshake_requests_per_second: 16
      handshake_request_burst: 32
      max_pending_stream_builds_per_tunnel: 64
      max_datagram_bytes: 65507
      handshake_timeout_secs: 15
      stream_requests_per_second: 32
      stream_request_burst: 64
```

默认安全策略按方向区分：

- 出站具名 peer key 解析要求 `authority_current`，DNS TXT bootstrap 关闭；
- 入站具名 tunnel 使用已验证的 same-zone Host/Zone snapshot 同步准入，随后按配置做
  后台 authority confirmation；它不声称握手时已经取得 method-authority current receipt；
- 入站 anonymous 默认拒绝；
- 每条业务 stream 仍应由 process-chain 根据 `source_identity_trust` 决定是否需要
  `method_authority_current`，不能仅凭 tunnel 已建立授予敏感服务权限。

`named_min_relation` 支持 `same_zone`、`known_owner`、`any`。`same_owner` 等未实现枚举值、
已删除的 `inbound_self_declared_fallback` 和其它未知字段会导致配置反序列化失败，不会
静默忽略。

Identity manager 实际探测：

- 私钥：security root 下的 identity 私钥材料；
- 文档：`device.jwt`、`device_doc.jwt`、`did.json`；
- 旧式 `device_config_path` 若指向 `did.json`，会探测同目录 owner-signed
  `device_doc.jwt`。

逻辑 DID 本地 stack 必须有 owner-signed DeviceDocument JWT；`did:dev` 可以直接由 key
身份启动。

## 10. 明确接受的风险与后续项

- HelloStream 当前没有额外 MAC。知道未完成 stream id 的链路内攻击者可以抢占 waiter；
  影响限于 DoS，不能通过 AEAD 认证或读取业务明文。
- 没有 authenticated close record。至少一条认证记录之后，record boundary 上的 FIN
  被视为正常 EOF，尾部截断无法与正常关闭区分。
- Hello/HelloAck 和可选 DeviceDocument JWT 是明文，会暴露 identity metadata；当前
  版本优先保证可认证建链，未提供身份隐私。
- Hello 与 DeviceDocument JWT 受 u16 控制包长度限制。
- 逻辑名字与 canonical DEV DID 的一一绑定按活跃实例仲裁（§3.1）：出站对同一名字先后
  解析到不同 canonical DEV DID（如 TXT bootstrap 名字迁移）时，旧 canonical tunnel
  不会被出站路径主动关闭，依赖 liveness/轮换或入站 revision 仲裁收敛；这是“不另造
  版本判断规则”的既定取舍。
- 按既定 D1 不做后台定时吊销轮询：若合法设备在吊销后不再连接本节点，存量 tunnel
  只能由 liveness、自然轮换或一次性/懒式 authority confirmation 清理。
- 上游提供 `FreshnessRequirement::NotProvenRegressed` 后，可用其替换 RTCP 当前对
  local/authority freshness 的本地策略映射；在此之前保持 typed matching。
