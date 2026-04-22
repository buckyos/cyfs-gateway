# RTCP 协议文档

> RTCP是Reverse Tcp的缩写，对应核心的协议动作ROpen

本文基于当前代码实现整理，目标是说明 `cyfs-gateway` 中 RTCP 的实际线协议、建链流程、开流流程和关键字段语义。实现入口主要在：

- `src/components/cyfs-gateway-lib/src/rtcp/package.rs`
- `src/components/cyfs-gateway-lib/src/rtcp/rtcp.rs`
- `src/components/cyfs-gateway-lib/src/rtcp/datagram.rs`
- `src/components/cyfs-gateway-lib/src/stack/rtcp_stack.rs`

这里的 RTCP 是项目内自定义协议，不是 RFC 里的 Real-time Transport Control Protocol。

配置 `on_new_tunnel_hook_point` 控制 tunnel 来源的示例见：[rtcp_on_new_tunnel_hook_point_example.md](/Users/liuzhicong/project/cyfs-gateway/doc/rtcp_on_new_tunnel_hook_point_example.md)

通过固定 SOCKS5 端口把客户端接入 RTCP 网络的示例见：[rtcp_socks_proxy_example.md](/Users/liuzhicong/project/cyfs-gateway/doc/rtcp_socks_proxy_example.md)

## 1. 协议目标

RTCP 解决的是“设备之间只有 RTCP 端口可达，业务端口不可直连”时的服务访问问题。它有三个核心能力：

- 建立 A 和 B 之间的长连接 tunnel。
- 在 tunnel 上协商新的加密数据流，用来访问对端 TCP 服务。
- 在同一套机制上承载“伪 UDP”Datagram。

RTCP 的默认监听端口是 `2980/TCP`。

## 2. 角色与连接模型

RTCP 区分两类 TCP 连接：

- `Tunnel`：长连接控制通道，用来收发 `Hello`、`Ping`、`Open`、`ROpen` 等控制包。
- `Stream`：为某个业务流单独建立的新 TCP 连接。建立后立即切到对称加密，承载真实业务字节流或 datagram 字节流。

一个 tunnel 建立后，两端都可以基于该 tunnel 再创建新的 stream。但两端对“谁来主动建立 stream 的 TCP 连接”判断不同：

- 主动发起 tunnel 的一侧：`can_direct = true`，后续优先走 `Open`。
- 被动接受 tunnel 的一侧：`can_direct = false`，后续优先走 `ROpen`。

这不是协议层的对等性差异，而是当前实现里的建流策略差异。

## 3. Tunnel URL
rtcp://remote_peer/target_stream_id

## 3. 线协议总览

RTCP 在线上有两种首部格式。

### 3.1 控制包格式

控制包格式定义在 `package.rs`，头部固定 8 字节：

```text
0               2 3   4               8
+---------------+---+---+---------------+--------------...
| len(u16, BE)  |jp |cmd| seq(u32, BE)  | JSON body
+---------------+---+---+---------------+--------------...
```

字段说明：

- `len`
  - 2 字节，大端。
  - 表示整个包总长度，包含 `len` 字段本身。
  - 当前实现限制 `len <= 65535`。
- `json_pos`
  - 1 字节。
  - 表示 JSON 正文的起始偏移。
  - 当前发送端固定写死为 `8`。
  - 接收端只校验 `json_pos >= 6`，然后按 `json_pos - 2` 在剩余缓冲区中定位 JSON，因此当前实现实际要求它等于 8。
- `cmd`
  - 1 字节，命令字。
- `seq`
  - 4 字节，大端。
  - 用于请求/响应关联，尤其是 `Open/OpenResp`。
- `JSON body`
  - UTF-8 编码 JSON。
  - 不再做额外长度字段，直接由 `len` 推导。

### 3.2 HelloStream 特殊首包

当 `len == 0` 时，这不是控制包，而是一个特殊的 `HelloStream` 首包：

```text
0               2 34
+---------------+----------------------------------------+
| 0x0000        | stream_id(32 bytes raw ascii bytes)    |
+---------------+----------------------------------------+
```

说明：

- `HelloStream` 只能出现在一条新 TCP 连接的第一个包；后续再出现会被拒绝。
- 当前实现中 `stream_id` 实际上是 `16` 个随机字节的十六进制字符串，因此线上固定是 `32` 字节 ASCII。
- `HelloStream` 只用来把这条新 TCP 连接绑定到某个待建立的业务流；它不是 JSON 包。

## 4. 命令字与包体字段

当前实现支持的 `cmd` 如下：

| cmd | 名称 | 方向 | 用途 |
| --- | --- | --- | --- |
| 1 | `Hello` | tunnel 建立时 | 认证并建立控制通道 |
| 2 | `HelloAck` | 预留 | 已定义，但当前实现未实际发送 |
| 3 | `Ping` | tunnel 内 | 存活探测 |
| 4 | `Pong` | tunnel 内 | `Ping` 的响应 |
| 5 | `ROpen` | tunnel 内 | 请求对端反向建立一条 stream TCP 连接 |
| 6 | `ROpenResp` | tunnel 内 | `ROpen` 的响应 |
| 7 | `Open` | tunnel 内 | 请求对端准备接收一条由本端主动建立的 stream |
| 8 | `OpenResp` | tunnel 内 | `Open` 的响应 |

### 4.1 Hello

```json
{
  "from_id": "did:...",
  "to_id": "did:...",
  "my_port": 2980,
  "tunnel_token": "<jwt>",
  "device_doc_jwt": "<optional jwt>"
}
```

字段说明：

- `from_id`
  - 发起端设备 ID。
  - 接收端会把它作为来源设备身份。
  - 如果同时携带 `device_doc_jwt`，则要求 `device_doc_jwt` 解出的 `id` 与它完全一致。
- `to_id`
  - 目标设备 ID。
  - 当前实现会记录日志，但不会据此校验“是否就是本机”。
- `my_port`
  - 发起端 RTCP 栈监听端口。
  - 接收端后续会把它当成“回连该设备 RTCP 端口”的目标端口。
- `tunnel_token`
  - 必填。
  - 一个 EdDSA JWT，里面携带本次 tunnel 的临时密钥交换信息。
- `device_doc_jwt`
  - 可选。
  - 跨 zone 首次接入时很重要，允许接收端在还不知道 `from_id` 对应设备公钥时完成准入和 token 验签。

### 4.2 tunnel_token 载荷

`tunnel_token` 的 JWT payload 为：

```json
{
  "to": "<target did hostname>",
  "from": "<source did hostname>",
  "xpub": "<hex encoded 32-byte x25519 public key>",
  "exp": 1711111111
}
```

字段说明：

- `to`
  - 发起端认为的目标设备 host name。
  - 当前接收端不会显式校验 `to`。
- `from`
  - 发起端设备 host name。
  - 接收端会校验它与已确认的来源设备 ID 一致。
- `xpub`
  - 发起端本次 tunnel 的一次性 X25519 公钥，16 进制编码。
  - 接收端据此与自己的静态 X25519 私钥做 DH，导出 tunnel AES key。
- `exp`
  - JWT 过期时间。
  - 当前生成时为“当前时间 + 2 小时”。

### 4.3 HelloAck

```json
{
  "test_result": true
}
```

说明：

- 该包体结构仍然保留在代码里。
- 但当前 tunnel 建立流程里没有发送 `HelloAck`，所以它属于“定义存在、实现未使用”的历史字段。

### 4.4 Ping / Pong

`Ping`：

```json
{
  "timestamp": 1711111111
}
```

`Pong`：

```json
{
  "timestamp": 0
}
```

说明：

- `Ping` 由 `Tunnel::ping()` 主动发送。
- 收到 `Ping` 后，对端立即回 `Pong`，复用同一个 `seq`。
- 当前实现不会把 `Ping` 的时间戳原样带回，`Pong.timestamp` 固定为 `0`。
- 当前没有自动心跳线程，`ping()` 是按需调用。

### 4.5 Open / ROpen

`Open` 和 `ROpen` 的 JSON 结构完全相同：

```json
{
  "streamid": "<32-char hex string>",
  "purpose": 0,
  "dest_port": 80,
  "dest_host": "127.0.0.1"
}
```

兼容性说明：

- 反序列化时同时兼容 `streamid` 和 `stream_id`。
- 当前发送端写的是 `streamid`。

字段说明：

- `streamid`
  - 一条业务 stream 的会话标识。
  - 当前实现是 `16` 随机字节的十六进制字符串，因此长度固定 `32`。
  - 它还有第二层作用：解码成 16 字节后，直接作为该业务 stream 的 IV/nonce。
- `purpose`
  - 可选。
  - `0` 或缺省表示普通字节流 `Stream`。
  - `1` 表示 `Datagram` 模式。
  - `2` 表示Raw Stream,不用加密
  - `3` 表示Raw Datagram,不用加密
- `dest_port`
  - 目标端口。
- `dest_host`
  - 目标主机。
  - 可以是 IP、域名，也可以在 `dest_port == 0` 时直接塞一个完整 URL。

当前上层实现对目标地址的解释规则是：

- 若 `dest_port != 0`：按普通 `tcp://dest_host:dest_port` 语义处理。
- 若 `dest_port == 0`：要求 `dest_host` 是一个带 scheme 和 port 的完整 URL，例如 `tcp://example.com:443/path`。

### 4.6 OpenResp / ROpenResp

```json
{
  "result": 0
}
```

当前实现中的 `result` 约定：

- `0`：成功。
- `2`：仅在 `ROpen` 路径下使用，表示对端无法建立反向 TCP 连接。

注意：

- `OpenResp.result` 当前并不会被调用方读取，收到包后只负责按 `seq` 唤醒等待者。
- `ROpenResp.result` 当前也没有被调用方消费。

因此，从“现状”看，这两个响应包更像是一个同步点，而不是完整的错误回传机制。

## 5. 认证、密钥交换与加密

RTCP 当前实现同时使用长期设备密钥和短期会话密钥。

### 5.1 本地长期密钥

本地 RTCP 栈启动时会加载设备私钥：

- Ed25519 私钥：用于签发 `tunnel_token`。
- 同一把私钥转换出的静态 X25519 私钥：用于和对端 `xpub` 做 DH，导出 tunnel 对称密钥。

### 5.2 发起侧如何生成 tunnel_token

发起侧 `create_tunnel()` 时执行：

1. 解析目标设备 DID。
2. 解析目标设备的 Ed25519 exchange key。
3. 把目标 Ed25519 公钥转换成 X25519 公钥。
4. 生成一次性 X25519 密钥对 `my_secret / my_public`。
5. 用 `my_secret` 和目标 X25519 公钥做 DH。
6. 对共享密钥做 `SHA-256`，得到 `32` 字节 AES key。
7. 将 `my_public` 以十六进制写入 `tunnel_token.xpub`。
8. 用本地 Ed25519 私钥对 JWT 做 EdDSA 签名。

### 5.3 接收侧如何确认来源身份

收到 `Hello` 后，接收侧先确定“该用哪个公钥验签 `tunnel_token`”。

有两条路径：

1. `device_doc_jwt` 存在
   - 先不验签解析 JWT，拿到 `owner`。
   - 解析 owner 的 auth key。
   - 用 owner 公钥正式验证 `device_doc_jwt`。
   - 校验 `device_doc_jwt.id == hello.from_id`。
   - 从设备文档的默认 key 提取设备 Ed25519 公钥。
   - 用这个设备公钥验证 `tunnel_token`。

2. `device_doc_jwt` 不存在
   - 直接根据 `hello.from_id` 解析设备公钥。
   - 用该设备公钥验证 `tunnel_token`。

### 5.4 tunnel AES key 的导出

接收端验签 `tunnel_token` 后：

1. 读取 `xpub`。
2. 用自己的静态 X25519 私钥与 `xpub` 做 DH。
3. 对共享密钥做 `SHA-256`。
4. 得到 tunnel 的 `AES-256 key`。

### 5.5 加密范围

RTCP 当前实现里有两层加密语义：

- `Hello` 和 `HelloStream` 首包本身不加密。
- 一旦 tunnel 或 stream 被正式接管，后续字节都走 `EncryptedStream`。

IV/nonce 选择规则：

- tunnel 控制通道
  - 使用 `tunnel_token.xpub` 解码后的 32 字节中的前 16 字节作为 IV。
- 业务 stream
  - 使用 `streamid` 解码后的 16 字节作为 IV。

业务 stream 复用的是“所属 tunnel 的同一把 AES key”，只是 IV 改成 `streamid` 对应的值。

## 6. Tunnel 建立流程

下面描述的是当前真实实现，而不是早期设计。

### 6.1 发起端 A

1. 解析目标 `rtcp://<did>[:port]`。
2. 解析目标设备 IP。
3. TCP 连接目标 RTCP 端口，默认 `2980`。
4. 生成 `tunnel_token`、AES key、一次性 `xpub`。
5. 发送 `Hello`。
6. 本地立即把这条 TCP 连接包装成 tunnel，标记 `can_direct = true`。
7. 启动 tunnel 读循环。

### 6.2 接收端 B

1. `accept()` 新 TCP。
2. 读取首包。
3. 若首包是 `Hello`，进入 tunnel 建立流程。
4. 校验来源身份和 `tunnel_token`。
5. 从 `Hello.my_port` 记录对端 RTCP 监听端口。
6. 调用 `listener.on_new_tunnel(...)` 做准入控制。
7. 把这条 TCP 包装成 tunnel，标记 `can_direct = false`。
8. 启动 tunnel 读循环。

### 6.3 当前实现上的重要事实

- 没有 `HelloAck` 往返，`Hello` 发出后只要本地建好 `RTcpTunnel` 就认为 tunnel 已建立。
- `to_id` 当前不做“必须等于本机 ID”的校验。
- 对端后续回连端口来自 `Hello.my_port`，不是当前 TCP 连接的源端口。

## 7. Open 流程

`Open` 用在“当前这一侧是 tunnel 主动发起者，`can_direct = true`”的场景。

设 A 是主动建 tunnel 的一侧，B 是被动接受的一侧。A 希望访问 B 的服务。

### 7.1 时序

1. A 生成 `streamid = hex(random[16])`。
2. A 生成新的 `seq`，向 tunnel 发送 `Open(streamid, purpose, dest_host, dest_port)`。
3. B 收到 `Open` 后，先登记一个等待项，键为 `<B.this_device_id>_<streamid>`。
4. B 回 `OpenResp(seq, result=0)`。
5. A 收到 `OpenResp` 后，以“当前 tunnel 对端 IP + 对端 RTCP 端口”再建立一条新的 TCP 连接。
6. A 在这条新连接上发送 `HelloStream(streamid)`。
7. B 的 RTCP listener 收到该新连接，读到 `HelloStream(streamid)`，查找刚才登记的等待项。
8. A 和 B 两边都把这条新 TCP 包装成 `EncryptedStream`，AES key 复用 tunnel key，IV 使用 `streamid` 解出的 16 字节。
9. B 把 stream 交给上层 `on_new_stream()` 或 `on_new_datagram()`。

### 7.2 关键点

- `OpenResp` 只是告诉 A“可以开始建立新 TCP 连接了”。
- 新 stream 连接不是复用 tunnel，而是重新建一个 TCP 连接。
- 新 stream 的目标地址不是重新做一次 DID 解析，而是复用已有 tunnel 对端的 IP。

## 8. ROpen 流程

`ROpen` 用在“当前这一侧是 tunnel 被动接受者，`can_direct = false`”的场景。

设 B 是被动接受 tunnel 的一侧，A 是主动建 tunnel 的一侧。B 希望访问 A 的服务。

### 8.1 时序

1. B 生成 `streamid = hex(random[16])`。
2. B 在本地登记等待项，键为 `<B.this_device_id>_<streamid>`。
3. B 向 tunnel 发送 `ROpen(streamid, purpose, dest_host, dest_port)`。
4. A 收到 `ROpen` 后，用“当前 tunnel 对端 IP + `Hello.my_port`”建立一条新的 TCP 连接回到 B。
5. 若回连失败，A 回 `ROpenResp(seq, result=2)`。
6. 若回连成功，A 先回 `ROpenResp(seq, result=0)`。
7. A 在新 TCP 上发送 `HelloStream(streamid)`。
8. B 的 listener 收到新连接并匹配等待项。
9. A 和 B 两边都把这条新 TCP 包装成 `EncryptedStream`，AES key 复用 tunnel key，IV 使用 `streamid`。
10. A 把 stream 交给本地上层，去连接自己这一侧的真实服务。

### 8.2 和 Open 的本质区别

两者的业务目标相同，区别只在“谁来主动建立新的 stream TCP 连接”：

- `Open`：由请求方自己去连对端 RTCP 端口。
- `ROpen`：由对端反向连回来。

## 9. Datagram 模式

Datagram 并没有单独的 UDP tunnel。当前实现只是把 datagram 封装进一条加密 stream 里。

触发方式：

- `Open/ROpen.purpose = Datagram`

上层字节格式：

```text
+-------------------+-------------------+
| datagram_len u32  | datagram payload  |
+-------------------+-------------------+
```

字段说明：

- `datagram_len`
  - 4 字节，大端。
- `datagram payload`
  - 原始 datagram 内容。

所以 Datagram 模式的真实语义是：

- 建立一条新的 RTCP 加密 stream。
- 在该 stream 上用 `u32 length + payload` 复用多个 datagram。

## 10. 地址解析与连接选择

发起 `create_tunnel()` 时，当前实现会按多个候选名称解析目标 IP，而不是只看一个字段。候选通常包括：

- 调用方传入的 stack id host 部分
- `target.did.to_host_name()`
- `target.did.to_raw_host_name()`
- `target.did.to_string()`

如果 DID info 文档里有 `ip`、`ips` 或 `all_ip`，也会作为候选来源。当前实现会按顺序尝试所有解析到的 IP，某个 IP 连接失败时会继续尝试下一个。

这属于实现层行为，但会直接影响建 tunnel 的实际连通性。

## 11. on_new_tunnel_hook_point 可见字段

这不是线协议字段，但它决定了“隧道建立后，业务栈能看到哪些来源信息”。

`device_doc_jwt` 校验成功时，`on_new_tunnel_hook_point` 当前能拿到：

- `source_addr`
- `source_device_id`
- `source_device_name`
- `source_device_owner`
- `source_zone_did`
- `source_device_doc_jwt`

如果未携带 `device_doc_jwt`，则只保证拿到：

- `source_addr`
- `source_device_id`

## 12. 本地配置与 device_doc_jwt

RTCP stack 的 `device_config_path` 当前支持两类文件内容：

- 设备文档 JSON
- owner 已签名的设备文档 JWT

行为差异：

- 如果本地加载的是 JSON，RTCP 仍能工作，但发起 `Hello` 时不会自动携带 `device_doc_jwt`。
- 如果本地加载的是 JWT，发起 `Hello` 时会自动把它塞进 `device_doc_jwt` 字段。

因此，跨 zone 首次接入若希望让对端在“尚未知晓本设备公钥”的前提下完成准入，应该配置 JWT 形式的设备文档。

## 13. 当前实现与文义设计的差异

为了避免文档误导，下面这些点要特别说明：

- `HelloAck` 已定义，但当前实现里没有参与建链流程。
- `Hello.to_id` 当前不会被校验。
- `OpenResp.result` 和 `ROpenResp.result` 当前没有形成完整错误语义。
- `Pong.timestamp` 当前固定为 `0`，不是对 `Ping.timestamp` 的镜像。
- tunnel 和 stream 的首包 `Hello` / `HelloStream` 都是明文；真正加密从 `EncryptedStream` 接管后开始。
- Datagram 不是 UDP 打洞，而是“在加密 TCP stream 里封装 datagram”。

## 14. 安全注意事项与协议 TODO

本节记录的是“当前实现已经确认存在，但暂未完成修订”的协议问题。它们不是建议级优化，而是后续协议升级时必须正式文档化并落地的 TODO。

### 14.1 TODO: 为 tunnel 与 stream 增加完整性保护

当前现状：

- RTCP 的 tunnel 和业务 stream 当前使用 `AES-256-CTR` 做字节流加密。
- 当前协议帧中没有 MAC，也没有 AEAD tag。
- 因此它只提供保密性，不提供传输完整性。

风险：

- 链路上的攻击者即使无法解密，也可以对密文做按位篡改。
- 对控制面来说，这意味着 `Open`、`ROpen`、`Ping`、响应包等都有被静默篡改的风险。
- 对业务面来说，这意味着经 RTCP 转发的应用数据可能被无告警篡改。

协议 TODO：

- 后续协议版本需要把 tunnel 和 stream 的传输层升级为“带认证的加密”。
- 推荐方向是直接改为 AEAD，例如 `AES-GCM` 或 `ChaCha20-Poly1305`。
- 如果出于兼容性原因不能一步切换到 AEAD，至少也要在每个加密记录上补 `encrypt-then-MAC`。
- 在正式完成该升级前，不应把当前 RTCP 视为“具备完整传输安全”的协议。

### 14.2 TODO: 为 Hello 建立抗重放与密钥确认机制

当前现状：

- `Hello` 依赖签名过的 `tunnel_token` 建立 tunnel。
- 接收端在验证来源身份后，会直接创建并发布 tunnel。
- 当前没有 challenge-response，也没有显式的 key confirmation。
- `HelloAck` 结构虽然存在，但当前实现未参与握手。

风险：

- 只要攻击者能捕获一次合法 `Hello`，就在 `tunnel_token` 过期前存在重放空间。
- 当前 `tunnel_token` 的有效期是 2 小时，这对重放窗口来说过长。
- 重放后的连接即使最终不能正常使用，也可能替换现有 tunnel、干扰在线状态，或者影响 `on_new_tunnel` 观察到的结果。

协议 TODO：

- 后续协议版本需要把 `HelloAck` 或等价握手包正式纳入握手流程。
- 新握手必须至少补齐三件事：
  - 服务端 challenge 或等价随机因子。
  - 发起端对 challenge 和会话密钥的持有证明。
  - 接收端的 anti-replay 判定。
- `tunnel_token` 也应从“长时间可重放的 bearer token”收紧为“短时、单次、带上下文绑定”的握手材料。
- 在协议修订完成前，应把 RTCP 的握手视为“可认证但不可抗重放”的临时方案。

### 14.3 TODO: 规范 stream 建立超时与清理语义

当前现状：

- `Open` / `ROpen` 建流依赖 `stream_id` 在两端匹配等待状态。
- 当前实现中，等待 `HelloStream` 的项超时后不会完全清理。
- 对端可以不断发起建流，再让其在等待阶段超时。

风险：

- 长时间运行时，等待表可能累积失效项，形成内存占用增长。
- `on_open` 当前是串行等待的，单个请求阻塞还会拖住该 tunnel 的读循环，形成可利用的可用性问题。

协议 TODO：

- 后续协议文档需要明确规定 stream 建立的生命周期：
  - 等待态的超时时间。
  - 超时后的强制清理行为。
  - 对端迟到的 `HelloStream` 应如何处理。
- 协议还应明确每 tunnel / 每 peer 的并发建流上限和速率限制要求。
- 在实现上，超时清理与资源配额应视为协议一致性要求，而不是可选优化。

## 15. 最小实现心智模型

如果只记住 RTCP 的核心机制，可以简化成下面四句话：

1. 先用 `Hello + tunnel_token` 在一个 TCP 连接上建立加密 tunnel。
2. tunnel 只传控制消息，不直接承载业务流。
3. 每次业务访问都要再新建一条 TCP 连接，并用 `HelloStream(streamid)` 把它绑定到 tunnel 中的某个 `Open/ROpen` 请求。
4. tunnel 和所有业务 stream 都复用同一把 AES key，但每条业务 stream 用自己的 `streamid` 作为 IV。
