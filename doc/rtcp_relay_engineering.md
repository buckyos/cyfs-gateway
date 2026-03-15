# RTCP Relay Session 工程方案

## 1. 文档目标

本文给出一份面向实现的 RTCP Relay 升级方案。

目标不是重新设计一套复杂的 Overlay 协议，而是把问题收敛为：

> **RTCP 里的各种 session 最终通过哪个 TCP stream 建出来。**

基于这个判断，协议拆成两层：

- 邻居协议：节点之间直接存在 TCP 连接时，沿用现有 RTCP 协议。
- 中转协议：Relay 节点只负责协助两端拼出一条 TCP byte stream；拼好后，这条 stream 被上层当成某种 RTCP session 使用。

这份方案只解决一跳透明中转：

- `Client -> Relay -> Server`

多跳能力后续可以在同一模型上继续扩展，但不是本文的首要目标。

## 2. 设计原则

### 2.1 不改现有 Tunnel 语义

现有 RTCP 的核心语义保持不变：

- `Hello` 负责 Tunnel 身份建立
- `HelloAck` 负责 Tunnel 建立确认
- `Ping/Pong` 负责保活
- `Open/ROpen` 负责在已建立 Tunnel 上打开业务 stream

中转能力不替代这套逻辑，只负责为各种 session 创造一条可用的 TCP byte stream。

### 2.2 Relay 不理解最终 Tunnel 身份

Relay 节点不解析最终 `Hello` 或业务流载荷的业务意义，不参与：

- 最终 Tunnel 双方身份确认
- Tunnel Token 校验
- 端到端 Tunnel 归属判定

Relay 只做两件事：

- 协调两端建立新的 TCP stream
- 在配对成功后做纯字节转发

### 2.3 只增加最少命令

第一版只新增两类能力：

1. 邻居 Tunnel 上的中转控制命令
2. 新 TCP stream 首包的会话标记

不引入复杂路由命令，不引入新的 Overlay 身份层。

## 3. 现有实现基础

当前代码已经具备以下条件：

- 相邻节点之间已有稳定 RTCP Tunnel，支持 `keep_tunnel`
- `Hello` 已包含完整身份建立信息
- `HelloAck` 类型已定义，但当前握手闭环尚未完整使用
- `Open/ROpen` 已能在已建 Tunnel 上开第二条 TCP stream
- `HelloStream(session_key)` 已能给新 TCP stream 做配对

相关代码位置：

- 协议包定义：[src/components/cyfs-gateway-lib/src/rtcp/package.rs](/Users/liuzhicong/project/cyfs-gateway/src/components/cyfs-gateway-lib/src/rtcp/package.rs)
- Tunnel 建立与包处理：[src/components/cyfs-gateway-lib/src/rtcp/rtcp.rs](/Users/liuzhicong/project/cyfs-gateway/src/components/cyfs-gateway-lib/src/rtcp/rtcp.rs)
- RTCP 栈与 keep tunnel：[src/components/cyfs-gateway-lib/src/stack/rtcp_stack.rs](/Users/liuzhicong/project/cyfs-gateway/src/components/cyfs-gateway-lib/src/stack/rtcp_stack.rs)

## 4. 核心模型

### 4.1 Session 抽象

本文把 RTCP 中需要额外新建 TCP stream 的对象统一抽象为 `session`。

第一版只定义两种 session：

- `tunnel_session`
- `stream_session`

#### 4.1.1 tunnel_session

用于承载 RTCP Tunnel 控制流。

建立完成后，这条 stream 上会继续收发：

- `Hello`
- `HelloAck`
- `Ping/Pong`
- `Open/ROpen`

#### 4.1.2 stream_session

用于承载某次 `Open/ROpen` 打开的业务字节流。

建立完成后，这条 stream 本身不再发送新的 RTCP Tunnel 控制命令，而是直接作为：

- TCP 字节流
- 或加密后的 `EncryptedStream`

交给现有业务转发逻辑使用。

### 4.2 邻居 Tunnel

如果 A 能直接连到 B 的 RTCP 端口，那么：

1. A 建立 TCP 连接到 B:2980
2. A 在该连接上发送 `Hello`
3. B 返回 `HelloAck`
4. 该 TCP 连接成为 A 与 B 的 `tunnel_session`

这是现有模型，不变。

### 4.3 Relay 构造 session

如果 A 不能直达 B，但 A 与 Relay、Relay 与 B 之间都已有邻居 Tunnel，则：

1. A 在 `A <-> Relay` 这条邻居 Tunnel 上请求 Relay 协助建立某个 session
2. Relay 在 `Relay <-> B` 这条邻居 Tunnel 上通知 B 配合建立
3. A 和 B 分别向 Relay 新建一个 TCP stream，并声明这是同一个 session
4. Relay 把这两个新 stream 配对并做纯字节转发
5. 配对完成后，这条 stream 被上层解释成对应的 `session_type`

这个模型的关键点是：

> **Relay 协助建立的是“承载 session 的 TCP stream”，不是代替两端解释 session 的协议语义。**

### 4.4 中转 tunnel_session

如果 A 不能直达 B，但 A 与 Relay、Relay 与 B 之间都已有邻居 Tunnel，则：

1. A 在 `A <-> Relay` 这条邻居 Tunnel 上请求 Relay 协助建立到 B 的 Tunnel
2. Relay 在 `Relay <-> B` 这条邻居 Tunnel 上通知 B 配合建立
3. A 和 B 分别向 Relay 新建一个 TCP stream，并声明这是同一个 `tunnel_session`
4. Relay 把这两个新 stream 配对并做纯字节转发
5. A 在这条已配对 stream 上发送现有 `Hello`
6. B 在这条 stream 上返回现有 `HelloAck`
7. A 和 B 认为自己已建立一条直达逻辑 Tunnel

这是 `tunnel_session` 在 relay 模式下的构造过程。

### 4.5 中转 stream_session

如果 A 与 B 之间已经有一条逻辑 Tunnel，但这条 Tunnel 本身不能直接建立第二条数据 TCP 连接，那么：

1. A 在已有 Tunnel 上发送 `Open` 或 `ROpen`
2. A 或 B 中负责“构造 stream_session”的一方，向自己的 relay 邻居发起 session 构造请求
3. Relay 通知对端配合建立同一个 `stream_session`
4. 双方各自向 Relay 新建一个 TCP stream，并以同一个 `session_id` 标识
5. Relay 把这两个 stream 纯字节配对
6. 两端把得到的 stream 包装成现有 `EncryptedStream`
7. 该 stream 交给现有 `on_new_stream/on_new_datagram` 或业务转发逻辑

因此在 relay 场景里：

- `Open/ROpen` 仍然存在
- 但它们解决的是“谁负责发起这次 stream_session 构造”
- 真正的数据流建立仍然依赖 Relay 的纯字节流协助

## 5. 协议扩展

### 5.1 新增邻居控制命令

在现有 `CmdType` 里新增两种命令：

- `BuildSessionReq`
- `BuildSessionResp`

建议命令编号：

- `BuildSessionReq = 9`
- `BuildSessionResp = 10`

第一版不引入更多中转控制命令。

### 5.2 BuildSessionReq

语义：

> 请求当前邻居协助建立一条到目标节点的 session stream。

建议字段：

```json
{
  "session_id": "32-byte hex string",
  "session_type": "tunnel | stream",
  "target_id": "did string",
  "source_id": "did string",
  "mode": "relay",
  "hop_limit": 1,
  "dest_host": "optional string",
  "dest_port": 0,
  "purpose": "stream | datagram"
}
```

字段说明：

- `session_id`
  - 本次 session 构造的唯一标识
  - 推荐使用 16 字节随机数转 hex，长度 32
- `session_type`
  - `tunnel` 表示构造 `tunnel_session`
  - `stream` 表示构造 `stream_session`
- `target_id`
  - 最终目标节点 DID
- `source_id`
  - 最终发起方 DID
  - 第一版可以冗余携带，便于 Relay 和目标端做日志、校验、调试
- `mode`
  - 固定为 `relay`
  - 为后续可能的其他建链模式保留扩展位
- `hop_limit`
  - 第一版固定为 `1`
- `dest_host`
  - 仅 `session_type=stream` 时有意义
  - 表示目标端最终要访问的主机
- `dest_port`
  - 仅 `session_type=stream` 时有意义
  - 表示目标端最终要访问的端口
- `purpose`
  - 仅 `session_type=stream` 时有意义
  - 对齐现有 `StreamPurpose`

### 5.3 BuildSessionResp

语义：

> 返回当前 Relay 是否接受本次 session 构造请求。

建议字段：

```json
{
  "result": 0,
  "reason": "optional error string"
}
```

返回码建议：

- `0`：accepted
- `1`：target tunnel not found
- `2`：relay policy denied
- `3`：target rejected
- `4`：timeout
- `5`：internal error

第一版不在 `Resp` 中返回路径信息。

## 6. SessionHello 设计

### 6.1 为什么需要 SessionHello

现有新建 stream 的首包是 `HelloStream(session_key)`，语义是：

> 这是一条业务 stream，请按 `session_key` 去等待队列里配对。

对于 relay session 构造，需要表达另一种语义：

> 这不是普通业务 stream，而是一条等待 Relay 配对的 session stream。

因此需要引入带类型的 stream 首包。

### 6.2 推荐方案

把现有 `HelloStream(session_key)` 抽象升级为 `SessionHello`。

建议结构：

```json
{
  "session_type": "stream | tunnel",
  "session_id": "32-byte hex string"
}
```

### 6.3 兼容策略

为了兼容现有实现，推荐采用分阶段改造：

#### Phase A

内部先抽象一个统一概念：

- 现有 `HelloStream(session_key)` 在逻辑上视为：

```json
{
  "session_type": "stream",
  "session_id": "<old session_key>"
}
```

#### Phase B

新增一种新的首包编码，专门承载：

```json
{
  "session_type": "tunnel",
  "session_id": "<session_id>"
}
```

#### Phase C

等新旧节点兼容完成后，再考虑是否彻底用统一 `SessionHello` 替代现在的裸 `HelloStream` 形式。

### 6.4 编码建议

推荐不要破坏当前普通 `HelloStream` 的旧格式，而是：

- 保留现有：
  - `len == 0` + 32 字节 session key
- 新增一种新的首包类型：
  - 使用普通包头
  - `cmd = SessionHello`
  - body 为 `{ session_type, session_id }`

这样好处是：

- 老逻辑不受影响
- 新逻辑只在 relay 场景触发
- 首包分流更清晰

建议新增：

- `SessionHello = 11`

第一包允许三种合法类型：

- `HelloStream`，表示旧业务 stream
- `SessionHello(session_type=stream)`，表示新业务 stream
- `SessionHello(session_type=tunnel)`，表示 relay tunnel_session
- `SessionHello(session_type=stream)`，表示 relay stream_session

## 7. 一跳中转构造 tunnel_session 时序

假设：

- A 与 R 之间已建立邻居 Tunnel
- R 与 B 之间已建立邻居 Tunnel
- A 想通过 R 与 B 建 Tunnel

### 7.1 时序图

```text
A                          R                          B
|                          |                          |
|-- BuildSessionReq ------>|                          |
|                          |-- BuildSessionReq ------>|
|                          |<----- BuildSessionResp --|
|<----- BuildSessionResp --|                          |
|                          |                          |
|==== TCP connect to R ===>|                          |
|-- SessionHello(tunnel) ->|                          |
|                          |<=== TCP connect =========|
|                          |<- SessionHello(tunnel) --|
|                          |                          |
|      Relay pairs two TCP streams and byte-forward   |
|------------------------ Hello ---------------------->|
|<---------------------- HelloAck ---------------------|
|                          |                          |
|   Tunnel established between A and B logically      |
```

### 7.2 详细步骤

#### Step 1. A 请求中转建链

A 在已有 `A <-> R` Tunnel 上发送 `BuildSessionReq`：

- `session_id = s1`
- `session_type = tunnel`
- `target_id = B`
- `source_id = A`

#### Step 2. R 校验本地条件

R 检查：

- 是否允许 A 使用自己做 relay
- 是否已有到 B 的邻居 Tunnel
- 是否当前资源允许建立新 bootstrap 会话

如果不满足，直接给 A 返回 `BuildSessionResp(result != 0)`。

#### Step 3. R 通知 B 配合建链

R 通过已有 `R <-> B` 邻居 Tunnel 向 B 发送 `BuildSessionReq`：

- `session_id = s1`
- `session_type = tunnel`
- `target_id = A`
- `source_id = A`

这里的含义不是让 B 作为 relay，而是：

> 请你为会话 `s1` 主动向我建立一条 tunnel_session stream，随后你会在上面收到来自 A 的 Tunnel Hello。

#### Step 4. B 接受并准备

B 收到请求后：

- 校验是否允许来自 A 的该次建链
- 向 R 返回 `BuildSessionResp(accepted)`
- 发起一个新的 TCP 连接到 R 的 RTCP 端口
- 第一包发送 `SessionHello(session_type=tunnel, session_id=s1)`

#### Step 5. A 建立自己的 bootstrap stream

A 在收到 R 的 `BuildSessionResp(accepted)` 后：

- 发起一个新的 TCP 连接到 R 的 RTCP 端口
- 第一包发送 `SessionHello(session_type=tunnel, session_id=s1)`

顺序上 A、B 谁先连到 R 都可以。

#### Step 6. R 配对并转发

R 在本地维护一个 `pending_relay_session_pair_map`：

- key: `session_id`
- value: 来自 source 和 target 的两个 stream 槽位

当两边 `SessionHello` 都到齐后：

- Relay 将这两个 TCP stream 绑定
- 后续不再解析其中的 RTCP 语义
- 只做双向字节转发

#### Step 7. A 在配对后的 stream 上发送 Hello

此时对 A 来说，自己面对的是一条“通往 B 的 TCP stream”。

A 立刻在该 stream 上发送现有 `Hello`：

- `from_id = A`
- `to_id = B`
- `my_port = A.rtcp_port`
- `tunnel_token = ...`
- `device_doc_jwt = optional`

#### Step 8. B 正常处理 Hello

B 收到 `Hello` 后，按现有逻辑执行：

- 解析来源身份
- 校验 `tunnel_token`
- 校验 `device_doc_jwt`（如果存在）
- 创建 `RTcpTunnel`
- 返回 `HelloAck`

#### Step 9. A 收到 HelloAck，完成建链

A 收到 `HelloAck` 后，将该 stream 注册为：

- 目标为 B 的逻辑 Tunnel

从此之后：

- A 可以在该 Tunnel 上发 `Ping/Open/ROpen`
- B 也可以在该 Tunnel 上发 `Ping/Open/ROpen`

Relay 对它们来说不再参与协议语义，只存在于底层字节转发路径。

## 8. 一跳中转构造 stream_session 时序

假设：

- A 与 B 之间已有一条逻辑 Tunnel
- 这条 Tunnel 的底层不是直连，因此无法直接二次 `Tcp.connect(peer:2980)`
- A 想通过该 Tunnel 打开 B 上的一个业务 stream

### 8.1 时序图

```text
A                          R                          B
|                          |                          |
|-------- Open/ROpen on tunnel ---------------------->|
|                          |                          |
|-- BuildSessionReq ------>|                          |
|                          |-- BuildSessionReq ------>|
|                          |<----- BuildSessionResp --|
|<----- BuildSessionResp --|                          |
|                          |                          |
|==== TCP connect to R ===>|                          |
|-- SessionHello(stream) ->|                          |
|                          |<=== TCP connect =========|
|                          |<- SessionHello(stream) --|
|                          |                          |
|      Relay pairs two TCP streams and byte-forward   |
|================ encrypted stream bytes ============>|
|<=============== encrypted stream bytes =============|
```

### 8.2 说明

这里和 `tunnel_session` 的区别只有一条：

- `tunnel_session` 配对完成后，后续先走 `Hello/HelloAck`
- `stream_session` 配对完成后，后续不再走 `Hello`，直接进入业务流字节转发

也就是说，Relay 看到的工作模式完全一样：

- 收控制命令
- 等两边 `SessionHello`
- 配对
- 纯字节转发

真正不同的是：

- 配对后的 stream 交给谁
- 配对后上层还要不要再发送 `Hello`

## 9. 为什么 Hello 和 SessionHello 必须分层

这里要明确一个工程边界。

`SessionHello` 解决的是：

- 这条新 TCP stream 在 Relay 看来属于什么类型
- 应该和哪个待配对会话绑定

`Hello/HelloAck` 解决的是：

- 这条已配对 byte stream 上最终两端是谁
- 是否允许建立 RTCP Tunnel
- Tunnel 建立后用什么 key 加密后续控制包

因此：

- `SessionHello` 是 Relay 关心的首包
- `Hello` 是最终目标节点关心的 `tunnel_session` 首包

两者职责不同，不能合并。

## 10. 节点状态机

### 10.1 发起方 A

状态：

1. `Idle`
2. `RequestingRelay`
3. `ConnectingBootstrap`
4. `WaitingHelloAck`
5. `Established`
6. `Failed`

转移：

- `Idle -> RequestingRelay`
  - 发送 `BuildSessionReq`
- `RequestingRelay -> ConnectingBootstrap`
  - 收到 `BuildSessionResp(accepted)`
- `ConnectingBootstrap -> WaitingHelloAck`
  - 建立到 Relay 的 bootstrap TCP stream 并发送 `SessionHello`
  - Relay 配对完成后发送 `Hello`
- `WaitingHelloAck -> Established`
  - 收到 `HelloAck`
- 任意状态 -> `Failed`
  - 超时、拒绝、连接失败、认证失败

### 10.2 目标方 B

状态：

1. `Idle`
2. `PendingBootstrap`
3. `WaitingHello`
4. `Established`
5. `Failed`

转移：

- `Idle -> PendingBootstrap`
  - 收到来自 Relay 的 `BuildSessionReq`
- `PendingBootstrap -> WaitingHello`
  - 已向 Relay 建立 bootstrap TCP stream 并发送 `SessionHello`
- `WaitingHello -> Established`
  - 收到来自 A 的 `Hello` 并完成 `HelloAck`
- 任意状态 -> `Failed`
  - 超时、连接失败、认证失败、策略拒绝

### 10.3 Relay R

状态：

1. `Init`
2. `WaitingPeerStreams`
3. `Forwarding`
4. `Closed`

转移：

- `Init -> WaitingPeerStreams`
  - 接受 A 的 `BuildSessionReq`
  - 转发给 B
- `WaitingPeerStreams -> Forwarding`
  - 两边 `SessionHello(tunnel)` 都到齐
- `Forwarding -> Closed`
  - 任意一边断开或转发失败

## 11. 数据结构建议

### 10.1 发起方待建链表

建议新增：

```rust
HashMap<String, PendingRelaySession>
```

其中 key 为 `session_id`。

字段建议：

- `target_id`
- `session_type`
- `created_at`
- `notify`
- `state`

### 10.2 Relay 侧配对表

建议新增：

```rust
HashMap<String, PendingRelaySessionPair>
```

字段建议：

- `source_id`
- `target_id`
- `session_type`
- `source_stream: Option<TcpStream>`
- `target_stream: Option<TcpStream>`
- `created_at`
- `state`

### 10.3 目标侧待接收表

目标 B 在收到 `BuildSessionReq` 后，也建议保留一份待接收状态：

```rust
HashMap<String, PendingIncomingRelaySession>
```

作用：

- 记录该次会话是否已被授权
- 在收到后续 `Hello` 时做关联日志和超时清理

## 12. 与现有 Open/ROpen 的关系

本方案不修改 `Open/ROpen` 的角色定位。

### 12.1 `Open/ROpen` 仍然是逻辑 Tunnel 上层控制命令

它们解决的是：

> 在一条已经建立好的逻辑 Tunnel 上，谁负责去发起这次 `stream_session` 的构造。

### 12.2 直连时保留现有行为

如果当前 Tunnel 是直连：

- `Open` 仍走当前直接建 stream 的逻辑
- `ROpen` 仍走当前反连建 stream 的逻辑

### 12.3 Relay 时改成 session 构造

如果当前 Tunnel 不是直连，而是通过 Relay 建立：

- `Open/ROpen` 仍然表示谁来触发这次开流
- 但真正的新数据 TCP stream 不再直接连到真实 peer
- 而是走 `BuildSessionReq/Resp + SessionHello(stream)` 由 Relay 协助建立

因此未来不应只保留一个布尔值 `can_direct`，而应提升为类似：

```rust
enum SessionBuildMode {
    Direct,
    Relay,
}
```

也可以进一步扩成：

```rust
enum SessionBuildMode {
    Direct,
    RelayVia(DID),
}
```

这样 `request_open_stream()` 的核心分支就不再是：

- `can_direct == true`
- `can_direct == false`

而是：

- `SessionBuildMode::Direct`
- `SessionBuildMode::Relay`

## 13. 兼容性策略

### 12.1 旧节点互通

旧节点之间完全不受影响：

- 继续使用 `Hello`
- 继续使用 `HelloStream`
- 继续使用 `Open/ROpen`

### 12.2 新旧混部

如果某个节点不支持新命令：

- 收到 `BuildSessionReq` 时返回 `unsupported`
- 收到 `SessionHello` 新首包时直接关闭连接

这样行为明确，便于快速回退。

### 12.3 推荐顺序

建议升级顺序：

1. 先让 Relay 节点支持新命令和新首包
2. 再让终端节点支持中转建链
3. 最后再在配置中打开 relay 能力

## 14. 代码改造点

### 13.1 `package.rs`

需要新增：

- `CmdType::BuildSessionReq`
- `CmdType::BuildSessionResp`
- `CmdType::SessionHello`

以及对应 body 和 package struct。

### 13.2 `read_package()`

当前首包识别只有：

- `HelloStream`
- `Hello`

需要扩展为：

- `HelloStream`
- `SessionHello`
- `Hello`

### 13.3 `serve_connection()`

当前新连接首包进入两条分支：

- `on_new_stream`
- `on_new_tunnel`

需要新增第三条：

- `on_session_hello`

其中 `on_session_hello` 再根据 `session_type` 分发：

- `stream`
- `tunnel`

### 13.4 `RTcpInner`

需要新增：

- 发起中转建 session 的方法
- 处理 `BuildSessionReq/Resp` 的逻辑
- Relay 配对表
- bootstrap stream 转发逻辑

### 13.5 `RTcpTunnel`

需要把 `HelloAck` 真正纳入 tunnel_session 建立闭环：

- 发起直连 Tunnel 时等待 `HelloAck`
- 通过 Relay 建 Tunnel 时同样等待 `HelloAck`

否则无法严格区分：

- TCP 已联通
- Tunnel 已建立成功

### 13.6 `rtcp_stack.rs`

建议增加配置：

- `relay_enabled: bool`
- `relay_for_peers: Option<Vec<String>>`
- `relay_build_timeout_ms: Option<u64>`
- `relay_pending_limit: Option<usize>`

第一版配置可以先做得简单，只保留：

- `relay_enabled`

### 14.7 `request_open_stream()` 的关键重构

当前 `request_open_stream()` 的分支是：

- `can_direct == true` 时自己直连对端 RTCP 端口
- `can_direct == false` 时走 `ROpen`

这在 Relay 模式下不够。

建议改成两层判断：

1. 控制层仍决定发 `Open` 还是 `ROpen`
2. session 构造层决定这次 `stream_session` 是：
   - 直连构造
   - Relay 构造

也就是说：

- `Open/ROpen` 决定“谁触发”
- `SessionBuildMode` 决定“stream_session 怎么建”

## 15. 超时与清理

### 14.1 建议超时

- `BuildSessionReq` 等待响应：10 秒
- `SessionHello` 双边配对等待：15 秒
- `HelloAck` 等待：15 秒

### 14.2 清理规则

以下情况必须清理 pending 状态：

- 任意一边返回拒绝
- 任意一边 bootstrap TCP 连接失败
- Relay 等待另一侧超时
- A 发出 `Hello` 后 B 未返回 `HelloAck`
- 任意一侧中途断开

避免 `pending_*_map` 无限增长。

## 16. 日志建议

每次 relay session 建立都至少输出以下日志字段：

- `session_id`
- `source_id`
- `target_id`
- `relay_id`
- `phase`
- `result`

推荐关键阶段：

- `build_session_req_recv`
- `build_session_req_forward`
- `bootstrap_stream_arrived`
- `bootstrap_stream_paired`
- `hello_forwarding_started`
- `hello_ack_received`
- `relay_session_established`
- `relay_session_failed`

## 17. 第一版实现边界

第一版明确只做以下能力：

- 单 relay
- 单次构造单个 session
- Relay 不缓存历史路径
- Relay 不做拓扑发现
- Relay 不做多跳递归
- Relay 不代理业务协议

第一版不做：

- 多跳 Relay
- Route Hint
- Strict Path
- Overlay Tunnel 持久复用 ID
- Relay 上的端到端流量可观测增强

## 18. 落地步骤

### Phase 1

补齐 Tunnel 握手闭环：

- 直连建 Tunnel 时真正等待 `HelloAck`
- 清理当前“发出 Hello 就认为 Tunnel 已建立”的路径

### Phase 2

引入新命令与新首包：

- `BuildSessionReq/Resp`
- `SessionHello(tunnel)`
- `SessionHello(stream)`

### Phase 3

完成 Relay 配对与纯转发。

### Phase 4

打通两条路径：

- relay `tunnel_session`
- relay `stream_session`

### Phase 5

补充：

- 配置项
- 超时清理
- 日志
- 单元测试与集成测试

## 19. 测试建议

至少覆盖以下场景：

1. A 直连 B，现有 `Hello/Open/ROpen` 行为不回归
2. A 通过 R 与 B 建 `tunnel_session` 成功
3. R 没有到 B 的邻居 Tunnel，返回失败
4. B 拒绝 Relay 建链请求
5. A 建了 bootstrap stream，但 B 超时未到
6. B 建了 bootstrap stream，但 A 超时未到
7. bootstrap 配对成功，但 `Hello` 认证失败
8. bootstrap 配对成功，但 `HelloAck` 超时
9. 同一 `session_id` 重复使用时被拒绝
10. 中途任一侧断开时 Relay 能正确清理状态
11. 已建立 relay `tunnel_session` 后，`Open` 能通过 relay 建 `stream_session`
12. 已建立 relay `tunnel_session` 后，`ROpen` 能通过 relay 建 `stream_session`

## 20. 结论

这次升级的核心不是引入复杂 Overlay 命令，而是把 RTCP 明确拆成：

- 邻居层：负责现有 RTCP 协议
- Relay 协调层：只负责帮两端建立各种 session 的 TCP stream

其中：

- 对 `tunnel_session`，Relay 拼出 stream 后，后续仍然走现有 `Hello/HelloAck`
- 对 `stream_session`，Relay 拼出 stream 后，后续直接进入业务字节流

这样可以同时满足三点：

- 不破坏现有 RTCP 语义
- 工程改动范围可控
- 为后续多跳扩展保留空间
