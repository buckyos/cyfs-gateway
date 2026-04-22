# cyfs-gateway Tunnel 框架

本文基于当前仓库实现整理，目标是说明 `cyfs-gateway` 里 tunnel 的统一抽象、URL 语义、内置协议、RTCP 在框架中的位置，以及如何扩展一个新的 tunnel 协议。

核心代码入口：

- `src/components/cyfs-gateway-lib/src/tunnel.rs`
- `src/components/cyfs-gateway-lib/src/tunnel_mgr.rs`
- `src/components/cyfs-gateway-lib/src/tunnel_connector.rs`
- `src/components/cyfs-gateway-lib/src/ip/tunnel.rs`
- `src/components/cyfs-gateway-lib/src/socks/tunnel.rs`
- `src/components/cyfs-gateway-lib/src/tls_tunnel.rs`
- `src/components/cyfs-gateway-lib/src/quic_tunnel.rs`
- `src/components/cyfs-gateway-lib/src/rtcp/rtcp.rs`
- `src/components/cyfs-gateway-lib/src/stack/rtcp_stack.rs`

## 1. 设计目的

`cyfs-gateway` 并不把“远端连接能力”散落在 HTTP/TCP/UDP/SOCKS 等不同模块里，而是抽象成统一的 tunnel 能力层：

- 上层只关心“我要打开一个 stream”或“我要创建一个 datagram client”
- 下层决定这个连接到底走本地 TCP、TLS、QUIC、SOCKS，还是走设备间的 RTCP tunnel
- 统一入口是 URL

这使得：

- `forward tcp:///127.0.0.1:9000`
- `forward tls:///example.com:443`
- `forward rtcp://remote.dev.did/:80`
- HTTP upstream 通过 `TunnelConnector`

都能复用同一套 tunnel 分发逻辑。

## 2. 核心抽象

### 2.1 Tunnel

`tunnel.rs` 定义了统一 trait：

- `Tunnel::ping()`
- `Tunnel::open_stream_by_dest(dest_port, dest_host)`
- `Tunnel::open_stream(stream_id)`
- `Tunnel::create_datagram_client_by_dest(dest_port, dest_host)`
- `Tunnel::create_datagram_client(session_id)`

可以把它理解为：

- `Tunnel` 是“到某类网络/某个远端栈的接入句柄”
- `stream_id` / `session_id` 是在这个 tunnel 上进一步定位目标对象的标识

其中：

- stream 返回 `Box<dyn AsyncStream>`
- datagram 返回 `Box<dyn DatagramClientBox>`

### 2.2 TunnelBuilder

`TunnelBuilder::create_tunnel(tunnel_stack_id)` 负责把某个 URL authority 转换成具体 tunnel 实例。

这里的 `tunnel_stack_id` 不是固定语义，不同协议自己解释：

- `rtcp://remote.dev.did` 里，authority 表示目标设备/远端 RTCP 栈
- `socks://user:pass@127.0.0.1:1080` 里，authority 表示 SOCKS 服务器
- `tcp://127.0.0.1:18080` 里，authority 会被当成 `IPTunnel.ip_stack_id`
- `tls` / `quic` 的 builder 当前不使用 authority 建 tunnel 状态

### 2.3 TunnelManager

`TunnelManager` 是总调度器：

- 按 URL scheme 查找对应 `TunnelBuilder`
- `get_tunnel(url, ...)` 只创建 tunnel，不开流
- `open_stream_by_url(url)` 先建 tunnel，再用 path 调 `open_stream`
- `create_datagram_client_by_url(url)` 先建 tunnel，再用 path 调 `create_datagram_client`

默认注册的协议：

- `tcp`
- `ptcp`
- `udp`
- `quic`
- `tls`
- `socks`

`rtcp` / `rudp` 不是 `TunnelManager::new()` 默认注册，而是在 `RtcpStack::start()` 时动态注册。

## 3. URL 模型

当前框架的统一约定是：

- authority 表示“tunnel 的目标”
- path 表示“在 tunnel 上要打开的 stream/datagram 目标”

可写成：

```text
$scheme://[$params@]$tunnel_stack_id[:$tunnel_port]/$stream_or_session_id
```

其中：

- `$tunnel_stack_id` 的核心部分是 host
- `@` 前面的 `$params` 统一视为“只对当前 TunnelBuilder 有意义的参数段”
- 这段参数不强制限定为 `username:password`
- 具体语义完全由对应的 TunnelBuilder 自己解析

例如 `socks://user:pass@127.0.0.1:1080` 在当前实现里会把 `user:pass` 解释成 SOCKS 认证信息，但从框架角度看，这只是某个 builder 对参数段的一种具体用法。

## 3.1 标识规范与唯一性口径

为了让不同模块对“同一条 tunnel”形成一致理解，这里补充三个约束。

### 3.1.1 host 端尽量使用 DID 对应的 host name

对于带设备语义的 tunnel，URL 的 host 端应尽可能使用“从 DID 转出来的 host name”。

原因是：

- DID 在这里不仅是身份标识，也被当作可进入 URL host 位的名字
- 当前 RTCP 相关实现已经大量使用 `did.to_host_name()` 作为 URL host
- 这样可以把“设备身份”和“URL 可寻址名字”统一到同一套规范化表达

因此文档口径建议是：

- 能写 DID host name 时，优先写 DID host name
- 不同别名如果本质上指向同一个 DID，最终应尽量收敛到同一个 host 表达

### 3.1.2 同一 scheme 下，host 是默认主标识

当前框架里，`scheme` 表示“精确使用哪个 tunnel builder”，而同一个 `scheme` 下的 `host` 是默认主标识。

也就是说，设计约束上更接近：

```text
tunnel identity ~= (scheme, normalized_host)
```

但这个口径要分成“上层默认获取模型”和“builder 内部运行态”两层来看。

上层默认获取模型更接近：

```text
lookup key ~= (scheme, normalized_host)
```

builder 内部如果有需要，则完全可以进一步细分为：

```text
runtime key ~= (scheme, builder_params, normalized_host)
```

这表示：

- 对上层来说，默认仍然是“按 scheme 和 host 找 tunnel”
- 对 builder 内部来说，可以同时持有多个“参数不同但目标 host 相同”的 tunnel

原则上这在系统内部是可行的。例如：

- `socks://user_a:pass_a@host`
- `socks://user_b:pass_b@host`

从 builder 角度，它们可以是两个不同的 tunnel 实例，因为参数段不同。

这里的含义不是“所有协议现在都已经在代码里按这些键做统一缓存”，而是：

- `scheme` 决定选择哪个 builder
- `host` 决定默认视角下的目标 tunnel 身份
- `params` 如果存在，则由 builder 决定是否把它纳入内部实例区分
- `get_tunnel()` 天然适合作为“获取某个精确 tunnel”的入口

当前实现中，这个语义最明显地体现在 `rtcp`：

- 外部通过 `rtcp://<host>` 精确选择 RTCP builder
- RTCP 内部又会把同一对设备的 tunnel 复用为同一个运行态 tunnel

对其他协议，这个约束更多还是一致性口径，而不是已经全部落成的统一缓存策略。

同时还要注意一个默认行为：

- 如果上层长期使用的是 `get_tunnel` 模型
- 并且传入的信息最终只收敛到 `scheme + host`
- 没有把参数段继续显式带入上层索引语义

那么上层最终看到的，应该只是该 `scheme + host` 下“最后一个创建成功并被当前模型命中的 tunnel”。

换句话说：

- builder 内部可以同时存在多个到同一 host 的 tunnel
- 但如果上层仍然只按 host 取，那它天然只会拿到一个默认命中对象
- 这个默认对象在很多设计里通常就是“最后一个成功创建/覆盖的 tunnel”

### 3.1.3 未来可以引入 `any://`

未来可以支持一个更宽松的 scheme，例如：

```text
any://target-host/...
```

它的语义不是“精确指定某个 builder”，而是：

- 只给出目标 host
- 在所有 builder 里查找“是否已经存在可到达该 host 的 tunnel”
- 只要找到可用 tunnel，就基于它继续开 stream / datagram

因此可以把两类 scheme 区分为：

- 精确 scheme：如 `rtcp://`、`tls://`、`socks://`
  含义是“必须使用这个 builder”
- 宽匹配 scheme：如未来的 `any://`
  含义是“只关心到这个 host，有可用 tunnel 就复用”

当前代码里还没有 `any://` 实现，但文档层面可以先把这个方向固定下来。

### 3.2 Tunnel URL

如果 URL 只写到 authority 为止，那么它表示“拿到一个 tunnel 句柄”，常用于后续再调用：

- `open_stream_by_dest(dest_port, dest_host)`
- `create_datagram_client_by_dest(dest_port, dest_host)`

例如：

```text
rtcp://remote.dev.did
socks://user:pass@127.0.0.1:1080
tcp://192.168.1.10
```

这里要特别注意：

- `rtcp://...`、`socks://...` 这类 authority 通常可以直接理解成 remote
- 但 `tcp://192.168.1.10` 在当前实现里并不等价于“远端 TCP tunnel”
- 对 `IPTunnel` 而言，这类 authority 更接近本地 bind 信息，而不是独立的 remote tunnel 身份

这类 URL 常见于：

- SOCKS server 先根据 `target` 拿到一个 tunnel
- 然后再按客户端请求的目标主机和端口调用 `open_stream_by_dest`

### 3.3 完整 Tunnel URL 与 Target Stream ID

更完整的心智模型是：

```text
tunnel url = remote + target_stream_id
```

也就是：

- 前半段描述“基于哪条 tunnel”
- 后半段描述“要在这条 tunnel 上打开什么 target stream”

这里的 `target_stream_id` 是 tunnel URL path 部分承载的内容。

它的语义是：

- 基于某个 tunnel 去打开一个 stream
- 或基于某个 tunnel 去打开一个 datagram client
- 具体是哪一种，取决于调用入口，以及该 tunnel 对应的 scheme 能力

最简写的方法，是只给一个 port，不附带其他信息。例如：

```text
rtcp://remote.dev.did/:80
rudp://remote.dev.did/:53
```

这表示：

- remote 已经由 authority 指定
- target stream id 只给出最终目标端口
- 具体的目标 host 由 tunnel 自己补齐默认值或按协议规则解释

直接用于 `TunnelManager::open_stream_by_url()` 的例子：

```text
tcp:///127.0.0.1:9000
tls:///example.com:443
quic:///example.com:443
rtcp://remote.dev.did/:80
rtcp://remote.dev.did/google.com:443
```

注意：

- `tcp:///127.0.0.1:9000` 的 authority 为空，真正的 target 在 path
- `rtcp://remote.dev.did/:80` 表示先连 `remote.dev.did`，再让 remote 侧访问其本地 `127.0.0.1:80`
- `rtcp://remote.dev.did/google.com:443` 表示让 remote 侧去连最终目标 `google.com:443`

### 3.4 Remote 与 Target 的术语区分

为了避免把 tunnel 对端和最终服务目标混在一起，建议统一使用下面这套术语。

#### Remote

`Remote` 指的是 tunnel 本身的目标，也就是“这条 tunnel 通到哪里”。

例如：

- `rtcp://remote.dev.did/:80` 里的 `remote.dev.did` 是 remote
- `socks://user:pass@127.0.0.1:1080` 里的 `127.0.0.1:1080` 是 remote

它描述的是 tunnel 层的对端，而不是最终业务服务。

#### Target

`Target` 指的是最终目标。

它一定是一个标准 TCP/UDP 世界里的实体，也就是我们最终想访问的现有服务。

例如：

- `rtcp://remote.dev.did/:80` 里的 target 是 remote 侧默认 host 上的 `80`
- `rtcp://remote.dev.did/google.com:443` 里的 target 是 `google.com:443`
- `tcp:///127.0.0.1:9000` 里的 target 是本机 TCP 世界中的 `127.0.0.1:9000`

换句话说：

- remote 是 tunnel 的对端
- target 是 tunnel 打开后最终要访问的服务

### 3.5 三斜杠 URL 的含义

像 `tcp:///127.0.0.1:9000` 这种带三个斜杠的写法，在这套心智模型里很重要。

它表示：

- 当前 URL 没有填写 remote host
- 所选 builder 不需要先连一个远端 tunnel
- 而是直接使用“本地可用的 tunnel 能力”去打开 target

以 `tcp:///127.0.0.1:9000` 为例：

- `scheme = tcp`
- authority 为空
- target stream id 是 `/127.0.0.1:9000`

在当前实现里，这类 `tcp` / `udp` / `tls` / `quic` 风格的 builder，本质上更接近：

- 不先建立一个独立的 remote tunnel
- 而是直接基于本机 tunnel 能力去打开最终 target

所以可以把 `tcp:///...` 理解成：

- “在本地 tunnel 上打开一个 TCP stream”
- 而不是“先找到某个远端 TCP tunnel，再在其上开流”

### 3.6 Datagram URL

直接用于 `TunnelManager::create_datagram_client_by_url()`：

```text
udp:///8.8.8.8:53
rudp://remote.dev.did/:53
```

### 3.7 嵌套 URL

嵌套 URL 需要分成两类来看：

- target 段嵌套
- remote 或参数段嵌套

二者都服务于同一个目标：让 tunnel 框架本身也成为另一层 tunnel 的承载层，从而形成多跳模型。

#### 3.7.1 target 段嵌套

这一类是当前心智模型里最直接的一种：

- 某条 tunnel 的 target 不是一个简单的 `host:port`
- 而是另一个完整的 Stream URL

例如：

```text
rtcp://remote.dev.did/tls%3A%2F%2F%2Fexample.com%3A443
```

它的含义不是“在 remote 上直接连一个普通 `example.com:443`”，而是：

1. 先到达 `remote.dev.did` 这条 tunnel 的 remote
2. 在 remote 侧把 target stream id 解码成 `tls:///example.com:443`
3. 在 remote 侧的 tunnel 框架里，再执行一次“基于一个 tunnel 打开一个 target”的相同行为

也就是说：

- target 本身可以再次是一个 tunnel URL
- remote 侧收到后会把它当作新的目标，再递归执行一次同样的打开逻辑

这就是多跳模型成立的基础。

换一种说法：

- 第一跳负责把请求送到 remote
- 后续跳由 remote 侧根据嵌套 target 再次决定怎么开下一个 stream

在实现上，当前代码已经具备这类能力的基础：

- `IPTunnel::open_stream()` 支持 path 解码后再分发到 `tcp://` 或 `tls://`
- `RTcpTunnel::open_stream()` / `create_datagram_client()` 也会先对 path 做 URL decode，并识别是否是一个完整 URL

所以“target stream id 可以递归地是另一个 URL”这个想法在当前代码里是成立的，但前提是必须做 URL 编码，不能直接把内层 URL 原样放进 path。

#### 3.7.2 target 嵌套为什么等价于多跳

基于上面的术语，target 嵌套本质上等价于：

- 我先通过第一条 tunnel 到达第一个 remote
- 然后让第一个 remote 再按同样的 tunnel URL 规则，继续打开下一段 target

因此只要 remote 侧也运行同一套 tunnel 框架，就可以自然形成：

- 一跳
- 两跳
- 多跳

而不需要为“第几跳”单独定义新的协议字段。

#### 3.7.3 remote / 参数段嵌套

除了 target 可以嵌套以外，remote 本身的建立方式也可以来自另一层 tunnel 框架。

但这不是一个强制要求每个 tunnel 都支持的功能。

原因是：

- 有些 tunnel 根本不存在“先去打开一个远端 remote tunnel”这一步
- 比如 `IPTunnel` 这类 builder，更接近直接在本机能力上打开 target
- 对这类 tunnel 来说，remote 嵌套没有明确意义

因此更准确的口径应该是：

- target 嵌套是 tunnel URL 通用模型的一部分
- remote/参数段嵌套是某些 builder 可以选择支持的高级能力

#### 3.7.4 remote 嵌套的语义

当一个 tunnel 支持 remote 嵌套时，参数中的嵌套实际表达的是两层意思：

1. 建立方式
   我不是通过“直连 remote”的方式创建这条 tunnel。
2. 创建流程
   我在创建 tunnel 时，本身也是通过框架内的 Stream 模型，也就是某个 Stream URL，先拿到一条底层流，再在这条流上跑上层 tunnel 协议。

也就是说，某个 tunnel 的“建链通道”本身，也可以来自另一个 tunnel。

#### 3.7.5 RTCP 的完整语义

RTCP 是最适合支持这套完整语义的协议。

原因是：

- RTCP 本质上就是“在一条双向 stream 上跑自己的 tunnel 控制协议”
- 因此它天然可以把“底层怎么拿到这条 stream”抽象成可替换步骤

从设计上，RTCP 可以支持如下逻辑：

1. 初始连接
   我不是直接 TCP connect 到目标 remote 设备。
   我先通过某个嵌套的 Stream URL 拿到底层 stream。
   例如，这条底层 stream 可以是“通过一个 SOCKS5 stream 到达目标 remote”。
2. 创建 tunnel
   拿到底层 stream 之后，在这条 stream 上执行 RTCP 自己原来的 `Hello`、`Open`、`ROpen`、加密流接管等逻辑。
3. 后续运行
   一旦 RTCP tunnel 建好，再在这个 tunnel 的 stream 上继续打开新的 target，甚至继续承载嵌套 target。

这意味着：

- RTCP 的 tunnel 不一定非要建立在“直连 TCP socket”上
- 它也可以建立在“由另一条 Stream URL 打开的底层 stream”上
- 从而把 tunnel 的创建过程本身也纳入 tunnel 框架

#### 3.7.6 一个可理解的 RTCP 多跳示例

可以把未来支持的语义理解成下面这类过程：

1. 本地先通过 `socks://...` 打开一条 stream
2. 这条 stream 的最终 remote 是目标 RTCP 设备
3. RTCP 不直接用 `TcpStream::connect()`，而是复用这条已打开的 stream 作为自己的底层传输
4. RTCP tunnel 建立后，再在其上打开 target
5. 这个 target 还可以继续是另一个嵌套 URL

于是整条链路就会变成：

- “用 tunnel 框架创建 RTCP tunnel”
- 再“用 RTCP tunnel 创建下一条 stream/datagram”

从模型上看，这正是 tunnel 框架自举自身的过程。

#### 3.7.7 当前实现与未来方向

需要明确区分当前代码和目标语义：

- 当前代码已经支持 target 段里放入嵌套 URL，并在部分 tunnel 中递归解析
- 当前代码还没有把“remote 的建立过程也走嵌套 Stream URL”完整抽象成通用能力
- 这部分更适合作为 RTCP 优先支持的增强方向

因此现阶段最准确的表述是：

- target 嵌套已经是现有模型的一部分
- remote 嵌套是可选能力，不要求所有 tunnel 都支持
- RTCP 应该成为第一个支持完整嵌套语义的 tunnel 协议

#### 3.7.8 设计意图：通过 URL 组合获得可组合扩展性

Tunnel URL 的最终设计意图，是让整个系统通过“不断增加新的 Tunnel Builder + 组合 URL”获得很强的可组合扩展性。

也就是说：

- 我们不需要为每一种多跳路由、每一种安全等级、每一种复用策略单独设计新的上层接口
- 只需要不断往系统里增加新的 Tunnel Builder
- 再通过字符串级别的 URL 组合，就能在统一框架里表达复杂的路由和中转管理

从这个角度看，Tunnel URL 的价值不只是“定位一个连接目标”，而是：

- 描述建链方式
- 描述目标访问方式
- 描述多跳组合关系
- 描述安全边界和复用边界

因此，复杂链路在框架中的表达方式，本质上可以退化成“字符串拼接后的 URL 组合”。

这正是 Tunnel URL 设计的最终目标。

#### 3.7.9 两种嵌套方式背后的安全语义

前面讲的两种嵌套方式，不只是技术实现上的差异，本质上也是基于安全性和节点角色定位做出的区分。

##### 在 Target 端做跳转

这种方式更适用于两个可信节点之间。

典型场景是：

- 我的笔记本电脑
- 我的云端 VPS

这两个节点都属于我自己，因此它们互为可信节点。

在这种情况下，更自然的选择是：

- 先建立到 VPS 的 tunnel
- 再让 VPS 根据嵌套 target 去打开任意后续目标

这样做的特点是：

- VPS 知道我最终要访问什么 target
- VPS 可以记录、审计、缓存、放行这些 target
- 更适合“可信跳板代我继续访问外部目标”的场景

因此可以把 target 端跳转理解成：

- “我信任 remote 节点理解并执行我的下一跳目标”

##### 在 Remote 端做跳转

这种方式更适用于中间链路不可信的场景。

典型场景是：

- 我的笔记本电脑
- 我的 NAS

我希望两者之间建立 RTCP 连接，但中间可能经过公共节点、第三方网络，或者不可信中转。

在这种情况下，如果我真正看重的是 tunnel 层的端到端加密能力，那么更合理的做法是：

- 不让中间节点看到最终的上层行为
- 而是在 remote 的建立方式上做嵌套
- 先借助某种中转 stream 建出到底层 remote 的连接
- 然后在这条底层 stream 上建立 RTCP tunnel

这样做的特点是：

- 中间节点只知道它承载了一条底层 stream
- 真正的 tunnel 语义和后续 target 行为都被封装在 RTCP 内部
- 更适合“借路但不暴露真实访问语义”的场景

因此可以把 remote 端跳转理解成：

- “我不信任中间跳板知道我的真实 tunnel 行为，所以只借它提供传输通道”

##### 两种方式的核心差别

二者的根本区别不在“能不能多跳”，而在：

- 下一跳决策是暴露给可信 remote
- 还是隐藏在上层 tunnel 协议内部

可以简单总结成：

- target 嵌套：适合可信节点替我继续执行访问
- remote 嵌套：适合不可信中间链路只负责转运，不理解真实 tunnel 语义

## 4. 内置协议的实际行为

### 4.1 `tcp` / `udp`

实现：`ip/tunnel.rs`

语义：

- `tcp` 用 `IPTunnel` 打开普通 TCP 连接
- `udp` 用 `IPTunnel` 创建 `UdpClient`
- 如果 builder 的 `target_id` 为空，默认走任意本地地址发起连接
- 如果 builder 的 `target_id` 非空，会把它当成本地 bind 地址

这意味着 `tcp` 在当前框架里更像“IP 出口能力”，而不是“带复用状态的远端 tunnel 协议”。

### 4.2 `tls`

实现：`tls_tunnel.rs`

语义：

- 解析 path 得到 `host:port`
- 先解析 IP
- 再建立 TCP
- 最后做 rustls 客户端握手

当前只支持 stream，不支持 datagram。

### 4.3 `quic`

实现：`quic_tunnel.rs`

语义：

- 解析 path 得到 `host:port`
- 建 QUIC 连接
- 打开一个双向流并包装成 `AsyncStream`

当前只支持 stream，不支持 datagram。

### 4.4 `socks`

实现：`socks/tunnel.rs`

语义：

- authority 表示 SOCKS5 服务器地址，可带用户名密码
- `open_stream_by_dest()` 通过 SOCKS5 CONNECT 连目标
- `create_datagram_client_by_dest()` 通过 SOCKS5 UDP ASSOCIATE 建 UDP 客户端

如果 authority 为空，则退化成：

- stream 直接本地 TCP 连接
- datagram 直接本地 UDP 连接

### 4.5 `ptcp`

实现：`ip/proxy_tunnel.rs`

语义：

- builder 的 `target_id` 必须是源地址 `ip:port`
- `stream_id` 必须是完整目标地址
- 建立 TCP 连接后会先写一段 PROXY protocol v1 头

这个协议是为了把源地址信息显式传给下游。

### 4.6 `rtcp` / `rudp`

实现：

- `rtcp/rtcp.rs`
- `stack/rtcp_stack.rs`

这是当前项目里真正“设备到设备 tunnel”意义最强的协议。

它的特点是：

- 通过 `Hello + tunnel_token` 建立设备间控制 tunnel
- tunnel 内只传控制消息
- 每次业务 stream / datagram 都再建立新的 TCP 连接
- 数据连接再切到 `EncryptedStream`

更完整的 RTCP 协议细节见 [rtcp.md](/Users/liuzhicong/project/cyfs-gateway/doc/rtcp.md)。

## 5. RTCP 在 tunnel 框架里的位置

### 5.1 tunnel 的复用语义

原始设计里常说“两个设备之间有且仅有一条 tunnel”，但就当前代码而言，这个语义只在 `rtcp` 上成立，而且是“按本端 did + 对端 did”做复用：

- key 形如 `this_device_did + "_" + target_device_did`
- `RTcpInner::create_tunnel()` 会优先复用现有 tunnel
- 新建成功后把 `RTcpTunnel` 放进 `RTcpTunnelMap`
- 如果收到新的入站 tunnel，且 key 已存在，会关闭旧 tunnel 再替换

而 `tcp` / `tls` / `quic` / `socks` / `ptcp` 当前都只是“按 URL 现建现用”的 tunnel 句柄，不具备 RTCP 这种设备级单例语义。

所以更准确的说法是：

- tunnel 框架支持“某些协议自行实现 tunnel 复用”
- 当前明确实现了复用缓存的是 `rtcp`

### 5.2 `rtcp` 与 `rudp` 的关系

在 `RtcpStack::start()` 中：

- `rtcp` 和 `rudp` 复用同一个 `RtcpTunnelBuilder`
- 二者底层都走 RTCP

差别主要在调用方式：

- `rtcp://...` 更常用于 `open_stream_by_url()`
- `rudp://...` 更常用于 `create_datagram_client_by_url()`

需要注意，当前所谓 datagram 并不是单独的 UDP tunnel，而是“基于 RTCP stream 封装的 datagram 客户端”。

### 5.3 keep_tunnel

`RtcpStack` 支持 `keep_tunnel`：

- 启动后后台循环调用 `TunnelManager::get_tunnel("rtcp://...")`
- 成功后调用 `ping()`
- 成功时每 2 分钟检查一次
- 失败时每 15 秒重试一次

这说明 RTCP tunnel 在框架里不仅能“按需创建”，也能被当作一个长期保持的连接资源。

## 6. 上层如何使用 tunnel 框架

### 6.1 通用 stream 转发

`stack/mod.rs` 的 `stream_forward()`：

- 把目标字符串解析成 URL
- 调用 `TunnelManager::open_stream_by_url()`
- 对源 stream 和目标 stream 做双向转发

所以 `forward rtcp://remote.dev.did/:80`、`forward tls:///example.com:443`、`forward tcp:///127.0.0.1:9000` 可以共用一条代码路径。

### 6.2 通用 datagram 转发

`stack/mod.rs` 的 `datagram_forward()`：

- 调用 `TunnelManager::create_datagram_client_by_url()`
- 再做双向 datagram copy

### 6.3 HTTP upstream

`TunnelConnector` 实现了 `tower_service::Service<Uri>`：

- 内部拿着一个目标 stream URL
- 通过 `TunnelManager::open_stream_by_url()` 拿到 `AsyncStream`
- 再包装成 hyper 可用的连接对象

因此 HTTP server 可以把 tunnel URL 当成一种 upstream 连接器。

### 6.4 SOCKS 接入

`src/apps/cyfs_gateway/src/socks.rs` 里：

- 先根据 `proxy_target` 调 `TunnelManager::get_tunnel()`
- 再用客户端请求里的目标地址调用 `open_stream_by_dest()`

也就是说，SOCKS 模块把 tunnel 框架当作“远端出口选择器”。

## 7. 现阶段需要注意的实现边界

### 7.1 不是所有 scheme 都支持 stream 和 datagram 两种能力

当前大致是：

- `tcp`：支持 stream 和 datagram
- `udp`：主要用于 datagram
- `socks`：支持 stream 和 datagram
- `rtcp`：支持 stream，也能承载 datagram
- `rudp`：通常用于 datagram
- `tls`：只支持 stream
- `quic`：只支持 stream
- `ptcp`：只支持 stream

### 7.2 `enable_tunnel` 目前没有在 `TunnelManager` 里生效

`TunnelManager::get_tunnel()` 的第二个参数当前名字就是 `_enable_tunnel`，未参与实际过滤逻辑。

所以如果文档讨论“开启哪些 tunnel scheme”，应明确这是配置层概念，不是 tunnel manager 当前强制执行的行为。

### 7.3 URL 语义依赖具体协议

虽然外层形式统一，但 authority/path 的内部解释仍然是协议相关的：

- `socks://authority` 里的 authority 是代理服务器
- `rtcp://authority/path` 里的 authority 是远端设备，path 是远端目标
- `tcp:///path` 里的 path 是真正目标地址
- `ptcp://authority/path` 同时依赖 authority 和 path

因此 tunnel 框架是“统一入口 + 协议自解释”，不是“所有协议都共享同一种内部语义模型”。

## 8. 如何扩展一个新的 tunnel 协议

最小步骤如下。

### 8.1 实现 `Tunnel`

至少需要决定：

- `open_stream_by_dest()` 怎么把目标主机端口转换成真实连接
- `open_stream()` 怎么解析 `stream_id`
- 是否支持 datagram；如果不支持，返回 `Unsupported` 类错误

### 8.2 实现 `TunnelBuilder`

`create_tunnel(tunnel_stack_id)` 负责：

- 解析 authority
- 创建协议状态
- 返回 `Box<dyn TunnelBox>`

### 8.3 注册 builder

有两种常见方式：

- 像 `tcp/tls/quic/socks/ptcp` 一样，在 `TunnelManager::new()` 里默认注册
- 像 `rtcp/rudp` 一样，在某个 stack 成功启动后动态注册

动态注册适合：

- 协议依赖本地监听端口
- 协议需要设备私钥或栈上下文
- 协议要在运行时维护共享状态

### 8.4 如果协议有入站面

像 RTCP 这样既能出站建 tunnel，也能监听入站连接的协议，还需要：

- 独立的 stack 生命周期
- 入站连接处理器
- 必要时把入站 tunnel 放进复用表

也就是说：

- `Tunnel` 负责“怎么用”
- `Stack` 负责“怎么监听、怎么注册、怎么维护运行态”

## 9. 一句话总结

当前 `cyfs-gateway` 的 tunnel 框架，本质上是“用 URL + trait 抽象统一不同网络出口与远端链路”的一层能力总线：

- `TunnelManager` 负责按 scheme 分发
- `Tunnel` 负责提供统一 stream/datagram 接口
- `RTCP` 在这套框架里提供真正的设备间复用 tunnel
- 其他协议则更多是“统一形态的直连/代理连接器”

如果只看现状实现，最准确的理解不是“所有 tunnel 都是同一种二层协议栈”，而是“不同传输能力被收敛到同一套可编排的 URL 接口下”。
