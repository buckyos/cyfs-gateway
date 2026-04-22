# cyfs-gateway Tunnel 框架

本文不按“代码文件导读”的方式展开，而是按下面的顺序理解 tunnel 框架：

1. 先看设计意图：它想统一解决什么问题。
2. 再看按用途划分的例子：不同 URL 分别在表达什么。
3. 最后再看当前实现：哪些能力已经落地，哪些还是设计方向。

相关代码入口：

- `src/components/cyfs-gateway-lib/src/tunnel.rs`
- `src/components/cyfs-gateway-lib/src/tunnel_mgr.rs`
- `src/components/cyfs-gateway-lib/src/tunnel_connector.rs`
- `src/components/cyfs-gateway-lib/src/ip/tunnel.rs`
- `src/components/cyfs-gateway-lib/src/ip/proxy_tunnel.rs`
- `src/components/cyfs-gateway-lib/src/socks/tunnel.rs`
- `src/components/cyfs-gateway-lib/src/tls_tunnel.rs`
- `src/components/cyfs-gateway-lib/src/quic_tunnel.rs`
- `src/components/cyfs-gateway-lib/src/rtcp/rtcp.rs`
- `src/components/cyfs-gateway-lib/src/stack/rtcp_stack.rs`

## 1. 设计意图

### 1.1 框架真正想统一的不是“协议”，而是“建链方式”

`cyfs-gateway` 面对的问题不是只有 TCP/UDP/TLS/QUIC 这些传输协议，而是：

- 上层希望只表达“我要访问哪里”
- 中间层希望只表达“应该走哪条链路”
- 下层再决定它究竟是本地直连、代理转发，还是设备到设备 tunnel

所以 tunnel 框架的核心价值，不是把所有协议揉成一个协议，而是把不同的建链方式收敛成一套统一接口。

统一之后，上层可以用同一种方式处理：

- 本地 TCP 连接
- 经过 SOCKS5 的连接
- 经过 TLS/QUIC 的连接
- 设备到设备的 RTCP/RUDP 连接

对上层来说，差别只是 URL 不同；对下层来说，差别才是由哪个 builder 和 tunnel 去落地。

### 1.2 统一抽象解决的三个问题

第一，统一入口。

- 上层只需要提交 URL
- `TunnelManager` 负责按 scheme 找 builder
- `Tunnel` 负责把“开 stream / 开 datagram client”变成统一动作

第二，统一组合方式。

- URL 的前半段表达“通过哪条 tunnel”
- URL 的后半段表达“在这条 tunnel 上访问哪个 target”
- 这样多种传输方式可以被组合，而不是让每个上层模块写一套自己的连接逻辑

第三，统一扩展方式。

- 新协议只要实现 `Tunnel` + `TunnelBuilder`
- 再注册一个新的 scheme
- 现有上层逻辑就可以直接复用，不需要再为新协议补一套专用入口

### 1.3 这个框架里的两个核心术语

为了避免把“tunnel 对端”和“最终业务目标”混在一起，建议固定下面这组术语。

#### Remote

`Remote` 表示 tunnel 本身通向哪里，也就是这条 tunnel 的对端。

例如：

- `rtcp://remote.dev.did/:80` 里的 `remote.dev.did`
- `socks://user:pass@127.0.0.1:1080` 里的 `127.0.0.1:1080`

#### Target

`Target` 表示 tunnel 打开后最终要访问的服务。

例如：

- `rtcp://remote.dev.did/:80` 的 target 是 remote 侧默认主机上的 `80`
- `rtcp://remote.dev.did/google.com:443` 的 target 是 `google.com:443`
- `tcp:///127.0.0.1:9000` 的 target 是本地 IP 世界中的 `127.0.0.1:9000`

一句话概括：

- remote 是“先到哪”
- target 是“到了以后再访问谁”

### 1.4 URL 是这套框架的组合语言

这套框架把 URL 当成一种组合语言，而不是单纯的地址字符串。

统一心智模型可以写成：

```text
$scheme://[$params@]$remote/$target
```

也可以进一步理解为：

```text
tunnel url = remote + target
```

其中：

- `scheme` 决定使用哪个 `TunnelBuilder`
- `authority` 主要承载 remote
- `path` 主要承载 target
- `params@` 是 builder 私有参数段，不强制等价于用户名密码

这也是为什么同样是 URL：

- `tcp:///127.0.0.1:9000`
- `socks://user:pass@127.0.0.1:1080`
- `rtcp://remote.dev.did/:80`

能进入同一套框架，但行为仍然不同。

### 1.5 三斜杠 URL 的设计含义

像 `tcp:///127.0.0.1:9000` 这样的三斜杠 URL 很重要。

它表示：

- 没有显式 remote
- 当前 builder 不依赖先连一个远端 tunnel
- 而是直接用本地已有能力去访问 target

所以：

- `tcp:///127.0.0.1:9000` 更像“用本地 TCP 能力去连目标”
- 不是“先找到某个远端 TCP tunnel，再在其上开流”

这个区分能帮助理解为什么 `tcp`/`udp`/`tls`/`quic` 和 `rtcp`/`socks` 在 URL 外形上类似，但语义层级不同。

### 1.6 设计方向：通过 URL 组合获得可扩展性

Tunnel URL 的长期价值，不只是“描述一个连接目标”，而是让系统通过 URL 组合表达更复杂的链路。

也就是说，未来如果需要新的能力：

- 新的中转协议
- 新的安全封装
- 新的多跳方式
- 新的复用策略

理论上都优先通过“增加新的 builder + 组合 URL”的方式表达，而不是不断给上层接口加新特判。

这也是 tunnel 框架最值得保留的设计意图：上层接口尽量稳定，变化留在 scheme 和 URL 组合里。

## 2. 按用途理解这套框架

如果直接从 trait 和 manager 开始读，很容易把 tunnel 看成“只是个通用连接器”。更容易建立心智模型的方式，是先按用途看它在解决什么问题。

### 2.1 用途一：把本地网络能力包装成统一出口

最简单的一类用途，是把本地直连能力也收进 tunnel 框架，让上层只依赖统一 URL。

典型例子：

```text
tcp:///127.0.0.1:9000
tls:///example.com:443
quic:///example.com:443
udp:///8.8.8.8:53
```

这些 URL 的共同点是：

- authority 为空
- target 在 path
- 本质上是在调用“本机已有的连接能力”

适合的使用场景：

- 把本地 TCP/TLS/QUIC/UDP 访问统一接入 `TunnelManager`
- 让上层 forwarding、HTTP upstream、代理模块都复用同一套出站接口

这类 tunnel 的价值主要是“统一形态”，不是“远端复用状态”。

### 2.2 用途二：把代理出口也收进同一套心智模型

第二类用途，是把“先经过某个代理，再访问目标”的流程统一表达出来。

典型例子：

```text
socks://user:pass@127.0.0.1:1080
```

或者先拿 tunnel，再按目标访问：

```text
socks://user:pass@127.0.0.1:1080
```

然后在代码里调用：

- `open_stream_by_dest(dest_port, dest_host)`
- `create_datagram_client_by_dest(dest_port, dest_host)`

这类用途的设计意义在于：

- 上层不必知道 SOCKS CONNECT、UDP ASSOCIATE 的细节
- 只需要知道“这是一条可用的出口”
- 目标地址再作为 target 传进去

从用途角度看，SOCKS 模块不是一个特殊系统，而是 tunnel 框架里的“远端出口提供者”。

### 2.3 用途三：把设备到设备链路抽象成真正的 tunnel

第三类用途，是这套框架里最接近“真正 tunnel”语义的一类，也就是 `rtcp` / `rudp`。

典型例子：

```text
rtcp://remote.dev.did/:80
rtcp://remote.dev.did/google.com:443
rudp://remote.dev.did/:53
```

这类 URL 的含义是：

1. 先通过 authority 指定 remote，也就是远端设备或远端 stack。
2. 再通过 path 指定 target，也就是让 remote 去访问哪个服务。

两种最常见的理解方式：

- `rtcp://remote.dev.did/:80`
  表示先连到 `remote.dev.did`，再让 remote 侧访问其默认主机上的 `80`
- `rtcp://remote.dev.did/google.com:443`
  表示先连到 `remote.dev.did`，再让 remote 侧去访问 `google.com:443`

这一类用途和本地直连最大的不同是：

- URL 前半段不只是“参数”
- 它真的表示一条独立的远端链路
- 并且这条链路本身值得被复用、保活和管理

### 2.4 用途四：让上层转发逻辑完全不关心底层协议

一旦所有出站方式都统一成 tunnel URL，上层转发逻辑就可以只关心“把数据从 A 转到 B”。

例如同一种 stream forward 逻辑，可以处理：

```text
forward tcp:///127.0.0.1:9000
forward tls:///example.com:443
forward rtcp://remote.dev.did/:80
```

这类用途说明 tunnel 框架的直接收益不是“支持了多少协议”，而是：

- 上层模块的代码路径被统一了
- URL 成了跨模块共享的链路描述方式

### 2.5 用途五：把 HTTP upstream 也纳入 tunnel 框架

HTTP server 在需要把请求转发到 upstream 时，原本往往直接依赖 TCP/TLS 连接器。

在 `cyfs-gateway` 里，这一步可以转成 tunnel URL。

例如，一个 HTTP upstream 可以落到：

```text
tls:///example.com:443
```

或者：

```text
rtcp://remote.dev.did/google.com:443
```

从用途角度看，`TunnelConnector` 做的事不是“实现一种新协议”，而是把 HTTP upstream 连接动作转交给 tunnel 框架。

这意味着 HTTP 模块天然继承了 tunnel 框架的能力边界，而不是自己维护一套连接策略。

### 2.6 用途六：表达多跳，而不是为多跳单独发明新接口

Tunnel URL 的一个更重要用途，是用嵌套 URL 表达多跳。

例如：

```text
rtcp://remote.dev.did/tls%3A%2F%2F%2Fexample.com%3A443
```

它表示：

1. 先到达 `remote.dev.did`
2. 再让 remote 侧把解码后的 target 当作新的 URL
3. 按同一套 tunnel 规则继续打开下一跳

这件事的意义不是“URL 里还能放 URL”，而是：

- 第一跳和后续跳使用同一种表达模型
- 多跳不需要为“第二跳、第三跳”设计新字段
- 只要 remote 侧也实现同一套 tunnel 框架，模型就能自然递归

这里要特别注意：

- 嵌套 URL 放进 path 时必须做 percent-encoding
- 否则会破坏外层 URL 结构

### 2.7 用途七：区分“可信 remote 代执行”与“中间链路只转运”

嵌套还有一层更深的设计含义：它不仅表达多跳，也表达信任边界。

#### 场景 A：可信 remote 代我访问 target

例如：

- 本地笔记本
- 自己控制的 VPS

这时更自然的方式是 target 嵌套：

- 我先建立到 VPS 的 tunnel
- 再让 VPS 继续访问后续 target

这意味着：

- VPS 知道我的最终 target
- VPS 可以代我做路由、审计、缓存和访问控制

适合“可信跳板继续执行下一跳”的场景。

#### 场景 B：中间链路不可信，只提供传输通道

例如：

- 本地笔记本
- 远端 NAS
- 中间经过第三方网络或不可信中转

这时更合理的目标是：

- 中间节点只负责承载底层 stream
- 真正的 tunnel 语义和后续 target 语义都封装在上层协议里

这更接近“remote 建立过程也可嵌套”的方向，也就是：

- 先借助某条底层 stream 把通道打通
- 再在这条 stream 上建立 RTCP 这样的上层 tunnel

可以用一个更具体的例子来理解。

为了便于阅读，先写成“说明性写法”：

```text
rtcp://(socks://aaa:bbb@pub.proxy.com/remote.com)@remote.com:2981/google.com:443/
```

这里的括号不是字面语法，只是为了强调：

- `socks://aaa:bbb@pub.proxy.com/remote.com`
  是“用于建立 RTCP 底层 stream 的 bootstrap URL”
- 外层真正的 RTCP remote 仍然是 `remote.com:2981`
- 最终 target 仍然是 `google.com:443`

真正落到 URL 里的写法，应该把括号里的内容整体做 percent-encoding，然后放到 `params@remote` 这一段：

```text
rtcp://socks%3A%2F%2Faaa%3Abbb%40pub.proxy.com%2Fremote.com@remote.com:2981/google.com:443/
```

它表达的意图是：

1. 先不要直接 TCP connect `remote.com:2981`
2. 先按 `socks://aaa:bbb@pub.proxy.com/remote.com` 这条底层 stream URL，借助 `pub.proxy.com` 拿到一条通向 `remote.com` 的底层 stream
3. 再在这条底层 stream 上建立外层 RTCP tunnel，RTCP 对端仍然视为 `remote.com:2981`
4. RTCP tunnel 建好后，再让 remote 侧去访问 `google.com:443`

这个例子要表达的重点不是“再套一层协议”，而是：

- 中间的 `pub.proxy.com` 只负责提供传输通道
- 真正的 tunnel 身份仍然是 `remote.com:2981`
- 最终 target 语义仍然在 RTCP tunnel 之上展开

这个方向目前还不是通用能力，但从设计上看，RTCP 最适合成为第一个完整支持它的协议。

### 2.8 用途八：把“长期保持连接”变成框架内能力

并不是所有 tunnel 都值得长期保留，但设备到设备 tunnel 往往值得。

对 `rtcp` 来说，一个重要用途就是：

- 不是按需现连现用
- 而是把某条设备间 tunnel 当成长期资源保活

这也是 `keep_tunnel` 的意义：

- 它不只是一个“后台 ping”
- 而是在表明 RTCP 在框架里的角色更接近“长期存在的链路”
- 而不是一次性的出站连接器

## 3. 用这些例子反推 URL 语义

有了前面的用途视角，再看 URL 规则会更清楚。

### 3.1 authority 和 path 的默认职责

默认约定是：

- authority 表示 remote
- path 表示 target

写成统一形式：

```text
$scheme://[$params@]$tunnel_stack_id[:$tunnel_port]/$stream_or_session_id
```

但要注意，这只是统一外形，不是说每种协议都完全共享相同内部语义。

更准确的说法是：

- tunnel 框架提供统一外层结构
- 具体解释仍由各自 builder 决定

例如：

- `socks://user:pass@127.0.0.1:1080` 的 authority 表示 SOCKS 服务器
- `rtcp://remote.dev.did/:80` 的 authority 表示远端设备
- `tcp:///127.0.0.1:9000` 则没有 authority，target 完全在 path

### 3.2 `get_tunnel()` 和 `open_stream_by_url()` 关注点不同

如果 URL 只写到 authority：

```text
rtcp://remote.dev.did
socks://user:pass@127.0.0.1:1080
tcp://192.168.1.10
```

它更像是在表达“拿到一条 tunnel 句柄”。

适合后续再调用：

- `open_stream_by_dest(dest_port, dest_host)`
- `create_datagram_client_by_dest(dest_port, dest_host)`

而完整 URL 更像是在表达“立刻打开目标 stream 或 datagram”。

例如：

```text
tcp:///127.0.0.1:9000
tls:///example.com:443
rtcp://remote.dev.did/:80
```

所以：

- `get_tunnel()` 更偏“先拿出口/链路”
- `open_stream_by_url()` 更偏“直接访问目标”

### 3.3 builder 参数段是协议私有空间

`$params@` 的设计意义，是给某个 builder 留一段私有解释空间。

框架层只要求：

- 这段参数跟随 scheme 进入对应 builder
- 框架本身不强行定义其语义

因此：

- 对 `socks` 来说，它可以是认证信息
- 对 `rtcp` 这类需要“先拿到底层 stream 再建立上层 tunnel”的协议来说，它也可以承载一个经过编码的 bootstrap stream URL
- 对未来协议来说，也可以是别的建链参数

这个约束很重要，因为它保证 URL 结构统一，但不把所有协议都压成同一套字段解释。

### 3.4 host 规范化建议

对于带设备语义的 tunnel，host 端建议尽量使用 DID 对应的 host name。

原因是：

- DID 同时承担身份和可放入 URL host 位的名字
- 当前 RTCP 相关实现已经大量使用 `did.to_host_name()`
- 这样更容易把“设备身份”和“URL 寻址名”统一成同一种稳定表达

因此更推荐：

- 能写 DID host name 时，优先写 DID host name
- 避免同一设备长期混用多种 host 别名

### 3.5 对“同一条 tunnel”的默认理解

从设计口径看，更接近：

```text
tunnel identity ~= (scheme, normalized_host)
```

但这个口径主要是上层默认视角，不等于所有 builder 都必须按这个键做统一缓存。

更准确的分层是：

- 上层默认按 `(scheme, normalized_host)` 理解“我要哪条 tunnel”
- builder 内部如果需要，可以继续把参数段纳入运行时区分

例如：

```text
socks://user_a:pass_a@host
socks://user_b:pass_b@host
```

从 builder 内部看，完全可以是两个不同实例；
从上层默认心智看，它们仍然指向同一个 scheme 下的同一个 host 目标。

当前真正把“同一对端复用为同一条 tunnel”落实得最明显的是 `rtcp`。

### 3.6 一个未来可能有价值的方向：`any://`

如果以后需要一个“不精确指定 builder，只要能到达就行”的入口，可以考虑引入：

```text
any://target-host/...
```

它的语义不是“必须使用某个 scheme”，而是：

- 只给出 host
- 在已有 builder 或现有 tunnel 中查找可用链路
- 命中即可复用

这和现有精确 scheme 的区别是：

- `rtcp://`、`tls://`、`socks://` 表示“必须走这个 builder”
- `any://` 会更像“我只关心到达目标，不关心你底层选哪种 tunnel”

当前代码里还没有这个实现，这里只保留设计方向。

## 4. 当前实现如何落地

前面的部分描述的是理解框架的推荐顺序。下面才回到当前代码。

## 4.1 核心抽象

### `Tunnel`

`src/components/cyfs-gateway-lib/src/tunnel.rs` 里定义的 `Tunnel` trait，统一了五类动作：

- `ping()`
- `open_stream_by_dest(dest_port, dest_host)`
- `open_stream(stream_id)`
- `create_datagram_client_by_dest(dest_port, dest_host)`
- `create_datagram_client(session_id)`

可以把它理解成：

- `Tunnel` 表示“一种可用的网络出口或远端链路”
- `stream_id` / `session_id` 表示“在这条 tunnel 上继续访问哪个目标”

### `TunnelBuilder`

`TunnelBuilder::create_tunnel(tunnel_stack_id)` 负责：

- 读取 URL authority
- 把它解释成该协议自己的 remote 或建链参数
- 返回对应的 `Tunnel`

### `TunnelManager`

`TunnelManager` 负责按 scheme 调度：

- `get_tunnel(url, ...)` 只创建 tunnel，不直接开流
- `open_stream_by_url(url)` 先建 tunnel，再用 path 调 `open_stream()`
- `create_datagram_client_by_url(url)` 先建 tunnel，再用 path 调 `create_datagram_client()`

默认注册的 builder 有：

- `tcp`
- `ptcp`
- `udp`
- `quic`
- `tls`
- `socks`

`rtcp` / `rudp` 不在 `TunnelManager::new()` 默认注册，而是在 `RtcpStack::start()` 里动态注册。

## 4.2 内置协议的当前行为

### `tcp` / `udp`

实现：`src/components/cyfs-gateway-lib/src/ip/tunnel.rs`

当前行为：

- `tcp` 用 `IPTunnel` 建普通 TCP 连接
- `udp` 用 `IPTunnel` 创建 UDP datagram client
- builder 的 `target_id` 为空时，通常表示直接用本地默认能力出站
- builder 的 `target_id` 非空时，可作为本地 bind 信息使用

因此它更像“本地 IP 出口能力”，不是“设备级远端 tunnel”。

### `tls`

实现：`src/components/cyfs-gateway-lib/src/tls_tunnel.rs`

当前行为：

- 从 path 解析 `host:port`
- 建 TCP
- 做 rustls 客户端握手
- 只支持 stream，不支持 datagram

### `quic`

实现：`src/components/cyfs-gateway-lib/src/quic_tunnel.rs`

当前行为：

- 从 path 解析 `host:port`
- 建 QUIC 连接
- 打开双向流并包装成 `AsyncStream`
- 当前只支持 stream

### `socks`

实现：`src/components/cyfs-gateway-lib/src/socks/tunnel.rs`

当前行为：

- authority 表示 SOCKS5 服务器，可带认证信息
- `open_stream_by_dest()` 通过 SOCKS5 CONNECT 连目标
- `create_datagram_client_by_dest()` 通过 SOCKS5 UDP ASSOCIATE 建 datagram client
- authority 为空时，会退化为本地 TCP/UDP 直连

### `ptcp`

实现：`src/components/cyfs-gateway-lib/src/ip/proxy_tunnel.rs`

当前行为：

- builder 的 `target_id` 需要是源地址 `ip:port`
- `stream_id` 需要是完整目标地址
- 建立 TCP 连接后，会先写 PROXY protocol v1 头

它的设计目的，是把源地址显式传给下游。

### `rtcp` / `rudp`

实现：

- `src/components/cyfs-gateway-lib/src/rtcp/rtcp.rs`
- `src/components/cyfs-gateway-lib/src/stack/rtcp_stack.rs`

当前行为：

- 通过 `Hello + tunnel_token` 建立设备间控制 tunnel
- tunnel 内主要承载控制消息
- 业务 stream / datagram 通过后续连接承载，再切到加密流
- `rtcp` 更偏 stream 使用
- `rudp` 更偏 datagram 使用

更完整的协议细节见 [rtcp.md](/Users/liuzhicong/project/cyfs-gateway/doc/rtcp.md)。

## 4.3 RTCP 在当前框架里的特殊地位

如果只看当前实现，RTCP 是最接近“真正 tunnel”语义的协议。

原因有三点。

第一，它有设备级复用语义。

- 当前代码会按“本端 did + 对端 did”复用 tunnel
- 已存在时优先复用
- 新入站 tunnel 命中相同 key 时，会替换旧 tunnel

第二，它有 stack 生命周期。

- 不是只靠 builder 临时建对象
- 而是需要监听、接收入站连接、维护运行态

第三，它支持 keepalive / keep_tunnel。

- 可被视作一个长期保持的设备间链路
- 而不只是某次访问时才临时拉起的连接

因此如果把整个框架看成一条连续光谱：

- `tcp` / `tls` / `quic` / `socks` 更像统一形态的出站连接器
- `rtcp` / `rudp` 才真正体现“可维护、可复用、可保活的远端 tunnel”

## 4.4 上层当前如何使用 tunnel 框架

### 通用 stream 转发

`stack/mod.rs` 的 `stream_forward()` 会：

- 把目标字符串解析为 URL
- 调用 `TunnelManager::open_stream_by_url()`
- 再对源和目标做双向转发

### 通用 datagram 转发

`stack/mod.rs` 的 `datagram_forward()` 会：

- 调用 `TunnelManager::create_datagram_client_by_url()`
- 再做 datagram copy

### HTTP upstream

`TunnelConnector` 会：

- 持有一个 stream URL
- 调用 `TunnelManager::open_stream_by_url()`
- 再把返回的 `AsyncStream` 包装给 HTTP 客户端层使用

### SOCKS 接入

`src/apps/cyfs_gateway/src/socks.rs` 的典型方式是：

- 先基于 `proxy_target` 获取 tunnel
- 再根据客户端请求目标调用 `open_stream_by_dest()`

## 5. 现阶段的实现边界

### 5.1 不是所有 scheme 都同时支持 stream 和 datagram

当前大致可以这样理解：

- `tcp`：主要用于 stream，也具备 datagram 入口实现
- `udp`：主要用于 datagram
- `socks`：支持 stream 和 datagram
- `rtcp`：以 stream 为主，也能承载 datagram 相关能力
- `rudp`：通常用于 datagram
- `tls`：只支持 stream
- `quic`：只支持 stream
- `ptcp`：只支持 stream

文档或配置如果写“统一支持”，需要明确是“统一入口”，不是“统一能力矩阵”。

### 5.2 `enable_tunnel` 目前没有在 `TunnelManager` 中生效

`TunnelManager::get_tunnel()` 的第二个参数当前是 `_enable_tunnel`，并未实际参与过滤逻辑。

因此如果讨论“允许哪些 tunnel scheme”，应把它视为配置层概念，而不是 manager 已经强制执行的行为。

### 5.3 URL 外形统一，但内部语义仍然协议相关

这套框架应理解为：

- 统一入口
- 统一 URL 外壳
- 协议自解释

而不是：

- 所有协议共享完全一致的 authority/path 语义

换句话说，框架统一的是组合方式，不是抹平所有协议差异。

### 5.4 嵌套 URL 目前是“部分能力已经存在，完整模型还未完全收束”

当前可以比较确定的是：

- target 段嵌套已经是现有模型的一部分
- path 中嵌入完整 URL 时需要 percent-encoding
- 部分 tunnel 已经具备递归解析嵌套 target 的基础

但仍需区分：

- “target 是另一个 URL”这件事，已经有现实价值
- “remote 的建立过程本身也走嵌套 Stream URL”，还不是通用落地能力

从设计方向看，RTCP 最适合优先承接后一种能力。

## 6. 如何扩展一个新的 tunnel 协议

如果要增加新的 tunnel 协议，最小步骤是：

### 6.1 实现 `Tunnel`

至少要回答三个问题：

- 如何把目标转换成真实 stream
- 如何把 path 中的 `stream_id` / `session_id` 解释成目标
- 是否支持 datagram；如果不支持，如何清晰返回 `Unsupported`

### 6.2 实现 `TunnelBuilder`

`create_tunnel(tunnel_stack_id)` 需要负责：

- 解析 authority
- 创建协议自己的运行态或连接句柄
- 返回 `Box<dyn TunnelBox>`

### 6.3 注册 builder

常见方式有两种：

- 像 `tcp/tls/quic/socks/ptcp` 一样，在 `TunnelManager::new()` 中默认注册
- 像 `rtcp/rudp` 一样，在对应 stack 成功启动后动态注册

动态注册更适合下面几类协议：

- 依赖本地监听端口
- 依赖设备私钥或 stack 上下文
- 需要维护共享运行态

### 6.4 如果协议同时有入站面，就要区分 Tunnel 和 Stack

像 RTCP 这样既能主动建链，又能接收入站连接的协议，通常不能只靠一个 `TunnelBuilder`。

还需要：

- 独立 stack 生命周期
- 入站监听和接入处理
- 运行态复用表
- 启动后再把 builder 注册给 `TunnelManager`

因此可以把职责分开理解：

- `Tunnel` 负责“怎么用这条链路”
- `Stack` 负责“怎么监听、怎么维护、怎么注册到框架”

## 7. 一句话总结

`cyfs-gateway` 的 tunnel 框架，本质上不是“把所有网络协议做成同一种协议”，而是：

- 用统一 trait 把不同建链方式收敛成同一种能力入口
- 用 URL 表达 remote、target 和组合关系
- 让上层转发、代理、HTTP upstream 共享同一套出站模型
- 再由具体协议决定它只是一个连接器，还是一条值得复用和长期维护的 tunnel

如果只看当前实现，最准确的结论是：

- `tcp` / `tls` / `quic` / `socks` 更多是在提供统一形态的访问能力
- `rtcp` / `rudp` 才更接近设备到设备、可复用、可保活的 tunnel 核心形态
