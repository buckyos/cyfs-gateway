# 数据转发说明

本文件用于稳定回答“数据怎么转发”“应该用 `call-server` 还是 `forward`”“能不能做反向代理 / 四层转发 / 多上游转发”这类问题。

## 1. 先区分四种不同问题

- `call-server`
  目标是把流量交给一个已经声明在 `servers` 里的 server 对象
- `forward`
  目标是把流量直接转发给一个 upstream URL
- `socks`
  目标是让支持代理的应用通过 SOCKS5 访问远端服务或远端网络资源
- `tun + 宿主机路由`
  目标是处理 `tun` 的 IP 级地址承载与宿主机路由问题，不只是把单条业务流量转给某个上游

不要把这四类方案混成一个词来讲。

## 2. 当前已校验的运行时事实

根据 [implementation-checked.md](implementation-checked.md)，当前可以稳定确认：

- `call-server` 是网关注册的外部命令，执行后返回 `server <id>` 控制动作
- `forward` 是网关注册的外部命令，执行后返回 `forward "<selected_url>"` 控制动作
- `forward` 支持：
  - 缺省算法 `round_robin`
  - 可选算法 `ip_hash`
  - inline upstream 列表
  - `--map <map>` 形式的上游表
  - `url,weight=N` 形式的权重
- `forward` 对 inline upstream 和 `--map` key 的基础校验，只要求它们能被 `Url::parse(...)` 解析
- HTTP server 当前会消费 `server` / `forward` 动作
- TCP / RTCP stack 当前会消费 `server` / `forward` 动作
- UDP stack 当前会消费 `server` / `forward` 动作
- `socks` server 的 `target` / `enable_tunnel` / `rule_config` 会进入代理接入执行路径

因此，skill 可以把“数据转发”稳定拆成：

- server 分发
- upstream 转发
- SOCKS5 代理接入
- `tun` 型 IP 级地址接入（需额外宿主机前提）

## 2.1 `forward` upstream URL 的格式规则

`forward` 的参数层面使用的是 URL，而不是裸的 `host:port`。

最小规则：

- 必须能被 `Url::parse(...)` 成功解析
- 多上游时每个 upstream 都按独立 URL 校验
- 若带权重，格式是 `<url>,weight=<正整数>`
- `--map` 形式里，map 的 key 是 URL，value 是正整数权重

因此下面这些写法属于同一类语法：

```txt
forward http://127.0.0.1:8080
forward https://api.example.com:443
forward tcp:///127.0.0.1:9000
forward udp:///127.0.0.1:2300
forward rtcp://device-id.example/:80
forward rudp://device-id.example:2998/test:80
```

而下面这些写法不应当当成规范示例：

```txt
forward 127.0.0.1:8080
forward /tmp/socket
forward example.com:9000
```

因为它们不是带 scheme 的 URL。

## 2.2 “能解析”不等于“该入口一定支持”

`forward` 命令只负责把参数解析成 URL 并选出一个目标。
真正能不能工作，要看消费这个 `forward` 动作的运行时入口：

- HTTP server
- stream stack，如 TCP / TLS / RTCP
- datagram stack，如 UDP / RUDP

写规范时必须把这两层区分开。

## 2.3 当前可稳定说明的 upstream URL 形态

### A. HTTP server 中的 `forward`

当 `forward` 结果被 HTTP server 消费时：

- `http://...` 和 `https://...` 会按 HTTP 反向代理处理
- 非 `http/https` scheme 会走 tunnel connector 路径
- 对 `http://...` / `https://...`，`target_url` 会和原请求 URI 拼接后再发请求

推荐写法：

```txt
forward http://127.0.0.1:8080
forward https://api.example.com
forward https://api.example.com/base/
```

拼接语义：

- 原请求是 `/v1/chat`
- `forward http://127.0.0.1:8080`
  实际上游请求 URL 变成 `http://127.0.0.1:8080/v1/chat`
- `forward https://api.example.com/base/`
  实际上游请求 URL 变成 `https://api.example.com/base/v1/chat`

注意：

- 这里的 `forward` 目标更像“上游基地址”
- 如果你想保留原始 URI，通常只写 host[:port] 或 base path 前缀，不要在 target 里重复完整业务路径

### B. stream stack 中的 `forward`

当 `forward` 结果被 TCP / TLS / RTCP 这类 stream 入口消费时，运行时调用的是 `stream_forward(...)`，目标 URL 会交给 tunnel manager 按 scheme 选择 tunnel builder。

当前有源码证据可稳定说明的 scheme：

- `tcp://...`
- `tls://...`
- `rtcp://...`
- `socks://...`

其中本地直连最常见的规范写法是：

```txt
forward tcp:///127.0.0.1:9000
forward tls:///example.com:443
forward rtcp://remote-stack-id/:80
```

语义说明：

- `tcp:///127.0.0.1:9000`
  scheme 是 `tcp`
  authority 为空
  path 是 `/127.0.0.1:9000`
  对 IP tunnel 而言，这表示“在当前 tunnel 内打开到 127.0.0.1:9000 的 stream”
- `tls:///example.com:443`
  scheme 是 `tls`
  authority 为空
  path 是 `/example.com:443`
  `TlsTunnel::open_stream()` 会从 path 里解析出 `host:port`
  TLS 连接时仍然会把 `example.com` 作为目标 host 和 SNI 使用
- `rtcp://remote-stack-id/:80`
  authority 是远端 tunnel / stack 标识
  path 里的 `:80` 是目标 stream id 或目标端口语义的一部分

补充：

- `TunnelManager` 当前注册了 `tcp`、`ptcp`、`udp`、`quic`、`tls`、`socks` builder
- `rtcp` / `rudp` 属于 RTCP stack 注册到 tunnel manager 的远端隧道协议
- 如果 scheme 没有对应 builder，即使 URL 能解析，运行时也会报 unknown protocol

### C. datagram stack 中的 `forward`

当 `forward` 结果被 UDP / RUDP 等 datagram 入口消费时，目标 URL 会交给 `create_datagram_client_by_url(...)`。

当前可稳定说明的常见写法：

```txt
forward udp:///127.0.0.1:2300
forward rudp://remote-stack-id:2998/test:80
```

语义说明：

- `udp:///127.0.0.1:2300`
  适合本地 UDP 目标
- `rudp://remote-stack-id:2998/test:80`
  适合经远端 datagram tunnel 转发

### D. 嵌套 URL / 编码 path

当前 `TunnelManager` 和 RTCP tunnel 的测试表明：

- path 中可以承载 `host:port`
- path 中也可以承载另一个完整 URL
- 如果在外层 URL 的 path 中嵌入完整 URL，需要先做 URL 编码

因此像下面这种形态是有实现证据的：

```txt
rtcp://sn.example/%72%74%63%70%3A%2F%2Fpeer.example%2F%3A443
```

但这类写法属于高级场景，不建议在基础文档里当成默认示例。

## 3. 选型口径

### 3.1 什么时候用 `call-server`

适合：

- 目标已经是某个已声明的 `servers.<id>`
- 需要把流量交给 `http` / `dir` / `dns` / `socks` 等 server 对象
- 希望转发目标仍然受 server 配置对象管理

推荐口径：

- “这是 server 分发，不是直接的 upstream URL 转发。”
- “`call-server` 适合在 process chain 里做逻辑分流，再交给某个 server。”

### 3.2 什么时候用 `forward`

适合：

- 目标是一个具体 upstream URL
- 需要反向代理或四层直接转发
- 需要多上游选择或按源 IP 做稳定映射

推荐口径：

- “这是 upstream 转发，目标是 URL，而不是 server id。”
- “如果需要多个上游，可用 `round_robin` / `ip_hash` 与权重。”
- “先区分这是 HTTP 上游基地址、stream tunnel URL，还是 datagram tunnel URL。”

### 3.3 什么时候用 `socks`

适合：

- 只有支持代理的 app 需要访问远端服务
- 希望按规则文件或代理目标控制出口
- 不要求整机进入同一虚拟网段

推荐口径：

- “这是应用代理接入，不是整机三层互通。”

### 3.4 什么时候该切到 `tun + 宿主机路由`

适合：

- 目标是整个网段、整个设备、多个服务地址都可达
- 需要三层私网规划
- 需要宿主机开启转发、静态路由、NAT、防火墙配合

推荐口径：

- “这已经不是单纯的数据转发动作，而是 overlay 网络接入问题。”

## 4. 最小回答模板

只要用户问“怎么转发”，至少给出：

1. 目标层级
2. 应选入口，是 `call-server`、`forward`、`socks` 还是 `tun`
3. 运行时动作
4. 目标对象，是 server id、upstream URL、代理目标还是 overlay 对端
5. 是否需要多上游算法
6. 验证步骤

## 5. 最小配置骨架

### 5.1 HTTP 入口先分发到 HTTP server，再在 server 内决定转发目标

```yaml
stacks:
  web_in:
    protocol: tcp
    bind: 0.0.0.0:80
    hook_point:
      main:
        priority: 1
        blocks:
          route:
            priority: 1
            block: |
              call http-probe;
              call-server http_router;

servers:
  http_router:
    type: http
    hook_point:
      main:
        priority: 1
        blocks:
          route:
            priority: 1
            block: |
              match ${REQ.host} "api.example.com" && forward "http://127.0.0.1:8080";
              match ${REQ.path} "/static/*" && call-server static_dir;
              error 404 "not found";

  static_dir:
    type: dir
    root_path: ./www
```

说明：

- 入口 stack 只负责把流量交给 `http_router`
- `http_router` 再决定是 `forward` 到上游，还是 `call-server` 到本地 `dir` server

### 5.2 TCP 四层直接转发

```yaml
stacks:
  tcp_ingress:
    protocol: tcp
    bind: 0.0.0.0:9000
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              forward tcp:///10.0.0.20:9000;
```

说明：

- 这里讨论的是 stream 级转发
- 如果目标不是 URL 而是已配置 server，就改成 `call-server xxx`

### 5.3 多上游转发

```txt
forward ip_hash tcp:///10.0.0.21:9000,weight=3 tcp:///10.0.0.22:9000,weight=1
```

或：

```txt
forward round_robin --map $UPSTREAMS
```

说明：

- `ip_hash` 适合希望同一来源更稳定地命中同一上游
- `round_robin` 适合普通轮询分担

### 5.3.1 upstream URL 速查

```txt
http://127.0.0.1:8080
https://api.example.com:443
tcp:///127.0.0.1:9000
udp:///127.0.0.1:2300
tls://example.com:443
rtcp://remote-stack-id/:80
rudp://remote-stack-id:2998/test:80
socks://user:pass@127.0.0.1:1080
```

速记：

- HTTP 反向代理优先用 `http://` / `https://`
- 本地四层转发常见写法是 `tcp:///host:port` 或 `udp:///host:port`
- 远端 tunnel 转发常见写法是 `rtcp://...` 或 `rudp://...`
- 代理型上游可以是 `socks://...`

不要省略 scheme。

### 5.4 应用代理接入

```yaml
servers:
  app_proxy:
    type: socks
    target: rtcp://edge-a
    enable_tunnel: true
    rule_config: ./rules/proxy.yaml
```

说明：

- 这是 app 通过 SOCKS5 访问远端资源
- 不要把它表述成“整机已经加入同一虚拟网段”

## 6. 验证顺序

### `call-server`

- 确认目标 server id 已声明
- 确认目标 server 类型与当前入口兼容
- 确认命中规则后返回的是 `server <id>`

### `forward`

- 确认 upstream URL 可解析
- 确认 URL scheme 在当前入口有对应运行时实现，而不只是“语法可解析”
- 确认协议和端口正确
- 如果是 HTTP server，确认是否符合“target_url + 原请求 URI”的拼接预期
- 若是多上游，确认算法和权重来源清晰
- 实测请求或连接是否真正到达目标上游

### `socks`

- 确认 app 是否真的走了代理
- 确认 `target`、`enable_tunnel`、`rule_config` 是否符合预期
- 区分“代理没生效”和“远端资源本身不可达”

### `tun`

- 先看隧道
- 再看 `tun` 地址
- 再看宿主机路由 / 转发 / 防火墙
- 最后看应用层连通

## 7. 常见误判

- 把 `call-server` 说成“转发到 URL”
- 把 `forward` 说成“切换到某个 server 配置对象”
- 把 `socks` 代理接入说成“整机 VPN”
- 把 `forward` 这类业务流量动作说成“已经解决跨网段互联”
- 没有区分 HTTP 反向代理、四层转发和 `tun` 地址承载问题
