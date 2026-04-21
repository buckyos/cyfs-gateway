# 当前实现校验说明

本文件记录本 skill 已对照当前 `cyfs-gateway` 源码校验过的事实。
如果回答里出现“当前应用支持”“字段存在”“默认值是”“能直接承诺”这类表述，必须能追溯到这里。

## 校验范围

- 本地源码目录：`/mnt/f/work/cyfs-gateway`
- 校验时 HEAD：`d9ff3b8`

## 已校验的当前实现事实

### 1. 当前注册的 stack 协议

在 `src/apps/cyfs_gateway/src/lib.rs` 中，`GatewayConfigParser` 和 `GatewayFactory` 显式注册了：

- `tcp`
- `udp`
- `rtcp`
- `tls`
- `quic`
- `tun`

结论：skill 可以把这 6 个协议列为“当前应用层正式支持”。

### 2. 当前注册的 server 类型

在 `src/apps/cyfs_gateway/src/lib.rs` 中，当前显式注册了：

- `http`
- `socks`
- `dns`
- `dir`
- `control_server`
- `local_dns`
- `sn`
- `acme_response`

结论：skill 可以把这 8 个 server 类型列为“当前应用层正式支持”。

### 3. `tun` 的当前配置语义

在 `src/components/cyfs-tun/src/tun_stack.rs` 中，`TunStackConfig` 当前字段包括：

- `id`
- `protocol`
- `bind`
- `mask`
- `mtu`
- `tcp_timeout`
- `udp_timeout`
- `io_dump_*`
- `hook_point`

创建 stack 时使用的是：

- `.ip(config.bind)`
- `.mask(...)`
- `.mtu(...)`

结论：当前有明确证据表明 `tun` 是以 IP、mask、MTU 为核心的 L3 / IP 级配置模型；这能证明字段语义，但不足以单独承诺完整组网效果。

### 3.1 `tun.hook_point` 的必填性与运行时作用

在 `src/components/cyfs-tun/src/tun_stack.rs` 中，当前可回溯到以下事实：

- `TunStackBuilder` 创建时会检查 `hook_point`，缺失则返回 `hook_point is required`
- `TunStackConfig` 中 `hook_point` 不是可选字段
- `tun` 的 TCP / UDP 连接处理会先执行 `hook_point`
- 结合本文件后续已校验事实，当前可消费的有效动作应按 process chain 返回的 `forward ...` 或 `server ...` 理解
- 若没有可消费的返回动作，则不会形成有效业务转发路径

结论：

- `tun` 配置里的 `hook_point` 属于必填项，不应省略
- 讨论“组网 / 互通 / 虚拟局域网”时，不能只给 `bind` / `mask` / `mtu`
- 仅有 `tun` 地址参数不足以形成可用数据路径，还必须说明 `hook_point` 的转发逻辑

### 4. `socks` 的当前配置语义

在 `src/components/cyfs-socks/src/server/config.rs` 中，`SocksServerConfig` 当前字段包括：

- `id`
- `username`
- `password`
- `target`
- `enable_tunnel`
- `rule_config`
- `hook_point`

在 `src/components/cyfs-socks/src/server/server.rs` 中，`target`、`enable_tunnel`、`rule_config` 会进入 `SocksProxyConfig`。
在 `src/apps/cyfs_gateway/src/socks.rs` 中，`SocksTunnelBuilder` 会：

- 基于 `proxy_target` 与 `enable_tunnel` 调用 `TunnelManager::get_tunnel(...)`
- 再按请求目标地址 `open_stream_by_dest(...)`

结论：当前有明确证据表明 `socks` 不只是本地直连代理配置，还支持通过 tunnel manager 构建面向代理目标的通道。

### 5. `rule_config` 的当前语义

在 `src/components/cyfs-socks/src/rule/rule_engine.rs` 中，`RuleEngine::load_target(...)` 支持：

- 本地规则文件
- 远程 URL

结论：skill 可以表述 `rule_config` 是可选规则来源，且支持本地与远程目标。

### 6. `hook_point` / `post_hook_point` / `on_new_tunnel_hook_point` / `blocks` 的 map-to-vector 转换

在 `src/apps/cyfs_gateway/src/config_loader.rs` 中，当前存在：

- `blocks_map_to_vector(...)`
- `hook_point_value_map_to_vector(...)`
- `hook_point_value_map_to_vector_in_value(...)`

并被用于：

- stack 的 `hook_point`
- RTCP 的 `on_new_tunnel_hook_point`
- HTTP server 的 `hook_point`
- HTTP server 的 `post_hook_point`
- `global_process_chains`

结论：skill 可以稳定宣称这些区域支持 YAML map 写法并在解析阶段转成数组。

### 7. 顶层 map key 注入为 `id` / `name`

在 `src/apps/cyfs_gateway/src/config_loader.rs` 的 `GatewayConfigParser::parse(...)` 中：

- `stacks.<key>` 会注入 `id`
- `servers.<key>` 会注入 `id`
- `timers.<key>` 会注入 `id`
- `limiters.<key>` 会注入 `id`
- `collections.<key>` 会注入 `name`
- `global_process_chains.<key>` 会注入 `id`

结论：skill 可以把“map key 是定义源”写成硬规则。

### 8. 路径归一化规则

在 `src/components/cyfs-gateway-lib/src/server/mod.rs` 中：

- `set_gateway_main_config_dir(...)` 会设置主配置目录
- `normalize_all_path_value_config(...)` 会归一化 `path` 与 `*_path`
- 相对路径按传入的 `base_dir` 归一化

在 `src/apps/cyfs_gateway/src/lib.rs` 中，加载主配置文件后会先设置主配置目录，再调用 `normalize_all_path_value_config(...)`。

结论：skill 可以稳定宣称“配置值里的 `path` / `*_path` 按主配置文件目录解释”。

### 9. includes 解析规则

在 `src/apps/cyfs_gateway/src/config_merger.rs` 中：

- 本地 include 相对当前 include 文件所在目录解析
- 远程 include 相对当前 URL 的父路径解析
- 本地 include 允许目录
- 远程 include 允许远程文件

结论：skill 可以稳定宣称“include 路径相对当前 include 源，而不是相对主配置文件”。

### 10. `ndn` 的当前状态

在 `src/components/cyfs-gateway-lib/src/server/ndn_server.rs` 中，库里存在 `NdnServerConfig`。
但在 `src/apps/cyfs_gateway/src/lib.rs` 中，没有注册 `ndn` 对应 parser/factory。

结论：skill 必须把 `ndn` 表述为“库里有实现，但当前应用没有注册支持”。

### 11. `forward` 的当前语义

在 `src/components/cyfs-gateway-lib/src/cmds/mod.rs` 中，`Forward` 被注册为网关默认外部命令。
在 `src/components/cyfs-gateway-lib/src/cmds/forward.rs` 中，当前可以直接确认：

- 默认算法是 `round_robin`
- 显式支持 `round_robin` 与 `ip_hash`
- 支持 inline upstream 列表
- 支持 `--map <map>` 形式的 upstream 来源
- inline upstream 支持 `url,weight=N`
- `--map` 的 value 支持字符串或数字权重，且必须是正整数
- 运行时会选出一个目标并返回 `forward "<selected_url>"`

结论：skill 可以稳定宣称 `forward` 是“按算法从一个或多个 upstream 中选出目标 URL 的控制动作”。

### 12. `call-server` 的当前语义

在 `src/components/cyfs-gateway-lib/src/cmds/mod.rs` 中，`CallServer` 被注册为网关默认外部命令。
在 `src/components/cyfs-gateway-lib/src/cmds/server.rs` 中，`call-server <server_id>` 当前会返回：

- `server <server_id>`

结论：skill 可以稳定宣称 `call-server` 是“把流量交给已声明 server 对象”的控制动作，而不是直接 forward 到 URL。

### 13. 当前哪些入口会消费 `server` / `forward` 动作

在 `src/components/cyfs-gateway-lib/src/server/http_server.rs` 中，HTTP server 当前会：

- 消费 `server <id>`，并把请求交给目标 HTTP server
- 消费 `forward <url>`，并调用 `handle_forward_upstream(...)`

在 `src/components/cyfs-gateway-lib/src/stack/tcp_stack.rs` 中，TCP stack 当前会：

- 消费 `forward <url>`，并调用 `stream_forward(...)`
- 消费 `server <id>`，并把连接交给目标 HTTP 或 stream server

在 `src/components/cyfs-gateway-lib/src/stack/rtcp_stack.rs` 中，RTCP stack 当前会：

- 消费 `forward <url>`，并调用 `stream_forward(...)`
- 消费 `server <id>`，并把连接交给目标 HTTP 或 stream server

在 `src/components/cyfs-gateway-lib/src/stack/udp_stack.rs` 中，UDP stack 当前会：

- 消费 `forward <url>`，并通过 `create_datagram_client_by_url(...)` 创建 datagram 转发客户端
- 消费 `server <id>`，并把 datagram 交给目标 datagram server

结论：skill 可以稳定宣称“数据转发”不只存在于 HTTP 反向代理场景，还覆盖 TCP / RTCP / UDP 入口对 `server` / `forward` 控制动作的消费。

### 14. `tls` upstream URL 在当前 tunnel 实现中的形态

在 `src/components/cyfs-gateway-lib/src/tunnel_mgr.rs` 中，`open_stream_by_url(...)` 会：

- 按 URL scheme 选择 tunnel builder
- 把 URL 的 `authority` 传给 `create_tunnel(...)`
- 再把 URL 的 `path` 传给 tunnel 的 `open_stream(...)`

在 `src/components/cyfs-gateway-lib/src/tls_tunnel.rs` 中：

- `TlsTunnelBuilder::create_tunnel(...)` 当前忽略传入的 `tunnel_stack_id`
- `TlsTunnel::open_stream(...)` 只通过 `get_dest_info_from_url_path(stream_id)` 从 path 里解析目标 `host:port`
- 解析出的 host 会继续用于 DNS 解析和 TLS `ServerName` / SNI

结论：在当前 `forward` -> `TunnelManager` -> `TlsTunnel` 这条执行路径里，TLS upstream 的规范写法应是：

- `tls:///host:port`

而不是把 `host:port` 放在 authority 里的 `tls://host:port`。

## 当前没有足够证据直接承诺的部分

以下结论在本次校验中没有找到足够实现证据，skill 不应直接承诺：

- `tun` 等价于 TAP
- 仅凭 `tun` 配置就会自动建立端到端三层互通
- `tun.bind` / `mask` 本身就等价于一个已经落地的虚拟私网方案
- hub-spoke / full-mesh / 异地组网是 `cyfs-gateway` 原生内建且无需额外宿主机动作的能力
- `cyfs-gateway` 原生提供 L2 bridge / switch 语义
- 不同网段设备会天然形成同一广播域
- 依赖 ARP、广播、mDNS、NetBIOS 的 app 能自动按原生局域网方式工作
- `socks5` 方案等价于整机 VPN 或整机三层互通

这些结论如果要说，只能写成“当前 evidence 不足”。
