# 当前实现校验说明

本文件记录本 skill 已对照当前 `cyfs-gateway` 源码校验过的事实。
如果回答里出现“当前应用支持”“字段存在”“默认值是”“能直接承诺”这类表述，必须能追溯到这里。

## 校验范围

- 源码仓库：`cyfs-gateway`
- 校验日期：2026-11-04
- 校验基线：仓库 `666ea22` 的本地实现（Beta2.2）
- 校验方式：源码静态核对、skill 结构、相对链接、YAML 示例及 Rust 字段集合检查；本轮未运行 Rust 测试或网络互通测试。下文引用测试文件用于定位已有行为覆盖，不代表本轮执行结果

## 已校验的当前实现事实

### 1. 当前注册的 stack 协议

`src/components/cyfs-gateway-app-lib/src/stack_registry.rs` 的 `CoreGatewayModule`
注册前 5 种协议，`src/components/cyfs-gateway-modules/src/lib.rs` 的
`TunGatewayModule` 注册 `tun`：

- `tcp`
- `udp`
- `rtcp`
- `tls`
- `quic`
- `tun`

两个二进制在各自的薄 `lib.rs` 中都安装 core 与 tun 模块。结论：skill 可以把这 6 个
协议列为两个当前应用编译安装的能力。配置只会创建其中实际声明的 Stack 实例。

### 2. 当前注册的 server 类型

`src/components/cyfs-gateway-app-lib/src/server_registry.rs` 的 core registration 与
`src/components/cyfs-gateway-modules/src/lib.rs` 的 DNS、SOCKS adapter 为两个应用共同注册：

- `http`
- `socks`
- `dns`
- `dir`
- `cyfs-dir`
- `named-inbox-cache`
- `control_server`
- `local_dns`
- `acme_response`

每个 registration 同时包含 config parser、runtime factory 和 context builder；`dir` 与
`named-inbox-cache` 显式标记为 contextless。`cyfs_gateway` 和 `web3_gateway` 都显式安装
`CoreGatewayModule`、`DnsGatewayModule`、`SocksGatewayModule`、`TunGatewayModule`、
`SnClientGatewayModule`。但只有 `src/apps/web3_gateway/src/lib.rs` 额外安装
`SnGatewayModule`，增加 contextless 的 `sn` server。`cyfs_gateway` 有 9 种 server，
`web3_gateway` 有 10 种；SN client 提供 `sn-dns` ACME provider 不代表安装 SN server。

当前两个应用均未安装 traffic adapter；若配置包含 `traffic` 段，解析时会提示缺少对应模块。

结论：skill 必须按应用分别说明能力；没有安装相应
模块的其它应用会在 parse 阶段拒绝该类型，并列出已安装能力。

### 2.1 编译能力与配置实例

- Cargo dependency 与二进制的显式 `.install(...)` 清单决定可用能力；
- YAML/JSON 只决定从这些能力中创建哪些 Server/Stack 实例及其顺序；
- 配置不能动态装载 Rust 模块，也不会因为组件 crate 出现在依赖图中而自动注册能力；
- Server/Stack registry 在 composition build 后不可变，解析、首次创建和 reload 共用
  同一份 registry。

### 3. `tun` 的当前配置语义

在 `src/components/cyfs-tun/src/tun_stack.rs` 中，`TunStackConfig` 当前字段包括：

- `id`
- `protocol`
- `bind`
- `mask`
- `mtu`
- `tcp_timeout`
- `udp_timeout`
- `stream_idle_timeout`
- `connect_timeout`
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
- `stream_idle_timeout`
- `connect_timeout`
- `hook_point`

在 `src/components/cyfs-socks/src/server/server.rs` 中，`target`、`enable_tunnel`、`rule_config` 会进入 `SocksProxyConfig`。
`target` 是 URL，`enable_tunnel` 是 `Option<Vec<String>>`，不是 bool，`hook_point` 必填。
`src/components/cyfs-socks/src/socks/socks5.rs` 的 hook 消费 `DIRECT` / `PROXY <url>` /
`REJECT` 决策，和 stack 的 `forward` 动作不同。
在 `src/components/cyfs-socks/src/tunnel/tunnel_builder.rs` 中，
`SocksTunnelBuilder` 会：

- 基于 `proxy_target` 与 `enable_tunnel` 调用 `TunnelManager::get_tunnel(...)`
- 再按请求目标地址 `open_stream_by_dest_with_timeout(...)`

`src/components/cyfs-gateway-lib/src/tunnel_mgr.rs` 的 `get_tunnel()` 将参数命名为
`_enable_tunnel` 并忽略，实际仅按 URL scheme 选择 builder。

结论：`socks` 支持通过 tunnel manager 构建代理通道，但不能把 `enable_tunnel` 列表
描述成当前有效的协议筛选或启用开关。

### 5. `rule_config` 的当前语义

在 `src/components/cyfs-socks/src/rule/rule_engine.rs` 中，`RuleEngine::load_target(...)` 支持：

- 本地规则文件
- 远程 URL

结论：skill 可以表述 `rule_config` 是可选规则来源，且支持本地与远程目标。

### 6. `hook_point` / `post_hook_point` / `on_new_tunnel_hook_point` / `blocks` 的 map-to-vector 转换

在 `src/components/cyfs-gateway-app-lib/src/config_parser.rs` 中，当前存在：

- `blocks_map_to_vector(...)`
- `hook_point_value_map_to_vector(...)`
- `hook_point_value_map_to_vector_in_value(...)`

并被用于：

- stack 的 `hook_point`
- RTCP 的 `on_new_tunnel_hook_point`
- HTTP server 的 `hook_point`
- HTTP server 的 `post_hook_point`
- `cyfs-dir` server 的 `hook_point`
- `global_process_chains`

DNS / SOCKS / TUN 的 adapter parser 位于 `src/components/cyfs-gateway-modules/src/lib.rs`，
也调用相同转换器。转换器要求 map，不能把底层 Rust 数组配置直接传给应用入口。

结论：这些区域使用 map 并在解析阶段转成数组。chain 按 priority 升序；block 排序须区分
入口：`src/components/cyfs-gateway-lib/src/config.rs` 的 `create_process_chain()` 按 block priority
排序（包括 DNS）；SOCKS 的 `parse_process_chain()` 则使用 JSON loader 保留传入 block 顺序。

### 7. 顶层 map key 注入为 `id` / `name`

在 `src/components/cyfs-gateway-app-lib/src/config_loader.rs` 的
`GatewayConfigParser::parse(...)` 中：

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

在 `src/components/cyfs-gateway-app-lib/src/gateway.rs` 的 `load_user_config_from_file()` 中，
控制面基础配置合入和参数替换后调用 `normalize_all_path_value_config(...)`。

结论：字符串 `path` / `*_path` 按主配置文件目录解释，并保留 `#fragment`；
`semantic_root` / `rule_config` / `auth_data_dir` 及不以 `_path` 结尾的身份目录别名不在通用归一化范围内。
`load_config_from_file()` 仅对应用默认主配置套用已保存 patch；任意 `-c` 文件不自动套用。

### 9. includes 解析规则

在 `src/components/cyfs-gateway-app-lib/src/config_merger.rs` 中：

- 本地 include 相对当前 include 文件所在目录解析
- 远程 include 相对当前 URL 的父路径解析
- 本地 include 允许目录
- 远程 include 允许远程文件

结论：skill 可以稳定宣称“include 路径相对当前 include 源，而不是相对主配置文件”。

### 10. `ndn` 的当前状态

旧版 `NdnServer` / `NdnServerConfig` 已移除。当前 `cyfs://` 语义服务由
`CyfsDirServer` 提供，配置类型是 `cyfs-dir`；composition 中没有 `ndn` registration。

结论：skill 必须把 `ndn` 表述为“旧类型已经移除，当前应用不支持”；需要该语义时使用
已经注册的 `cyfs-dir`。

### 11. `forward` 的当前语义

在 `src/components/cyfs-gateway-lib/src/cmds/mod.rs` 中，`Forward` 被注册为网关默认外部命令。
在 `src/components/cyfs-gateway-lib/src/cmds/forward.rs` 中，当前可以直接确认：

- 默认算法是 `round_robin`
- 显式支持 `round_robin` / `rr`、`ip_hash`、`hash`、`consistent_hash`、`least_time`
- 支持 inline upstream 列表
- 支持 `--map <map>` 形式的 upstream 来源
- 支持 `--backup-map <map>` 形式的 backup upstream 来源
- inline upstream 支持 `url,weight=N`
- `--map` 的 value 支持字符串或数字权重，且必须是正整数
- 支持 `--next-upstream`、`--tries`、`--next-upstream-timeout`、`--max-fails`、`--fail-timeout`、`--group` 等 group 参数
- 支持 HTTP 状态码 retry 条件与 `--max-body-buffer`
- 支持 `--hash-key`，并在 process chain 执行时捕获已经解析出的 key value
- 未启用 group 语义时，运行时选出一个目标并返回 `forward "<selected_url>"`
- 启用 group 语义时，运行时构造 `ForwardPlan`；有效的多候选 plan 返回 `forward-group "<base64-json-plan>"`，单 URL 且未启用重试的 plan 默认退化为普通 `forward`，除非设置 `--force-group`
- `--group` 只作为失败状态 key 的逻辑名称，不执行预定义 upstream registry lookup

在 `src/components/cyfs-gateway-lib/src/forward/plan.rs`、`selector.rs`、`failure_state.rs` 中，当前可以直接确认：

- 单 URL plan 等价于一次尝试、关闭 next upstream
- primary 排在 backup 之前；处于失败窗口的候选被排到健康候选之后
- `max_fails` 默认 1，`fail_timeout` 默认 10 秒
- group 失败状态是当前进程内的 `group + URL` 状态，不落盘
- `hash` / `consistent_hash` 使用捕获的业务 key；`ip_hash` 使用请求来源 IP
- `least_time` 由执行入口读取 tunnel manager 已有 URL history 做受限 RTT 重排

结论：skill 可以稳定宣称 `forward` 同时具备“兼容的单 URL / 预选一个 URL 模式”和“候选计划 + 执行阶段 next upstream 模式”。不能把旧多 URL 语法误写成自动故障切换；只有显式 group 语义和有效重试策略才会在同一次请求内尝试下一候选。

### 11.1 group retry 的当前执行边界

在 `src/components/cyfs-gateway-lib/src/stack/mod.rs` 中：

- `stream_forward_group(...)` 只在 `open_stream_by_url(...)` 阶段重试；开始 `copy_bidirectional(...)` 后不切换
- `datagram_forward_group(...)` 只在 `create_datagram_client_by_url(...)` 阶段重试；开始 datagram 双向复制后不切换
- `next_upstream_timeout` 是所有候选共享的墙钟预算

在 `src/components/cyfs-gateway-lib/src/server/http_server.rs` 中：

- connect-only 路径只在请求尚可安全交给下一候选时重试
- 状态码路径支持 `http_5xx`、`http_502`、`http_503`、`http_504`
- 状态码 retry 需要缓冲并重放请求体
- GET / HEAD / PUT / DELETE / OPTIONS / TRACE 被归为幂等；其他方法需要显式 `non_idempotent`
- 配置状态码条件但省略 `--max-body-buffer` 时默认 64 KiB；0 表示不启用状态码 retry
- 请求体超过已启用的缓冲上限时返回请求错误
- `invalid_header` 当前只存在于条件模型和解析器中，状态判断没有对应实现

在 provider-first 路径中，`--server-map` 会给 route 标记 `server_id`，selector 会保持同 provider route 相邻；但 `ProviderPolicy.retry_scope` 当前没有被 HTTP / stream / datagram executor 用来截断候选遍历。`Forward::check(...)` 的“至少一个 upstream”预检目前只统计 inline、`--map`、`--backup-map`，没有统计 `--server-map`，因此 `--server-map` 不能单独作为稳定的用户入口。skill 必须把这两个限制写明，不能承诺有状态业务不会跨 provider retry。

### 12. `call-server` 的当前语义

在 `src/components/cyfs-gateway-lib/src/cmds/mod.rs` 中，`CallServer` 被注册为网关默认外部命令。
在 `src/components/cyfs-gateway-lib/src/cmds/server.rs` 中，`call-server <server_id>` 当前会返回：

- `server <server_id>`

结论：skill 可以稳定宣称 `call-server` 是“把流量交给已声明 server 对象”的控制动作，而不是直接 forward 到 URL。

### 13. 当前哪些入口会消费 `server` / `forward` 动作

在 `src/components/cyfs-gateway-lib/src/server/http_server.rs` 中，HTTP server 当前会：

- 消费 `server <id>`，并把请求交给目标 HTTP server
- 消费 `forward <url>`，并调用 `handle_forward_upstream(...)`
- 消费 `forward-group <plan>`，并调用 group HTTP upstream 处理路径

在 `src/components/cyfs-gateway-lib/src/stack/tcp_stack.rs` 中，TCP stack 当前会：

- 消费 `forward <url>`，并调用 `stream_forward(...)`
- 消费 `forward-group <plan>`，并调用 `stream_forward_group(...)`
- 消费 `server <id>`，并把连接交给目标 HTTP 或 stream server

在 `src/components/cyfs-gateway-lib/src/stack/tls_stack.rs` 和 `quic_stack.rs` 中，TLS / QUIC stream stack 当前也会消费 `forward-group <plan>` 并进入 stream group 执行路径。

在 `src/components/cyfs-gateway-lib/src/stack/rtcp_stack.rs` 中，RTCP stack 当前会：

- 消费 `forward <url>`，并调用 `stream_forward(...)`
- stream 入口消费 `forward-group <plan>`，并调用 `stream_forward_group(...)`
- datagram 入口消费 `forward-group <plan>`，并调用 `datagram_forward_group(...)`
- 消费 `server <id>`，并把连接交给目标 HTTP 或 stream server

在 `src/components/cyfs-gateway-lib/src/stack/udp_stack.rs` 中，UDP stack 当前会：

- 消费 `forward <url>`，并通过 `create_datagram_client_by_url(...)` 创建 datagram 转发客户端
- 消费 `forward-group <plan>`，并调用 `datagram_forward_group(...)`
- 消费 `server <id>`，并把 datagram 交给目标 datagram server

结论：skill 可以稳定宣称“数据转发”不只存在于 HTTP 反向代理场景，还覆盖 HTTP、TCP、TLS、QUIC、RTCP、UDP 对普通 `forward` 或 group `forward` 控制动作的消费。不能泛化为所有入口：例如当前 `cyfs-tun` 的处理分支仍只有普通 `forward`，没有 `forward-group` 分支。

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

### 15. TLS / QUIC 身份与证书 schema

- `src/components/cyfs-gateway-lib/src/stack/tls_stack.rs`：`TlsStackConfig` 使用 `hosts`，
  无 `certs` / `client_auth`；`TlsHostConfig` 支持字符串身份主机和 `{host, cert_path, key_path}`
  对象（host 别名 domain），显式证书两个路径必须成对提供。
- `src/components/cyfs-gateway-lib/src/stack/quic_stack.rs`：`QuicStackConfig` 同时保留
  字符串 `hosts` 和兼容 `certs`；元素 `StackCertConfig` 在 `config.rs` 定义，附加数据采用 flatten。
- 两类 stack 均可指定 `identity_manager`；顶层继承规则见 `config_parser.rs` 的
  `apply_gateway_identity_manager_to_stack()`，仅注入字符串 hosts 模式，已有 stack 级对象整体优先。
- TCP/TLS/QUIC/RTCP/TUN/SOCKS 的 stream idle 默认 600 秒；QUIC/RTCP/TUN/SOCKS 的 connect
  默认 60 秒（`stack/mod.rs`），0 关闭。HTTP 的同名 connect 字段另有毫秒/时长字符串语义。
- `tcp_stack.rs` / `udp_stack.rs` 的并发默认均为 0（不设业务上限），UDP `max_sessions`
  也默认为 0；`session_idle_time` 仍默认 120 秒。

### 16. RTCP v4 的身份、准入、资源与保活

- `stack/rtcp_stack.rs` 的 `RtcpStackConfig` 拒绝未知字段，支持 `identity`（别名 did /
  device_did）、`identity_manager`、可选 legacy 字段及四个策略对象。
- `load_rtcp_identity_material()` 禁止 identity 与 key_path / device_config_path / name
  混用；legacy 模式要求 key_path。逻辑 DID 要求匹配的签名设备 JWT；加载器支持显式 JWT、
  身份目录 JWT 与 legacy 设备文件旁的 `device_doc.jwt` 等来源。
- `rtcp/rtcp.rs` 的 `RtcpPeerIdentityConfig` / `RtcpInboundAdmissionConfig` 默认是
  authority_current、禁止 DNS TXT bootstrap、拒绝匿名、same_zone，重确认年龄 unlimited。
- 同文件的 `RtcpLivenessConfig` / `RtcpLimitsConfig` 给出保活、速率和容量默认值及校验；
  完整字段见 config-reference。datagram 上限由 `rtcp/datagram.rs` 定义为 65507 字节。
- `prepare_update()` 拒绝安全策略、身份和私钥变化，需重建 stack。
- `on_new_tunnel_hook_point` 在内建身份/准入检查之后调用，不能用链中的 accept 替代握手策略。

### 17. 新增 server 的字段依据

- `server/cyfs_dir_server.rs`：`CyfsDirServerConfig` 定义 named_store_config_path、
  http_backend_links、签名选项、semantic_root、url_prefix、obj_id_in_host、mode、
  scan_interval_secs（默认 60）和可选 hook_point；链解析变量为 RESP_cyobj_meta / RESP_cyobj_id。
- `server/named_inbox_cache_server.rs`：`NamedInboxCacheServerConfig::validate()` 校验
  target_zone、accepted_paths、cache_path、HTTP(S) origin、正时长/配额/容量，拒绝未知字段；
  接收路径要求 `VerifiedDispatchContext`。字段默认值见 config-reference 对应表。
- `src/components/cyfs-sn/src/sn_server.rs`：`SNServerConfig` 的 ip / bns_server_url 可省略，
  另有 region_probe_config_path、local_relay_node、app_did 等可选字段；该 server 仅 web3 应用安装。

### 18. 顶层 name client / identity manager / ACME

- `config_parser.rs` 定义 `GatewayNameClientConfig`，仅允许 zone_locker_bypass，默认空；
  `config_loader.rs` 解析，`gateway.rs` 在 start / reload 中验证为 DID 并设置到全局 name client。
  `src/apps/cyfs_gateway/tests/test_name_client_config.rs` 覆盖启动、名单替换、错误输入保留旧名单。
- `GatewayIdentityManagerConfig` 定义公共/安全根目录和别名；注入 TLS/QUIC 的 hosts、RTCP
  的 identity 模式，也给未显式设置 identity manager 的 ACME 补值。
- `AcmeConfig` 支持 account、issuer、dns_providers、hosts、identity_manager、check_interval、
  renew_before_expiry；没有 issuers。`tunnel_client_certs` 无当前装载代码，不能作为有效配置。
- `global_collection_manager.rs` 的 `CollectionConfig.data` 使用 serde flatten；类型附加字段
  写在 collection 对象内，不应包一层 data。

### 19. 来源变量与可信身份

- `server/server.rs` 的 `RequestSourceInfo` 区分 conn_source_*、real_source_*、source_*；
  HTTP REQ 的这些保留字段来自 StreamInfo，不是同名客户端头。
- `server/http_server.rs` 仅从 trusted_upstreams 接受 X-Forwarded-For / X-Real-IP 来源恢复，
  已有 PROXY/tunnel 恢复信息优先；顶层 REQ_remote_* 与 REQ_conn_remote_* / REQ_real_remote_*
  是相应来源字段的兼容变量。
- HTTP REQ.source_device_did / source_identity_trust 来自 stream 的 RTCP 身份。
  跨 HTTP 转发如需生成身份头，应先删除客户端同名头再从可信字段填入；当前应用不自动把任意
  身份头视为认证结果。
- `stack/rtcp_stack.rs` 暴露 source_device_id、real_source_did、source_did、
  source_canonical_device_id、source_identity_trust、source_zone_relation 等字段；不能将它们
  与 HTTP 的 source_device_did 字段名混用。

### 20. `call-stack` 与 DNS resolve 扩展

- `cmds/mod.rs` 注册 `CallStack`；`cmds/stack.rs` 的 `call-stack <stack_id>` 返回 lib 级
  `stack <id>`。TCP/TLS 消费该动作并将当前 ordered stream 交给目标 stack；
  目标兼容性与路由循环检查由 `stack/stack.rs` 的 manager 处理，目前可接收的目标为 TCP/TLS。
- `DnsGatewayModule` 安装 `src/components/cyfs-dns/src/cmd_resolve.rs` 的 `resolve` 扩展，
  支持默认 DNS、指定 DNS IP/端口或已声明的 name server；不是名为 dns-resolve 的命令。

### 21. DSL 当前语法与内建命令

- `src/components/cyfs-process-chain/src/cmd/factory.rs` 注册 `first-ok`、`oneof`、`split`、
  URI/query 命令、echo 及手册已有的控制/集合/字符串命令；命令完整性应以该 registry 核对。
- `cmd/control.rs`：first-ok 至少接受两个命令替换，按 success/error/control 顺序组合，
  不吞掉 control；`cmd/match_.rs` 的 oneof 使用与 eq 相同的 typed/loose 比较。
- `cmd/uri.rs` 定义 parse-authority（别名 parse-auth）、parse-uri、parse-query、build-uri、
  build-query、query-get；`cmd/string.rs` 的 split 返回 List，可 capture。
- `block/parser.rs` / `block/exec.rs` 支持 case/when/end（含 subject as binding）、for、
  if、match-result；变量路径的动态下标、安全访问与缺省值见
  `src/components/cyfs-process-chain/src/test/test_var.rs`，Map/List 字面量见
  `src/components/cyfs-process-chain/src/test/test_collection_literal.rs`。
- `src/components/cyfs-process-chain/src/test/test_case.rs` / `test_first_ok.rs` 验证单次 subject
  求值、绑定恢复、分支选择、结果组合和非法输入；不能把 case 当成普通命令或 shell case 模板。

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
