# 配置参考

这是 cyfs-gateway 配置规范的发布版参考文件。

它整合了配置装载、合并、路径归一化、顶层结构、类型支持范围和关键字段规则，可直接单独使用。

## 1. 配置装载链

运行时有三个关键概念：

- `user_config`
- `effective_config`
- 内置控制面默认配置 `gateway_control_server.yaml`

行为规则：

1. 先读取主配置文件及其 `includes`
2. 再把 `gateway_control_server.yaml` 作为基础配置合入
3. 这份结果视为 `user_config`
4. 仅当加载应用默认配置文件且存在有效的已保存 patch 时，在 `user_config` 基础上叠加得到 `effective_config`；指定其它配置文件不会自动套用该 patch
5. 实际运行使用的是 `effective_config`

因此：

- `user_config` 不是“纯用户原文”
- `effective_config` 才是最终生效配置
- 控制面基础配置合入后先做参数替换和路径归一化，再形成 `user_config`；无效的已保存 patch 会记日志并忽略

## 2. includes 与 merge

根对象只识别：

```yaml
includes:
  - path: other.yaml
```

支持：

- 本地文件
- 本地目录
- `http://` / `https://` 远程文件

相对 include 解析规则：

- 本地 include：相对当前 include 文件所在目录
- 远程 include：相对当前 URL 的父目录

merge 语义：

- object 对 object：递归 merge
- array 对 array：去重追加
- array 对单值：若不存在则追加
- 其他类型：后者覆盖前者

结论：

- 当前文件优先级高于它 include 的文件
- 不能把它理解成“简单整段覆盖”

## 3. 路径归一化

配置值中以下字段会被识别为路径：

- `path`
- 所有以 `_path` 结尾的字段

规则：

- 相对路径统一按“主配置文件目录”解释
- 不是按 include 文件所在目录解释
- `a.json#fragment` 这类值会只归一化路径部分，保留 `#fragment`
- 这是按 key 名称递归处理字符串值，不会识别任意“看起来像路径”的字段；`semantic_root`、`rule_config`、`auth_data_dir` 不在这条通用规则内。身份目录建议使用 canonical 的 `public_root_path` / `security_root_path`，不要假定别名也会在此阶段归一化

所以必须区分两件事：

- include 路径相对当前 include 文件
- 配置字段里的 `path` / `*_path` 相对主配置文件

## 4. 顶层 section

常见顶层字段：

- `includes`
- `user_name`
- `password`
- `js_externals`
- `timers`
- `device_manager`
- `identity_manager`
- `name_client`
- `acme`
- `tls_ca`
- `limiters`
- `collections`
- `global_process_chains`
- `stacks`
- `servers`

真正会被解析并构造成运行时对象的主要 section：

- `stacks`
- `servers`
- `global_process_chains`
- `collections`
- `timers`
- `limiters`
- `device_manager`
- `identity_manager`
- `name_client`
- `acme`
- `tls_ca`

`traffic` 需要额外安装 traffic adapter；当前两个应用均未安装，配置该 section 会报错。
旧 `tunnel_client_certs` 没有当前配置解析/运行时装载入口，不作为支持项。

## 5. map key 注入规则

这些 section 的 map key 会变成运行时主标识：

| section | 注入字段 |
| --- | --- |
| `stacks.<key>` | `id = <key>` |
| `servers.<key>` | `id = <key>` |
| `timers.<key>` | `id = <key>` |
| `limiters.<key>` | `id = <key>` |
| `collections.<key>` | `name = <key>` |
| `global_process_chains.<key>` | `id = <key>` |
| `blocks.<key>` | `id = <key>` |

因此：

- `id` / `name` 通常不需要在 YAML 里手写
- map key 才是配置定义源

## 6. hook_point 结构

常见写法：

```yaml
hook_point:
  main:
    priority: 1
    blocks:
      default:
        priority: 1
        block: |
          call-server welcome;
```

规则：

- `hook_point` 是 chain map
- `blocks` 是 block map
- 解析时会转成数组
- chain 按 `priority` 从小到大执行；使用 `ProcessChainConfig::create_process_chain()` 的入口也按 block 的 `priority` 升序排列
- SOCKS 使用 JSON loader，保留转换后的 block 顺序，不按 block 的 `priority` 排序；不要依赖 SOCKS 的 block 优先级，需固定顺序时用单个 block 或显式 `exec`
- 应用配置解析入口要求 chain map 和 block map，不接受底层 Rust 类型使用的数组写法

当前会做 map-to-vector 转换的区域：

- stack 的 `hook_point`
- HTTP server 的 `hook_point`
- HTTP server 的 `post_hook_point`
- `cyfs-dir` / DNS / SOCKS server 的 `hook_point`
- RTCP stack 的 `on_new_tunnel_hook_point`
- `global_process_chains`

## 7. 已支持的 stack 协议

当前 cyfs-gateway 应用层正式支持：

- `tcp`
- `udp`
- `tls`
- `quic`
- `rtcp`
- `tun`

所有 stack 都使用 `protocol`，`id` 由 map key 注入。下文 `?` 表示可省略。
`io_dump_*` 指 `io_dump_file`、`io_dump_rotate_size`、`io_dump_rotate_max_files`、
`io_dump_max_upload_bytes_per_conn`、`io_dump_max_download_bytes_per_conn`。

### `tcp`

字段：

- `bind`
- `transparent?`
- `concurrency?`
- `trusted_upstreams?`
- `stream_idle_timeout?`
- `io_dump_file?`
- `io_dump_rotate_size?`
- `io_dump_rotate_max_files?`
- `io_dump_max_upload_bytes_per_conn?`
- `io_dump_max_download_bytes_per_conn?`
- `reuse_address?`
- `hook_point`

默认：

- `transparent = false`
- `reuse_address = false`
- `concurrency = 0` 表示不设业务并发上限；`stream_idle_timeout = 600`（秒，0 关闭）
- `trusted_upstreams = []`；配置为 IP/CIDR 列表，配合 `proxy-protocol-probe` 限制可恢复来源地址的直接上游

### `udp`

字段：

- `bind`
- `concurrency?`
- `max_sessions?`
- `session_idle_time?`
- `transparent?`
- `io_dump_*`
- `reuse_address?`
- `hook_point`

常用默认值：

- `concurrency = 0`、`max_sessions = 0`，均表示不设该项业务上限
- `session_idle_time = 120`

### `tls`

字段：

- `bind`
- `hook_point`
- `hosts?`
- `identity_manager?`
- `concurrency?`
- `alpn_protocols?`
- `io_dump_*`
- `reuse_address?`
- `trusted_upstreams?`
- `stream_idle_timeout?`

`hosts` 元素可以是主机名字符串，或显式证书对象：

- 字符串：通过 identity manager 的身份目录读取该主机证书
- 对象：`host`（别名 `domain`）、`cert_path`、`key_path`；两个路径必须成对提供，装载后须为绝对路径
- `identity_manager` 使用 `public_root_path?`、`security_root_path?`；可继承顶层配置
- 当前 TLS schema 没有 `certs` 或 `client_auth` 字段，不能沿用旧示例
- `trusted_upstreams` 与 TCP 的 PROXY protocol 信任来源规则相同
- `stream_idle_timeout` 默认 600 秒，0 关闭

### `quic`

字段：

- `bind`
- `concurrency?`
- `hook_point`
- `hosts?`（字符串数组，通过 identity manager 加载证书）
- `identity_manager?`
- `certs?`（兼容显式证书/ACME 配置，默认空数组）
- `alpn_protocols?`
- `io_dump_*`
- `reuse_address?`
- `stream_idle_timeout?`
- `connect_timeout?`

QUIC `certs` 元素字段：`domain`、`identity?`、`identity_manager?`、`acme_type?`、
`cert_path?`、`key_path?`，以及扁平展开的 ACME 附加数据（不是名为 `data` 的嵌套对象）。
不能把 QUIC 的 `certs` 写法直接复制给 TLS。

### `rtcp`

字段：

- `bind`
- `hook_point`
- `keep_tunnel?`
- `keep-tunnel?`，是 `keep_tunnel` 的别名
- `on_new_tunnel_hook_point?`
- `identity?`（别名 `did` / `device_did`）
- `identity_manager?`
- `key_path?`
- `device_config_path?`
- `device_doc_jwt?`
- `name?`
- `io_dump_*`
- `reuse_address?`
- `peer_identity?`
- `inbound_admission?`
- `liveness?`
- `limits?`
- `stream_idle_timeout?`
- `connect_timeout?`

约束：

- 身份目录模式：配置 `identity`，按 identity manager 加载身份；不能同时配置 `key_path` / `device_config_path` / `name`
- 显式配置 stack 级 `identity_manager` 时必须有 `identity`
- 兼容模式：未配置 `identity` 时 `key_path` 必填；此时未配置 `device_config_path` 和 `device_doc_jwt` 才要求 `name`
- 逻辑 DID（非 `did:dev:<pkx>`）必须提供与 DID 和私钥匹配的 owner 签名设备 JWT；可显式写 `device_doc_jwt`（别名 `device-doc-jwt` / `device_document_jwt`）、由设备文件取得，或由身份目录/设备文件旁的 JWT 文件加载
- RTCP 配置及以下四个策略对象拒绝未知字段；安全策略、身份或私钥变化需要重建 stack，不能假定原位 reload

RTCP v4 策略字段与默认值：

| 对象 | 字段与默认值 |
| --- | --- |
| `peer_identity` | `requirement: authority_current`（可选 `trusted_snapshot`）；`dns_txt_bootstrap: false` |
| `inbound_admission` | `anonymous: reject`（可选 `allow`）；`named_min_relation: same_zone`（可选 `known_owner` / `any`）；`authority_reconfirm_max_age: unlimited`（也可写整数秒或数字字符串） |
| `liveness` | `ping_interval_secs: 30`、`pong_timeout_secs: 10`、`max_missed_pongs: 3`、`idle_probe_secs: 60`、`idle_timeout_secs: 600` |
| `limits` | `max_pending_handshakes: 256`、`handshake_requests_per_second: 16`、`handshake_request_burst: 32`、`max_pending_stream_builds_per_tunnel: 64`、`max_stream_ids_per_tunnel: 65536`、`max_datagram_bytes: 65507`、`handshake_timeout_secs: 15`、`stream_requests_per_second: 32`、`stream_request_burst: 64` |

保活和 limits 数值必须大于 0；`max_stream_ids_per_tunnel <= 1048576`，
`max_datagram_bytes <= 65507`。默认拒绝匿名、要求同 Zone，跨 Zone 方案必须按实际身份关系
配置准入，不能只靠 `on_new_tunnel_hook_point` 中的 `accept` 绕过握手策略。
QUIC / RTCP / SOCKS 的 `stream_idle_timeout`、`connect_timeout` 使用整数秒，
默认分别为 600 / 60，0 关闭；不要与 HTTP 的毫秒整数/时长字符串混淆。

### `tun`

必填字段：

- `bind`
- `hook_point`

可选字段：

- `mask?`
- `mtu?`
- `tcp_timeout?`
- `udp_timeout?`
- `stream_idle_timeout?`
- `connect_timeout?`
- `io_dump_*`

默认：

- `mask = 255.255.255.0`
- `mtu = 1500`
- `tcp_timeout = 60`
- `udp_timeout = 60`
- `stream_idle_timeout = 600`、`connect_timeout = 60`（整数秒，0 关闭；与 ipstack 的 tcp/udp timeout 分开）

运行时语义：

- `tun` 当前应按带 IP 参数的 stack 配置理解，不是普通监听 socket，也不能直接等价成二层 bridge / TAP
- `bind` 是传给 `TunStack` builder 的本地 IP 参数
- `mask` 是传给 `TunStack` builder 的掩码参数
- `mtu` 是传给 `TunStack` builder 的 MTU 参数；当前默认值为 `1500`
- `tcp_timeout`、`udp_timeout` 是当前 `tun` stack 暴露出来的超时类参数；当前默认值都为 `60`
- `hook_point` 不只是一个可挂载 DSL 的入口，而是 `tun` 流量处理路径的必需部分
- `tun` 的 TCP / UDP 连接处理会先执行 `hook_point`
- `hook_point` 需要返回当前宿主可消费的转发动作；当前应按 `forward ...` 或 `server ...` 理解
- 若 `hook_point` 没有返回可消费动作，则不会形成有效业务转发路径

使用约束：

- `bind` 与 `mask` 只定义 `tun` stack 的 IP 参数，不自动证明 underlay 联通、静态路由、IP 转发或防火墙已经满足
- 仅有 `bind` / `mask` / `mtu` 这类地址参数不足以形成可用业务路径，还必须说明 `hook_point` 的转发逻辑
- 若用户继续讨论跨机互通，必须把 underlay、静态路由、防火墙、MTU、是否需要 NAT 单列为外部前提
- 若目标是多节点或站点互联，不能把它表述成“当前应用原生内建能力”；只能写成外部组网方案，并要求补验证步骤
- app 是否访问 `tun` 地址、物理地址或代理入口，属于部署与接入设计，不属于 `tun` 字段自身语义
- 如果用户需求依赖广播、ARP、mDNS、NetBIOS 或零配置发现，不能把 `tun` 方案表述成“天然等价于原生局域网”
- 不能给出缺少 `hook_point` 的 `tun` 配置示例

回答 `tun` 使用问题时至少写出：

- 已确认字段：`bind`、`mask`、`mtu`、`tcp_timeout`、`udp_timeout`、`hook_point`
- 已确认默认值：`mask = 255.255.255.0`、`mtu = 1500`、`tcp_timeout = 60`、`udp_timeout = 60`
- `hook_point` 的转发目标是 `call-server` 还是 `forward`
- 外部前提：underlay、静态路由、防火墙、MTU、是否需要 NAT
- 接入方式：应用访问哪个地址或是否应改走代理
- 无证据部分：哪些组网效果当前不能直接承诺

推荐写法：

- 把 `tun` 和宿主机动作拆开描述：
  `cyfs-gateway` 负责 `tun` stack 配置
  宿主机负责路由、转发、防火墙和 MTU
- 把 `tun` 和 `socks` 区分描述：
  `tun` 负责 IP 级参数配置
  `socks` 适合支持代理的单个应用接入
- 把 `tun` 和 `forward` / `call-server` 区分描述：
  `tun` 解决的是 `tun` stack 的 IP 级入口配置
  `forward` / `call-server` 解决的是流量命中后交给哪个 server 或 upstream

## 8. 已支持的 server 类型

两个应用共同支持以下 9 种 server（每个对象使用 `type`，`id` 由 key 注入）：

- `http`
- `socks`
- `dns`
- `dir`
- `cyfs-dir`
- `named-inbox-cache`
- `control_server`
- `local_dns`
- `acme_response`

`web3_gateway` 额外安装 `SnGatewayModule`，支持第 10 种 `sn`；
`cyfs_gateway` 只安装 `SnClientGatewayModule`，支持 `sn-dns` ACME provider，不能配置 `type: sn`。

### `http`

字段：

- `version?`
- `h3_port?`
- `hook_point`
- `post_hook_point?`
- `trusted_upstreams?`
- `gzip`
- `gzip_types`
- `gzip_min_length`
- `gzip_comp_level`
- `gzip_http_version`
- `gzip_vary`
- `gzip_disable?`
- `gzip_request`
- `brotli`
- `brotli_types`
- `brotli_min_length`
- `brotli_comp_level`
- `dns_timeout?`
- `connect_timeout?`
- `tls_handshake_timeout?`
- `http_handshake_timeout?`
- `tunnel_open_timeout?`
- `response_timeout?`
- `request_body_idle_timeout?`

`trusted_upstreams` 默认空列表；仅当直接上游命中 IP/CIDR 且没有更强的来源恢复信息时，
才把 `X-Forwarded-For` / `X-Real-IP` 恢复为 `real_source_*`。客户端提交的头本身不是可信身份。
压缩字段均可省略，`gzip` / `brotli` 默认关闭。

超时字段说明：

- 每个字段既可写毫秒整数，也可写时长字符串（`500ms`、`5s`、`2m`）；写 `0` 表示关闭该阶段的超时。
- 默认值：`dns_timeout = 5s`、`connect_timeout = 800ms`、`tls_handshake_timeout = 5s`、`http_handshake_timeout = 5s`、`tunnel_open_timeout = 0`（沿用 `tunnel_mgr` 的 `connect_timeout`）、`response_timeout = 60s`、`request_body_idle_timeout = 60s`。
- 覆盖的阶段依次是：解析上游域名、单次 TCP 连接尝试、https 上游 TLS 握手、HTTP 客户端连接握手（直连 / TLS / tunnel）、tunnel 流打开的底层 connect 预算、等待上游响应头、请求体读取。
- 所有超时都作用在底层第三方调用（tokio socket、TLS / HTTP / QUIC 握手等）上，`tunnel_open_timeout` 也是作为本次 tunnel open 下发给底层 connect 的预算；任何超时都不会用 `timeout` 包裹网关自身接口（tunnel 打开、请求处理入口等），因此不存在"单请求总预算"配置项。
- process chain（`hook_point` / `post_hook_point` 链）的执行不设超时，因此没有对应的超时配置项。
- 请求体相关语义说明（重要）：`request_body_idle_timeout` 是**空闲**超时，只限制"相邻两次收到请求体数据之间的间隔"，请求体大小与合法上传耗时都不设总时长上限；`response_timeout` 的起算点是**请求体发送完成**（无请求体时是请求发出），因此大文件慢速上传不会被判成上游超时。若把 `request_body_idle_timeout` 设为 `0`，则退化为从请求发出起算 `response_timeout`。

### `dir`

字段：

- `version?`
- `root_path`
- `base_url?`
- `index_file?`
- `fallback_file?`
- `autoindex`
- `etag`
- `if_modified_since?`
- `cache_policy?`
- `html_cache_control?`
- `cache_control?`

默认：

- `base_url = /`、`index_file = index.html`、`autoindex = false`、`etag = true`、`if_modified_since = exact`
- `cache_policy = html-revalidate`：HTML 响应带 `Cache-Control: no-cache`，其它文件不带；`none` 表示都不带
- `html_cache_control` / `cache_control` 分别覆盖预设里 HTML / 非 HTML 文件的 `Cache-Control`

行为要点（细节见 `doc/dir_server_usage.md`）：

- 请求 path 按段百分号解码一次再校验；`..`（含 `%2e%2e`）返回 403，解码出分隔符或 NUL 的段返回 400
- 目录 URL 缺尾部 `/` 且会返回 index 或列表时，301 到 `./<name>/`（相对地址，保留 query）
- 只支持单个 `bytes` Range；多段 Range 返回完整 200；越界返回 416；HEAD 忽略 Range
- 条件请求按 RFC 9110 顺序：`If-Match` → `If-Unmodified-Since` → `If-None-Match` → `If-Modified-Since`；`If-Range` 不匹配时返回完整 200
- `dir` 自己不压缩；压缩由 `http` server 的 `gzip` / `brotli` 在响应回到客户端前完成，206/416 与带 `Cache-Control: no-transform` 的响应不压缩，压缩后 ETag 变弱、去掉 `Accept-Ranges`

### `cyfs-dir`

必填：`named_store_config_path`（NamedDataMgr store 布局配置）。

可选字段：`http_backend_links`（device DID → HTTP 基地址 map，默认空）、`signing_key_path`、
`signing_kid`、`semantic_root`、`url_prefix`（默认空）、`obj_id_in_host`（默认 false）、
`mode`（`local-link` / `in-store`）、`scan_interval_secs`（默认 60，0 关闭扫描）、`hook_point`。

它是 HTTP server 对象，可由 HTTP 路由 `call-server` 调用。hook 可设置全局变量
`RESP_cyobj_meta`（含 `obj_type` / `obj_id` / `obj_json` 及可选 `path_obj_jwt` 的 JSON 字符串）
或 `RESP_cyobj_id`（已存在于 store 的 ObjId）。没有解析结果时回退到 `semantic_root`（若配置）。
`semantic_root` 不匹配通用路径 key 规则，建议显式提供绝对路径。

### `named-inbox-cache`

必填：`target_zone`、非空 `accepted_paths` 数组、`cache_path`。

| 可选字段 | 默认值/约束 |
| --- | --- |
| `upstream` | 不设置；若配置必须是 HTTP(S) origin，不能带用户凭证、业务路径、query 或 fragment |
| `upstream_timeout` / `poll_interval` | `3s` / `5s` |
| `retry_backoff` | `[5s, 30s, 2m, 10m]`，不能为空 |
| `concurrency` | 1，必须大于 0 |
| `drain_enabled` | 未指定时按是否存在 upstream 决定；true 要求配置 upstream |
| `max_object_bytes` / `max_entries` / `max_bytes` | 65536 / 10000 / 268435456，必须大于 0 |
| `per_principal_quota` | 可选对象，必须同时提供大于 0 的 `max_entries`、`max_bytes` |
| `cache_ttl` | 可选正时长 |

这是 named object dispatch 的 HTTP 缓存接收服务，要求路由提供验证过的 dispatch context；
不是通用 HTTP 代理缓存。配置及 quota 对象拒绝未知字段，所有调度时长必须大于 0。

### `dns`

字段：

- `hook_point`

### `local_dns`

字段：

- `file_path`

### `socks`

字段：

- `username?`
- `password?`
- `target`
- `enable_tunnel?`
- `rule_config?`
- `stream_idle_timeout?`
- `connect_timeout?`
- `hook_point`

`target` 是 URL，`enable_tunnel` 是协议名字符串数组（例如 `[rtcp]`），不是布尔开关。
当前 `TunnelManager::get_tunnel()` 接收但忽略 `enable_tunnel`，实际按目标 URL scheme
选择 builder；不能承诺该列表有筛选/启用协议的效果。
`hook_point` 必填，代理决策使用 `DIRECT` / `PROXY <url>` / `REJECT` 返回值；
例如 `return "PROXY rtcp://edge.example/";`。不能把 stack 的 `forward` 动作照搬成 SOCKS 决策。
`username` / `password` 成对配置时启用用户名密码认证。

### `sn`（仅 `web3_gateway`）

字段：

- `host`
- `ip?`
- `boot_jwt?`（仅用于 SN 自身 hostname 的兼容 BOOT TXT）
- `owner_pkx?`（仅用于 SN 自身 hostname 的兼容 PKX TXT）
- `device_jwt?`（仅用于 SN 自身 hostname 的兼容 DEV TXT；缺省为空数组）
- `aliases?`
- `auth_data_dir?`
- `region_probe_config_path?`
- `seed_path?`
- `bns_server_url?`（默认空字符串）
- `bns_session_token?`
- `pkx_doh_url?`
- `relay_allocation?`
- `local_relay_node?`
- `sn_controller_kid?`
- `allowed_controller_doc_types?`
- `bns_proxy?`
- `app_did?`
- `auth_db?`
- `device_info_db?`
- `db_path?`

`region_probe_config_path` 指向 schema v1 JSON；未配置时 region probe 地址返回 404，
文件无效返回 503，不影响注册。`local_relay_node` 用于幂等注册同进程 relay。
HTTP S2S provider 场景使用 `app_did` 加载应用身份；不要从字段名推导这些可选对象的嵌套 schema。

### `control_server`

字段：

- 只有 `type`
- `id` 由 map key 注入

### `acme_response`

字段：

- 只有 `type`
- `id` 由 map key 注入

## 9. 顶层对象规则

### `timers`

规则：

- key 注入成 `id`
- `timeout` 必须大于 0
- `process-chain` 和 `process_chain` 两种写法都支持

### `limiters`

字段：

- `upper_limiter`
- `download_speed`
- `upload_speed`
- `concurrent`

规则：

- `download_speed` / `upload_speed` 使用字符串速率
- `upper_limiter` 形成依赖关系，解析时会做拓扑排序

### `collections`

当前支持：

- `memory_set`
- `json_set`
- `sqlite_set`
- `text_set`
- `memory_map`
- `json_map`
- `sqlite_map`
- `ip_region_map`

通用字段：

- `type`
- `file_path`
- `only_read_file`

类型附加数据采用 serde flatten，直接写在 collection 对象内，不包一层 `data`。
例如 `ip_region_map` 的 `ipv6_file_path`、`cache_policy`、`auto_update_interval_secs`、
`request_timeout_secs`、`ipv4_sha256`、`ipv6_sha256` 都在 `type` / `file_path` 同级。

补充：

- `json_map` 支持 `file_path: ./all_info.json#app_info`
- `ip_region_map` 解析阶段会自动注入 `cache_path`

### `device_manager`

字段：

- `enabled`
- `offline_timeout_seconds`
- `cleanup_interval_seconds`

默认：

- `enabled = false`
- `offline_timeout_seconds = 600`
- `cleanup_interval_seconds = 60`

### `identity_manager`

字段：`public_root_path?`、`security_root_path?`。公共目录别名为 `public_root` /
`public_identity_root` / `public_identity_root_path`；安全目录别名为 `security_root`。
优先用 canonical 的 `*_path` 写法，以应用通用路径归一化。

- 顶层配置会注入未显式设置 stack 级 `identity_manager` 的 TLS / QUIC 字符串 `hosts` 模式，和 RTCP `identity` 模式
- 不注入 RTCP 的兼容私钥配置；stack 级配置整体优先，不逐字段补齐
- ACME 未显式指定自己的 identity manager 时也会继承顶层值

### `name_client`

唯一字段：`zone_locker_bypass`，默认空数组，元素为字符串；接受主机名或 DID。
它用于解析访问本网关 Zone locker 所必经的节点/中继时跳过 Zone locker 查询，避免解析回环。

- 启动时在 stack 开始接流量之前应用；reload 时替换整个名单，删除 section 等价于清空
- 条目按 `DID::from_str` 验证；坏条目使启动/reload 失败，reload 验证失败时保留旧名单
- section 拒绝未知字段；这不是 RTCP 身份校验或准入的豁免名单

### `acme`

字段：

- `account?`
- `issuer?`
- `dns_providers?`
- `hosts?`（默认空数组）
- `identity_manager?`
- `check_interval?`
- `renew_before_expiry?`

`hosts` 元素：`host`（别名 `hostname` / `domain`）、`challenge_type?`（别名 `acme_type` /
`method`）、`dns_provider?`、`identity?`、`identity_manager?`，以及扁平附加数据。
当前 `AcmeConfig` 没有 `issuers` 字段，不能把它列为生效配置。

### `tls_ca`

字段：

- `cert_path`
- `key_path`

## 10. 控制面默认配置

`gateway_control_server.yaml` 会在用户配置前作为基础配置注入，默认带入：

- `stacks.__control_server__`
- `servers.__control_server__`
- `servers.acme_response`

因此：

- 用户不必显式声明 control server
- 规范里不能把它写成“必须手工配置”

## 11. 当前不要宣称为正式支持的类型

旧 `NdnServerConfig` 已移除，两个应用都没有 `ndn` registration；相关语义使用
`cyfs-dir`，不能输出 `type: ndn`。

`traffic` 没有安装 adapter，`tunnel_client_certs` 没有当前装载入口；不要把旧配置段或
反序列化时被忽略的未知字段当成已支持能力。
