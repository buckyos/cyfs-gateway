# cyfs_gateway中process chain执行环境变量说明

cyfs_gateway中各个process chain执行位置都可以通过环境变量获取到当前请求的相关数据，以下为各个process chain能获取到的环境变量说明

## HTTP Request 环境变量

| 变量 | 类型 | 说明 |
| --- | --- | --- |
| `REQ_host` | `Visitor(String, read-only)` | HTTP `host` 头 |
| `REQ_method` | `Visitor(String, read-only)` | HTTP method，映射到 `REQ.method` |
| `REQ_content_length` | `Visitor(String, read-only)` | HTTP `content-length` 头 |
| `REQ_content_type` | `Visitor(String, read-only)` | HTTP `content-type` 头 |
| `REQ_user_agent` | `Visitor(String, read-only)` | HTTP `user-agent` 头 |
| `REQ_url` | `Visitor(String, read/write)` | 完整 URI 字符串，设置会更新请求 URI |
| `REQ_remote_ip` | `String` | 当前请求源地址 IP（来自 `StreamInfo.src_addr`） |
| `REQ_remote_port` | `String` | 当前请求源地址端口（来自 `StreamInfo.src_addr`） |
| `REQ_conn_remote_ip` | `String` | 连接层源地址 IP（来自 `StreamInfo.conn_src_addr`） |
| `REQ_conn_remote_port` | `String` | 连接层源地址端口（来自 `StreamInfo.conn_src_addr`） |
| `REQ_real_remote_ip` | `String` | 真实源地址 IP（来自 `StreamInfo.real_src_addr`） |
| `REQ_real_remote_port` | `String` | 真实源地址端口（来自 `StreamInfo.real_src_addr`） |
| `REQ_target_ip` | `String` | 当前请求目标地址 IP（来自 `StreamInfo.dst_addr`，可选） |
| `REQ_target_port` | `String` | 当前请求目标地址端口（来自 `StreamInfo.dst_addr`，可选） |
| `REQ_source_mac` | `String` | 源设备 MAC（可选） |
| `REQ_source_hostname` | `String` | 源设备主机名（可选） |
| `REQ_source_online_secs` | `String` | 源设备当日在线秒数（可选） |
| `REQ` | `Map` | HTTP 请求 Map（见下表） |

`REQ` Map 字段（值均为 `CollectionValue::String`）：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `path` | `String` | URI path |
| `method` | `String` | HTTP method |
| `uri` | `String` | 完整 URI |
| `version` | `String` | HTTP version（如 `HTTP/1.1`） |
| `<header-name>` | `String` | 任意请求头名称，对应头值 |

备注：非 UTF-8 的 header 值会被转换为空字符串。

## Tcp Stack、TlsStack、TunStack Tcp环境变量

| 变量 | 类型 | 说明 |
| --- | --- | --- |
| `REQ` | `Map` | 请求 Map（见下表） |

`REQ` Map 字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `dest_port` | `String` | 目标端口（u16 字符串化） |
| `dest_host` | `String` | 目标主机名（可选） |
| `dest_addr` | `String` | 目标 SocketAddr（可选） |
| `dest_ip` | `String` | 目标 IP（由 `dest_addr` 派生，可选） |
| `app_protocol` | `String` | 应用层协议标识（可选） |
| `dest_url` | `String` | 目标 URL（可选） |
| `source_addr` | `String` | 源 SocketAddr（可选） |
| `source_ip` | `String` | 源 IP（由 `source_addr` 派生，可选） |
| `source_port` | `String` | 源端口（由 `source_addr` 派生，可选） |
| `source_mac` | `String` | 源 MAC（可选） |
| `source_hostname` | `String` | 源主机名（可选） |
| `source_online_secs` | `String` | 源设备当日在线秒数（可选） |
| `source_device_id` | `String` | 源设备 ID（可选） |
| `source_app_id` | `String` | 源应用 ID（可选） |
| `source_user_id` | `String` | 源用户 ID（可选） |
| `ext` | `Map` | 扩展 Map（可选） |
| `incoming_stream` | `Any` | `Arc<Mutex<Option<Box<dyn AsyncStream>>>>` handle |

### Socks Server环境变量

| 变量  | 类型  | 说明               |
| ----- | ----- | ------------------ |
| `REQ` | `Map` | 请求 Map（见下表） |

`REQ` Map 字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `inbound` | `String` | 入站地址字符串（来自 `StreamInfo.src_addr`，缺失时为空字符串） |
| `target` | `Map` | 目标地址 Map（见下表） |
| `source_ip` | `String` | 从 `inbound` 解析出的源 IP（不可解析或缺失时为空字符串） |
| `source_port` | `String` | 从 `inbound` 解析出的源端口（不可解析或缺失时为空字符串） |

`REQ.target` Map 字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `type` | `String` | 目标地址类型：`ip` 或 `domain` |
| `addr` | `String` | 目标地址字符串；`type=ip` 时为 SocketAddr，`type=domain` 时为 `host:port` |
| `port` | `String` | 目标端口 |
| `ip` | `String` | 目标 IP（仅 `type=ip` 时存在） |
| `host` | `String` | 目标主机名（仅 `type=domain` 时存在） |

备注：Socks 请求环境变量为只读，不支持在 process chain 中写入或删除。

### DNS  Server环境变量

| 变量  | 类型  | 说明               |
| ----- | ----- | ------------------ |
| `REQ` | `Map` | 请求 Map（见下表） |

`REQ` Map 字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `name` | `String` | 查询的域名 |
| `record_type` | `String` | DNS 记录类型 |
| `source_addr` | `String` | 客户端 IP |
| `source_port` | `String` | 客户端端口 |
| `dest_addr` | `String` | 目标 SocketAddr（可选） |
| `dest_ip` | `String` | 目标 IP（可选） |
| `dest_port` | `String` | 目标端口（可选） |

### TUN  Stack Udp 环境变量：

| 变量  | 类型 | 说明               |
| ----- | ---- | ------------------ |
| `REQ` | Map  | 请求 Map（见下表） |

`REQ` Map 字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `dest_addr` | `String` | 目标 SocketAddr |
| `dest_ip` | `String` | 目标 IP |
| `dest_port` | `String` | 目标端口 |
| `source_addr` | `String` | 源 SocketAddr |
| `source_ip` | `String` | 源 IP |
| `source_port` | `String` | 源端口 |
| `app_protocol` | `String` | 应用层协议（固定为 `udp`） |

### QUIC  Stack环境变量：

| 变量  | 类型  | 说明               |
| ----- | ----- | ------------------ |
| `REQ` | `Map` | 请求 Map（见下表） |

`REQ` Map 字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `dest_host` | `String` | QUIC 握手 SNI server_name |
| `dest_addr` | `String` | 目标 SocketAddr |
| `dest_ip` | `String` | 目标 IP |
| `dest_port` | `String` | 目标端口 |
| `source_addr` | `String` | 客户端 SocketAddr |
| `source_ip` | `String` | 客户端 IP |
| `source_port` | `String` | 客户端端口 |
| `source_mac` | `String` | 源 MAC（可选） |
| `source_hostname` | `String` | 源主机名（可选） |
| `source_online_secs` | `String` | 源设备当日在线秒数（可选） |

### RTCP  Stack TCP环境变量：

| 变量  | 类型  | 说明               |
| ----- | ----- | ------------------ |
| `REQ` | `Map` | 请求 Map（见下表） |

`REQ` Map 字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `dest_port` | `String` | 目标端口 |
| `dest_host` | `String` | 目标主机名（可能为空） |
| `dest_addr` | `String` | 目标 SocketAddr |
| `dest_ip` | `String` | 目标 IP |
| `protocol` | `String` | 传输协议（固定为 `tcp`） |
| `path` | `String` | 路径信息（可能为空） |
| `source_addr` | `String` | 源 SocketAddr |
| `source_ip` | `String` | 源 IP |
| `source_port` | `String` | 源端口 |
| `source_mac` | `String` | 源 MAC（可选） |
| `source_hostname` | `String` | 源主机名（可选） |
| `source_online_secs` | `String` | 源设备当日在线秒数（可选） |

### RTCP  Stack UDP环境变量：

| 变量  | 类型  | 说明               |
| ----- | ----- | ------------------ |
| `REQ` | `Map` | 请求 Map（见下表） |

`REQ` Map 字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `dest_port` | `String` | 目标端口 |
| `dest_host` | `String` | 目标主机名（可能为空） |
| `dest_addr` | `String` | 目标 SocketAddr |
| `dest_ip` | `String` | 目标 IP |
| `protocol` | `String` | 传输协议（固定为 `udp`） |
| `path` | `String` | 路径信息（可能为空） |
| `source_addr` | `String` | 源 SocketAddr |
| `source_ip` | `String` | 源 IP |
| `source_port` | `String` | 源端口 |
| `source_mac` | `String` | 源 MAC（可选） |
| `source_hostname` | `String` | 源主机名（可选） |
| `source_online_secs` | `String` | 源设备当日在线秒数（可选） |
