# SN-RPC-API

本文定义当前 `cyfs-sn` 对外暴露的 SN RPC API。本文以现有实现为准：

- 服务端路由：`src/components/cyfs-sn/src/sn_server.rs`
- RPC handler：`src/components/cyfs-sn/src/api/*.rs`
- Rust 客户端：`src/components/cyfs-gateway-api/src/sn_client.rs`

SN RPC 只负责账号会话、user_domain 相关本地记录、设备在线运行态和 OOD 连接信息查询。BNS name、zone、DID document、device mini doc、BNS DNS TXT 等文档写入不属于 SN RPC，统一由独立 BNS API / `bns-client` 承担。

## 1. 传输模型

协议为 kRPC over HTTP。请求体是 kRPC `RPCRequest`，常用字段如下：

```json
{
  "method": "auth.login",
  "params": {},
  "token": "optional access token",
  "seq": 1,
  "trace_id": "optional trace id"
}
```

成功响应里的业务 payload 是 `RPCResult::Success` 的值。除特别说明外，成功 payload 带 `"code": 0`。错误响应为 `RPCResult::Failed(string)`；SN 业务错误字符串通常带 `[SN:<code>:<name>]` 前缀。

RPC method 必须使用 `namespace.method` 形式。当前实现不再做 legacy 裸方法名归一化。

## 2. 路径与职责

| HTTP path | 公开性 | 职责 | 方法 |
|-----------|--------|------|------|
| `/kapi/sn` | 公网 | SN 命名空间根，不承载 RPC 方法 | 无 |
| `/kapi/sn/auth` | 公网 | 账号、会话、user profile、user_domain、user DNS record | `auth.*`、`user.*`、`domain.*` |
| `/kapi/sn/deviceinfo` | 公网 | 设备在线态上报、在线态查询、OOD 连接信息解析 | `device.*`、`deviceinfo.*` |
| `/` | 内网/管理面 | 运维管理 | `admin.clear_state_by_active_code` |

路径是强约束。方法发到非首选路径会返回 unknown method，例如 `auth.check_username` 不能再发到 `/kapi/sn`。

## 3. 认证规则

- `auth.check_username`、`auth.check_active_code`、`auth.register`、`auth.login`、`auth.refresh` 不需要 access token。
- `auth.logout` 可同时吊销请求里的 access token 和参数里的 refresh token。
- `auth.me`、`user.*`、`domain.*`、`device.register`、`device.update`、`device.get`、`device.list` 需要 SN access token。
- `deviceinfo.resolve_ood_by_did`、`deviceinfo.resolve_ood_by_hostname` 是匿名只读接口。
- 带用户作用域的接口只允许访问 token 所属用户；即使参数里带 `name`，也必须等于当前登录用户。

`auth.register` 和 `auth.login` 返回 access/refresh token。access token 放在 kRPC request 的 `token` 字段中。

## 4. `/kapi/sn/auth`

### 4.1 `auth.*`

| Method | Params | Result | 说明 |
|--------|--------|--------|------|
| `auth.check_username` | `name: string` | `valid`, `reason`, `message`, `normalized_name` | 检查用户名格式、保留名和是否已存在。用户名会 trim + lowercase。 |
| `auth.check_active_code` | `active_code: string` | `valid: bool` | 检查激活码是否可用。 |
| `auth.register` | `name`, `pwd_hash`, `active_code`, `request_id?`, `asset_owner?`, `owner_config?` | `code`, `access_token`, `refresh_token`, `need_bind_owner_key` | 注册 SN 用户。启用 BNS 写入时会通过 SN controller 注册同名 BNS name。 |
| `auth.login` | `name`, `pwd_hash` | `code`, `access_token`, `refresh_token`, `need_bind_owner_key` | 登录已激活用户。 |
| `auth.refresh` | `refresh_token` | `code`, `access_token` | 用 refresh token 换新 access token。 |
| `auth.logout` | `refresh_token?` | `code` | 吊销当前 access token 和/或给定 refresh token。 |
| `auth.me` | `{}` | 同 `user.get_profile` | 返回当前登录用户 profile。 |

`auth.register` 的 BNS 行为取决于 SN 配置：配置 `bns_write_enabled` / `bns_indexer_url` 且提供 `bns_evm` controller 私钥时，注册会走 EVM BNS 写路径；否则只创建 SN 本地账号。

### 4.2 `user.*`

| Method | Params | Result | 说明 |
|--------|--------|--------|------|
| `user.get_profile` | `{}` | `code`, `name`, `owner_key_bound`, `user_domain`, `self_cert`, `sn_ips`, `zone_config` | 返回当前用户 profile。 |
| `user.set_self_cert` | `self_cert: bool`, `device_did?` | `code` | 开启 `self_cert` 时必须提供属于当前用户的在线设备 DID。关闭时不需要 DID。 |
| `user.add_dns_record` | `device_did`, `domain`, `record_type`, `record`, `ttl?`, `has_cert?` | `code`, `device_name` | 只管理当前用户已绑定 `user_domain` 及其子域的本地 DNS 记录。 |
| `user.remove_dns_record` | `device_did`, `domain`, `record_type`, `has_cert?` | `code` | 删除当前用户 `user_domain` 范围内的本地 DNS 记录。 |
| `user.list_dns_records` | `{}` | `code`, `items[]` | 列出当前用户本地 DNS 记录。 |

`user.add_dns_record` / `user.remove_dns_record` 要求 `device_did` 属于当前用户。`record_type` 主要面向 `A`、`AAAA`、`TXT`；记录保存在 SN compatibility store，并由 SN DNS NameServer 解析。它不是 BNS `dns_txt` 写入接口。

`items[]` 结构：

```json
{
  "domain": "home.example.com",
  "record_type": "A",
  "record": "203.0.113.10",
  "ttl": 600
}
```

### 4.3 `domain.*`

| Method | Params | Result | 说明 |
|--------|--------|--------|------|
| `domain.begin_verify` | `domain` | `code`, `domain`, `pkx`, `pkx_record_name`, `state`, `created_at`, `updated_at` | 发起 user_domain PKX/TXT 绑定挑战。 |
| `domain.create_pkx_binding` | 同 `domain.begin_verify` | 同 `domain.begin_verify` | 兼容别名。 |
| `domain.verify` | `domain`, `txt_records[]` 或 `txt_record` 或 `record` | `code`, `domain`, `pkx`, `pkx_record_name`, `verified_at` | 校验 TXT 记录并绑定 user_domain。 |
| `domain.verify_pkx_binding` | 同 `domain.verify` | 同 `domain.verify` | 兼容别名。 |
| `domain.unbind` | `domain` | `code` | 解绑当前用户的 user_domain。 |

`domain.*` 管的是 SN 账号的 `user_domain`，不是 BNS Domain 所有权变更。

## 5. `/kapi/sn/deviceinfo`

### 5.1 `device.*`

`device.*` 现在表示设备在线/运行态，不再发布设备身份文档。

| Method | Params | Result | 说明 |
|--------|--------|--------|------|
| `device.register` | `device_name`, `device_did`, `device_ip`, `device_info`, `endpoints?`, `report_seq?`, `ttl?` | `code` + `SnDeviceStateView` | 首次或重复上报设备在线态。 |
| `device.update` | `device_name`, `device_did?`, `device_ip`, `device_info`, `endpoints?`, `report_seq?`, `ttl?` | `code` + `SnDeviceStateView` | 更新在线态。首次上报必须有 `device_did`；已有记录可省略。 |
| `device.get` | `device_name?` 或 `device_did?` | `code` + `SnDeviceStateView` | 查询当前用户某设备在线态。 |
| `device.list` | `state?`, `offset?`, `limit?` | `code`, `items[]` | 列出当前用户设备在线态。 |

`device.update` 如果携带 `mini_config_jwt` 会返回 `invalid_params`，因为设备身份文档发布已经迁移到 BNS API。

`endpoints[]` 的元素结构：

```json
{
  "endpoint_id": "rtcp-public-1",
  "protocol": "rtcp",
  "host": "203.0.113.10",
  "port": 8080,
  "scope": "public",
  "priority": 100,
  "source": "device_report",
  "expires_at": 1760000000
}
```

枚举值：

| 字段 | 可选值 |
|------|--------|
| `state` | `online`, `offline`, `stale`, `blocked` |
| `protocol` | `tcp`, `udp`, `quic`, `rtcp`, `http`, `https` |
| `scope` | `public`, `private`, `relay`, `loopback`, `unknown` |
| `source` | `device_report`, `from_ip`, `relay_observed`, `admin` |

`SnDeviceStateView` 结构：

```json
{
  "code": 0,
  "did": "did:dev:...",
  "zone": "alice",
  "device_name": "ood1",
  "device_role": "ood",
  "state": "online",
  "public_ips": ["203.0.113.10"],
  "private_ips": [],
  "active_endpoints": [],
  "preferred_endpoint": null,
  "nat_type": "unknown",
  "is_wan_device": true,
  "last_seen_at": 1760000000,
  "expires_at": 1760000300
}
```

`ttl` 默认 300 秒。`device_name == "ood1"` 会被标记为 `ood` 角色，其余默认为 `normal`。

### 5.2 `deviceinfo.*`

| Method | Params | Result | 说明 |
|--------|--------|--------|------|
| `deviceinfo.resolve_ood_by_did` | `source_device_id` | `did_hostname`, `owner_id`, `self_cert`, `state` | 按设备 DID 解析 OOD 连接信息。 |
| `deviceinfo.resolve_ood_by_hostname` | `dest_host` | `did_hostname`, `owner_id`, `self_cert`, `state` | 按 hostname 解析 OOD 连接信息。 |

`state` 是面向连接决策的状态：在线设备返回 `active`，离线/过期返回 `suspended`，被阻断返回 `banned`。该接口供 relay / QA / process-chain 获取建连所需运行态；它不是通用 DID 或域名解析接口。

## 6. 内网管理 RPC

`admin.clear_state_by_active_code` 只允许发到内网管理根路径 `/`，不允许出现在 `/kapi/sn/auth`、`/kapi/sn/deviceinfo` 或 `/kapi/sn`。

| Method | Params | Result | 说明 |
|--------|--------|--------|------|
| `admin.clear_state_by_active_code` | `{}` | `code`, `deleted_users`, `deleted_devices`, `deleted_domain_records`, `deleted_did_documents`, `activation_code_reset` | 清理内置激活码关联的测试/运维状态。请求参数中不允许带 `active_code`。 |

## 7. 非 RPC 解析接口

SN 仍然提供两个标准解析面，但它们不是 SN RPC：

| 接口 | 形式 | 说明 |
|------|------|------|
| W3C DID Resolver | `GET /1.0/identifiers/{did}?type={doc_type}` | 支持 `did:bns`、`did:dev`、`did:web`，返回 `application/json` 或 `application/jwt`。 |
| DNS NameServer | DNS `A` / `AAAA` / `TXT` 查询 | 解析 SN 自身、user_domain、本地 DNS 记录、BNS 文档和设备在线态。 |

需要解析 DID 或域名时优先使用这两个标准接口，不再通过 kRPC `query.resolve_*`。

## 8. 错误码

| Code | Name |
|------|------|
| 1000 | `invalid_params` |
| 1001 | `invalid_username` |
| 1002 | `username_already_exists` |
| 1003 | `invalid_active_code` |
| 1004 | `user_auth_not_found` |
| 1005 | `invalid_password` |
| 1006 | `auth_required` |
| 1007 | `invalid_token` |
| 1008 | `user_not_found` |
| 1012 | `device_not_found` |
| 1013 | `device_permission_denied` |
| 1014 | `invalid_device_did` |
| 1015 | `invalid_domain` |
| 1017 | `hostname_not_found` |
| 1018 | `cross_user_access_denied` |
| 1019 | `unsupported_password_algo` |
| 1020 | `invalid_password_storage` |
| 1022 | `user_not_activated` |
| 1023 | `bns_permission_denied` |
| 1024 | `bns_name_already_exists` |
| 1025 | `bns_write_failed` |
| 1099 | `internal_error` |

BNS 写入错误只会从 `auth.register` 的 SN 代注册路径冒出。`CONTROLLER_SCOPE_DENIED` / `NOT_EFFECTIVE_OWNER` 映射为 `bns_permission_denied`，`NAME_ALREADY_EXISTS` 映射为 `bns_name_already_exists`，其他 BNS 写入错误映射为 `bns_write_failed`。

## 9. 从旧 SN API 迁移

| 旧接口/路径 | 新用法 |
|-------------|--------|
| `/kapi/sn` 上调用任意 RPC | 按方法改发 `/kapi/sn/auth` 或 `/kapi/sn/deviceinfo`；`/kapi/sn` 不再承载 RPC。 |
| `/kapi/sn/bns` | 不再属于 SN。BNS 文档、zone、DID、device mini doc、BNS DNS TXT 写入改用 `/kapi/bns` 或 `bns-client`。 |
| 裸方法名，如 `register`、`get`、`bind_zone_config` | 改为 namespaced method，例如 `auth.register`、`device.get`。 |
| `zone.bind_config`、`zone.get` | 改用 BNS API；SN 解析侧会通过 BNS reader 和标准 resolver 读取结果。 |
| `did.set_document`、`did.get_document` | 写/读文档改用 BNS API；解析 DID 用 `GET /1.0/identifiers/{did}`。 |
| `device.register` 发布 `mini_config_jwt` | 设备身份文档改用 BNS API；SN 的 `device.register/update` 只上报在线态。 |
| `dns.add_record` / `dns.remove_record` | user_domain 本地记录改为 `user.add_dns_record` / `user.remove_dns_record`；BNS Domain 的 TXT/记录改用 BNS API。 |
| `query.resolve_did` / `query.resolve_hostname` / `query.resolve_device` | DID 和域名解析改用 W3C DID Resolver / DNS NameServer；OOD 建连信息改用 `deviceinfo.resolve_ood_by_*`。 |
| `user.bind_owner_key` / `user.get_owner_key` | 已移除。owner/controller 权限管理走 BNS 侧流程。 |

`cyfs-gateway-api::SnClient` 已按新路径封装 auth 与 deviceinfo 两个 target；传入旧 `/kapi/sn` 或 `/kapi/sn/bns` 后缀的 base URL 时，会自动归一化到新路径。
