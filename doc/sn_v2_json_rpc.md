# SN V2 JSON-RPC API

本文档描述 SN 新增的 v2 管理面接口。v2 保留 `/kapi/sn` 前缀，不改旧版 `/kapi/sn` JSON-RPC 行为；新能力通过 `/kapi/sn/v2/<module>` 暴露，同时兼容内部 rewrite 后的 `/v2/<module>`。

## 设计目标

- 保留旧版 `/kapi/sn` method 分发表和参数语义
- 新增 `register(name, pwd) + active(name, code)` 的账号注册和激活能力
- 新增 server-signed JWT，作为 v2 管理面的鉴权令牌
- 在 v2 下补齐 owner key、zone、device、dns、did、query 等管理能力
- 复用原有 `users`、`devices`、`user_dns_records`、`did_documents` 数据表

## 请求格式

所有 v2 接口继续使用 JSON-RPC body：

```json
{
  "method": "login",
  "params": {
    "name": "alice",
    "pwd": "12345678"
  },
  "sys": [
    1,
    "optional-jwt-token"
  ]
}
```

说明：

- path 负责模块分流
- `method` 负责模块内业务分发
- 除登录、注册、公开查询外，大多数接口都需要在 `sys[1]` 中带上 v2 access token
- v2 失败响应使用 `RPCResult::Failed(string)`，错误字符串格式固定为 `[SNV2:<code>:<name>] <message>`

## 路由布局

- `/kapi/sn/v2/auth`
- `/kapi/sn/v2/user`
- `/kapi/sn/v2/zone`
- `/kapi/sn/v2/device`
- `/kapi/sn/v2/dns`
- `/kapi/sn/v2/did`
- `/kapi/sn/v2/query`

内部如果前置代理已经去掉了 `/kapi/sn`，服务端也接受 `/v2/<module>`。

## Token 说明

- `active` 和 `login` 返回 `access_token` 与 `refresh_token`
- `access_token` 用于大多数 v2 接口，当前有效期为 1 小时
- `refresh_token` 仅用于 `auth.refresh`，当前有效期为 1 天
- token 为服务端签发，不复用旧版 user/device 自签 token

## 错误码

v2 的稳定错误码通过 `RPCResult::Failed(string)` 暴露，字符串格式为：

```text
[SNV2:1005:invalid_password] invalid password
```

建议调用方优先解析中括号内的 `code` 和 `name`，不要依赖后面的自由文本。

当前保留的错误码如下：

- `1000 invalid_params`
- `1001 invalid_username`
- `1002 username_already_exists`
- `1003 invalid_active_code`
- `1004 user_auth_not_found`
- `1005 invalid_password`
- `1006 auth_required`
- `1007 invalid_token`
- `1008 user_not_found`
- `1009 owner_key_required`
- `1010 invalid_public_key`
- `1011 invalid_zone_config`
- `1012 device_not_found`
- `1013 device_permission_denied`
- `1014 invalid_device_did`
- `1015 invalid_domain`
- `1016 did_document_not_found`
- `1017 hostname_not_found`
- `1018 cross_user_access_denied`
- `1019 unsupported_password_algo`
- `1020 invalid_password_storage`
- `1021 invalid_did`
- `1022 user_not_activated`
- `1099 internal_error`

## auth

path: `/kapi/sn/v2/auth`

- `check_username`
  - params: `{ "name": "alice" }`
  - result: `{ "code": 0, "valid": true }`
- `check_active_code`
  - params: `{ "active_code": "..." }`
  - result: `{ "code": 0, "valid": true }`
- `register`
  - params: `{ "name": "alice", "pwd": "..." }`
  - result: `{ "code": 0, "need_active": true }`
- `active`
  - params: `{ "name": "alice", "code": "..." }`
  - result: `{ "code": 0, "access_token": "...", "refresh_token": "...", "need_bind_owner_key": true }`
- `login`
  - params: `{ "name": "alice", "pwd": "..." }`
  - 前置条件：用户已完成 `active`
  - result: `{ "code": 0, "access_token": "...", "refresh_token": "..." }`
- `refresh`
  - params: `{ "refresh_token": "..." }`
  - result: `{ "code": 0, "access_token": "..." }`
- `logout`
  - params: `{}`
  - result: `{ "code": 0 }`
- `me`
  - params: `{}`
  - result: `{ "code": 0, "name": "alice", "owner_key_bound": false, ... }`

## user

path: `/kapi/sn/v2/user`

- `bind_owner_key`
  - params: `{ "public_key": <jwk-object-or-string> }`
  - 作用：把 owner 公钥写回 `users.public_key`
- `get_owner_key`
  - params: `{}`
- `set_self_cert`
  - params: `{ "self_cert": true }`
- `get_profile`
  - params: `{}`

## zone

path: `/kapi/sn/v2/zone`

- `get`
  - params: `{ "name": "optional-self-name" }`
- `bind_config`
  - params: `{ "zone_config": "<jwt>", "user_domain": "optional-domain" }`
  - 前置条件：owner key 已绑定
  - 说明：`zone_config` 仍由客户端按旧规则生成签名 JWT

## device

path: `/kapi/sn/v2/device`

- `register`
  - params:
```json
{
  "device_name": "ood1",
  "device_did": "did:dev:xxx",
  "mini_config_jwt": "xxx",
  "device_ip": "127.0.0.1",
  "device_info": "{\"id\":\"did:dev:xxx\"}"
}
```
  - 前置条件：owner key 已绑定
  - 说明：`mini_config_jwt` 仍沿用旧版 owner key 签名语义
- `update`
  - params: `{ "device_name": "ood1", "device_ip": "127.0.0.1", "device_info": "...", "device_did": "optional", "mini_config_jwt": "optional" }`
- `get`
  - params: `{ "device_name": "ood1", "name": "optional-self-name" }`
- `list`
  - params: `{ "name": "optional-self-name" }`
- `get_by_pk`
  - params: `{ "public_key": "<jwk-string>" }`
- `query_by_did`
  - params: `{ "source_device_id": "did:dev:xxx" }`
- `query_by_hostname`
  - params: `{ "dest_host": "home.alice.web3.example.com" }`

## dns

path: `/kapi/sn/v2/dns`

- `add_record`
  - params: `{ "device_did": "did:dev:xxx", "domain": "home.alice.web3.example.com", "record_type": "A", "record": "127.0.0.1", "ttl": 600, "has_cert": true }`
- `remove_record`
  - params: `{ "device_did": "did:dev:xxx", "domain": "home.alice.web3.example.com", "record_type": "A", "has_cert": false }`
- `list_records`
  - params: `{ "name": "optional-self-name" }`

## did

path: `/kapi/sn/v2/did`

- `set_document`
  - params: `{ "obj_name": "profile", "did_document": { ... }, "doc_type": "optional" }`
- `get_document`
  - params: `{ "name": "optional-self-name", "obj_name": "profile", "doc_type": "optional" }`

## query

path: `/kapi/sn/v2/query`

- `resolve_did`
  - params: `{ "did": "did:bns:alice", "type": "zone|boot|doc|info" }`
- `resolve_hostname`
  - params: `{ "host": "home.alice.web3.example.com" }`
- `resolve_device`
  - params: `{ "name": "alice", "device_name": "ood1" }`

## 与旧版的关系

- `/kapi/sn` 旧接口完全保留
- 旧 method 名、旧参数和旧鉴权语义不变
- v2 只通过新 path 进入，不污染旧 method 空间
- v2 的账号体系新增 `user_auth_v2` 存储密码哈希
- `clear_state_by_active_code` 现在会同时清理 v2 密码凭据

## 实现位置

- path 分流与旧入口兼容：`src/components/cyfs-sn/src/sn_server.rs`
- v2 分发表与 handler：`src/components/cyfs-sn/src/v2/mod.rs`
- v2 密码凭据表与 DB 扩展：`src/components/cyfs-sn/src/sn_db.rs`、`src/components/cyfs-sn/src/sqlite_db.rs`
