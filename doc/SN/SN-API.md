# SN-Server API 现状整理

> 本文整理当前 SN-Server 对外提供的 RPC API，以及客户端侧 `src/components/cyfs-gateway-api/src/sn_client.rs` 当前实际使用的子集。用于在本次 breaking change 版本中对 SN-API 做调整前的基线参考。
>
> 代码位置:
> - 服务端 API 分发: `src/components/cyfs-sn/src/sn_server.rs`(`handle_namespaced_rpc_call`)
> - 服务端 V2 handler: `src/components/cyfs-sn/src/api/*.rs`
> - 客户端封装: `src/components/cyfs-gateway-api/src/sn_client.rs`

---

## 1. 传输与路由模型

- 协议: kRPC over HTTP(JSON-RPC 风格,`{ method, params, token, seq, trace_id }`)。
- HTTP 路径分三类(`SnRpcPath`):

  | 路径 | 枚举 | 用途 |
  |------|------|------|
  | `/kapi/sn` | `Root` | 兼容路径 / 解析类只读接口。允许所有方法(向后兼容) |
  | `/kapi/sn/auth` | `Auth` | 账号认证类方法(`auth.*`) |
  | `/kapi/sn/bns` | `Bns` | 需写入 BNS / 需登录态的账号与资源管理方法 |

- 方法名采用 **namespace.method** 形式(如 `device.register`)。同时保留一批 **裸方法名(legacy)** 作为别名,由 `canonical_method_name()` 归一化到 namespaced 形式。
- `is_method_allowed_on_path()`: `Auth`/`Bns` 路径只接受 `preferred_rpc_path()` 与其匹配的方法;`Root` 路径接受全部(并对非首选方法打 warning)。

### 1.1 方法别名(legacy → canonical)

`canonical_method_name()` 中的映射,说明历史裸方法名仍可用:

| legacy 裸名 | canonical |
|-------------|-----------|
| `check_active_code` | `auth.check_active_code` |
| `check_username` | `auth.check_username` |
| `clear_state_by_active_code` | `admin.clear_state_by_active_code` |
| `register_user` | `user.register_by_public_key` |
| `bind_zone_config` | `zone.bind_config` |
| `set_user_self_cert` | `user.set_self_cert` |
| `set_user_did_document` | `did.set_document` |
| `register` | `device.register` |
| `get` | `device.get` |
| `get_by_pk` | `device.get_by_pk` |
| `query_by_hostname` | `query.by_hostname` |
| `query_by_did` | `query.by_did` |
| `device.query_by_hostname` | `query.by_hostname` |
| `device.query_by_did` | `query.by_did` |

> 注意 `update`(裸名)被路由到 **V1** `update_device`,而 `device.update` 路由到 **V2** handler——两者不是同一实现。

---

## 2. V1 / V2 双轨现状(重点)

当前 SN-Server 对多个方法做了 **运行时按参数/Token 分流**,同一个 method 名同时支持新旧两套实现。这是历史兼容包袱,也是本次 breaking change 主要要清理的对象。分流逻辑见 `handle_namespaced_rpc_call`:

| method | 走 V1(旧)条件 | 走 V2(新)条件 |
|--------|----------------|----------------|
| `auth.check_username` | 无 `name`(用旧 `username` 字段) | 有 `name` 且无 `username` |
| `zone.bind_config` | 带 `user_name` 字段 **或** 无 V2 access token | 有 V2 token 且无 `user_name` |
| `device.register` | 带 `user_name` 字段 | 无 `user_name`(走登录态) |
| `device.get` | 带 `owner_id`/`device_id` | 否则走 V2(登录态 + `device_name`) |
| `did.set_document` | 带 `owner_user` 字段 **或** 无 V2 token | 有 V2 token 且无 `owner_user` |
| `user.set_self_cert` | 带 `name` 字段 **或** 无 V2 token | 有 V2 token 且无 `name` |
| `dns.add_record` / `dns.remove_record` | 无 V2 token | 有 V2 token |

**客户端 `sn_client.rs` 当前调用的全部是 V1 路径**(都带 `user_name`/`owner_id`/`owner_user` 等旧字段),详见 §5。

---

## 3. V2 API(`src/components/cyfs-sn/src/api/*.rs`)

V2 采用 access/refresh token 会话模型。`require_account_username()` 从 token 解析当前登录用户;`resolve_self_scoped_username()` 允许带 `name` 但必须等于登录用户(否则 `cross_user_access_denied`)。统一成功返回 `{ "code": 0, ... }`。

### 3.1 `auth.*`(路径 `/kapi/sn/auth`)— `api/auth.rs`

| method | 入参 | 返回 | 说明 |
|--------|------|------|------|
| `auth.check_username` | `name` | (V2 透传 `username`) | 用户名可用性检查 |
| `auth.check_active_code` | `active_code` | — | 激活码检查 |
| `auth.register` | `name`, `pwd_hash`, `active_code`, `request_id?`, `asset_owner?`, `owner_config?` | `access_token`, `refresh_token`, `need_bind_owner_key` | 注册;有 BNS controller 时同时 `register_name` 上链 |
| `auth.login` | `name`, `pwd_hash`, `active_code?` | `access_token`, `refresh_token`, `need_bind_owner_key` | 登录,校验密码 + 用户状态 Active |
| `auth.refresh` | `refresh_token` | `access_token` | 刷新 access token |
| `auth.logout` | `refresh_token?` (+ header token) | `code` | 吊销 access/refresh 会话 |
| `auth.me` | (token) | profile json | 当前登录用户信息 |

### 3.2 `user.*`(路径 `/kapi/sn/bns`)— `api/user.rs`

| method | 入参 | 返回 | 说明 |
|--------|------|------|------|
| `user.bind_owner_key` | `public_key`(JWK obj/str) | `code` | 绑定 owner 公钥 |
| `user.get_owner_key` | (token) | `public_key` | 获取 owner 公钥 |
| `user.set_self_cert` | `self_cert: bool`, `device_did?` | `code` | 开启自签需带已拥有的 `device_did` |
| `user.get_profile` | (token) | `name`,`owner_key_bound`,`user_domain`,`self_cert`,`sn_ips`,`zone_config` | 用户档案 |
| `user.register_by_public_key` | (V1 `register_user`) | — | 旧的公钥注册,canonical 归到此 |

### 3.3 `zone.*` — `api/zone.rs`

| method | 路径 | 入参 | 返回 | 说明 |
|--------|------|------|------|------|
| `zone.get` | Bns | (self-scoped,`name?`) | `user_name`,`boot`,`user_domain`,`self_cert` | 读取 zone 配置 |
| `zone.bind_config` | Bns | `zone_config`(JWT/JSON str), `boot_config?`, `user_domain?`, `request_id?` | `bns_receipt` | 绑定 zone;有 controller 走 `bind_zone_documents` 上链。`boot_config` 缺省时仅写 zone 文档 |
| `zone.unbind_config` | Bns | (V1) | — | 解绑(仅 V1 实现) |

### 3.4 `device.*` — `api/device.rs`

| method | 路径 | 入参 | 返回 | 说明 |
|--------|------|------|------|------|
| `device.register` | Bns | `device_name`, `device_did`, `mini_config_jwt`, `device_ip`, `device_info`, `request_id?` | `pending_bns_publish`, `bns_receipt` | 用 owner 公钥校验 mini_config_jwt,`did:dev:<x>` 必须等于 `device_did`;有 controller 走 `publish_device_mini_doc` 上链 |
| `device.update` | Bns | `device_name`, `device_did?`, `mini_config_jwt?`, `device_ip`, `device_info` | `code` | 更新设备记录 |
| `device.get` | Root | `device_name`(self-scoped) | device json | 取自己某设备 |
| `device.list` | Bns | (self-scoped) | `items[]` | 列出自己全部设备 |
| `device.get_by_pk` | Root | `public_key` (V1) | — | 按公钥查设备 |
| `query.by_did` | Root | `source_device_id` | `OODInfo` | (旧 `device.query_by_did`) |
| `query.by_hostname` | Root | `dest_host` | `OODInfo` | (旧 `device.query_by_hostname`) |

### 3.5 `query.*`(路径 `/kapi/sn`,匿名只读)— `api/query.rs`

| method | 入参 | 返回 | 说明 |
|--------|------|------|------|
| `query.resolve_did` | `did`, `doc_type?`(或 legacy `type`) | `document` | 解析 DID 文档(JsonLd 或 `{jwt}`) |
| `query.resolve_hostname` | `host` | `OODInfo` | hostname → OOD |
| `query.resolve_device` | `name`, `device_name` | device json | 按用户名+设备名解析 |

### 3.6 `dns.*` — `api/dns.rs`

| method | 入参 | 返回 | 说明 |
|--------|------|------|------|
| `dns.add_record` | `device_did`, `domain`, `record_type`, `record`, `ttl?`, `has_cert?`, `request_id?` | `device_name`, `bns_receipt` | 域名须为用户域或 `<x>.<user>.web3.<host>` 子域;TXT 有 controller 时上链 |
| `dns.remove_record` | `device_did`, `domain`, `record_type`, `record?`, `has_cert?`, `request_id?` | `bns_receipt` | 删除记录 |
| `dns.list_records` | (self-scoped) | `items[]`(domain/record_type/record/ttl) | 列出 |

### 3.7 `domain.*`(路径 `/kapi/sn/bns`)— `api/domain.rs`

| method | 别名 | 入参 | 返回 | 说明 |
|--------|------|------|------|------|
| `domain.begin_verify` | `domain.create_pkx_binding` | `domain` | `pkx`,`pkx_record_name`,`state`,... | 发起自定义域名 PKX 绑定挑战 |
| `domain.verify` | `domain.verify_pkx_binding` | `domain`, `txt_records[]`/`txt_record`/`record` | `pkx`,`verified_at` | 验证 TXT |
| `domain.unbind` | — | `domain` | `code` | 解绑 |

### 3.8 `did.*` — `api/did.rs`

| method | 路径 | 入参 | 返回 | 说明 |
|--------|------|------|------|------|
| `did.set_document` | Root(V1)/Bns(V2) | `obj_name`, `did_document`, `doc_type?`(默认 `did_doc`), `request_id?` | `obj_id`, `doc_type`, `bns_receipt` | 有 controller 走 `publish_document` 上链 |
| `did.get_document` | Root | `name?`, `obj_name`, `doc_type?` | `obj_id`, `did_document`, `doc_type` | 读取 |

### 3.9 `admin.*`

| method | 说明 |
|--------|------|
| `admin.clear_state_by_active_code` | 按激活码清理状态(测试/运维用) |

### 3.10 解析面(非 kRPC,`sn_server.rs` / `sn_resolver.rs`)

除 kRPC 外,SN 还对外提供两个 **标准解析接口**,由 `SnResolver` 统一支撑(解析来源:BNS 文档 / device mini doc / 在线设备信息 / 本地兼容缓存):

| 接口 | 形式 | 入口 | 说明 |
|------|------|------|------|
| **W3C DID Resolver** | HTTP GET,非 kRPC | `handle_http_did_resolve_request("did:xxx[?type=...]")` | 支持 `did:bns` / `did:dev` / `did:web`;返回 `application/json`(JsonLd)或 `application/jwt`,带 CORS `*`。`type` 对应 doc_type |
| **DNS NameServer** | `NameServer::query` | `SNServer::query(name, record_type, from_ip)` | A/AAAA/TXT 名字解析,带 `name_info_cache` 缓存 |

> 重要:kRPC 的 `query.resolve_did` / `query.resolve_hostname` 与上面的标准 resolver **功能重叠**——它们只是 `resolver.resolve_*` 的 kRPC 包装。最终形态应保留标准 W3C DID Resolver + DNS NameServer,废弃这些 kRPC `query.resolve_*` 方法(见 §7)。

解析来源枚举(`sn_resolver.rs`):Zone = `BnsName` / `UserDomain` / `LegacyWeb3Host`;DNS = `ExplicitRecord` / `BnsDocument` / `DeviceOnlineInfo` / `SnSelf`;DID = `BnsDocument` / `DeviceMiniDocument` / `DeviceOnlineInfo` / `LegacyLocalDidDocument`。

---

## 4. 错误码(`api/errors.rs`,前缀 `[SNV2:<code>:<name>]`)

| code | name | code | name |
|------|------|------|------|
| 1000 | invalid_params | 1013 | device_permission_denied |
| 1001 | invalid_username | 1014 | invalid_device_did |
| 1002 | username_already_exists | 1015 | invalid_domain |
| 1003 | invalid_active_code | 1016 | did_document_not_found |
| 1004 | user_auth_not_found | 1017 | hostname_not_found |
| 1005 | invalid_password | 1018 | cross_user_access_denied |
| 1006 | auth_required | 1019 | unsupported_password_algo |
| 1007 | invalid_token | 1020 | invalid_password_storage |
| 1008 | user_not_found | 1021 | invalid_did |
| 1009 | owner_key_required | 1022 | user_not_activated |
| 1010 | invalid_public_key | 1023 | bns_permission_denied |
| 1011 | invalid_zone_config | 1024 | bns_name_already_exists |
| 1012 | device_not_found | 1025 | bns_write_failed |
| | | 1099 | internal_error |

BNS 写入错误经 `bns_write_error()` 映射:`CONTROLLER_SCOPE_DENIED`/`NOT_EFFECTIVE_OWNER` → `bns_permission_denied`,`NAME_ALREADY_EXISTS` → `bns_name_already_exists`,其余 → `bns_write_failed`,payload 携带 `{bns_code, expected, actual, message}`。

---

## 5. 客户端视角 — `sn_client.rs` 当前实际使用

`SnClient` 有两种形态:`InProcess`(本进程 `SnHandler` trait)与 `KRPC`(远程)。当前仅封装 **5 个方法**,且全部命中服务端 **V1 路径**。

| 客户端函数 | 调用 method | 请求结构(字段) | 目标路径 | 命中 |
|------------|-------------|------------------|----------|------|
| `sn_bind_zone_config` | `zone.bind_config` | `SnBindZoneConfigReq` { `zone_config`, `user_name`, `user_domain?` } | `Bns` | V1(带 `user_name`) |
| `sn_update_device_info` | `device.update` | `SnUpdateDeviceInfoReq` { `owner_id`, `device_id`, `device_info: DeviceInfo` } | `Bns` | V1(带 `owner_id`) |
| `sn_get_device_info` | `device.get` | `SnGetDeviceInfoReq` { `owner_id`, `device_id` } | `Root` | V1(带 `owner_id`) |
| `sn_register_device` | `device.register` | `SnRegisterDeviceReq` { `user_name`, `device_name`, `device_did`, `device_ip`, `device_info`, `mini_config_jwt` } | `Bns` | V1(带 `user_name`) |
| `sn_set_user_did_document` | `did.set_document` | `SnSetUserDidDocumentReq` { `owner_user`, `obj_name`, `did_document`, `doc_type?` } | `Root` | V1(带 `owner_user`) |

`normalize_sn_url()` 会把 base URL 归一化到 `/kapi/sn` 或 `/kapi/sn/bns`。`SnHandler` trait 定义了与上述 5 个方法对应的 in-process 接口。

另有非 RPC 的辅助函数 `get_real_sn_host_name(sn, device_id)`:GET `https://{sn}/config?device_id=...`,读取 `host` 字段。

### 客户端缺口(相对服务端 V2)

客户端尚未封装的 V2 能力:`auth.*`(register/login/refresh/logout/me)、`user.*`(bind_owner_key/get_owner_key/get_profile/set_self_cert)、`zone.get`、`device.list`/`device.get_by_pk`、`query.*`(resolve_did/resolve_hostname/resolve_device、by_did/by_hostname)、`dns.*`、`domain.*`、`did.get_document`。

---

## 6. 本次 breaking change 可考虑的调整点

> 以下为基于现状整理出的待决议事项,供调整设计参考:

1. **收敛 V1/V2 双轨**:`zone.bind_config`/`device.register`/`device.get`/`did.set_document`/`user.set_self_cert`/`dns.*` 目前按"是否带旧字段 / 是否有 V2 token"运行时分流。breaking 版本可直接移除 V1 分支,统一走登录态 + self-scoped 模型。
2. **客户端升级到 V2**:`sn_client.rs` 当前 5 个方法全部走 V1(显式传 `user_name`/`owner_id`/`owner_user`)。需改为基于 access token 的会话模型,并去掉跨用户字段。
3. **裸方法别名清理**:`canonical_method_name()` 中的 legacy 裸名(`register`/`get`/`update`/`bind_zone_config` 等)可在本次一并废弃。
4. **`update` vs `device.update` 歧义**:裸 `update` 走 V1 `update_device`,`device.update` 走 V2,语义不一致,建议统一。
5. **路径策略**:确认是否继续保留 `Root` 路径对所有方法的兼容收口,还是强制按 `preferred_rpc_path` 分流。

---

## 7. 重构目标(最终形态)

本次 breaking change 的目标是 **重新切分路径职责,把 BNS 彻底移出 SN**。核心原则:**`/kapi/sn` 本身不挂任何 API**,只作为 SN 的命名空间根(如有需要可保留非 RPC 的 `GET /config`)。

### 7.1 目标路径布局

| 路径 | 是否属于 SN | 职责 | 承载方法 |
|------|-------------|------|----------|
| `/kapi/sn` | 是(根) | **不提供 API**。仅命名空间根 | — |
| `/kapi/sn/auth` | 是 | 账号与会话(SN 拥有用户账号) | `auth.*` |
| `/kapi/sn/deviceinfo` | 是(新增) | 设备**在线/运行态**上报与查询(relay + 在线追踪,SN 数据面核心) | `device.*`(在线态部分)、OOD 解析(原 `query.by_did/by_hostname`,relay 经 QA Server 调用,见 §7.4-3) |
| `/kapi/bns` | **否(独立组件)** | 命名与文档上链,脱离 SN 范围 | name 注册、`zone.*`、`did.*`、`domain.*`、BNS `dns_txt` 上链 |
| 内网管理面 | 是(不暴露公网) | 运维/管理,仅内网或本机可达(InternalRoot `/` 或独立管理端口/socket) | `admin.*` |

> DID/域名解析不在上表:由标准 W3C DID Resolver + DNS NameServer 承担(非 kRPC,见 §3.10)。
>
> `admin.*`(当前仅 `admin.clear_state_by_active_code`)现挂在公网 `Root` 路径,**最终形态不再暴露公网**,只在内网/管理面可达。

要点:
- **去掉 `/kapi/sn/bns`**:其上承载的"写 BNS / 文档上链"职责整体迁移到独立的 `/kapi/bns`,不再视为 SN 的一部分。
- **新增 `/kapi/sn/deviceinfo`**:把原先散落在 `Root`/`Bns` 路径上的设备信息与解析类方法收口到这里,使 SN 的数据面职责清晰、自洽。
- **`/kapi/sn` 清空**:迁移完成后该路径下不再路由任何 RPC 方法,`Root` 作为兼容收口的历史角色随之取消(配合 §6.5)。

### 7.2 方法迁移映射(现状 → 目标)

| 现 method | 现路径 | 目标 | 目标归属 |
|-----------|--------|------|----------|
| `auth.check_username` / `check_active_code` | Auth | `/kapi/sn/auth` | SN |
| `auth.register` / `login` / `refresh` / `logout` / `me` | Auth | `/kapi/sn/auth`(注册仍由 SN 统一上链,§7.3-1) | SN |
| `device.register` / `update` / `get` / `list` | Bns/Root | `/kapi/sn/deviceinfo`(改为在线/运行态语义) | SN |
| `device.get_by_pk` | Root | **去掉**(实现已移除) | — |
| `query.by_did` / `by_hostname` | Root | 保留并改名为 `deviceinfo.resolve_ood*`(relay 经 QA Server 调用,§7.4-3) | SN |
| `dns.add_record` / `remove_record` / `list_records` | Bns/Root | 并入 `user.*`,**仅服务 user_domain**(§7.3-3) | SN |
| `user.get_profile` / `set_self_cert` | Bns | `/kapi/sn/auth`(账号属性) | SN |
| `user.bind_owner_key` / `get_owner_key` | Bns | **去掉**(原协助换密钥用,本版本移除) | — |
| `query.resolve_did` / `resolve_hostname` / `resolve_device` | Root | **去掉**,改用 W3C DID Resolver + DNS NameServer(§3.10) | SN(非 kRPC) |
| `zone.get` / `bind_config` / `unbind_config` | Bns | `/kapi/bns` | BNS |
| `did.set_document` / `get_document` | Bns/Root | `/kapi/bns` | BNS |
| `domain.begin_verify` / `verify` / `unbind`(PKX 绑定) | Bns | 保留 SN,落在 `/kapi/sn/auth`(user_domain 属账号,§7.4-4) | SN |
| `user.register_by_public_key` | Bns | (并入 `/kapi/sn/auth` 或废弃) | SN |
| `admin.clear_state_by_active_code` | Root(**公网可达,需收口**) | 移出公网,仅内网/管理面(InternalRoot `/` 或独立管理端口/socket) | SN(内网) |

### 7.3 已定决策

针对原"待确认"项,已确定如下:

1. **名字注册(过渡期)**:用户的**首个名字(注册)由 SN 统一管理上链,并分配 controller 密钥**。`auth.register` 保留内嵌的 BNS `register_name` 逻辑,SN 作为 controller 代理,不要求客户端自行调用 `/kapi/bns`。
2. **owner key 去掉**:`user.bind_owner_key` / `user.get_owner_key` 本版本**移除**(原本用于协助用户更换密钥,非必需,后续如需再单独设计)。
3. **`dns.*` 折入 `user.*`,且只服务 user_domain**:`user_domain` 视为 user 的一部分,DNS 记录管理收到 `user.*` 下。**SN 的 `user.add_dns_record` / `remove` / `list` 必然且仅针对 user_domain**,沿用**旧本地逻辑**(记录存 SN 本地,由 DNS NameServer 解析)。
   - 非 user_domain 的用户(即用户名本身是 **BNS Domain**)**不走这个接口**,而是直接用 `bns-client` 更新 BNS `dns_txt` 文档(`/kapi/bns`)。
   - 因此 SN 侧不存在"域名类型分流"分支:接口入口即假定 user_domain,无需在 add_dns_record 内判定用户是否为 BNS Domain。
4. **解析面统一**:SN 已有标准 **W3C DID Resolver** + **DNS NameServer**(§3.10),覆盖 DID/域名解析,故 kRPC `query.resolve_*` 全部去掉。`zone.*` / `did.*` 迁至 `/kapi/bns` 后,SN 解析仍由 `SnResolver` 经 BNS reader 回查 + 本地兼容缓存完成,无需在 SN 侧另存 zone/did 副本。

### 7.4 复审:其他"其实应归 BNS"的点

以"身份/文档写 → BNS,运行/在线态 → SN"的原则复审全部方法,发现 `device.*` 与 zone/did/dns 属同一模式,需进一步拆分:

1. **设备身份文档(device mini doc)→ BNS(最主要)**:`device.register` 当前在有 BNS controller 时会把 `did` + `mini_config_jwt` 通过 `publish_device_mini_doc` 发布为 BNS `device_mini_doc` 文档(见 `api/device.rs`;无 controller 时才写本地 `register_device_record`)。这是一次 **BNS 文档写**,应改由 `bns-client` 承担。SN 的 `device.*` 只保留**在线/运行态**(`ip` / endpoints / 在线状态,即 `sync_device_online_state` → `device_info_db` / `SnDeviceStateView`)——这才是 SN 作为 Super Node 的核心。
   - 对应地,`device.update` 中"带 `did` + `mini_config_jwt`"的分支属身份更新(→ BNS),"仅 `ip` / `device_info`"的分支属在线态上报(→ SN deviceinfo)。
2. **`device.get` / `list` / `get_by_pk` 的身份读取 → resolver/BNS**:静态身份读取应来自 BNS / 标准 resolver;SN deviceinfo 只读在线态(IP、endpoints、relay 分配)。
3. **`query.by_did` / `query.by_hostname` → 保留 + 改名(relay 内部接口)**:二者返回 `OODInfo`(did_hostname / owner_id / self_cert / state),是 **sn_relay 经 QA Server 在 process chain 里使用的内部接口**(SN 以 `Server::QA` 注册,`QAServer::serve_question` 把 question 转 RPC 再 `handle_rpc_call`)。返回的 `state`(active/suspended/disabled/banned)等运行态是标准 resolver 给不了的、建连必需的信息,因此**保留**在 `/kapi/sn/deviceinfo`,不并入 W3C resolver。建议改名以体现"解析 OOD 连接信息":如 `deviceinfo.resolve_ood_by_hostname` / `deviceinfo.resolve_ood_by_did`(或合并为 `deviceinfo.resolve_ood`,入参兼容 hostname/did),改名时保留 QA / process-chain 的接入不变。
4. **`domain.*`(PKX 绑定)→ 维持 SN**(仅复核):产出的是 user_domain,而 user_domain 已决策为 user 的一部分(§7.3-3),故 PKX 域名验证保留在 SN 侧,与 BNS Domain 路线并行。

> 结论:最终 `/kapi/sn/deviceinfo` 的本质是**设备在线/运行态(relay + 在线追踪)**;凡是"文档/身份发布"(zone / did / device mini doc / dns_txt)一律归 `bns-client` / `/kapi/bns`。

### 7.5 客户端影响(`sn_client.rs`)

- `sn_client` → 收敛为仅对接 `/kapi/sn/auth`(会话)与 `/kapi/sn/deviceinfo`(设备**在线/运行态**),并升级到 access token 会话模型。设备身份(mini doc)发布改走 `bns-client`(§7.4-1)。
- BNS 相关(`zone.*` / `did.*` / `domain.*`)→ **复用已存在的 `components/bns-client`**(其已封装 BNS indexer RPC client 与 SN 侧写入控制器 `SnBnsController`:EVM `register_name` / `publish_document` / `apply_mutations` 等)。`sn_client.rs` 移除 `sn_set_user_did_document`、`sn_bind_zone_config` 等 BNS 封装,改由调用方直接走 `bns-client` / `/kapi/bns`。
- DID/域名解析 → 直接走标准 W3C DID Resolver / DNS,不再经 kRPC。
