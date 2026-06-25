# SN-Resolver

`sn_resolver` 是 SN 内部的统一解析工具库。它负责把 hostname、DID、BNS name、zone、device_name 等输入解析成 DNS、DID document、gateway device、relay、证书状态等调用方需要的结果。

当本文和当前 `cyfs-sn` 实现冲突时，以 `doc/SN/新SN核心流程整理.md` 的设计意图为准；当前实现只作为兼容行为、字段来源和迁移状态的参考。

## 目标

- 为 DNS server、HTTP relay、RTCP relay、node_daemon 查询、DID HTTP resolver 和 JSON-RPC query 接口提供同一套解析逻辑。
- 明确 BNS 权威文档、SN 本地账号状态、设备在线状态和 relay 分配之间的查询优先级。
- 消除旧实现中散落在 `SNServer` 上的解析逻辑，避免 DNS、HTTP relay、DID resolver 得到不一致结果。
- 把解析结果定义为合成数据，不额外引入新的权威存储。
- 兼容现有 `cyfs-sn` 的 `/kapi/sn`、`/kapi/sn/bns`、DNS `NameServer` 和 DID resolver 行为，给迁移留下明确边界。

## 非目标

- 不负责注册、绑定、写 BNS document 或写本地 DB。
- 不签发或校验登录 token，不替代 `sn_authority`。
- 不决定 BNS owner/controller 权限。
- 不维护设备在线心跳，不替代 `sn_device_info`。
- 不维护 zone 到 relay 的分配，不替代 `sn_relay_manager`。
- 不执行 ACME 签发流程，只读取 DNS TXT 和 `self_cert` 状态。

## 权限边界

`sn_resolver` 是只读模块。它可以被公开查询入口调用，因此不能把“能解析到数据”解释为“调用方有权访问后端服务”。

- DNS A/AAAA/TXT 查询默认公开。
- DID document 查询默认公开，但只能返回可公开的 document 或公开设备信息。
- HTTP relay 和 RTCP relay 可以使用 resolver 找到目标 zone/device/relay，但准入判断必须交给 `sn_relay_manager` 和对应 relay 策略。
- node_daemon 查询自己的 `zone_info` 时，身份校验应由 API handler 或 `sn_authority` 完成，resolver 只读取并合成结果。
- 涉及 BNS 修改的请求必须走 `sn_bns_controller`，不能通过 resolver 旁路写入。

## 数据来源

### BNS 权威状态

来自 `bns-indexer`：

- name owner / owner_config。
- authority key 和 controller policy。
- `zone` document。
- `boot` document。
- `device_mini_doc` document。
- `dns_txt` document。
- document version、name seq、更新时间等元数据。

BNS document 是名字、zone 拓扑、gateway device 声明、设备基础身份和 DNS TXT 的权威来源。

### SN 本地状态

来自 `sn_auth`：

- `sn_user <-> user_domain` 绑定关系。
- `zone_info` 运行态缓存，例如 `self_cert`、当前 relay 分配结果、兼容旧实现的 `sn_ips`。
- 本地 user DNS records 的兼容数据。

来自 `sn_device_info`：

- device 当前在线状态。
- device 上报 IP、from_ip、NAT/公网判断、最近更新时间。
- device 描述中可导出的 `ip`、`ips`、`all_ip`。

来自 `sn_relay_manager`：

- zone 当前分配的 relay SN。
- relay 节点健康状态。
- 手工调整和迁移状态。

## 输入归一化

所有入口在进入查询流程前应做统一归一化：

- hostname 去掉末尾 `.`，转小写。
- record type 规范为 `A`、`AAAA`、`TXT`。第一阶段只支持这三类；其它类型返回不支持或继续交给上游递归 resolver。
- BNS name / username 按 `buckyos-kit::is_valid_name` 和注册规则校验。
- DID 使用 `name_lib::DID::from_str` 解析，只接受明确支持的 method。
- device_name 保持大小写敏感还是小写，必须与 BNS `device_mini_doc` 的声明一致；解析层不应自行猜测。

旧实现只去掉 DNS 末尾 `.`，cache key 中会转小写；新实现应把归一化提前到 resolver 入口，避免 cache、DNS、HTTP、DID 行为不一致。

## 核心输出类型

### ZoneResolution

用于描述一个 hostname / DID / name 最终归属的 zone：

```text
ZoneResolution {
  input: String,
  canonical_name: String,
  zone_name: String,
  owner: BnsOwner,
  zone_doc: ZoneDocument,
  boot_doc: BootDocument,
  user_domain: Option<String>,
  self_cert: bool,
  relay_sn: Option<String>,
  source: BnsName | UserDomain | LegacyWeb3Host,
}
```

`self_cert` 来自 `sn_auth.zone_info` 的运行态；不能把它写入 BNS 权威 document 后再由 resolver 反向推断。

### GatewayResolution

用于 HTTP relay、DNS A/AAAA 和 node_daemon 查询 gateway：

```text
GatewayResolution {
  zone_name: String,
  hostname: String,
  gateway_device_name: String,
  gateway_did: String,
  device_doc: DeviceMiniDocument,
  online: Option<DeviceOnlineInfo>,
  addresses: Vec<IpAddr>,
  relay_sn: Option<String>,
  self_cert: bool,
}
```

`gateway_device_name` 必须来自 BNS `zone` 或 `boot` 文档。旧实现中写死 `ood1` 只是兼容行为，不能作为新设计依赖。

### DnsResolution

用于 DNS server：

```text
DnsResolution {
  hostname: String,
  record_type: A | AAAA | TXT,
  ttl: u32,
  addresses: Vec<IpAddr>,
  txt: Vec<String>,
  source: ExplicitRecord | BnsDocument | DeviceOnlineInfo | SnSelf,
}
```

同一 hostname 的 TXT 可以来自多个 document 合并；A/AAAA 则按优先级选择并去重。

### DidResolution

用于 DID HTTP resolver 和 `query.resolve_did`：

```text
DidResolution {
  did: String,
  doc_type: String,
  document: Json | Jwt,
  source: BnsDocument | DeviceMiniDocument | DeviceOnlineInfo | LegacyLocalDidDocument,
}
```

## Hostname 分类

resolver 应按以下顺序识别 hostname：

1. SN 自身 hostname：`sn.<server_host>`、`<server_host>`、配置的 aliases。
2. BNS 域名或 BNS 兼容域名。
3. `user_domain` 或其子域名。
4. 普通公网域名。

### SN 自身 hostname

用于引导和兼容旧 DNS 行为：

- `A/AAAA`: 返回当前 SN server IP，按 record type 过滤 IPv4/IPv6。
- `TXT`: 返回当前 SN 的 `PKX`、`BOOT`、可选 `DEV`。

当前实现位于 `src/components/cyfs-sn/src/sn_server.rs` 的 `query_name_info_uncached` 和 `create_name_info_from_zone_config`。

### BNS 兼容域名

旧实现支持 `*.web3.<server_host>`：

- `alice.web3.buckyos.ai` 映射到 username `alice`。
- `home.alice.web3.buckyos.ai` 映射到 username `alice`，`sub_host=home.alice`。
- `www-alice.web3.buckyos.ai` 映射到 username `alice`，这是兼容旧 URL 的规则。

新 resolver 可以保留该解析器作为 legacy adapter，但权威查询应转成 BNS name：

```text
alice.web3.<server_host> -> did:bns:alice / BNS name alice
home.alice.web3.<server_host> -> zone alice, service/subhost home
```

`sub_host` 不决定 BNS owner，只作为 HTTP relay 的目标 host 上下文传递。最终 gateway device 仍由 zone/boot 文档决定。

### user_domain

`user_domain` 是传统 DNS 域名到 SN 用户或 BNS name 的绑定关系，第一阶段仍存放在 `sn_auth`。

解析规则：

- 精确命中 `user_domain` 时，映射到对应 `sn_user` / BNS name。
- 命中 `user_domain` 的子域名时，保留相对子域名作为 service/subhost。
- 如果存在显式本地 DNS record，优先返回该 record。
- 如果没有显式 A/AAAA，则解析该 zone 的 gateway device 并返回当前可达地址。
- 如果没有显式 TXT，则合并 BNS `zone`、`boot`、`dns_txt` 生成 TXT。

当前实现对 `*.web3.<server_host>` 会优先查本地 `user_dns_records`；对普通 `user_domain` 只做精确 `get_user_info_by_domain`，没有完整处理显式子域名 record。新 resolver 需要补齐该差异。

### 普通公网域名

resolver 不应把普通公网域名误判为 SN 管理域名。普通域名应返回 `NotManaged`，由外层 DNS 递归或 HTTP 代理策略继续处理。

## DNS 解析

所有 SN 管理域名的 DNS 查询必须先进入 `sn_resolver`。

### TXT 查询

BNS 域名：

1. 读取 BNS `zone` document。
2. 读取 BNS `boot` document。
3. 读取 BNS `dns_txt` document。
4. 合并为多条 TXT。

兼容旧格式时可以继续输出：

- `PKX=<owner public key x>;`
- `BOOT=<boot jwt>;`
- `DEV=<device mini config jwt>;`

但新接口内部应使用结构化 document，不应只依赖 TXT 字符串再反解析。

非 BNS `user_domain`：

1. 根据 `sn_auth.user_domain` 找到 BNS name。
2. 如果该 hostname 有显式 TXT record，先返回显式 record。
3. 否则合并该用户的 BNS `zone`、`boot`、`dns_txt`。
4. 必要时叠加 user_domain proof 或兼容 TXT。

ACME `_acme-challenge` 属于 `dns_txt` document 的典型使用场景。写入应由 `sn_bns_controller` 使用 SN controller key 完成，resolver 只读取。

### A/AAAA 查询

BNS 域名：

1. 如果 BNS `zone` document 明确声明 `gateway_ips`，优先返回这些 IP。
2. 否则从 `zone` 或 `boot` document 得到 gateway device name。
3. 读取对应 `device_mini_doc`，确认 device DID 和 zone/device_name。
4. 查询 `sn_device_info` 获得在线态和当前可达地址。
5. 按 record type 过滤 IPv4/IPv6，去重后返回。

非 BNS `user_domain`：

1. 如果本地兼容 DNS record 中有显式 A/AAAA，直接返回该 record。
2. 否则映射到 BNS name，走 BNS 域名的 gateway device 查询流程。

地址选择规则：

- 不返回 loopback 地址。
- 不返回 Docker bridge 常见地址段 `172.16.0.0/12`。
- IPv4 只进入 A，IPv6 只进入 AAAA。
- 同一个 IP 去重。
- 如果设备不是 WAN device，可以追加当前分配的 relay/sn IP 作为入口地址。
- `sn_device_info` 的上报地址只表示在线态和可达性，不决定 gateway device 的权威身份。

旧实现的 `get_user_zonegate_address` 会查询 `ood1`，对非 WAN device 追加 `sn_ips` 或当前 SN server IP，再追加 device IP 和 `all_ip`。新实现应保留地址过滤和去重逻辑，但把 `ood1` 替换为 BNS `zone/boot` 声明的 gateway device。

## Hostname 到 Gateway 解析

HTTP relay 需要从请求 hostname 找到目标 gateway：

```text
resolve_gateway_by_hostname(hostname) -> GatewayResolution
```

流程：

1. 归一化 hostname。
2. 识别 BNS name、legacy `*.web3.<server_host>` 或 `user_domain`。
3. 解析 zone。
4. 从 BNS `zone` / `boot` 获取 gateway device name。
5. 读取 gateway device 的 `device_mini_doc`。
6. 查询 `sn_device_info` 的在线态。
7. 查询 `sn_relay_manager` 得到当前 relay SN。
8. 返回 `GatewayResolution`。

调用方使用方式：

- HTTP relay 使用 `zone_name` 和 `gateway_did` 找本地 RTCP tunnel 或转发到正确 relay。
- DNS server 使用 `addresses` 构造 A/AAAA。
- node_daemon 使用 `relay_sn` 判断是否需要重新 keep tunnel。
- 入口协议转发使用 `self_cert` 决定默认转发 80 还是 443。

当前 `query_device_by_hostname_v2` 返回 `OODInfo { did_hostname, owner_id, self_cert, state }`，并硬编码 `ood1`。新接口应保留兼容输出，但内部应从 `GatewayResolution` 投影得到。

## DID 解析

### 支持的 DID

第一阶段支持：

- `did:bns:<username>`
- `did:bns:<device_name>.<username>`
- `did:bns:<device_name>.<user_domain>`
- `did:web:<user_domain>`
- `did:web:<device_name>.<user_domain>`
- `did:dev:<device public key/id>`

其它 method 返回 `UnsupportedDidMethod`。

### did:bns:<username>

默认 `doc_type=zone`。

- `zone`: 返回 BNS `zone` document，兼容期可包含 `public_key`、`boot`、`self_cert`、`user_domain`、`sn_ips`。
- `boot`: 返回 BNS `boot` document。
- 其它 `doc_type`: 解释为 device_name 或普通 document type。优先查询 BNS document；兼容期可查询本地 `user_did_documents`。

旧实现对 `did:bns:<username>` 的 `zone` 会由 `SNUserInfo` 合成 `zone_config` JSON，对 `boot` 返回本地 `zone_config` 字段。新实现应改为 BNS document 读取，本地字段只作为迁移 fallback。

### did:bns:<device_name>.<owner>

如果 `<owner>` 不含 `.`，按 BNS username 处理；如果包含 `.`，先按 `user_domain` 映射到 username。

默认 `doc_type=doc`：

- `doc`: 返回 device 的 `device_mini_doc` / DeviceConfig。
- `info`: 返回设备在线信息的公开投影。
- 其它 `doc_type`: 查询对应 BNS document 或兼容本地 DID document。

旧实现会先查 `devices` 表，如果不是设备，再查 `user_did_documents`。新实现应把 BNS document 放在前面，设备在线信息只来自 `sn_device_info`。

### did:web

`did:web:<domain>` 先映射到 `user_domain`：

- 精确匹配 user_domain -> `did:bns:<username>`。
- `<device_name>.<user_domain>` -> `did:bns:<device_name>.<username>`。

如果找不到绑定，返回 `NotFound`，不递归公网 DID resolver。

### did:dev

`did:dev:<id>` 根据 DID 查询 `sn_device_info` / device index：

- `doc`: 返回对应 device 的 `device_mini_doc` / DeviceConfig。
- `info`: 返回公开在线信息。

如果 device 未注册或已过期，返回 `DeviceNotFound`。是否允许返回过期设备的静态 `device_mini_doc` 需要由 BNS document policy 决定，不应从在线态隐式推断。

## Relay 查询

resolver 不维护 relay 分配，但需要提供读取入口：

```text
resolve_relay_for_zone(zone_name) -> RelayResolution
```

输出：

```text
RelayResolution {
  zone_name: String,
  relay_sn: String,
  relay_state: Healthy | Draining | Offline | Unknown,
  migration_hint: Option<RelayMigrationHint>,
}
```

使用场景：

- node_daemon 周期性查询 zone_info，发现 relay 变化后重新 keep tunnel。
- relay 节点收到 keep_tunnel 时，查询 zone 是否归属当前 relay。
- HTTP relay 发现目标 zone 不属于当前节点时，返回重定向信息或转发到正确 relay。

准入策略不在 resolver 中实现。resolver 只返回当前分配和健康信息。

## 缓存

当前实现有 `NameInfoCache`：

- key 为 normalized name + record type。
- 支持命中缓存和 tombstone。
- 默认 TTL 60 秒。
- 最小 TTL 60 秒。

新 resolver 应保留缓存能力，但缓存对象应按解析层级拆分：

- BNS document cache：按 name + doc_type + version 缓存，version 变化立即失效。
- DNS result cache：按 hostname + record_type 缓存，TTL 取 document TTL、显式 DNS record TTL 和默认值的最小安全值。
- Device online cache：短 TTL，不能长时间缓存离线/地址变化。
- Tombstone cache：只缓存明确不存在的 name/domain/device，TTL 要短于正向结果。

缓存失效触发：

- BNS document version/name seq 更新。
- `sn_device_info.update_ood_info` 更新设备在线态。
- `sn_auth` 修改 user_domain、self_cert、zone_info。
- `sn_relay_manager` 修改 zone -> relay。
- DNS record / dns_txt document 更新。

公开 DNS 查询可以使用缓存；HTTP relay 和 keep_tunnel 准入查询应允许绕过或使用更短 TTL，避免 relay 迁移时继续使用旧结果。

## 错误语义

建议使用结构化错误，API handler 再映射到现有错误码或 HTTP 状态：

- `NotManaged`: 普通公网域名，不属于 SN。
- `NameNotFound`: BNS name 或 user_domain 不存在。
- `DocumentNotFound`: 指定 doc_type 不存在。
- `DeviceNotFound`: gateway/device 不存在。
- `DeviceOffline`: device 存在但没有可用在线地址。
- `UnsupportedRecordType`: 不支持的 DNS record type。
- `UnsupportedDidMethod`: 不支持的 DID method。
- `InvalidHostname`: hostname 格式非法。
- `InvalidDid`: DID 格式非法。
- `BackendUnavailable`: BNS、DB 或 device_info 查询失败。

旧 `NameServer::query` 对 tombstone 会返回 `ServerErrorCode::NotFound`。新实现应保留外部兼容，但内部不要把“普通公网域名”和“管理域名不存在”混成同一种状态。

## API 投影

resolver 是内部库，外部接口只消费其结果。

### DNS NameServer

```text
query(name, record_type, from_ip) -> NameInfo
```

投影规则：

- `DnsResolution.addresses` -> `NameInfo.address`。
- `DnsResolution.txt` -> `NameInfo.txt`。
- `DnsResolution.ttl` -> `NameInfo.ttl`。

### JSON-RPC query

现有兼容接口：

- `query.resolve_did`
- `query.resolve_hostname`
- `query.resolve_device`
- legacy `query.by_hostname`
- legacy `query.by_did`

建议内部实现：

- `query.resolve_did` 调用 `resolve_did`。
- `query.resolve_hostname` 调用 `resolve_gateway_by_hostname`，再投影成 `OODInfo`。
- `query.resolve_device` 调用 `resolve_device(zone/name, device_name)`。

### DID HTTP Resolver

现有路径：

```text
GET /1.0/identifiers/<did>?type=<doc_type>
```

内部调用 `resolve_did`，根据 `DidResolution.document` 输出 `application/json` 或 `application/jwt`。

### HTTP Relay

HTTP relay 不应直接查 DB。它应调用：

```text
resolve_gateway_by_hostname(host)
resolve_relay_for_zone(zone)
```

然后交给 relay/tunnel 层执行准入和转发。

## 与现有 cyfs-sn 实现的对应关系

当前已实现能力：

- `src/components/cyfs-sn/src/sn_server.rs`
  - `NameServer::query`
  - `query_name_info_uncached`
  - `query_did_v2`
  - `query_device_by_hostname_v2`
  - `get_user_subhost_from_host`
  - `get_user_zonegate_address`
  - `NameInfoCache`
- `src/components/cyfs-sn/src/v2/query.rs`
  - `resolve_did`
  - `resolve_hostname`
  - `resolve_device`
- `src/components/cyfs-sn/src/v2/device.rs`
  - `query_by_hostname`
  - `query_by_did`
- `src/components/cyfs-sn/src/v2/dns.rs`
  - `add_record`
  - `remove_record`
  - `list_records`
- `src/components/cyfs-sn/src/sqlite_db.rs`
  - `users`
  - `devices`
  - `user_dns_records`
  - `user_did_documents`

当前主要差距：

- BNS document 尚未成为解析的第一权威来源。
- gateway device 仍硬编码为 `ood1`。
- `zone_config` 字段兼容承载 boot 信息，`zone` 和 `boot` 未结构化拆开。
- `user_domain` 的显式 DNS record 和子域名解析还不完整。
- DNS、DID、HTTP hostname 解析逻辑分散在 `SNServer`。
- `self_cert`、`sn_ips`、device online 地址混在用户和设备查询路径里，没有统一输出模型。
- cache 只缓存 DNS `NameInfo`，没有感知 BNS version、device online 更新和 relay 迁移。

## 迁移步骤

1. 抽出 `sn_resolver` 模块，先包住现有 `SNServer` 解析逻辑，保证旧测试不变。
2. 定义 `ZoneResolution`、`GatewayResolution`、`DnsResolution`、`DidResolution`、`RelayResolution`。
3. 把 `NameServer::query`、`query_did_v2`、`query_device_by_hostname_v2` 改为调用 resolver，再做兼容投影。
4. 接入 `bns-indexer` read client，把 BNS `zone`、`boot`、`device_mini_doc`、`dns_txt` 放到第一优先级。
5. 把 gateway device 从硬编码 `ood1` 改成读取 BNS `zone/boot`。
6. 把本地 `user_dns_records` 限定为兼容 fallback；新写入通过 `sn_bns_controller` 发布 BNS `dns_txt`。
7. 增加 cache invalidation：BNS version、device online 更新、user_domain 修改、relay 分配变化。
8. 删除或降级 `SNServer` 中重复的解析 helper，只保留路由和兼容入口。

## 测试要求

至少覆盖：

- `sn.<server_host>`、`<server_host>`、alias 的 A/AAAA/TXT。
- `alice.web3.<server_host>`、`home.alice.web3.<server_host>`、`www-alice.web3.<server_host>` 的 username 提取。
- BNS name 的 TXT 合并：`zone`、`boot`、`dns_txt`。
- BNS name 的 A/AAAA：显式 `gateway_ips` 优先；无显式 IP 时走 gateway device 在线态。
- user_domain 精确命中和子域名命中。
- user_domain 显式 A/AAAA/TXT record 优先。
- gateway device 不再固定为 `ood1`。
- device online 地址过滤 loopback、`172.16.0.0/12`、record type 和去重。
- `did:bns:<username>` 的 `zone` / `boot` / device doc。
- `did:bns:<device>.<username>` 的 `doc` / `info`。
- `did:web:<user_domain>` 和 `did:web:<device>.<user_domain>` 映射。
- `did:dev:<id>` 的 `doc` / `info`。
- DNS cache hit、tombstone、TTL 到期和 device online 更新失效。
- relay 分配变化后 resolver 返回新的 `relay_sn`。
