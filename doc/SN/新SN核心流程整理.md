# 新 SN 核心流程整理

## 架构定位

SN 是 BNS 早期可用性的过渡服务，最终目标不是生态化，而是被 `BNS + local resolver + user-owned gateway` 替代并关闭。

这个定位决定了几个边界：

- BNS 负责名字、文档、owner/controller authority、controller policy 等权威状态。
- local resolver 负责把传统 DNS 使用方式桥接到 BNS 解析。
- user-owned gateway 负责用户自己的公网可达入口，可以部署在 VPS、云主机、家庭公网 IP 或托管但用户可控的 gateway 上。
- SN 只负责在 user-owned gateway 还没有普及时提供 fallback bootstrap/relay 能力，解决 Personal Server 仍在 NAT 后面的过渡问题。

因此，`cyfs-sn` 的开源实现主要是 SN 过渡层的参考实现，用来说明协议原理、支持审计、测试和兼容性验证；它不应该被理解为鼓励普通用户或第三方服务商长期运行生产 SN。第三方运行 SN 可以作为兼容结果存在，但不应成为 BNS 的产品主路径，也不应形成“用户选择 SN 服务商”的终局模型。

设计上应避免把 SN 写进 BNS 的长期信任模型：

- BNS 合约不设计“选择 SN provider / operator”的权威字段。
- SN 不拥有域名解析权威，也不成为用户身份入口。
- SN controller 只用于过渡阶段必要的受限自动写操作，并且必须可被迁移或撤销。
- 官方 SN 的长期目标不是承载更多流量，而是随着 user-owned gateway 普及逐步降低依赖，最终可以下线。

## 设计目标

新版本 SN 基于 `bns-indexer` 构造。BNS 负责名字、文档、controller key、controller policy 等权威状态；SN 作为过渡服务，现阶段负责账号、设备在线信息、域名绑定、边缘 relay 分配和流量转发。

重点不是把所有状态都上链，而是让 SN 对 BNS 的写操作走未来合约也能支持的 controller 机制：

- Owner 仍然是名字和核心文档的最终控制者。
- SN 可以在 BNS 创建阶段同步写入自己持有的 controller key/policy。
- SN 后续只对被授权的 doc type 执行自动化写操作，例如 `dns_txt`、relay assignment 相关文档。
- `bns-indexer` 保持为 registry/document 状态机，不直接承担 RPC 鉴权、账号登录或设备在线状态。

这些 controller 能力服务于过渡阶段的可用性，不代表 SN 是 BNS 终局架构的一部分。长期应把公网可达性迁移到 user-owned gateway，把 SN 依赖降到 0。

## 模块划分

### bns-indexer

BNS 权威状态机。负责：

- register name
- publish / resolve document
- authority key
- controller policy
- document version / name seq guard
- helper schema，例如 `zone`、`boot`、`device_mini_doc`、`dns_txt`

`sn_document_schema` 不单独拆服务，应该沉到 `bns-indexer` helper 中。

### sn_bns_controller

SN 对 `bns-indexer` 的写操作封装层。负责：

- 将 SN 鉴权结果转换为 BNS 可接受的 owner/controller 调用。
- 创建 BNS name 时同步设置 SN controller key 和 controller policy。
- 发布 `zone`、`boot`、`device_mini_doc`、`dns_txt` 等 BNS 文档。
- 维护 BNS 写操作的 version guard、幂等参数和错误映射。
- 约束 SN controller 只能写被授权的 doc type，避免 SN 拥有过宽权限。

这里是系统事务性的关键点。暂不单独设计 `sn_consistency_worker`，优先通过 `sn_bns_controller` 把 BNS name 创建、初始文档、SN controller 授权做成一个 BNS 侧原子流程。

### sn_auth

账号与用户侧低频状态。负责：

- 用户名、密码、登录 token。
- `sn_user <-> user_domain` 绑定关系。
- `zone_info` 中不适合放入 BNS 权威文档的运行状态，例如 `self_cert`、当前 relay 分配结果等。
- user_domain 的冲突检查和后续 domain proof 流程。

`sn_domain_registry / domain_proof` 暂不单独拆组件，作为 `sn_auth` 的一部分实现。

### sn_device_info

设备在线与设备上报状态。负责：

- 设备注册后的本地在线状态。
- `update_ood_info` 上报。
- device IP、from_ip、NAT/公网状态、最近更新时间。
- 供 resolver 和 relay 查询当前 gateway device 的可达地址。

BNS 中的 `device_mini_doc` 是设备身份和基础配置的权威文档；`sn_device_info` 是设备在线态和可达性缓存。

### sn_authority

鉴权工具库，不做独立 SSO 服务。负责验证并归一化：

- Owner ETH 私钥签发的请求。
- SN 登录后由 `sn_auth` 签发的用户 session token。
- 设备私钥签发的自动化请求。
- SN controller key 签发的 BNS 自动化请求。

输出应是统一的权限上下文，例如：

- `Owner(name)`
- `Controller(name, doc_type_scope)`
- `Device(zone, device_name, did)`
- `SnUser(username)`

业务模块不应重复解析 token，而是消费 `sn_authority` 的结果。

### sn_resolver

解析工具库，是 DNS、HTTP relay、rtcp relay、node_daemon 查询共同依赖。负责：

- 解析 BNS 域名和非 BNS 域名。
- 将 hostname / DID / zone / device_name 转成 zone、boot、gateway device、relay_sn、self_cert、A/AAAA/TXT 等结果。
- 封装 BNS 权威文档、`sn_auth` user_domain、`sn_device_info` 在线态之间的查询优先级。

### sn_relay_manager

过渡 relay 调度与准入。负责：

- zone -> sn_relay 的分配关系。
- relay 节点健康状态。
- keep_tunnel 准入。
- relay 迁移和手工调整。
- 判断某个 zone/device 是否应该接入当前 relay 节点。

`sn_relay_manager` 不应被设计成长期 SN 服务商市场的调度中心。它的职责是管理过渡期 fallback relay 资源，并为后续迁移到 user-owned gateway 保留清晰的退出路径。

不单独设计 `sn_tunnel_registry`。每个 zone 的 device 都走该 zone 当前分配的 `sn_relay`，本地 tunnel 状态由 relay 节点运行时维护；跨节点只需要 `sn_relay_manager` 管理 zone -> relay 的关系。

### sn_server / sn_api_gateway

现有 `sn_server` 继续作为 API gateway 和配置开发入口。负责：

- JSON-RPC / HTTP 路由。
- 参数校验、错误码、兼容旧接口。
- 调用 `sn_authority`、`sn_bns_controller`、`sn_auth`、`sn_device_info`、`sn_resolver`、`sn_relay_manager`。

### sn_acme_client

暂不单独拆成 `sn_acme_manager`。ACME 自动行为基于 `sn_auth` 中的 `zone_info` 和 BNS `dns_txt` 文档实现：

- DNS challenge 写入由 `sn_bns_controller` 使用 SN controller key 发布到 BNS `dns_txt`。
- 证书状态写回 `sn_auth.zone_info.self_cert`。
- 后续如果 ACME 生命周期、失败重试、TXT 清理变复杂，再考虑单独拆组件。

## 数据归属

### BNS 权威数据

- username / BNS name
- owner_config
- owner / controller authority key
- controller policy
- zone document
- boot document
- device_mini_doc
- dns_txt document
- 可被合约验证和审计的内容发布文档

### SN 本地数据

- 账号密码和登录态
- user_domain 绑定关系和 domain proof 状态
- device 在线态、IP、from_ip、最近上报时间
- zone_info 中的运行态，例如 self_cert、relay_sn 分配结果
- relay 健康状态和手工调度配置

这些数据是过渡服务运行态，不应进入 BNS 权威数据模型。尤其是 `relay_sn` 分配结果只能作为 fallback relay hint，不应成为域名归属、解析权威或用户身份的一部分。

### 查询合成数据

`sn_resolver` 输出的是合成结果，不应被当成新的权威存储。它从 BNS、`sn_auth`、`sn_device_info`、`sn_relay_manager` 读取状态并合成 DNS / DID / relay 查询结果。

## DNS 查询

所有 DNS 查询先进入 `sn_resolver`。

请求目标是 BNS 域名：

- `TXT`: 从 `bns-indexer` 读取 `zone`、`boot`、`dns_txt`，合并成多条 TXT 记录。
- `A/AAAA`: 优先使用 BNS `zone` 文档中的 `gateway_ips`；如果没有，则根据 `zone`/`boot` 中的 gateway device 配置查询 `sn_device_info`，返回当前可达 IP。

请求目标是非 BNS 域名：

- 先由 `sn_auth` 根据 `user_domain` 找到对应 `sn_user`。
- `TXT`: 合并该用户 BNS `zone`、`boot`、`dns_txt`，再叠加必要的 user_domain TXT 记录。
- `A/AAAA`: 如果 user_domain 记录里有显式 A/AAAA，则直接返回；否则通过 `sn_resolver` 找到该 zone 的 gateway device，再查询 `sn_device_info` 返回当前可达 IP。

注意：

- hostname 到 gateway device 的映射不能长期写死为 `ood1`，应该来自 `zone` 或 `boot` 文档。
- `sn_device_info` 只提供在线态和 IP，不决定 gateway device 的权威身份。

## 注册管理

### 注册用户 owner

输入：

- username
- owner public keys，至少包含 BNS/ETH owner key 和后续文档签名所需 key
- owner_config
- password_hash
- active_code 或其它注册许可

流程：

1. `sn_auth` 判断用户名是否合法、激活码是否可用。
2. `sn_bns_controller` 调用 `bns-indexer.register` 创建 BNS name。
3. BNS 创建阶段同步发布 owner_config，并设置 SN controller key / controller policy。
4. `sn_auth.register` 写入账号、密码和基础用户状态。
5. 返回登录态和 BNS name 状态。

需要保证：

- `sn_bns_controller` 的注册请求要有幂等 key。
- 如果 BNS name 已存在但 `sn_auth` 未完成，应能通过明确的恢复流程继续绑定账号或人工处理。
- SN controller policy 必须限制 doc type，不能给 SN 全量 owner 权限。

### bind zone

输入：

- zone_config
- zone_boot_config
- owner 签名或可映射为 owner authority 的 token

流程：

1. `sn_authority` 校验 owner 权限。
2. `sn_bns_controller` 校验 `zone_config` 和 `zone_boot_config` 签名。
3. 发布 BNS `zone` document。
4. 发布 BNS `boot` document。
5. 根据 zone/boot 内容更新 `sn_auth.zone_info` 中的运行态缓存。

### 注册设备

输入：

- zone
- device_name
- did:dev:xxxx
- device_mini_doc / DeviceConfig
- device 在线上报信息

流程：

1. `sn_authority` 校验 owner/session-token 或 device-token。
2. 校验 `device_mini_doc` 与 DID、公钥、zone/device_name 一致。
3. `sn_device_info.register_device` 写入设备在线态初始记录。
4. `sn_bns_controller` 发布 BNS `device_mini_doc`。

权限规则：

- owner 可以注册或替换 device。
- device 私钥只能更新自己的在线态。
- 如果允许 device 私钥发布 `device_mini_doc`，必须由 BNS controller policy 明确授予该 device 对特定 doc type / device_name 的权限。

### 注册 user_domain

`user_domain` 暂属于 `sn_auth`。

流程：

1. 用户发起绑定。
2. `sn_auth` 检查 user_domain 是否和历史绑定冲突。
3. domain proof 验证传统 DNS owner，验证方式可以是DNS TXT检查，必须有正确的PKX(sn_user.pkx)
4. 绑定 `user_domain.owner = sn_user`。

后续如果要把传统 DNS 注册局上链，需要单独设计合约层的 domain owner 确认机制。

## 鉴权

### BNS 修改类请求

优先使用 owner ETH 私钥或 BNS authority key 签名。`sn_authority` 将签名请求转换为 `Owner(name)` 或 `Controller(name, doc_type_scope)`。

SN 登录 token 只表示 `SnUser(username)`，不天然等价于 BNS owner。它可以用于 UI 管理和低风险账号操作；涉及 BNS owner 权限时，应要求 owner 签名，或通过已经写入 BNS 的 controller policy 授权 SN 执行特定 doc type 的自动操作。

### BuckyOS 自动化请求

来自 BuckyOS 的自动化请求应该使用 device 私钥签名的 token。`sn_authority` 根据 zone + device_name 或 did 找到设备公钥，校验 token 后输出 `Device(zone, device_name, did)`。

device 权限主要用于：

- update_ood_info
- keep_tunnel
- ACME 证书状态上报
- 受限 DNS challenge 请求

device token 不应默认拥有 BNS owner 权限。

## BuckyOS 自动行为

自动行为原则上不是 owner 级链操作。需要写 BNS 时，由 `sn_bns_controller` 使用 SN controller key，在 BNS controller policy 授权范围内执行。

### update_ood_info

node_daemon:

- 调用 `sn_device_info.update_ood_info`

sn_device_info:

- 通过 `sn_authority` 校验 device token。
- 根据 zone + device_name 或 did 找到设备公钥。
- 根据 from_ip 和上报信息更新 device 在线数据库。

### keep_tunnel

node_daemon:

- 向 SN 查询当前 zone_info。
- 从 zone_info 得到分配的 `relay_sn`，例如 `us-sn.buckyos.ai`。
- 和该 relay_sn keep tunnel。
- zone_info 可能变化，node_daemon 应周期性检查，而不是只在 keep tunnel 前检查一次。

relay_sn:

- 校验来源 device_config / device token。
- 查询 `sn_relay_manager` 判断 device 所在 zone 是否属于当前 relay。
- 如果 zone 不属于当前 relay，拒绝接入并返回正确 relay 信息。

### sn_acme_client

证书无效时开始更新：

1. 根据证书机构要求生成 DNS challenge。
2. 调用 SN DNS API。
3. `sn_bns_controller` 使用 SN controller key 发布 BNS `dns_txt` document。
4. ACME 校验成功后，调用 `sn_auth.update_zone_info(self_cert=true)`。
5. ACME 校验失败时，不应立即覆盖已有有效证书状态；应区分“本轮签发失败”和“当前证书不可用”。

## http 流量中转

HTTP/HTTPS 中转是过渡访问路径。终局形态下，用户应优先通过自己的 public gateway 提供公网访问；只有当 gateway 不可达或用户尚未迁移时，才使用 SN relay 兜底。

浏览器：

- 向 `sn_relay` 节点发 HTTP/HTTPS 请求。

sn_relay:

1. 根据 target hostname 调用 `sn_resolver` 查询 gateway device 和目标 zone。
2. 查询 `sn_relay_manager` 判断该 zone 是否属于当前 relay。
3. 如果属于当前 relay，则通过本节点已有 RTCP tunnel 或本地可建立的 tunnel forward 到 gateway device。
4. 如果不属于当前 relay，则返回重定向信息，或把 raw tcp forward 到正确 relay。

forward 目标端口：

- 根据 `self_cert` 和请求协议决定转发 80 或 443。
- `self_cert` 来自 `sn_auth.zone_info` 的运行态；后续可由证书有效性周期校验修正。

## rtcp 流量中转

目标场景：

- zone 内两台设备通过 SN relay 建立 rtcp tunnel。
- zone 外任意设备通过 SN relay 到达特定 zone 的 gateway。

原则：

- SN relay 是 fallback tunnel，不是长期网络入口。
- zone -> relay 的归属由 `sn_relay_manager` 管理。
- relay 节点本地维护实时 tunnel 连接，不另设全局 `sn_tunnel_registry`。
- 跨 zone 或 zone 外访问需要明确准入策略，避免任何设备都能通过 relay 打到 gateway。

## 用户管理

一部分操作在 `sn.buckyos.ai` 页面完成，也应能在 BuckyOS App 中完成。

需要支持：

- unbind_zone
- change_pwd
- update_user_doc
- bind / unbind user_domain
- owner key rotation
- controller key rotation
- 手工调整 relay 分配

其中 owner key / controller key rotation 必须通过 `sn_bns_controller` 走 BNS authority/controller 机制。

## 内容发布

先支持 CLI 工具，再在 BuckyOS App 里支持。

publishDocument:

- 普通 owner 文档需要 Owner ETH 私钥或 BNS authority key。
- SN 自动化文档需要 SN controller key，并且只能发布 controller policy 授权的 doc type。
- 发布请求必须携带 expected_version / name_seq guard，避免覆盖并发更新。

## SN Admin

### 传统用户安全

包括邮箱验证码、密码找回、账号冻结、账号恢复。

这些属于 `sn_auth`，不应影响 BNS owner 权限。账号恢复只能恢复 SN 登录能力，不能绕过 BNS owner key。

### 激活码管理

包括激活码生成、发放、禁用、回收和审计。

### 手工调整 sn_relay

目前系统可以根据 register 或首次上线时的 from_ip 自动把 zone 绑定到某个 `sn_relay`。

这个分区逻辑必须支持手工修改：

- 修改 zone -> relay 分配。
- 设置迁移窗口。
- 通知 node_daemon 重新 keep tunnel。
- relay 节点拒绝不属于自己的 zone 时返回正确 relay。

### 运维审计

需要记录：

- BNS 写操作请求、authority、doc_type、version。
- user_domain 绑定和 domain proof。
- relay 分配调整。
- ACME challenge 写入和清理。
- 设备在线态关键变更。
