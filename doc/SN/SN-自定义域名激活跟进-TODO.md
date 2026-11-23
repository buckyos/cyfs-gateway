# SN 自定义域名激活跟进 TODO

日期：2026-11-22。状态：未开始，没有排期。

来源：`buckyos/notepads/node-active-custom-domain-todo.md`（Node Active 激活流程优化）。那一期明确不动服务器，只优化客户端流程，凡是需要 SN 配合的都用现有接口绕过。本文记录绕过留下的缺口，供 SN 侧后续处理。

涉及仓库：`cyfs-gateway`（cyfs-sn、cyfs-gateway-api）、`sn-business`（AuthDB、relay 管理的 Postgres 实现）、`buckyos-websdk`（SN client）。

本文结论来自 2026-11-22 读代码，没有在线上 SN 验证过。

## 1. 共同约束

- 线上已有按现状工作的客户端，SN 先上线、客户端后上线。新能力只加不改：现有方法的参数、返回字段、错误名保持可用。
- 客户端这一期依赖的现有行为见 §5，改动前先对照。
- SQLite（cyfs-sn）和 Postgres（sn-business）两套实现同步，契约测试都跑。

## 2. 待办总表

| 编号 | 事项 | 优先级 | 解决什么 |
| --- | --- | --- | --- |
| S1 | `zone.set_region`：已有账号改分区 | P1 | 现在只有新注册能选分区；钱包用户、已注册账号和重新激活只能看 |
| S2 | 地址应答读完整设备文档，并统一四种接入方式 | P1 | 现在靠客户端在文档里写特定字段来绕过 |
| S3 | `domain.bind` 可重复调用，并能查全部绑定 | P2 | NS 委派后 `_pkx` 查不到，再次绑定会失败 |
| S4 | 账号 token 可写自己的证书挑战 | P2 | 试挑战现在只能等设备登记之后做 |
| S5 | 分区显示名 | P3 | 现在只有 `region_id`，由前端翻译 |
| S6 | 绑定的错误分类、域名被接管的通知 | P3 | 用户看不懂失败原因；域名被别人接管时双方都没有提示 |
| S7 | `self_cert` 按域名记录 | P3 | 现在是用户级标记 |

## 3. 各项说明

### S1 `zone.set_region`

- **现状：** `region` 只在 `auth.register` 接受，没有改分区的公开接口。relay 管理器内部已支持改派和迁移（`assign_zone_relay`、`start_relay_migration`、`complete_relay_migration`）。
- **建议：** 新增 `zone.set_region`，参数只有 `region`，身份来自账号 token 或设备 token。按分区选 relay，走已有的迁移窗口。
  - 分区没变：直接成功，不产生新的迁移。
  - 未知分区、分区内没有可用节点：分别报错，原分配不变。注意这与注册时不同，注册时未知分区会回退到 GeoIP。
  - 客户端不能指定具体 relay，与 `auth.register` 一致。
  - 加频率限制，避免反复迁移。
- **返回：** 与 `zone.get_info` 相同的视图，让客户端立即拿到新的 `relay_sn`。
- **客户端跟进：** 钱包、已注册账号和重新激活可以选分区，只在提交激活时生效；设置页也能改。
- **验收：** 改分区后节点隧道连到新 relay，迁移窗口内旧连接不断；重复提交同一分区没有变化；失败时原 relay 继续可用。

### S2 地址应答

- **现状：**
  - SN 从 mini 设备文档读 `net_id`（`sn_resolver.rs` 的 `resolve_device_mini_doc`、`device_document_network_type`），而页面激活发布的 mini 文档没有这一项，四种接入方式都会按“未知”应答 relay。
  - A 记录只对 `wan_dyn`、`portmap` 应答设备地址（`resolve_standard_dns_ipv4`），`wan` 应答 relay。
  - `portmap` 应答设备地址是错的：它只映射了 RTCP 端口，浏览器连不上 443。
- **客户端这一期的绕过：** `wan` 在签名的 Zone 文档写 `gateway_ips`；`wan_dyn` 在 mini 设备文档写 `net_id`；`nat`、`portmap` 不写。
- **建议：** 从 Zone 文档的 `devices`（owner 签名的完整设备文档）读 `net_id` 和 `ips`，规则统一为：

  | 接入方式 | A / AAAA |
  | --- | --- |
  | `nat`、`portmap`、未知 | 分配的 relay |
  | `wan_dyn` | 设备上报的公网地址 |
  | `wan` | 签名的固定地址：先 `gateway_ips`，再设备文档的 `ips` |

- **两处必须同一次改：** 读完整设备文档，和 `portmap` 改应答 relay。只做前一项，`portmap` 用户会立刻从 relay 变成设备地址，浏览器打不开。`device_document_requires_sn_relay` 对 `portmap` 的判断和现有测试（`["wan_dyn", "portmap", "nat", ""]` 那组）要一起改。
- **顺带核对 AAAA：** 它走另一条路径（`resolve_gateway_addresses`），会把设备上报的公网 IPv6 和 relay 一起返回，`nat` 也不例外。确认是否符合预期。
- **兼容：** 继续认 `gateway_ips` 和 mini 文档的 `net_id`。
- **验收：** 四种接入方式的 A / AAAA 各有用例；`wan_dyn` 换 IP 后应答跟着变；旧客户端发布的文档应答不变（`portmap` 仍是 relay）。

### S3 `domain.bind` 可重复调用

- **现状：** 每次绑定都查外部 DNS 的 `_pkx` TXT。NS 委派给 SN 之后，`_pkx` 由 SN 应答，而 SN 只应答显式写入的记录，所以查不到，再次绑定会失败。`user.get_profile` 只返回最新的一个 `user_domain`。
- **客户端这一期的绕过：** 先查 `user.get_profile`，已是目标域名就不调 `domain.bind`。剩一个缺口：同一账号绑过两个都已委派的域名，要换回前一个时会失败，用户得先临时撤掉 NS。
- **建议：** 同一用户、同一 PKX 已有有效绑定时直接成功，不查 DNS；另加一个只读方法列出自己的全部有效绑定。owner 换过密钥、PKX 变了的，仍要重新证明。
- **不能改的：** 绑定别人的域名仍必须查外部 DNS。NS 委派不带用户身份，不能当作归属证明。
- **验收：** 已委派的域名重复绑定成功；另一用户绑定同一域名仍要求 `_pkx`；密钥变化后要求重新证明。

### S4 账号 token 写证书挑战

- **现状：** `user.add_dns_record` 要求 `device_did` 属于已登记的设备，首次激活前没有。
- **客户端这一期的绕过：** 试挑战放在提交激活时、`device.register` 之后。失败时 BNS 文档已经发布，用户要重试。
- **建议：** 账号 token 写和删 `_acme-challenge.<自己已绑定的域名>` 的 TXT 时不要求 `device_did`，其它名字和类型不变。
- **客户端跟进：** 试挑战提前到域名步骤，通过才能走下一步。
- **验收：** 不能写别人的域名、别的名字、A / AAAA；设备 token 的限制不变。

### S5 分区显示名

区域探测配置（`region-probe-config.json`）给每个分区加可选的多语言显示名。旧客户端忽略它；没有时客户端显示 `region_id`。

### S6 错误分类与接管通知

- 域名被封、账号未激活、BNS 不可达、外部 DNS 查询失败，各给一个稳定的错误名，不带内部报文。
- 域名被另一用户接管时通知原用户，接管方也应看到“此域名原来绑定在别的账号”。

### S7 `self_cert` 按域名记录

现在是用户级标记，不区分默认域名和自定义域名，也不随证书过期自动关闭。证书过期或被删时 relay 仍把 TLS 转给节点，浏览器看到证书错误。建议按主机名记录，并让节点在证书失效时上报关闭。

## 4. 不需要做的

- `domain.prepare`：`_pkx` 的记录名和值由客户端自己算，不再需要。
- BNS Server 回答 `did:web`：owner 已定，设备文档由 Zone 在 boot 之后自己经 HTTPS 提供。

## 5. 客户端这一期依赖的现有行为

改 SN 时不要破坏：

- `domain.bind` 的成功条件和 PKX 算法：记录名 `_pkx.<域名>`，值 `PKX(<owner 公钥 x>)`，公钥来自 BNS 的 OwnerDocument。
- `user.get_profile` 返回 `user_domain`，等于最近一次成功绑定的域名。
- `dns.<SN>` 对已绑定域名应答 NS 和 SOA，包括激活之前。
- 没有设备时，已绑定域名和 `<用户名>.web3.<SN>` 的 A 应答分配的 relay。
- `user.add_dns_record` / `user.remove_dns_record` 接受账号 token 加已登记的 `device_did`。
- `gateway_ips` 优先于其它地址来源；mini 设备文档里的 `net_id` 被识别；没有 `net_id` 时应答 relay。
- `user.set_self_cert` 接受已登记的设备 DID。
- `auth.register` 的 `region`、`zone.get_info` 的 `relay_sn`。

## 6. 建议顺序

S1 和 S2 先做，各自独立。S3、S4 一起做，客户端可以同时把试挑战提前。其余随后。
