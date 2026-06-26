# 新 SN 重构 · 阶段二 TODO

> 本文是阶段二（编排/接线层）的待办清单，依据 `doc/SN/` 各设计文档与当前 `cyfs-sn` / `bns-client` / `bns-indexer` 实现的对照审查整理。
>
> **阶段一已完成**：数据层与状态机重写、模块抽取、读路径接入。各模块的"现状/当前实现"小节已在对应设计文档中更新。
>
> **阶段二主线**：把已经各自建好的模块**串起来**——补齐统一鉴权层、把 BNS 写入接进 SN 写 API、接通"建好但没接线"的孤儿能力。当本文与设计意图冲突时，以 `doc/SN/新SN核心流程整理.md` 为准。

## 优先级总览

| 优先级 | 事项 | 影响模块 | 性质 |
|---|---|---|---|
| P0 | 实现 `sn_authority` 统一鉴权上下文 | 全部 | 核心架构缺件 |
| P0 | 把 `SnBnsController` 接进 cyfs-sn 写 API | bns-controller / auth / zone / device / dns / did | BNS 写入主线未启动 |
| P1 | 接通已建好的孤儿能力 | relay / auth / device_info | 差最后一根线，性价比最高 |
| P2 | resolver 补齐（子域名 / from_ip / 缓存） | resolver | 功能完整性 |
| P2 | device_info remote 模式 + 运维 | device_info | 部署形态 |
| P3 | 遗留清理与审计 | 全部 | 收尾 |

---

## P0-1 · sn_authority 统一鉴权上下文

设计要求统一输出 `Owner(name)` / `Controller(name, doc_type_scope)` / `Device(zone, device_name, did)` / `SnUser(username)`，业务模块消费结果而非各自解析 token。**目前完全不存在**——每个 handler 仍内联解析 token。

- [ ] 新建 `sn_authority` 模块，定义 `AuthContext` 枚举（Owner / Controller / Device / SnUser）。
- [ ] 实现四类签名验证并归一化：owner ETH/BNS authority key、SN session token、device 私钥、SN controller key。
- [ ] V2 handler（`api/*.rs`）改为消费 `sn_authority` 结果，移除内联 `RPCSessionToken::from_string(...).verify_by_key(...)`（散落在 `sn_server.rs:1114+/1226+/2191+` 等）。
- [ ] 提供 `sn_authority → CallAuthority` 桥接，供 `SnBnsController` 使用（见 P0-2）。

## P0-2 · 把 SnBnsController 接进 cyfs-sn 写 API

写入层 `SnBnsController`（`bns-client/src/sn_bns_controller.rs`，1151 行）已基本完成，但 **cyfs-sn 从不实例化或调用它**；所有写 API 仍只写本地 SQLite。

- [ ] `api/auth.rs::register`：在 `register_user_v2` 之外调用 `bootstrap_name`（BNS name + owner doc + controller key/policy 原子创建），去掉 `need_bind_owner_key=true` 的 compat 状态。
- [ ] `api/zone.rs::bind_config`：调用 `bind_zone_documents` 发布 BNS `zone` / `boot`，`users.zone_config` 降级为迁移缓存。
- [ ] `api/device.rs::register`：调用 `publish_device_mini_doc`，引入 `pending_bns_publish` 状态。
- [ ] `api/dns.rs::add_record / remove_record`：调用 `upsert_dns_txt`（Controller authority 路径）。
- [ ] `api/did.rs::set_document`：改为 BNS `publish_document`，不再只写本地 `did_documents`。
- [ ] 持久化幂等存储：用 SQLite 实现 `SnBnsWriteRequestStore`（替换内存版 `MemorySnBnsWriteRequestStore`），落地 `sn_bns_write_requests` 表 + 基于 BNS 状态的恢复路径。
- [ ] 错误映射：在 cyfs-sn 侧实现 `CONTROLLER_SCOPE_DENIED` / `NOT_EFFECTIVE_OWNER` / `NAME_ALREADY_EXISTS` 等 → SN API code 的映射表，透出 `bns_code/expected/actual`。
- [ ] 补 zone/boot schema 校验器（目前按不透明 `Value` 透传）。

## P1 · 接通孤儿能力（建好但没接线）

### Relay
- [ ] `check_relay_admission` **零调用方**——接入实时 keep_tunnel 准入路径。
- [ ] admission 内补 token / `sn_authority` 校验（目前 `auth_context` 传入但从不验证，`TokenInvalid` 永不返回）。
- [ ] register / bind_zone / update_ood_info 流程触发 `assign_zone_relay` 自动分配；评估 `lease_expires_at` 过期再分配。
- [ ] 心跳超时检测 → 标记 `unhealthy` → 受影响 zone 故障切换（`RelayAssignmentSource::Recovery` 已定义但从不产生）。
- [ ] `choose_relay_node` 使用 `from_ip` 做地理选择（目前接收但忽略）。

### Auth / PKX
- [ ] PKX domain proof 在 DB 层已实现但**无 RPC handler、无 DNS TXT 查询接线**，端到端不可达——补 `domain.*` RPC 与 DNS TXT 查询。
- [ ] 堵绕过路径：`zone.bind_config` / `register_user_with_owner_key` 当前无证明即可把 user_domain 置为 `active`。
- [ ] 接通 session 撤销表与 `logout`（目前 `logout` 是 no-op，撤销表是死基础设施；token 无 `kid`/`jti`，issue 路径不写 `account_sessions`）。
- [ ] 修正 owner 权限语义：当前是"本地存储 key = owner"，应走 BNS authority。
- [ ] 堵 `self_cert` 绕过：`user.set_self_cert` / `dns.add_record(has_cert=true)` 当前可被裸 access token 设置，需 device 证明。
- [ ] 写入 `owner_key_ref` 列（当前 insert 恒为 NULL）。

### Device Info
- [ ] `sync_device_online_state`（`sn_server.rs:775-824`）补齐真实输入：`from_ip`（入口观测源 IP）、`nat_type`、`report_seq`——目前恒传 `None`/`Unknown`，使已实现的 NAT 检测与 stale-report 拒绝在生产路径**空转**。
- [ ] 修正硬编码：role（`device_name=="ood1"` 判断）、ttl（恒 300）、endpoint scope（恒 `Public`）。

## P2 · Resolver 功能补齐

- [ ] user_domain **子域名转发解析**（目前仅精确匹配，`home.alice.example.com` 无法回退到父 user_domain）。
- [ ] **按来源 from_ip 选内/外网地址**（目前无条件吐出全部 public+private IP；`resolve_did` 的 `from_ip` 参数被忽略）。
- [ ] 缓存分层与失效：BNS version 缓存、device-online 短 TTL、基于 BNS/device/relay 变更的失效钩子；统一目前 `NameInfoCache` 与 `SnResolverCache` 两层重叠缓存。
- [ ] 分类顺序：当前 user_domain 先于 BNS owner，与文档优先级相反。
- [ ] BNS 名校验接入 `buckyos-kit::is_valid_name`（目前仅查空/长度）。
- [ ] 非 WAN 设备应追加**当前分配 relay 的地址**，而非用户 `sn_ips`。

## P2 · Device Info remote 模式 + 运维

- [ ] remote 独立服务模式 + 健康检查（目前只有 `open_local`，`RemoteError` 定义了但没用）。
- [ ] 旧 `devices` 表（`sqlite_db.rs`）仍是 `device.get/list/query_by_did` 权威来源——把 API 读路径迁到新组件。
- [ ] `device_state_events` 保留策略（目前只插不删）。
- [ ] 指标 / 健康 / 超时。

## P3 · 数据面 Relay 节点

- [ ] 实现数据面 `sn_relay` 节点模块（启动、监听、register、heartbeat 客户端）。
- [ ] keep_tunnel 服务：收 RTCP hello → 验 token → `check_relay_admission` → 建本地 tunnel。
- [ ] HTTP/HTTPS 转发：按 Host/SNI + `self_cert` 选 80/443，咨询 manager 确认 zone 归属，复用 per-relay RTCP tunnel。
- [ ] RTCP 转发：zone 内 + zone 外到达 gateway，执行跨 zone 准入策略。
- [ ] 错误 relay 处理：HTTP redirect / RTCP reject / raw-tcp forward 到正确 relay。

## P3 · 遗留清理与审计

- [ ] 删除死代码 `query_name_info_uncached`、ood1 绑定的 `get_user_zonegate_address` 及 `sn_server.rs` 兜底分支。
- [ ] relay 迁移 / admin 操作审计事件（`operator` 字段当前被丢弃）；`relay.*` API gateway 入口。
- [ ] 运维审计：BNS 写操作（authority/doc_type/version）、user_domain 绑定与 proof、relay 分配调整、ACME challenge 写入清理、设备在线态关键变更。
- [ ] 传统账号安全：改密、找回、限流（目前仅 freeze/unfreeze）。
