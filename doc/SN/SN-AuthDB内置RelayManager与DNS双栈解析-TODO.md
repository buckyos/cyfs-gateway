# SN AuthDB 内置 Relay Manager 与 DNS 双栈解析 TODO

状态：`cyfs-gateway` 实现完成（2026-07-23）；`sn-business` provider、服务角色鉴权和
商用集群部署项待跨仓完成。

相关文档：

- [CYFS-SN-无状态多副本改造-TODO.md](./CYFS-SN-无状态多副本改造-TODO.md)
- [SN-Relay.md](./SN-Relay.md)
- [SN-Relay-Register-Assignment-TODO.md](./SN-Relay-Register-Assignment-TODO.md)
- [SN-Auth.md](./SN-Auth.md)
- [新SN核心流程整理.md](./新SN核心流程整理.md)

## 0. 已确认的架构决定

本 TODO 固定以下方向：

1. `relay_manager` 不再作为独立 remote provider 部署，而是成为 AuthDB provider
   的内部业务模块。
2. `relay_nodes`、node address、assignment、pending、admission 和 migration
   等 relay 控制面表与用户、`zone_info`、session 等 AuthDB 表位于同一个共享数据库。
3. 用户最终分配到的 relay node 是 user/zone info 的组成部分。物理存储仍可使用
   规范化的 assignment 表，但 `get_user_info` / `get_zone_info` 必须返回一致的
   assignment 投影，不再依赖跨服务异步回写 `zone_info.relay_sn`。
4. AuthDB S2S contract 负责 relay 分配和查询；`cyfs-sn` 不再在本地创建
   `SqliteSnRelayManager`，也不维护私有 `relay_assignments`。
5. AuthDB 额外提供完整的 `relay_node -> 两个 IP` 内部查询接口，供
   Web3 SN DNS resolver 缓存和使用。
6. 每个 relay node 恰好有两个类型化 `IpAddr`。两个地址都可以是 IPv4、都可以是
   IPv6，或一 IPv4 加一 IPv6；DNS A/AAAA 按地址族过滤，不能把 IP 固定建模为
   `ipv4_1` / `ipv4_2`。

本文替代
[CYFS-SN-无状态多副本改造-TODO.md](./CYFS-SN-无状态多副本改造-TODO.md)
中“把 relay manager 做成独立 remote service”的旧方案。

### 0.1 本仓完成摘要

- `SqliteSnAuthDB` 使用同一连接池初始化和管理 relay node、双 IP、assignment、
  pending、admission、migration 和持久化 node-map revision；生产 `SNServer`
  不再创建第二个 `SqliteSnRelayManager`。
- AuthDB trait、in-process client、KRPC client/handler 已覆盖 relay node 管理、
  分配、迁移、准入及完整 IP map；用户注册使用一次高层 AuthDB 调用并显式返回
  `assigned` 或 `pending`，SQLite 实现将 user/auth 与 assignment/pending 放在同一
  数据库事务中提交。
- assignment 只保存 `relay_id`；`SNUserInfo` 和 `ZoneInfo` 通过 join 返回统一的
  `UserRelayInfo`。旧 `zone_info.relay_sn` 会迁移后清空，运行期为只读投影。
- resolver 使用带 TTL 和 revision 的 AuthDB node-map 缓存；relay 路径不再读取
  legacy `sn_ips` 或回退当前 SN 的 `server_ip`，A/AAAA 严格按 `IpAddr` 地址族生成。
- 本仓测试覆盖双 IPv4、双 IPv6、双栈、canonical wire/storage 校验、revision、
  并发幂等、pending 补偿、RPC envelope、DNS NODATA/SERVFAIL 和缓存刷新。

## 1. 背景与当前缺口

当前 `cyfs-sn` 的 relay 控制面已经有 `SnRelayManager` trait 和
`SqliteSnRelayManager` 实现，但它仍由每个 `SNServer` 实例使用本地 `db_path`
创建。即使账号和 `zone_info` 已通过 `SnAuthDbClient` 访问 remote AuthDB，
`relay_nodes` 和 `relay_assignments` 仍是每个 SN 副本的本地状态。

这会产生以下问题：

- 多个 `sn-api` 副本可能看到不同的 relay node、负载和 assignment。
- 用户数据在 AuthDB，assignment 在本地 relay SQLite，无法形成同一事务和一致快照。
- 分配成功后还需要单独调用 `update_zone_relay_sn` 回写 AuthDB，存在中间失败和漂移。
- `sn-dns` 无法仅依赖共享 AuthDB 得到“用户被分配到哪个 relay，以及该 relay
  对应哪些公网 IP”。
- 当前 resolver 在需要 relay 时仍读取 legacy `sn_ips`，为空则回退当前
  `SNServer.config.server_ip`。这不能正确表达多 relay node 的实际路由关系。
- 当前 `RelayNode` 只有 `public_host` 和 endpoint，没有供权威 A/AAAA 响应直接使用的
  两个类型化公网 IP。

## 2. 目标

- AuthDB 是 user/zone relay assignment 的唯一运行时真相源。
- AuthDB provider 内部执行 relay node 注册、心跳、自动分配、迁移、准入和 pending
  补偿逻辑。
- 本地 SQLite 开发模式仍可工作，但 relay 表必须由 `SqliteSnAuthDB` 使用同一数据库
  初始化和管理，不再创建第二个 relay manager 数据库边界。
- 生产 `sn-api`、`sn-dns` 和 `sn-relay` 副本只通过 AuthDB S2S contract 访问共享
  relay 状态。
- `SNUserInfo` / `ZoneInfo` 能读取当前 assignment 的 `relay_id`、`relay_sn`、
  `generation` 和 `state`。
- DNS resolver 能用 assignment 的 `relay_id` 查询完整 node IP 映射，并正确生成
  A 与 AAAA 响应。
- 每个 relay node 的两个 IP 都必须经过强类型解析、规范化和地址族测试。

## 3. 非目标

- 不把 DNS packet 构造或 BNS 文档解析移进 AuthDB。
- 不把 relay 的实时 tunnel/连接表写入 AuthDB；每个 relay node 继续本地维护数据面
  连接。
- 不把 `relay_nodes -> IP` 映射作为公开用户 API；它只允许经过服务身份认证的
  SN 内部组件读取。
- 不用 DNS 查询 `relay_sn` hostname 来间接发现 relay IP。AuthDB 中的显式 IP 才是
  DNS 合成路径的数据源。
- 不保留长期的本地 relay SQLite 与 remote AuthDB 双写模式。

## 4. 目标架构

```text
auth.register / relay heartbeat / admin migration
                         |
                         v
              AuthDB S2S contract
                         |
            +------------v-------------+
            | AuthDB provider          |
            |                          |
            | users / auth / sessions  |
            | zone_info                |
            | internal relay_manager   |
            | relay_nodes + 2 IPs      |
            | relay_assignments        |
            | pending / admission      |
            +------------+-------------+
                         |
          +--------------+------------------+
          |                                 |
          v                                 v
 get user/zone relay info       get relay_nodes -> [IP; 2]
          |                                 |
          +---------------+-----------------+
                          v
                    Web3 SN resolver
                          |
                  A: IPv4 / AAAA: IPv6
```

### 4.1 AuthDB provider 内部职责

AuthDB provider 内部的 relay manager 负责：

- 注册、更新和禁用 relay node。
- 保存每个 node 的两个公网 IP、endpoint、region、ISP、能力和健康状态。
- 接收 heartbeat，更新负载、容量和健康状态。
- 以 user/zone 为键自动分配 relay。
- 在用户信息查询中投影当前 assignment。
- 执行 migration、generation 单调递增和 admission 判定。
- 持久化并重试 allocation pending。
- 维护 node IP map 的单调 `revision`，供 DNS 缓存一致刷新。

`cyfs-sn` 中可以保留 `SnRelayManager` 作为领域逻辑接口或 provider 内部模块边界，
但不再为它提供独立的生产 URL、独立数据库或独立部署单元。

### 4.2 `cyfs-sn` 调用方职责

- `sn-api`：向 AuthDB 提交服务端观察到的 source IP 和非可信 region hint，不自行选择
  relay node。
- `sn-dns`：读取 user/zone assignment，并用完整 node IP map 合成 A/AAAA。
- `sn-relay`：通过 AuthDB 查询 assignment/admission；不读取其它 SN 副本的本地文件。
- `sn_resolver`：继续负责 BNS、device state、user DNS 与 relay address 的优先级合成，
  不持久化 assignment。

## 5. 数据模型

### 5.1 `relay_nodes`

保留 relay node 的稳定身份和调度元数据：

```text
relay_nodes
  relay_id             primary key
  relay_sn             unique
  public_host
  http_endpoint
  rtcp_endpoint
  region
  isp
  tags
  capabilities
  status
  capacity_score
  current_load
  last_heartbeat_at
  drain_until
  created_at
  updated_at
```

`relay_id` 是 assignment 和 node IP map 的稳定 join key。`relay_sn` 是可读名称，
不能作为跨表唯一关联的唯一真相。

### 5.2 `relay_node_addresses`

两个 IP 使用规范化子表表达，不增加 `ipv4_1`、`ipv4_2` 之类绑定地址族的列：

```text
relay_node_addresses
  relay_id             foreign key -> relay_nodes.relay_id
  slot                 0 or 1
  ip                   canonical IP value
  created_at
  updated_at

  primary key (relay_id, slot)
```

约束：

- 一个可注册、可分配或可发布到 DNS 的 node 必须恰好有 `slot=0` 和 `slot=1`
  两条地址。
- S2S/Rust contract 使用 `std::net::IpAddr`，不在业务层传递未校验字符串。
- PostgreSQL provider 优先使用 `inet`；SQLite 开发实现使用 canonical string，
  每次写入必须先解析为 `IpAddr`，每次读取失败视为数据损坏。
- 两个 slot 可以是任意 IPv4/IPv6 组合。
- 不要求 IP 在所有 node 间全局唯一，以兼容共享入口或 anycast；如产品部署要求唯一，
  应由部署校验实现，而不是写死通用 schema。
- 更新两个 IP 必须在一个事务中完成；不能让读者观察到只更新一个 slot 的中间状态。
- node 注册、IP 更新和删除必须推进全局 node-map `revision`。

### 5.3 User/zone assignment

物理存储继续使用规范化 assignment 表：

```text
relay_assignments
  zone                 primary key / user-zone foreign key
  relay_id             foreign key -> relay_nodes.relay_id
  state
  source
  reason
  generation
  backup_relay_id
  sticky_until
  lease_expires_at
  migrated_from
  migration_deadline
  source_version
  created_at
  updated_at
```

调整原则：

- `relay_id` 是 assignment 的权威目标。
- `relay_sn` 不再作为独立可漂移字段重复保存；API 响应通过 join `relay_nodes`
  得到当前 `relay_sn`。
- `zone_info.relay_sn` 不再是需要异步回写的第二份真相。兼容期可保留只读投影，
  最终由 assignment join 生成。
- `get_user_info` 和 `get_zone_info` 返回统一的 `UserRelayInfo`：

```rust
pub struct UserRelayInfo {
    pub relay_id: String,
    pub relay_sn: String,
    pub state: RelayAssignmentState,
    pub generation: u64,
}
```

“relay node 是 userinfo 的一部分”指 API/查询投影的一致组成部分，不要求把完整
`relay_nodes` 行或两个 IP 复制进 `users` 表。

### 5.4 其它 relay 控制面表

以下表一并迁入 AuthDB provider 的共享数据库：

- `relay_allocation_pending`
- `relay_admission_events`
- migration/admission 后续需要的审计表

这些表必须与 user、assignment 和 node 生命周期使用同一 provider 的事务和并发约束。

## 6. AuthDB S2S contract

所有接口沿用 AuthDB S2S 路径：

```text
/kapi/sn/s2s/auth-db
```

不再新增独立 `sn_relay_manager` endpoint。

### 6.1 User/zone relay 接口

至少增加或调整：

```text
sn_auth_db.allocate_zone_relay
sn_auth_db.get_zone_relay
sn_auth_db.start_relay_migration
sn_auth_db.complete_relay_migration
sn_auth_db.check_relay_admission
```

同时让：

```text
sn_auth_db.get_user_info
sn_auth_db.get_zone_info
```

返回 `UserRelayInfo` 投影。`update_zone_relay_sn` 在迁移完成后删除；外部调用方不能直接
修改 user 的 relay 字段。

### 6.2 Relay node 管理接口

至少增加：

```text
sn_auth_db.register_relay_node
sn_auth_db.heartbeat_relay_node
sn_auth_db.update_relay_node_addresses
sn_auth_db.get_relay_node
sn_auth_db.list_relay_nodes
```

写接口必须做服务身份和角色鉴权：

- relay node 只能注册/heartbeat 自己的 `relay_id`。
- SN API 只能提交自动分配请求，不能绕过策略指定任意 node。
- migration、disable、address update 属于 admin/operator 权限。

### 6.3 完整 node -> IP 查询接口

新增内部只读接口：

```text
sn_auth_db.get_relay_nodes_ip_map
```

建议 contract：

```rust
pub struct RelayNodeIpMapReq {
    pub if_revision: Option<u64>,
}

pub struct RelayNodeIpEntry {
    pub relay_id: String,
    pub relay_sn: String,
    pub ips: [IpAddr; 2],
    pub status: RelayNodeStatus,
    pub updated_at: u64,
}

pub struct RelayNodeIpMapSnapshot {
    pub revision: u64,
    pub generated_at: u64,
    pub nodes: Vec<RelayNodeIpEntry>,
}
```

接口语义：

- 这是全量快照接口，不分页、不返回增量，也不接受 region、status、relay_id 等
  过滤条件。
- revision 变化时一次返回所有当前非 deleted node，以及每个 node 的完整两个 IP；
  Deleted node 不属于当前映射。
- 响应保留 `status`，使 DNS、relay 和管理调用方能按自身语义判断 Active、
  Draining、Unhealthy、Disabled，但服务端不能因 status 省略当前 node。
- 每个 entry 必须恰好返回两个可解析的 `IpAddr`；数据不完整时 provider 返回数据损坏
  错误，不得静默丢一个 IP。
- `nodes` 按 `relay_id` 稳定排序，便于测试、缓存和快照比较。
- `revision` 在 node 身份、status、两个 IP 或 DNS 可见属性改变时单调递增。
- `if_revision` 仅用于判断快照是否变化：命中时可返回明确的 not-modified；未命中时
  必须返回完整快照，不能返回从旧 revision 到新 revision 的 delta。
- 该接口返回内部拓扑，只允许 `sn-dns`、`sn-api`、`sn-relay` 等受信服务调用，
  不挂到公开 `/kapi/sn/auth`。

## 7. 注册与自动分配事务

目标注册路径：

```text
auth.register
  -> BNS bootstrap 成功
  -> AuthDB register user（携带 preferred_region 和服务端观察 source_ip）
  -> AuthDB 同一业务事务内：
       创建 user/auth/zone_info
       调用内部 relay_manager 选择 node
       成功：写 relay_assignments
       暂无 node：写 relay_allocation_pending
       提交 user + assignment/pending
  -> 返回 auth session
```

要求：

- source IP 仍由 SN HTTP/process-chain 上下文产生，客户端 RPC params 不能指定。
- region 仍是不可信 hint，不能直接指定 `relay_id`。
- relay 不可用不能回滚已经完成的 BNS bootstrap，也不能使本地账号处于未知状态。
- 注册 provider 响应应明确区分 `assigned` 与 `pending`，不能仅靠日志表达。
- pending worker 由 AuthDB provider 内部运行；node 恢复或注册后应触发重试。
- 多个 `sn-api` 副本并发注册/补偿同一 zone 时，数据库约束必须保证只产生一个当前
  assignment，并返回同一 generation。
- assignment 成功与 userinfo 可见性在同一提交后生效，不再调用
  `sync_zone_relay_cache -> update_zone_relay_sn`。

如现有 `register_user` contract 不适合承载分配提示，可增加
`register_user_with_relay_allocation` 高层接口；不要在 SN API 侧恢复本地选择逻辑。

## 8. Web3 SN DNS 解析

### 8.1 数据读取

Web3 SN resolver 的 relay 路径改为：

1. 通过 AuthDB user/zone info 得到当前 `relay_id`、state 和 generation。
2. 从 `get_relay_nodes_ip_map` 的本地有界 TTL 快照中按 `relay_id` 找到两个 IP。
3. 快照没有该 `relay_id` 时立即刷新一次；刷新后仍不存在则返回结构化
   `BackendUnavailable`，不能回退到任意当前 SN 的 `server_ip`。
4. node map 缓存只保存可丢弃快照；assignment 仍来自 AuthDB 权威查询。

可选的后续优化是增加一个事务性 `get_zone_relay_route` 接口，一次返回 assignment
与两个 IP；第一版仍必须保留完整 node IP map 接口，以支持 DNS 副本缓存和批量解析。

### 8.2 地址选择

现有直接地址优先级保持不变：

1. BNS `zone.gateway_ips`
2. user_domain 显式 A/AAAA
3. 可直接到达的 gateway/device 地址
4. 需要 relay 时，使用该 user/zone assignment 对应 node 的两个 IP

relay 地址的 DNS 规则：

| Node 的两个 IP | A 查询 | AAAA 查询 |
| --- | --- | --- |
| 两个 IPv4 | 返回两个 IPv4 | 权威 NODATA |
| 一个 IPv4、一个 IPv6 | 返回 IPv4 | 返回 IPv6 |
| 两个 IPv6 | 权威 NODATA | 返回两个 IPv6 |

附加要求：

- A 只返回 `IpAddr::V4`；AAAA 只返回 `IpAddr::V6`。
- 同一 RRset 去重并保持稳定顺序；不得把 IPv4-mapped IPv6 错发为 A。
- 没有请求地址族属于正常 NODATA，不是 NXDOMAIN，也不是后端错误。
- relay-required user 缺少 assignment、assignment 指向未知 node、node address
  数据损坏或 AuthDB 不可用时返回 `TemporaryFailure/SERVFAIL`，不得把流量导向
  其它 relay。
- 已有 assignment 的 Draining node 在迁移窗口内是否继续进入 DNS，沿用 assignment
  state/migration 规则；新 assignment 仍只能选择 Active node。
- DNS TTL 不能超过 assignment/node-map 的有效期；node IP 或 assignment revision
  变化后必须能够在有界时间内刷新。
- 删除当前 resolver 的 relay 路径对 legacy `get_user_sn_ips` 和
  `config.server_ip` 的依赖。

## 9. 本地 SQLite 与生产 provider

### 9.1 本地开发模式

- `SqliteSnAuthDB::initialize_database` 同时创建 auth 和 relay 控制面表。
- SQLite AuthDB 内部实现 relay manager 的选择与事务逻辑。
- `SNServer` 只持有 `SnAuthDBRef`，不再额外创建 `SqliteSnRelayManager`。
- 本地和 remote contract 使用同一组 request/response 类型与 contract tests。

### 9.2 生产模式

- `sn-business` 的 AuthDB/PostgreSQL provider 增加 relay schema 和内部 manager。
- `sn-api`、`sn-dns`、`sn-relay` 通过同一个 AuthDB S2S URL 与服务身份访问。
- cluster 模式禁止创建本地 relay SQLite、WAL 或 pending 文件。
- provider 对 assignment 使用数据库事务、唯一约束或行锁保证跨副本一致性。
- node-map revision 使用数据库中的单调序列/版本，不使用单进程内原子计数。

## 10. 数据迁移与切换

- [x] 为现有 `relay_nodes`、`relay_assignments`、`relay_allocation_pending`、
  `relay_admission_events` 定义一次性迁移工具或 provider seed/import 格式。
- [x] 通过 `relay_sn` 把旧 `zone_info.relay_sn` 解析为稳定 `relay_id`；无法匹配的用户
  写入 pending/修复清单，禁止静默绑定到 fallback node。
- [ ] 旧 relay node 没有显式双 IP 时必须由部署配置补齐两个 IP；不得通过运行时 DNS
  解析 `public_host` 自动生成权威映射。（代码已禁止 fallback；部署数据待补齐。）
- [x] 导入前验证每个可服务 node 恰好两个 IP，并覆盖 IPv4-only、IPv6-only 和双栈。
- [x] 切换读路径到 AuthDB 后停止写本地 relay 表和 `zone_info.relay_sn` 缓存。
- [x] 删除 `SNServer` 本地 relay manager 初始化路径；商用切换前仍需确认无旧版本
  进程继续双写。
- [ ] Beta2.2 为 breaking change，不保留无限期 dual-read/dual-write 兼容。

## 11. 实施清单

### A. 共享类型与 schema `[cyfs-gateway]`

- [x] 为 relay node 增加两个类型化 IP 的共享 contract。
- [x] 增加 `UserRelayInfo`，并接入 `SNUserInfo` / `ZoneInfo`。
- [x] 把 relay assignment 的权威关联改为 `relay_id`，消除重复 `relay_sn` 真相。
- [x] 将 relay 控制面 schema 纳入 `SqliteSnAuthDB` 初始化与迁移。
- [x] 为 node-map revision 增加持久化 schema。

### B. AuthDB trait 与 S2S contract `[cyfs-gateway]`

- [x] 在 `SnAuthDB` 或其内部 relay 子接口增加 allocation、node、migration、
  admission 和 map 查询能力。
- [x] 为 `SnAuthDbClient` 实现所有 relay S2S 转发。
- [x] 为 AuthDB RPC handler 增加对应 method dispatch 和结构化错误。
- [x] 增加 `sn_auth_db.get_relay_nodes_ip_map` 与 revision/not-modified 语义。
- [x] 收敛 `update_zone_relay_sn` 为只读投影保护：旧入口保留兼容错误，不再允许写入。

### C. Provider 内部 relay manager `[跨仓]`

- [x] 将 `SqliteSnRelayManager` 收为 AuthDB provider 内部模块并复用同一连接池和事务
  逻辑，未复制第二套选择算法。
- [x] 在本地 SQLite AuthDB 实现内部 relay manager。
- [ ] 在 `sn-business` PostgreSQL AuthDB provider 实现相同 contract。
- [ ] 在 PostgreSQL provider 落地跨进程 assignment 锁和常驻 pending/heartbeat
  worker。（SQLite 已实现唯一约束、并发幂等、node 恢复触发 pending 补偿和迁移。）
- [ ] 对 node 注册、heartbeat、admin mutation 和只读 map API 实施服务角色鉴权。

### D. SN server 清理 `[cyfs-gateway]`

- [x] `auth.register` 改为调用 AuthDB 的带 relay allocation 注册/分配接口。
- [x] 从 `SNServer` 删除独立 `SnRelayManagerRef` 和本地 manager 装配。
- [x] resolver、admission 和 migration 调用改为走 `SnAuthDBRef`。
- [x] cluster 模式不再解析或打开 relay `db_path`。
- [x] 删除本地 `sync_zone_relay_cache` 双写路径。

### E. DNS 双栈接线 `[cyfs-gateway]`

- [x] 为 resolver 增加 AuthDB relay-node-map reader 和有界 TTL/revision cache。
- [x] 需要 relay 时按 user assignment 的 `relay_id` 查两个 IP。
- [x] 删除 relay 路径的 `sn_ips` / 当前 `server_ip` fallback。
- [x] A/AAAA 严格按 `IpAddr` 地址族过滤。
- [x] 接入结构化 NODATA、SERVFAIL 和 authority metadata。
- [x] node IP/assignment 更新后使相关 DNS cache 在有界时间内失效。

### F. 商用部署 `[sn-business]`

- [ ] AuthDB provider schema 和 migration 增加所有 relay 表及两个 IP。
- [ ] 更新 `sn_api.yaml`、`sn_dns.yaml`、`sn_relay.yaml` 的 provider 权限和配置。
- [ ] relay node 启动注册必须提交两个 IP。
- [ ] DNS 角色获得 map/userinfo 只读权限，不获得 node mutation/admin 权限。
- [ ] 移除独立 relay manager URL/PVC/部署计划。

## 12. 测试要求

### 12.1 Contract 与数据库

- [x] SQLite in-process 与 remote KRPC 的 request/response contract 一致。
- [x] 一个 node 少于或多于两个 IP 时注册失败。
- [x] 两 IPv4、两 IPv6、IPv4+IPv6 都能序列化、持久化并无损读回。
- [x] 非法 IPv4/IPv6、带端口字符串、zone index 等非 canonical 输入被拒绝。
- [x] 两个 IP 事务更新期间不会暴露半个快照。
- [x] node map revision 在相关 mutation 后单调递增，普通 heartbeat 仅在 DNS 可见字段
  改变时推进 revision。
- [x] revision 变化后返回全部非 deleted node；不支持分页、过滤或 delta 响应。
- [x] 多调用方并发为同一 user/zone 分配时得到同一个 relay_id/generation。
- [x] user/auth 与 assignment/pending 同事务提交；userinfo、zone info 和 assignment
  在提交后保持一致。

### 12.2 DNS

- [x] 两 IPv4：A 返回两条，AAAA 返回权威 NODATA。
- [x] IPv4+IPv6：A/AAAA 各返回对应地址。
- [x] 两 IPv6：AAAA 返回两条，A 返回权威 NODATA。
- [x] assignment 指向未知 node 时返回 SERVFAIL，不回退当前 SN IP。
- [x] map cache miss 会刷新一次；revision 未变化不重复下载完整快照。
- [x] node IP 更新后，在约定 TTL 内 DNS reader 返回新地址。
- [x] BNS `gateway_ips` 或用户直连地址存在时，不错误注入 relay IP。
- [x] IPv4-mapped IPv6、重复 IP 和地址顺序有稳定、明确的行为。

### 12.3 端到端

- [ ] `auth.register` 在副本 A 完成，副本 B 查询 userinfo 能看到同一 relay assignment。
- [x] `sn-dns` 根据 assignment 返回被分配 node 的 A/AAAA。
- [x] relay node IP 更新后无需重启 SN/DNS。
- [x] relay node 恢复/注册时 pending 由 SQLite AuthDB provider 补偿，成功后
  userinfo 投影立即可见。
- [ ] 只读 root filesystem、无本地 SQLite/PVC 的 cluster 模式通过测试。

## 13. 验收标准

- 生产 `SNServer` 不再创建或读取本地 relay 控制面表。
- AuthDB provider 是 relay node、双 IP 和 user/zone assignment 的唯一共享真相源。
- userinfo/zone info 查询能直接读到当前 relay node，不依赖异步
  `update_zone_relay_sn`。
- `get_relay_nodes_ip_map` 返回每个非 deleted node 及恰好两个类型化 IP，并有可缓存的
  单调 revision。
- Web3 SN 的 A/AAAA 结果来自用户实际 assignment 对应的 node；不会使用任意 SN
  `server_ip` 或其它 relay。
- IPv4-only、IPv6-only 和双栈 node 均符合 DNS 响应矩阵。
- 多副本并发、node IP 更新和 assignment 迁移不会产生跨副本分裂或长期脏缓存。
- cluster 模式运行期不产生 `sn.sqlite3`、WAL、SHM 或其它 relay 本地持久化文件。
