# CYFS-SN 无状态多副本改造 TODO

状态：TODO（2026-07-22 按现有实现复核）

相关文档：

- [新SN核心流程整理.md](./新SN核心流程整理.md)
- [SN-Auth.md](./SN-Auth.md)
- [SN-Relay.md](./SN-Relay.md)
- [SN-AuthDB内置RelayManager与DNS双栈解析-TODO.md](./SN-AuthDB内置RelayManager与DNS双栈解析-TODO.md)
- [SN部署Node整理.md](./SN部署Node整理.md)
- [CYFS-SN-配置收敛-TODO.md](./CYFS-SN-配置收敛-TODO.md)
- [SN-API.md](./SN-API.md)
- [`cyfs-sn`](../../src/components/cyfs-sn/)

商用产品侧相关目录（位于独立的 `sn-business` 仓库，不属于本仓库）：

- `src/apps/sn_gateway/`：`sn_gateway` 可执行程序装配、`sn_api.yaml`、
  `sn_dns.yaml`、`sn_relay.yaml` 和三个配置渲染器；
- `CD/cluster_config/nightly/`：`sn-api`、`sn-dns`、`sn-relay` 的部署、调度和
  同版本约束；
- `src/modules/sn_db_provider/`、`src/apps/sn_db_provider_app/`：账号、session、
  user DNS 和设备在线态的 PostgreSQL provider 与 S2S 服务。

> 仓库边界：SN 的业务部署拆分已经从本仓库原
> `src/web3-gateway/web3_{sn_api,dns,relay}.yaml` 迁移到商用产品仓库
> `sn-business/src/apps/sn_gateway/`。本仓库只继续维护通用 `type: sn` 能力、
> 配置契约、remote client 和可复用测试；商用配置、provider 部署与集群验收在
> `sn-business` 完成。

## 0. 本次复核结论

已经完成的基础工作：

- [x] 商用产品已提供独立的 `sn_gateway` 装配，并把业务部署拆成 `sn-api`、
  `sn-dns`、`sn-relay` 三个 App；三者复用同一版本的 `sn_gateway` 二进制。
- [x] `auth_db` 与 `device_info_db` 已成为相互独立的 remote provider URL；
  两者都缺省时仍保留本地 SQLite 开发模式。
- [x] 账号、session、user DNS 和设备在线态已有 S2S contract/client；商用
  `sn_db_provider` 已提供对应 PostgreSQL 实现。
- [x] `bns_proxy` 已改为可选；未配置时是 BNS 只读模式，不初始化 BNS write
  request/controller binding store。
- [x] `ip` 已可选，BNS 地址已收敛为必填 `bns_server_url`，配置使用
  `deny_unknown_fields` 拒绝旧字段和拼写错误。

尚未实现的关键部分：

- `SnServerFactory` 仍总是解析 `db_path` 并打开 compatibility 和 relay SQLite；
- AuthDB provider 尚未内置 relay manager、relay 控制面表和 node 双 IP
  查询 contract；
- `SNServer::new` 仍总是创建本地 token key 目录和密钥；
- `type: sn` 仍一次性注册 NameServer、HttpServer、QAServer 三种能力，没有
  resolver-only/authority-only/API role；
- 配置 `bns_proxy` 的 API 实例仍把 BNS 幂等、controller binding 和 nonce 协调
  保存在本地；
- 当前 `cyfs-sn` remote client 固定不携带 session token，而商用
  `sn_db_provider_app` 在非 loopback 监听时要求 provider token；生产访问控制契约
  尚未对齐；
- 商用三套配置和渲染器仍需按当前 Beta2.2 字段完成迁移与启动验收；业务角色拆分
  已完成，但不代表运行时已经无状态。

## 1. 背景

商用 `sn-business` 已把主要部署角色拆分为：

- `sn-dns`（`sn_dns.yaml`）：DNS 查询入口；
- `sn-relay`（`sn_relay.yaml`）：HTTP/TLS/RTCP 流量入口和设备中继；
- `sn-api`（`sn_api.yaml`）：SN RPC、DID Resolver 和 Web2 兼容 BNS Gateway。

三个角色只在部署和流量入口层完成了拆分：它们复用同一个 `sn_gateway` 产物，
并且各自仍配置一个进程内 `type: sn` server。由于 `resolve` / `qa` 目前只支持
进程内引用，DNS 和 relay 角色仍会进入与 API 角色相同的 `SnServerFactory` 初始化
路径。

账号与设备主数据已具备 remote S2S 接口：分别配置 `auth_db` 和
`device_info_db` 时，`cyfs-sn` crate 使用 `SnAuthDbClient` 和
`SnDeviceInfoDbClient` 访问远程 provider。这解决了账号、session 记录和设备
在线态的主要共享存储问题；两个 backend 可以独立选择。

但 `type: sn` 当前仍会无条件初始化本地 token key、compatibility store 和
relay manager；配置 `bns_proxy` 时还会初始化 BNS 写入运行态。所以“部署角色已
拆分”并不等于 `cyfs-sn` crate 已经是无状态服务。

## 2. 目标

生产 cluster 模式下，商用 `sn-api` 可以部署多个对等副本，并满足：

- 不需要本地 SQLite；
- 不需要可写数据目录或 PVC；
- 不在本地生成或保存 SN access/refresh token 私钥；
- 任意副本都能处理登录、refresh、logout 和已认证请求；
- 副本重启或调度到新节点不丢失业务状态；
- 副本间不依赖 sticky session；
- 只保留可丢弃、可重建的进程内缓存和指标。

`sn-dns` 和 `sn-relay` 内部所需的 SN resolve/authority 能力也应是只读、
无状态的 adapter，不应因为当前 `resolve` / `qa` 只支持进程内调用，就被迫
初始化完整的有状态 `SNServer`。

## 3. 非目标和已确认边界

- BNS 权威真相源仍在智能合约；本改造不引入第二个 BNS 权威数据库。
- `bns-indexer` 仍是合约事件的只读投影，可重建，不成为 SN 本地真相源。
- 不把 DNS 入口或流量转发重新合并回 `sn-api`。
- 不要求多副本共享进程内 DNS/BNS 读缓存；缓存只需有正确的 TTL 和失效语义。
- 可以保留两个 remote URL 均缺省的本地 SQLite 单机开发/all-in-one 模式，但必须与生产
  cluster 模式明确隔离。
- 本改造不保留本地 compatibility 数据兼容，不设计新的 compatibility
  迁移层。

## 4. 当前本地状态清单

| 状态 | 当前实现 | remote auth/device 模式是否仍使用 | 性质 | 目标归属 |
|---|---|---:|---|---|
| SN JWT 私钥/公钥 | `SnAuthManager` 在 `auth_data_dir` 创建 `private_key.pem`、`public_key.json` | 是，所有角色 | 认证关键状态 | `sn_auth` |
| 账号、session、user DNS | `SnAuthDB`；可由 `SnAuthDbClient` 访问 remote provider | 否，已可 remote | 业务状态 | `sn_auth` |
| 设备在线态 | `SnDeviceInfoDB`；可由 `SnDeviceInfoDbClient` 访问 remote provider | 否，已可 remote | 运行态 | `sn_device_info` |
| legacy device/DID/DNS | `SqliteSnCompatibilityStore`；remote auth 时仅 user DNS 路由到 `SnAuthDB` | 是，仍总是打开 | 历史兼容状态 | 删除 |
| relay node/双 IP/assignment/pending/admission | `SqliteSnRelayManager` | 是，仍总是打开 | user/zone 关联的共享运行态 | AuthDB provider 内部 relay manager |
| BNS 写请求幂等记录 | `sn_bns_write_requests` | 仅配置 `bns_proxy` 时 | 非权威操作状态 | BNS/controller 服务 |
| username -> controller 绑定 | `sn_bns_controller_bindings` | 仅配置 `bns_proxy` 时 | Web2 兼容路由状态 | BNS/controller 服务或可重建映射 |
| DNS/name cache | 进程内 `HashMap` | 是 | 可丢弃缓存 | 保留本地 |
| EVM next nonce cache | 进程内 `HashMap` | 仅配置 `bns_proxy` 时 | 并发协调状态 | BNS/controller 服务 |

当前 `auth_db` / `device_info_db` 只替换对应的两个 backend。随后
`SnServerFactory` 仍使用同一个 `db_path` 无条件打开 compatibility 和 relay
SQLite；只有 BNS 相关 SQLite 已按 `bns_proxy` 是否存在改为条件初始化。

此外，`SnServerFactory` 目前只对 `bns_server_url` 执行启动 readiness probe，
不会在启动阶段探测 remote `auth_db` / `device_info_db`；remote provider 故障会在
首个业务请求时暴露。

## 5. 目标架构和职责边界

```text
                         +----------------------+
                         | BNS contract         |
                         | authoritative source |
                         +----------+-----------+
                                    |
                             events / RPC
                                    |
                         +----------v-----------+
                         | BNS server/indexer   |
                         +----------+-----------+
                                    |

 client/load balancer    +----------v------------------------------+
        ---------------->| sn_gateway / type:sn replica A/B/C       |
                         | routing + validation + orchestration     |
                         | no SQLite, no writable business files    |
                         +----+----------------+----------------+---+
                              |                |
                         +----v----------------v---+    +--------v---+
                         | AuthDB provider         |    | device-info|
                         | token/account/user DNS  |    | shared DB  |
                         | internal relay manager  |    +-----------+
                         | node 双 IP + assignment |
                         +-------------------------+
```

### 5.0 跨仓职责

| 工作 | `cyfs-gateway` | `sn-business` |
|---|---|---|
| `type: sn` 配置 schema、factory 和 role/capability 初始化 | 负责 | 消费固定版本 |
| remote AuthDB（含 relay）/device/BNS client contract | 负责通用 contract/client | 负责生产 provider/server 与共享存储 |
| `sn_gateway` 可执行程序、三角色 YAML 和渲染器 | 不再维护商用副本 | 负责 |
| cluster placement、Secret、只读文件系统和多副本部署 | 提供可验证的不变量 | 负责实施与验收 |
| 通用单元/contract 测试 | 负责 | 复用并补充 provider 测试 |
| 商用跨服务、多副本端到端测试 | 提供测试钩子 | 负责 |

本文后续任务以 `[cyfs-gateway]`、`[sn-business]` 或 `[跨仓]` 标明主要落点。

### 5.1 `sn_auth`

`sn_auth` 是完整认证服务，不再只是 `SnAuthDB` CRUD provider。负责：

- 用户名/邮箱/密码凭证和账号状态；
- access token 和 refresh token 签发；
- token 私钥保管和轮换；
- refresh、logout、session revoke 和用户全会话撤销；
- session 持久化与过期清理；
- 对外提供 JWKS/公钥集或 token introspection；
- 输出稳定的认证主体和 session 状态。

### 5.2 `sn_authority`

`sn_authority` 仍是无状态工具层，负责把不同凭证归一化为
`AuthContext`，不保存用户、session 或签名私钥。

SN 用户 token 验证建议使用：

1. `sn_auth` 独占私钥并签发带 `kid` 的 JWT；
2. `cyfs-sn` crate 通过 `sn_auth` JWKS 验签，JWKS 可做短 TTL 内存缓存；
3. 需要立即撤销语义时，继续查询共享 session 状态，或调用 introspection；
4. 验证成功后只向业务模块传递 `AuthContext`。

### 5.3 AuthDB 内部 `sn_relay_manager`

DNS 和 relay 数据面虽然已拆分，relay 控制状态目前仍在 `cyfs-sn` crate
本地 SQLite 中。目标上不再部署独立 remote relay manager；AuthDB provider
在同一个共享数据库和 S2S contract 内部实现 `sn_relay_manager`，统一负责：

- relay node 注册、心跳、容量和健康状态；
- 每个 relay node 的两个类型化 IPv4/IPv6 地址；
- zone -> relay assignment；
- sticky assignment、迁移、pending 和失败补偿；
- relay admission 判定所需的共享状态；
- user/zone info 的 assignment 投影；
- 供 Web3 SN DNS 使用的完整 `relay_nodes -> [IpAddr; 2]` 快照。

`type: sn` 注册、DNS 和 relay 准入流程统一调用 AuthDB S2S；不再打开
`SqliteSnRelayManager`，也不再通过异步 `update_zone_relay_sn` 维护第二份真相。
详细 contract、schema、DNS A/AAAA 语义和迁移计划见
[SN-AuthDB内置RelayManager与DNS双栈解析-TODO.md](./SN-AuthDB内置RelayManager与DNS双栈解析-TODO.md)。

### 5.4 BNS Web2 兼容写路径

BNS 真相源保持在合约。`sn_bns_write_requests` 和
`sn_bns_controller_bindings` 不是权威数据，但当前会影响幂等重试、交易
nonce 恢复和 controller 选择，不能作为每个 `type: sn` 副本的私有状态。

推荐边界：

- `type: sn` 只把 Web2 兼容写请求转交给独立 BNS/controller 服务；
- request-id 幂等、controller binding、nonce 分配和交易恢复由该服务统一处理；
- `type: sn` 仅消费提交结果和合约/indexer 最终状态；
- 不修改 BNS 合约的权威模型。

## 6. 实施任务

### A. 删除 compatibility store `[cyfs-gateway]`

- [ ] 删除 `SqliteSnCompatibilityStore` 和
  `AuthDbRoutedSnCompatibilityStore`。
- [ ] 删除 `LegacyResolverCompatibilityReader`。
- [ ] 删除 `SNServer.compat_store` 字段及其 accessor。
- [ ] 删除 `devices`、`user_dns_records`、`did_documents` compatibility schema
  初始化代码。
- [ ] device 查询只读 `SnDeviceInfoDB` 和 BNS `device_mini_doc`。
- [ ] DID document 查询只读 BNS/indexer，不再回退到本地 SQLite。
- [x] remote `auth_db` 模式下，user DNS RRset 已通过
  `AuthDbRoutedSnCompatibilityStore` 读写 `SnAuthDB` S2S provider。
- [ ] 删除 compatibility store 后，user DNS RRset 直接读写 `SnAuthDB`，不再经
  compatibility 抽象；本地单机模式仍由本地 `SnAuthDB` 实现同一 contract。
- [ ] 删除 compatibility 专用测试和旧数据迁移分支；需要的业务用例改为
  BNS/remote provider fixture。
- [ ] 更新 API 文档，明确不再支持仅存在于旧 SN SQLite 的 device/DID
  数据。

### B. 把 token 生命周期收回 `sn_auth` `[跨仓]`

- [x] `SnAuthDB` 和 remote S2S provider 已支持 account session 的 create、get、
  revoke session、revoke user sessions。
- [ ] 定义 `SnAuthService` 接口，与现有 `SnAuthDB` 存储接口区分。
- [ ] 提供 login/authenticate + issue tokens 接口。
- [ ] 提供 refresh 接口，refresh token 的验签、session 检查和新 access token
  签发均在 `sn_auth` 内完成。
- [ ] 提供 logout/revoke session/revoke user sessions 接口。
- [ ] 提供 JWKS 接口，支持 `kid`、密钥轮换和旧 token 的平滑验证窗口。
- [ ] 根据安全性和性能需求提供 token introspection/session status 接口。
- [ ] 将 `hash_password`、`verify_password`、token issue/refresh 逻辑从
  `cyfs-sn` 移入 `sn_auth`。
- [ ] `cyfs-sn` 删除 `SnAuthManager.token_encode_key` 和所有 access/refresh token
  签发代码。
- [ ] `cyfs-sn` 不再创建 `auth_data_dir`，不再自动生成
  `private_key.pem` / `public_key.json`。
- [ ] `sn_auth` 私钥来自集群 Secret/KMS 或等价安全存储，禁止每个
  `cyfs-sn` 副本各自生成。
- [ ] 确保账号冻结、logout 和会话撤销在所有 `cyfs-sn` 副本立即可见。
- [ ] provider 通信必须使用受信内网、mTLS 或等价服务身份验证，
  不允许公网匿名调用 token 签发接口。

### C. 改造 `sn_authority` `[cyfs-gateway]`

- [x] 已有统一 `AuthContext::SnUser` / `AuthContext::Device` 入口；受保护的 user、
  zone、device 和 DNS API 已通过 `require_sn_user*` 消费该上下文。
- [ ] 为 SN 用户 token 增加 `kid`、`iss`、`aud`、`sub`、`jti`、`iat`、`exp`
  的明确校验规则。
- [ ] 从 `sn_auth` JWKS 加载公钥，只做有界 TTL 的可丢弃内存缓存。
- [ ] 对未知 `kid` 允许一次受控 JWKS refresh，但不允许降级为不验签。
- [ ] 把 session 撤销检查改为 remote `sn_auth` 状态查询或 introspection。
- [ ] 定义 `sn_auth` 不可用时的 fail-closed 规则；不得因为远程超时就
  把 token 当作有效。
- [ ] token 改为 remote `sn_auth` 后，清理 `auth.refresh` / `auth.logout` 之外残留的
  JWT/session 直连逻辑，保持业务 API 只消费 `AuthContext`。

### D. 将 relay manager 收敛到 AuthDB provider `[跨仓]`

- [ ] 扩展 AuthDB S2S contract，由 provider 内部实现 `SnRelayManager` 领域逻辑；
  不增加独立 relay manager endpoint。
- [ ] AuthDB 共享数据库保存 relay node 双 IP、zone assignment、pending、
  admission 和 migration，为注册与 heartbeat 提供跨副本一致的并发约束。
- [ ] `auth.register` 中的 relay allocation 改为调用 AuthDB provider。
- [ ] user/zone info 返回 assignment 投影；删除 `zone_info.relay_sn` 异步双写真相。
- [ ] 增加完整 `relay_nodes -> [IpAddr; 2]` S2S 快照，Web3 SN DNS 按 assignment
  生成 A/AAAA。
- [ ] 从生产 `cyfs-sn` 初始化路径移除 `SqliteSnRelayManager`。
- [ ] 多个 `sn-api` 副本并发为同一 zone 分配 relay 时必须返回同一有效
  assignment，不得分裂。

### E. 消除 BNS 写路径对 SN 本地 SQLite 的依赖 `[跨仓]`

- [x] `bns_proxy` 缺失时已是合法只读模式，且不会创建
  `sn_bns_write_requests` / `sn_bns_controller_bindings`。
- [ ] 将 `sn_bns_write_requests` 的 request-id 幂等与交易恢复移入独立
  BNS/controller 服务。
- [ ] 将 controller nonce 分配收敛到可跨副本协调的单一边界。
- [ ] 将 `sn_bns_controller_bindings` 迁移到该服务，或设计为从统一配置/
  链上 controller policy 可确定重建的映射。
- [ ] `type: sn` BNS gateway 只做认证、参数校验和转发，不在本地保存
  pending/succeeded/failed 交易状态。
- [ ] 相同 request-id 通过不同 `sn-api` 副本提交时，只能产生一个业务
  意图或返回已有结果。
- [ ] 保持“合约是 BNS 真相源”；本步不把幂等库提升为权威数据库。

### F. 按部署角色初始化能力 `[跨仓]`

- [x] 商用产品已把 `sn-api`、`sn-dns`、`sn-relay` 声明为三个独立部署 App，
  并约束它们复用同一版本的 `sn_gateway` 产物。
- [ ] 为 `type: sn` 增加明确的 cluster/role 能力选择，或拆成更小的
  server/adapter type，避免所有角色都构造完整 `SNServer`。
- [ ] `sn-api` 只初始化 API gateway、resolver client、authority client 和
  remote provider clients。
- [ ] `sn-dns` 的进程内 `resolve` adapter 只初始化 BNS/remote provider 只读依赖
  和内存缓存。
- [ ] `sn-relay` 的进程内 `qa`/authority adapter 只初始化设备身份与准入
  查询所需的只读依赖。
- [ ] resolver-only/authority-only 角色不得初始化 token issuer、BNS writer 或
  relay allocation writer。
- [x] 允许在生产只读角色中不配置 BNS proxy；配置块缺失即只读。

### G. 生产 cluster 配置和文件系统不变量 `[跨仓]`

- [ ] 增加明确的 cluster/remote 生产模式，不再仅通过配置两个 remote backend
  隐式表达“所有状态已远程化”。
- [ ] cluster 模式启动时禁止 fallback 到本地 SQLite。
- [ ] cluster 模式启动时校验 AuthDB（含 relay capabilities）和
  `sn_device_info` 等必需 remote endpoint 的 readiness。
- [ ] 对齐 `cyfs-sn` remote client 与商用 `sn_db_provider_app` 的服务身份认证；
  当前 client 固定不发送 session token，而 provider 的非 loopback 模式要求 token，
  不能把两端分别完成误判为生产链路已经可用。
- [ ] cluster 模式下不解析、创建或打开 `db_path`。
- [ ] cluster 模式下不创建 `auth_data_dir`、`private_key.pem`、
  `public_key.json` 或任何其它业务状态文件。
- [ ] 所有本地文件依赖仅限于只读配置、证书、Secret 和 GeoIP 数据。
- [ ] 生产配置不包含 `seed_path`；种子数据从 provider 端导入。
- [ ] 在 `sn-business/src/apps/sn_gateway/` 更新 `sn_dns.yaml`、
  `sn_relay.yaml`、`sn_api.yaml` 和三个 `start_*.ts` 渲染器，显式配置各角色；
  本仓库不再恢复已删除的 `web3_{dns,relay,sn_api}.yaml`。
- [ ] 商用配置迁移到当前 Beta2.2 字段：使用 `bns_server_url`、`auth_db`、
  `device_info_db` 和 `bns_proxy.controllers`，删除 `bns_rpc_url`、`bns_evm`、
  `sn_db_provider` 等旧/未实现字段；渲染结果必须通过 `deny_unknown_fields`。
- [ ] 三个 `start_*.ts` 从注释/stub 变为可执行渲染器，输出与 YAML include
  文件名一致的参数文件，并增加参数完整性测试。

### H. 可观测性和测试 `[跨仓]`

- [x] 已有 auth/device backend 四种选择、remote client contract、remote device
  store 和 user DNS provider 路由的基础测试。
- [ ] 启动时输出一条不含 secret 的状态归属摘要，例如：
  `mode=cluster auth=remote device_info=remote relay=remote local_persistent_state=none`。
- [ ] 对意外打开 SQLite、自动生成 token key 或回退本地 provider 记录明确错误。
- [ ] provider 调用指标至少包含 latency、timeout、error code、circuit state，
  不记录 token、密码或完整凭证。
- [ ] 在 `sn-business` 增加两个以上 `sn-api` 副本的端到端测试，请求经负载均衡
  轮询发送。
- [ ] 用例：A 副本注册/登录，B 副本使用 access token，C 副本 refresh。
- [ ] 用例：A 副本 logout/revoke 后，B/C 副本立即拒绝旧 token。
- [ ] 用例：同一 request-id 分别进入不同副本，认证、relay 和 BNS 兼容写路径
  都保持幂等。
- [ ] 用例：杀死处理过请求的副本，新副本不依赖其本地目录即可继续
  处理请求。
- [ ] 在只读 root filesystem 和无 PVC 容器中运行 cluster 模式端到端测试。
- [ ] 检查运行期文件系统：不应出现 `sn.sqlite3`、`-wal`、`-shm`、
  token key 或其它未声明业务文件。

## 7. 建议实施顺序

1. 先在 `sn-business` 把三套 YAML 和渲染器迁移到当前 Beta2.2 配置契约，建立
   可启动、但仍有状态的三角色基线。
2. 在 `cyfs-gateway` 删除 compatibility store 和所有本地 fallback，缩小状态面。
3. 在 `sn-business` 提供完整 `sn_auth` service；在 `cyfs-gateway` 把 token
   签发、refresh、revoke 和私钥管理切换到该服务。
4. 改造 `sn_authority`，使其消费 JWKS/introspection 并输出统一 `AuthContext`。
5. 将 relay manager、控制面表和 node 双 IP 映射收敛到 AuthDB provider，
   移除 `type: sn` 本地 relay SQLite。
6. 将 BNS Web2 兼容写入的幂等、binding 和 nonce 协调收敛到 BNS/controller
   服务。
7. 增加角色化初始化，让 DNS/relay 的进程内 adapter 不构造无关的有状态
   能力。
8. 在 `sn-business` 启用 cluster 模式的只读文件系统验收和多副本端到端测试。

## 8. 验收标准

- `sn-api` 三副本在无共享磁盘、无 sticky session 条件下通过所有
  register/login/refresh/logout/device/BNS 兼容流程。
- cluster 模式下，`sn_gateway` 的 `type: sn` 不创建、打开或修改任何 SQLite
  数据库。
- cluster 模式下，`sn_gateway` 不生成 token 私钥或其它业务状态文件。
- 任意副本签发后的 token 均可在其它副本使用，且撤销结果对全部副本
  立即生效。
- relay node 和 zone assignment 不因 API 副本切换而变化或分裂。
- BNS 权威结果只由合约/indexer 决定；本地缓存丢失不会改变权威结果。
- 相同 BNS 兼容写请求经不同 API 副本重试时不会因副本私有状态而
  重复产生业务意图。
- `sn-dns` 和 `sn-relay` 的进程内 SN adapter 不写本地 SQLite/token key。
- `sn-business` 三套商用配置只使用当前 `SNServerConfig` 字段，渲染器和
  cluster-config 测试可证明所有必填参数均被注入。
- 单机 SQLite 开发模式仍可使用，但不能在 cluster 模式中静默启用。

## 9. 完成定义

当以下语句成立时，本 TODO 才能标记为 DONE：

> 生产 cluster 模式的 `sn_gateway` / `type: sn` 副本只依赖远程权威/共享服务和只读
> 配置；删除任意一个副本的本地文件系统，不会丢失业务状态、破坏幂等性
> 或影响其它副本继续处理请求。

完成时需要同时具备：

- `cyfs-gateway` 中通用能力、配置不变量和 contract 测试通过；
- `sn-business` 中商用 provider、三角色配置、只读文件系统和多副本端到端测试
  通过。

仅完成任一仓库，或仅完成 `sn-api` / `sn-dns` / `sn-relay` 的部署拆分，都不能把
本 TODO 标记为 DONE。
