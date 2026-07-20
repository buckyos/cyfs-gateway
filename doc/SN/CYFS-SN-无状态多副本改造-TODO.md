# CYFS-SN 无状态多副本改造 TODO

状态：TODO

相关文档：

- [新SN核心流程整理.md](./新SN核心流程整理.md)
- [SN-Auth.md](./SN-Auth.md)
- [SN-Relay.md](./SN-Relay.md)
- [SN部署Node整理.md](./SN部署Node整理.md)
- [`web3_dns.yaml`](../../src/web3-gateway/web3_dns.yaml)
- [`web3_relay.yaml`](../../src/web3-gateway/web3_relay.yaml)
- [`web3_sn_api.yaml`](../../src/web3-gateway/web3_sn_api.yaml)

## 1. 背景

Web3 Gateway 已把主要部署角色拆分为：

- `web3_dns`：DNS 查询入口；
- `web3_relay`：HTTP/TLS/RTCP 流量入口和设备中继；
- `web3_sn_api`：SN RPC、DID Resolver 和 Web2 兼容 BNS Gateway。

账号与设备主数据已具备 remote S2S 接口：`db_type=postgres`
时，`cyfs-sn` 使用 `SnAuthDbClient` 和 `SnDeviceInfoDbClient` 访问远程
provider。这解决了账号、session 记录和设备在线态的主要共享存储问题。

但 `type: sn` 当前仍会无条件初始化本地 token key、compatibility store、
relay manager 和 BNS 写入运行态。所以“部署角色已拆分”并不等于
`cyfs-sn` 已经是无状态服务。

## 2. 目标

生产 cluster 模式下，`web3_sn_api` 可以部署多个对等副本，并满足：

- 不需要本地 SQLite；
- 不需要可写数据目录或 PVC；
- 不在本地生成或保存 SN access/refresh token 私钥；
- 任意副本都能处理登录、refresh、logout 和已认证请求；
- 副本重启或调度到新节点不丢失业务状态；
- 副本间不依赖 sticky session；
- 只保留可丢弃、可重建的进程内缓存和指标。

`web3_dns` 和 `web3_relay` 内部所需的 SN resolve/authority 能力也应是只读、
无状态的 adapter，不应因为当前 `resolve` / `qa` 只支持进程内调用，就被迫
初始化完整的有状态 `SNServer`。

## 3. 非目标和已确认边界

- BNS 权威真相源仍在智能合约；本改造不引入第二个 BNS 权威数据库。
- `bns-indexer` 仍是合约事件的只读投影，可重建，不成为 SN 本地真相源。
- 不把 DNS 入口或流量转发重新合并回 `web3_sn_api`。
- 不要求多副本共享进程内 DNS/BNS 读缓存；缓存只需有正确的 TTL 和失效语义。
- 可以保留 `db_type=sqlite` 的单机开发/all-in-one 模式，但必须与生产
  cluster 模式明确隔离。
- 本改造不保留本地 compatibility 数据兼容，不设计新的 compatibility
  迁移层。

## 4. 当前本地状态清单

| 状态 | 当前位置 | remote DB 模式是否仍使用 | 性质 | 目标归属 |
|---|---|---:|---|---|
| SN JWT 私钥/公钥 | `auth_data_dir/private_key.pem`、`public_key.json` | 是 | 认证关键状态 | `sn_auth` |
| 账号和 session 记录 | `SnAuthDB` | 否，已可 remote | 业务状态 | `sn_auth` |
| 设备在线态 | `SnDeviceInfoDB` | 否，已可 remote | 运行态 | `sn_device_info` |
| legacy device/DID/DNS | `SqliteSnCompatibilityStore` | 是 | 历史兼容状态 | 删除 |
| relay node/assignment/pending/admission | `SqliteSnRelayManager` | 是 | 共享运行态 | `sn_relay_manager` |
| BNS 写请求幂等记录 | `sn_bns_write_requests` | 是 | 非权威操作状态 | BNS/controller 服务 |
| username -> controller 绑定 | `sn_bns_controller_bindings` | 是 | Web2 兼容路由状态 | BNS/controller 服务或可重建映射 |
| DNS/name cache | 进程内 `HashMap` | 是 | 可丢弃缓存 | 保留本地 |
| EVM next nonce cache | 进程内 `HashMap` | 是 | 并发协调状态 | BNS/controller 服务 |

当前 `db_type=postgres` 只替换 `auth_db` 和 `device_info_db`。随后
`SnServerFactory` 仍使用同一个 `db_path` 无条件打开 compatibility、relay 和 BNS
相关 SQLite store。

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
        ---------------->| cyfs-sn API replica A/B/C                |
                         | routing + validation + orchestration     |
                         | no SQLite, no writable business files    |
                         +----+----------------+----------------+---+
                              |                |                |
                         +----v-----+    +-----v------+   +-----v----------+
                         | sn_auth  |    | device-info|   | relay manager  |
                         | token +  |    | shared DB  |   | shared state   |
                         | account  |    +------------+   +----------------+
                         +----------+
```

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
2. `cyfs-sn` 通过 `sn_auth` JWKS 验签，JWKS 可做短 TTL 内存缓存；
3. 需要立即撤销语义时，继续查询共享 session 状态，或调用 introspection；
4. 验证成功后只向业务模块传递 `AuthContext`。

### 5.3 `sn_relay_manager`

DNS 和 relay 数据面虽然已拆分，relay 控制状态目前仍在 `cyfs-sn`
本地 SQLite 中。`sn_relay_manager` 应使用共享存储并提供 remote API，统一负责：

- relay node 注册、心跳、容量和健康状态；
- zone -> relay assignment；
- sticky assignment、迁移、pending 和失败补偿；
- relay admission 判定所需的共享状态。

`cyfs-sn` 注册流程只调用 remote relay manager，不再打开
`SqliteSnRelayManager`。

### 5.4 BNS Web2 兼容写路径

BNS 真相源保持在合约。`sn_bns_write_requests` 和
`sn_bns_controller_bindings` 不是权威数据，但当前会影响幂等重试、交易
nonce 恢复和 controller 选择，不能作为每个 `cyfs-sn` 副本的私有状态。

推荐边界：

- `cyfs-sn` 只把 Web2 兼容写请求转交给独立 BNS/controller 服务；
- request-id 幂等、controller binding、nonce 分配和交易恢复由该服务统一处理；
- `cyfs-sn` 仅消费提交结果和合约/indexer 最终状态；
- 不修改 BNS 合约的权威模型。

## 6. 实施任务

### A. 删除 compatibility store

- [ ] 删除 `SqliteSnCompatibilityStore` 和
  `AuthDbRoutedSnCompatibilityStore`。
- [ ] 删除 `LegacyResolverCompatibilityReader`。
- [ ] 删除 `SNServer.compat_store` 字段及其 accessor。
- [ ] 删除 `devices`、`user_dns_records`、`did_documents` compatibility schema
  初始化代码。
- [ ] device 查询只读 `SnDeviceInfoDB` 和 BNS `device_mini_doc`。
- [ ] DID document 查询只读 BNS/indexer，不再回退到本地 SQLite。
- [ ] user DNS RRset 只读写 remote `sn_auth` 提供的共享存储。
- [ ] 删除 compatibility 专用测试和旧数据迁移分支；需要的业务用例改为
  BNS/remote provider fixture。
- [ ] 更新 API 文档，明确不再支持仅存在于旧 SN SQLite 的 device/DID
  数据。

### B. 把 token 生命周期收回 `sn_auth`

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

### C. 改造 `sn_authority`

- [ ] 为 SN 用户 token 增加 `kid`、`iss`、`aud`、`sub`、`jti`、`iat`、`exp`
  的明确校验规则。
- [ ] 从 `sn_auth` JWKS 加载公钥，只做有界 TTL 的可丢弃内存缓存。
- [ ] 对未知 `kid` 允许一次受控 JWKS refresh，但不允许降级为不验签。
- [ ] 把 session 撤销检查改为 remote `sn_auth` 状态查询或 introspection。
- [ ] 定义 `sn_auth` 不可用时的 fail-closed 规则；不得因为远程超时就
  把 token 当作有效。
- [ ] 业务 API 只消费归一化后的 `AuthContext`，不重复处理 JWT/session。

### D. 远程化 relay manager 控制状态

- [ ] 为 `SnRelayManager` 提供生产 remote client/server 实现。
- [ ] relay manager provider 使用共享数据库，为 zone assignment 和 relay node
  心跳提供跨副本一致的并发约束。
- [ ] `auth.register` 中的 relay allocation 改为调用 remote manager。
- [ ] 从生产 `cyfs-sn` 初始化路径移除 `SqliteSnRelayManager`。
- [ ] 明确 assignment 的权威状态和 BNS `relay_assignment` 文档、
  `sn_auth.zone_info.relay_sn` 缓存之间的投影/恢复规则。
- [ ] 多个 `web3_sn_api` 并发为同一 zone 分配 relay 时必须返回同一有效
  assignment，不得分裂。

### E. 消除 BNS 写路径对 SN 本地 SQLite 的依赖

- [ ] 将 `sn_bns_write_requests` 的 request-id 幂等与交易恢复移入独立
  BNS/controller 服务。
- [ ] 将 controller nonce 分配收敛到可跨副本协调的单一边界。
- [ ] 将 `sn_bns_controller_bindings` 迁移到该服务，或设计为从统一配置/
  链上 controller policy 可确定重建的映射。
- [ ] `cyfs-sn` BNS gateway 只做认证、参数校验和转发，不在本地保存
  pending/succeeded/failed 交易状态。
- [ ] 相同 request-id 通过不同 `cyfs-sn` 副本提交时，只能产生一个业务
  意图或返回已有结果。
- [ ] 保持“合约是 BNS 真相源”；本步不把幂等库提升为权威数据库。

### F. 按部署角色初始化能力

- [ ] 为 `type: sn` 增加明确的 cluster/role 能力选择，或拆成更小的
  server/adapter type，避免所有角色都构造完整 `SNServer`。
- [ ] `web3_sn_api` 只初始化 API gateway、resolver client、authority client 和
  remote provider clients。
- [ ] `web3_dns` 的进程内 `resolve` adapter 只初始化 BNS/remote provider 只读依赖
  和内存缓存。
- [ ] `web3_relay` 的进程内 `qa`/authority adapter 只初始化设备身份与准入
  查询所需的只读依赖。
- [ ] resolver-only/authority-only 角色不得初始化 token issuer、BNS writer 或
  relay allocation writer。
- [ ] 允许在生产只读角色中禁用 BNS proxy；当前
  `bns_proxy.enabled=false` 的启动限制需按角色放开。

### G. 生产 cluster 配置和文件系统不变量

- [ ] 增加明确的 cluster/remote 生产模式，不再仅通过名为
  `db_type=postgres` 的开关隐式表达“所有状态已远程化”。
- [ ] cluster 模式启动时禁止 fallback 到本地 SQLite。
- [ ] cluster 模式启动时校验 `sn_auth`、`sn_device_info`、
  `sn_relay_manager` 等必需 remote endpoint 的 readiness。
- [ ] cluster 模式下不解析、创建或打开 `db_path`。
- [ ] cluster 模式下不创建 `auth_data_dir`、`private_key.pem`、
  `public_key.json` 或任何其它业务状态文件。
- [ ] 所有本地文件依赖仅限于只读配置、证书、Secret 和 GeoIP 数据。
- [ ] 生产配置不包含 `seed_path`；种子数据从 provider 端导入。
- [ ] 更新 `web3_dns.yaml`、`web3_relay.yaml`、`web3_sn_api.yaml`
  及生成脚本，显式配置各角色。

### H. 可观测性和测试

- [ ] 启动时输出一条不含 secret 的状态归属摘要，例如：
  `mode=cluster auth=remote device_info=remote relay=remote local_persistent_state=none`。
- [ ] 对意外打开 SQLite、自动生成 token key 或回退本地 provider 记录明确错误。
- [ ] provider 调用指标至少包含 latency、timeout、error code、circuit state，
  不记录 token、密码或完整凭证。
- [ ] 增加两个以上 `cyfs-sn` API 副本的端到端测试，请求经负载均衡
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

1. 删除 compatibility store 和所有本地 fallback，缩小状态面。
2. 把 token 签发、refresh、revoke 和私钥管理移入 `sn_auth`。
3. 改造 `sn_authority`，使其消费 JWKS/introspection 并输出统一 `AuthContext`。
4. 远程化 relay manager，移除 `cyfs-sn` 本地 relay SQLite。
5. 将 BNS Web2 兼容写入的幂等、binding 和 nonce 协调收敛到 BNS/controller
   服务。
6. 增加角色化初始化，让 DNS/relay 的进程内 adapter 不构造无关的有状态
   能力。
7. 启用 cluster 模式的只读文件系统验收和多副本端到端测试。

## 8. 验收标准

- `web3_sn_api` 三副本在无共享磁盘、无 sticky session 条件下通过所有
  register/login/refresh/logout/device/BNS 兼容流程。
- cluster 模式下，`cyfs-sn` 不创建、打开或修改任何 SQLite 数据库。
- cluster 模式下，`cyfs-sn` 不生成 token 私钥或其它业务状态文件。
- 任意副本签发后的 token 均可在其它副本使用，且撤销结果对全部副本
  立即生效。
- relay node 和 zone assignment 不因 API 副本切换而变化或分裂。
- BNS 权威结果只由合约/indexer 决定；本地缓存丢失不会改变权威结果。
- 相同 BNS 兼容写请求经不同 API 副本重试时不会因副本私有状态而
  重复产生业务意图。
- `web3_dns` 和 `web3_relay` 的进程内 SN adapter 不写本地 SQLite/token key。
- 单机 SQLite 开发模式仍可使用，但不能在 cluster 模式中静默启用。

## 9. 完成定义

当以下语句成立时，本 TODO 才能标记为 DONE：

> 生产 cluster 模式的 `cyfs-sn` 副本只依赖远程权威/共享服务和只读
> 配置；删除任意一个副本的本地文件系统，不会丢失业务状态、破坏幂等性
> 或影响其它副本继续处理请求。
