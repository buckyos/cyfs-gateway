# CYFS-SN 配置收敛 TODO

状态：DONE（2026-07-22；原收敛项与新增 §6 均已实施）

Beta2.2 原配置收敛已完成。本文同时保留为破坏性迁移和验收记录，并追加
SN 自身 DNS bootstrap 字段可选化。除 §6 明确标记的追加项外，下文描述的
目标配置即当前配置，不再兼容被删除的旧字段。

本文档固化 Beta2.2 已完成的 SN 配置破坏性调整。Beta2.2 允许删除旧字段；
不保留多套字段的长期兼容分支。

## 1. 已确认的目标配置

```yaml
servers:
  web3_sn:
    id: web3_sn
    type: sn
    host: example.com

    # 三项均可选，只用于 host / sn.<host> / aliases 的兼容 TXT bootstrap。
    # 不属于 RTCP stack identity；只解析 *.web3.<host> 和 user-domain 的部署可省略。
    boot_jwt: eyJ...
    owner_pkx: ...
    device_jwt:
      - eyJ...

    # 可选。只有解析 SN 自身地址或需要 SN relay fallback 时才使用。
    ip: 203.0.113.10

    # 唯一 BNS server 地址，语义是不带 RPC path 的 origin/base URL。
    bns_server_url: http://bns-server:18080

    # 可选。配置后开启 BNS 写入/proxy 能力；缺省时 SN 以 BNS 只读模式运行。
    # BNS controller 与 proxy 配置收敛为一个块。
    bns_proxy:
      require_user_asset_owner: true
      controllers:
        - id: default
          private_key_env: BNS_SN_CONTROLLER_PRIVATE_KEY

    # 两个字段都可选、可独立配置。值是 remote provider base URL。
    # 缺省某字段时，该 backend 使用本地 SQLite 实现。
    auth_db: http://sn-auth-provider:8080
    device_info_db: http://sn-device-info-provider:8080

    # 仍用于其余本地 SQLite 状态，不再用来选择上述 backend。
    db_path: /var/lib/cyfs/sn.sqlite3
```

最终字段语义：

- `boot_jwt: Option<String>`；
- `owner_pkx: Option<String>`；
- `device_jwt: Vec<String>`，字段缺省时使用空数组；
- `ip: Option<String>`；
- `bns_server_url: String`；
- `bns_proxy: Option<SNBnsProxyConfig>`，controller key 只在此块配置；
- `auth_db: Option<String>`；
- `device_info_db: Option<String>`。

在本 TODO 讨论的运行时集成字段中，只有 `bns_server_url` 必须配置；
`boot_jwt`、`owner_pkx`、`device_jwt`、`ip`、`bns_proxy`、`auth_db` 和
`device_info_db` 均为可选。`host` 仍然必须配置，用于确定 SN hostname 和
唯一权威 zone `web3.<host>`。

`auth_db` / `device_info_db` 不包含 token、token file 或数据库 DSN。remote
provider 的访问控制采用部署环境的源 IP 认证；SN client 一律以
`session_token = None` 构造。

## 2. `ip` 改为可选配置

### 2.1 配置和启动

- 将 `SNServerConfig.ip` 改为 `Option<String>`。
- 未配置 `ip` 不影响 SN server 启动，也不影响不依赖 SN 地址的解析、
  认证和 BNS 请求。
- 如果显式配置了 `ip` 但不是合法 `IpAddr`，仍然在启动时返回
  `InvalidConfig`。“可选”不应吞掉拼写错误。
- `SnResolverConfig.server_ip` 改为 `Option<IpAddr>`。

### 2.2 运行时解析语义

只在下列分支需要取 `server_ip`：

1. `host` / `sn.<host>` / `aliases` 的 A/AAAA 自身解析；
2. 设备拓扑要求 SN relay，用户又没有 `sn_ips` 时；
3. 网关设备没有任何可导出地址，需要最终 SN relay fallback 时。

如果请求进入上述分支但 `server_ip` 为 `None`，返回明确的解析失败，不返回
空的成功结果，也不 panic。建议暂用不会进入 DNS negative cache 的
`SnResolverErrorKind::BackendUnavailable`，message 固定为
`SN server ip is not configured`。如实现者新增更准确的 error kind，必须保持同样的
“请求失败且不记 negative cache”语义。

需调整的函数包括：

- `SNServer::new` 中的 `ip` 解析；
- `SnResolverConfig::new`；
- `SnResolver::resolve_self_dns`：返回值改为 `SnResolverResult<DnsResolution>`；
- `SnResolver::resolve_gateway_addresses`：返回值改为
  `SnResolverResult<Vec<IpAddr>>`，并传递失败；
- 相关直接调用者和单元测试。

本次不顺带改变已配置 IP 的地址过滤策略；只实现 `server_ip` 缺省时的
显式失败传递，避免把无关 DNS 行为变更混入本次配置收敛。

## 3. 只保留 `bns_server_url`

### 3.1 配置语义

- 删除 `SNServerConfig.bns_rpc_url`，替换为 `bns_server_url`。
- `bns_server_url` 是 BNS server 的 origin/base URL，不携带 `/kapi/bns` path。
- SN 内部继续通过 `BnsRpcClient::new_bns_server_url(...)` 构造 client，由 client
  补全 `/kapi/bns`。
- gateway 的 `bns.<sn_host>` HTTP forward 也直接使用同一个
  `bns_server_url`。
- 空字符串仍为 `InvalidConfig`，启动 readiness probe 保留。

### 3.2 迁移和清理

- 删除 params 和生成脚本里的 `bns_rpc_url`，不再同时写两份相同值。
- 更新 `web3_gateway.yaml`、`web3_dns.yaml`、`web3_relay.yaml`、
  `web3_sn_api.yaml`、`params.json`、`make_sn_config.ts`、`init_anvil.py`、
  `sn-dev-up.sh` 及对应测试。
- 更新 `src/rootfs/etc/cyfs_gateway.yaml`、`doc/cyfs_gateway_config.yaml` 和 SN 配置文档。
- Beta2.2 不需要为 `bns_rpc_url` 保留默认 alias；旧字段应从生成物和测试中
  完全消失。

## 4. 删除 `bns_evm`，统一到 `bns_proxy`

### 4.1 目标模型

`bns_proxy` 整块可选。未配置时，SN 仍使用 `bns_server_url` 提供 BNS
读取和 resolver 能力，但不构造 controller、signer、write-request store 或
controller-binding store。

需要 BNS 写入能力时，controller key 只通过现有的
`bns_proxy.controllers` 配置：

```yaml
bns_proxy:
  require_user_asset_owner: true
  controllers:
    - id: default
      address: 0x...       # optional consistency check
      private_key_env: BNS_SN_CONTROLLER_PRIVATE_KEY
      weight: 1
  allowed_operations:     # optional; omitted means all supported operations
    - register_name_bootstrap
    - publish_dns_txt
    - publish_relay_assignment
    - publish_document
```

- 删除 `SNBnsEvmConfig` 及 `SNServerConfig.bns_evm`。
- 删除 `load_bns_evm_controller_private_key`、legacy single-controller fallback 和
  `legacy_mode`。
- `SNServerConfig.bns_proxy` 改为 `Option<SNBnsProxyConfig>`。
- 未配置 `bns_proxy` 是合法的 BNS 只读模式，不得导致 SN 启动失败。
- 仅当配置了 `bns_proxy` 时，`controllers` 必须非空；空列表在启动时
  返回明确的 `InvalidConfig`。
- 单 controller 不再是特殊模式，只是 `controllers` 长度为 1。
- `require_user_asset_owner` 统一缺省为 `true`；只有 dev/test 可显式配置
  `false`。
- controller principal 始终从对应 key 地址派生；删除只为 legacy 分支保留的
  `sn_controller_principal` 覆盖逻辑。如该字段仍有其它现实用途，实现者必须在保留前
  先增加用例证明。

### 4.2 只读模式运行时行为

- `SnServerFactory::build_bns_proxy` 改为按配置构造
  `ServerResult<Option<Arc<SnBnsProxy>>>`；未配置时直接返回 `Ok(None)`。
- `SNServer` 内的 proxy 引用改为 `Option<Arc<SnBnsProxy>>`，不得为了避免
  `Option` 而构造虚假/no-op controller。
- BNS 读取、DNS resolver、DID resolver 和不依赖写链的 SN API 正常工作。
- `auth.register` 当前依赖 BNS bootstrap；未配置 proxy 时在请求阶段
  返回稳定、明确的“BNS proxy is not configured”能力不可用错误，不得
  回退为仅创建本地用户。
- `/kapi/sn/bns-proxy` 下的所有写操作在未配置 proxy 时返回同一类
  能力不可用错误，不 panic。
- 未配置 proxy 时不应创建 `sn_bns_write_requests` 和
  `sn_bns_controller_bindings` 表或相关运行态。
- 删除 `bns_proxy.enabled` 和 `bns_write_enabled` 这类重复开关：配置块存在
  即启用，缺失即只读。

### 4.3 模板迁移

所有现有：

```yaml
bns_evm:
  controller_private_key_env: BNS_SN_CONTROLLER_PRIVATE_KEY
bns_proxy:
  require_user_asset_owner: true
```

改为：

```yaml
bns_proxy:
  require_user_asset_owner: true
  controllers:
    - id: default
      private_key_env: BNS_SN_CONTROLLER_PRIVATE_KEY
```

开发环境中已有多 controller 注入逻辑的，应改为生成同一套目标结构，不得再
生成 `bns_evm`。

## 5. `auth_db` / `device_info_db` 独立 backend 选择

### 5.1 配置结构

在 `SNServerConfig` 中增加：

```rust
pub app_did: Option<String>,
pub auth_db: Option<SnRemoteProviderConfig>,
pub device_info_db: Option<SnRemoteProviderConfig>,
```

HTTPS provider 继续使用字符串 base URL 和原有路径：

- `auth_db: https://provider:8443` 归一化为
  `https://provider:8443/s2s/sn/auth-db`；
- `device_info_db: https://provider:8443` 归一化为
  `https://provider:8443/s2s/sn/device-info-db`。

HTTP provider 使用对象形式配置 `url`、`remote_app_did` 和
Base64URL Ed25519 `remote_public_key`，同时由顶层 `app_did` 定位本机
DID Identity 私钥。Payload S2S 路径分别归一化为
`/s2s/sn-auth-db` 和 `/s2s/sn-device-info-db`。

显式配置为空字符串时应返回 `InvalidConfig`，不得当作未配置后静默回退
本地 backend。

### 5.2 Factory 构造规则

`auth_db` 和 `device_info_db` 必须独立选择：

| `auth_db` | `device_info_db` | Auth backend | Device backend |
|---|---|---|---|
| 未配置 | 未配置 | `SqliteSnAuthDB` | `SqliteSnDeviceInfoDB` |
| 已配置 | 未配置 | `SnAuthDbClient` | `SqliteSnDeviceInfoDB` |
| 未配置 | 已配置 | `SqliteSnAuthDB` | `SnDeviceInfoDbClient` |
| 已配置 | 已配置 | `SnAuthDbClient` | `SnDeviceInfoDbClient` |

remote 分支固定使用：

```rust
SnAuthDbClient::new_krpc_url(auth_db_url, None)
SnDeviceInfoDbClient::new_krpc_url(device_info_db_url, None)
```

- 不增加 `session_token`、`session_token_file`、`provider_token` 等 SN 配置字段。
- IP 认证的 provider 侧实现和基础设施 ACL 不在本 TODO 的 client 改造范围内。
- 不为 remote provider 增加 PostgreSQL 假设；provider 后面使用什么存储与 SN client
  配置无关。

### 5.3 删除误导性 DB 切换层

- 删除 `db_type=postgres|postgresql` 触发 remote client 的分支。
- 删除 `SnPostgresDbConfig`、`postgres_db_config`、`provider_base_url`、
  `provider_url`、`auth_db_url`、`device_info_db_url`、
  `provider_session_token*` 和 `provider_token*` 解析逻辑。
- 删除 `db_type` 作为 backend selector。如果 `db_type` 没有其它用途，从
  `SNServerConfig` 和配置文档完全删除。
- 保留 `db_path`，用于本地 auth/device backend，以及尚未远程化的
  compatibility、relay 和 BNS proxy store。
- 不应再使用 `#[serde(flatten)] Option<Value>` 吸收 DB 配置。将 `db_path`
  定义为正式、显式字段，避免未知配置键被静默接受。

### 5.4 Seed 语义

- `auth_db` 未配置时，保留现有本地 `seed_path` 导入。
- `auth_db` 已配置时，如果同时配置 `seed_path`，启动返回
  `InvalidConfig`；seed 必须在 auth provider 侧导入。
- `device_info_db` 是否 remote 不影响 seed 判定。

## 6. SN 自身 DNS bootstrap 字段改为可选

### 6.1 字段用途和边界

当前 `boot_jwt`、`owner_pkx`、`device_jwt` 只由 `SnResolver::resolve_self_dns`
消费，用于查询 `host`、`sn.<host>` 或 `aliases` 的 TXT 时分别生成：

- `BOOT=<boot_jwt>;`
- `PKX=<owner_pkx>;`
- `DEV=<device_jwt>;`

这三个字段不是 RTCP stack 的本机身份配置，不得用来替代 Gateway identity
manager。RTCP 本机身份继续由 stack 的 `identity`（兼容别名 `did` /
`device_did`）和 `identity_manager` 加载；legacy 部署仍可使用 `key_path` 与
`device_config_path`。

`*.web3.<host>` 和 active `user_domain` 的解析不读取这三个顶层字段：

- PKX 来自对应 BNS owner 或用户公钥；
- BOOT 来自对应 BNS `boot` document、`zone.boot_jwt` 或明确的 legacy zone 数据；
- DEV 来自对应 BNS `device_mini`、zone devices 或兼容设备记录；
- 其它 TXT 来自显式 DNS record 或 BNS `dns_txt`。

因此，只提供 `web3.<host>` 和 `user_domain` 权威 DNS 的部署可以完全省略这三个
字段，不得被迫生成一套与 RTCP identity manager 重复的 bootstrap 材料。

### 6.2 目标配置模型

将 `SNServerConfig` 改为：

```rust
pub boot_jwt: Option<String>,
pub owner_pkx: Option<String>,
#[serde(default)]
pub device_jwt: Vec<String>,
```

`SnResolverConfig` 同步使用可选的 `boot_jwt` / `owner_pkx` 和缺省为空的
`device_jwts`。配置缺失或值为空时，SN 自身 TXT 不生成对应记录；不得生成
`PKX=;`、`BOOT=;` 或 `DEV=;`。为兼容现有生成物，显式空字符串按未配置处理，
后续模板应直接省略字段。

三个字段必须可以独立配置，不能要求同时出现。未配置全部三个字段时：

- `*.web3.<host>` 和 `user_domain` 的 A/AAAA/TXT 解析保持不变；
- SN 自身 hostname 的 A/AAAA 行为仍只由可选 `ip` 决定；
- SN 自身 hostname 不再合成 PKX/BOOT/DEV TXT；
- RTCP stack 的启动和身份加载完全不受影响。

### 6.3 模板和文档迁移

- 生产模板默认删除 `boot_jwt`、`owner_pkx`、`device_jwt`。
- 仍需兼容 SN 自身 TXT bootstrap 的 dev/test profile 可以继续生成并配置。
- `make_sn_config.ts` 不得再把生成这三个值作为启动 `cyfs-sn` 的必要条件。
- SN 完整部署文档应把 RTCP `identity` / `device_did` 放在 `stacks` 配置下，
  不得放进 `servers.web3_sn`；`SNServerConfig` 使用 `deny_unknown_fields`，
  在 server block 中配置 `device_did` 应继续报错。
- 保留 per-zone BNS `boot` / `device_mini` 数据模型；本项只处理 SN 自身 hostname
  的全局兼容值，不删除用户 zone 的 BOOT/DEV 能力。

## 7. 实施顺序

1. 先改 `SNServerConfig` 和配置解析单元测试，锁定目标 YAML 结构。
2. 改 `ip` 可选语义及 resolver 错误传递。
3. 将 BNS URL 收敛到 `bns_server_url`。
4. 删除 `bns_evm` legacy 路径，将所有模板改为 `bns_proxy.controllers`。
5. 将 auth/device backend 分别改为可选 URL 驱动，删除 `db_type=postgres`
   和 token 配置。
6. 将 SN 自身 TXT bootstrap 三字段改为可选，解除其与启动配置的强制绑定。
7. 更新配置生成器、开发环境脚本、样例、文档和旧 TODO 中的过时说明。
8. 执行格式化和分层测试，最后做全局旧字段残留扫描。

## 8. 测试和验收

### 8.1 必须增加的测试

- 配置不带 `ip` 可成功构造 SN；不依赖 `server_ip` 的查询正常。
- 缺少 `ip` 时，SN 自身 A/AAAA 和 relay fallback 返回明确解析失败。
- 显式非法 `ip` 启动失败。
- 配置同时缺少 `boot_jwt`、`owner_pkx` 和 `device_jwt` 时可成功解析和启动。
- 三个自身 TXT bootstrap 字段均可独立配置；缺省或空值不生成空的
  PKX/BOOT/DEV TXT。
- 不配置三个字段时，`*.web3.<host>` 和 `user_domain` 的 A/AAAA/TXT 解析
  仍从 BNS、auth、device-info 和显式 DNS record 获取数据。
- RTCP identity manager 配置只依赖 stack `identity`，不依赖三个 SN server
  bootstrap 字段。
- IPv4/IPv6 记录类型匹配逻辑保持不变。
- `bns_server_url` 被用于 readiness probe、BNS 读写和 HTTP forward
  生成物；不再需要 `bns_rpc_url`。
- 单 controller 和多 controller 都仅使用 `bns_proxy.controllers`。
- 不配置 `bns_proxy` 时 SN 可成功启动，BNS 读取/resolver 正常，且不创建
  BNS proxy 本地表。
- 不配置 `bns_proxy` 时，`auth.register` 和 BNS proxy 写方法返回稳定的
  capability-unavailable 错误。
- 显式配置 `bns_proxy` 但 `controllers` 为空时启动失败。
- `require_user_asset_owner` 缺省 true，显式 false 仍保留 dev/test fallback。
- auth/device backend 四种本地/远程组合均构造正确。
- remote clients 使用正确的 KRPC path，且 session token 为 `None`。
- 空 `auth_db` / `device_info_db` URL 失败，不回退本地。
- remote `auth_db` 与 `seed_path` 同时出现时启动失败。

### 8.2 建议执行命令

```bash
cd src
cargo fmt --check
cargo test -p cyfs-sn --lib -- --test-threads=1
cargo test -p cyfs-sn --tests -- --test-threads=1
cargo test -p cyfs_gateway --test test_cyfs_gateway -- --test-threads=1
```

如改到配置生成器或 Web3 Gateway 模板，同时运行对应 TypeScript/Python 测试和：

```bash
cd src/apps/cyfs_gateway/web
npm run build
```

Web 代码未变时无需强制安装前端依赖。

### 8.3 最终残留扫描

```bash
rg -n "bns_rpc_url|bns_evm|SnPostgresDbConfig|provider_session_token|provider_token|db_type.*postgres" src doc/SN
```

除明确记录历史设计的 `[DONE]` 文档外，生产代码、模板、测试、示例和
当前配置文档不应再出现旧字段。对 `[DONE]` 文档应加注“历史配置已被
Beta2.2 取代”，避免被误当成现行文档。

## 9. 非目标和边界

- 本 TODO 不实现 remote provider 服务本身，只改 SN 的 client/backend 选择。
- 本 TODO 不将 compatibility store、relay manager、BNS write request store 或
  controller binding store 远程化。
- 配置了 `auth_db` / `device_info_db` 不等于 SN 已完全无状态；其余本地
  状态仍由既有无状态化 TODO 跟踪。
- 本 TODO 不改变 provider RPC method 集合和 response envelope。
- 本 TODO 不引入 session-token 备用认证路径；安全边界是部署环境的源 IP
  认证。

## 10. 完成记录

### 10.1 原收敛项（DONE，2026-07-22）

- `ip` 已改为可选；缺少 IP 时仅依赖 SN 地址的解析分支返回
  `BackendUnavailable`，显式非法 IP 仍阻止启动。
- BNS 地址已统一为 `bns_server_url`；写能力只由可选的
  `bns_proxy.controllers` 开启，缺省时以只读模式运行。
- `auth_db` 与 `device_info_db` 已改为相互独立的可选 provider base URL；remote
  client 固定不携带 session token，本地分支继续使用 `db_path`。
- 旧的 `bns_rpc_url`、`bns_evm`、BNS 写开关、DB selector/DSN/token 解析和
  legacy controller fallback 已从生产代码、模板、生成器及现行配置文档删除。
- 已增加可选 IP、只读 BNS、controller 配置、四种 backend 组合、空 URL、
  remote auth seed 冲突以及模板生成相关回归测试。

验收结果：`cyfs-sn` lib/tests、`cyfs_gateway` lib/集成测试、Deno 配置生成测试、
Python staging 测试以及 `git diff --check` 均通过。workspace 的全量
`cargo fmt --check` 仍会报告本次修改范围之外的既有格式差异，因此未对无关文件做
批量格式化。

### 10.2 SN 自身 DNS bootstrap 可选化（DONE，2026-07-22）

- [x] `boot_jwt`、`owner_pkx` 改为 `Option<String>`。
- [x] `device_jwt` 缺省为空数组。
- [x] resolver 不再要求三个字段存在，也不生成空 TXT。
- [x] 生产模板和生成器默认省略三个字段。
- [x] 增加无 bootstrap 配置下的 web3/user-domain DNS 与 RTCP identity 回归测试。

验收结果：`cyfs-sn` lib/tests、`cyfs_gateway` 集成测试、RTCP identity parser
回归测试、Deno 配置生成测试和 `git diff --check` 均通过。workspace 全量
`cargo fmt --check` 仍报告本次修改范围之外的既有格式差异，未对无关文件做
批量格式化。
