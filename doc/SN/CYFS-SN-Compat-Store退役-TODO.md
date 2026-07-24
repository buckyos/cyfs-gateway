# CYFS-SN Compat Store 退役 TODO

> 状态：待实施。2026-07-23 按 Beta2.2 breaking change 重新设计。  
> 前提：真实数据尚未上线，测试环境允许清库重建；本轮不提供旧 schema
> migration、旧数据导入或 runtime fallback。

## 1. 设计基线

本轮按 clean-slate 标准实施：

- 不保留 `devices`、`did_documents`、旧 `user_dns_records` 的表结构。
- 不保留 `SnCompatibilityStore` trait、adapter、feature flag 或只读 fallback。
- 不保证旧数据库文件可直接启动；部署升级步骤是停止服务、清库、按新 schema 重建。
- 可以同时修改 Rust public API、S2S contract、RPC response 和序列化枚举。
- 只保留确认仍需要的业务能力，不保留旧存储模型或调用形状。

compat store 当前混合了三类职责，目标上必须完全拆开：

| 当前职责 | 新权威来源 | 处理方式 |
| --- | --- | --- |
| user DNS RRset | `SnAuthDB` | 重新设计 schema 和结构化 contract |
| device 在线态 | `SnDeviceInfoDB` | resolver/API 直接读取 |
| device 静态文档 | BNS/indexer `device_mini_doc` | resolver 直接读取 |
| 普通 DID document | BNS/indexer | resolver 直接读取 |
| legacy `devices` | 无 | 删除 |
| legacy `did_documents` | 无 | 删除 |

## 2. Review 结论

### P0：user DNS 是现行业务，不是应被删除的 legacy 数据

以下能力当前都经过 `compat_store`：

- `dns.add_record`
- `dns.remove_record`
- `dns.list_records`
- resolver 的显式 A/AAAA/TXT 查询
- 权威 DNS 的 owner-name existence 判定

它们需要保留，但不应继续使用 compatibility 抽象。local 和 remote 模式统一直接调用
`SnAuthDB` contract。

### P0：当前 DNS 数据模型不应原样搬迁

旧表把每个 value 存成一行，并由查询层使用逗号拼接返回：

- TTL 实际属于 RRset，却重复存放在每个 value 上；
- TXT value 本身可能包含逗号，字符串拼接不是可靠 wire contract；
- `(owner, domain, type, value)` 允许同一个 DNS name 被不同 owner 同时占有；
- query 不带 owner，会把不同 owner 的残留 value 合并；
- `Option<record>` 同时表示精确删除和整组删除，接口语义不清；
- 缺少可供多副本 cache invalidation 使用的 revision/change log。

本轮应使用标准的 `name -> rrset -> rdata` 模型，而不是把旧
`user_dns_records` DDL 移入 `SnAuthDB`。

### P0：不能机械删除 resolver compatibility reader

`LegacyResolverCompatibilityReader` 不只读取旧表，它还间接读取
`SnDeviceInfoDB`。当前 `resolve_device_mini_doc` 把 compatibility reader 当作
BNS 缺失时的设备来源。

删除前必须把 resolver 改为显式依赖：

- AuthDB user DNS reader；
- BNS static document reader；
- device-info online-state reader。

三种数据不能再统一伪装成 `ResolverDeviceDocument`。

### P1：多副本 cache coherence 必须成为新 contract 的一部分

当前 add/remove 只清理写请求所在 SN 副本的本地 cache。其他副本会继续返回旧 RRset、
NODATA 或 NXDOMAIN，直到 TTL 到期。

新 AuthDB schema 和 S2S contract 必须提供单调 revision 与 change feed，使每个 SN
副本能可靠失效正缓存和负缓存。对 `_acme-challenge` 等控制记录，在 change feed
完成前应直接绕过本地缓存。

### P1：管理 API 不应暴露存储表计数

`SnClearStateResult` 当前返回 `deleted_devices`、`deleted_domain_records`、
`deleted_did_documents`。这些字段把 RPC contract 与旧表结构绑定。

新 contract 只返回业务结果，例如清理的 account 数和 activation code 状态；底层删除
多少 rrset/rdata 不再成为公共 API。

### P1：DID source 需要按真实来源重新命名

`SnDidDocumentSource::LegacyCompatibilityStore` 同时被用于：

- 真正的 legacy device/DID 数据；
- 从 `SnAuthDB` user/zone 信息生成的 zone/boot projection。

前者删除；后者如果仍保留，应改为 `AuthDbProjection` 等准确来源。breaking change
版本无需保留旧序列化值。

## 3. 新 user DNS 领域模型

### 3.1 数据库表

建议由 `SqliteSnAuthDB` 和生产 AuthDB provider 实现以下逻辑模型。生产数据库可以
使用等价 DDL，但约束和事务语义必须一致。

#### `user_dns_names`

一条记录代表一个 DNS owner name，并保证该 name 只能属于一个 SN user。

```text
name          TEXT PRIMARY KEY
owner         TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE
created_at    INTEGER NOT NULL
updated_at    INTEGER NOT NULL
```

约束：

- `name` 必须是 canonical ASCII FQDN：小写、无结尾点、按 DNS label 校验；
- 同一个 `name` 的 A/AAAA/TXT 必须属于同一个 owner；
- owner 变更不能通过普通 upsert 完成，必须先执行受信任的 domain
  unbind/rebind 流程。

#### `user_dns_rrsets`

一条记录代表一个 RRset。TTL 是 RRset 属性，不属于单个 value。

```text
name          TEXT NOT NULL REFERENCES user_dns_names(name) ON DELETE CASCADE
record_type   TEXT NOT NULL
ttl           INTEGER NOT NULL
revision      INTEGER NOT NULL
created_at    INTEGER NOT NULL
updated_at    INTEGER NOT NULL
PRIMARY KEY (name, record_type)
```

约束：

- 第一版只允许 `A`、`AAAA`、`TXT`；
- TTL 使用统一上下限，例如 `30..=86400`，默认值由 API 固定为 600；
- revision 是产生该 RRset 当前状态的全局 DNS revision。

#### `user_dns_rdata`

一条记录代表 RRset 中的一个 value。

```text
name          TEXT NOT NULL
record_type   TEXT NOT NULL
rdata         TEXT NOT NULL
created_at    INTEGER NOT NULL
PRIMARY KEY (name, record_type, rdata)
FOREIGN KEY (name, record_type)
  REFERENCES user_dns_rrsets(name, record_type) ON DELETE CASCADE
```

约束：

- A 必须保存 canonical IPv4 字符串；
- AAAA 必须保存 canonical IPv6 字符串；
- TXT 按独立字符串保存，禁止逗号拼接；长度和 DNS wire 分段规则在 API 层校验；
- 重复写入同一 value 幂等。

#### `user_dns_state`

单行状态表负责分配连续的全局 revision，避免各实现使用
`SELECT MAX(revision) + 1` 产生竞争：

```text
singleton_id  INTEGER PRIMARY KEY CHECK (singleton_id = 1)
revision      INTEGER NOT NULL
```

每次实际 mutation 在同一个 transaction 内锁定该行、将 revision 加一，并把新值写入
RRset 和 change event。transaction 回滚时 revision 增量也必须回滚。

#### `user_dns_changes`

同一 mutation transaction 内追加 change event，用于多副本 cache invalidation。

```text
revision      INTEGER PRIMARY KEY
name          TEXT NOT NULL
record_type   TEXT NULL
operation     TEXT NOT NULL
committed_at  INTEGER NOT NULL
```

约束：

- revision 全局单调递增；
- operation 至少包含 `upsert_rrset`、`delete_rrset`、`delete_name`；
- mutation 和 change event 必须在同一个数据库事务提交；
- change log 支持按 revision 增量读取和有界保留；
- consumer 落后于最早保留 revision 时必须清空本地 DNS cache 并从当前 revision
  重新开始，不能静默跳过。

SQLite connection 必须启用 foreign key enforcement。生产 provider 也必须用数据库
constraint 保证唯一性和 cascade，不能只依赖应用层检查。

### 3.2 Mutation 语义

新接口使用明确动作，不再用 `Option<record>` 重载删除语义：

```text
put_user_dns_value(owner, name, type, value, ttl)
remove_user_dns_value(owner, name, type, value)
delete_user_dns_rrset(owner, name, type)
get_user_dns_rrset(name, type)
list_user_dns_rrsets(owner)
list_user_dns_changes(after_revision, limit)
```

规则：

- `put_user_dns_value` 对相同 value 幂等；
- 并发加入不同 TXT value 时必须全部保留；
- 已存在 RRset 再加入 value 时，TTL 取
  `min(current_ttl, requested_ttl)`，避免一个并发调用延长其他 value 的缓存时间；
- 如需主动增大 TTL，另设 owner-only `set_user_dns_rrset_ttl`，不能借 add value
  隐式完成；
- 删除最后一个 value 时自动删除空 RRset；
- 删除 name 下最后一个 RRset 时自动删除 `user_dns_names`；
- Device context 只能调用精确 value 删除；
- 整组删除只允许 SnUser 管理路径；
- owner 不匹配返回明确的 ownership conflict，不得读取或合并另一 owner 的值；
- no-op mutation 不增加 revision；实际状态变化只增加一次 revision。

domain unbind、account clear/delete 等批量操作必须显式产生 change event，不能只依赖
foreign-key cascade，否则其他 SN 副本无法失效缓存。

### 3.3 结构化 S2S contract

删除 `(String, u32)` 和逗号拼接响应，使用结构化类型：

```rust
pub enum UserDnsRecordType {
    A,
    Aaaa,
    Txt,
}

pub struct UserDnsRrset {
    pub name: String,
    pub record_type: UserDnsRecordType,
    pub ttl: u32,
    pub values: Vec<String>,
    pub revision: u64,
}

pub struct UserDnsLookup {
    pub rrset: Option<UserDnsRrset>,
    pub observed_revision: u64,
}

pub struct UserDnsChange {
    pub revision: u64,
    pub name: String,
    pub record_type: Option<UserDnsRecordType>,
    pub operation: UserDnsChangeOperation,
}
```

要求：

- negative lookup 也返回 `observed_revision`；
- mutation response 返回 committed revision；
- change page 同时返回 `current_revision` 和 `earliest_available_revision`，供 consumer
  判断 retention gap；
- list RRset 按 canonical name、record type、value 稳定排序；
- local `SqliteSnAuthDB`、in-process provider 和 remote S2S provider 使用相同
  contract tests；
- provider 不支持新 contract 时 SN 在启动 readiness 阶段直接失败，禁止运行时
  fallback。

## 4. 新 resolver 数据边界

不要再把 static document、online state 和 legacy row 转换成同一种 compatibility
document。

| 查询 | 数据源 | 缺失语义 |
| --- | --- | --- |
| 显式 DNS RRset | AuthDB user DNS | 结合权威 zone 返回 NODATA/NXDOMAIN |
| device static `doc` | BNS `device_mini_doc` / zone document | document not found |
| device `info` / 在线状态 | `SnDeviceInfoDB` | device not found |
| device DNS 地址 | BNS static config + `SnDeviceInfoDB` endpoints + relay assignment | 按现有优先级组合 |
| 普通 BNS DID document | BNS/indexer | document not found |
| OOD runtime 状态 | `SnDeviceInfoDB` | device not found |

具体约束：

- BNS static document 不得由 online-state JSON 冒充；
- online state 可以为 DNS address 和 `info` 响应提供数据，但不能生成
  `device_mini_doc`；
- `did:dev:*` 查询可以先通过 `SnDeviceInfoDB` 找到 zone/device name，再读取对应
  BNS static document；
- `did:bns:*` 的 zone/boot AuthDB projection 若继续保留，source 必须标记为
  `AuthDbProjection`；
- 仅存在于旧 `devices` / `did_documents` 的数据一律视为不存在。

## 5. 实施任务

### A. 固定新 schema 和 contract

文件：

- `src/components/cyfs-sn/src/sn_auth.rs`
- `src/components/cyfs-sn/src/s2s_api/sn_auth_db.rs`
- `src/components/cyfs-gateway-api/`
- 生产 AuthDB provider

- [ ] 提升 AuthDB schema version；旧 version 启动时返回明确的
  `incompatible schema, recreate database`，不执行兼容 migration。
- [ ] 删除 `devices`、`did_documents`、旧 `user_dns_records` DDL。
- [ ] 实现 `user_dns_names`、`user_dns_rrsets`、`user_dns_rdata`、
  `user_dns_state` 和 `user_dns_changes`。
- [ ] 固定 canonical domain、record type、rdata、TTL 和 TXT size validation。
- [ ] 定义结构化 RRset、lookup、mutation result 和 change event 类型。
- [ ] 删除旧 add/remove/query/list user DNS S2S method，统一切换到新 method；
  不保留双 contract。
- [ ] production provider 与本地 `SqliteSnAuthDB` 同步实现，启动时校验 capability。

### B. 实现 AuthDB user DNS 事务

- [ ] 实现 name owner claim；数据库保证同一 name 不能跨 owner。
- [ ] 实现幂等 put、并发多值 add、RRset TTL 规则和稳定排序。
- [ ] 实现精确 value 删除、显式 RRset 删除及空 rrset/name 清理。
- [ ] 每次实际 mutation 在同一事务生成一个全局 revision/change event。
- [ ] revision 只能由事务内的 `user_dns_state` 分配；禁止 `MAX + 1` 和进程内计数器。
- [ ] domain unbind、account delete、`clear_state_by_active_code` 产生完整删除事件。
- [ ] 并发测试覆盖两个事务同时 claim name、同时 add value、add/remove 交错和重复
  request。
- [ ] remote provider failure 必须 fail-closed，不得创建或读取本地替代数据。

### C. API 直接调用 AuthDB

文件：

- `src/components/cyfs-sn/src/api/dns.rs`
- `src/components/cyfs-sn/src/api/common.rs`
- `src/components/cyfs-sn/src/sn_server.rs`

- [ ] `dns.add_record` 改为 `put_user_dns_value`。
- [ ] `dns.remove_record` 拆分精确 value 删除与 owner-only RRset 删除。
- [ ] `dns.list_records` 返回结构化 RRset；同步修改 gateway API 和客户端。
- [ ] 保留 SnUser/Device identity、domain scope、Device 仅限 ACME TXT 等授权边界。
- [ ] 所有 name/type/value 在授权前后使用同一 canonical representation，避免校验值和
  落库值不同。
- [ ] mutation 成功后按 committed revision 更新当前副本 cache cursor。

### D. Resolver 直接使用 AuthDB 与 device-info

文件：

- `src/components/cyfs-sn/src/sn_resolver.rs`
- `src/components/cyfs-sn/src/sn_server.rs`
- `src/components/cyfs-sn/src/sn_did_resolver.rs`

- [ ] 为 `SnAuthReader` 增加结构化 user DNS lookup/change-feed 能力，或增加命名准确的
  `UserDnsReader`；禁止出现新的 compatibility reader。
- [ ] 显式 DNS 查询直接消费 `Vec<String>`，删除逗号 split/join。
- [ ] name existence 使用 AuthDB name/RRset 查询，保持权威 NXDOMAIN/NODATA 语义。
- [ ] 保持 explicit RRset 高于 BNS/合成记录的现有优先级。
- [ ] `_acme-challenge` / `_pkx` 缺失时不得回退到 BNS。
- [ ] 每个 SN 副本消费 `user_dns_changes` 并同时失效正缓存和负缓存。
- [ ] change consumer 断档时清空全部 user DNS cache；恢复前控制记录绕过缓存。
- [ ] `_acme-challenge`、`_pkx` 等控制 name 的正负查询默认绕过本地 TTL cache，保证
  commit 后任一 SN 副本的下一次查询直接观察 AuthDB；普通 RRset 的跨副本陈旧窗口不得
  超过声明的 change-feed poll SLA。
- [ ] static device document 只读 BNS；online info 只读 `SnDeviceInfoDB`。
- [ ] 重构 `resolve_device_mini_doc` 及其调用者，不再使用 online state 冒充 static doc。
- [ ] 删除 local DID document fallback，统一返回结构化 not-found。

### E. 删除 compat store 与 legacy 分支

文件：

- `src/components/cyfs-sn/src/sn_compat_store.rs`
- `src/components/cyfs-sn/src/lib.rs`
- `src/components/cyfs-sn/src/sn_server.rs`
- `src/components/cyfs-sn/src/sn_resolver.rs`
- `src/components/cyfs-sn/src/api/user.rs`
- `src/components/cyfs-sn/src/api/dns.rs`
- `src/components/cyfs-sn/src/api/device.rs`

- [ ] 删除 `sn_compat_store.rs`。
- [ ] 删除 module 声明和 public re-export。
- [ ] 删除 `SnCompatibilityStore`、ref alias、两个实现和 `SNDeviceInfo`。
- [ ] 删除 `LegacyResolverCompatibilityReader`。
- [ ] 删除 `ResolverCompatibilityReader`、empty implementation、
  `SnResolver.compatibility` 和 `with_compatibility_reader`。
- [ ] 删除 `SNServer.compat_store` 字段、constructor 参数和 accessor。
- [ ] `SnServerFactory` 不再打开或初始化 compatibility SQLite。
- [ ] 删除 `resolve_ood_by_did`、device ownership 和 report DID inference 中的
  legacy device fallback。
- [ ] 删除 `resolve_legacy_local_did_doc`、`ood_info_from_legacy_device`、
  `build_legacy_device_info_json` 和其他 legacy conversion helper。
- [ ] 删除 `SnDidDocumentSource::LegacyCompatibilityStore`；需要保留的 AuthDB
  projection 改用新 source。

### F. 重做 clear-state 与 schema 初始化

- [ ] `SnClearStateResult` 只表达业务结果，不返回各存储表删除行数。
- [ ] 删除 `sqlite_master` probe、optional legacy table count/delete。
- [ ] 使用 foreign key cascade 清理关联数据，同时由业务事务写 change event。
- [ ] fresh AuthDB 初始化后只包含新 schema；不存在任何 compatibility table/index。
- [ ] 删除所有 old-index drop、ALTER、copy-table 等 migration 分支。

### G. 测试和文档

需要更新：

- `src/components/cyfs-sn/tests/sn_auth_user_dns_contract.rs`
- `doc/SN/SN-API.md`
- `doc/SN/SN-Auth.md`
- `doc/SN/SN-Resolver.md`
- `doc/SN/SN-DID-Resolver.md`
- `doc/BNS/SN-BNS-Contoller.md`

- [ ] 删除 compat-store unit/integration fixture。
- [ ] 用 AuthDB RRset fixture 替换 `StaticCompatibilityReader`。
- [ ] 更新所有 `SNServer::new` 测试构造。
- [ ] schema test 校验 table、PK、FK、CHECK、index 和 foreign-key enforcement。
- [ ] contract test 覆盖 local/in-process/remote 三种实现。
- [ ] DNS test 覆盖 A/AAAA canonicalization、TXT 逗号、TXT 多值、TTL、
  幂等和稳定排序。
- [ ] authorization test 覆盖跨 owner name claim、Device 精确删除和 SnUser
  RRset 删除。
- [ ] 两个 SN resolver 实例共享 provider：控制记录在 commit 后的下一次查询直接可见；
  普通记录在声明的 poll SLA 内完成正/负 cache 失效。
- [ ] 模拟 change-log retention gap，验证 consumer 清空 cache 后恢复。
- [ ] 覆盖 BNS static doc、device-info online state 分离后的所有 DID/DNS 组合。
- [ ] 旧 schema 文件启动必须返回明确 incompatibility error；测试不要求 migration。
- [ ] 文档和 release note 明确必须清库重建，以及所有删除/重命名的 API。

建议验证命令：

```bash
cd src
cargo test -p cyfs-sn -- --test-threads=1
cargo test -p cyfs_gateway --test test_control_server
cargo check --workspace
```

## 6. 实施顺序

1. 固定新 AuthDB schema、Rust types 和 S2S contract；
2. 同时实现 local SQLite 与 production provider，并完成 contract tests；
3. API 切换到结构化 AuthDB RRset contract；
4. resolver 切换 user DNS、change feed、BNS static 和 device-info online reader；
5. 删除 compat store、legacy device/DID 分支和旧 public API；
6. 重做 clear-state、测试、文档和部署模板；
7. 所有测试环境清库，使用新 schema 做端到端验收。

不设计 provider-first 滚动兼容窗口。Beta2.2 的 SN、AuthDB provider 和客户端必须作为
同一 breaking release 升级；混跑版本应在 capability/schema handshake 阶段被拒绝。

## 7. 完成标准

- [ ] 源码和测试中不存在 `SnCompatibilityStore`、
  `SqliteSnCompatibilityStore`、`AuthDbRoutedSnCompatibilityStore`、
  `LegacyResolverCompatibilityReader`。
- [ ] 数据库中不存在 `devices`、`did_documents`、旧 `user_dns_records`。
- [ ] user DNS 使用 name/RRset/rdata 三层模型和强 owner 约束。
- [ ] S2S contract 不再使用逗号拼接 value 或 `Option<record>` 重载删除语义。
- [ ] local、remote、多副本查询具有一致结果，正负 cache 均能按 revision 失效。
- [ ] static device document、online state、DID document 的来源完全分离。
- [ ] 管理 API 不暴露数据库表级删除计数。
- [ ] 旧 schema 被明确拒绝；fresh schema 初始化和全量测试通过。
- [ ] `cargo test -p cyfs-sn -- --test-threads=1` 与 workspace check 通过。
