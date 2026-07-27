# CYFS-SN `create_auth` 退役与注册凭证原子化 TODO

状态：本仓库部分已完成（2026-07-26 落地）。剩余未完成项均在仓库外
`sn-business`（PostgresSnAuthDB provider 与 contract tests），需随 contract v3
同版发布，见第 4、5 节中标注 **[仓库外]** 的条目。

相关实现：

- [`sn_auth.rs`](../../src/components/cyfs-sn/src/sn_auth.rs)
- [`s2s_api/sn_auth_db.rs`](../../src/components/cyfs-sn/src/s2s_api/sn_auth_db.rs)
- [`sn_seed.rs`](../../src/components/cyfs-sn/src/sn_seed.rs)
- [`api/auth.rs`](../../src/components/cyfs-sn/src/api/auth.rs)
- [`SN-Auth.md`](./SN-Auth.md)

## 0. Review 结论

可以删除 `SnAuthDB::create_auth`，而且应在 Beta2.2 的 breaking change 中直接
删除，不保留 deprecated 方法或 RPC alias。

常规 `auth.register` 已经满足“创建用户时必须带密码”：

1. `api/auth.rs` 的 `auth.register` 必填 `pwd_hash`，服务端先生成
   `password_hash` / `password_salt`；
2. handler 调用 `register_user_with_relay_allocation`，请求中已经包含完整凭证；
3. SQLite 的 `register_user_tx` 在同一个事务内写 `users` 和 `user_auth`，失败时
   不消费激活码。

当前唯一没有满足该不变量的生产实现是 trusted seed/import 路径：

- `register_user_with_owner_key` 只创建 `users`、`zone_info` 和可选 domain
  binding，不接收密码；
- `sn_seed` 在上述事务提交后再调用 `create_auth`；
- 两步之间若进程退出或第二步失败，会留下已经激活、激活码已经消费、但无法登录的
  passwordless user；
- seed 重放目前会用 seed 中的密码为“属性完全匹配且缺少 auth”的存量用户补建凭证。
  这既掩盖了破坏的不变量，也让 seed importer 兼具隐式 credential mutation 能力。

`create_auth` 在仓库内没有其它业务用途；剩余代码均为该 seed 两阶段流程、测试夹具
或 S2S 转发样板。因此删除的前置条件只有一个：让 owner-key trusted registration
也携带密码，并在同一个数据库事务内创建 `user_auth`。

## 1. 目标不变量

- 任意成功的用户创建都同时、原子地创建且仅创建一条 `user_auth`。
- 不允许存在“先创建 user、稍后补 credential”的业务 API 或 S2S API。
- `users` 中的每个账号都必须能在 `user_auth` 中找到对应行。
- seed/import 只创建完整账号；对已存在账号不得创建、覆盖或重置密码。
- 修改/找回密码将来使用独立、显式鉴权的 credential mutation API，不复用注册
  接口，也不恢复 `create_auth`。

非目标：

- 不合并 `users` 与 `user_auth` 表；
- 不在本项中实现 change-password、forgot-password 或密码算法升级；
- 不改变现有 `pwd_hash` 被服务端再次 PBKDF2 的历史语义。

## 2. Core AuthDB 改造

- [x] 新增 core 请求结构 `RegisterUserWithOwnerKeyReq`，至少包含：
  `active_code`、`username`、`email`、`password_hash`、`password_salt`、
  `password_algo`、`public_key`、`zone_config`、`user_domain`、`sn_ips`。
- [x] 将 `SnAuthDB::register_user_with_owner_key` 改成接收上述 request struct，
  避免继续扩展位置参数；保留 trusted seed/import only 的安全注释。
- [x] 抽取共用的 `insert_user_auth_tx` helper，让普通注册和 owner-key 注册使用
  同一份 `user_auth` INSERT 与错误映射。
- [x] 在 `SqliteSnAuthDB::register_user_with_owner_key` 的现有事务中写入
  `users`、`user_auth`、`zone_info`、可选 domain binding，最后消费激活码并提交。
  （凭证三字段为空时直接拒绝 `InvalidInput`，不开启事务。）
- [x] 任一步失败必须回滚用户、凭证、zone/domain 投影和激活码状态。
- [x] 从 `SnAuthDB` trait、`SnAuthDbClient` forwarding impl 和
  `SqliteSnAuthDB` impl 中删除 `create_auth`。（`RemoteSnAuthDB` 转发一并删除。）

不应提供临时兼容实现，也不应把 `create_auth` 改名为 `set_auth` 后保留同样的
post-create 语义。

## 3. Seed/import 收口

- [x] 新 seed user 仍先在内存中计算 PBKDF2 hash/salt，再把凭证随
  `RegisterUserWithOwnerKeyReq` 一次提交。
- [x] 删除新用户注册后的第二次 `create_auth` 调用及 `auth_created` 分支。
- [x] 删除“已存在且 `get_auth` 为 `None` 时用 seed 密码补建凭证”的逻辑。
- [x] 已存在用户缺少 `user_auth` 时返回明确的 DB invariant error 并让启动失败；
  不计作普通 conflict，也不静默继续。（校验先于字段 mismatch 判定执行。）
- [x] 保持现有 ensure-exists 语义：账号完整且字段一致时零写入；字段冲突时仍不
  覆盖既有资料或密码。
- [x] 更新 seed 注释和测试，明确 seed password 只在首次原子创建时使用。

这里选择 fail fast，而不是自动修复。缺失 `user_auth` 表示数据库来自旧 contract、
中断的旧流程或外部写坏；用配置文件中的密码静默接管存量账号不是安全的迁移策略。

## 4. S2S contract breaking change

- [x] 删除 `METHOD_CREATE_AUTH`。
- [x] 删除 `SnAuthDbCreateAuthReq` 及其 constructor/parser。
- [x] 删除 client 的 `sn_auth_db.create_auth` 调用。
- [x] 删除 server router 对 `sn_auth_db.create_auth` 和短 alias `create_auth` 的
  handler；旧调用统一返回 unknown method。
- [x] 扩展 `sn_auth_db.register_user_with_owner_key` 的 wire request，加入三个密码
  credential 字段，并与 core request 共用一种 serde schema，避免 DTO 漂移。
  （wire DTO `SnAuthDbRegisterUserWithOwnerKeyReq` 已删除，client/server 直接
  序列化/解析 core `RegisterUserWithOwnerKeyReq`。）
- [x] 将 `SN_AUTH_DB_CONTRACT_VERSION` 从 `2` 升为 `3`。
- [ ] **[仓库外]** 同步修改仓库外 `sn-business` 的 `PostgresSnAuthDB`、provider
  router/client 与 contract tests；SN API 和 AuthDB provider 必须同版本发布，
  不支持新旧混跑。

当前 `SNServer` 启动时会严格比较 AuthDB contract/schema capability，因此 contract
version bump 可以在流量进入前拒绝未同步升级的 remote provider。

## 5. Schema 与存量数据策略

- [x] 将 `SN_AUTH_DB_SCHEMA_VERSION` 从 `2` 升为 `3`，即使表的列定义不变，也用
  schema version 表达“passwordless user 不再是合法状态”的语义变化。
- [x] fresh schema 初始化写入 version `3`（改为绑定
  `SN_AUTH_DB_SCHEMA_VERSION` 常量写入，避免字面量漂移），更新
  wrong-version/fresh-schema 测试。
- [x] 延续 Beta2.2 已确定的策略：旧 SQLite DB 不做 ALTER/copy migration，启动时
  返回 `incompatible schema, recreate database`，由部署显式重建。
- [x] 在本地 AuthDB 启动校验或专用 invariant test 中执行等价检查：

  ```sql
  SELECT u.username
  FROM users u
  LEFT JOIN user_auth a ON a.username = u.username
  WHERE a.username IS NULL;
  ```

  结果必须为空。现有外键只能保证 `user_auth -> users`，不能反向保证每个 user
  都有 auth；反向约束仍由原子注册事务和启动/readiness 校验保证。
  （已落地为 `SqliteSnAuthDB::initialize_database` 内的
  `assert_no_passwordless_users` 启动校验。）
- [ ] **[仓库外]** PostgreSQL provider 同样增加 orphan-user 检查，并在升级前清理
  或重建旧测试数据；不得由 seed 自动补密码。

## 6. 调用方与文档清理

- [x] `api/auth.rs` 的注册预查删除冗余的 `get_auth(username).is_some()`，只以
  `is_user_exist` 判断用户名占用；新的不变量不再允许 orphan auth/user 状态。
- [x] 更新 `SN-Auth.md`：从已实现方法列表删除 `create_auth`，记录所有注册路径都
  原子写入 `users + user_auth`，并把 schema/contract version 更新为 `3`。
- [x] 检查其它设计文档和仓库外 provider 文档，不再把 credential 补录描述为合法
  创建流程。（仓内文档已清理；仓库外 provider 文档随第 4 节 [仓库外] 条目同步。）
- [x] 全仓搜索确认除本 TODO 的历史说明外，不再存在
  `create_auth`、`METHOD_CREATE_AUTH`、`SnAuthDbCreateAuthReq`。
  （仅剩 unknown-method 回归测试中作为字符串断言的旧方法名，以及
  `SN-Auth.md` 中“已删除”的历史记述。）

## 7. 测试 TODO

- [x] 普通 `register_user` 成功后同时存在 `users` 与 `user_auth`，现有测试继续
  通过。
- [x] `register_user_with_owner_key` 成功后密码可由 `verify_password` 验证
  （`test_register_user_with_owner_key_creates_credentials_atomically`）。
- [x] owner-key 注册在 `user_auth` INSERT 失败时完整回滚。SQLite 测试可临时创建
  `BEFORE INSERT ON user_auth` 的 abort trigger 注入失败，并断言：
  user/zone/domain/auth 均不存在、激活码仍未使用
  （`test_register_user_with_owner_key_rolls_back_on_auth_failure`）。
- [x] seed 首次导入创建完整账号，第二次导入为零写入且不改变 credential 时间戳。
- [x] seed 遇到存量 passwordless user 时 fail fast，且不写入 seed 密码
  （`test_sn_seed_fails_fast_on_existing_passwordless_user`）。
- [x] seed conflict 测试改为通过新的 owner-key 原子注册接口预置“真实账号”，不再
  单独调用 `create_auth`。
- [x] 清理直接 `INSERT INTO users` 的测试夹具：除预期失败且不会落库的约束测试外，
  session 等测试应通过完整注册 helper 创建账号，避免测试继续把 passwordless user
  当成合法前置状态。
- [x] S2S client/server round-trip 覆盖 owner-key 请求的三个 credential 字段
  （`test_owner_key_registration_roundtrip_and_create_auth_routes_removed`，
  含缺 credential 字段的旧 wire request 解析失败断言）。
- [x] 对旧 `sn_auth_db.create_auth` 和 `create_auth` alias 增加 unknown-method
  断言，防止路由残留。
- [x] remote capability contract `2` 被新版 SN 拒绝，contract `3` 可启动
  （capability 校验抽出为 `SnServerFactory::ensure_auth_db_capabilities`，
  `test_auth_db_capability_gate_rejects_stale_contract` 直接覆盖）。

建议验证命令：

```bash
cd src
cargo fmt --check
cargo test -p cyfs-sn -- --test-threads=1
cargo test -- --test-threads=1
```

## 8. 完成标准

- [x] 所有用户创建入口都要求 credential，并在一个 backend transaction 内完成。
- [x] 运行时代码和 S2S wire contract 中不存在 post-create `create_auth` 能力。
- [x] seed/import 不再修复或修改存量 credential。
- [ ] SQLite 与 PostgreSQL provider 都拒绝 passwordless user 状态。
  （SQLite 已完成；PostgreSQL 在仓库外 `sn-business`，见第 5 节 [仓库外]。）
- [x] contract/schema version、文档、测试和部署配置同步完成（本仓库范围）。
- [x] `cyfs-sn` crate 测试与 workspace 单线程测试通过。
