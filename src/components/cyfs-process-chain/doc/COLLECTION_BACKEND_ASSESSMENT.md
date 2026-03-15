# Collection Backend 现状与演进评估

本文件用于整理 `cyfs-process-chain` 当前 collection 后端模型、已知边界，以及未来可能的演进方向。

- crate: `cyfs-process-chain`
- related crates: `cyfs-gateway-lib`
- updated: `2026-03-09`

## 1. 结论摘要

当前 `cyfs-process-chain` 里的 collection 后端，主模型并不是“直接操作持久化存储”，而是：

- 启动时从文件或配置加载。
- 运行时以内存集合为主进行读写。
- 只有在显式 `flush` 时才将变更落盘。

因此：

- JSON collection 当前本质上是“内存态 + dirty flush”的持久化缓存模型。
- process-chain 层的 SQLite collection 目前未实现，不应对外暴露为可用能力。
- 如果未来要支持“直接操作 sqlite、写入立即生效”的 live backend，需要明确它不是简单补一个 loader，而是 collection 语义层的一次扩展。

## 2. 当前实现现状

### 2.1 trait 设计的默认假设

当前 collection trait 的核心接口是容器操作接口：

- `len / get / insert / remove / traverse / dump`

持久化相关接口只有可选的：

- `is_flushable()`
- `flush()`

这说明当前抽象的默认假设是：

- collection 首先是一个运行时容器。
- 持久化只是附加能力，而不是主语义。
- trait 并没有表达事务、自动提交、回滚、刷新策略、只读/只写模式等更强的存储语义。

### 2.2 Memory collection 是真实运行态基线

`MemoryListCollection` / `MemorySetCollection` / `MemoryMapCollection` / `MemoryMultiMapCollection` 是当前运行时语义的基线实现。

它们具备以下特征：

- 数据常驻内存。
- 使用 `RwLock` 管理并发访问。
- 遍历期禁止修改，保证脚本执行期行为稳定。
- `Map/MultiMap` 默认强调稳定遍历顺序。

因此现有命令语义和测试语义，基本都建立在“像内存容器一样工作”的前提上。

### 2.3 JSON collection 是“内存镜像 + flush”

当前 JSON collection 的实现方式是：

- 打开文件时一次性加载 JSON 数据。
- 将数据转换成 `Memory*Collection`。
- 运行时所有读写都委托给内存集合。
- 修改后只打 dirty 标记。
- `flush()` 时整体写回文件。

这意味着：

- JSON collection 并不是直接面向文件的 live collection。
- 运行期语义与 memory collection 基本一致。
- 持久化时机是显式 flush，而不是每次写操作立即生效。

### 2.4 process-chain 层的 SQLite 现状

在 `cyfs-process-chain` 内部，`CollectionFileFormat::Sqlite` 目前只停留在格式枚举层。

当前状态是：

- process-chain 运行时没有可用的 sqlite collection 实现。
- HookPointEnv 已改为对 sqlite 明确返回错误，而不是 `unimplemented!` 崩溃。
- 因此 sqlite 在 process-chain 层当前应被视为“保留格式位，不是可用 backend”。

### 2.5 gateway-lib 里已经存在直连 sqlite 雏形

在 `cyfs-gateway-lib` 中，已经有两类直接操作 sqlite 的实现：

- `SqliteSet`
- `SqliteMap`

它们的特点是：

- 读写直接落到 sqlite。
- 不依赖 process-chain 的内存镜像。
- `insert/get/remove/traverse` 都是数据库操作。

这说明“直连 sqlite backend”在技术上可行，但它们目前并不等价于 process-chain 当前的 collection 语义模型。

## 3. 当前模型的优点与限制

### 3.1 当前模型的优点

“内存态 + flush” 模型当前有几个明显优势：

- DSL 语义稳定，行为更接近普通容器。
- 遍历顺序容易保证。
- 遍历期间写保护容易实现。
- 脚本层不需要关心事务、连接、提交策略。
- JSON 持久化实现简单，调试成本低。

### 3.2 当前模型的限制

它也有明显限制：

- flush 前的数据不具备持久化保证。
- 没有自动提交、批量提交或事务边界语义。
- 持久化接口过弱，只有 `flush()`，缺少更细粒度控制。
- 不适合高并发多进程共享更新场景。
- 不适合把 sqlite 当成实时共享状态数据库来用。

## 4. 直接 sqlite backend 的主要挑战

如果未来要支持“collection 底层直接操作 sqlite，读写立即生效”，主要挑战不在于连上 sqlite，而在于保持 collection 语义一致。

### 4.1 遍历顺序语义

当前内存和 JSON collection 都依赖有序容器，遍历顺序稳定。

而 sqlite 查询如果没有显式 `ORDER BY`：

- 结果顺序不可视为稳定。
- 这会影响 `for`、`dump`、`keys_snapshot` 等路径。

如果要维持现有语义，需要：

- 为 sqlite backend 增加顺序列，例如 `seq`。
- 明确重复插入、删除后再插入、更新已有值时是否改变顺序。

### 4.2 遍历期写入限制

当前 memory collection 明确禁止 traversal 期间修改。

如果改成直连 sqlite：

- 是继续禁止，还是允许基于查询快照写入，需要明确。
- 如果允许，脚本行为将受游标、查询时点、并发写入影响。
- 如果禁止，需要重新在 sqlite backend 中实现这类运行时保护。

### 4.3 类型支持边界

当前 JSON 持久化支持的 `CollectionValue` 实际上很有限：

- 支持：`null / bool / number / string`
- 不支持：`List / Set / Map / MultiMap / Visitor / Any`

`cyfs-gateway-lib` 里的 `SqliteMap` 当前也是把值转成 JSON string 保存，本质上仍受这类边界约束。

因此直连 sqlite backend 并不会自动解决复杂类型持久化问题，反而需要更明确地限定：

- 哪些类型允许入库。
- 哪些类型必须拒绝。
- 是否允许嵌套 collection。
- `Visitor` / `Any` 这类运行时对象如何处理。

### 4.4 类型覆盖不完整

现有直连 sqlite 雏形只覆盖：

- Set
- Map

尚未覆盖：

- List
- MultiMap

而 process-chain 当前 collection 语义是四类一起使用的。若只支持一部分，会带来配置和命令能力的不对称。

### 4.5 trait 与 backend 语义未分层

当前 trait 更像“内存容器接口 + 可选 flush”。

如果引入 live sqlite backend，至少需要回答：

- `flush()` 在 live backend 上是否还需要存在。
- `is_flushable()` 对实时存储 backend 是否恒为 false。
- 是否需要引入 backend capability，例如 `is_live / supports_transaction / supports_ordering`。
- 是否需要区分“运行时容器接口”和“持久化后端接口”。

## 5. 演进方向评估

### 5.1 方向 A：维持当前模型，强化边界

这是当前最稳妥的短期方向。

做法：

- 继续以 memory collection 为运行时主模型。
- JSON 继续作为“加载 + flush”后端。
- SQLite 在 process-chain 层保持明确报错，不对外宣称支持。
- 通过文档和配置校验把边界写清楚。

优点：

- 改动小。
- 不破坏现有 DSL 语义。
- 测试和实现成本最低。

适用前提：

- 当前业务对“立即持久化”没有刚性要求。
- collection 更像脚本执行态上下文，而不是共享数据库。

### 5.2 方向 B：仍以内存为主，但补齐持久化语义

这是中期更平衡的方向。

做法：

- 保持运行时以内存 collection 为主。
- 在现有 `flush()` 之外，补充更清晰的持久化能力描述。
- 例如增加 backend 配置语义或策略接口：
  - `load_mode`
  - `flush_mode`
  - `read_only`
  - `auto_flush`

这个方向不一定要立刻改 trait，但至少可以先把配置层和文档层补清楚。

优点：

- 保持现有执行模型稳定。
- 能逐步解决“持久化接口太弱”的问题。
- 为以后引入更强后端做铺垫。

### 5.3 方向 C：引入 live sqlite backend

这是长期可行但成本更高的方向。

建议做法不是“直接把当前 sqlite 打开”，而是：

- 将其定义为另一类 backend，例如 `sqlite_live`。
- 明确它的语义与 memory/json backend 的异同。
- 分阶段只在 set/map 上试点。

建议分阶段：

1. 先支持 sqlite live set。
2. 再支持 sqlite live map。
3. 仅在类型边界清楚后，再考虑 list/multimap。

进入这个方向前，需要先明确：

- 遍历顺序是否必须稳定。
- 是否要求 traversal 期间禁止写入。
- `CollectionValue` 的允许入库类型集合。
- 是否需要事务或批量写入抽象。

## 6. 推荐结论

基于当前代码和需求状态，推荐结论如下：

### 6.1 短期推荐

- 保持 process-chain 当前 collection 主模型不变。
- 将 sqlite 继续视为未支持 backend。
- 保持“显式错误返回”边界，避免误用或 panic。
- 在文档中明确：当前 JSON 也是内存态运行，不是直写后端。

### 6.2 中期推荐

- 优先整理持久化语义，而不是先上 live sqlite。
- 把“何时落盘、是否自动 flush、哪些后端支持持久化”说清楚。
- 让配置模型先能表达 backend 行为，再决定是否扩展 trait。

### 6.3 长期推荐

- 如果确实存在“共享状态、立即生效、跨进程可见”的真实需求，再单独设计 sqlite live backend。
- 不建议直接把当前 gateway-lib 的 sqlite 实现无修改搬进 process-chain。
- 更合理的方式是先抽象共用 backend 能力，再按 process-chain 语义补齐顺序、类型和遍历期写保护。

## 7. 后续落地建议

如果未来要继续推进，建议按以下顺序展开：

1. 先补文档与配置边界：明确 memory/json/sqlite 的当前状态。
2. 梳理 process-chain collection trait 中哪些语义是必须保持一致的。
3. 盘点 gateway-lib 现有 sqlite set/map 哪些能力可复用，哪些与现有语义冲突。
4. 若确实需要 live backend，先做 set/map 的最小试点，不要同时覆盖 list/multimap。
5. 在试点前先确定类型支持白名单与顺序语义，不要边实现边决定。

## 8. 一句话判断

当前 `cyfs-process-chain` 的 collection 后端，本质上是“运行时内存容器 + 可选持久化 flush”；“直接 sqlite、写入立即生效”的方案技术上可行，但它属于新的 backend 语义设计，不是简单把现有 sqlite 开关打开即可。