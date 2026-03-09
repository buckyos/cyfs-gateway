# RFC: Collection 语义与 Backend 能力模型

本文档用于正式化 `cyfs-process-chain` 中 collection 的语言语义与 backend 能力边界。

本文档的目标不是解释某个具体实现文件，而是给出脚本作者、运行时实现者与未来 backend 扩展者都可以依赖的一组公共契约。

- crate: `cyfs-process-chain`
- status: draft
- updated: `2026-03-09`

## 1. 文档目标

本文档主要回答以下问题：

- collection 在语言中的定位是什么。
- collection 变量赋值与参数传递时采用什么语义。
- List/Set/Map/MultiMap 的顺序语义是什么。
- 遍历期间允许哪些修改，禁止哪些修改。
- 持久化与 backend 差异属于语言语义还是运行时能力。
- 不同 backend 至少必须满足哪些公共契约。

本文档优先定义“语言层应当稳定可依赖的语义”，其次才说明“当前实现状态”。

## 2. 术语定义

### 2.1 Collection

本文所说的 collection 包括以下四类运行时容器：

- `List`
- `Set`
- `Map`
- `MultiMap`

### 2.2 引用语义

引用语义指两个变量或参数持有同一个 collection 对象的共享引用。

若其中一方修改 collection 内容，另一方观察到相同变化。

### 2.3 稳定顺序

稳定顺序指在不引入额外重排操作的前提下：

- 遍历结果遵循插入顺序或语言定义的固定顺序。
- 删除元素后，其余元素保持相对顺序不变。
- 重复插入既有元素不会无故改变其相对位置，除非该类型语义明确规定允许重排。

### 2.4 Flush

`flush` 指把某个 backend 中尚未持久化的 collection 变更显式写入持久化介质。

### 2.5 Live Backend

live backend 指读写操作直接作用于持久化后端，其可见性不依赖显式 `flush()`。

### 2.6 可移植脚本

可移植脚本指仅依赖语言公共契约，不依赖某个 backend 私有行为的脚本。

## 3. Collection 的语言定位

在 `process_chain` 中，collection 的首要定位是：

> 规则执行期的结构化状态容器。

这意味着：

- collection 首先服务于规则表达和状态传递。
- collection 不是数据库查询抽象，也不是宿主外部存储的直接别名。
- backend 的存在不应反向主导语言主语义。

因此语言设计上应优先保证：

- 引用语义可预测。
- 遍历顺序可预测。
- 遍历期修改约束可预测。
- 后端差异不会破坏上述核心语义。

## 4. Collection 引用语义

### 4.1 赋值语义

将 collection 赋给变量时，默认采用引用语义，而不是值拷贝语义。

例如：

- `local a=$tags`
- `local current=$REQ.target`

若右侧是 collection，则左侧变量与右侧变量共享同一个底层对象。

### 4.2 参数传递语义

当 collection 通过以下方式传递时，默认保持引用语义：

- block/chain 调用中的参数传递
- `invoke --arg ...` 传递 collection 值
- 命令返回值被赋给变量

除非未来引入显式 clone/copy 机制，否则 collection 传递不应被理解为深拷贝。

### 4.3 可观察后果

基于引用语义，以下行为属于语言契约：

- 若两个变量引用同一个 `Set/Map/MultiMap/List`，任一方的写操作对另一方可见。
- 若 collection 被传入下游 chain 或 block，下游修改对上游可见，除非调用边界另有明确拷贝语义。
- collection 的“别名共享”是正常语义，不属于未定义行为。

### 4.4 当前未提供的能力

当前语言层未正式提供以下能力：

- collection 的显式深拷贝语义
- collection 的只读借用语义
- collection 的事务性快照复制语义

若脚本需要这些能力，当前不应假定语言已支持。

## 5. 顺序语义

### 5.1 List

`List` 的顺序语义如下：

- 遍历顺序等于当前索引顺序。
- `push` 追加到尾部。
- `insert(index, value)` 将元素插入指定位置，后续元素顺延。
- `remove(index)` 删除元素后，后续元素前移。
- `set(index, value)` 只替换值，不改变其他元素顺序。

### 5.2 Set

`Set` 在语言层不是无序集合，而是稳定有序集合。

其顺序语义如下：

- 遍历顺序遵循首次插入顺序。
- 重复插入已有元素不会改变该元素顺序。
- 删除元素后，剩余元素相对顺序保持不变。
- 删除后再次插入同一元素，该元素被视为新插入，位于当前尾部。

### 5.3 Map

`Map` 的顺序语义如下：

- 遍历顺序遵循 key 的首次插入顺序。
- 对已存在 key 执行 `insert`/更新，不应改变该 key 的相对顺序。
- 删除 key 后，剩余 key 的相对顺序保持不变。
- 删除后再次插入同一 key，该 key 被视为新插入，位于当前尾部。

### 5.4 MultiMap

`MultiMap` 有两层顺序语义：

- key 的遍历顺序遵循 key 的首次插入顺序。
- 每个 key 下 value 集合的遍历顺序遵循该 value 的首次插入顺序。

此外：

- 对同一 key 重复插入已有 value，不应改变其相对顺序。
- 删除某个 value 后，其他 value 保持相对顺序不变。
- 删除后再次插入同一 value，应视为新插入，位于该 key 下尾部。

### 5.5 顺序语义的层级

顺序语义属于语言核心契约的一部分，不应被视为某个具体 backend 的偶然行为。

因此：

- backend 可以有不同实现手段。
- 但 backend 不应破坏语言定义的顺序语义。

## 6. 遍历与修改语义

### 6.1 总原则

语言层默认要求 collection 在遍历期间保持行为可预测。

因此，当前推荐的公共契约是：

> 同一 collection 在一次遍历进行期间，不允许对其执行会改变结构的写操作。

### 6.2 结构性写操作

结构性写操作包括但不限于：

- List: `push / insert / set / remove / pop / clear`
- Set: `insert / remove`
- Map: `insert_new / insert / remove`
- MultiMap: `insert / insert_many / remove / remove_many / remove_all`

### 6.3 当前语义要求

若脚本在遍历同一 collection 期间执行结构性写操作，应视为运行时错误，而不是允许 backend 自由决定行为。

该要求的目的在于：

- 避免不同 backend 在游标、快照、锁策略上的差异泄漏到语言层。
- 保持脚本在 memory/json/future backend 上具有一致可预测性。

### 6.4 Backend 责任

即使某个 backend 在技术上允许边遍历边写入，该 backend 也不应直接暴露这种差异，除非语言规范将来显式放宽此约束。

## 7. 持久化语义

### 7.1 语言主语义与持久化分离

在 `process_chain` 中，持久化能力不改变 collection 的语言主语义，只影响：

- 数据从哪里载入。
- 变更何时变为 durable。
- backend 是否支持跨进程或跨重启可见。

因此：

- collection 的引用语义、顺序语义、遍历约束优先于持久化实现差异。

### 7.2 Memory Backend

对 memory backend，语言层只保证：

- 运行时可读写。
- 生命周期受宿主进程及执行上下文约束。

不保证：

- 重启后持久化。
- 跨进程共享可见。

### 7.3 Flush-Based Backend

对 flush-based backend，例如当前的 JSON backend，语言层保证：

- 运行时仍按正常 collection 语义工作。
- backend 可在内存中积累脏变更。
- 只有在显式 `flush()` 成功之后，才可以认为变更被 durable 地写入后端介质。

因此：

- 未 flush 的变更不应被脚本或宿主假定为已持久化。
- `flush()` 失败时，语言层应视为持久化失败，而不是静默成功。

### 7.4 Live Backend

若未来引入 live backend，则其应满足：

- 读写直接作用于后端。
- 不依赖显式 `flush()` 才生效。

但 live backend 仍不得破坏：

- 引用语义
- 顺序语义
- 遍历期写保护语义

### 7.5 持久化不是复制语义

无论 collection 是否可持久化，持久化动作本身都不意味着值拷贝或隔离。

持久化只决定 durability，不改变 collection 在当前运行期的共享引用关系。

## 8. Backend 能力模型

为了避免直接用 backend 名字描述语义，建议将 backend 能力拆成独立维度。

### 8.1 能力维度

一个 collection backend 可以拥有以下能力维度：

- `stable_order`: 是否保证语言要求的稳定顺序
- `flush_based_persistence`: 是否通过显式 `flush()` 提供持久化
- `live_persistence`: 是否写入立即生效
- `complex_value_support`: 是否支持复杂 `CollectionValue`
- `cross_process_visibility`: 是否支持跨进程共享可见
- `transactional_write`: 是否支持事务性写入

### 8.2 语言最低公共契约

所有被视为语言级 collection backend 的实现，至少必须满足：

- `stable_order = true`
- 保持引用语义一致
- 保持遍历期写保护一致
- 不把 backend 私有差异泄漏成脚本行为差异

### 8.3 Backend 私有能力

以下能力可以视为 backend 私有扩展，而非语言最低公共契约：

- 是否跨进程共享
- 是否支持事务
- 是否支持高并发外部写入
- 是否支持更复杂的持久化值模型

## 9. 值类型限制

### 9.1 三层类型集合

collection 相关值类型应区分三层：

1. 运行时可持有值
2. 可持久化值
3. 跨 backend 可移植值

这三层不必完全相同。

### 9.2 运行时可持有值

运行时 collection 中可以出现的值，原则上由 `CollectionValue` 定义决定。

这包括但不限于：

- `null`
- `bool`
- `number`
- `string`
- 某些 collection 引用
- 某些 visitor 或 runtime 专用对象

### 9.3 可持久化值

backend 若支持持久化，不代表所有运行时值都可持久化。

当前或未来 backend 可显式限制：

- 仅支持基础标量值
- 不支持 `Visitor`
- 不支持 `Any`
- 不支持嵌套 collection

### 9.4 可移植值

若脚本希望跨 backend 保持行为一致，则应优先只依赖最小公共值集合。

当前推荐的最小公共集合是：

- `null`
- `bool`
- `number`
- `string`

复杂值是否能跨 backend 可移植，不应默认假定为支持。

## 10. 可移植性规则

### 10.1 脚本作者默认可依赖的内容

脚本作者在不显式绑定某个 backend 时，应只依赖以下内容：

- collection 的引用语义
- collection 的稳定顺序语义
- 遍历期间禁止结构性修改
- collection 作为运行时状态容器的公共操作契约

### 10.2 不应默认依赖的内容

脚本作者不应默认依赖：

- 写入后立即 durable
- backend 支持复杂值持久化
- 跨进程可见
- backend 提供数据库级事务语义
- backend 暴露额外排序或查询能力

## 11. 当前落地状态

截至本文档更新时间，当前实现状态如下：

- memory backend: 已实现，为当前语言运行时基线
- json backend: 已实现，采用“load into memory + dirty flush”模型
- process-chain 内部 sqlite backend: 未实现，不属于当前可用语言能力
- gateway-lib 中的 sqlite set/map: 仅可视为未来可参考实现，不等同于 process-chain 当前语言契约

因此，当前最稳妥的语言解释是：

- collection 主模型仍然是 memory-first
- 持久化 backend 只是在该模型外增加 durability 能力

## 12. 未定与保留项

以下问题在未来仍可能演进，当前文档不将其视为既定能力：

- 是否引入 collection 显式 clone/copy 语义
- 是否引入只读视图或只读借用
- 是否引入 live sqlite backend
- 是否把 backend capability 暴露给脚本层
- 是否引入事务型 collection backend 抽象
- 是否允许在某些受控场景下放宽遍历期写保护

## 13. 一句话约束

`process_chain` 中的 collection 首先是规则执行期的结构化状态容器。

引用、顺序与遍历修改约束属于语言契约。

持久化与 backend 差异属于运行时能力，但不得破坏上述核心语义，除非规范未来显式放宽。