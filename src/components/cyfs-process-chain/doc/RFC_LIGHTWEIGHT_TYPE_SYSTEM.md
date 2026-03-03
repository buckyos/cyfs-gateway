# 轻量类型系统 RFC（草案）

- status: Draft
- scope: `src/components/cyfs-process-chain`
- goal: 把脚本运行时从“字符串中心”升级为“轻量一等类型”，并优先保证实现简洁与可维护性

## 1. 背景与现状

当前实现已经支持集合类型引用（`Set/Map/MultiMap`）在变量中传递，但核心求值和命令返回仍偏字符串语义：

1. `CollectionValue` 缺少 `Bool/Number/Null/List/Object` 一等类型，见 [coll.rs](../src/collection/coll.rs)。
2. 命令参数大量通过 `evaluate_string` 收敛为字符串，见 [block.rs](../src/block/block.rs)。
3. `CommandResult` 的 success/error payload 仍是 `String`，见 [cmd.rs](../src/cmd/cmd.rs)。
4. 多数命令实现天然字符串化，例如 `match`、`range`、`map-add` 等。

这会导致：

1. 隐式转换不透明（`"123"`、`123`、`"true"` 的语义边界不清）。
2. 条件与比较逻辑容易出现“能跑但语义漂移”。
3. 脚本作者难以区分 `missing`、`null`、`""`。

## 2. 设计目标

1. 运行时行为默认保持稳定，但不为不优雅的旧持久化格式强行兼容。
2. 新增类型能力可按 policy 渐进启用。
3. 显式转换优先，减少隐式魔法。
4. `missing` 与 `null` 明确分离。
5. 保持集合引用语义（`Set/Map/MultiMap`）不被破坏。

## 3. 非目标

1. 不在第一阶段引入完整静态类型检查器。
2. 不在第一阶段改写整套 DSL 语法。
3. 不把 `MapCollection`/`SetCollection` 强行替换为 JSON object/array。
4. 不为历史 JSON 持久化边角格式提供额外兼容分支。

## 4. 值模型建议

建议扩展现有 `CollectionValue`，最小新增：

1. `Null`
2. `Bool(bool)`
3. `Number(NumberValue)`（建议 `Int(i64)` + `Float(f64)`，后续可演进）
4. `List(Vec<CollectionValue>)`
5. `Object(BTreeMap<String, CollectionValue>)`

保留已有：

1. `String`
2. `Set`
3. `Map`
4. `MultiMap`
5. `Visitor`
6. `Any`

原则：

1. `Object/List` 是值类型（可克隆）。
2. `Set/Map/MultiMap` 继续是可变集合引用类型（保持当前引用语义）。
3. `Display` 仅用于调试或日志，不作为语义转换入口。

## 5. Policy 扩展建议

在现有 `ExecutionPolicy`（当前只有 `missing_var`）基础上扩展：

1. `literal_mode`: `legacy_string | typed`
2. `coercion_mode`: `legacy | warn | strict`
3. `bool_mode`: `command_status | strict_bool | truthy`

默认建议：

1. `literal_mode=legacy_string`
2. `coercion_mode=legacy`
3. `bool_mode=command_status`

说明：

1. 默认值保持旧行为。
2. 新项目可显式开启 typed/strict。
3. warn 模式用于迁移窗口，先观测再收紧。

## 6. 转换规则建议（核心）

### 6.1 基础原则

1. 允许显式转换（命令或函数），不鼓励隐式转换。
2. 隐式转换只在 `coercion_mode=legacy|warn` 下存在。
3. `strict` 下，类型不匹配直接报错。

### 6.2 `missing` vs `null`

1. `missing`：路径不存在（当前已有语义）。
2. `null`：存在但值为空。
3. `??` 仅对 `missing` 生效（延续当前语义）；若后续要支持 `null` 参与 coalesce，建议新增独立操作符或 policy 开关，避免破坏旧脚本。

## 7. 命令层 API 建议

新增统一取参辅助层，减少每个命令重复写转换逻辑：

1. `evaluate_value()`（已存在）
2. `evaluate_string(policy)`
3. `evaluate_bool(policy)`
4. `evaluate_number(policy)`
5. `evaluate_list(policy)`
6. `evaluate_object(policy)`

并提供统一错误码：

1. `E_TYPE_MISMATCH`
2. `E_COERCION_FAILED`
3. `E_INVALID_NUMBER`
4. `E_NULL_NOT_ALLOWED`
5. `E_MISSING_VALUE`

## 8. 语法与命令建议（分阶段）

### 阶段 A（低风险，先做）

1. 扩展运行时值类型（不改默认字面量解析）。
2. 新增显式转换命令：
   - `to-bool`
   - `to-number`
   - `to-string`
   - `is-null`
   - `is-number`
3. `type` 命令返回更细的类型名（兼容旧值）。

### 阶段 B（中风险）

1. 对 `eq/range/match` 增加 typed 分支或新命令：
   - `eq-typed`
   - `cmp`
2. `coercion_mode=warn` 时记录隐式转换告警日志。

### 阶段 C（高收益）

1. 在 `literal_mode=typed` 下启用字面量识别：
   - `true/false/null`
   - 整数/浮点数字面量
2. 增加 list/object 字面量（可选）：
   - `[]`
   - `{}`
   - 或通过 `parse-json` 作为过渡方案。

### 阶段 D（结构性升级）

1. 将 `CommandResult::Success/Error` payload 从 `String` 升级为 typed value。
2. 为 `$(...)` 增加 typed substitution（可与现有字符串替换并存）。

## 9. 兼容策略

1. 默认 policy 仍保持 legacy，尽量不改变既有脚本执行语义。
2. 新能力通过 policy 或新命令显式启用。
3. 对 JSON 持久化格式采取“可维护性优先”策略：
   - 原生支持 `null/bool/number/string`。
   - 对 `List/Set/Map/MultiMap/Visitor/Any` 直接报错，不再降级写入空字符串。
   - 不引入旧格式兼容分支（当前历史数据量可控）。
4. 文档提供迁移提示：若历史文件包含“被降级为字符串”的旧数据，按业务需要一次性清洗。

## 10. 测试矩阵建议

1. parser 层：
   - legacy vs typed literal 解析差异
2. evaluator 层：
   - string/bool/number/null/list/object 转换
   - strict/warn/legacy coercion
3. command 层：
   - `eq/range/match` 在不同 policy 下行为
4. integration 层：
   - invoke/goto/if 下 typed payload 传递
   - missing/null/coalesce 组合

## 11. 推荐落地顺序

1. `P0`: 值类型扩展 + policy 字段扩展 + 取参辅助函数。
2. `P1`: 显式转换命令 + `type` 命令增强 + 错误码统一。
3. `P2`: 比较/匹配命令 typed 化（先加新命令，再考虑替换旧命令）。
4. `P3`: parser typed literal 与可选 list/object 字面量。
5. `P4`: `CommandResult` typed payload（最后做，改动面最大）。

## 12. 与当前实现的关系

本 RFC 兼容当前以下已实现能力：

1. `ExecutionPolicy` 机制（可扩展 policy 字段）。
2. `missing_var` strict/lenient 机制。
3. 变量路径 `.` + `[]` + `?.` + `??`。
4. 集合引用语义（`Map/Set/MultiMap`）与 `invoke` 参数传递。

建议先按 `P0/P1` 开两个里程碑，避免一次性大改。
