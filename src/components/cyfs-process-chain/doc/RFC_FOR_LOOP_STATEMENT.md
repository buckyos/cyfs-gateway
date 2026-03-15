# RFC: `for ... in ...` 循环语句（草案）

本文档定义 `cyfs-process-chain` 的结构化容器遍历语句，目标是解决当前 `map-reduce` 在可读性和表达能力上的限制。

## 1. 背景与问题

当前脚本里“遍历容器并处理命中逻辑”主要依赖 `map`（map-reduce）命令，存在以下痛点：

- `map_cmd` 必须是单个命令替换，复杂控制流（多行逻辑、条件分支）表达困难。
- `break` 仅绑定到 map-reduce 语义，脚本作者心智负担高。
- 路由、过滤、聚合等常见场景需要较多样板代码。

目标是引入语句级循环，让脚本在“遍历 + 分支 + 控制流”上具备统一能力。

## 2. 目标与非目标

### 2.1 目标

- 提供直观可读的容器遍历语法。
- 支持 `break`（以及后续可扩展 `continue`）。
- 与现有 `if/elif/else`、`return/error/exit/goto` 语义一致。
- 不破坏现有 `map-reduce` 命令行为（先共存）。

### 2.2 非目标（V1 不做）

- 不引入 Python/JS 风格表达式推导。
- 不引入自定义排序器 / comparator 语法。
- 不做循环并行执行。

## 3. 语法提案

为保持 DSL 一致性，采用 `then ... end` 风格（而非 `{}`）：

```process-chain
for item in $list then
    ...
end
```

```process-chain
for key in $set then
    ...
end
```

```process-chain
for key, value in $map then
    ...
end
```

```process-chain
for key, value in $multi_map then
    ...
end
```

可选语法糖（后续）：

```process-chain
for index, item in $list then
    ...
end
```

> 注：若未来支持 `{}` 形式，应作为 parser sugar，不改变核心 AST 与执行模型。

## 4. 运行时语义

### 4.1 容器类型与绑定变量

- `List`：
  - `for item in $list`：绑定 `item`。
  - （后续）`for index, item in $list`：绑定 `index` + `item`。
- `Set`：`for key in $set` 绑定元素字符串。
- `Map`：`for key, value in $map` 绑定 key/value。
- `MultiMap`：`for key, value in $multi_map`，每个 `(key, value)` 迭代一次。

### 4.2 作用域

- 循环变量为“循环局部变量”，可见范围仅在 `for ... end` 块内。
- 每次迭代覆盖本轮循环变量值。
- 循环外不可读（避免污染 block 作用域）。

### 4.3 控制流

- `break`：终止当前最近一层循环。
- （后续）`continue`：跳过当前迭代并进入下一轮。
- `return/error/exit/goto`：按既有语义向外传播，不被循环吞掉。

### 4.4 修改容器约束

- 默认沿用现有集合遍历约束：遍历过程中禁止直接修改同一容器结构（避免并发修改问题）。

## 5. 与 `map-reduce` 的关系

### 5.1 共存策略（推荐）

- `map` 命令继续保留，保障兼容。
- 新增 `for` 语句用于大多数业务遍历逻辑。
- 官方示例优先推荐 `for`，`map` 逐步弱化为“偏函数式/聚合场景”。

### 5.2 迁移示例

现有写法：

```process-chain
map $routes $(call check_route $__key $__value) reduce $(echo $__result);
```

建议写法：

```process-chain
for key, value in $routes then
    if call check_route $key $value then
        break;
    end
end
```

## 6. 路由场景说明

`for` 可以表达“模式表遍历 + 命中停止”，但需注意：

- 当前 `Map/MultiMap` 的迭代顺序采用插入顺序，`for key, value in $map` / `for key in $multi_map`
  在同一份数据上可稳定复现“首命中优先级”。
- 若业务需要“显式优先级字段排序”（而不是插入顺序），仍建议在脚本层通过 `List` 维护规则顺序。

## 7. 静态检查（pc-lint）建议

新增规则建议：

- `for` 目标不是集合类型（error）。
- `break` 出现在循环外（error）。
- 循环变量遮蔽外层同名变量（warning）。
- 循环变量定义后未使用（info/warning，可配置）。

## 8. 分阶段落地计划

### P1（最小可用）

- 支持 `for item in $list|$set`、`for key,value in $map|$multi_map`。
- 支持 `break` 在循环内生效。
- 单测覆盖：正常遍历、命中 break、嵌套循环、非法 break。

### P2（增强）

- 支持 `continue`。
- 支持 `for index, item in $list`。
- lint 规则首版接入。

### P3（可选）

- 语法糖 `{}` 风格（仅 parser sugar）。
- 与 `route-match` 等高层命令方案联动。

## 9. 开放问题

- 循环变量是否允许显式声明作用域关键字（如 `local`）？
- `break` 是否支持携带值（复用现有 `break value`）并可被外层读取？
- 是否需要引入 `for ... where ...` 过滤语法，还是坚持“if 组合”？
