# RFC: `match-result` 结果分支语句（草案）

本文档定义 `cyfs-process-chain` 的结构化结果分支语句 `match-result`，目标是让脚本可以直接对命令执行结果 `CommandResult` 做分支处理，减少当前依赖 `capture` 拆解状态、再配合 `if` 手工拼装控制流的样板代码。

## 1. 背景与问题

当前 DSL 中，命令执行结果由 [src/cmd/cmd.rs](../src/cmd/cmd.rs) 中的 `CommandResult` 表示：

- `Success(CollectionValue)`
- `Error(CollectionValue)`
- `Control(CommandControl)`

当前脚本若要根据某个子命令的不同结果执行不同逻辑，通常只能使用 `capture`：

```process-chain
capture --value v --status st --control-kind kind --from from $(some-command)

if eq $st "success" then
    ...
elif eq $st "error" then
    ...
else
    ...
end
```

这种写法存在几个明显问题：

- 结果解构步骤冗长，业务意图不够直观。
- `Success` / `Error` / `Control` 的三态分支需要手工拼装。
- `Control` 的传播语义容易被脚本作者误处理。
- `capture` 暴露的是底层机制，而不是业务友好的控制流结构。

目标是提供一个语句级结构，让脚本作者能直接表达“执行一次子命令，然后按结果类型进入不同分支”。

## 2. 目标与非目标

### 2.1 目标

- 提供结果导向的结构化控制流。
- 只执行一次子命令，然后基于其 `CommandResult` 分支。
- 与现有 `if/for`、`return/error/exit/break` 语义保持一致。
- 第一版优先复用现有 `capture` 语义与运行时模型，避免重复造轮子。

### 2.2 非目标（V1 不做）

- 不实现 Rust 风格的通用模式匹配语言。
- 不支持复杂 payload 模式匹配，如 `Ok(Number(n))`。
- 不支持 guard 语法，如 `ok(v) if ...`。
- 不支持分支表达式求值返回（保持语句式 DSL 设计）。

## 3. 设计原则

### 3.1 它是“语句”，不是“命令”

`match-result` 应建模为语句级控制结构，而不是普通 command：

- 普通 command 适合“输入若干参数，返回一个结果”。
- `match-result` 的核心是“执行一次子命令，再根据结果类型进入不同语句块”。
- 这与当前 `if ... then ... end`、`for ... in ... end` 更接近。

### 3.2 `Control` 默认透传

`Control` 在当前 DSL 中不是普通返回码，而是结构化流程控制：

- `Return(...)`
- `Error(...)`
- `Exit(...)`
- `Break(...)`

第一版必须避免默认吞掉这些控制动作。因此：

- 若脚本未显式声明 `control(...)` 分支，则所有 `Control` 原样向外传播。
- 只有显式声明了 `control(...)` 分支，才视为调用方想拦截 control。

这个规则是整个设计中最关键的一条。

## 4. 语法提案

### 4.1 推荐语法（MVP）

```process-chain
match-result $(some-command)
ok(value)
    ...
err(err_value)
    ...
end
```

带 control 分支的版本：

```process-chain
match-result $(some-command)
ok(value)
    ...
err(err_value)
    ...
control(action, from, value)
    ...
end
```

### 4.2 语法说明

- `$(some-command)` 必须是命令替换，保证子命令只执行一次。
- 第一版只接受 `$(...)` 形式，不接受裸命令形式如 `match-result exec --chain foo`。
- `ok(...)` / `err(...)` / `control(...)` 都不是必填全套；V1 只要求至少声明一个分支。
- 因此如果脚本只关心成功路径，可以只写 `ok(value)`；如果只关心 control，也可以只写 `control(action, from, value)`。
- `ok(value)` 匹配 `CommandResult::Success(value)`。
- `err(err_value)` 匹配 `CommandResult::Error(err_value)`。
- `control(action, from, value)` 匹配 `CommandResult::Control(...)`。
- `end` 结束整个 `match-result` 块。

### 4.3 不推荐的第一版语法

以下 Rust 风格语法不建议在 V1 引入：

```text
match-result $(cmd) {
Ok(v) => ...
Err(e) => ...
}
```

原因：

- 当前 DSL 以逐行语句块为主，不是表达式型语言。
- 项目中已经存在 `match` 系列命令，直接引入 Rust 风格 `match` 容易产生认知冲突。
- 花括号与箭头语法会显著增加 parser 复杂度，但第一版收益有限。

同时，以下“裸命令”形式也不建议在 V1 支持：

```text
match-result exec --chain auth_flow
```

原因：

- `$(...)` 已是当前 DSL 中“将子命令作为子表达式求值”的既有约定。
- 强制 `$(...)` 可以明确子命令边界，避免 parser 在分支头与子命令参数之间产生歧义。
- 这也让 `match-result` 更容易复用 `capture` 与 command substitution 的现有实现路径。

## 5. 运行时语义

### 5.1 分支匹配规则

执行流程如下：

1. 先执行一次子命令，得到 `CommandResult`。
2. 若结果为 `Success(value)`：
    - 若存在 `ok(...)` 分支，则进入该分支。
    - 若不存在 `ok(...)` 分支，则返回原始 `Success(value)`。
3. 若结果为 `Error(value)`：
    - 若存在 `err(...)` 分支，则进入该分支。
    - 若不存在 `err(...)` 分支，则返回原始 `Error(value)`。
4. 若结果为 `Control(control)`：
   - 若存在 `control(...)` 分支，则进入该分支。
   - 若不存在 `control(...)` 分支，则原样向外传播，不消费该结果。

这意味着 `match-result` 不是强制穷尽匹配结构；未声明的结果类型会保持默认行为继续向外传递。

### 5.2 分支变量绑定

建议分支变量采用 block-local 作用域，仅在对应分支中可见：

- `ok(value)` 中的 `value` 仅在 `ok` 分支内可见。
- `err(err_value)` 中的 `err_value` 仅在 `err` 分支内可见。
- `control(action, from, value)` 中的变量仅在该分支内可见。

这可以避免不同分支变量互相污染，也避免分支结束后的残留状态。

### 5.3 `control(action, from, value)` 的绑定规则

建议映射如下：

- `action`
  - `return`
  - `error`
  - `exit`
  - `break`

- `from`
  - 当 control 为 `Return` 或 `Error` 时，取 `block|chain|lib`
  - 当 control 为 `Exit` 或 `Break` 时，取 `null` 或空值

- `value`
  - 取 control 携带的 payload

### 5.4 语句返回值

`match-result` 语句本身返回“命中分支执行后的最后一个 `CommandResult`”。

也就是说：

- 若 `ok` 分支最后执行了某个普通命令，则返回该命令结果。
- 若 `err` 分支内部执行了 `return --from block ...`，则该 control 继续传播。
- 若未声明 `err` 分支且子命令返回了 `Error(value)`，则整个 `match-result` 返回原始 `Error(value)`。
- 若未声明 `control` 分支且子命令直接返回了 `Control`，则整个 `match-result` 不消费，直接原样返回。

## 6. 与 `capture` 的关系

### 6.1 `capture` 继续保留

`capture` 仍然有价值：

- 适合需要把结果拆成若干变量后，在更远处多次使用的场景。
- 适合调试、日志、低层控制。

但它不适合作为主要的“结果分支控制流”。

### 6.2 `match-result` 建议实现为 `capture` 语法糖

第一版的推荐实现路径：

- `match-result` 在 parser / linker 层被编译为等价的内部结构。
- 运行时复用现有 `capture` 的结果拆解逻辑。
- 用统一的结果解释规则，避免再造第二套 `CommandResult` 解构语义。

这能降低实现风险，并保证 `capture` 与 `match-result` 的行为一致。

## 7. 示例

### 7.1 Success / Error 分支

```process-chain
match-result $(match $REQ.host "*.example.com")
ok(value)
    echo "matched" $value;
    return --from block "allow";
err(err_value)
    echo "not matched" $err_value;
    return --from block "deny";
end
```

### 7.2 显式处理 control

```process-chain
match-result $(invoke --chain auth_flow --arg req $REQ)
ok(value)
    local auth_result=$value;
    return --from block $auth_result;
err(err_value)
    error --from block $err_value;
control(action, from, value)
    echo "callee control:" $action $from $value;
    return --from block $value;
end
```

### 7.3 未声明 control 分支时透传

```process-chain
match-result $(exec --chain other_chain)
ok(value)
    echo "ok" $value;
err(err_value)
    echo "err" $err_value;
end
```

若 `other_chain` 返回 `return --from lib ...`，则该 `Control` 不会被 `match-result` 吃掉，而是继续向外传播。

### 7.4 只声明 ok 分支

```process-chain
match-result $(some-command)
ok(value)
    echo "success:" $value;
end
```

这类写法是合法的。

- 若 `some-command` 返回 `Success(value)`，则进入 `ok` 分支。
- 若 `some-command` 返回 `Error(value)`，则整个语句返回原始 `Error(value)`。
- 若 `some-command` 返回 `Control(...)`，则整个语句返回原始 `Control(...)`，除非显式声明了 `control(...)` 分支。

### 7.5 只声明 err 分支

```process-chain
match-result $(match $REQ.host "*.example.com")
err(err_value)
    echo "not matched:" $err_value;
    return --from block "fallback";
end
```

这类写法同样合法。

- 若子命令返回 `Error(value)`，则进入 `err` 分支。
- 若子命令返回 `Success(value)`，则整个语句返回原始 `Success(value)`。
- 若子命令返回 `Control(...)`，则整个语句返回原始 `Control(...)`，除非显式声明了 `control(...)` 分支。

### 7.6 只声明 control 分支

```process-chain
match-result $(invoke --chain auth_flow --arg req $REQ)
control(action, from, value)
    echo "callee control:" $action $from $value;
    return --from block $value;
end
```

这种写法适合“只想拦截调用方 control，其余 success/error 保持默认行为”的场景。

- 若子命令返回 `Control(...)`，则进入 `control` 分支。
- 若子命令返回 `Success(value)`，则整个语句返回原始 `Success(value)`。
- 若子命令返回 `Error(value)`，则整个语句返回原始 `Error(value)`。

## 8. 解析与 AST 建议

### 8.1 Parser 建议

在 block parser 中新增一类语句结构：

- `match-result <command-substitution>`
- 后续紧跟零到多个分支头
  - `ok(...)`
  - `err(...)`
  - `control(...)`
- 每个分支下是若干行嵌套语句
- 以 `end` 结束

### 8.2 AST 建议

可以新增类似结构：

```rust
pub struct MatchResultStatement {
    pub command: Expression,
    pub ok_branch: Option<MatchResultBranch>,
    pub err_branch: Option<MatchResultBranch>,
    pub control_branch: Option<MatchControlBranch>,
}
```

其中分支持有：

- 绑定变量名
- 分支语句列表

不建议第一版支持多个 `ok` / 多个 `err` / 多个 `control` 分支，以降低复杂度。

## 9. 分阶段落地计划

### P1（MVP）

- 支持 `match-result $(cmd)`。
- 支持 `ok(value)` 与 `err(value)`。
- 支持统一的 `control(action, from, value)`。
- 默认 `Control` 透传。
- 分支变量仅分支内可见。

### P2（增强）

- 支持省略绑定变量，如 `ok()` / `err()`。
- 支持更细粒度的 control 分支声明。
- 支持 `else` 风格兜底分支（可选）。

### P3（可选）

- 支持 guard。
- 支持 payload 类型匹配。
- 若确有必要，再评估 Rust 风格语法糖。

## 10. 最小测试矩阵

第一版建议至少覆盖以下测试：

1. `Success` 命中 `ok` 分支。
2. `Error` 命中 `err` 分支。
3. `Control` 且未声明 `control` 分支时原样透传。
4. `Control` 且声明了 `control` 分支时可被显式处理。
5. 分支变量仅在分支内可见。
6. 子命令只执行一次。
7. 分支最后一个结果成为 `match-result` 的结果。

## 11. 开放问题

- `control` 是否需要在 V1 就支持按 action 细分分支，而不是统一一个分支？
- `from` 在 `exit/break` 场景下采用 `null`、空字符串，还是直接省略绑定更合适？
- 分支变量是否要允许 `_` 作为显式忽略占位符？
- 未来是否需要把 `match-result` 与 `invoke/exec` 的 control 规范进一步统一成更高层的“调用约定”？

## 12. 结论

`match-result` 适合作为 `cyfs-process-chain` 的结构化结果分支语句。

它解决的是当前 `capture` 过于底层、结果控制流表达不直观的问题；同时又不需要把 DSL 扩展成一门完整的模式匹配语言。

推荐采用“语句块 + 强制 `$(cmd)` 输入 + control 默认透传 + 复用 capture 语义”的实现路线，以最小风险获得最大的可用性收益。