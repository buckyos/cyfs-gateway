# pc-lint (MVP)

`pc-lint` 是 `cyfs-process-chain` 的静态检查工具（第一版），用于在运行前发现常见脚本问题。

crate:

- `src/components/cyfs-process-chain-lint`

## 快速使用

```bash
cd src
cargo run -p cyfs-process-chain-lint -- check <file-or-dir>
```

示例：

```bash
cd src
cargo run -p cyfs-process-chain-lint -- \
  check components/cyfs-process-chain/doc/templates \
  --format text \
  --fail-on error
```

## CLI 参数

```text
pc-lint check <INPUT> [--format text|json] [--fail-on error|warning|info] [--known-var <NAME>...]
```

- `INPUT`: 单个文件或目录（递归扫描 `.xml` / `.json`）。
- `--format`: 输出格式，默认 `text`。
- `--fail-on`: 达到该严重级别时以非 0 退出（默认 `error`）。
- `--known-var`: 追加“已知外部变量”，减少未定义变量误报。

## 默认已知变量

当前默认内置：

- `REQ`
- `REQ_HEADER`
- `REQ_URL`
- `__args`
- `__key`
- `__value`
- `__index`

## 已实现规则（MVP）

### `PC-LINT-1001` Undefined variable

- 严重级别：`error`
- 含义：检测到变量读取时未定义（按当前静态可见作用域判断）。
- 说明：对 `?.` / `?[...]` / `??` 触发的“可选读取”做降噪处理，避免误报。

### `PC-LINT-3001` Unused variable

- 严重级别：`warning`
- 含义：检测到变量定义后未被使用。
- 说明：以下划线 `_` 开头的变量默认忽略未使用告警。

### `PC-LINT-3002` Scope shadowing

- 严重级别：`warning`
- 含义：检测到变量定义遮蔽了外层作用域同名变量（例如 block 遮蔽 chain/global）。

### `PC-LINT-3003` Overwritten before read

- 严重级别：`warning`
- 含义：检测到变量在读取前被同作用域重新赋值覆盖。

### `PC-LINT-4001` Loose comparison risk

- 严重级别：`warning`
- 含义：检测到 `eq/ne/gt/ge/lt/le` 使用 `--loose`。
- 目的：提示潜在隐式转换风险。
- 说明：同样覆盖 `==` / `!=` 等语法糖映射后的 loose 比较。

### `PC-LINT-4101` Rewrite-reg template `$` ambiguity

- 严重级别：`warning`
- 含义：在 `rewrite-reg/rewrite-regex` 的 template 参数中检测到非 `$<digit>` 的 `$` 用法。
- 说明：该上下文中 `$name` 不表示 DSL 变量插值，通常是误用；双引号下字面 `$` 也需要 `\$`。

### `PC-LINT-4102` Rewrite-reg template multi-digit capture risk

- 严重级别：`warning`
- 含义：检测到 template 中使用 `$10` 这类多位捕获组引用。
- 说明：当前运行时会按 `$1` + `0` 解释，存在语义歧义。

### `PC-LINT-4103` Command substitution composite expression error

- 严重级别：`error`
- 含义：解析失败且疑似在 `$(...)` 中混入 `&&/||/;` 组合表达。
- 说明：`$(...)` 只支持单命令，建议将组合逻辑外提到 `if`/`capture`。

## 当前限制

- 分支与控制流是保守近似分析，不是完整路径敏感 CFG。
- 动态变量名/动态路径属于启发式处理，可能存在少量误报或漏报。
- 当前尚未覆盖“恒不可能分支/跨作用域副作用”等高级规则。
