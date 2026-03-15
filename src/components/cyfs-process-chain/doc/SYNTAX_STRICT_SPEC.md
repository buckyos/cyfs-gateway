# Process-Chain Strict Syntax Spec (Draft)

本文档定义一套“严格语法”约束，目标是减少 `$` 相关歧义和 `$(...)` 组合表达踩坑。

## 1. 设计目标

- 同一语法符号在同一上下文只有一种主要语义。
- 能静态检查的问题尽量在 lint 阶段提示，而不是运行时报错。
- 兼顾可读性和可迁移性，优先给出“推荐写法”。

## 2. 上下文语义

| 上下文 | 典型位置 | `$` 语义 |
| --- | --- | --- |
| 变量表达式 | `$a` / `${a.b}` | 变量读取 |
| 普通参数/字符串 | `echo "$a"` / `append` 参数 | 建议仅显式变量读取，不混入 regex template 语义 |
| `rewrite-reg/rewrite-regex` 的 template 参数 | `rewrite-reg ... "<template>"` | 仅 `$<digit>` 表示捕获组引用 |
| 命令替换 | `$(...)` | 仅允许一个命令表达式 |

补充：在双引号字符串里，字面 `$` 需要写成 `\$`；或改用单引号字符串。

## 3. 规则

### 3.1 rewrite-reg template

- 只把 `$<digit>` 识别为捕获组替换（如 `$1`, `$2`）。
- `$name` 不表示 DSL 变量插值，通常是可疑写法。
- `$10` 在当前运行时语义上会被当作 `$1` + 字符 `0`，建议显式拆写或避免。

### 3.2 command substitution

- `$(...)` 内只允许一个命令。
- 不允许在 `$(...)` 内直接拼 `&&`/`||`/`;` 形成组合表达。
- 复杂逻辑建议写成多行：先 `capture` 提取，再在外层 `if/elif/else` 组合。

## 4. 推荐写法

错误示例：

```process-chain
echo $(eq $a 1 && echo ok);
rewrite-reg $path '^/(.*)$' "/$user/$1";      # 双引号中未转义 $，且 $user 不是变量插值
```

推荐示例：

```process-chain
capture --ok is_ok --value match_val -- call eq $a 1;
if $is_ok then
  echo "ok";
end

local suffix="user";
rewrite-reg $path '^/(.*)$' '/$1';            # template 只保留捕获组语义
rewrite-reg $path '^/(.*)$' "/\$user/\$1";    # 如果确实要字面 '$'，双引号下需写 '\$'
```

说明：第二段仅展示“不要把 `$user` 当 template 变量”的思路；template 参数内建议只使用 `$<digit>`。

## 5. lint 对应规则

- `PC-LINT-4101`：rewrite-reg template 中出现非捕获组 `$` 写法。
- `PC-LINT-4102`：rewrite-reg template 中出现多位捕获组（如 `$10`）风险。
- `PC-LINT-4103`：`$(...)` 组合表达语法错误提示。
