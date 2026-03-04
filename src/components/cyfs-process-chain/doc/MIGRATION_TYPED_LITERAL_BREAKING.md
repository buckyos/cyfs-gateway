# Typed Literal 破坏性迁移清单与批量规则（草案）

- status: Draft
- scope: `src/components/cyfs-process-chain`
- scenario: 不保留 `legacy` 兼容策略，默认启用 typed literal（`true/false/null/123/12.5`）

## 1. 目标与边界

本草案用于“从零开始”的升级路径：把未加引号的基础字面量直接视为 typed value，而不是字符串，并接受对应的破坏性变更。

本草案不覆盖：

1. 历史 JSON 兼容层设计。
2. 完整静态类型检查器。
3. 复杂表达式系统（仅讨论基础字面量与常见命令参数迁移）。

## 2. 破坏性清单（Checklist）

| 编号 | 影响面 | 旧行为（字符串中心） | 新行为（typed-first） | 风险等级 | 迁移动作 |
|---|---|---|---|---|---|
| B01 | 未加引号字面量 | `123/true/null` 常被当字符串使用 | 直接变 `Number/Bool/Null` | 高 | 字符串语义一律加引号 |
| B02 | 字符串命令参数 | `match/append/replace/...` 可依赖隐式字符串化 | 在 strict typed 下可能报类型错误 | 高 | 对字符串参数强制引号或显式转换 |
| B03 | 集合 ID/Key 参数 | `map-add test 123 value` 中 `123` 常作为字符串 key | 可能变为 number key 或类型不匹配 | 高 | 集合 ID 和 key 全部显式写成字符串 |
| B04 | 变量路径 `[]` 访问 | `$m[123]` 常等价 key `"123"` | 可能解释为数字索引语义 | 高 | map key 强制 `$m["123"]`，list 索引用数字 |
| B05 | 控制流 payload | `return/error/exit` 默认字符串通道 | 若控制流 typed 化，调用方断言会变化 | 中 | 协议化返回值继续用引号字符串 |
| B06 | 外部命令入参 | external handler 常假设参数是字符串 | 可能收到 `Bool/Number/Null` | 中 | external 接口补充 typed 分支或先转字符串 |
| B07 | 测试与文档 | 旧用例隐式依赖字符串化 | 断言类型/文本会变化 | 中 | 按迁移规则统一更新测试与示例 |

## 3. 批量迁移规则（推荐执行顺序）

### R1. 字符串语义强制加引号

凡是“业务上应是字符串”的 token，一律写成 `"..."` 或 `'...'`，不要裸写。

示例：

```txt
# before
local user_id=123;
local enabled=true;
return --from lib ok;

# after
local user_id="123";
local enabled="true";
return --from lib "ok";
```

### R2. 集合 ID 与 key 统一按字符串处理

`map_id / set_id / list_id / key` 等命名标识统一加引号，避免 literal typed 化误伤。

```txt
# before
map-add users 123 active;
set-add tags true;

# after
map-add "users" "123" "active";
set-add "tags" "true";
```

### R3. 路径访问明确区分 map key 与 list index

1. map key（即使看起来像数字）使用引号：`$m["123"]`  
2. list index 使用数字：`$list[0]`

```txt
# before
$route[123]

# after (map key)
$route["123"]
```

### R4. 模式与模板参数始终引号化

`match` pattern、`match-reg` regex、字符串模板等全部加引号，避免 parser/evaluator 漂移。

```txt
# before
match $host *.example.com;
match-reg $url ^/api/.*$;

# after
match $host "*.example.com";
match-reg $url "^/api/.*$";
```

### R5. 需要 typed 的地方保留裸字面量

仅在明确需要 typed 行为时使用裸字面量，例如：

```txt
local retry_count=3;   # Number
local enabled=true;    # Bool
local deleted_at=null; # Null
```

### R6. 动态输入先归一化，再进入业务判断

输入来源不稳定（环境变量、外部命令返回、invoke 参数）时，先用显式转换命令做归一化，再执行判断逻辑。

```txt
local n_text=$REQ.retryCount;
local n=$(to-number $n_text);
is-number $n || error --from block "invalid_retry_count";
```

备注：若后续引入 `to-string`、`eq-typed`、`cmp` 等命令，应优先采用 typed 原生命令，逐步减少旧字符串命令依赖。

### R7. 外部命令参数协议显式化

external 命令应定义参数契约：

1. 明确哪些参数接受 typed。
2. 对仅接受字符串的参数，在脚本侧加引号。
3. 在 external 实现中避免默认 `as_str().unwrap()`。

### R8. 返回值协议固定化

跨链路（`invoke/exec/goto/return/error`）传递的业务状态建议使用字符串协议（如 `"ok"`, `"reject"`, `"E_TIMEOUT"`），避免调用端被 typed 改动波及。

### R9. 对“真假值”做显式约束

不要混用 `"true"` 与 `true`。在脚本接口文档中明确字段类型，并在命令入口做校验。

### R10. 迁移期禁止新增裸字面量字符串风格

代码评审规则：新脚本里凡是字符串常量必须加引号，防止回流旧写法。

## 4. 批量迁移流程（建议）

### 步骤 1：全量扫描候选点

先做“疑似裸字面量”扫描，建立改造清单：

```bash
cd src
rg -n '\b(true|false|null)\b|\b-?[0-9]+(\.[0-9]+)?\b' components/cyfs-process-chain
```

再重点扫描字符串语义命令：

```bash
cd src
rg -n '\b(match|match-reg|append|replace|map-add|set-add|return|error|exit)\b' components/cyfs-process-chain
```

### 步骤 2：按规则批量改造

优先改造高风险位点：

1. `map-add/set-add/list-*` 的 id/key/value。
2. `match/match-reg/append` 的 pattern/template 参数。
3. `return/error/exit` 的协议化返回值。

### 步骤 3：回归与收敛

1. 先跑单测（重点 `test_var/test_coercion/test_list`）。
2. 再跑 `cyfs-process-chain` 全量测试。
3. 对 external 命令补充 typed 输入测试。

## 5. 评审门禁建议

迁移期建议新增两条门禁：

1. 新增脚本中，字符串常量必须加引号。
2. map key 若是字面量数字，必须写成 `["123"]` 或显式说明 list 索引意图。

---

`CommandResult` typed payload 已落地（`return/error/goto/invoke` 控制流边界已切换为 typed value 传递）；如需进一步规范外部接口契约，建议补充“控制流协议迁移”子文档，集中约束跨模块调用边界。
