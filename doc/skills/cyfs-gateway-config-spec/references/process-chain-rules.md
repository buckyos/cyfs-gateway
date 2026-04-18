# Process Chain 规则

这是 cyfs-gateway 中 process chain 的自包含规则摘要，可直接用于写规范、写示例、做 review。

## 1. 它在配置里的位置

process chain 主要承载在这些字段里：

- `stacks.<id>.hook_point`
- `servers.<id>.hook_point`
- `servers.<id>.post_hook_point`
- `stacks.<rtcp>.on_new_tunnel_hook_point`
- `global_process_chains`
- `timers.<id>.process-chain` / `process_chain`

常见 YAML 形状：

```yaml
hook_point:
  main:
    priority: 1
    blocks:
      default:
        priority: 1
        block: |
          match $REQ.path "/api/*" && call-server api_server;
          reject;
```

解释：

- `hook_point` 是 chain map
- 每个 chain 下有 `priority`
- `blocks` 是 block map
- 每个 block 有 `priority` 和多行 DSL 文本 `block`

运行时会把 map 形式转换成数组，并按 `priority` 执行。

## 2. 执行模型

可以把它理解成三层：

- `block = function / 子程序`
- `chain = 一个独立执行体`
- `hook_point = chain 列表`

关键语义：

- 一个 chain 内的所有 block 共享同一套 chain 环境变量
- 在一个 block 中写入的变量，后续 block 可直接读取
- 不同 chain 之间默认隔离
- 同一个 hook_point 上的多个 chain 共享全局环境，但不共享 chain 局部变量
- `return` 会结束当前返回作用域
- 命中终止类结果后，当前 chain / hook_point 不再继续按普通顺序往下跑

执行顺序：

1. 先按 chain 优先级执行
2. 每个 chain 内再按 block 优先级执行
3. 若没有终止结果，继续后续 block / chain
4. 遇到终止结果，由 hook 的宿主解释结果

## 3. 变量与作用域

常见变量写法：

- `$VAR`
- `${REQ.path}`
- `${REQ.target.host}`
- `${RESP.server}`

赋值和作用域约定：

- 默认赋值是 `chain` 级
- `global` / `export`：全局作用域
- `chain`：当前 chain 作用域
- `block` / `local`：当前 block 局部作用域

常见写法：

```txt
my_var=123
global user_id=alice
local full_url="https://${REQ.host}${REQ.uri}"
```

实践建议：

- 跨 block 共享的中间结果用默认 chain 级变量
- 只在当前 block 临时使用的值用 `local`
- 真正需要跨 chain 共享时才用 `global`

## 4. 常见语法约定

它的逻辑风格接近 shell：

- `cmd1 && cmd2`：前者成功时执行后者
- 规则从上到下执行
- 遇到终止指令后停止当前链路
- 多条命令通常按换行或 `;` 分隔

### 4.1 表达式链

一行 DSL 本质上是“表达式链”：

- 表达式之间可用 `&&` / `||` 连接
- 也可以用 `;` 分成多个 statement
- `!` 只能作用在紧随其后的单个表达式上
- `()` 可显式分组，控制组合逻辑
- 执行顺序是从左到右，按 `&&` / `||` 短路

最常见的判断风格不是返回布尔值，而是看命令状态：

- `success` 视为条件成立
- `error` 视为条件不成立
- `control` 在普通 `if` 条件里非法，会报错

中缀比较语法糖：

- `a == b` -> `eq --loose a b`
- `a === b` -> `eq a b`
- `a != b` -> `ne --loose a b`
- `a !== b` -> `ne a b`
- `a > b` / `>=` / `<` / `<=` -> `gt` / `ge` / `lt` / `le`

注意：

- `==` / `!=` 是宽松比较，不等于大小写忽略
- `===` / `!==` 是严格 typed 比较
- 数值比较不会自动做字符串宽松转换

### 4.2 结构化控制块

当逻辑不再适合一行 `predicate && action` 时，应该改用 statement 级语法。
这些语句属于 DSL 语法层，不是普通命令。

#### `if / elif / else / end`

规范形状：

```txt
if <condition> then
    ...
elif <condition> then
    ...
else
    ...
end
```

精确规则：

- `if` / `elif` 头必须以 `then` 结尾
- 条件不能为空
- `else` 必须单独成行，且最多出现一次
- `end` 结束整个 `if` 语句
- `elif` 可以有多个
- `else` 可以省略
- 分支体可以为空
- 支持嵌套

条件支持：

- 谓词命令：`if eq $REQ.method "GET" then`
- 取反：`if !match $REQ.path "/api/*" then`
- 逻辑组合：`if (eq $REQ.method "GET" || eq $REQ.method "HEAD") && !match $REQ.path "/internal/*" then`
- 比较语法糖：`if $REQ.target.port >= 1024 then`

运行时语义：

- 按 `if` -> `elif` 顺序逐个求值
- 第一个成功分支命中后，后续分支不再执行
- 所有条件都不成立时，执行 `else`
- 没有 `else` 时，整个 `if` 语句返回普通 success，继续后续语句
- 条件里如果出现 `return` / `error --from ...` / `exit` / `goto` 这类 control 结果，会直接报错，而不是当作真值

常见 parse/runtime 错误：

- 缺少 `end`
- `if` / `elif` 头缺少 `then`
- `if` / `elif` 条件为空
- `else` 后面又出现 `elif`
- 条件里写了 `return` / `error --from ...` / `exit` / `goto`

例子：

```txt
if match $REQ.path "/api/*" && eq $REQ.method "GET" then
    call-server api_get;
elif match $REQ.path "/api/*" then
    call-server api_mutation;
else
    reject;
end
```

#### `for ... in ... then ... end`

规范形状：

```txt
for item in $list then
    ...
end

for key, value in $map then
    ...
end
```

精确规则：

- 头必须以 `then` 结尾
- 第一变量始终必填；第二变量可选
- `for item in $list`：`item` 是元素值
- `for idx, item in $list`：`idx` 是索引，`item` 是元素值
- `for item in $set`：`item` 是元素值
- `for key, value in $map`：`key` / `value` 分别是 map 键和值
- `for key, values in $multi_map`：第二变量拿到 value 集合

运行时语义：

- 循环变量只在 `for ... end` 内可见
- 与外层同名变量会在循环结束后恢复
- `break [value]` 只退出当前循环
- `return` / `error` / `exit` / `goto` 继续按原语义向外传播
- 遍历中修改同一个正在遍历的 collection 会失败

#### `match-result ... end`

规范形状：

```txt
match-result $(<command>)
ok(value)
    ...
err(err_value)
    ...
control(action, from, value)
    ...
end
```

精确规则：

- 头部必须是单个命令替换 `$(...)`
- `ok(...)` / `err(...)` / `control(...)` 至少出现一个
- 每种分支最多出现一次
- `control(...)` 必须声明三个不同变量：`action, from, value`

运行时语义：

- 先执行一次 `$(...)`
- 再按 `ok / err / control` 分支消费结果
- 未处理的结果类型会原样向外传播
- 适合处理“一个命令可能返回 success / error / control”的复杂逻辑

典型规则：

```txt
match ${REQ.host} "*.example.com" && forward "http://127.0.0.1:8080";
reject;
```

含义：

1. 先匹配 host
2. 匹配成功则终止并返回 `forward ...`
3. 否则继续执行下一句
4. 最终拒绝

## 5. 结果类型与控制语义

process chain 里的执行结果可以粗分成三类：

- `success`：当前表达式 / 语句成立或执行成功
- `error`：当前表达式 / 语句失败，常被上层逻辑当作“条件不成立”
- `control`：不是普通真假值，而是显式改变控制流

最常见的 `control` 家族：

- `return` / `error --from ...`
  向 block / chain / lib 调用者返回
- `goto`
  改写执行位置，当前路径后续代码不再继续
- `exit`
  结束当前 process-chain list
- `accept` / `reject` / `drop`
  是网关宿主最常见的终止结果
- `break`
  只对 `for` / `map` 这类迭代语境有意义

这里的重点是“语义分类”，不是命令手册。
如果需要精确语法、参数形式、目标寻址规则、`--from` 差异，直接看 [process-chain-command-manual.md](process-chain-command-manual.md)。

## 6. 环境变量速查

不同 hook 暴露的环境变量不同，最常用的是 `REQ` 和 `RESP`。

### HTTP `hook_point`

常见字段：

- `REQ.path`
- `REQ.uri`
- `REQ.method`
- `REQ.host`
- `REQ.<header-name>`
- `REQ_remote_ip`
- `REQ_remote_port`

### HTTP `post_hook_point`

只重点暴露：

- `RESP`

`RESP` 是响应头 map，可用 `map-add` / `map-set` / `map-remove` 修改。

限制：

- 只能改响应头
- 不能改状态码
- 不能重新决定路由
- `drop` / `reject` / `return` 等 control 结果会被忽略

### TCP / TLS / TUN TCP

常见字段：

- `REQ.dest_host`
- `REQ.dest_port`
- `REQ.dest_addr`
- `REQ.source_addr`
- `REQ.source_ip`
- `REQ.source_port`

### SOCKS

常见字段：

- `REQ.target.type`
- `REQ.target.host`
- `REQ.target.ip`
- `REQ.target.port`
- `REQ.inbound`

注意：

- SOCKS 请求环境变量按当前实现视为只读

### DNS

常见字段：

- `REQ.name`
- `REQ.record_type`
- `REQ.source_addr`

### RTCP `on_new_tunnel_hook_point`

最常见的是使用来源相关字段做准入判断，例如：

- `REQ.source_device_id`
- `REQ.source_addr`

## 7. 写配置时的推荐模式

### 模式 1：主链路 + 明确兜底

```txt
match $REQ.path "/api/*" && call-server api;
match $REQ.path "/static/*" && call-server web_dir;
reject;
```

适合简单路由。

### 模式 2：拆 block 做模块化

```txt
exec parse_target;
exec permit_check;
exec route_request;
reject;
```

适合复杂业务逻辑。

### 模式 3：HTTP 路由与响应后处理分离

- 路由决策放 `hook_point`
- header 改写放 `post_hook_point`

不要把二次路由写进 `post_hook_point`。

### 模式 4：全局共享规则抽到 `global_process_chains`

适合复用：

- 通用鉴权片段
- 通用 header 处理
- 通用选择器逻辑

## 8. 文档分工

- `process-chain-rules.md`
  只负责解释配置承载位置、执行模型、变量作用域、表达式链、结构化语句、环境变量和推荐模式
- `process-chain-command-manual.md`
  负责解释 statement / 命令的精确语法、参数、返回语义、canonical 名称和宿主扩展命令

简单判断：

- 用户问“这段 DSL 为什么这样执行”或“语法骨架怎么写”
  先看本文件
- 用户问“某条命令到底怎么写”
  看 `process-chain-command-manual.md`

## 9. 写规范时的最低要求

如果用户要求“包含 process chain 规则的配置规范”，答案至少应覆盖：

- process chain 在配置里的承载位置
- chain / block / hook_point 的执行关系
- 变量与作用域
- 表达式链的 `&&` / `||` / `!` / `;` / `()` 与 success/error 判定方式
- `if/elif/else/end` 这类结构化语句的基本语义
- `exec` / `return` / `error` / `accept` / `reject` / `forward` 的语义
- `post_hook_point` 的限制
- `REQ` / `RESP` 的最常用字段

如果用户要求的是“完整 DSL 手册”或“命令精确语法”，再继续扩展到 `process-chain-command-manual.md` 里的命令列表。
