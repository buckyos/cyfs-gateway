# Process Chain 命令手册

这是 cyfs-gateway / cyfs-process-chain 当前内建命令的自包含手册。

用途：

- 查询某条命令的规范写法
- 确认命令真实名称、参数形式、作用域和返回语义
- 区分旧文档里混用的别名写法和当前实际注册名

边界：

- 本文覆盖两层内容：
  - `cyfs-process-chain` 的固定内建命令
  - `cyfs-gateway` 运行时默认注册的一组宿主扩展命令
- 执行模型、hook_point/chains/blocks 的关系，仍以 `process-chain-rules.md` 为准。

## 1. 使用方式

这份文档只回答两类问题：

- 某条命令的精确语法是什么
- 参数、作用域、返回语义、canonical 名称到底是什么

不重复解释：

- hook_point / chain / block 的执行模型
- 规则为什么会这样流转
- 基础语法设计原则

这些内容统一看 [process-chain-rules.md](process-chain-rules.md)。

在开始前先记三点：

- process chain 以 `success / error / control` 三态运行
- 很多路由规则都写成 `predicate && action`
- 旧资料常把 `match-reg` / `rewrite-reg` 写成下划线版本，这里统一只用当前 canonical 名

结构化语句不在本手册展开，统一放在 [process-chain-rules.md](process-chain-rules.md)。

## 2. 控制命令

| 命令 | 规范语法 | 说明 |
| --- | --- | --- |
| `goto` | `goto --block <id>` / `goto --chain <id>` / `goto --lib <id>` | 先执行目标，再把结果映射成当前调用者的 `return/error`；支持 `--arg KEY VALUE`、`--from`、`--ok-from`、`--err-from` |
| `exec` | `exec <block_id>` / `exec --block <id>` / `exec --chain <id>` / `exec --lib <id>` | 调用 block/chain/lib，执行完成后继续当前代码；不传命名参数 |
| `invoke` | `invoke <block_id>` / `invoke --chain <id> --arg k v ...` | 类似 `exec`，但会把命名参数注入到 `__args.<key>` |
| `return` | `return [value]` / `return --from block|chain|lib [value]` | 成功返回到指定层级 |
| `error` | `error [value]` / `error --from block|chain|lib [value]` | 失败返回到指定层级 |
| `exit` | `exit` / `exit <value>` | 结束当前 process-chain list |
| `break` | `break` / `break <value>` | 只用于 `map` 内部提前中断 |
| `accept` | `accept` | 等价于 `exit accept` |
| `reject` | `reject` | 等价于 `exit reject` |
| `drop` | `drop` | 等价于 `exit drop` |

### 控制命令细节

- `goto` 的目标解析规则与 `invoke` 相同，支持：
  - block: `block` / `chain:block` / `lib:chain:block`
  - chain: `chain` / `lib:chain`
  - lib: `lib`
- `exec` / `invoke` 如果目标内部出现 `return` / `error`，会被归一化成普通 success/error 结果。
- `exit` 不能在 `exec` / `invoke` 的目标内部作为可返回 control 继续上传；它本来就是结束当前 list。
- `break` 只适合 map-reduce 语境，不适合普通 hook chain。

### 常用例子

```txt
match $REQ.path "/api/*" && call-server api_server;
match-include $IP $REQ_real_remote_ip && accept;
goto --chain auth_flow --from chain;
invoke --block enrich_req --arg req $REQ --arg tenant $tenant_id;
return --from lib "done";
error --from chain "permission denied";
```

## 3. 变量与结果命令

| 命令 | 规范语法 | 说明 |
| --- | --- | --- |
| `assign` | 实际写法通常是 `name=value`、`global name=value`、`local name=value` | 赋值或调整变量默认作用域；实际 DSL 多直接写赋值语法，不显式写 `assign` |
| `delete` | `delete [--global|--chain|--block] <name>` | 删除变量；支持删除 `map.path` 形式的嵌套项 |
| `type` | `type [--global|--chain|--block] <name>` | 返回值类型；找不到变量时返回 error `"None"` |
| `to-bool` | `to-bool <value>` | 按运行时 coercion 规则转成布尔值 |
| `to-number` | `to-number <value>` | 按运行时 coercion 规则转成数字 |
| `is-null` | `is-null <value>` | 判断是否为 Null |
| `is-bool` | `is-bool <value>` | 判断是否为 Bool |
| `is-number` | `is-number <value>` | 判断是否为 Number |
| `capture` | `capture --value v --status s $(cmd ...)` | 执行一次子命令，把结果值/状态写入本地变量，同时原样返回原始结果 |

### `capture` 可抓取的字段

- `--value VAR`：`CommandResult.value()`
- `--status VAR`：`success` / `error` / `control`
- `--ok VAR`：是否 success
- `--error VAR`：是否 error
- `--control VAR`：是否 control
- `--control-kind VAR`：`return` / `error` / `exit` / `break`
- `--from VAR`：`block` / `chain` / `lib`

### 变量命令例子

```txt
user_id=alice
global tenant_id=demo
local full_url=$(append "https://" $REQ.host $REQ.url)
type $REQ.target
capture --value result --status st $(call my_ext $REQ.path)
delete --block tmp_value
```

## 4. 匹配与比较命令

| 命令 | 规范语法 | 说明 |
| --- | --- | --- |
| `match` | `match [--no-ignore-case] <value> <glob>` | glob 匹配，默认大小写不敏感 |
| `match-reg` | `match-reg [--capture name] [--no-ignore-case] <value> <regex>` | 正则匹配；可把 capture 写回 `name[0]`、`name[1]`... |
| `eq` | `eq [--ignore-case] [--loose] <left> <right>` | 相等比较；默认强类型比较 |
| `ne` | `ne [--ignore-case] [--loose] <left> <right>` | 不等比较 |
| `gt` | `gt [--loose] <left> <right>` | 数值大于 |
| `ge` | `ge [--loose] <left> <right>` | 数值大于等于 |
| `lt` | `lt [--loose] <left> <right>` | 数值小于 |
| `le` | `le [--loose] <left> <right>` | 数值小于等于 |
| `range` | `range <value> <begin> <end>` | 判断数值是否落在闭区间 `[begin, end]` |

### 比较命令细节

- `match` 用 glob，不是正则。
- `match-reg` 用 Rust regex；`--capture name` 会写环境变量：
  - `name[0]`、`name[1]`、`name[2]` ...
- `eq` / `ne`：
  - 默认强类型比较
  - `--ignore-case` 只对字符串比较有意义
  - `--loose` 允许字符串和数字宽松比较
- `gt` / `ge` / `lt` / `le` / `range` 都是数值比较；无法解析为数字时会失败

### 常用例子

```txt
match $REQ.path "/api/*" && call-server api;
match-reg --capture hp $REQ.host "^([a-zA-Z0-9_]+)[-.]" || reject;
eq --ignore-case $REQ.method "GET" && accept;
gt --loose $REQ.content_length 1048576 && reject;
range $REQ.target.port 1000 2000 && accept;
```

## 5. 字符串命令

| 命令 | 规范语法 | 说明 |
| --- | --- | --- |
| `rewrite` | `rewrite <$var> <glob> <template>` | 用 glob 重写变量值；会回写原变量 |
| `rewrite-reg` | `rewrite-reg <$var> <regex> <template>` | 用正则重写变量值；模板里可用 `$1`、`$2` |
| `replace` | `replace [-i|--ignore-case] <$var> <match> <replacement>` | 替换变量值中的子串；会回写原变量 |
| `append` | `append <a> <b> [more...]` | 直接拼接多个参数并返回新字符串 |
| `slice` | `slice <string> <start:end>` | 按字节区间切片；要求 UTF-8 边界合法 |
| `strlen` | `strlen <string>` | 返回字符串长度；当前实现按字节数计算 |
| `starts-with` | `starts-with [-i|--ignore-case] <string> <prefix>` | 前缀判断 |
| `ends-with` | `ends-with [-i|--ignore-case] <string> <suffix>` | 后缀判断 |
| `url_encode` | `url_encode <string>` | URL 百分号编码 |
| `url_decode` | `url_decode <string>` | URL 百分号解码；非法 `%XX` 或非 UTF-8 会报错 |

### 字符串命令细节

- `rewrite` 适合 glob 改写，比如路径前缀、host 模板。
- `rewrite-reg` 的 canonical 名是 `rewrite-reg`；不要写成 `rewrite_reg`。
- `replace` / `rewrite` / `rewrite-reg` 都会修改原变量。
- `append` 只返回结果，不会自动写回变量；需要配合赋值：

```txt
local full_url=$(append "https://" $REQ.host $REQ.url)
rewrite $REQ.url "/kapi/my-service/*" "/kapi/*"
rewrite-reg $REQ.url "^/test/(\\w+)(?:/(\\d+))?" "/new/$1/$2"
replace -i $REQ.host ".internal" ".svc"
slice $REQ.path 0:10
strlen $REQ.path
starts-with $REQ.path "/api/"
ends-with $REQ.host ".example.com"
url_encode $REQ.url
```

## 6. Collection 命令

### 6.1 `match-include`

```txt
match-include <collection> <key> [value...]
```

行为按 collection 类型不同：

- `List`：要求 `<key>` 与后续所有 `value` 都包含在 list 中
- `Set`：只检查 `<key>` 是否存在
- `Map`：
  - 只给 `<key>`：检查 key 是否存在
  - 给 `<key> <value>`：检查 key 对应值是否等于该 value
- `MultiMap`：
  - 只给 `<key>`：检查 key 是否存在
  - 给 `<key> <value...>`：要求这些 value 都挂在该 key 下

例子：

```txt
match-include $APP_INFO $app_id || reject;
match-include $IP $REQ_real_remote_ip && accept;
match-include $HOST $REQ.host "www.example.com" && call-server web;
```

### 6.2 List 命令

| 命令 | 规范语法 | 说明 |
| --- | --- | --- |
| `list-create` | `list-create [--global|--chain|--block] <list_id>` | 创建 list；默认 chain 级 |
| `list-push` | `list-push <list_id> <value...>` | 末尾追加一个或多个值 |
| `list-insert` | `list-insert <list_id> <index> <value>` | 在指定下标插入 |
| `list-set` | `list-set <list_id> <index> <value>` | 覆盖指定下标 |
| `list-remove` | `list-remove <list_id> <index>` | 删除指定下标；成功时返回被删值 |
| `list-pop` | `list-pop <list_id>` | 弹出末尾元素；成功时返回被弹出值 |
| `list-clear` | `list-clear <list_id>` | 清空整个 list |

例子：

```txt
list-create request_history
list-push request_history "step1" "step2"
list-insert request_history 0 "begin"
list-set request_history 1 "rewritten"
list-remove request_history 0
list-pop request_history
list-clear request_history
```

### 6.3 Set 命令

| 命令 | 规范语法 | 说明 |
| --- | --- | --- |
| `set-create` | `set-create [--global|--chain|--block] <set_id>` | 创建 set；默认 chain 级 |
| `set-add` | `set-add <set_id> <value...>` | 插入一个或多个值；至少插入一个新值才算 success |
| `set-remove` | `set-remove <set_id> <value...>` | 删除一个或多个值；至少删掉一个值才算 success |

例子：

```txt
set-create trusted_hosts
set-add trusted_hosts "192.168.1.1" "192.168.100.1"
set-remove trusted_hosts "192.168.1.1"
match-include trusted_hosts $REQ_real_remote_ip && accept;
```

### 6.4 Map / MultiMap 命令

| 命令 | 规范语法 | 说明 |
| --- | --- | --- |
| `map-create` | `map-create [-m|--multi] [--global|--chain|--block] <map_id>` | 创建 Map 或 MultiMap；默认普通 Map |
| `map-add` | `map-add <map_id> <key> <value...>` | Map 只能给一个 value；MultiMap 可给多个 value |
| `map-remove` | `map-remove <map_id> <key> [value...]` | Map 可按 key 删除整项；MultiMap 需要给 value 才能删具体值 |

关键差异：

- 普通 `Map`
  - `map-add map_id key value`
  - `map-remove map_id key`
- `MultiMap`
  - `map-create --multi map_id`
  - `map-add map_id key value1 value2 ...`
  - `map-remove map_id key value1 value2 ...`

注意：

- 当前实现下，`MultiMap` 的 `map-remove` 不适合只给 key；应明确给出要删的 value。
- `map-add` 对普通 Map 是“覆盖或新增”，不是“只允许新增”。

例子：

```txt
map-create session_map
map-add session_map session123 user1
map-remove session_map session123

map-create --multi ip_event_map
map-add ip_event_map 192.168.0.1 login blocked
map-remove ip_event_map 192.168.0.1 blocked
```

## 7. Map-Reduce 命令

| 命令 | 规范语法 | 说明 |
| --- | --- | --- |
| `map` | `map <coll> <map_cmd>` / `map <coll> <map_cmd> reduce <reduce_cmd>` / `map --begin $(...) --map $(...) [--reduce $(...)] <coll>` | 在 collection 上执行 map-reduce；`break` 只在这里有意义 |

说明：

- `map_cmd` / `reduce_cmd` 通常写成命令替换：`$(...)`
- `--begin` 只执行一次，用来初始化局部变量
- `map` 阶段对集合元素逐个处理
- `reduce` 阶段聚合 map 结果

例子：

```txt
map --begin $(local sum="") --map $(sum=$(append $sum ${key})) my_coll
map my_coll $(echo ${key}) reduce $(echo ${sum})
```

## 8. CYFS Gateway 宿主扩展命令

这些命令不是 `cyfs-process-chain` core built-in，而是 `cyfs-gateway` 默认注册到运行时的扩展命令。写网关配置时，它们通常可以直接当命令使用。

### 8.1 最常用的路由 / 响应动作

| 命令 | 规范语法 | 说明 |
| --- | --- | --- |
| `call-server` | `call-server <server_id>` | 返回 `server <id>` 动作，把处理交给另一个 server 配置对象 |
| `forward` | `forward [round_robin\|ip_hash] <upstream...>` / `forward [round_robin\|ip_hash] --map <map>` | 返回 `forward "..."` 动作；支持多上游与权重 |
| `redirect` | `redirect <location> [301\|302\|303\|307\|308]` | 返回 HTTP 重定向响应 |
| `error` | `error <status 400..599> [message]` | 返回 HTTP 错误响应；这是网关 HTTP 响应命令，不是 core control `error --from ...` |

关键区别：

- core control `error`：

```txt
error --from chain "permission denied"
```

- gateway HTTP response `error`：

```txt
error 403 "permission denied"
```

`forward` 例子：

```txt
forward "http://127.0.0.1:8080"
forward tcp:///127.0.0.1:80 tcp:///127.0.0.1:81
forward ip_hash tcp:///127.0.0.1:80,weight=3 tcp:///127.0.0.1:81,weight=1
forward round_robin --map $UPSTREAMS
```

说明：

- `forward` 缺省算法是 `round_robin`
- 支持 `ip_hash`
- inline upstream 可写 `url,weight=N`
- `--map` 需要一个 map，key 是 upstream URL，value 是权重

### 8.2 Probe / 协议探测命令

| 命令 | 规范语法 | 说明 |
| --- | --- | --- |
| `http-probe` | `http-probe` | 探测明文 HTTP 流，写入 `REQ.dest_host`、`REQ.app_protocol=http`、`REQ.ext.method/path/version/url` |
| `https-sni-probe` | `https-sni-probe` | 探测 TLS ClientHello 的 SNI，写入 `REQ.dest_host`、`REQ.app_protocol=https` |
| `proxy-protocol-probe` | `proxy-protocol-probe` | 探测 PROXY protocol v1/v2，写入 `REQ.ext.proxy_*` 并更新源地址信息 |

这些 probe 命令通常要求当前宿主环境里有 `REQ.incoming_stream`。

### 8.3 鉴权 / 解析 / 运维辅助命令

| 命令 | 规范语法 | 说明 |
| --- | --- | --- |
| `verify-jwt` | `verify-jwt <jwt> <issuer_public_key_map>` | 校验 JWT，并返回 payload map；第二个参数是以 `iss` 为 key 的公钥 map |
| `parse-cookie` | `parse-cookie <cookie_header>` | 把 `Cookie:` 头解析成 map |
| `set-limit` | `set-limit <limiter_id>` / `set-limit <down> <up>` / `set-limit <limiter_id> <down> <up>` | 为当前连接设置限速参数 |
| `set-stat` | `set-stat <group_id...>` | 为当前连接设置统计分组，写入全局 `STAT` set |
| `in-time-range` | `in-time-range [--minute spec] [--hour spec] [--weekday spec] [--monthday spec] [--month spec] [--date spec] [--utc]` | 判断当前时间是否命中给定条件 |
| `num-cmp` | `num-cmp <left> <op> <right>` | 数值比较；`op` 支持 `eq/gt/lt/ge/le` 及符号别名 |

补充说明：

- `verify-jwt`
  - key map 的 key 是 JWT payload 里的 `iss`
  - value 可以是 JWK JSON 字符串，或 Ed25519 公钥 x 值
- `parse-cookie`
  - 返回 map，field 冲突时后值覆盖前值
- `set-limit`
  - 速率格式支持 `B/s`、`KB/s`、`MB/s`、`GB/s`
- `in-time-range`
  - 支持 `*`、`a-b`、`a,b,c`、`*/k`
  - `weekday` 支持 `mon..sun`
- `num-cmp`
  - 操作符支持 `eq|gt|lt|ge|le|==|>|<|>=|<=`

### 8.4 诊断命令

- `qa`
  - 这是网关调试 / 诊断命令，不应写进正式配置规范的“固定支持命令清单”。
  - 用户如果明确问 `qa`，需要单独再展开。

## 9. 通用外部命令入口

| 命令 | 规范语法 | 说明 |
| --- | --- | --- |
| `call` | `call <command> [args...]` | 调用运行时注册的外部命令；固定内建只保证 `call` 这个入口，不保证具体外部命令名 |

说明：

- 外部命令必须先被运行时注册，否则会报错。
- 可见命名空间通常形如：
  - `local::cmd`
  - `global::cmd`
- 如果用户问某个 `call xxx` 是否可用，不能只凭本文断言，必须再确认运行时是否注册了该命令。

例子：

```txt
call verify_token $REQ.token
call local::user_lookup alice
call global::geo_lookup $REQ_real_remote_ip
```

## 10. 快速索引

按组查找：

- 控制流：`goto` `exec` `invoke` `return` `error` `exit` `break` `accept` `reject` `drop`
- 变量：赋值语法、`delete` `type` `to-bool` `to-number` `is-null` `is-bool` `is-number` `capture`
- 匹配：`match` `match-reg` `eq` `ne` `gt` `ge` `lt` `le` `range`
- 字符串：`rewrite` `rewrite-reg` `replace` `append` `slice` `strlen` `starts-with` `ends-with` `url_encode` `url_decode`
- 集合：`match-include`、所有 `list-*` / `set-*` / `map-*`
- 聚合：`map`
- 网关宿主扩展：`call-server` `forward` `redirect` `error` `http-probe` `https-sni-probe` `proxy-protocol-probe` `verify-jwt` `parse-cookie` `set-limit` `set-stat` `in-time-range` `num-cmp`
- 通用外部入口：`call`

如果用户问的是：

- “这条命令到底会不会终止当前 chain？”先看第 2 节
- “这个比较是强类型还是宽松比较？”先看第 4 节
- “这个字符串命令会不会改写原变量？”先看第 5 节
- “Map / MultiMap 到底怎么删？”先看第 6.4 节
- “`error` 到底是控制流还是 HTTP 响应？”先看第 8.1 节
