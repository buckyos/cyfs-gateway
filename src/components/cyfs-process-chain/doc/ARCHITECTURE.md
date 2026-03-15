# cyfs-process-chain 架构与现状

本文件描述 `src/components/cyfs-process-chain` 当前实现状态（以代码为准）。

- crate: `cyfs-process-chain`
- version: `0.5.1`
- updated: `2026-03-09`

## 1. 工程定位

`cyfs-process-chain` 是一个可嵌入的脚本执行引擎，支持：

- 以 `Block/Chain/Lib` 为组织层级的流程编排。
- DSL 解析、链接（link）与执行。
- 变量环境分层（global/chain/block）。
- 集合类型（set/map/multi-map）操作。
- 内置命令 + 外部命令（Rust/JS）扩展。
- HTTP/TCP 场景变量封装与探测辅助命令。

该 crate 同时包含：

- `lib.rs`：供其他组件调用。
- `main.rs`：内置 REPL 工具（交互调试和导出命令文档）。

## 2. 代码结构（核心模块）

- `block/`
  - DSL 语法解析（`BlockParser`）与 block 执行（`BlockExecuter`）。
- `chain/`
  - chain/lib 管理、link、执行上下文、环境管理。
- `cmd/`
  - 内置命令系统（control/string/match/collection/...）。
- `hook_point/`
  - HookPoint、HookPointEnv、XML/JSON 配置加载、执行入口。
- `collection/`
  - 内存与文件集合抽象（set/map/multi-map + value 类型系统）。
- `http/` `tcp/`
  - HTTP/TCP 相关变量和 probe 命令支持。
- `js/`
  - JavaScript 外部命令执行器（异步线程 + boa engine）。
- `pipe/`
  - 命令输入输出抽象（标准 IO / 共享内存 pipe）。
- `repl/`
  - 交互调试器与命令帮助导出。

## 3. 执行模型

### 3.1 数据层级

- `ProcessChainLib`
  - 包含多个 `ProcessChain`，按 `priority` 升序。
- `ProcessChain`
  - 包含多个 `Block`，顺序执行。
- `Block`
  - 包含多行 `Line`，每行包含多个 `Statement`。
- `Statement`
  - 由表达式序列组成，支持 `!`、`&&`、`||` 以及分组 `(...)`。

### 3.2 链接（Link）

执行前会把文本命令链接为可执行器：

1. `ProcessChainManager::link()` 克隆所有 chain 并逐个 link。
2. `BlockCommandLinker` 按命令名从 `COMMAND_PARSER_FACTORY` 找 parser。
3. 如果命令名不在内置 parser，但在 external command 工厂中存在：
   - 自动重写为 `call <original_command> ...`。
4. 递归处理命令替换参数 `$(...)`。

### 3.3 运行时上下文

`Context` 持有：

- `ExecPointer`（当前 lib/chain/block 指针）。
- `EnvManager`（global/chain/block 三层环境）。
- `ProcessChainLinkedManager`（已 link 的流程库）。
- `GotoCounter`（历史遗留计数器，当前无 goto 命令入口）。
- `CommandPipe`（stdout/stderr/stdin 抽象）。

## 4. DSL 语法（当前实现）

### 4.1 基本语法

- 注释行：`#` 或 `//` 开头。
- 多行 block：按换行分割。
- 单行多语句：用 `;` 分隔。
- 表达式组合：支持 `! expr`、`expr && expr`、`expr || expr`、`(expr...)`。

### 4.2 赋值语法糖

解析器支持下列赋值写法，最终都转成 `assign` 命令：

- `KEY=VALUE`（默认 chain 级）
- `export KEY=VALUE` / `global KEY=VALUE`（global 级）
- `local KEY=VALUE` / `block KEY=VALUE`（block 级）

赋值 RHS 支持 `CollectionValue` 全类型（不仅是 string）：

- `String`
- `Set`
- `Map`
- `MultiMap`
- 以及其他内部 `CollectionValue` 变体

例如：

- `local geo=$geoByIp[$REQ.clientIp]`（Map 赋值）
- `local trusted=$trustedCountrySet`（Set 赋值）

注意：集合赋值是引用语义（共享引用），不是深拷贝。  
`a=$b` 后，对 `a` 和 `b` 的集合内容修改会相互可见。

### 4.3 参数类型

- 字面量：`abc` / `'abc'` / `"abc"`
- 变量：`$name`、`${name}`、`$map["k"]`、`$map[$k]`
- 安全访问与默认值：`${geoByIp[$REQ.clientIp]?.country ?? "unknown"}`、`$geoByIp[$REQ.clientIp]?.country??"unknown"`
- 命令替换：`$( ... )`

## 5. 变量与环境

### 5.1 环境层级

- `Global`：跨 chain 共享。
- `Chain`：默认层级。
- `Block`：每个 block 执行上下文独立。

### 5.2 路径变量

变量支持路径形式：`a.b.c`

- 路径分隔符是 `.`。
- 字面 `.` 可用反斜杠转义：`1\.2\.3\.4`。
- 支持 bracket 访问：`a["b.c"]`、`a['b.c']`、`a[$key]`、`a[${key}]`。
- 支持动态路径段：`a.($key).b`、`a.(${key}).b`。
- 支持可选访问：`a?.b`、`a?["b"]`、`a[$k]?.meta?.["region.code"]`。
- 支持默认值（coalesce）：`a?.b ?? "x"`、`a?.b??$fallback`。

可选访问语义（`?.` / `?[...]`）：

- 在可选段上发生“缺失”或“类型不匹配”时，不抛 strict missing-var 错误，结果按 missing 处理。
- 若后续带 `??`，则使用右侧默认值；若不带 `??`，最终返回空串。

默认值语义（`??`）：

- 仅在左侧结果为 missing 时生效；左侧存在值（即使空串）则不触发默认值。
- 右侧当前支持字面量与变量表达式（如 `"x"`、`'x'`、`$REQ.country`、`${REQ.country}`）。
- 右侧暂不支持命令替换 `$(...)`（会报明确错误）。

与 policy 的关系：

- `missing_var=strict` 时，普通路径缺失仍报错。
- 显式可选访问（`?.` / `?[...]`）会绕过 strict 的缺失报错，按上述可选语义执行。

### 5.3 外部环境

`EnvExternal` 可挂载到指定层级环境，提供 `contains/get/set/remove` 四个能力。

## 6. 命令系统

### 6.1 内置命令注册

`cmd/factory.rs` 当前注册了 control/action/variable/match/string/collection/debug/map-reduce/external 等命令组。

注意：

- `goto` 目前采用“结构化 tail-transfer”实现（不是传统 PC 跳转）。
- 其行为可理解为：先执行目标（类似 `invoke`），再将结果映射为 `return/error` 返回到指定作用域。

### 6.2 控制流语义

- `return [--from block|chain|lib] [value]`
- `error  [--from block|chain|lib] [value]`
- `exit [value]`
- `break [value]`（仅 map-reduce 内有效）
- `goto --block|--chain|--lib <target> [--from block|chain|lib] [--ok-from block|chain|lib] [--err-from block|chain|lib] [--arg k v]...`
- `drop/accept/reject` 等价为 `exit` 并携带对应动作值。

`exec` 支持按作用域执行目标：

- `exec --block <block|chain:block|lib:chain:block>`
- `exec --chain <chain|lib:chain>`
- `exec --lib <lib>`
- `exec <block>`（默认等价 `--block`）

`exec` 对被调目标返回值会做归一化：

- 目标返回 `Return` -> `Success(value)`
- 目标返回 `Error` -> `Error(value)`
- 目标返回 `Exit/Break` -> 视为错误（非法控制动作）

`invoke` 在 `exec` 目标解析规则之上增加参数传递：

- `invoke --chain auth_flow --arg user $REQ.user --arg pass $REQ.pass`
- 被调流程通过 `$__args.<key>` 读取参数。
- 参数值支持 `CollectionValue` 全类型，集合类型按引用语义传递。
- 当前返回值语义与 `exec` 保持一致（字符串归一化返回）。

`goto` 与 `invoke` 的关系：

- `goto` 复用 `invoke` 目标执行与参数传递能力（包括 `--arg`）。
- 目标执行成功 -> 映射为 `return --from <ok-level> <value>`。
- 目标执行失败 -> 映射为 `error  --from <err-level> <value>`。
- `--from` 可作为 success/error 的共同默认值；也可用 `--ok-from` / `--err-from` 分别覆盖。
- 所有映射参数省略时，默认 `block`（与 `return/error` 不带 `--from` 一致）。

## 7. 外部命令扩展

### 7.1 Rust 外部命令

- 通过 `ParserContext::register_external_command` 注册。
- 未显式写 `call` 也可执行（link 阶段自动改写）。

### 7.2 JavaScript 外部命令

- `HookPointEnv::register_js_external_command(name, source)`。
- JS 执行器运行在独立线程（boa runtime）。
- JS 命令支持可选 `help`、`check`、`exec`（当前 `check` 预留未接入主流程）。

## 8. HookPoint 与配置加载

`hook_point/loader.rs` 支持两种格式加载 process chain lib：

- XML：`ProcessChainXMLLoader`
- JSON：`ProcessChainJSONLoader`

每条 chain 至少要有一个 block，否则报错。

`HookPointEnv` 负责：

- 创建 hook point 级环境（global）。
- 加载集合（json 文件）。
- 注册外部命令（Rust/JS）。
- 将 `HookPoint` link 成可执行 `HookPointExecutor`。

## 9. 集合与持久化

支持集合类型：

- `Set`
- `Map`
- `MultiMap`

### 9.1 顺序语义（确定性遍历）

当前 `Set/Map/MultiMap` 在内存和 JSON 后端统一使用有序容器实现（`IndexSet` / `IndexMap`）：

- 遍历相关接口（`traverse` / `get_all` / `keys_snapshot` / `dump`）遵循插入顺序。
- 对已存在 key/value 的重复 `insert` 不会改变其相对顺序。
- 删除语义使用“稳定删除”（保留剩余元素相对顺序）。
- `MultiMap.get(key)` 返回该 key 下“首个插入”的 value。

当前落地状态：

- 内存集合：已实现。
- JSON 文件集合：已实现（在 `HookPointEnv::load_collection` 里加载）。
- SQLite 集合：接口占位，`unimplemented!`。

`CollectionValue` 的 JSON 持久化当前规则：

- 原生支持：`null` / `bool` / `number` / `string`。
- 不支持：`List/Set/Map/MultiMap/Visitor/Any`（序列化时直接报错）。
- 兼容策略：不再为历史“非 string 值降级为空字符串”的旧格式增加额外兼容分支。

## 10. 已知限制与待补齐点

当前代码中的明确限制：

- `goto` 是结构化语义糖，不支持 label/行号等“任意跳转”能力。
- SQLite collection 未实现。
- `break` 只能在 map-reduce 循环里使用。
- `map-add` 在 multi value 场景只取第一个值（代码内有 FIXME）。
- 若干 HTTP body/TCP probe 分支存在 FIXME（错误处理策略待统一）。
- `collection/db.rs` 为空，`collection/manager.rs` 未在 `mod.rs` 导出。
- `??` 默认值右侧暂不支持命令替换 `$(...)`（当前仅支持字面量/变量表达式）。

## 11. 运行时错误定位（当前）

运行时异常已统一为结构化错误字符串，包含：

- 错误码（如 `PC-RUNTIME-0101`）
- `lib/chain/block/line/source`
- 可选 `command`
- `cause`（下层原始错误）

格式示例：

- `[PC-RUNTIME-0101] Failed to execute line | lib=test_var_policy_lib chain=route_chain_policy block=route line=1 source=local country=$geoByIp[$REQ.clientIp].country; command=- | cause=...`

## 12. 与网关工程的关系

workspace 内以下组件直接依赖本 crate：

- `cyfs-gateway-lib`
- `cyfs-dns`
- `cyfs-socks`
- `cyfs-tun`
- `apps/cyfs_gateway`

网关侧通常通过配置构建 process chain，再注入全局集合、外部命令、JS externals，最终在 HTTP/UDP/TCP 等入口执行。

## 13. 参考文档

- 命令级帮助请看 [COMMAND_REFERENCE.md](./COMMAND_REFERENCE.md)。
- 中文对照版请看 [COMMAND_REFERENCE.zh-CN.md](./COMMAND_REFERENCE.zh-CN.md)。
- 该文件中的 external 命令基于 REPL 默认注册集合；实际网关运行时以业务注册为准。
