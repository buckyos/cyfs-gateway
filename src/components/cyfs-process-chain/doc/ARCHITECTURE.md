# cyfs-process-chain 架构与现状

本文件描述 `src/components/cyfs-process-chain` 当前实现状态（以代码为准）。

- crate: `cyfs-process-chain`
- version: `0.5.1`
- updated: `2026-03-02`

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

### 4.3 参数类型

- 字面量：`abc` / `'abc'` / `"abc"`
- 变量：`$name`、`${name}`、`$map["k"]`、`$map[$k]`
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

### 5.3 外部环境

`EnvExternal` 可挂载到指定层级环境，提供 `contains/get/set/remove` 四个能力。

## 6. 命令系统

### 6.1 内置命令注册

`cmd/factory.rs` 当前注册了 control/action/variable/match/string/collection/debug/map-reduce/external 等命令组。

注意：

- `goto` 实现在 `cmd/control.rs` 中已被注释，且未注册到 factory。
- 因此当前运行时不支持 `goto`。

### 6.2 控制流语义

- `return [--from block|chain|lib] [value]`
- `error  [--from block|chain|lib] [value]`
- `exit [value]`
- `break [value]`（仅 map-reduce 内有效）
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

当前落地状态：

- 内存集合：已实现。
- JSON 文件集合：已实现（在 `HookPointEnv::load_collection` 里加载）。
- SQLite 集合：接口占位，`unimplemented!`。

## 10. 已知限制与待补齐点

当前代码中的明确限制：

- `goto` 命令未启用（仅保留注释实现）。
- SQLite collection 未实现。
- `break` 只能在 map-reduce 循环里使用。
- `map-add` 在 multi value 场景只取第一个值（代码内有 FIXME）。
- 若干 HTTP body/TCP probe 分支存在 FIXME（错误处理策略待统一）。
- `collection/db.rs` 为空，`collection/manager.rs` 未在 `mod.rs` 导出。

## 11. 与网关工程的关系

workspace 内以下组件直接依赖本 crate：

- `cyfs-gateway-lib`
- `cyfs-dns`
- `cyfs-socks`
- `cyfs-tun`
- `apps/cyfs_gateway`

网关侧通常通过配置构建 process chain，再注入全局集合、外部命令、JS externals，最终在 HTTP/UDP/TCP 等入口执行。

## 12. 参考文档

- 命令级帮助请看 [COMMAND_REFERENCE.md](./COMMAND_REFERENCE.md)。
- 该文件中的 external 命令基于 REPL 默认注册集合；实际网关运行时以业务注册为准。
