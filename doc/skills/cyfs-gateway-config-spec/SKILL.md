---
name: cyfs-gateway-config-spec
description: 用于独立生成、审查或讲解 cyfs-gateway 的配置定义规范，包含 YAML/JSON/TOML 配置结构、装载合并规则、已支持的 stack/server 类型，以及 process chain 执行与编写规则。
---

# CYFS Gateway 配置定义规范

这是一个自包含 skill。
它已经把 cyfs-gateway 的配置装载、合并、类型注册和字段规则抽取为固定知识，使用时不依赖原项目目录或源码环境。
如果把这个 skill 拷贝到别处，它仍然应当可以直接使用。

## 何时使用

- 需要编写或修改 `cyfs_gateway.yaml`、拆分配置文件、生成配置示例
- 需要解释某个字段是否生效、ID 从哪里来、为什么合并结果与预期不同
- 需要从仓库中提取一份“配置定义规范”或做配置 review

## 工作流

1. 先读 [references/config-reference.md](references/config-reference.md)，确认装载链、merge 语义、路径规则、顶层结构和已支持类型。
2. 涉及 process chain 时，读 [references/process-chain-rules.md](references/process-chain-rules.md)。
3. 需要查 `if/elif/else/end`、`for ... end`、`match-result ... end` 这类结构化语句时，继续读 [references/process-chain-rules.md](references/process-chain-rules.md)；需要查具体 DSL 命令、参数形式、命令别名差异、collection 命令行为时，读 [references/process-chain-command-manual.md](references/process-chain-command-manual.md)。
4. 生成规范时，先写“运行时行为”，再写“推荐写法”。
5. 生成示例时，优先输出最小可运行配置，再追加可选字段。

## 必须遵守的规范

- `stacks`、`servers`、`timers`、`limiters`、`collections`、`global_process_chains` 都是“map 作为定义源”，运行时再把 key 注入成 `id` 或 `name`。
- `hook_point`、`post_hook_point`、`on_new_tunnel_hook_point`、`blocks` 在 YAML 里通常写成 map；解析阶段会转成数组。
- 只有本 skill 已列出的协议和服务类型，才能声明为“当前应用支持”。库内存在但未注册的类型不能写进正式规范。
- process chain 规则、控制流和常见环境变量，以本 skill 的 `process-chain-rules.md` 为准。
- process chain 的具体命令名、参数形式和 collection 命令行为，以本 skill 的 `process-chain-command-manual.md` 为准；不要混用旧文档里的下划线/短横线写法。
- `if/elif/else/end`、`for ... in ... then ... end`、`match-result ... end` 是 statement 级语法，不是普通命令；写规范时要把“结构化语句”和“控制命令”分开讲。
- `path` 和 `*_path` 会在最终解析前统一做路径归一化。写规范时必须明确“相对路径按主配置文件目录解释”。
- 说明配置来源时，要区分：
  已注入控制面默认值的 `user_config`
  叠加已保存 patch 后的 `effective_config`
  内置控制面默认配置 `gateway_control_server.yaml`
- 说明默认值时，只能使用本 skill 已明确写出的默认值；没有列出的字段不要擅自补默认值。
- 这个 skill 的回答应视为“已抽取好的 cyfs-gateway 配置规范”，不要求用户再提供源码上下文。

## 输出要求

- 给出规范时直接下结论，不要求附带仓库路径。
- 先写运行时真相，再写推荐写法。
- 如果用户要求“完整支持列表”，必须指出：
  当前 `cyfs_gateway` 注册的 stack 协议是 `tcp`、`udp`、`tls`、`quic`、`rtcp`、`tun`
  当前注册的 server 类型是 `http`、`socks`、`dns`、`dir`、`control_server`、`local_dns`、`sn`、`acme_response`
- 如果提到 `ndn`，必须注明：库里有 `NdnServerConfig`，但 `src/apps/cyfs_gateway/src/lib.rs` 当前没有注册对应 parser/factory。
- 如果用户要“独立规范文档”或“可复制的 skill”，只使用本 skill 自带 references 中的内容组织答案，不再要求回到仓库核对。
- 如果用户要求“配置规范 + process chain 规则”，需要同时覆盖配置承载结构和 DSL 执行规则，而不是只给 YAML 结构。
- 如果用户要求“完整命令列表”、“某条命令怎么写”、“某个 collection 命令的精确行为”，优先按 `process-chain-command-manual.md` 回答，并使用文档中的 canonical 命令名。
- 如果用户要求“完整逻辑控制语法”，必须同时覆盖表达式链的 `&&` / `||` / `!` / `;` / `()`，以及 statement 级的 `if/elif/else/end`、`for ... end`、`match-result ... end`。

## 快速检查清单

- 顶层 map key 是否会被转换成 `id` / `name`
- `protocol` / `type` 是否属于当前 app 已注册集合
- `hook_point` / `post_hook_point` / `global_process_chains` 中的 process chain 是否满足执行模型
- 相对路径是否按主配置文件目录解释
- timer 的 `timeout` 是否大于 0
- limiter 的 `upper_limiter` 依赖关系是否清晰
- TLS/QUIC/RTCP 的证书或密钥路径字段是否完整
