---
name: cyfs-gateway-config-spec
description: 用于独立讲解、审查、设计和排查 cyfs-gateway 配置规范，覆盖 YAML/JSON/TOML 配置结构、装载合并、已支持的 stack/server 类型、process chain 执行规则，以及基于当前实现证据的能力边界与保守场景分析。
---

# CYFS Gateway 配置与组网分析规范

这是一个自包含 skill。
它把 cyfs-gateway 的配置装载、合并、类型注册、字段规则、process chain 语义，以及常见组网分析框架抽取为固定知识，使用时不依赖原项目目录或源码环境。
如果把这个 skill 拷贝到别处，它仍然应当可以直接使用。

## 何时使用

- 需要编写或修改 `cyfs_gateway.yaml`、拆分配置文件、生成配置示例
- 需要解释某个字段是否生效、ID 从哪里来、为什么合并结果与预期不同
- 需要从仓库中提取一份“配置定义规范”或做配置 review
- 需要判断某个网络需求是否能由 cyfs-gateway 的当前基础规则支撑，尤其是 `tun`、SOCKS5 代理接入、DNS/服务发现、策略路由这类边界题
- 需要把“业务目标”映射成 stack/server/process chain/宿主机网络动作，并区分哪些属于 cyfs-gateway 本身、哪些属于外部前提
- 需要解释或设计基于 process chain 的数据转发、server 分发、反向代理、多上游转发或按协议探测后的上游选择
- 需要排查“隧道建立了但业务不通”“DNS 正确但 app 连不上”“不同网段设备想像局域网那样互连”

## 工作流

1. 先判断问题类型：
   - 配置语法与 merge
   - 路由与转发
   - `tun` 基础字段与默认值
   - SOCKS5 代理接入
   - DNS / 服务发现
   - 能力边界 / 不可承诺项
   - 故障排查
2. 先读 [references/implementation-checked.md](references/implementation-checked.md)，确认哪些结论已经对照当前源码校验过。
3. 如果问题涉及“虚拟局域网”“异地组网”“不同网段像同一局域网”，先读 [references/capability-boundaries.md](references/capability-boundaries.md)，确认应按 `tun` 的基础字段、`socks5` 型应用代理接入，还是 evidence 不足的 L2 广播域来讨论。
4. 再读 [references/config-reference.md](references/config-reference.md)，确认装载链、merge 语义、路径规则、顶层结构和已支持类型。
5. 涉及 process chain 时，读 [references/process-chain-rules.md](references/process-chain-rules.md)。
6. 如果问题涉及数据转发、上游选择、`call-server` / `forward`、多上游算法、反向代理或 stream/datagram 转发，读 [references/data-forwarding.md](references/data-forwarding.md)。
7. 需要查 `if/elif/else/end`、`for ... end`、`match-result ... end` 这类结构化语句时，继续读 [references/process-chain-rules.md](references/process-chain-rules.md)；需要查具体 DSL 命令、参数形式、命令别名差异、collection 命令行为时，读 [references/process-chain-command-manual.md](references/process-chain-command-manual.md)。
7.5. 只要要输出配置示例，必须先锁定目标 `protocol` 或 `server type` 的字段集合。
   - `stacks.<id>` 示例中的字段，必须全部来自 `config-reference.md` 对应协议的小节，或 `implementation-checked.md` 明确校验过的字段。
   - `servers.<id>` 示例中的字段，必须全部来自 `config-reference.md` 对应 server 类型的小节，或 `implementation-checked.md` 明确校验过的字段。
   - 找不到逐字证据的字段，一律不得写入示例。
   - 如果缺少足够证据组成完整可运行示例，必须降级为：
     1. 只给已证实的片段；
     2. 或明确写“当前 skill 没有足够证据，不能给出该字段/完整示例”。
8. 如果是组网设计题，再读：
   - [references/scenario-cookbook.md](references/scenario-cookbook.md)
   - [references/host-network-prerequisites.md](references/host-network-prerequisites.md)
   - [references/troubleshooting-playbook.md](references/troubleshooting-playbook.md)
   - [references/examples/README.md](references/examples/README.md)
9. 输出规范时，先写“运行时行为”，再写“推荐写法”。
10. 输出方案时，先写“能力边界与已确认事实”，再写“外部前提 / 地址规划 / 宿主机动作 / 验证步骤”。
11. 生成示例时，优先输出最小可运行配置，再追加可选字段；但 `tun` 示例里的最小配置仍必须包含 `hook_point`。

## 必须遵守的规范

- `stacks`、`servers`、`timers`、`limiters`、`collections`、`global_process_chains` 都是“map 作为定义源”，运行时再把 key 注入成 `id` 或 `name`。
- `hook_point`、`post_hook_point`、`on_new_tunnel_hook_point`、`blocks` 在 YAML 里通常写成 map；解析阶段会转成数组。
- 只有本 skill 已列出的协议和服务类型，才能声明为“当前应用支持”。库内存在但未注册的类型不能写进正式规范。
- process chain 规则、控制流和常见环境变量，以本 skill 的 `process-chain-rules.md` 为准。
- process chain 的具体命令名、参数形式和 collection 命令行为，以本 skill 的 `process-chain-command-manual.md` 为准；不要混用旧文档里的下划线/短横线写法。
- `if/elif/else/end`、`for ... in ... then ... end`、`match-result ... end` 是 statement 级语法，不是普通命令；写规范时要把“结构化语句”和“控制命令”分开讲。
- `path` 和 `*_path` 会在最终解析前统一做路径归一化。写规范时必须明确“相对路径按主配置文件目录解释”。
- 讨论“数据转发”时，必须先区分三类入口：
  `call-server`：把请求或连接交给已声明的 server 对象
  `forward`：直接把流量转给目标 upstream URL
  `socks` server：让支持代理的应用经 `target` / `rule_config` / `enable_tunnel` 接入远端资源
- 讨论 `forward` 时，只能使用本 skill 已校验的语义：
  缺省算法 `round_robin`
  可选算法 `ip_hash`
  支持 inline upstream 与 `--map`
  upstream 权重必须是正整数
- 不能把 `forward`、`call-server` 这种业务流量转发动作，和 `tun` 的 IP 级配置、宿主机 IP 转发、静态路由混成同一层概念。
- 讨论 `tun` 时，必须区分两层：
  `bind` / `mask` / `mtu` / timeout 等 IP 级参数
  `hook_point` 驱动的数据处理与转发动作
- 对当前实现，`tun.hook_point` 应视为必填；不能输出缺少 `hook_point` 的 `tun` 配置示例。
- 对“组局域网”“互通”“虚拟网段承载业务流量”类问题，必须明确说明：
  仅配置 `tun` 地址参数不够，还需要 `hook_point` 产出有效的 `forward` 或 `server` 动作。
- 不能把 `accept` 等泛化成 `tun` 组网的充分动作，除非本 skill 的 reference 已明确证明宿主会消费该动作并形成业务转发。
- 说明配置来源时，要区分：
  已注入控制面默认值的 `user_config`
  叠加已保存 patch 后的 `effective_config`
  内置控制面默认配置 `gateway_control_server.yaml`
- 说明默认值时，只能使用本 skill 已明确写出的默认值；没有列出的字段不要擅自补默认值。
- 这个 skill 的回答应视为“已抽取好的 cyfs-gateway 配置与组网规范”，不要求用户再提供源码上下文。
- 当用户提到“虚拟局域网”“像同一局域网”“异地组成一个局域网”时，必须先区分：
  `tun` 型 IP 级接口配置：当前直接证据只覆盖 `bind` / `mask` / `mtu` / timeout / `hook_point`
  `socks5` 型代理接入：支持代理的应用通过代理访问远端服务或远端网络资源
  L2 broadcast domain：依赖 ARP、广播、mDNS、NetBIOS 等自动发现
- 如果 reference 没有明确证明 L2 bridge / TAP / 广播转发能力，也没有明确证明 `tun` 的自动建链 / 自动路由语义，就只能把 `tun` 解释为带 IP 参数的 stack 配置；不能宣称等价于二层交换网络或完整私网能力。
- `socks5` 型方案只能承诺“支持代理的应用通过代理访问目标服务”；不能把它表述成“整机进入同一局域网”或“整机自动接入同一虚拟网段”。
- 回答组网方案时，必须同时区分三层信息：
  cyfs-gateway 内配置
  宿主机网络动作，如 IP 转发、静态路由、防火墙、NAT、MTU
  应用侧接入方式，如固定地址、域名解析、系统代理、服务发现约束
- 只要应用依赖局域网广播发现，就必须显式提示能力边界；不能默认承诺“不同网段也会像原生局域网一样自动发现”。
- 如果 evidence 不足以支持某种运行时语义，必须明确写“当前 skill 没有足够证据，不应下结论”，而不是靠经验补齐。
- 任何关于“当前应用支持什么”“字段是否存在”“默认值是什么”“配置如何归一化”“`socks5` 是否支持 `enable_tunnel` / `rule_config`”“`tun` 是否是 IP 级配置”的结论，都必须能回溯到 [references/implementation-checked.md](references/implementation-checked.md) 中列出的当前实现证据。
- 配置示例必须遵守“字段闭包”：
  对任意 `stacks.<id>` 或 `servers.<id>` 示例，所使用的 key 必须完全落在当前 skill 已列出的字段集合内。
- 不允许根据同类产品经验、命名习惯或常识补出未在 reference 中出现的字段，例如 `listen`、`addr`、`port`、`upstream`、`backend`、`targets` 等。
- 只要某个字段没有被当前 skill 明确列为“当前应用支持”或“当前字段存在”，就必须视为未知，不能写进正式配置示例。
- `call-server` 方案只有在目标 server 类型的字段足够形成证据化示例时才能展开；否则应优先改用 `forward` 示例，或明确声明证据不足。
- 若回答中出现任何未证实字段，该字段所属的整段配置示例都应判定为无效，必须重写。
- 已知负面样例：
  当前 skill 没有证据证明 `servers.<id>.type: http` 支持 `listen` 字段；除非 reference 以后新增证据，否则禁止输出该写法。

## 输出要求

- 给出规范时直接下结论，不要求附带仓库路径。
- 先写运行时真相，再写推荐写法。
- 如果用户要求“完整支持列表”，必须指出：
  当前 `cyfs_gateway` 注册的 stack 协议是 `tcp`、`udp`、`tls`、`quic`、`rtcp`、`tun`
  当前注册的 server 类型是 `http`、`socks`、`dns`、`dir`、`control_server`、`local_dns`、`sn`、`acme_response`
- 如果提到 `ndn`，必须注明：库里存在 `NdnServerConfig`，但当前 `src/apps/cyfs_gateway/src/lib.rs` 没有注册对应 parser/factory，不能当成当前应用支持项。
- 如果用户要“独立规范文档”或“可复制的 skill”，只使用本 skill 自带 references 中的内容组织答案，不再要求回到仓库核对。
- 如果用户要求“配置规范 + process chain 规则”，需要同时覆盖配置承载结构和 DSL 执行规则，而不是只给 YAML 结构。
- 如果用户要求“完整命令列表”“某条命令怎么写”“某个 collection 命令的精确行为”，优先按 `process-chain-command-manual.md` 回答，并使用文档中的 canonical 命令名。
- 如果用户要求“完整逻辑控制语法”，必须同时覆盖表达式链的 `&&` / `||` / `!` / `;` / `()`，以及 statement 级的 `if/elif/else/end`、`for ... end`、`match-result ... end`。
- 如果用户要求“数据转发”“上游转发”“反向代理”“server 分发”“四层转发”，回答结构必须至少包含：
  目标层级
  入口类型，是 `call-server`、`forward`、`socks` 还是 `tun + 宿主机路由`
  运行时动作
  上游或 server 目标
  是否涉及多上游与选择算法
  验证步骤
- 如果用户要求“怎么搭一个虚拟局域网”“怎么让不同网段设备像在同一局域网里通信”，回答结构必须至少包含：
  目标归类
  已确认的 `tun` / `socks` 基础事实
  当前不能直接承诺的部分
  外部前提
  宿主机网络动作
  DNS / 服务发现策略或代理接入策略
  验证步骤
  常见故障排查
- 如果用户明确问“`tun stack` 怎么用”“`tun.bind` / `mask` / `mtu` 应该怎么配”“`tun` 方案为什么不通”，回答结构必须至少包含：
  已确认字段与默认值
  `bind` / `mask` 的参数关系
  `hook_point` 的必填性与其返回的转发动作
  外部前提，如 underlay、路由、防火墙、MTU
  应用访问的是哪个地址，还是应改走代理
  验证顺序与能力边界
- 如果用户要求“给出一台机器上的 `tun` 配置”，答案至少包含：
  `protocol`
  `bind`
  `mask`
  `mtu`
  `tcp_timeout`
  `udp_timeout`
  `hook_point`
- 不允许给出缺少 `hook_point` 的 `tun` 最小示例。
- 若当前 evidence 不足以给出完整可运行的 `hook_point` 业务逻辑，必须明确说明至少还缺少：
  转发目标是 `call-server` 还是 `forward`
  对应的 server 或 upstream 是什么
- 对“虚拟局域网”这类问题，优先给出“`tun` 基础规则 + 外部前提”或“代理接入”的表述；只有 evidence 足够时，才允许提升到“二层局域网”。
- 配置示例分为两类：
  - 证据化配置：每个字段都能在当前 skill references 中找到依据。
  - 示意伪代码：用于解释思路，但不能当成真实 schema。
- 默认只允许输出“证据化配置”。
- 只有当用户明确要求“伪代码 / 思路示意”时，才允许输出示意伪代码；并且必须在代码块前明确标注：
  “以下为示意伪代码，不代表当前 skill 已证实的配置字段。”
- 用户只要问“怎么配”，优先给证据化配置；证据不够时，宁可少写，不可补猜。

## 场景化分析规则

### 1. 先判目标，不要先写配置

用户说“网络打通了没”“像局域网一样”“设备能不能直连”，先拆成这些问题：

- 目标是固定地址直连，还是自动发现
- 目标是单个 app 互通，还是整段子网互通
- 目标是临时点对点，还是长期 hub-spoke / full-mesh
- 能否接受在宿主机上配置路由、开转发、调防火墙、改 DNS
- 应用能否配置 SOCKS5 或系统代理

### 2. “虚拟局域网”默认按四类理解

- `tun` 型 IP 级配置：
  适合先讨论 `bind` / `mask` / `mtu` / timeout / `hook_point` 这些基础规则
- `socks5` 型应用代理接入：
  适合“支持代理的 app 访问远端服务，但不要求整机进入同一虚拟网段”
- 基于 process chain 的数据转发：
  适合“按请求条件或协议探测结果，把流量分发到某个 server 或某个 upstream URL”
- L2 broadcast domain：
  适合“应用依赖广播、ARP、mDNS、NetBIOS、零配置发现”

如果 reference 没有明确证明二层桥接语义，也没有明确证明 `tun` 的完整组网语义，回答时默认只承诺基础字段事实、代理接入和数据转发这三类非二层内容。

### 3. 组网方案的固定输出模板

- 能力边界：哪些结论是 skill 已有证据支持的，哪些不能下结论
- 基础事实：`tun` / `socks` / `forward` / `call-server` 中哪些语义已确认
- 转发入口：`call-server`、`forward`、`socks`、`tun + 宿主机转发`
- 地址规划：只有在用户明确做外部组网讨论时才写
- 宿主机动作：IP 转发、静态路由、MTU、NAT、防火墙放行
- 应用接入：固定 IP、域名、SOCKS5 / 系统代理、是否允许广播发现缺失
- 验证步骤：先验证基础连通，再看地址、端口和应用层
- 故障定位：按基础连通、地址 / 路由、DNS / 代理、应用四层分段排查

### 4. 推荐措辞

- 用“当前 skill 明确支持的配置事实”描述 schema、类型、字段和 DSL
- 用“当前 skill 只能直接确认 `tun` 的基础字段与默认值”描述 `tun` 类问题
- 用“建议按应用代理接入方案设计”描述 `socks5` 类远端访问
- 用“建议按 server 分发或 upstream 转发方案设计”描述 `call-server` / `forward` 类数据转发
- 用“当前 skill 没有足够证据证明”描述二层桥接、广播域复现、自动发现兼容性

## 快速检查清单

- 顶层 map key 是否会被转换成 `id` / `name`
- `protocol` / `type` 是否属于当前 app 已注册集合
- `hook_point` / `post_hook_point` / `global_process_chains` 中的 process chain 是否满足执行模型
- 是否区分 `call-server`、`forward`、`socks target` 与 `tun` / 宿主机转发
- 如果用了 `forward`，是否写清上游 URL、选择算法、权重来源和验证方式
- 相对路径是否按主配置文件目录解释
- timer 的 `timeout` 是否大于 0
- limiter 的 `upper_limiter` 依赖关系是否清晰
- TLS/QUIC/RTCP 的证书或密钥路径字段是否完整
- 如果是跨网段互联，是否已经区分 cyfs-gateway 基础字段事实与宿主机外部前提
- 如果是“虚拟局域网”，是否已经区分 `tun` 型基础字段、`socks5` 型代理接入与 L2 broadcast domain
- 是否写清楚宿主机上的路由 / 转发 / 防火墙前置条件
- 是否写清楚应用是固定地址直连、系统代理接入，还是依赖服务发现
- 是否把“已校验事实”和“保守工程推断”明确区分开
- 本答案里的每一个 YAML key，是否都能在 references 中检索到？
- 若用了 `servers.<id>.type = <type>`，该 type 的每个字段是否都在 `config-reference.md` 对应小节出现过？
- 若某个示例需要的关键字段没有证据，是否已经降级为“只给片段 + 明说缺口”，而不是补猜？
