# js_extend_cert_provider Proposal

## 元数据
- version: v0.6
- module: cert-manager
- submodule: js_extend_cert_provider
- stage: proposal
- status: approved

## 状态
- 人类可读状态：已批准

## 背景与目标
`cert-manager` 已经把 ACME provider、证书消费入口和 provider 选择规则纳入统一模块边界。除 ACME 外，仍需要一种通用扩展 provider，让用户通过 JS 脚本接入自定义 CA、内部签发平台或其他证书更新流程，而 Rust 侧只维护统一生命周期边界。

`js_extend_cert_provider` 的目标是把这类脚本扩展能力作为 `cert-manager` 下的独立子模块定义清楚：它是 certificate lifecycle provider，不是 ACME solver，也不是跨 provider fallback。

## 范围
### 范围内
- 定义 `js_extend_cert_provider` 作为 `cert-manager` 的直接子模块。
- 支持通过 `cert_providers.<id>.type=js_extend` 声明脚本扩展 provider。
- 支持两种脚本来源：直接 `script_path`，或固定目录下的 `script_name` 包。
- 支持 provider 级 `params` 传入脚本；参数可直接内联在配置中，也可通过 `params_path` 从独立 JSON / YAML 文件装载；Rust-JS 接口不暴露 provider id、usage、store 路径或 request 原始结构。
- 规定脚本固定返回 `{ "cert": "...PEM...", "key": "...PEM..." }` 后，由 Rust 侧负责解析、校验、落盘和状态更新。
- 规定每个 `js_extend_cert_provider` 只读写自己的 provider-owned store，store 路径按 ACME provider 的证书目录派生规则生成，不由用户配置。
- 规定脚本失败时不得跨 provider fallback，已有可用材料应保留并记录错误状态。

### 范围外
- 不为每个第三方 CA 单独新增 Rust provider。
- 不把 ACME HTTP-01、DNS-01、TLS-ALPN-01 challenge 或 DNS provider factory 搬入 `js_extend_cert_provider`。
- 不让脚本直接成为 `CertManager` 的路由层或 fallback 层。
- 不新增与 `cert_providers` 平行的顶层配置入口。
- 不改变本地静态证书、self-signed fallback 或 tunnel local 证书的消费路径。

### 与相邻模块的边界
- `acme-provider` 负责 ACME account、order、challenge、keystore 和 ACME 续期。
- `js_extend_cert_provider` 只负责脚本扩展 provider 的证书获取、校验、store 与状态。
- `gateway-runtime` 只负责从配置创建 provider runtime 并注册到 `CertManager`。
- `runtime-configs` 只负责配置输入和默认值，不拥有脚本执行语义。

## 约束
- provider 选择必须显式稳定：请求绑定到某个 `js_extend_cert_provider` 后，只能消费该 provider 管理的材料。
- 脚本参数是 provider-specific data；`CertManager` 不解释脚本参数、第三方 CA 类型或平台协议。
- private key 不得出现在控制面状态输出中。
- provider store 必须按 provider id 隔离，避免不同 provider 共享证书所有权；用户配置不得覆盖 provider store 路径。
- 脚本失败、输出非法或证书材料不匹配时，不允许回退到 ACME、自签或其他 JS 扩展 provider。

## 高层结果
- `js_extend_cert_provider` 成为 `cert-manager` 下可独立设计、测试和验收的子模块。
- 后续 design 可以围绕配置契约、脚本调用契约、provider-owned store、状态机和错误处理展开。
- 后续 implementation 可以引用本 proposal，而不是从主 `cert-manager` proposal 中抽取零散脚本扩展 provider 描述。

## 实现准入覆盖
| 条目 ID | 当前批准内容 | 可直接支持的实现任务 | 需要先补充的情况 |
|---------|--------------|----------------------|------------------|
| P-cert-js-extend-1 | `js_extend_cert_provider` 是独立 certificate lifecycle provider 子模块 | 新增子模块设计、配置解析设计、provider runtime 设计 | 改名、改配置入口或改变它与 ACME provider 的边界 |
| P-cert-js-extend-2 | 通过 `cert_providers.<id>.type=js_extend` 声明 provider | 配置解析、路径归一化、gateway wiring | 新增平行配置入口或引入其他脚本 provider type 作为主语义 |
| P-cert-js-extend-3 | 脚本来源为 `script_path` 或 `script_name`，provider params 以内联 `params` 或文件型 `params_path` 装载后原样传入；Rust-JS 接口只传最小申请上下文 | 脚本装载和调用契约设计、参数文件装载 | 引入其他脚本来源、环境变量协议、非 JS 执行器，或把 provider id / usage / store 路径 / request 原始结构暴露给脚本 |
| P-cert-js-extend-4 | Rust 侧负责材料解析、校验、落盘和状态；脚本固定返回 `{ cert, key }`；脚本不拥有 provider store 语义；store 路径按 ACME provider 证书目录规则派生 | store、status、刷新状态机设计 | 让脚本跨 provider 写 store、允许用户配置 store 路径、允许 path 型输出，或让脚本输出直接绕过 Rust 校验 |
| P-cert-js-extend-5 | 禁止跨 provider fallback，失败保留旧材料并记录错误 | 错误处理、reload、query 行为设计 | 引入 fallback、共享证书池或“谁先 ready 用谁”的行为 |

## 风险
- 脚本调用契约不清会导致用户扩展不可迁移。
- provider store 隔离不清会导致证书所有权混乱。
- 将 JS 扩展 provider 与 ACME solver 混用，会污染 challenge 暴露面和 provider 边界。
- 失败处理若清空旧材料，可能造成可用证书被脚本临时故障影响。
