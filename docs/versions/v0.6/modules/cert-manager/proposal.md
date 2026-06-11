# cert-manager Proposal

## 元数据
- version: v0.6
- module: cert-manager
- stage: proposal
- status: approved

## 状态
- 人类可读状态：评审中

## 子 proposal 索引
| 文档 | 子模块 | 范围 |
|------|--------|------|
| `js_extend_cert_provider/proposal.md` | js_extend_cert_provider | JS 扩展证书 provider 的目标、范围、配置入口、脚本扩展边界、store 隔离和失败语义 |

## 背景与目标
当前仓库的证书能力已经覆盖入站 TLS / QUIC 证书、ACME 自动申请与续期、自签 fallback，以及 tunnel 客户端证书装载，但实现边界仍分散在 `cyfs-acme`、`self_cert_mgr`、TLS / QUIC stack 和 gateway 装配层中。`doc/cert_manager_architecture.md` 已经给出了当前真实运行时与推荐演进方向，本 proposal 的目标是把这些结论转成可作为后续 design、testing 与 implementation 准入输入的版本化基线。

## 范围
### 范围内
- 固化当前证书来源：静态证书、ACME 动态证书、自签 fallback、tunnel 客户端证书
- 固化 `provider`、`order`、`challenge`、`solver` 的语义边界
- 固化 provider 选择规则：哪个证书需求指定了哪个 provider，就只使用该 provider 管理的证书
- 定义第一阶段基线：先统一内部模型，保持现有外部配置兼容
- 保留旧格式兼容：`cert_providers` 可缺省，未显式指定 `cert_provider` 但声明 `acme_type` 的 TLS / QUIC 域名使用默认 ACME provider
- 增加 JS 扩展证书 provider 子模块：`js_extend_cert_provider`；详细目标、范围和配置入口见 `js_extend_cert_provider/proposal.md`
- 为 `cert-manager` 建立长期模块文档、版本化模块包和统一测试入口

### 范围外
- 在本任务内直接重构 `cyfs-acme`、`self_cert_mgr` 或 stack 实现
- 立即引入新的顶层配置面，如统一 `cert.providers` / `profiles`
- 为每种第三方 CA 或平台分别引入 Rust provider
- 把当前 DNS-only 的 identifier / key policy 扩展成通用 SAN 或通用 key policy 模型

### 与相邻模块的边界
- `gateway-runtime` 负责 manager、stack、server 的装配与启动，不负责定义证书生命周期语义
- `runtime-configs` 负责配置输入与打包默认值，不负责申请、续期和 solver 执行
- `cyfs-dns` 等 DNS provider 是 solver 执行器，不是证书 provider

## 约束
- 允许使用的库/组件：现有 Rust 工作区 crate、现有控制平面与 stack 测试、`harness/scripts/test-run.py`
- 不允许采用的方式：先新建一套完全平行的通用证书 crate、先改外部配置再反推内部模型、把 provider 与 solver 概念混用
- 不允许采用的方式：把不同 provider 管理的证书混用，或在用户已指定 provider 后隐式切换到其他 provider
- 运行时或部署约束：同一个 gateway 进程内应集中管理 ACME account、challenge 与证书状态；当前外部配置面 `acme`、`tls_ca`、`stacks[].certs[]`、`tunnel_client_certs` 必须保持兼容

## 高层结果
- `cert-manager` 拥有清晰的长期模块边界和版本化阶段工件
- 后续第一阶段实现任务可以围绕统一内部类型推进，而不必先改外部配置
- provider / solver、服务端证书消费 / 生命周期管理之间的边界在仓库中可审计

## 实现准入覆盖
| 条目 ID | 当前批准内容 | 可直接支持的实现任务 | 需要先补充的情况 |
|---------|--------------|----------------------|------------------|
| P-cert-1 | 固化当前证书来源、模块边界、配置兼容承诺和测试入口 | 文档维护、测试入口维护、围绕当前边界的小幅整理 | 任意改变当前证书来源语义、配置入口或模块边界的实现任务 |
| P-cert-2 | 第一阶段允许统一内部模型，但保持现有外部配置与 consumer 行为兼容 | 引入 `CertRequest` / `IssuedCert` / `CertProvider` / `CertOrder` / `Challenge` / `ChallengeSolver` 等内部抽象，并接入 ACME 与 self-signed provider | 新增 provider、引入新配置面、扩展 identifier / key policy、改变 provider 与 solver 边界 |
| P-cert-3 | provider 独立管理自己申请或装载的证书；用户指定 provider 后不得混用其他 provider 的证书 | 在统一内部模型中保留 provider-owned state、按 provider 精确解析请求与结果归属 | 任意引入跨 provider 回退、共享证书池或“先取到谁就用谁”的实现策略 |
| P-cert-4 | 旧格式兼容入口保留默认 ACME provider；`cert_providers` 可缺省；TLS / QUIC 动态证书条目未设置 `cert_provider` 但设置 `acme_type` 时绑定默认 provider | 默认 provider wiring、配置翻译和 resolver 请求路由的兼容修复 | 改变显式 `cert_provider` 的精确绑定语义，或把默认 provider 扩展成跨 provider fallback |
| P-cert-5 | JS 扩展 provider 独立为 `js_extend_cert_provider` 子模块；详细 proposal 见 `js_extend_cert_provider/proposal.md` | 子模块 proposal / design / testing 的维护，以及 `type=js_extend` provider 的后续实现准入映射 | 改变脚本扩展 provider 的配置入口、跨 provider 边界、store 所有权或 fallback 语义 |

## 风险
- 证书生命周期跨越多个 crate 与运行时入口，边界漂移后很难只靠编译错误发现问题
- 配置兼容性要求较强，外部行为轻微变化就可能影响部署
- challenge 暴露面与 client auth 同时涉及安全和可用性，缺少证据时风险较高
