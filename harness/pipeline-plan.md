# Pipeline 计划

## 使用说明
- 本文件是 auto-pipeline 的计划工件。
- 本次 pipeline 由用户确认启动，用于推进 `gateway-runtime` 的 TLS reuseport 重构。

## 触发信息
- 目标模块：`gateway-runtime`
- 已批准 proposal：`docs/versions/v0.6/modules/gateway-runtime/proposal.md`
- 用户已确认启动：是，要求自动处理后续流程
- 当前变更 ID：`P-tls-reuseport-1`

## 验收基线
- 最终验收以 `docs/versions/v0.6/modules/gateway-runtime/proposal.md` 为准。
- 下游 design、testing、implementation 和 acceptance 不得改变 proposal 中的目标、范围与非目标。

## 阶段图
| Task ID | 阶段 | 职责 | 范围 | 依赖 | 输出 | 完成条件 |
|---------|------|------|------|------|------|----------|
| P-1 | proposal | 固化 TCP reuseport 重构目标和范围 | `gateway-runtime` | 用户确认 | `proposal.md` | `P-tcp-reuseport-1` 批准 |
| D-1 | design | 定义 `TcpStack` 使用外部 `ServerRuntime` 和 `sfo-reuseport::TcpServer` 的实现形态 | `cyfs-gateway-lib` + runtime wiring | P-1 | `design.md` | Rust 类型、接口、生命周期和路径归属明确 |
| T-1 | testing | 定义验证覆盖和统一入口 | unit / dv / integration | D-1 | `testing.md`、`testplan.yaml` | TCP stack 聚焦测试和运行时入口可追踪 |
| I-1 | implementation | 交付最小代码与测试改动 | TCP stack + factory wiring | D-1, T-1 | 代码与测试 | 实现映射到批准文档 |
| A-1 | acceptance | 审计文档、实现和验证结果 | `gateway-runtime` | I-1 | `docs/versions/v0.6/reviews/` | acceptance 通过或给出回退路由 |
| P-2 | proposal | 固化 TLS reuseport 重构目标和范围 | `gateway-runtime` | 用户确认 | `proposal.md` | `P-tls-reuseport-1` 批准 |
| D-2 | design | 定义 `TlsStack` 使用外部 `ServerRuntime` 和 `sfo-reuseport::TcpServer` 的实现形态 | `cyfs-gateway-lib` + runtime wiring | P-2 | `design.md` | Rust 类型、接口、生命周期和路径归属明确 |
| T-2 | testing | 定义验证覆盖和统一入口 | unit / dv / integration | D-2 | `testing.md`、`testplan.yaml` | TLS stack 聚焦测试和运行时入口可追踪 |
| I-2 | implementation | 交付最小代码与测试改动 | TLS stack + factory wiring | D-2, T-2 | 代码与测试 | 实现映射到批准文档 |
| A-2 | acceptance | 审计文档、实现和验证结果 | `gateway-runtime` | I-2 | `docs/versions/v0.6/reviews/` | acceptance 通过或给出回退路由 |

## 回退规则
- Proposal 问题：回退到 P-1。
- Design 问题：回退到 D-1。
- Testing 问题：回退到 T-1。
- Implementation 问题：回退到 I-1。

## 退出条件
- [x] `P-tcp-reuseport-1` 的 proposal / design / testing 覆盖完整
- [x] `P-tls-reuseport-1` 的 proposal / design / testing 覆盖完整
- [x] implementation 完成
- [x] 必需验证有结果或明确记录阻塞原因
- [x] acceptance 通过
