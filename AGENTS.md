# Agent 指南（cyfs-gateway）

## 概览
- `cyfs-gateway` 是一个 Rust 工作区，涵盖网关运行时、控制平面、协议栈与 Web 控制台。
- 当前仓库已经接入一套以 retrofit 方式落地的 Harness Engineering 工作流。
- 当前 harness 基线位于 `docs/versions/v0.6/`，对应 `src/Cargo.toml` 中的工作区版本 `0.6.0`。

## 工作模型
- 人负责定义意图、范围与审批边界。
- Agent 在仓库内已定义的规则和模块边界内执行。
- 验收基于证据，并且与实现阶段分离。
- 本仓库已启用 auto-pipeline 模式，但只有在用户确认 `proposal.md` 已批准后才能启动。

## 任务读取顺序
1. 先读本文件。
2. 如果任务属于某个模块，继续读 `docs/versions/v0.6/modules/<module>/`。
3. 读取 `docs/modules/<module>.md` 了解长期边界。
4. 读取 `docs/architecture/`。
5. 读取 `harness/rules/` 以及相关的 `harness/process_rules/`。
6. `doc/` 下的历史设计资料只作为参考输入，不作为 harness 的事实来源。

## 当前结构
- Harness 入口：`AGENTS.md`
- 项目级约束：`docs/architecture/`
- 长期模块边界：`docs/modules/`
- 版本化模块包：`docs/versions/v0.6/modules/`
- 验收报告模板：`docs/reviews/_template/acceptance-report.md`
- 稳定规则：`harness/rules/`
- 执行层覆盖规则：`harness/process_rules/`
- pipeline 计划工件：`harness/pipeline-plan.md`
- 验证入口：`harness/scripts/test-run.py`

## 阶段边界
- Proposal 阶段职责：定义可审批的目标、范围、非目标与约束基线。Proposal 任务只能修改 `proposal.md`。
- Pipeline planning 阶段职责：在执行开始前创建阶段图、依赖、输出与完成条件。Pipeline planning 任务只能修改 `harness/pipeline-plan.md` 及对应任务定义。
- 设计阶段职责：把已批准的意图转成可执行的方案形态。设计任务只能修改 `design.md`、`design/` 以及必要的长期边界同步文档。
- 测试阶段职责：定义可验证的证据、执行入口与通过条件。测试任务只能修改 `testing.md`、`testing/` 与 `testplan.yaml`。
- 实现阶段职责：在已批准设计与测试输入之上，用最小代码和测试改动完成交付。实现任务只能修改代码和测试代码。
- 验收阶段职责：独立审计 proposal、design、testing、implementation 与证据是否仍然一致。验收任务只能写评审报告。

## Auto-Pipeline
- 启动信号：用户确认某个模块的 `proposal.md` 已批准。
- 规划规则：pipeline 必须先规划 design、testing、implementation、acceptance 全部阶段，再允许下游执行。
- 子任务规则：每个阶段必须作为独立子任务执行；如果 `design.md` 定义了直接子模块，应按真实边界继续拆成子任务。
- 验收基线：最终验收以已批准的 `proposal.md` 为准，`design.md`、`testing.md`、`acceptance.md` 只能细化执行，不能悄悄改写 proposal 意图。
- 失败回路：acceptance 失败后，必须把问题路由回 proposal、design、testing 或 implementation 中正确的上游阶段，而不是直接结束 pipeline。
- 退出条件：只有当 proposal 定义的目标达成、阻塞问题关闭、必需证据齐全且最终 acceptance 通过时，pipeline 才能退出。

## 验证
- 统一入口：`python3 ./harness/scripts/test-run.py <module> <level>`
- 级别：`unit`、`dv`、`integration`
- 当前第一个代表性模块包是 `docs/versions/v0.6/modules/gateway-runtime/`。

## 护栏
- 保持 `AGENTS.md` 简短，把稳定细节放到 `docs/` 和 `harness/`。
- 优先围绕现有交付方式做增量补强，而不是重写整套仓库流程。
- 除非某个 harness 文档明确引用，否则把 `doc/` 视为历史或探索性参考资料。
- 如果后续阶段发现上游问题，应把工作退回对应阶段，而不是跨阶段直接修补。
- auto-pipeline 不得跳过规划直接进入实现，也不得把一次失败的 acceptance 当成终态。
