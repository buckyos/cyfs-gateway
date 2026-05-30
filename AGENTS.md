# Agent Guide (cyfs-gateway)

本仓库采用分层 Harness Engineering 结构。`AGENTS.md` 只做导航，不承载完整规则细节。

## 首次读取顺序
1. `harness/rules/task-entry-gate-rules.md`
2. `docs/architecture/repository-baseline.md`
3. `docs/architecture/module-map.md`
4. `docs/modules/<module>.md`
5. `docs/versions/v0.6/modules/<module>/proposal.md`
6. `docs/versions/v0.6/modules/<module>/design.md`
7. `docs/versions/v0.6/modules/<module>/testing.md`
8. `docs/versions/v0.6/modules/<module>/testplan.yaml`
9. `docs/versions/v0.6/modules/<module>/acceptance.md`
10. `harness/rules/*.md`
11. `harness/process_rules/*.md`

## 仓库地图
- Rust 工作区：`src/`
- 主服务：`src/apps/cyfs_gateway/`
- 核心库：`src/components/cyfs-gateway-lib/`
- Web 控制台：`src/apps/cyfs_gateway/web/`
- 运行时配置：`src/rootfs/etc/`
- 历史资料：`doc/`
- 项目级基线：`docs/architecture/`
- 长期模块边界：`docs/modules/`
- 版本化模块包：`docs/versions/v0.6/modules/`
- 验收报告：`docs/versions/v0.6/reviews/`
- Durable harness 规则：`harness/rules/`
- 项目自定义规则：`harness/custom-rules/`
- 执行流程与任务模板：`harness/process_rules/`
- 人审与分级：`harness/human-rules/`、`harness/checklists/`

## 阶段职责
- Proposal：定义目标、范围、非目标和约束，输出 `proposal.md`
- Design：定义实现形态、子模块、接口和路径归属，输出 `design.md`
- Testing：在 implementation 后定义验证覆盖、补充测试实现、证据路径和 `testplan.yaml`
- Implementation：只修改生产代码与必要的非测试运行时/构建资源
- Acceptance：审计证据链并输出独立验收报告

## 阶段边界
- Implementation 开始前，`proposal.md`、`design.md` 必须存在且处于批准态。
- 批准态不是充分条件；implementation 必须确认已批准文档直接覆盖当前变更。
- 若当前变更无法映射到 proposal / design 的具体条目，必须回退到对应文档阶段补充；测试覆盖不足在 implementation 后回到 testing 阶段补充。
- 单阶段任务收尾前运行 `python3 ./harness/scripts/stage-scope-check.py --stage <stage>`，确认 diff 没有越过阶段边界。
- Acceptance 只写报告，不在原任务里修代码或补上游文档。

## 关键规则入口
- 任务入口规则：`harness/rules/task-entry-gate-rules.md`
- Proposal 规则：`harness/rules/proposal-doc-rules.md`
- Design 规则：`harness/rules/design-doc-rules.md`
- Rust Design 附加规则：`harness/rules/rust-design-doc-rules.md`
- Testing 规则：`harness/rules/testing-doc-rules.md`
- 模块包约束：`harness/rules/module-packet-rules.md`
- Implementation 准入：`harness/rules/implementation-admission-rules.md`
- Schema 校验：`harness/rules/schema-validation-rules.md`
- 验收规则：`harness/rules/acceptance-task-rules.md`
- 验收 Review Gate：`harness/rules/acceptance-review-rules.md`
- 触发式加严：`harness/rules/trigger-rules.md`
- 配置模板同步：`harness/custom-rules/config-template-sync-rules.md`
- 禁止全局 Rust 格式化：`harness/custom-rules/no-global-cargo-fmt-rules.md`
- 统一测试入口：`harness/rules/unified-test-entry-rules.md`
- Auto-pipeline：`harness/rules/auto-pipeline-rules.md`
- 模块交付循环：`harness/process_rules/module-delivery-loop.md`

## 标准命令
- Rust 构建：`cd src && cargo build --verbose`
- Rust 全量测试：`cd src && cargo test -- --test-threads=1`
- Web 构建：`cd src/apps/cyfs_gateway/web && npm run build`
- 统一测试入口：
  - `python3 ./harness/scripts/test-run.py <module> unit`
  - `python3 ./harness/scripts/test-run.py <module> dv`
  - `python3 ./harness/scripts/test-run.py <module> integration`
  - `python3 ./harness/scripts/test-run.py <module> all`
  - `python3 ./harness/scripts/test-run.py all all`
  - `./test-run.sh all all`
  - `test-run.bat all all`

## 仓库约束
- 优先做小而局部的改动，不把 bugfix 和重构混在一起。
- Rust 测试默认使用单线程，尤其是涉及端口、共享状态或运行时启动时。
- agent 不执行全局 `cargo fmt`；详见 `harness/custom-rules/no-global-cargo-fmt-rules.md`。
- 配置、控制平面、运行时组装、process-chain、SN/DNS/RTCP 和 UI 契约改动，先看 `trigger-rules.md` 再决定附加验证。
- `doc/` 是历史资料和参考资料层；harness 事实来源是 `docs/` 和 `harness/`。历史资料可作为输入引用，但不能单独作为 implementation admission 证据。
- Auto-pipeline 规则默认存在但不自动启用；只有用户明确要求启用、启动、运行或进入 automatic pipeline 时才读取并执行。
