# 模块包规则

## 目标
- 让 `docs/versions/<version>/modules/<module>/` 成为版本化模块工作的固定入口。
- 固定模块包的文件结构、读取顺序和一致性要求。
- 为 implementation 准入、acceptance 审计和统一测试入口提供稳定路径。

## 标准结构
- `proposal.md`
- `design.md`
- 可选：
  - `testing.md`
  - `testplan.yaml`
  - `acceptance.md`
  - `design/`
  - `testing/`
  - 直接子模块包 `<submodule>/proposal.md`、`<submodule>/design.md` 及其可选测试/验收材料
  - 其他仅属于该模块包的辅助材料

## 读取顺序
1. `proposal.md`
2. `design.md`
3. 如果当前变更属于直接子模块，读取该子模块包的 `proposal.md`、`design.md` 和已有测试材料
4. `design/`
5. `testing.md`
6. `testing/`
7. `testplan.yaml`
8. `acceptance.md`
9. `docs/modules/<module>.md`
10. `docs/architecture/`
11. `harness/rules/`

## 一致性要求
- `proposal.md`、`design.md` 的 `version`、`module` 必须互相一致。
- 可选 `testing.md`、`acceptance.md`、`testplan.yaml` 的模块与版本必须与模块包目录一致。
- `proposal.md`、`design.md` 的 `status` 必须使用统一状态集；implementation 准入只接受 `approved`。
- 长期模块文档与版本化模块包之间若存在边界冲突，应先回退到 proposal 或 design。

## 阶段责任映射
- Proposal：定义批准基线，不写实现细节。
- Design：定义实现形态、路径归属与直接子模块。
- Testing：在 implementation 后定义验证覆盖、补充测试实现、证据路径与 `testplan.yaml`。
- Acceptance：生成或最终确认验收规则与期望结果，并输出独立评审报告。
- Review report：记录某次实际验收，不回写标准文档。

## 当前任务映射要求
- Implementation 或 bugfix 开始前，必须能给出：
  - proposal 中支持当前改动的具体条目
  - design 中覆盖当前实现形态的具体章节或路径归属
- 如果只能引用模块总览、历史资料或“approved-baseline”笼统说明，视为覆盖不足。

## 缺失文件时的默认回退
- 缺失 `proposal.md`：回退到 proposal
- 缺失 `design.md`：回退到 design
- Implementation 后缺失必要测试设计、测试实现或 `testplan.yaml`：回退到 testing
- 缺失验收报告：进入 acceptance 输出独立报告；`acceptance.md` 是可选指导，不是必需标准文件
- 缺失长期模块文档且边界不清：回退到 design，并同步 `docs/modules/<module>.md`

## 验收与报告位置
- `acceptance.md` 可选；存在时只声明标准，不记录某次执行结果。
- 每次实际验收都应输出到 `docs/versions/<version>/reviews/`。
- 验收报告必须引用对应模块包路径，而不是只引用聊天说明。
