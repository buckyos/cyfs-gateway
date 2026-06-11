# 模块交付循环

## 目标
- 在必需文档齐备后，为模块级工作提供一条稳定执行回路。

## 执行前置检查
- 读取 `docs/versions/v0.6/modules/<module>/` 下的模块包。
- 读取 `docs/modules/<module>.md` 与相关 architecture 文档。
- 读取 `harness/rules/` 与相关 `harness/process_rules/`。
- 只有用户显式要求进入 auto-pipeline 时，才读取并执行 `harness/rules/auto-pipeline-rules.md`；普通需求澄清、阶段文档确认、补文档、实现或修复请求不得隐式升级为 auto-pipeline。
- 先检查模块包是否满足 `harness/rules/module-packet-rules.md` 的固定结构与元数据一致性。
- 先确认当前任务属于哪个阶段，以及该阶段允许修改哪些文件。
- 如果当前阶段是 implementation，先满足 `harness/rules/implementation-admission-rules.md`，记录 proposal/design/testing 的具体支撑条目，再开始代码改动。

## 循环步骤
1. 根据当前阶段确认输入、边界与完成条件。
2. 如果当前阶段是 implementation，先确认已批准文档是否已经覆盖当前任务；未覆盖时立即回退到对应文档阶段补充。
3. 只修改当前阶段拥有的工件。
4. 仅在以下情况执行验证：
   - 当前阶段任务明确要求附带证据
   - 用户明确要求
   - 调试需要新的失败证据
   - `harness/rules/trigger-rules.md` 对当前改动要求附加检查
5. 检查失败、日志与不一致之处。
6. 如果问题属于上游阶段，记录证据并回退，不跨阶段直接修补。
7. 如果问题仍在当前阶段边界内，继续修补当前阶段工件或实现代码。
8. 反复执行，直到满足当前阶段完成条件与下一阶段闸门。
9. 交给下一阶段，或产出 acceptance 报告。

## 仓库特定说明
- 对运行时改动，如果需要验证，优先跑聚焦 Rust 测试，再考虑全量集成。
- 对配置敏感改动，如果命中触发规则，应优先使用单线程测试，并记录所有 bind 敏感行为。
- 对 dashboard 工作，如果命中 UI 契约触发规则，应先完成本地 build，再让 acceptance 去审运行时契约。
