# cyfs-tun 验收

## 验收范围
- 版本：`v0.6`
- 模块：`cyfs-tun`
- 范围内：tun stack 模块边界、版本化 proposal / design / testing 工件、统一测试入口定义
- 范围外：TUN 行为重构、`tuntunnel` 语义修正、新的集成测试实现

## 证据链
- Proposal 基线：`docs/versions/v0.6/modules/cyfs-tun/proposal.md`
- 设计基线：`docs/versions/v0.6/modules/cyfs-tun/design.md`
- 测试基线：`docs/versions/v0.6/modules/cyfs-tun/testing.md`
- 长期模块文档：`docs/modules/cyfs-tun.md`

## Auto-Pipeline 基线
- 若通过 auto-pipeline 执行，最终验收以已批准的 `proposal.md` 为准。
- `design.md`、`testing.md`、`acceptance.md` 只能细化执行，不得改变 proposal 意图。

## 通过条件
- [ ] Proposal、design、testing、acceptance 与长期边界文档相互一致
- [ ] `testplan.yaml` 与 `testing.md` 中声明的级别、模式和原因一致
- [ ] `cyfs-tun` 的源码归属、相邻模块边界和测试缺口都已显式记录
- [ ] 后续 tun 相关工作可以据此路由回正确阶段，而不是依赖聊天上下文

## 失败条件
- 模块边界仍然混在 `gateway-runtime` 中而没有独立事实来源
- `testplan.yaml` 对缺失的 DV / integration 证据未显式说明原因
- 文档声称存在 tun 集成验证，但仓库中没有对应入口
- 验收结果被写回标准文档，而不是单独评审报告

## 回退路由
- Proposal 问题：模块归属、范围或相邻边界定义错误
- 设计问题：子模块拆解、路径归属或当前实现形态记录错误
- 测试问题：`testing.md`、`testplan.yaml` 与真实证据面不一致
- Implementation 问题：后续 tun 代码或测试未满足已批准文档约束
