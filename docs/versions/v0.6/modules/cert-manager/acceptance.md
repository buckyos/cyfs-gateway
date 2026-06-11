# cert-manager 验收标准

## 验收范围
- 版本：`v0.6`
- 模块：`cert-manager`
- 范围内：当前证书来源定义、`provider` / `solver` 边界、第一阶段统一内部模型基线、统一测试入口
- 范围外：本次任务内未实现的代码重构、新 provider、新配置面与历史 `doc/` 文档整体替换

## 证据链
- Proposal 基线：`docs/versions/v0.6/modules/cert-manager/proposal.md`
- 设计基线：`docs/versions/v0.6/modules/cert-manager/design.md`
- 测试基线：`docs/versions/v0.6/modules/cert-manager/testing.md`
- 长期模块边界文档：`docs/modules/cert-manager.md`

## 通过条件
- [ ] Proposal、design、testing 与长期模块边界文档对当前证书运行时描述一致
- [ ] 当前证书来源、consumer、challenge 暴露路径与源码归属一致
- [ ] `provider` 与 `solver` 的边界没有被文档混淆
- [ ] 每个 provider 的证书所有权与状态边界清晰，用户指定 provider 后不存在跨 provider 混用
- [ ] `testplan.yaml` 与统一测试入口、`testing.md` 中的步骤一致
- [ ] 已知自动化缺口被显式记录，且没有被伪装成“已覆盖”

## 失败条件
- 模块边界与 `gateway-runtime` / `runtime-configs` 的职责发生冲突
- 第一阶段基线在文档中改变了外部配置兼容承诺
- 文档允许或默认接受“指定某个 provider 却使用其他 provider 证书”的行为
- `testplan.yaml`、`testing.md` 与实际测试入口不一致
- 文档把 solver 执行器错误描述为证书 provider，或反之

## 回退路由
- Proposal 问题：回退到 `docs/versions/v0.6/modules/cert-manager/proposal.md`
- 设计问题：回退到 `docs/versions/v0.6/modules/cert-manager/design.md`
- 测试问题：回退到 `docs/versions/v0.6/modules/cert-manager/testing.md` 与 `testplan.yaml`
- Implementation 问题：在后续实现任务中回退到对应的已批准文档阶段，而不是在 acceptance 内修补
