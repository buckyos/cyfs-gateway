# js_extend_cert_provider 子模块测试

## 元数据
- version: v0.6
- module: cert-manager
- submodule: js_extend_cert_provider
- stage: testing
- status: approved

## 状态
- 人类可读状态：已批准

## 测试来源
- Proposal 条目：`js_extend_cert_provider/proposal.md` 中 `P-cert-js-extend-*`
- Design 条目：`js_extend_cert_provider/design.md` 中“脚本调用契约”“Rust 类型与接口设计”“调用流程”“错误处理”
- 主测试入口：`docs/versions/v0.6/modules/cert-manager/testing.md`
- 机器可读计划：`docs/versions/v0.6/modules/cert-manager/testplan.yaml`

## 统一测试入口
| 层级 | testplan step | 入口 | 覆盖范围 |
|------|---------------|------|----------|
| unit | `cert-manager-unit-js_extend_cert_provider` | `python3 ./harness/scripts/test-run.py cert-manager unit` | provider runtime、脚本调用、输出校验、store、状态机 |
| unit | `cert-manager-unit-parse-js_extend_cert_provider` | `python3 ./harness/scripts/test-run.py cert-manager unit` | `type=js_extend` 配置解析与拒绝非法字段 |
| dv | 主模块 gateway wiring DV | `python3 ./harness/scripts/test-run.py cert-manager dv` | gateway 创建 provider runtime 并注册到 `CertManager` 的可运行路径 |

## 覆盖矩阵
| 测试项 | 必须覆盖 | 失败 / 边界 | 证据路径 |
|--------|----------|-------------|----------|
| 配置解析 | `type=js_extend`、`script_path` / `script_name` 二选一、`check_interval`、`renew_before_expiry`、`params`、`params_path` | 脚本来源缺失或冲突、`params` 与 `params_path` 同时出现、`params_path` 文件读取或解析失败、配置中出现 `store_path`、provider id 重复 | `src/apps/cyfs_gateway/src/config_loader.rs`、`src/apps/cyfs_gateway/src/gateway.rs` |
| store 路径派生 | `default` provider 使用 `cyfs_gateway/certs`，非 `default` provider 使用 `cyfs_gateway/certs/<provider-id>` | 用户配置覆盖 store、跨 provider 读取或写入 | `src/apps/cyfs_gateway/src/config_loader.rs`、`src/components/cyfs-acme/src/js_extend_cert_provider.rs` |
| 脚本输入契约 | Rust 侧只传 `{ domain, params }`；`params_path` 装载结果与内联 `params` 使用同一脚本输入位置 | 传入 `op`、`provider`、`usage`、`derived_store_path` 或 `request` 字段 | `src/components/cyfs-acme/src/js_extend_cert_provider.rs`、`src/apps/cyfs_gateway/src/gateway.rs` |
| 脚本输出契约 | 只接受 `{ cert, key }` PEM | 缺字段、非 JSON object、`fullchain` / `private_key` 别名、`cert_path` / `key_path` path 型输出 | `src/components/cyfs-acme/src/js_extend_cert_provider.rs` |
| 材料校验 | 证书链与私钥可解析且匹配，证书未过期 | 非 PEM、证书私钥不匹配、过期证书 | `src/components/cyfs-acme/src/js_extend_cert_provider.rs` |
| request 状态机 | missing / renew-needed 时调用脚本，ready / renewing material 可被查询 | 未 ready 查询、not-found 查询、重复刷新并发 | `src/components/cyfs-acme/src/js_extend_cert_provider.rs` |
| 失败保留旧材料 | 刷新失败时保留上一份 ready / renewing material 并记录 `last_error` | 脚本失败清空旧材料、隐式 fallback 到 ACME / self-signed / 其他 JS provider | `src/components/cyfs-acme/src/js_extend_cert_provider.rs` |
| gateway wiring | `cert_providers.<id>.type=js_extend` 创建 `JsExtendCertProvider` 并注册到 `CertManager` | provider 未注册、reload 半提交、consumer 混用其他 provider 材料 | `src/apps/cyfs_gateway/src/gateway.rs` |

## 单元测试
| 测试名 / 模式 | 覆盖行为 | 所属 step |
|---------------|----------|-----------|
| `test_parse_js_extend_cert_provider_config` | 解析 `type=js_extend`、脚本来源、renew policy、params 和 params_path，并拒绝 `store_path` / `params` 与 `params_path` 同时配置 | `cert-manager-unit-parse-js_extend_cert_provider` |
| `test_build_js_extend_cert_provider_config_loads_params_path` | 从 JSON / YAML 参数文件装载 provider params，失败时阻止 provider runtime 构建 | `cert-manager-unit-parse-js_extend_cert_provider` |
| `test_js_extend_cert_provider_*` | 脚本调用只传 `{ domain, params }`、固定 `{ cert, key }` 输出、材料校验、落盘、定时检查与失败保留旧材料 | `cert-manager-unit-js_extend_cert_provider` |

## DV / 集成边界
- 子模块自身以 unit 为主；gateway wiring 的可运行证据由主模块 DV 承接。
- TLS / QUIC / tunnel consumer 是否只消费指定 provider 的材料由 `cert-manager` 主测试文档中的 consumer-adapter 条目承接。
- 本子模块不单独定义 integration step；若后续新增端到端 JS provider 场景，必须先同步主 `testing.md` 和 `testplan.yaml`。

## 实现准入映射
| Proposal / Design 条目 | Testing 覆盖 | 机器入口 | 缺口处理 |
|------------------------|---------------|----------|----------|
| `P-cert-js-extend-2` / 配置契约 | 配置解析、脚本来源二选一、拒绝 `store_path` | `cert-manager-unit-parse-js_extend_cert_provider` | 改变配置入口或新增字段时先补本测试文档与主 testplan |
| `P-cert-js-extend-3` / 脚本调用契约 | `{ domain, params }` 输入，禁止额外 Rust 内部字段泄漏；`params_path` 文件装载后仍进入同一 `params` 字段 | `cert-manager-unit-js_extend_cert_provider`、`cert-manager-unit-parse-js_extend_cert_provider` | 改变脚本输入时先补 proposal / design / testing |
| `P-cert-js-extend-4` / 输出、store、状态 | 固定 `{ cert, key }` 输出、PEM 校验、provider store 落盘 | `cert-manager-unit-js_extend_cert_provider` | 支持 path 型输出或别名输出前必须回退 proposal |
| `P-cert-js-extend-5` / 失败语义 | 脚本失败保留旧材料、记录 `last_error`、禁止 fallback | `cert-manager-unit-js_extend_cert_provider` | 引入 fallback 或共享证书池前必须回退 proposal |

## 完成定义
- [ ] 子模块 proposal / design / testing 对脚本接口、store 派生与失败语义一致。
- [ ] 主 `testing.md` 指向本子模块测试文档。
- [ ] `testplan.yaml` 至少包含配置解析和 provider runtime 的机器可读 unit step。
- [ ] 若 implementation 改变脚本接口、配置入口或 store 语义，先回退到对应文档阶段。
