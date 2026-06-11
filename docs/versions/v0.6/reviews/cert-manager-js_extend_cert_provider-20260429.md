# cert-manager js_extend_cert_provider Acceptance Report

## 范围与日期
- 日期：2026-04-29
- 模块：`cert-manager`
- 子模块：`js_extend_cert_provider`
- Pipeline：`harness/pipeline-plan.md`
- 范围：实现 `type=js_extend` 证书 provider，固定 Rust-JS 接口为 `{ domain, params } -> { cert, key }`，store 路径按 ACME provider 规则派生且不允许用户配置。

## 审阅输入
- `docs/versions/v0.6/modules/cert-manager/proposal.md`
- `docs/versions/v0.6/modules/cert-manager/design.md`
- `docs/versions/v0.6/modules/cert-manager/testing.md`
- `docs/versions/v0.6/modules/cert-manager/testplan.yaml`
- `docs/versions/v0.6/modules/cert-manager/js_extend_cert_provider/proposal.md`
- `docs/versions/v0.6/modules/cert-manager/js_extend_cert_provider/design.md`
- `docs/versions/v0.6/modules/cert-manager/js_extend_cert_provider/testing.md`
- `src/components/cyfs-acme/src/js_extend_cert_provider.rs`
- `src/components/cyfs-acme/src/lib.rs`
- `src/apps/cyfs_gateway/src/config_loader.rs`
- `src/apps/cyfs_gateway/src/gateway.rs`
- `src/apps/cyfs_gateway/tests/test_control_server.rs`

## 准入检查
| 项 | 结论 | 证据 |
|----|------|------|
| proposal 批准态 | 通过 | `cert-manager/proposal.md` 与 `js_extend_cert_provider/proposal.md` 均为 `status: approved` |
| design 批准态 | 通过 | 主 design 与子模块 design 均为 `status: approved` |
| testing 批准态 | 通过 | 主 testing 与子模块 testing 均为 `status: approved` |
| 当前任务映射 | 通过 | `P-cert-5`、`P-cert-js-extend-2..5` 覆盖配置、脚本接口、store、失败语义 |
| testplan 映射 | 通过 | `cert-manager-unit-js_extend_cert_provider` 与 `cert-manager-unit-parse-js_extend_cert_provider` |

## 发现表
| ID | 严重度 | 阶段 | 结论 | 说明 |
|----|--------|------|------|------|
| F-1 | medium | testing | 已修复 | `test_cmd_server` 使用固定 `127.0.0.1:13451`，首次 DV 因端口占用失败；已改为测试内动态分配本地端口。 |

## 实现一致性
- `JsExtendCertProvider` 新增在 `src/components/cyfs-acme/src/js_extend_cert_provider.rs`，并从 `lib.rs` 导出。
- `type=js_extend` 配置解析新增 `JsExtendCertProviderConfig`，使用 `serde(deny_unknown_fields)` 拒绝 `store_path` 等非法字段。
- gateway wiring 对 `CertProviderConfig::JsExtend` 创建 `JsExtendCertProvider`，store root 复用 ACME provider 规则：`default -> cyfs_gateway/certs`，非 default -> `cyfs_gateway/certs/<provider-id>`。
- JS 调用只传 `{ domain, params }`，输出用 `deny_unknown_fields` 固定为 `{ cert, key }`，拒绝 path 型输出和别名输出。
- provider 刷新失败时记录 `last_error`，保留上一份 ready / renewing material，不做跨 provider fallback。

## 验证证据
| 命令 | 结果 | 备注 |
|------|------|------|
| `cargo check -p cyfs-acme` | 通过 | 无新增 warning |
| `cargo check -p cyfs_gateway` | 通过 | 仅有既有 `cyfs-gateway-lib` warning |
| `cargo test -p cyfs-acme js_extend_cert_provider --lib -- --test-threads=1` | 通过 | 2 passed |
| `cargo test -p cyfs_gateway test_parse_js_extend_cert_provider_config --lib -- --test-threads=1` | 通过 | 1 passed，存在既有 test warning |
| `cargo test -p cyfs_gateway --test test_control_server test_cmd_server -- --test-threads=1` | 通过 | 首次因固定端口失败，测试改为动态端口后通过 |

## 触发规则
- 命中“运行时或集成行为变更”：修改 `src/apps/cyfs_gateway/src/`。
- 已执行 unit：`cyfs-acme` provider runtime、`cyfs_gateway` 配置解析。
- 已执行 DV：`test_cmd_server` gateway wiring smoke。
- 未执行 full integration：本次没有新增端到端网络拓扑或控制面字段，已用最近 DV 覆盖 gateway wiring。

## 剩余风险
- JS package 的真实用户脚本兼容性仍依赖 `sfo-js` runtime 行为；当前单测覆盖直接 `script_path` 路径，`script_name` package 路径由相同 runner 解析到 package main 后执行。
- 现有仓库有若干 unrelated warning，未在本任务中修复。

## 结论
通过。当前 implementation 与已批准 proposal / design / testing 一致，必需 unit 与最近 DV 证据齐全，无需回退上游阶段。
