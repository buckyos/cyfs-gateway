# cert-manager 测试

## 元数据
- version: v0.6
- module: cert-manager
- stage: testing
- status: approved

## 测试文档索引
| 文档 | 主题 | 范围 |
|------|------|------|
| `js_extend_cert_provider/testing.md` | js_extend_cert_provider 子模块测试 | 脚本接口、配置解析、store 隔离、失败语义 |

## 统一测试入口
- 机器可读计划：`docs/versions/v0.6/modules/cert-manager/testplan.yaml`
- Unit：`python3 ./harness/scripts/test-run.py cert-manager unit`
- DV：`python3 ./harness/scripts/test-run.py cert-manager dv`
- Integration：`python3 ./harness/scripts/test-run.py cert-manager integration`
- 主机前置条件：可用的 Rust 工具链，以及 Linux 下 vendored OpenSSL 需要的原生构建工具，包括 `perl`、`cc`、`make`

## 子模块测试
| 子模块 | 职责 | 详细测试文档 | 必须覆盖的行为 | 边界/失败场景 | 测试类型 | 测试文件 |
|--------|------|--------------|----------------|---------------|----------|----------|
| acme-runtime-core | 管理 ACME account、order、challenge、续期和动态装载 | 无 | gateway 能创建全局 ACME manager 并注册 solver 路径；ACME 请求只消费 ACME 自己管理的证书 | 当前缺少直接覆盖 order 状态机与 challenge token HTTP 返回体的自动化测试 | dv | `src/apps/cyfs_gateway/src/gateway.rs`、`src/apps/cyfs_gateway/tests/test_control_server.rs` |
| js_extend_cert_provider-runtime | 执行用户 JS 脚本获取/更新证书并保存到按 ACME provider 规则派生的 provider store | `js_extend_cert_provider/testing.md` | `type=js_extend` 能通过 `script_path` 或 `script_name` 装载脚本，可用内联 `params` 或 `params_path` 参数文件，只传入 `{ domain, params }`，只接受 `{ cert, key }` 输出，并在定时检查时更新证书 | 脚本不存在、`params` 与 `params_path` 同时出现、`params_path` 文件非法、配置中出现 `store_path`、脚本失败、输出缺字段、输出使用 path 型或别名字段、证书/私钥不匹配、provider store 隔离 | unit + dv | `src/components/cyfs-acme/src/js_extend_cert_provider.rs`、`src/apps/cyfs_gateway/src/config_loader.rs`、`src/apps/cyfs_gateway/src/gateway.rs` |
| self-signed-runtime | 管理本地 CA 与 fallback 证书签发 | 无 | TLS / QUIC stack 在 `domain: "*"` 场景下可用 fallback 证书完成握手；self-signed fallback 不冒充 ACME 结果 | 当前缺少直接覆盖 CA 持久化与缓存淘汰的单测 | dv | `src/components/cyfs-gateway-lib/src/self_cert_mgr.rs`、`src/components/cyfs-gateway-lib/src/stack/tls_stack.rs`、`src/components/cyfs-gateway-lib/src/stack/quic_stack.rs` |
| cert-consumer-adapters | 服务端 resolver 与 tunnel 客户端证书消费适配 | 无 | snapshot prepare / commit / discard、wildcard 匹配、client cert policy 生效；consumer 只使用被请求 provider 的证书；旧 TLS / QUIC 动态证书条目未设置 `cert_provider` 但设置 `acme_type` 时使用默认 provider | 缺少 ACME manager、证书和私钥不匹配、非法 wildcard / acme_type 组合、跨 provider 混用、默认 provider 缺失 | unit + dv + integration | `src/components/cyfs-gateway-lib/src/tunnel_client_cert_manager.rs`、`src/components/cyfs-gateway-lib/src/stack/tls_cert_resolver.rs`、`src/apps/cyfs_gateway/tests/test_cyfs_gateway.rs` |
| challenge-exposure-and-wiring | 注册 DNS solver、`acme_response` server，并把 manager 接到 stack / server | 无 | gateway 启动时 wiring 完整，控制平面与 challenge server 能共存 | 当前缺少直接命中 `/.well-known/acme-challenge/<token>` 的 HTTP 契约测试 | dv + integration | `src/components/cyfs-gateway-lib/src/server/acme_http_challenge_server.rs`、`src/apps/cyfs_gateway/src/gateway.rs`、`src/apps/cyfs_gateway/tests/test_control_server.rs` |

## 模块级测试
| 测试项 | 覆盖边界 | 执行入口 | 预期结果 | 测试类型 | 测试文件/脚本 |
|--------|----------|----------|----------|----------|----------------|
| Tunnel client cert snapshot 与校验逻辑 | `prepare_reload`、`commit_prepared`、local / acme 校验 | `python3 ./harness/scripts/test-run.py cert-manager unit` | 选定单测通过 | unit | `src/components/cyfs-gateway-lib/src/tunnel_client_cert_manager.rs` |
| TLS / QUIC fallback 证书 runnable 行为 | `domain: "*"` 自签 fallback 与握手路径 | `python3 ./harness/scripts/test-run.py cert-manager dv` | TLS 与 QUIC 自签 fallback 测试通过 | dv | `src/components/cyfs-gateway-lib/src/stack/tls_stack.rs`、`src/components/cyfs-gateway-lib/src/stack/quic_stack.rs` |
| TLS client auth 证书策略 | client cert policy 与服务端证书消费关系 | `python3 ./harness/scripts/test-run.py cert-manager dv` | 合法证书通过，策略行为正确 | dv | `src/components/cyfs-gateway-lib/src/stack/tls_stack.rs` |
| Gateway 级证书消费集成 | `tunnel_client_certs` 与 TLS stack / SOCKS 路径联动 | `python3 ./harness/scripts/test-run.py cert-manager integration` | 端到端证书策略场景通过 | integration | `src/apps/cyfs_gateway/tests/test_cyfs_gateway.rs` |
| js_extend_cert_provider 配置与运行时 | `type=js_extend` provider 配置解析、`params_path` 参数文件装载、`{ domain, params } -> { cert, key }` 脚本接口、脚本输出落盘与状态 | `python3 ./harness/scripts/test-run.py cert-manager unit` | 聚焦单测通过 | unit | `src/components/cyfs-acme/src/js_extend_cert_provider.rs`、`src/apps/cyfs_gateway/src/config_loader.rs`、`src/apps/cyfs_gateway/src/gateway.rs` |

## 外部接口测试
| 接口 | 职责 | 成功场景 | 失败/边界场景 | 测试类型 | 测试文档/文件 |
|------|------|----------|---------------|----------|----------------|
| `stacks[].certs[]` | 为 TLS / QUIC stack 提供静态、ACME 或 fallback 证书来源 | 静态或 fallback 证书能完成握手 | wildcard 使用不当、client auth 策略不满足 | dv | `src/components/cyfs-gateway-lib/src/stack/tls_stack.rs`、`src/components/cyfs-gateway-lib/src/stack/quic_stack.rs` |
| `cert_providers` 缺省兼容 | 为旧格式 ACME 动态证书提供默认 provider | `cert_providers` 缺省且 TLS / QUIC cert 设置 `acme_type` 时，gateway 创建并使用 `default` provider | 多 provider 场景中未归一化到 `default`、显式 provider 被错误覆盖 | unit + dv | `src/apps/cyfs_gateway/src/gateway.rs`、`src/components/cyfs-gateway-lib/src/stack/tls_stack.rs`、`src/components/cyfs-gateway-lib/src/stack/quic_stack.rs` |
| `cert_providers.type=js_extend` | 为 TLS / QUIC / tunnel 动态证书提供脚本式证书生命周期 provider | `script_path` 或固定目录 `script_name` 能装载脚本，配置 params 或 params_path 文件内容随 domain 进入脚本，脚本固定返回 `{ cert, key }` 后 provider 可消费 | 脚本来源缺失、params 与 params_path 同时出现、params_path 文件非法、配置中出现 store_path、脚本执行失败、输出非法、输出使用 path 型或别名字段、store 泄漏到其他 provider | unit + dv | `src/components/cyfs-acme/src/js_extend_cert_provider.rs`、`src/apps/cyfs_gateway/src/config_loader.rs`、`src/apps/cyfs_gateway/src/gateway.rs` |
| `tunnel_client_certs` | 为 tunnel consumer 暴露客户端证书材料 | 指定 alias 的本地证书生效 | 缺少 manager、证书与私钥不匹配、未授权 alias 被拒绝 | unit + integration | `src/components/cyfs-gateway-lib/src/tunnel_client_cert_manager.rs`、`src/apps/cyfs_gateway/tests/test_cyfs_gateway.rs` |
| `acme_response` server | 暴露 `http-01` challenge 路径 | gateway 能成功装配 `acme_response` 与控制平面服务 | 当前缺少对 token body 返回值的直接断言 | dv | `src/apps/cyfs_gateway/tests/test_control_server.rs`、`src/components/cyfs-gateway-lib/src/server/acme_http_challenge_server.rs` |

## 单元测试
| 测试项 | 覆盖行为 | 测试文件 |
|--------|----------|----------|
| `test_prepare_reload_replaces_active_snapshot_only_after_commit` | prepare / commit 只在提交后替换 active snapshot | `src/components/cyfs-gateway-lib/src/tunnel_client_cert_manager.rs` |
| `test_prepare_reload_failure_keeps_previous_active_snapshot` | prepare 失败不会污染当前 active snapshot | `src/components/cyfs-gateway-lib/src/tunnel_client_cert_manager.rs` |
| `test_validate_acme_entry_rules` | 校验 wildcard 与 `acme_type` / `dns_provider` 约束 | `src/components/cyfs-gateway-lib/src/tunnel_client_cert_manager.rs` |
| `test_load_local_material_rejects_mismatched_key` | 拒绝证书与私钥不匹配的本地条目 | `src/components/cyfs-gateway-lib/src/tunnel_client_cert_manager.rs` |
| `test_matches_wildcard` | SNI wildcard 匹配逻辑 | `src/components/cyfs-gateway-lib/src/stack/tls_cert_resolver.rs` |
| `test_tls_acme_type_without_cert_provider_uses_default_provider` | 旧 TLS cert 条目未设置 `cert_provider` 但设置 `acme_type` 时绑定默认 provider | `src/components/cyfs-gateway-lib/src/stack/tls_stack.rs` |
| `test_js_extend_cert_provider_*` | js_extend_cert_provider 脚本调用只传 `{ domain, params }`、只接受 `{ cert, key }` 输出、落盘、定时检查状态与失败保留旧材料 | `src/components/cyfs-acme/src/js_extend_cert_provider.rs` |
| `test_parse_js_extend_cert_provider_config` | 解析 `type=js_extend`、`script_path` / `script_name`、params 与 params_path，并拒绝配置 `store_path` / `params` 与 `params_path` 同时配置 | `src/apps/cyfs_gateway/src/config_loader.rs` |
| `test_build_js_extend_cert_provider_config_loads_params_path` | 从 JSON / YAML 参数文件装载 provider params，并拒绝非法文件内容 | `src/apps/cyfs_gateway/src/gateway.rs` |

## DV 测试
- `test_tls_stack_self_cert` 与 `test_quic_stack_self_cert` 作为服务端 fallback 证书 runnable smoke，覆盖当前 wildcard 自签行为。
- `test_tls_stack_client_auth_on_requires_valid_cert` 作为证书消费和 client auth 联动的 runnable 验证。
- `test_cmd_server` 作为 gateway 装配层的低成本 smoke，覆盖 `acme_response` server 与全局证书 manager 的创建路径。

## 集成测试
- `test_socks5_to_tls_stack_with_client_cert_policy` 作为 `tunnel_client_certs`、TLS server cert、client auth policy 与 gateway 组装的端到端验证。

## 回归关注点
- 外部配置兼容但内部 provider / solver 语义发生漂移
- `AcmeCertManager` 与 tunnel client consumer 重新引入重复状态
- js_extend_cert_provider 固定 `{ domain, params } -> { cert, key }` 脚本契约无测试导致用户脚本不可迁移
- provider 身份在配置解析后丢失，导致“指定 A provider 却用了 B provider 证书”
- fallback 从显式入口膨胀成跨 provider 隐式兜底
- 自签 fallback 或 client auth 只在 TLS / QUIC 其中一条路径上回归
- `acme_response` server 仍能启动，但 challenge token 暴露行为已悄悄失效

## 实现准入映射
| Proposal / Design 条目 ID | Testing 条目 / 章节 | 对应 testplan level / step | 显式缺口或补充要求 |
|---------------------------|---------------------|----------------------------|--------------------|
| `P-cert-1` / `P-cert-1` | `模块级测试`、`外部接口测试` | `unit.cert-manager-unit-prepare-reload`、`unit.cert-manager-unit-wildcard`、`dv.cert-manager-dv-control-server` | 若当前任务改变配置入口、模块边界或 challenge 暴露契约，必须先补对应测试条目 |
| `P-cert-2` / `P-cert-2` | `子模块测试`、`DV 测试`、`集成测试` | `dv.cert-manager-dv-tls-self-cert`、`dv.cert-manager-dv-quic-self-cert`、`dv.cert-manager-dv-tls-client-auth`、`integration.cert-manager-integration-mtls-policy` | 若当前任务重构 `AcmeCertManager` 状态机、`SelfCertMgr` 持久化或 `acme_response` HTTP 返回契约，需先补直接自动化测试再进入 implementation |
| `P-cert-3` / `P-cert-3` | `子模块测试`、`回归关注点` | 现有 `unit` / `dv` / `integration` 只能部分覆盖 | 若当前任务修改 provider 选择、resolver 归属或 fallback 行为，必须先补“指定 provider 后不得混用其他 provider 证书”的直接自动化测试 |
| `P-cert-4` / 默认 provider 兼容规则 | `cert_providers` 缺省兼容、`单元测试` | `unit.cert-manager-unit-default-acme-provider` | 覆盖旧 TLS cert 条目归一化到 `default` provider；QUIC 使用同一翻译规则并由代码 review 交叉确认 |
| `P-cert-5` / `P-cert-js-extend-*` | `js_extend_cert_provider-runtime`、`cert_providers.type=js_extend`、`单元测试` | `unit.cert-manager-unit-js_extend_cert_provider`、`unit.cert-manager-unit-parse-js_extend_cert_provider` | 覆盖脚本来源、params / params_path 参数来源、拒绝 store_path 配置、`{ domain, params } -> { cert, key }` 固定接口、拒绝 path 型或别名输出、按 ACME provider 路径规则落盘与失败保留旧证书 |

## 完成定义
- [ ] 所有直接子模块都映射到了至少一条明确证据路径，或显式记录了测试缺口
- [ ] `testplan.yaml` 与本文中的统一测试入口一致
- [ ] 服务端证书消费、tunnel 客户端证书消费与 challenge 暴露面都有可审计的验证路径
- [ ] 当前自动化缺口已被显式记录，后续高风险实现不会默认继承这些缺口
