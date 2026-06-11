# gateway-runtime 测试

## 元数据
- version: v0.6
- module: gateway-runtime
- stage: testing
- status: approved
- approved_by: auto-pipeline
- approved_at: 2026-05-31T00:00:00+08:00

## 测试文档索引
| 文档 | 主题 | 范围 |
|------|------|------|
| `testing/app-process-integration-python-plan.md` | 真实 app 进程级 Python 集成测试 | `cyfs_gateway` binary、临时配置、真实客户端调用、process chain runtime case |

## 统一测试入口
- 机器可读计划：`docs/versions/v0.6/modules/gateway-runtime/testplan.yaml`
- Unit：`python3 ./harness/scripts/test-run.py gateway-runtime unit`
- DV：`python3 ./harness/scripts/test-run.py gateway-runtime dv`
- Integration：`python3 ./harness/scripts/test-run.py gateway-runtime integration`
- 主机前置条件：可用的 Rust 工具链，以及 Linux 下 vendored OpenSSL 需要的原生构建工具，包括 `perl`、`cc`、`make`

## 子模块测试
| 子模块 | 职责 | 必须覆盖的行为 | 边界/失败场景 | 测试类型 | 测试文件 |
|--------|------|----------------|---------------|----------|----------|
| config-loading | 加载和合并运行时配置 | 解析现有配置面并保持预期默认值 | 非法配置、bind 敏感数据 | unit + integration | 运行时配置加载代码、`test_cyfs_gateway.rs` |
| runtime-assembly | 组装 stack、server 与 manager | 运行时能够启动并注册预期行为 | 启动失败、stack 误注册、共享状态回归 | unit + integration | `cyfs-gateway-lib` 测试、`test_cyfs_gateway.rs` |
| control-plane | 提供控制 API 与认证流 | 登录、token、system info 请求可用 | 未登录、非法配置访问、token 流失败 | dv | `test_control_server.rs` |
| tcp-reuseport-runtime | 使用外部 `ServerRuntime` 启动 TCP stack | factory 注入 runtime、stack 启动、连接转发、端口释放 | 缺失 runtime、bind 失败、concurrency 不限流/限流配置 | unit | `src/components/cyfs-gateway-lib/src/stack/tcp_stack.rs` |
| tls-reuseport-runtime | 使用外部 `ServerRuntime` 启动 TLS stack | factory 注入 runtime、stack 启动、连接转发、端口释放 | 缺失 runtime、bind 失败、concurrency 不限流/限流配置 | unit | `src/components/cyfs-gateway-lib/src/stack/tls_stack.rs` |
| udp-reuseport-runtime | 使用外部 `ServerRuntime` 启动 UDP stack | factory 注入 runtime、stack 启动、datagram 转发、端口释放 | 缺失 runtime、bind 失败、concurrency 不限流/限流配置 | unit | `src/components/cyfs-gateway-lib/src/stack/udp_stack.rs` |
| quic-reuseport-runtime | 使用外部 `ServerRuntime` 启动 QUIC stack | factory 注入 runtime、stack 启动、连接转发、端口释放 | 缺失 runtime、bind 失败、concurrency 不限流/限流配置、worker CID routing | unit | `src/components/cyfs-gateway-lib/src/stack/quic_stack.rs` |
| runtime-tests | 保持测试入口可运行 | 各级别标准命令能够工作 | 命令漂移、文件缺失、模块包引用过期 | 元验证 | `harness/scripts/test-run.py`、`testplan.yaml` |

## 模块级测试
| 测试项 | 覆盖边界 | 执行入口 | 预期结果 | 测试类型 | 测试文件/脚本 |
|--------|----------|----------|----------|----------|----------------|
| TCP reuseport 聚焦测试 | `TcpStack` 创建、启动、转发、factory 注入和 drop | `python3 ./harness/scripts/test-run.py gateway-runtime unit` | 选定 TCP stack unit target 通过 | unit | `src/components/cyfs-gateway-lib/src/stack/tcp_stack.rs` |
| TLS reuseport 聚焦测试 | `TlsStack` 创建、启动、转发、factory 注入和 drop | `python3 ./harness/scripts/test-run.py gateway-runtime unit` | 选定 TLS stack unit target 通过 | unit | `src/components/cyfs-gateway-lib/src/stack/tls_stack.rs` |
| UDP reuseport 聚焦测试 | `UdpStack` 创建、启动、转发、factory 注入和 drop | `python3 ./harness/scripts/test-run.py gateway-runtime unit` | 选定 UDP stack unit target 通过 | unit | `src/components/cyfs-gateway-lib/src/stack/udp_stack.rs` |
| QUIC reuseport 聚焦测试 | `QuicStack` 创建、启动、转发、factory 注入和 drop | `python3 ./harness/scripts/test-run.py gateway-runtime unit` | 选定 QUIC stack unit target 通过 | unit | `src/components/cyfs-gateway-lib/src/stack/quic_stack.rs` |
| 控制平面可运行验证 | 已组装的控制平面服务端/客户端路径 | `python3 ./harness/scripts/test-run.py gateway-runtime dv` | 登录与配置访问流程通过 | dv | `src/apps/cyfs_gateway/tests/test_control_server.rs` |
| 完整网关集成 | 已组装运行时与配置、网络行为 | `python3 ./harness/scripts/test-run.py gateway-runtime integration` | 综合场景通过 | integration | `src/apps/cyfs_gateway/tests/test_cyfs_gateway.rs`、`tests/integration/cyfs_gateway_app/run.py` |

## 外部接口测试
| 接口 | 职责 | 成功场景 | 失败/边界场景 | 测试类型 | 测试文档/文件 |
|------|------|----------|---------------|----------|----------------|
| 控制平面 HTTP API | 认证并读取运行时状态 | system info、login、config fetch | 无 token、非法配置访问 | dv | `src/apps/cyfs_gateway/tests/test_control_server.rs` |
| 运行时配置面 | 将出厂默认值组装成可运行行为 | 运行时成功启动并正确路由 | bind 或配置合并异常 | integration | `src/apps/cyfs_gateway/tests/test_cyfs_gateway.rs`、`src/apps/cyfs_gateway/tests/test_cyfs_gateway.yaml`、`tests/integration/cyfs_gateway_app/run.py` |

## 单元测试
| 测试项 | 覆盖行为 | 测试文件 |
|--------|----------|----------|
| `test_tcp_stack_creation` | builder 必填项、外部 runtime 准入和基本创建 | `tcp_stack.rs` |
| `test_tcp_stack_forward` | TCP stack 启动后通过 process-chain 转发 | `tcp_stack.rs` |
| `test_tcp_stack_drop` | stack drop 后 listener 释放 | `tcp_stack.rs` |
| `test_tcp_stack_factory_create` | factory 使用外部 runtime 构造 stack | `tcp_stack.rs` |
| `test_tls_stack_creation` | builder 必填项、外部 runtime 准入和基本创建 | `tls_stack.rs` |
| `test_tls_stack_forward` | TLS stack 启动后通过 process-chain 转发 | `tls_stack.rs` |
| `test_tls_stack_drop` | stack drop 后 listener 释放 | `tls_stack.rs` |
| `test_tls_stack_factory_create` | factory 使用外部 runtime 构造 stack | `tls_stack.rs` |
| `test_udp_stack_creation` | builder 必填项、外部 runtime 准入和基本创建 | `udp_stack.rs` |
| `test_udp_stack_forward` | UDP stack 启动后通过 process-chain 转发 | `udp_stack.rs` |
| `test_udp_stack_drop` | stack drop 后 listener 释放 | `udp_stack.rs` |
| `test_udp_factory` | factory 使用外部 runtime 构造 stack | `udp_stack.rs` |
| `test_quic_stack_creation` | builder 必填项、外部 runtime 准入和基本创建 | `quic_stack.rs` |
| `test_quic_stack_reject` | QUIC stack 启动后通过 process-chain 拒绝连接 | `quic_stack.rs` |
| `test_quic_stack_drop` | stack drop 后 listener 释放 | `quic_stack.rs` |
| `test_quic_stack_server` | QUIC stack 启动后通过 HTTP/3 server 分支处理请求 | `quic_stack.rs` |
| `test_factory` | factory 使用外部 runtime 构造 stack | `quic_stack.rs` |

## DV 测试
- `test_control_server.rs` 是标准的单模块运行时 smoke，因为它会启动实际组装出来的控制平面服务端与客户端流程，但成本低于完整网关矩阵。

## 集成测试
- `test_cyfs_gateway.rs` 是标准的完整运行时集成验证，因为它会联合覆盖运行时、配置与网络行为。
- `tests/integration/cyfs_gateway_app/run.py` 是真实 app 进程级 Python 集成验证，因为它会编译并启动 `cyfs_gateway` binary，通过临时业务配置和真实客户端请求覆盖 CLI 帮助/文档/show config/key 生成、配置装载、内置 control server 注入、control RPC reload、HTTP/DNS/SOCKS/PROXY protocol 路由、multi-gateway `tcp`/`ptcp`/`udp`/`socks`/`rtcp` 通信、TLS self-cert smoke、timer/json_set 持久化和 process chain runtime 行为。
- 普通 app 进程级测试配置不得声明 `__control_server__`；控制面使用 `cyfs_gateway` 内置配置。multi-gateway 同时启动两个 app 进程时，仅允许覆盖已注入 `stacks.__control_server__.bind` 来隔离控制端口，不复制 control server 的 hook/server 定义。真实 reload 行为已由 control RPC 和 reload 后客户端 workload 覆盖，CLI `collection`/`reload` roundtrip 后续补充。
- QUIC/TUN 的 app 级 multi-gateway 通信需要 QUIC/HTTP3 客户端或宿主机 TUN 权限夹具，不纳入当前默认 Python integration；TLS 已通过 self-cert app smoke 覆盖，相关底层行为继续由库级 unit/integration 和后续专项夹具覆盖。

## 待补充 App Case
- 详细矩阵见 `testing/app-process-integration-python-plan.md` 的“待补充 Case 矩阵”。
- P0 默认集成已补充：本地 include/merge 细节、路径归一化、invalid server/timer、rule/router/dispatch/collection roundtrip、dir/compression 细节、gateway 外部命令。
- P1 默认集成已补充：DNS negative、SOCKS auth/domain、control token 边界、持久化 `json_set`、timer、`acme_response`。IPv6/rule_config、connection/device manager 后续按专项夹具继续扩展。
- P2 默认可自足部分已补充 TLS app smoke；QUIC/TUN、`cyfs-dir`、`sn`、`ip_region_map` 需要 QUIC/HTTP3 客户端、宿主机 TUN 权限、NamedDataMgr/SN 客户端或 xdb fixture，不进入当前默认 integration 必跑步骤。

## 回归关注点
- `TcpStackConfig.concurrency = 0` 必须保持不限流。
- `TlsStackConfig.concurrency = 0` 必须保持不限流。
- `UdpStackConfig.concurrency = 0` 必须保持不限流。
- `QuicStackConfig.concurrency = 0` 必须保持不限流。
- `concurrency > 0` 必须传给 `ServiceConfig::with_max_concurrency_per_worker()`，不按 worker 数平均。
- `concurrency > 0` 必须传给 `UdpServiceConfig::with_max_concurrency_per_worker()`，不按 worker 数平均。
- QUIC `concurrency > 0` 必须作为每个 worker endpoint 的 open connection 上限，不按 worker 数平均。
- `ServerRuntime` 不得在 `TcpStack`、`TlsStack`、`UdpStack` 或 `QuicStack` 内部创建。
- `TcpServer::close()`、`UdpServer::close()`、`QuicServer::close()` / drop 必须释放端口。
- transparent 和 reuse_address socket option 不能退化。

## 实现准入映射
| Proposal / Design 条目 ID | Testing 条目 / 章节 | 对应 testplan level / step | 显式缺口或补充要求 |
|---------------------------|---------------------|----------------------------|--------------------|
| `P-tcp-reuseport-1` | `TCP reuseport 聚焦测试`、`单元测试`、`回归关注点` | `unit.gateway-runtime-tcp-stack` | 若新增配置字段或改变控制平面契约，需要补充 dv/integration 目标 |
| `P-tls-reuseport-1` | `TLS reuseport 聚焦测试`、`单元测试`、`回归关注点` | `unit.gateway-runtime-tls-stack` | 若新增配置字段或改变控制平面契约，需要补充 dv/integration 目标 |
| `P-udp-reuseport-1` | `UDP reuseport 聚焦测试`、`单元测试`、`回归关注点` | `unit.gateway-runtime-udp-stack` | 若新增配置字段或改变控制平面契约，需要补充 dv/integration 目标 |
| `P-quic-reuseport-1` | `QUIC reuseport 聚焦测试`、`单元测试`、`回归关注点` | `unit.gateway-runtime-quic-stack` | 若新增配置字段或改变控制平面契约，需要补充 dv/integration 目标 |

## 完成定义
- [x] TCP reuseport 行为映射到明确 unit 证据路径
- [x] TLS reuseport 行为映射到明确 unit 证据路径
- [x] UDP reuseport 行为映射到明确 unit 证据路径
- [x] QUIC reuseport 行为映射到明确 unit 证据路径
- [x] `testplan.yaml` 包含可运行的 TCP stack unit 入口
- [x] `testplan.yaml` 包含可运行的 UDP stack unit 入口
- [x] `testplan.yaml` 包含可运行的 QUIC stack unit 入口
- [x] 控制平面与集成入口保留
- [x] 真实 app 进程级 Python 集成入口已登记到 integration level
- [x] 相关自动化测试通过，或剩余缺口已在 acceptance 中记录
