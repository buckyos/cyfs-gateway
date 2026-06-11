# gateway-runtime 设计

## 元数据
- version: v0.6
- module: gateway-runtime
- stage: design
- status: approved
- approved_by: auto-pipeline
- approved_at: 2026-05-31T00:00:00+08:00

## 目标与非目标
### 目标
- 为 `P-tcp-reuseport-1` 定义 TCP stack 使用 `sfo-reuseport` 的实现形态。
- 为 `P-tls-reuseport-1` 定义 TLS stack 使用 `sfo-reuseport` 的实现形态。
- 为 `P-udp-reuseport-1` 定义 UDP stack 使用 `sfo-reuseport` 的实现形态。
- 为 `P-quic-reuseport-1` 定义 QUIC stack 使用 `sfo-reuseport` 的实现形态。
- 明确 `ServerRuntime` 的外部生命周期、factory 注入方式和 `TcpStack` / `TlsStack` / `UdpStack` / `QuicStack` 启停语义。
- 保持现有 TCP/TLS/QUIC 连接处理链路、UDP datagram/session 处理链路、统计、connection manager 和热更新约束。

### 非目标
- 不重设计 stack trait、server trait 或 process-chain engine。
- 不扩展 runtime 配置格式。
- 不修改 RTCP 或 TUN stack。

## 总体方案
运行时组装层创建一个共享 `sfo_reuseport::ServerRuntime`，并在注册 TCP、TLS、UDP 与 QUIC stack factory 时传入。`TcpStackFactory` / `TlsStackFactory` / `UdpStackFactory` / `QuicStackFactory` 将 runtime clone 到各自 builder，stack 在 `start()` 中构造 `sfo_reuseport` service config 并调用对应 server 的 `serve()`。

`TcpStack` 不再手写 socket bind/listen 和 accept loop，也不再保存 listener `JoinHandle`。启动后保存 `sfo_reuseport::TcpServer`；drop 时调用 `close()` 释放 listener task。

`TlsStack` 采用同一监听生命周期模型，保留 TLS acceptor、证书解析、ALPN、统计、connection manager 和热更新 handler 逻辑；仅替换底层 listener 与并发限制实现。

`UdpStack` 不再在 `UdpStackInner::start()` 中手写 listener socket bind、transparent receive 和 recv loop。启动后保存 `sfo_reuseport::UdpServer`；`UdpServer::serve()` 的 datagram handler 继续调用现有 `UdpStackInner::handle_datagram()`，保留 process-chain、session map、socket cache、server/forward、统计、limiter、io dump 和清理 task 逻辑。

`QuicStack` 不再在 `QuicStackInner::start()` 中手写 UDP socket bind 和单 endpoint accept loop。启动后保存 `sfo_reuseport::QuicServer`，每个 worker socket 创建一个 `quinn::Endpoint::new_with_abstract_socket()`；worker endpoint 的 accept loop 继续调用现有 `QuicStackInner::accept()`，保留 TLS resolver、ALPN、process-chain、HTTP/3 server、forward、统计、limiter、io dump、connection manager 和热更新 handler 逻辑。

## 模块拆解
| 子模块 | 类型 | 职责 | 输入 | 输出 | 依赖 |
|--------|------|------|------|------|------|
| tcp-reuseport-runtime | runtime | 创建并注入共享 `ServerRuntime` | gateway startup | TCP factory 可用 | `sfo-reuseport` |
| tcp-stack-listener | stack | 用 `TcpServer` 替换手写 TCP listener | `TcpStackConfig`、`TcpStackContext` | 运行中的 TCP stack | `cyfs-gateway-lib` |
| tls-stack-listener | stack | 用 `TcpServer` 替换手写 TLS listener | `TlsStackConfig`、`TlsStackContext` | 运行中的 TLS stack | `cyfs-gateway-lib` |
| udp-stack-listener | stack | 用 `UdpServer` 替换手写 UDP listener | `UdpStackConfig`、`UdpStackContext` | 运行中的 UDP stack | `cyfs-gateway-lib` |
| quic-stack-listener | stack | 用 `QuicServer` worker socket 替换手写 QUIC listener | `QuicStackConfig`、`QuicStackContext` | 运行中的 QUIC stack | `cyfs-gateway-lib` |
| tcp-stack-tests | testing | 验证创建、启动、转发和 factory 注入 | Rust tests | 测试证据 | unified test entry |
| tls-stack-tests | testing | 验证创建、启动、转发和 factory 注入 | Rust tests | 测试证据 | unified test entry |
| udp-stack-tests | testing | 验证创建、启动、转发和 factory 注入 | Rust tests | 测试证据 | unified test entry |
| quic-stack-tests | testing | 验证创建、启动、转发和 factory 注入 | Rust tests | 测试证据 | unified test entry |

## 实现顺序
| 阶段 | 目标 | 前置条件 | 输出 |
|------|------|----------|------|
| 1 | 文档准入 | `P-tcp-reuseport-1` 批准 | proposal/design/testing/testplan 覆盖当前任务 |
| 2 | TCP stack 类型调整 | 阶段 1 完成 | builder/factory/stack 保存外部 runtime 和 `TcpServer` |
| 3 | 运行时接线 | 阶段 2 完成 | `cyfs_gateway` 注册 TCP factory 时传入 runtime |
| 4 | 测试调整 | 阶段 3 完成 | 聚焦 TCP stack tests 适配新构造方式 |
| 5 | 验收 | 阶段 4 完成 | acceptance 报告 |
| 6 | 文档准入 | `P-tls-reuseport-1` 批准 | proposal/design/testing/testplan 覆盖 TLS reuseport 任务 |
| 7 | TLS stack 类型调整 | 阶段 6 完成 | builder/factory/stack 保存外部 runtime 和 `TcpServer` |
| 8 | 运行时接线 | 阶段 7 完成 | `cyfs_gateway` 注册 TLS factory 时传入 runtime |
| 9 | 测试调整 | 阶段 8 完成 | 聚焦 TLS stack tests 适配新构造方式 |
| 10 | 验收 | 阶段 9 完成 | acceptance 报告 |
| 11 | 文档准入 | `P-udp-reuseport-1` 批准 | proposal/design/testing/testplan 覆盖 UDP reuseport 任务 |
| 12 | UDP stack 类型调整 | 阶段 11 完成 | builder/factory/inner 保存外部 runtime 和 `UdpServer` |
| 13 | 运行时接线 | 阶段 12 完成 | `cyfs_gateway` 注册 UDP factory 时传入 runtime |
| 14 | 测试调整 | 阶段 13 完成 | 聚焦 UDP stack tests 适配新构造方式 |
| 15 | 验收 | 阶段 14 完成 | acceptance 报告 |
| 16 | 文档准入 | `P-quic-reuseport-1` 批准 | proposal/design/testing/testplan 覆盖 QUIC reuseport 任务 |
| 17 | QUIC stack 类型调整 | 阶段 16 完成 | builder/factory/inner 保存外部 runtime 和 `QuicServer` |
| 18 | 运行时接线 | 阶段 17 完成 | `cyfs_gateway` 注册 QUIC factory 时传入 runtime |
| 19 | 测试调整 | 阶段 18 完成 | 聚焦 QUIC stack tests 适配新构造方式 |
| 20 | 验收 | 阶段 19 完成 | acceptance 报告 |

## 接口与依赖
### Rust 类型与接口
- `TcpStackFactory`
  - 新增字段：`server_runtime: sfo_reuseport::ServerRuntime`
  - 构造函数：`TcpStackFactory::new(connection_manager, server_runtime)`
- `TcpStackBuilder`
  - 新增字段：`server_runtime: Option<sfo_reuseport::ServerRuntime>`
  - 新增方法：`server_runtime(...)`
  - `build()` 前必须校验 runtime 已传入。
- `TcpStack`
  - 新增字段：`server_runtime: sfo_reuseport::ServerRuntime`
  - `handle: Mutex<Option<JoinHandle<()>>>` 改为 `server: Mutex<Option<sfo_reuseport::TcpServer>>`
  - `start_listener()` 返回 `TcpServer`。
- `TlsStackFactory`
  - 新增字段：`server_runtime: sfo_reuseport::ServerRuntime`
  - 构造函数：`TlsStackFactory::new(connection_manager, server_runtime)`
- `TlsStackBuilder`
  - 新增字段：`server_runtime: Option<sfo_reuseport::ServerRuntime>`
  - 新增方法：`server_runtime(...)`
  - `build()` 前必须校验 runtime 已传入。
- `TlsStack`
  - 新增字段：`server_runtime: sfo_reuseport::ServerRuntime`
  - `handle: Mutex<Option<JoinHandle<()>>>` 改为 `server: Mutex<Option<sfo_reuseport::TcpServer>>`
  - `start_listener()` 返回 `TcpServer`。
- `UdpStackFactory`
  - 新增字段：`server_runtime: sfo_reuseport::ServerRuntime`
  - 构造函数：`UdpStackFactory::new(connection_manager, server_runtime)`
- `UdpStackBuilder`
  - 新增字段：`server_runtime: Option<sfo_reuseport::ServerRuntime>`
  - 新增方法：`server_runtime(...)`
  - `build()` 前必须校验 runtime 已传入。
- `UdpStackInner`
  - 新增字段：`server_runtime: sfo_reuseport::ServerRuntime`
  - `start_listener()` 返回 `sfo_reuseport::UdpServer`
- `UdpStack`
  - `handle: Mutex<Option<JoinHandle<()>>>` 改为 `server: Mutex<Option<sfo_reuseport::UdpServer>>`
  - 保留 `clear_handle` 负责 session/socket cache 清理。
- UDP listener socket adapter
  - 允许现有 session/server/forward 逻辑在 `tokio::net::UdpSocket` 和 `sfo_reuseport::UdpSocket` 之间复用 `send_to()` 和 `local_addr()` 调用。
- `QuicStackFactory`
  - 新增字段：`server_runtime: sfo_reuseport::ServerRuntime`
  - 构造函数：`QuicStackFactory::new(connection_manager, server_runtime)`
- `QuicStackBuilder`
  - 新增字段：`server_runtime: Option<sfo_reuseport::ServerRuntime>`
  - 新增方法：`server_runtime(...)`
  - `build()` 前必须校验 runtime 已传入。
- `QuicStackInner`
  - 新增字段：`server_runtime: sfo_reuseport::ServerRuntime`
  - `start()` 返回 `sfo_reuseport::QuicServer`
  - 每个 worker 使用 `quinn::Endpoint::new_with_abstract_socket()` 绑定 `sfo_reuseport::UdpSocket`。
- `QuicStack`
  - `handle: Mutex<Option<JoinHandle<()>>>` 改为 `server: Mutex<Option<sfo_reuseport::QuicServer>>`
  - drop 时关闭 `QuicServer`，并关闭已注册 worker endpoint。

### 调用流程
1. `cyfs_gateway` 启动时创建 `ServerRuntime::start(ServerRuntimeConfig::new())`。
2. 注册 TCP factory：`TcpStackFactory::new(connect_manager.clone(), server_runtime.clone())`。
3. factory create 时通过 builder 注入 runtime。
4. `TcpStack::start()` 构造 `ServiceConfig`：
   - `bind_addr` 来自 `TcpStackConfig.bind`
   - `SocketOptions.reuse_address = reuse_address || transparent`
   - transparent 映射到 IPv4/IPv6 `TransparentMode::Required`
   - `concurrency != u32::MAX` 时调用 `with_max_concurrency_per_worker(concurrency as usize)`
5. `TcpServer::serve()` 的 handler 继续执行现有 TCP 连接处理逻辑：读取目标地址、创建 `StatStream`、登记 connection manager、调用 `TcpConnectionHandler::handle_connect()`。
6. `Drop` 调用 `TcpServer::close()`。
7. 注册 TLS factory：`TlsStackFactory::new(connect_manager.clone(), server_runtime.clone())`。
8. TLS factory create 时通过 builder 注入 runtime。
9. `TlsStack::start()` 构造 `ServiceConfig`：
   - `bind_addr` 来自 `TlsStackConfig.bind`
   - `SocketOptions.reuse_address = reuse_address`
   - transparent 选项保持禁用，因为 TLS stack 当前无 transparent 配置项
   - `concurrency != u32::MAX` 时调用 `with_max_concurrency_per_worker(concurrency as usize)`
10. `TcpServer::serve()` 的 handler 继续执行现有 TLS 连接处理逻辑：读取 peer/local addr、创建 `StatStream`、执行 TLS accept 和 `TlsConnectionHandler::handle_connect()`、登记 connection manager。
11. `Drop` 调用 `TcpServer::close()`。
12. 注册 UDP factory：`UdpStackFactory::new(connect_manager.clone(), server_runtime.clone())`。
13. UDP factory create 时通过 builder 注入 runtime。
14. `UdpStack::start()` 调用 `UdpStackInner::start_listener()` 构造 `UdpServiceConfig`：
   - `bind_addr` 来自 `UdpStackConfig.bind`
   - `SocketOptions.reuse_address = reuse_address || transparent`
   - transparent 映射到 IPv4/IPv6 `TransparentMode::Required`
   - `concurrency != u32::MAX` 时调用 `with_max_concurrency_per_worker(concurrency as usize)`
15. `UdpServer::serve()` 的 handler 继续执行现有 UDP datagram 处理逻辑：读取 `PacketMeta.peer_addr` 和 `PacketMeta.local_addr`、包装 listener socket、调用 `UdpStackInner::handle_datagram()`。
16. `Drop` 调用 `UdpServer::close()`，并 abort session 清理 task。
17. 注册 QUIC factory：`QuicStackFactory::new(connect_manager.clone(), server_runtime.clone())`。
18. QUIC factory create 时通过 builder 注入 runtime。
19. `QuicStack::start()` 调用 `QuicStackInner::start()` 构造 `UdpServiceConfig`：
   - `bind_addr` 来自 `QuicStackConfig.bind`
   - `SocketOptions.reuse_address = reuse_address`
   - `concurrency != u32::MAX` 时在 worker endpoint accept loop 中限制 `open_connections()`
20. `QuicServer::serve_socket()` 的 handler 为每个 worker socket 创建 `quinn::Endpoint`：
   - 使用 worker-aware QUIC CID generator，使 worker endpoint 发出的 connection id 能映射回对应 reuseport worker
   - `quinn::AsyncUdpSocket` adapter 使用 `sfo_reuseport::UdpSocket` 收发 QUIC datagram
   - worker endpoint accept loop 继续执行现有 QUIC 连接处理逻辑：接收 `Incoming`，读取 SNI，执行 process-chain 并进入 forward 或 server 分支
21. `Drop` 调用 `QuicServer::close()`，并关闭 worker endpoint。

### 错误与 shutdown
- `ServerRuntime::start()` 失败在运行时启动阶段返回错误。
- `TcpServer::serve()` 失败映射为 stack error。
- `TcpServer::close()` 错误只记录日志，不在 drop 中 panic。
- `UdpServer::serve()` 失败映射为 stack error。
- `UdpServer::close()` 错误只记录日志，不在 drop 中 panic。
- `QuicServer::serve_socket()` 失败映射为 stack error。
- `QuicServer::close()` 错误只记录日志，不在 drop 中 panic。

## 实现布局
| 路径 | 类型 | 职责 |
|------|------|------|
| `src/apps/cyfs_gateway/src/lib.rs` | Rust 源码 | 创建并注入 `ServerRuntime` |
| `src/apps/cyfs_gateway/tests/test_control_server.rs` | Rust 测试 | 测试运行时注册 TCP/TLS/UDP factory 时提供 runtime |
| `src/components/cyfs-gateway-lib/src/stack/tcp_stack.rs` | Rust 源码与测试 | TCP stack reuseport 实现和聚焦测试 |
| `src/components/cyfs-gateway-lib/src/stack/tls_stack.rs` | Rust 源码与测试 | TLS stack reuseport 实现和聚焦测试 |
| `src/components/cyfs-gateway-lib/src/stack/udp_stack.rs` | Rust 源码与测试 | UDP stack reuseport 实现和聚焦测试 |
| `src/components/cyfs-gateway-lib/src/stack/quic_stack.rs` | Rust 源码与测试 | QUIC stack reuseport 实现和聚焦测试 |
| `src/components/cyfs-gateway-lib/Cargo.toml` | Cargo 配置 | 使用 `sfo-reuseport` 0.2 |

## 实现准入映射
| Proposal 条目 ID | Design 条目 / 章节 | 相关路径或接口 |
|------------------|--------------------|----------------|
| `P-tcp-reuseport-1` | `总体方案`、`Rust 类型与接口`、`调用流程`、`实现布局` | `TcpStackFactory::new`、`TcpStackBuilder::server_runtime`、`TcpStack::start_listener`、`src/apps/cyfs_gateway/src/lib.rs` |
| `P-tls-reuseport-1` | `总体方案`、`Rust 类型与接口`、`调用流程`、`实现布局` | `TlsStackFactory::new`、`TlsStackBuilder::server_runtime`、`TlsStack::start_listener`、`src/apps/cyfs_gateway/src/lib.rs` |
| `P-udp-reuseport-1` | `总体方案`、`Rust 类型与接口`、`调用流程`、`实现布局` | `UdpStackFactory::new`、`UdpStackBuilder::server_runtime`、`UdpStackInner::start_listener`、`src/apps/cyfs_gateway/src/lib.rs` |
| `P-quic-reuseport-1` | `总体方案`、`Rust 类型与接口`、`调用流程`、`实现布局` | `QuicStackFactory::new`、`QuicStackBuilder::server_runtime`、`QuicStackInner::start`、`src/apps/cyfs_gateway/src/lib.rs` |

## 风险与回滚
- 若 `sfo-reuseport` handler 语义与原 accept loop 不一致，优先回滚 `TcpStack` 的 listener 替换，保留外部 runtime 注入文档以便重新设计。
- 若 transparent option 映射出现平台差异，回退到 design 阶段补充平台策略。
- 若 tests 暴露端口释放问题，优先修复 `TcpServer` close/drop 持有关系。
- 若 TLS handshake 或 connection manager 行为因 handler 边界改变出现回归，优先保留 `TlsConnectionHandler` 原行为并只修复 listener 适配层。
- 若 UDP datagram routing 或 transparent original-dst 行为因 handler 边界改变出现回归，优先保留 `UdpStackInner::handle_datagram()` 原行为并只修复 listener/socket 适配层。
- 若 QUIC handshake、CID routing 或 worker endpoint 行为因 handler 边界改变出现回归，优先保留 `QuicConnectionHandler` 原行为并只修复 listener/socket 适配层。
