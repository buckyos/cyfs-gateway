# gateway-runtime Proposal

## 元数据
- version: v0.6
- module: gateway-runtime
- stage: proposal
- status: approved
- approved_by: auto-pipeline
- approved_at: 2026-05-31T00:00:00+08:00

## 状态
- 人类可读状态：已批准

## 背景与目标
网关运行时负责配置加载、stack 与 server 注册、控制平面接线以及网络栈集成行为。TCP stack 当前已经迁移到 `sfo-reuseport`；TLS stack 仍在 `TlsStack` 内部手写 socket 创建、bind/listen、accept loop 和本地并发控制。UDP stack 仍在 `UdpStackInner` 内部手写 UDP socket 创建、bind、recv loop 和本地并发控制。QUIC stack 仍在 `QuicStackInner` 内部手写 UDP socket bind、quinn endpoint accept loop 和本地连接数限制。仓库已引入并更新 `sfo-reuseport`，该库能够提供 TCP/UDP/QUIC reuse-port worker listener 和 per-worker concurrency。

本次变更目标是让 TCP、TLS、UDP 与 QUIC stack 都使用 `sfo-reuseport` 提供的 server 能力，并让 `ServerRuntime` 由运行时组装层外部传入，避免 stack 自行创建或管理全局 worker runtime。

## 范围
### 范围内
- 将 `TcpStack` 的监听实现从手写 `tokio::net::TcpListener` accept loop 迁移到 `sfo_reuseport::TcpServer`。
- `TcpStackFactory`、`TcpStackBuilder` 和 `TcpStack` 接收外部传入的 `sfo_reuseport::ServerRuntime`。
- 保持 `TcpStackConfig.concurrency` 的当前目标语义：作为每个 reuseport worker 的并发上限。
- 将 `TlsStack` 的监听实现从手写 `tokio::net::TcpListener` accept loop 迁移到 `sfo_reuseport::TcpServer`。
- `TlsStackFactory`、`TlsStackBuilder` 和 `TlsStack` 接收外部传入的 `sfo_reuseport::ServerRuntime`。
- 保持 `TlsStackConfig.concurrency` 的当前目标语义：作为每个 reuseport worker 的并发上限。
- 将 `UdpStack` 的监听实现从手写 `socket2`/`tokio::net::UdpSocket` bind 和 recv loop 迁移到 `sfo_reuseport::UdpServer`。
- `UdpStackFactory`、`UdpStackBuilder` 和 `UdpStackInner` 接收外部传入的 `sfo_reuseport::ServerRuntime`。
- 保持 `UdpStackConfig.concurrency` 的当前目标语义：作为每个 reuseport worker 的 datagram handler 并发上限。
- 将 `QuicStack` 的监听实现从手写 `socket2`/`quinn::Endpoint` 单 listener accept loop 迁移到 `sfo_reuseport::QuicServer` worker socket。
- `QuicStackFactory`、`QuicStackBuilder` 和 `QuicStackInner` 接收外部传入的 `sfo_reuseport::ServerRuntime`。
- 保持 `QuicStackConfig.concurrency` 的当前目标语义：作为每个 reuseport worker 的 QUIC open connection 上限。
- 将 `concurrency = 0` 继续解释为不限制并发。
- 保持现有 process-chain、connection manager、统计、io dump、transparent、reuse_address、timeout 和热更新语义。
- 更新聚焦测试入口，使 TCP stack 重构有可追踪证据。
- 更新聚焦测试入口，使 TLS stack listener 重构有可追踪证据。
- 更新聚焦测试入口，使 UDP stack listener 重构有可追踪证据。
- 更新聚焦测试入口，使 QUIC stack listener 重构有可追踪证据。

### 范围外
- 不重构 RTCP 或 TUN stack。
- 不新增用户可见配置字段。
- 不改变控制平面 API。
- 不把总并发平均分配到 worker；`concurrency` 不除以 worker 数。
- 不引入新的 runtime 配置文件或 CLI 参数。

### 与相邻模块的边界
- `gateway-runtime` 负责创建和注入 `ServerRuntime`，并注册 TCP/TLS/UDP/QUIC stack factory。
- `cyfs-gateway-lib` 负责 TCP/TLS/UDP/QUIC stack 实现和 factory。
- `runtime-configs` 不在本次范围内，因为配置结构和默认模板不新增字段。

## 约束
- `ServerRuntime` 必须由外部组装层创建并传入，`TcpStack` 和 `TlsStack` 不得自行启动新的 `ServerRuntime`。
- `TcpStackConfig.concurrency` 和 `TlsStackConfig.concurrency` 映射为 `ServiceConfig::with_max_concurrency_per_worker(concurrency)`。
- `UdpStackConfig.concurrency` 映射为 `UdpServiceConfig::with_max_concurrency_per_worker(concurrency)`。
- `QuicStackConfig.concurrency` 映射为每个 worker endpoint 的 open connection 上限；`concurrency = 0` 不限流。
- `concurrency = 0` 仍通过现有 normalize 逻辑表示不限流，并且不设置 `max_concurrency_per_worker`。
- `bind`、`transparent`、`reuse_address`、`concurrency` 仍然是 listener 启动参数，热更新时必须保持不变。
- 代码改动保持小范围，不顺带重构 process-chain 或 connection manager 行为。

## 高层结果
- TCP/TLS/UDP/QUIC stack 由 `sfo-reuseport` 管理 reuse-port worker listener。
- `ServerRuntime` 生命周期由运行时组装层统一持有。
- TCP/TLS/QUIC 连接处理行为、UDP datagram/session 处理行为和现有配置契约保持兼容。
- 统一测试入口能覆盖 TCP/TLS/UDP/QUIC stack 创建、启动和基本转发行为。

## 实现准入覆盖
| 条目 ID | 当前批准内容 | 可直接支持的实现任务 | 需要先补充的情况 |
|---------|--------------|----------------------|------------------|
| P-base-1 | 建立 `gateway-runtime` 的 harness 基线模块包与验证入口 | 维护 harness 基线文档、模板和测试入口本身 | 其他未覆盖的运行时行为、契约或配置变更 |
| P-tcp-reuseport-1 | TCP stack 使用外部传入的 `sfo_reuseport::ServerRuntime` 和 `sfo_reuseport::TcpServer`，并把 `concurrency` 作为 per-worker concurrency | 修改 `TcpStack`、`TcpStackFactory`、运行时 factory 注册和相关聚焦测试 | 新增用户配置字段、改变控制平面 API、改变 UDP/QUIC 等其他 stack 行为 |
| P-tls-reuseport-1 | TLS stack 使用外部传入的 `sfo_reuseport::ServerRuntime` 和 `sfo_reuseport::TcpServer`，并把 `concurrency` 作为 per-worker concurrency | 修改 `TlsStack`、`TlsStackFactory`、运行时 factory 注册和相关聚焦测试 | 新增用户配置字段、改变控制平面 API、改变 UDP/QUIC/RTCP/TUN 等其他 stack 行为 |
| P-udp-reuseport-1 | UDP stack 使用外部传入的 `sfo_reuseport::ServerRuntime` 和 `sfo_reuseport::UdpServer`，并把 `concurrency` 作为 per-worker datagram handler concurrency | 修改 `UdpStack`、`UdpStackFactory`、运行时 factory 注册和相关聚焦测试 | 新增用户配置字段、改变控制平面 API、改变 QUIC/RTCP/TUN 等其他 stack 行为 |
| P-quic-reuseport-1 | QUIC stack 使用外部传入的 `sfo_reuseport::ServerRuntime` 和 `sfo_reuseport::QuicServer`，并把 `concurrency` 作为 per-worker open connection 上限 | 修改 `QuicStack`、`QuicStackFactory`、运行时 factory 注册和相关聚焦测试 | 新增用户配置字段、改变控制平面 API、改变 RTCP/TUN 等其他 stack 行为 |

## 风险
- TCP listener 生命周期从 `JoinHandle` 切换到 `TcpServer`，drop/close 路径必须释放端口。
- TLS listener 生命周期从 `JoinHandle` 切换到 `TcpServer`，drop/close 路径必须释放端口。
- UDP listener 生命周期从 `JoinHandle` 切换到 `UdpServer`，drop/close 路径必须释放端口。
- QUIC listener 生命周期从 `JoinHandle` 切换到 `QuicServer`，drop/close 路径必须关闭 worker endpoint 并释放端口。
- 并发限制从本地 `Semaphore` 迁移到 `sfo-reuseport` 的 worker limit，必须保持 `concurrency = 0` 不限流。
- transparent socket option 需要正确映射到 `sfo-reuseport::SocketOptions`。
- factory 构造签名变化会影响运行时注册和测试注册点。
