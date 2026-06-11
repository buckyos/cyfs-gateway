# gateway-runtime TLS reuseport 验收报告

## 元数据
- version: v0.6
- module: gateway-runtime
- change_id: P-tls-reuseport-1
- stage: acceptance
- status: passed
- reviewed_at: 2026-05-31T00:00:00+08:00

## 结论
- 通过。
- `TlsStack` listener 已由手写 socket/listener/accept loop 迁移到 `sfo_reuseport::TcpServer`。
- `TlsStackFactory`、`TlsStackBuilder`、`TlsStack` 已接收外部 `sfo_reuseport::ServerRuntime`。
- `TlsStackConfig.concurrency` 继续由 `normalize_concurrency()` 处理，非 `u32::MAX` 时映射到 `ServiceConfig::with_max_concurrency_per_worker()`。
- 运行时组装层复用现有 `ReuseportServerRuntime` 注入 TCP 与 TLS factory。

## 文档证据
- Proposal：`docs/versions/v0.6/modules/gateway-runtime/proposal.md`
  - `P-tls-reuseport-1` 已列入实现准入覆盖。
  - TLS listener、factory/builder/stack runtime 注入、per-worker concurrency 均列入范围。
- Design：`docs/versions/v0.6/modules/gateway-runtime/design.md`
  - `TlsStackFactory::new(connection_manager, server_runtime)`
  - `TlsStackBuilder::server_runtime(...)`
  - `TlsStack::start_listener() -> TcpServer`
  - TLS handler 保留原有 TLS acceptor、证书、ALPN、统计、connection manager 和热更新行为。
- Testing：`docs/versions/v0.6/modules/gateway-runtime/testing.md`
  - `P-tls-reuseport-1` 映射到 `unit.gateway-runtime-tls-stack`。
- Testplan：`docs/versions/v0.6/modules/gateway-runtime/testplan.yaml`
  - 新增 `gateway-runtime-tls-stack` step，执行 `cargo test -p cyfs-gateway-lib test_tls_stack -- --test-threads=1`。

## 实现证据
- `src/components/cyfs-gateway-lib/src/stack/tls_stack.rs`
  - 删除手写 `socket2` listener 与本地 `Semaphore` accept loop。
  - 新增 `ServerRuntime` / `TcpServer` 持有关系。
  - `Drop` 调用 `TcpServer::close()`。
  - 新增 `handle_reuseport_tls_stream()`，保持 TLS connection handler 的完整连接生命周期。
  - 新增 abortable TLS connection controller，保留 connection manager stop/wait 能力。
- `src/apps/cyfs_gateway/src/lib.rs`
  - TLS factory 注册时传入共享 `ReuseportServerRuntime`。
- `src/apps/cyfs_gateway/tests/test_control_server.rs`
  - 控制平面测试组装路径同步传入 runtime。

## 验证结果
- `python3 harness/scripts/schema-check.py --root . --version v0.6 --module gateway-runtime`
  - 通过。
- `python3 harness/scripts/admission-check.py --root . --version v0.6 --module gateway-runtime --change-id P-tls-reuseport-1`
  - 通过。
- `cd src && cargo check -p cyfs-gateway-lib`
  - 通过。
  - 仅保留既有 `udp_stack.rs` unused unsafe warning。
- `python3 ./harness/scripts/test-run.py gateway-runtime unit`
  - 通过。
  - TCP reuseport 聚焦测试：10 passed。
  - TLS reuseport 聚焦测试：11 passed。
- `python3 ./harness/scripts/test-run.py gateway-runtime dv`
  - 通过。
- `python3 ./harness/scripts/test-run.py gateway-runtime integration`
  - 通过。

## 触发规则
- 命中 `harness/rules/trigger-rules.md`：
  - 契约或协议变更：`src/components/cyfs-gateway-lib/src/stack/`
  - 运行时或集成行为变更：`src/apps/cyfs_gateway/src/`、`src/apps/cyfs_gateway/tests/`
- 已执行额外检查：
  - unit
  - dv
  - integration

## 剩余风险
- 工作区在本次任务前已有大量未提交/未跟踪文件；本报告只审计 `P-tls-reuseport-1` 相关文件。
- 验证期间仍有既有 warning，但不属于本次 TLS reuseport 行为回归。
