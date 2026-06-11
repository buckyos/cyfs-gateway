# gateway-runtime TCP reuseport 验收报告

## 结论
- 结果：通过
- 版本：`v0.6`
- 模块：`gateway-runtime`
- 变更 ID：`P-tcp-reuseport-1`
- 验收时间：2026-05-30

## 验收基线
- Proposal：`docs/versions/v0.6/modules/gateway-runtime/proposal.md`
- Design：`docs/versions/v0.6/modules/gateway-runtime/design.md`
- Testing：`docs/versions/v0.6/modules/gateway-runtime/testing.md`
- Testplan：`docs/versions/v0.6/modules/gateway-runtime/testplan.yaml`
- Acceptance 标准：`docs/versions/v0.6/modules/gateway-runtime/acceptance.md`

## 实现审计
- `TcpStackFactory` 接收外部 `ReuseportServerRuntime`，factory create 时传给 builder。
- `TcpStackBuilder` 要求 `server_runtime`，缺失时返回 invalid config。
- `TcpStack` 使用 `sfo_reuseport::TcpServer::serve()` 启动 listener，保存 `TcpServer` 并在 drop 时 close。
- `TcpStackConfig.concurrency` 直接映射到 `ServiceConfig::with_max_concurrency_per_worker()`；`concurrency = 0` 经 normalize 后不设置限制。
- connection manager 保留 stop/wait 能力，通过 abortable controller 绑定当前 handler future，避免 handler 提前返回导致 per-worker concurrency 失效。
- `cyfs_gateway` 运行时组装层创建共享 `ReuseportServerRuntime` 并注入 TCP factory。

## 测试证据
- `cargo check -p cyfs-gateway-lib`：通过。
- `cargo check -p cyfs_gateway`：通过。
- `python3 ./harness/scripts/test-run.py gateway-runtime unit`：通过。
  - connection manager smoke：1 passed。
  - TCP stack 聚焦测试：10 passed。
- `python3 ./harness/scripts/test-run.py gateway-runtime dv`：通过。
  - `test_control_server`：1 passed。
- `python3 ./harness/scripts/test-run.py gateway-runtime integration`：
  - 沙箱内首次运行失败，原因是 `get_buckyos_service_data_dir("cyfs_gateway")` 指向的服务数据目录在沙箱中只读。
  - 按权限规则在非沙箱文件系统限制下重跑：通过，`test_cyfs_gateway` 1 passed。

## 不一致项
- 未发现 proposal / design / testing / implementation 之间的阻塞性不一致。
- 保留既有 warning：
  - `udp_stack.rs` 中两个 `unused_unsafe` warning。
  - `test_control_server.rs` 中既有 unused 变量 warning。
  - `test_cyfs_gateway.rs` 中既有 dead code warning。

## 回退路由
- 无需回退。
