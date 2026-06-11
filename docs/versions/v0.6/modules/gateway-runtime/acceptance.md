# gateway-runtime 验收

## 验收范围
- 版本：`v0.6`
- 模块：`gateway-runtime`
- 范围内：`P-tcp-reuseport-1` 的 TCP stack reuseport 重构、运行时 `ServerRuntime` 注入、测试入口和证据链
- 范围外：UDP、QUIC、TLS、RTCP、TUN、控制平面 API、新配置字段

## 证据链
- Proposal 基线：`docs/versions/v0.6/modules/gateway-runtime/proposal.md`
- 设计基线：`docs/versions/v0.6/modules/gateway-runtime/design.md`
- 测试基线：`docs/versions/v0.6/modules/gateway-runtime/testing.md`
- 机器可读测试计划：`docs/versions/v0.6/modules/gateway-runtime/testplan.yaml`
- 长期模块文档：`docs/modules/gateway-runtime.md`

## Auto-Pipeline 基线
- 最终验收以已批准的 `proposal.md` 为准。
- `design.md`、`testing.md`、`acceptance.md` 只能细化执行，不得改变 proposal 意图。

## 通过条件
- [ ] `TcpStack` 不在内部创建 `sfo_reuseport::ServerRuntime`。
- [ ] `TcpStackFactory` / builder / stack 由外部接收并保存 `ServerRuntime`。
- [ ] TCP listener 使用 `sfo_reuseport::TcpServer`，并在 drop/close 时释放。
- [ ] `TcpStackConfig.concurrency` 映射为 per-worker concurrency，不按 worker 数平均。
- [ ] `concurrency = 0` 继续表示不限流。
- [ ] process-chain、connection manager、统计、io dump、transparent、reuse_address、timeout 与热更新约束保持兼容。
- [ ] `testplan.yaml` 调用的验证面与 `testing.md` 中声明一致。
- [ ] `unit`、`dv`、`integration` 有通过证据，或清楚记录环境阻塞原因。

## 失败条件
- implementation 依赖聊天上下文而无法映射到 `P-tcp-reuseport-1`。
- `ServerRuntime` 在 `TcpStack` 内部被创建。
- `concurrency` 被改成总并发或被 worker 数平均。
- `TcpServer` close/drop 后端口无法释放。
- 测试入口无法定位或执行声明的 `testplan.yaml`。

## 回退路由
- Proposal 问题：范围、非目标或并发语义错误。
- Design 问题：类型接口、生命周期、路径归属或 shutdown 设计错误。
- Testing 问题：`testing.md`、`testplan.yaml` 或可执行命令漂移。
- Implementation 问题：运行时代码或测试未满足文档要求。
