# gateway-runtime

## 职责
负责整体网关运行时的组装，包括配置加载、stack 与 server 注册、控制平面接线以及端到端运行行为。

## 主要路径
- `src/apps/cyfs_gateway/src/`
- `src/apps/cyfs_gateway/tests/`
- `src/components/cyfs-gateway-lib/src/`

## 输入
- `src/rootfs/etc/` 与本地 gateway YAML 中的运行时配置
- process-chain 定义与命令行为
- 来自 BuckyOS 基础库与 Tokio 运行时的外部依赖

## 输出
- 可运行的网关服务进程
- 控制平面端点
- HTTP、DNS、SOCKS、TLS、RTCP、QUIC 等栈与服务的集成运行行为

## 邻接边界
- 依赖 `process-chain-engine` 提供可编排请求处理能力
- 消费 `runtime-configs` 提供的默认组装与打包行为
- 依赖 `cert-manager` 提供证书生命周期、challenge 暴露面与服务端 / tunnel 证书消费能力
- 向 `web-dashboard` 暴露状态与控制接口

## 验证面
- `src/components/cyfs-gateway-lib/src/` 中的 Rust 单元测试
- `src/apps/cyfs_gateway/tests/` 中的运行时 smoke 与控制平面测试
- `src/apps/cyfs_gateway/tests/test_cyfs_gateway.rs` 中的完整网关集成测试

## 风险等级
Tier A：核心运行时行为、控制平面组装与网络契约变更都需要明确测试证据。
