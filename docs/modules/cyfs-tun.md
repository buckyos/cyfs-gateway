# cyfs-tun

## 职责
负责 TUN 设备侧的虚拟网络栈接入，包括创建并运行 tun stack、通过 `ipstack` 解析 TUN 流量、执行 hook_point，以及向 tunnel manager 暴露面向 tun writer 的 `tuntunnel` 入口。该入口的目标语义是接收完整原始 IP 包并写入 tun fd，由 tun 设备侧网络栈继续把报文分发给监听在 tun 设备上的服务。

## 主要路径
- `src/components/cyfs-tun/src/`
- `src/apps/cyfs_gateway/src/config_loader.rs`
- `src/apps/cyfs_gateway/src/gateway.rs`
- `src/apps/cyfs_gateway/src/lib.rs`

## 输入
- gateway YAML 中的 `protocol: tun` stack 配置
- 来自 `gateway-runtime` 注入的 server / tunnel / limiter / stat / process-chain 上下文
- TUN 设备上的 IP 流量
- 来自上游 packet tunnel 的原始 IP 包

## 输出
- 运行中的 tun stack
- 由 hook_point 驱动的 TCP / UDP 转发或 server 处理行为
- 注册到 tunnel manager 的 `tuntunnel` builder
- 基于 tun writer 的原始 IP 包注入入口

## 邻接边界
- 由 `gateway-runtime` 负责装配、注册 factory 和提供上下文
- 依赖 `process-chain-engine` 执行 hook_point 链路
- 消费 `runtime-configs` 提供的 tun stack 配置形态，但不定义整站运行时装配
- `cyfs-tun` 负责 tun fd 写入、packet 注入语义与 tun 侧服务可达性，但不拥有这些服务本身的应用协议逻辑
- packet-oriented tunnel 抽象定义仍归 `gateway-runtime` 所拥有的 `cyfs-gateway-lib`，`cyfs-tun` 只对接该契约

## 验证面
- `src/components/cyfs-tun/src/tun_tunnel.rs` 中的 crate 单元测试
- 配置解析与运行时接线当前通过 `gateway-runtime` 路径间接覆盖
- 目前缺少独立的 tun stack DV / integration 自动化证据

## 风险等级
Tier A：TUN 设备行为、虚拟网络契约与 tunnel 语义变更都需要显式测试和评审。
