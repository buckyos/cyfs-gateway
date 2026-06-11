# 模块地图

## 长期模块

| 模块 | 职责 | 主要路径 | 主要依赖 |
|------|------|----------|----------|
| `gateway-runtime` | 组装并运行网关服务、控制平面、运行时 server 图以及集成测试 | `src/apps/cyfs_gateway/`、`src/components/cyfs-gateway-lib/` | `cyfs-dns`、`cyfs-socks`、`cyfs-tun`、`server-runner`、运行时配置 |
| `cert-manager` | 统一管理 ACME、自签 fallback、服务端证书解析与 tunnel 客户端证书生命周期 | `src/components/cyfs-acme/`、`src/components/cyfs-gateway-lib/src/*cert*`、`src/apps/cyfs_gateway/src/gateway.rs` | `gateway-runtime`、`runtime-configs`、`cyfs-dns`、TLS / QUIC stack consumer |
| `cyfs-tun` | 提供 TUN 设备侧虚拟网络栈、hook_point 执行入口以及 `tuntunnel` 接线 | `src/components/cyfs-tun/`、`src/apps/cyfs_gateway/src/config_loader.rs`、`src/apps/cyfs_gateway/src/gateway.rs` | `gateway-runtime`、`process-chain-engine`、`runtime-configs` |
| `process-chain-engine` | 执行网关 server 与 stack 使用的可编排 process-chain 模型 | `src/components/cyfs-process-chain/`、`src/components/cyfs-process-chain-lint/` | gateway runtime、`doc/reference.md` 中的参考资料 |
| `runtime-configs` | 定义出厂运行时布局、bind 地址以及打包模板 | `src/rootfs/etc/`、`src/apps/cyfs_gateway/src/*.yaml` | gateway runtime、打包工作流 |
| `web-dashboard` | 提供 Vite/React 控制台与浏览器侧控制流程 | `src/apps/cyfs_gateway/web/` | control API、`cyfs_gateway` 暴露的运行时状态 |

## 依赖关系
- `runtime-configs` 为运行时组装提供输入。
- `process-chain-engine` 为 gateway runtime 提供执行原语。
- `cert-manager` 为 `gateway-runtime` 提供证书生命周期、resolver 与 challenge 能力，并消费 `runtime-configs` 暴露的证书相关配置入口。
- `gateway-runtime` 负责服务启动、server 注册与整体集成行为，并装配 `cert-manager` 到 stack、server 与 tunnel consumer。
- `cyfs-tun` 负责 TUN 设备、`ipstack` 与 `tuntunnel` 的模块内行为，并由 `gateway-runtime` 统一装配。
- `web-dashboard` 依赖运行时暴露出的稳定控制平面与数据模型契约。

## 文档规则
- `docs/modules/*.md` 用于记录长期职责和边界。
- `docs/versions/v0.6/modules/<module>/` 用于记录版本化的 proposal、design、testing 与 acceptance 工件。
- `doc/` 只在 harness 文档需要引用历史设计背景时使用。
