# cyfs-tun 设计

> 本文件记录 `cyfs-tun` 面向 raw packet 注入语义的目标实现形态，作为后续实现与测试的 design 基线。

## 元数据
- version: v0.6
- module: cyfs-tun
- stage: design
- status: draft

## 设计范围
### 目标
- 定义 `tun-tunnel` 以原始 IP 包注入 tun fd 的目标实现形态
- 明确 `cyfs-tun`、`gateway-runtime` 与 `cyfs-gateway-lib` 在该语义下的接口边界
- 把后续 raw packet 注入实现收敛到可执行的模块拆解、路径归属与实现顺序

### 非目标
- 在本次 design 里直接实现 raw packet 注入代码
- 在本次 design 里补做新的 DV / integration 自动化
- 保留“通过普通 TCP / UDP socket 代理近似 tun 注入”作为目标语义

## 总体方案
`cyfs-tun` 仍以 crate 形式承载 TUN 设备侧网络能力，但 `tun-tunnel` 的目标语义改为 packet-oriented 的 tun fd 注入，而不是基于 bind IP 的 socket 代理。`TunStackFactory` 继续由 gateway runtime 注册，配置解析阶段把 `protocol: tun` 的配置反序列化为 `TunStackConfig`，运行阶段由 `TunStack` 创建异步 TUN 设备；启动时设备被拆成 reader / writer 两个方向，reader 继续交给 `ipstack` 维护 tun 侧已有会话处理，writer 则被封装成按 stack id / bind IP 索引的 raw packet injector。`tun-tunnel` builder 解析目标 tun stack 后，不再创建 TCP / UDP socket，而是把上游交付的完整 IP 包写入对应 tun writer，由 tun 设备侧网络栈继续把报文分发给监听在 tun 设备上的服务。

由于原始 IP 包注入是 packet-oriented 语义，现有 `cyfs-gateway-lib` 中只暴露 byte-stream / payload-datagram 的 `Tunnel` / `DatagramClient` 抽象不足以无损表达该能力。本设计要求在 `gateway-runtime` 所拥有的 `cyfs-gateway-lib` tunnel 契约中补充 packet-oriented 接口或等价协议类别，再由 `cyfs-tun` 的 `tun-tunnel` adapter 对接该接口；未分帧的 `open_stream()` 不再作为 raw packet 注入的主路径。

## 模块拆解
| 子模块 | 类型 | 职责 | 输入 | 输出 | 依赖 | 是否拆分独立文档 |
|--------|------|------|------|------|------|------------------|
| tun-stack-runtime | runtime | 创建 TUN 设备、拆分 reader / writer、运行 `ipstack`、处理 tun 侧 TCP / UDP 会话与生命周期 | `TunStackConfig`、TUN 流量、stack context | 运行中的 tun stack、已注册的 packet injector、连接管理记录 | `tun_stack.rs`、`tun`、`ipstack`、`cyfs-gateway-lib` | no |
| tun-device-io | runtime | 持有 tun writer，校验原始 IP 包并按平台约定写入 tun fd | stack id、bind IP、raw IP packet、MTU / packet-information 配置 | tun 设备写入结果、packet 注入错误 | `tun_stack.rs`、`tun_device_io.rs`、`tun 0.8.7` | no |
| tun-tunnel-adapter | runtime | 维护 tun endpoint 与 injector 注册表，对接 packet-oriented tunnel 契约并路由到目标 tun writer | tun stack id、bind IP、原始 IP 包、上游 packet 请求 | packet 注入句柄、按 stack 解析的写入通路 | `tun_tunnel.rs`、`TunnelManager`、`cyfs-gateway-lib/src/tunnel.rs` | no |
| gateway-assembly | assembly | 在 runtime 中注册 parser / factory / context，并把 packet-oriented `tuntunnel` 契约接入 tunnel manager | gateway 配置、manager 上下文、tunnel 抽象定义 | 可被网关装配的 tun stack 与已注册 builder | `src/apps/cyfs_gateway/src/lib.rs`、`gateway.rs`、`config_loader.rs`、`src/components/cyfs-gateway-lib/src/tunnel.rs`、`tunnel_mgr.rs` | no |
| tun-tests | shared | 为 raw packet 注入语义、writer 注册表和平台包头规则提供可扩展证据入口 | `cyfs-tun` crate、future packet tests | 测试入口与缺口说明 | `tun_tunnel.rs`、future packet tests | no |

## 实现顺序
| 阶段 | 目标 | 前置条件 | 输出 | 依赖 | 是否可并行 |
|------|------|----------|------|------|------------|
| 1 | 收紧长期模块边界 | `P-tuntunnel-raw-1` 已建立 | `docs/modules/cyfs-tun.md` | 无 | 否 |
| 2 | 扩展 packet-oriented tunnel 契约 | 阶段 1 完成 | `cyfs-gateway-lib` 中的 packet 接口设计与 builder 接线点 | 1 | no |
| 3 | 在 `TunStack` 内拆分 tun 设备并建立 writer 注入句柄 | 阶段 2 完成 | `TunStackInner` 设备读写分工、injector 注册形态 | 2 | no |
| 4 | 以 packet injector 重写 `tun-tunnel` 适配层 | 阶段 3 完成 | stack 解析、raw packet 写入、legacy API 处理策略 | 2,3 | no |
| 5 | 在 testing 中补 raw packet 注入证据 | 阶段 4 的设计已冻结 | packet 级 unit / DV / integration 计划 | 2,3,4 | yes |

## 关键决策
- 将 `cyfs-tun` 从 `gateway-runtime` 基线中拆成独立模块包，但保留两者的装配关系。
- `tun-tunnel` 的目标语义被固定为“写入 tun fd 的原始 IP 包”，不再把普通 TCP / UDP socket 代理视为等价实现。
- raw packet 注入是 packet-oriented 能力，`Tunnel` / `DatagramClient` 现有抽象不足以表达该语义；需要由 `gateway-runtime` 所拥有的 `cyfs-gateway-lib` 补充 packet-oriented 契约后，再由 `cyfs-tun` 对接。
- `TunStack` 必须显式保留 tun writer，而不是把整块设备句柄完全交给 `ipstack`；reader 继续服务现有 tun 入站处理，writer 专用于外部 raw packet 注入。
- 设备写入必须显式处理 MTU、IP version 与 Unix 平台 packet-information 头，不能把这些规则散落在调用方。
- 对缺失的 DV / integration 证据保持显式缺口，而不是用运行时总测替代模块级证据。

## 接口与依赖
### 对外接口摘要
- `TunStackFactory`、`TunStackConfig`、`TunStackContext` 供 gateway runtime 装配 tun stack
- `TunStack` 在启动时注册 `tuntunnel` builder，并同时暴露与 stack id / bind IP 绑定的 packet injector
- `tun-tunnel` 只接收完整原始 IP 包并写入 tun writer，不负责替调用方生成 TCP / UDP socket 或补全会话语义
- `cyfs-gateway-lib` 需要增加 packet-oriented tunnel 契约与协议分类；legacy `open_stream()` 若未显式引入 packet framing，不再作为 raw packet 注入入口

### 配置与运行时接口
- `src/apps/cyfs_gateway/src/config_loader.rs` 负责把 `hook_point` map 形式转换为 `TunStackConfig`
- `src/rootfs/etc/cyfs_gateway.yaml` 提供 tun stack 配置示例
- `src/apps/cyfs_gateway/src/gateway.rs` 负责为 `protocol: tun` 生成 `TunStackContext`
- `src/components/cyfs-gateway-lib/src/tunnel.rs` 与 `tunnel_mgr.rs` 负责定义并注册 packet-oriented `tuntunnel` 契约

### 外部依赖约束
- `tun 0.8.7` 的异步设备支持 `split()`；design 依赖该能力把 reader 留给 `ipstack`、writer 留给 injector
- `ipstack 0.5.0` 负责把设备流量转成 TCP / UDP / unknown packet 流，并在 Unix 平台用 `packet_information` 控制 4-byte PI 头读写
- raw packet 注入在进入 tun writer 前应至少校验 IP version、长度与 MTU 上限；需要时可复用 `ipstack::NetworkPacket::parse` 做最小合法性检查
- 真实 TUN 设备路径对操作系统与权限敏感，Linux 下需要 root 能力

## 实现布局
```text
src/components/cyfs-tun/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── tun_device_io.rs   # planned
    ├── tun_stack.rs
    └── tun_tunnel.rs

src/apps/cyfs_gateway/src/
├── lib.rs
├── gateway.rs
└── config_loader.rs

src/components/cyfs-gateway-lib/src/
├── tunnel.rs
└── tunnel_mgr.rs

src/rootfs/etc/
└── cyfs_gateway.yaml
```

| 路径 | 类型 | 职责 | 备注 |
|------|------|------|------|
| `src/components/cyfs-tun/src/lib.rs` | Rust 源码 | 暴露 tun stack 公共入口 | crate 导出面 |
| `src/components/cyfs-tun/src/tun_stack.rs` | Rust 源码 | TUN 设备拆分、`ipstack` reader、hook_point 与 stack 生命周期 | 核心实现热点 |
| `src/components/cyfs-tun/src/tun_device_io.rs` | Rust 源码（planned） | tun writer 封装、PI 头处理与 raw packet 注入 | 计划中的 packet injector 路径 |
| `src/components/cyfs-tun/src/tun_tunnel.rs` | Rust 源码 | `tuntunnel` builder、endpoint / injector 注册与 packet 注入路由 | 当前 tunnel 语义敏感路径 |
| `src/apps/cyfs_gateway/src/lib.rs` | Rust 源码 | 注册 tun config parser 和 stack factory | 运行时接线点 |
| `src/apps/cyfs_gateway/src/gateway.rs` | Rust 源码 | 生成 `TunStackContext` | 与 runtime manager 耦合 |
| `src/apps/cyfs_gateway/src/config_loader.rs` | Rust 源码 | 解析 `TunStackConfig` | 配置契约入口 |
| `src/components/cyfs-gateway-lib/src/tunnel.rs` | Rust 源码 | 定义 tunnel / packet tunnel 公共契约 | `gateway-runtime` 所有，但本设计依赖其扩展 |
| `src/components/cyfs-gateway-lib/src/tunnel_mgr.rs` | Rust 源码 | 注册并分发 `tuntunnel` builder | protocol category 与 builder 接线点 |
| `src/rootfs/etc/cyfs_gateway.yaml` | YAML 配置 | 提供 tun stack 配置示例 | 默认配置参考 |

## 文档索引
| 文档 | 主题 | 范围 |
|------|------|------|
| `design.md` | `cyfs-tun` raw packet 注入方案 | 完整模块 |

## 实现准入映射
| Proposal 条目 ID | Design 条目 / 章节 | 相关路径或接口 | 哪些改动仍需先补 design |
|------------------|--------------------|----------------|--------------------------|
| `P-base-1` | `模块拆解`、`实现布局` | `src/components/cyfs-tun/src/`、`src/apps/cyfs_gateway/src/lib.rs`、`gateway.rs`、`config_loader.rs` | 任意改变 tun stack 配置结构、hook_point 行为或子模块边界的实现任务 |
| `P-tuntunnel-raw-1` | `总体方案`、`关键决策`、`接口与依赖`、`实现布局` | `src/components/cyfs-tun/src/tun_stack.rs`、`tun_device_io.rs`、`tun_tunnel.rs`、`src/components/cyfs-gateway-lib/src/tunnel.rs`、`tunnel_mgr.rs` | 任意改变 raw packet framing、packet tunnel 契约、PI 头处理策略、legacy API 兼容策略或跨模块所有权的实现任务 |

## 风险与回滚
- TUN 设备与虚拟网络行为对平台和权限敏感，文档与实现漂移容易引入难复现问题。
- raw packet 注入引入 packet 边界、PI 头与 MTU 约束；若调用方仍按 byte-stream 语义接入，会直接导致报文损坏。
- `cyfs-tun` 依赖 `gateway-runtime` 所拥有的 tunnel 抽象扩展，若跨模块文档不同步，implementation 很容易越界。
- 回滚优先级应是先回退 packet-oriented 契约扩展与 tun writer 注入路径，再恢复到上一个稳定的 `tuntunnel` 语义，而不是混用两套行为。
