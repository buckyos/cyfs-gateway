# cyfs-tun Proposal

## 元数据
- version: v0.6
- module: cyfs-tun
- stage: proposal
- status: draft

## 状态
- 人类可读状态：草稿

## 背景与目标
当前仓库把 `cyfs-tun` 作为 `gateway-runtime` 的依赖被间接描述，但缺少独立的长期边界文档和版本化模块包。这会让 tun 相关工作在修改 TUN 设备行为、`tuntunnel` 语义或配置契约时，只能回到聊天上下文或散落源码里反推归属。这个模块包的目标，是为 `cyfs-tun` 建立独立的 proposal、design、testing 与 acceptance 基线。

补充需求基线：`tun-tunnel` 后续若承担“把别的设备发来的数据交给监听 tun 设备的服务”这一职责，语义目标应是把原始 IP 包直接写入 tun fd，由 tun 设备侧网络栈继续分发，而不是通过普通 TCP / UDP socket 重新发起一条新的 L4 连接来近似该行为。

## 范围
### 范围内
- 记录 `cyfs-tun` 的长期职责、主要路径与相邻模块边界
- 建立 `cyfs-tun` 的版本化 proposal、design、testing、acceptance 与 `testplan.yaml`
- 显式记录当前自动化证据面与缺失的 DV / integration 缺口
- 为 `tun-tunnel` 的原始 IP 包注入语义建立可审批的目标与约束基线

### 范围外
- 修改 `TunStack`、`TunStackFactory` 或 `tun_tunnel` 的运行时行为
- 为 tun 模块补写新的自动化测试
- 重构 `gateway-runtime` 或 `process-chain-engine` 的模块边界
- 在本 proposal 中直接决定 raw packet 注入的具体实现结构、buffer 生命周期或平台适配细节

### 与相邻模块的边界
- `gateway-runtime` 负责解析总配置、注册 tun parser / factory，并在启动时装配 `cyfs-tun`
- `process-chain-engine` 负责执行 tun stack 的 hook_point 逻辑
- `runtime-configs` 提供 tun stack 的配置形态和默认示例，但不定义 tun 模块内部实现

## 约束
- 允许使用的库/组件：现有 Rust 工作区 crate、`harness/scripts/test-run.py`、现有 `cyfs-tun` 单元测试
- 不允许采用的方式：把 tun 模块规则继续埋在 `gateway-runtime` 基线里、伪造不存在的 DV / integration 覆盖、借创建模块包之机顺带修改 tun 行为、把“写入 tun 设备”需求退化为普通 TCP / UDP socket 代理
- 运行时或部署约束：真实 tun stack 依赖操作系统 TUN 能力和权限，独立模块测试当前不能假设所有环境具备 root 与设备条件

## 高层结果
- `cyfs-tun` 拥有独立的长期边界文档和版本化模块包
- 后续 tun 相关变更可以直接引用自己的 proposal / design / testing 条目
- 当前证据缺口被显式记录，后续可被正确路由到 testing 或 implementation 上游阶段
- `tun-tunnel` 若要承接外部设备流量，其目标语义被明确为“向 tun fd 注入原始 IP 包”，而不是“通过 socket 重新建连”

## 实现准入覆盖
| 条目 ID | 当前批准内容 | 可直接支持的实现任务 | 需要先补充的情况 |
|---------|--------------|----------------------|------------------|
| P-base-1 | 建立 `cyfs-tun` 的 harness 基线模块包与统一测试入口定义 | 维护这套基线文档、测试元数据和模块地图本身 | 任何改变 tun 行为、`tuntunnel` 契约、配置结构或测试覆盖面的实现任务 |
| P-tuntunnel-raw-1 | 若 `tun-tunnel` 需要把外部设备流量交给 tun 侧服务，必须以向 tun fd 写入原始 IP 包为目标语义 | 后续 design 可以据此定义 raw packet 注入路径、包边界、与 tun stack / tunnel manager 的接口关系 | 在 design 明确实现方案、testing 明确验证入口前，任何 raw packet 注入实现都不得开始 |

## 风险
- tun 模块处在系统设备、虚拟网络和运行时装配的交界面，边界不清会让后续 bugfix 越界。
- 当前自动化主要集中在 crate 单测，若不显式记录缺口，后续容易误判为“已有集成覆盖”。
- `tuntunnel` 语义存在演进空间，缺少独立 proposal 会让行为变更难以审计。
- raw packet 注入会把 `tun-tunnel` 从 socket 级代理提升为设备级报文通路，若 proposal 不先锁定语义，后续 design 很容易在“payload 转发”和“原始报文注入”之间摇摆。
