# [DONE] Gateway 公共宿主与静态模块化重构 TODO

## 完成记录

- 完成日期：2026-07-20。
- 已完成统一 Stack Registry、不可变 Composition、显式 AppProfile、静态模块 adapter、
  SN ACME provider 收敛，以及配置、Gateway runtime、CLI/服务入口的公共宿主迁移。
- cyfs_gateway 与 web3_gateway 现在只维护各自 profile、显式模块清单和极薄入口；
  Web3 的数据 namespace、配置 basename、模板 namespace 与 token audience 显式保留
  既有兼容值。
- 已完成测试去重、依赖和 build script 收尾，并更新相关架构/配置文档。
- 验收通过：cargo build --verbose、cargo test -- --test-threads=1，以及
  app-lib、modules、cyfs_gateway、web3_gateway 的分包测试。

## 1. 文档用途

本文是统一 Server Registry 完成后的后续实施说明，供 CodeAgent 分阶段完成
`cyfs_gateway` / `web3_gateway` 公共宿主和静态模块化重构。

已完成的 Server Registry 不属于本 TODO 的待办范围，不要重新实现或退回到 parser、
factory、context 分散注册的旧结构。其当前入口是：

- `src/components/cyfs-gateway-app-lib/src/server_registry.rs`
- `doc/Gateway统一Server注册机制-TODO.md`

本 TODO 的最终目标是：Gateway 的通用运行时只维护一份，二进制只声明应用身份和需要
静态编译、显式安装的模块。

## 2. 当前基线

基线提交：`2dc93679 Add server_registry`。

当前已确认：

- `cyfs_gateway/src/gateway.rs` 与 `web3_gateway/src/gateway.rs` 均为 5998 行且内容完全
  相同；
- 两份 `config_loader.rs` 均为 277 行且内容完全相同；
- 两份 `lib.rs` 仍有约 2400 行，主要差异只有应用名、日志和少量配置测试；
- Stack 仍在应用中分别注册 config parser 和 factory，并由
  `gateway.rs::build_stack_context` 的大 `match` 创建 context；
- `cyfs-gateway-app-lib::build_default_gateway_server_registry()` 仍直接注册全部 9 种
  Server，公共宿主因此直接依赖 `cyfs-dns`、`cyfs-sn`、`cyfs-socks` 等具体组件；
- 两个 app 各自保留一份 `acme_sn_provider.rs`，实现已经发生明显漂移；
- `web3_gateway` 的数据目录、默认配置、token audience、模板目录仍大量使用
  `cyfs_gateway` / `cyfs-gateway` 字面量；这些值可能是兼容约定，不能在重构时根据
  二进制名自动改掉；
- 两套集成测试存在大量复制，修复经常只落在其中一套。

## 3. 目标架构

目标依赖方向：

```text
cyfs-gateway-lib
    基础 Stack/Server/Tunnel trait 与数据面实现
            ^
            |
cyfs-gateway-app-lib
    公共宿主、配置、CLI、registry contract、模块组合与生命周期
            ^                         ^
            |                         |
gateway module adapters          binary profiles
    连接具体组件                    只声明身份和模块列表
            ^                         ^
            |                         |
cyfs-dns/cyfs-sn/...          cyfs_gateway/web3_gateway
```

目标二进制应接近：

```rust
pub fn app() -> anyhow::Result<GatewayApp> {
    GatewayApp::builder(cyfs_gateway_profile())
        .install(CoreGatewayModule::new())?
        .install(DnsGatewayModule::new())?
        .install(SocksGatewayModule::new())?
        .install(TunGatewayModule::new())?
        .install(SnGatewayModule::new())?
        .install(TrafficGatewayModule::new())?
        .build()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    app()?.run().await
}
```

Web3 二进制使用自己的 `AppProfile` 和显式模块清单。两个 profile 初期允许安装完全
相同的模块以保持行为，但不能再复制 Gateway 宿主实现。

### 3.1 编译期能力与运行时配置的边界

- Rust/Cargo 依赖和 `.install(...)` 列表决定二进制具备哪些能力；
- YAML/JSON 只能创建已编译并已安装模块的实例；
- 配置引用未安装的 Server/Stack 时，应返回包含已安装能力列表的明确错误；
- 不使用 YAML 动态加载 Rust 动态库；
- 不使用 `inventory`、`ctor` 等隐式全局注册；
- 不把 Cargo feature 作为唯一模块选择机制。feature 可以控制模块内部实现，但运行期
  注册事实必须来自显式 `.install(...)`。

## 4. 强制设计约束

### 4.1 保留统一 Server Registry

- [x] 保留 parser、factory、context builder 原子 registration；
- [x] 保留 build-time builder、运行期不可变 registry、重复注册 fail-fast；
- [x] 配置解析、首次启动、reload 继续共享同一 registry；
- [x] 抽取模块时只移动 concrete registration 的归属，不复制或弱化 registry contract；
- [x] 不恢复 `register_server_config_parser`、`register_server_factory` 或
  `build_server_context`。

### 4.2 显式 AppProfile

新增不可变 `GatewayAppProfile`，至少显式表达：

```rust
pub struct GatewayAppProfile {
    pub binary_name: &'static str,
    pub display_name: &'static str,
    pub log_name: &'static str,
    pub service_data_namespace: &'static str,
    pub config_basename: &'static str,
    pub token_audience: &'static str,
    pub template_namespace: &'static str,
}
```

- [x] 所有当前硬编码路径和身份字面量先映射到 profile 字段；
- [x] `cyfs_gateway` profile 保持现有行为；
- [x] `web3_gateway` 当前仍使用 `cyfs_gateway` 数据 namespace 和 `cyfs-gateway` token
  audience，初次迁移必须显式保留这些兼容值；
- [x] 不允许从 `display_name` 或 Cargo package name 隐式推导持久化路径；
- [x] 若后续需要把 Web3 数据迁移到独立目录，必须另立迁移任务，包含旧目录探测、迁移
  和回滚策略；不得夹带在本重构中。

### 4.3 显式 GatewayModule

模块接口负责向组合 builder 安装能力，不直接启动后台任务：

```rust
pub trait GatewayModule: Send + Sync + 'static {
    fn id(&self) -> &'static str;
    fn install(&self, builder: &mut GatewayCompositionBuilder) -> anyhow::Result<()>;
}
```

`GatewayCompositionBuilder` 至少持有：

- Server Registry builder；
- Stack Registry builder；
- ACME DNS provider factory registrations；
- 需要时才加入的 config section / runtime lifecycle registrations；
- 已安装 module id 集合。

- [x] module id 重复安装必须 fail-fast；
- [x] Server type、Stack protocol、ACME provider name 重复必须 fail-fast，并报告两个
  module 来源；
- [x] `build()` 后 composition 不可变；
- [x] 启动日志打印排序后的 module、Server 和 Stack 能力清单；
- [x] module 的安装顺序不能改变配置中 Server/Stack 实例的启动顺序。

### 4.4 不制造循环依赖

`cyfs-gateway-app-lib` 不应为了注册可选模块继续直接持有所有具体组件实现。优先使用
adapter crate：

```text
cyfs-gateway-module-dns     -> cyfs-gateway-app-lib + cyfs-dns
cyfs-gateway-module-socks   -> cyfs-gateway-app-lib + cyfs-socks
cyfs-gateway-module-tun     -> cyfs-gateway-app-lib + cyfs-tun
cyfs-gateway-module-sn      -> cyfs-gateway-app-lib + cyfs-sn + cyfs-gateway-api
cyfs-gateway-module-traffic -> cyfs-gateway-app-lib + cyfs-traffic
```

核心 TCP/UDP/RTCP/TLS/QUIC、HTTP、dir、cyfs-dir、control server 等只依赖
`cyfs-gateway-lib` 或 app-lib 自身的能力，可以由 `CoreGatewayModule` 留在 app-lib。

如果实现时证明单独 adapter crate 过细，可以合并只会共同安装的模块，但必须满足：

- app-lib 不反向依赖 adapter crate；
- app 通过 Cargo dependency 和 `.install(...)` 显式选择能力；
- concrete parser/factory/context 定义只有一份；
- 不能建立 `app-lib -> component -> app-lib` 循环。

## 5. 阶段 A：统一 Stack Registry

这是后续模块化的第一前置任务，应单独提交和验证。

### A1. Registry 模型

- [x] 在 `cyfs-gateway-app-lib` 新增 `stack_registry.rs`；
- [x] 参考 Server Registry 建立 `GatewayStackRegistryBuilder`、
  `GatewayStackRegistry`、`GatewayStackRegistration`；
- [x] registration 原子包含：
  - protocol key；
  - config parser；
  - runtime factory builder；
  - context builder；
  - registration source/module id；
- [x] factory builder 接收本轮 runtime，因为当前 Stack factory 需要
  `ConnectionManagerRef`，不能在配置解析前盲目构造；
- [x] runtime context 至少包含：
  - `ConnectionManagerRef`；
  - `ServerManagerRef`；
  - `TunnelManager`；
  - `LimiterManagerRef`；
  - `StatManagerRef`；
  - process chains、collections、JS externals；
  - `SelfCertMgrRef`；
- [x] `tcp`、`udp`、`rtcp`、`tls`、`quic`、`tun` 全部转为 registration；
- [x] 未知 protocol 错误包含已注册 protocol 列表；
- [x] duplicate / empty protocol fail-fast，禁止覆盖。

### A2. 接入解析、首次启动和 reload

- [x] `GatewayConfigParser` 同时接收不可变 Server Registry 和 Stack Registry；
- [x] 删除 `register_stack_config_parser(...)`；
- [x] 删除 `GatewayFactory::register_stack_factory(...)`；
- [x] 删除 `gateway.rs::build_stack_context`；
- [x] `GatewayFactory` / `Gateway` 保存同一个 `Arc<GatewayStackRegistry>`；
- [x] 抽取首次启动与 reload 共用的 Stack 创建/prepare helper；
- [x] 保持现有 reload 的 prepare/commit/rollback 事务边界；
- [x] 新 Stack 构建失败时不提交半成品，不提前破坏旧 Stack；
- [x] 保持配置中的 Stack 实例顺序，不按 registry key 排序启动。

### A3. Stack Registry 测试

- [x] duplicate、empty、unknown protocol 测试；
- [x] parser 和 runtime create 使用同一 registration；
- [x] factory/context 使用本轮 runtime，不能捕获上一次 reload 的 manager；
- [x] 默认能力 snapshot 精确覆盖 6 种 protocol；
- [x] reload 成功、prepare 失败回滚、删除 Stack 的回归测试；
- [x] `cyfs_gateway` 与 `web3_gateway` 当前能力清单一致。

阶段 A 完成检查：

```bash
rg -n "register_stack_config_parser|register_stack_factory|build_stack_context" src/apps
```

生产代码应无匹配。

## 6. 阶段 B：建立 Composition 与静态模块接口

### B1. Composition builder

- [x] 新增 `GatewayCompositionBuilder` 和不可变 `GatewayComposition`；
- [x] composition 同时拥有 Server/Stack Registry；
- [x] 实现 `install<M: GatewayModule>(...)` 或等价显式接口；
- [x] 记录 module id 与 registration source；
- [x] 提供稳定排序的 capability manifest，用于日志和测试；
- [x] 先实现 `CoreGatewayModule`，注册所有确定属于公共核心的能力；
- [x] 用 composition 替换 `build_default_gateway_server_registry()` 作为生产入口；
- [x] 旧 default helper 可在迁移期间作为测试兼容包装，但最终生产代码不得依赖
  “默认全部安装”的隐式入口。

### B2. ACME provider registration

当前 `GatewayFactory::create_gateway` 每次创建时调用进程级
`AcmeCertManager::register_dns_provider_factory("sn-dns", ...)`。模块化后应改为：

- [x] module 在 composition 中声明 ACME provider factory；
- [x] composition build 时校验 provider name 重复；
- [x] host 在第一次创建 `AcmeCertManager` 前统一应用 provider registrations；
- [x] reload 不重复、无校验地覆盖进程级 provider factory；
- [x] 测试构建 composition 时不要因为全局注册残留而互相污染；
- [x] `local` provider 仍按每一轮 runtime 的 `InnerDnsRecordManager` 注册到具体
  `AcmeCertManager` 实例，不错误提升为全局共享对象。

### B3. Runtime services

Server/Stack module 的 runtime 对象必须引用本轮构建的服务。为移除 app-lib 对可选组件
的具体依赖，需要为模块私有运行态提供明确机制：

- [x] 优先使用 module-owned runtime state 或最小 typed capability map；
- [x] typed capability 必须按 Rust 类型安全获取，缺失时返回包含 module id 的错误；
- [x] capability map 在本轮 runtime build 完成后不可变；
- [x] 不使用任意字符串 + `serde_json::Value` 充当服务定位器；
- [x] DNS 模块创建并共享本轮 `InnerDnsRecordManager`，供 DNS context 和本轮 local
  ACME provider 使用；
- [x] reload 不复用已经属于旧 manager 的 module runtime state。

不要一次性设计远超当前需求的通用 IoC 容器。只实现 DNS、ACME 和后续模块实际需要的
最小接口。

## 7. 阶段 C：抽取静态模块

### C1. CoreGatewayModule

- [x] 将以下公共 Stack registration 归入 core：`tcp`、`udp`、`rtcp`、`tls`、`quic`；
- [x] 将以下公共 Server registration 归入 core：`http`、`dir`、`cyfs-dir`、
  `control_server`、`acme_response`；
- [x] core 不自动安装 `dns`、`local_dns`、`socks`、`sn`、`tun`；
- [x] `WelcomeServer` 仍作为宿主内部 fallback Server，由公共生命周期创建，不伪装成
  配置驱动 Server registration。

### C2. 可选模块 adapter

- [x] `DnsGatewayModule`：`dns`、`local_dns`、对应 parser/factory/context 和
  `InnerDnsRecordManager` 生命周期；
- [x] `SocksGatewayModule`：`socks` parser/factory/context；
- [x] `TunGatewayModule`：`tun` parser/factory/context；
- [x] `SnGatewayModule`：`sn` parser/factory，并提供 SN ACME DNS provider；
- [x] `TrafficGatewayModule`：traffic config、limiter factory、quota service 的
  create/reload/shutdown；
- [x] 每个 module 至少有 capability snapshot 和最小构建测试；
- [x] 缺少某模块时，其配置应在 parse 阶段明确失败，而不是链接错误或运行时 panic。

### C3. 收敛 config parser 归属

当前 `cyfs-gateway-app-lib/src/config_parser.rs` 直接包含 DNS、SOCKS、TUN 等具体 parser。
抽取时：

- [x] core parser 保留在 app-lib；
- [x] `DnsServerConfigParser` / `LocalDnsConfigParser` 移入 DNS adapter；
- [x] `SocksServerConfigParser` 移入 SOCKS adapter；
- [x] `TunStackConfigParser` 移入 TUN adapter；
- [x] `SNServerConfigParser` 移入 SN adapter；
- [x] hook point map/vector 等通用转换 helper 保留在 app-lib，并按最小范围公开；
- [x] 不复制通用 parser helper 到多个 adapter crate。

### C4. 收敛 app-lib 依赖

- [x] concrete registration 移出后，清理 app-lib 不再需要的 `cyfs-dns`、`cyfs-sn`、
  `cyfs-socks`、`cyfs-tun` 直接依赖；
- [x] 用 `cargo tree -p cyfs-gateway-app-lib` 检查依赖方向；
- [x] app-lib 不得依赖任何 `cyfs-gateway-module-*` adapter；
- [x] 两个二进制只通过自己声明的 adapter dependencies 获得可选能力。

## 8. 阶段 D：收敛 SN ACME provider

两份 `acme_sn_provider.rs` 不能原样保留为两个插件。当前 `cyfs_gateway` 版本已经使用
`generate_sn_device_token`、device key DID、zone-scoped DID 和精确 TXT value 删除；
`web3_gateway` 版本仍使用旧 RPC token，并存在 remove 参数/错误文案漂移。

本 TODO 的默认决策：以当前 `cyfs_gateway` 的设备认证实现作为安全基线，抽成一份共享
`SnAcmeDnsModule`，两个 app 都使用它。`web3-gateway` 配置已经提供
`device_config_path`，不得为了保留旧代码而继续生成普通用户 RPC token。

- [x] 将实现移入 SN module adapter 或独立 `cyfs-gateway-module-acme-sn`；
- [x] 两个 app 删除本地 `acme_sn_provider.rs`；
- [x] 保留 private key 与 device document authentication key 一致性检查；
- [x] 保留短期 `sn-device` token；
- [x] 保留 `record` 精确删除和正确的 remove 错误上下文；
- [x] `access_token` 仅作为现有人工/调试兼容路径，不作为默认无人值守认证；
- [x] 为 Web3 配置补充真实 provider create 测试，证明现有
  `sn_private_key.pem + sn_device_config.json` 输入可用；
- [x] 保留或迁移现有 ACME lifecycle/smoke 测试。

只有出现明确产品需求和独立协议测试证明 Web3 必须使用另一种认证协议时，才允许拆成
两个有明确名称的 provider module；不得把当前历史漂移直接视为产品差异。

## 9. 阶段 E：迁移公共 Gateway 宿主

### E1. 配置模型与加载

- [x] 将两份完全相同的 `config_loader.rs` 移入 `cyfs-gateway-app-lib`；
- [x] `GatewayConfigParser` 由 `GatewayComposition` 提供 Server/Stack registries；
- [x] 保持 includes、params、路径归一化、saved config patch 和 control config 合并行为；
- [x] `TrafficConfig` 若已模块化，从 `GatewayConfig` 固定字段迁入 typed module config；
- [x] 模块 config 的初次 parse 与 reload parse 使用同一 parser/registration；
- [x] 删除两个 app 中的 `config_loader.rs`。

### E2. Gateway runtime

- [x] 将两份完全相同的 `gateway.rs` 移入 `cyfs-gateway-app-lib`；
- [x] 将 `GatewayFactory` 改为接收 `GatewayAppProfile + GatewayComposition`；
- [x] ACME provider、Server、Stack 和 module lifecycle 均来自 composition；
- [x] 初次启动和 reload 继续共享构建 helper；
- [x] 保持 Server/Stack reload 的事务和回滚语义；
- [x] 保持 control API、saved config、timer、collection、token 和 tunnel 行为；
- [x] 删除两个 app 中的 `gateway.rs`。

### E3. CLI 与服务入口

- [x] 将两份 `lib.rs` 中的公共 CLI command 定义、local tools、template、debug、login、
  control client dispatch 和 service startup 移入 app-lib；
- [x] 所有应用显示名、日志名、数据目录、配置名、token audience、模板 namespace 从
  `GatewayAppProfile` 获取；
- [x] `run_debug_command` 当前在 app-lib 内硬编码 `cyfs_gateway` 默认配置和 cache 目录，
  改为接收 profile/path provider；
- [x] CLI help、subcommand、参数名和退出码保持兼容；
- [x] app 的 `src/lib.rs` 只负责构造 profile/composition，并按需 re-export 公共测试 API；
- [x] app 的 `src/main.rs` 只调用 `app()?.run().await` 或等价入口；
- [x] 不再保留 `cyfs_gateway_main` / `web3_gateway_main` 两份完整实现。

## 10. 阶段 F：测试、构建与依赖收尾

### F1. 测试去重

- [x] 把两个 app 中相同的 Gateway 行为测试迁到 app-lib 或公共 test support；
- [x] 公共测试通过传入 profile/composition 运行，不通过复制文件运行；
- [x] 每个二进制保留 profile capability snapshot 和最小启动 smoke；
- [x] Web3 专属配置解析、SN/BNS 部署测试保留在 Web3 侧；
- [x] CYFS 专属 `e2e_sn_seed` 等测试保留在 CYFS 侧；
- [x] 修复共享测试时不再需要在两个近似文件中重复改动。

### F2. Cargo manifest 与 build script

- [x] 删除两个 app 已经由 app-lib 或 module adapter 间接提供、且源码不再直接使用的
  dependencies；
- [x] 不依赖 Cargo 的偶然 transitive dependency 编译，直接使用的 crate 必须直接声明；
- [x] 两份 Windows stack-size `build.rs` 改为共享 helper，使用 `CARGO_PKG_NAME` 生成
  bin link arg，或采用其它不复制实现的等价方式；
- [x] 更新 workspace members，确保所有 module adapter 纳入 CI；
- [x] 分别检查两个二进制的 `cargo tree`，确认模块依赖与 profile 清单一致。

### F3. 文档更新

- [x] 更新 `doc/ndn_server_usage.md` 的 registration 入口；
- [x] 更新 `doc/skills/cyfs-gateway-config-spec/references/implementation-checked.md`；
- [x] 更新仍指向 app 内 `gateway.rs` / `lib.rs` 的架构文档；
- [x] 文档明确区分“编译安装的能力”和“配置启用的实例”；
- [x] 旧 Server Registry TODO 保持完成记录，不删除历史。

## 11. 分阶段提交要求

CodeAgent 应按以下顺序提交，避免形成无法审查的大爆炸改动：

1. **Stack Registry**：只统一 Stack 注册和 reload 路径；
2. **Composition API**：加入 `GatewayModule`、`GatewayAppProfile` 和 capability manifest；
3. **Module adapters**：移动 concrete registrations/parser，不迁移 CLI；
4. **SN ACME 收敛**：统一 provider 和测试；
5. **Config/Gateway host 迁移**：删除两份 `config_loader.rs`、`gateway.rs`；
6. **CLI/入口迁移**：将两个 app 缩为 profile + module list；
7. **测试/manifest/doc 收尾**：去重并跑完整回归。

每个阶段必须：

- 保持工作区可编译；
- 运行该阶段相关的最小测试；
- 不顺手修改无关业务逻辑；
- 不覆盖或删除工作区中与本任务无关的未提交文件；
- 在提交说明中列出当前完成的 checklist 和尚未开始的下一阶段。

## 12. 验证命令

阶段内优先运行：

```bash
cd src
cargo test -p cyfs-gateway-app-lib -- --test-threads=1
cargo test -p cyfs_gateway -- --test-threads=1
cargo test -p web3_gateway -- --test-threads=1
```

新增 adapter crate 后逐个运行其单元测试。完成阶段 F 后必须运行：

```bash
cd src
cargo build --verbose
cargo test -- --test-threads=1
```

Web dashboard 不属于本任务；除非 Rust 重构改变其 API，否则不要求运行 npm 构建。

## 13. 最终完成标准

全部满足后才可将本 TODO 标记为完成：

- [x] Server Registry 仍是所有 Server parse/create 的唯一入口；
- [x] Stack Registry 是所有 Stack parse/create/reload 的唯一入口；
- [x] Server/Stack/ACME provider/module id 的重复注册全部 fail-fast；
- [x] 两个二进制通过显式 module list 声明编译能力；
- [x] app-lib 不再隐式注册所有可选模块；
- [x] `src/apps/cyfs_gateway/src/` 和 `src/apps/web3_gateway/src/` 中不再存在复制的
  `gateway.rs`、`config_loader.rs`、`acme_sn_provider.rs`；
- [x] 两个 app 不再包含复制的完整 CLI 实现；
- [x] Gateway 公共宿主实现只有一份；
- [x] AppProfile 显式覆盖所有持久化 namespace 和身份字面量，现有路径保持兼容；
- [x] Web3 不再使用旧的普通 RPC token 作为默认 SN ACME 无人值守认证；
- [x] 公共 Gateway 行为测试只有一份，profile/module 差异由参数化测试表达；
- [x] 未安装模块的配置在 parse 阶段给出可诊断错误；
- [x] `cargo build --verbose` 通过；
- [x] `cargo test -- --test-threads=1` 通过；
- [x] 相关架构和配置能力文档已更新。

最终源码形态应满足：真正的二进制 crate 只维护应用 profile、显式模块清单和极薄入口；
新增或移除一种静态模块时，不需要复制或修改 Gateway 公共宿主。
