# Gateway 统一 Server 注册机制 TODO

## 1. 背景

当前 Gateway 的一种 `server type` 需要在多个位置分别接入：

1. 在 `src/apps/*_gateway/src/lib.rs` 中向 `GatewayConfigParser` 注册 config parser；
2. 在同一文件中向 `GatewayFactory` 注册 `ServerFactory`；
3. 在 `src/apps/*_gateway/src/gateway.rs::build_server_context` 的 `match` 中构造
   `ServerContext`；
4. 首次启动和 reload 分别组装 `ServerManager`，两条路径都要保持一致。

这种注册方式不是一个完整的扩展点。parser、factory、context builder 之间没有结构化
关联，漏注册其中一项只能在配置解析或运行期暴露；注册函数内部使用
`HashMap::insert`，重复的 `server type` 还可能被静默覆盖。

目前 `cyfs_gateway` 与 `web3_gateway` 的以下文件仍然是复制关系：

- `src/apps/cyfs_gateway/src/config_loader.rs`
- `src/apps/web3_gateway/src/config_loader.rs`
- `src/apps/cyfs_gateway/src/gateway.rs`
- `src/apps/web3_gateway/src/gateway.rs`

本 TODO 先实现统一 Server 注册机制，为后续将完整 Gateway 宿主迁入
`cyfs-gateway-app-lib`、以及按二进制选择静态模块建立稳定接口。本轮只处理 Server，
不同时重构 Stack 注册。

## 2. 目标

- [x] 一个 `server type` 通过一次注册同时提供：
  - config parser；
  - runtime factory；
  - context builder。
- [x] parser、factory、context builder 使用同一个不可变注册表作为唯一事实来源。
- [x] 首次启动和 reload 使用同一个 Server 创建入口。
- [x] 重复注册、空 `server type`、未知 `server type` 都返回明确错误，禁止静默覆盖。
- [x] 注册表可以由未来的静态 `GatewayModule` 显式安装 Server，不依赖动态库、
  `inventory`、`ctor` 或其它隐式全局注册。
- [x] 保持现有配置格式和 `server type` 名称不变。
- [x] `cyfs_gateway` 和 `web3_gateway` 的 Server 能力保持一致，除非应用 profile 后续
  明确选择不同模块。

## 3. 非目标

本轮不要求：

- 统一 Stack 注册；
- 完成所有 `gateway.rs` / CLI 代码的公共库迁移；
- 引入运行时动态插件或稳定 ABI；
- 重新设计现有 `ServerConfig`、`ServerFactory`、`ServerContext` trait；
- 改变 YAML/JSON 配置格式；
- 把 `WelcomeServer`、timer、traffic、ACME provider 等非配置驱动能力强行建模为
  Server；
- 通过 Cargo feature 自动注册模块。

## 4. 当前 Server 清单

实现和测试必须覆盖当前正式注册的全部类型：

| server type | config parser | runtime factory | context |
| --- | --- | --- | --- |
| `http` | `HttpServerConfigParser` | `ProcessChainHttpServerFactory` | `HttpServerContext` |
| `socks` | `SocksServerConfigParser` | `SocksServerFactory` | `SocksServerContext` |
| `dns` | `DnsServerConfigParser` | `ProcessChainDnsServerFactory` | `DnsServerContext` |
| `dir` | `DirServerConfigParser` | `DirServerFactory` | `None` |
| `cyfs-dir` | `CyfsDirServerConfigParser` | `CyfsDirServerFactory` | `CyfsDirServerContext` |
| `control_server` | `GatewayControlServerConfigParser` | `GatewayControlServerFactory` | `GatewayControlServerContext` |
| `local_dns` | `LocalDnsConfigParser` | `LocalDnsFactory` | `LocalDnsServerContext` |
| `sn` | `SNServerConfigParser` | `SnServerFactory` | `None` |
| `acme_response` | `AcmeHttpChallengeServerConfigParser` | `AcmeHttpChallengeServerFactory` | `AcmeHttpChallengeServerContext` |

`dir` 和 `sn` 的 `None` context 是明确能力，不应被解释为漏注册。统一描述符必须显式
表达“该 Server 不需要 context”。

## 5. 建议设计

### 5.1 注册描述符

在 `cyfs-gateway-app-lib` 中新增 `server_registry` 模块。建议的概念接口如下，最终命名
可以按现有代码风格调整：

```rust
pub type JsonServerConfigParser = dyn ServerConfigParser<serde_json::Value>;

pub trait GatewayServerContextBuilder: Send + Sync {
    fn build(
        &self,
        runtime: &GatewayServerRuntime,
    ) -> ServerResult<Option<ServerContextRef>>;
}

pub struct GatewayServerRegistration {
    server_type: String,
    config_parser: Arc<JsonServerConfigParser>,
    server_factory: Arc<dyn ServerFactory>,
    context_builder: Arc<dyn GatewayServerContextBuilder>,
}
```

为闭包提供 blanket implementation，使简单 Server 不需要声明额外类型：

```rust
impl<F> GatewayServerContextBuilder for F
where
    F: Fn(&GatewayServerRuntime) -> ServerResult<Option<ServerContextRef>>
        + Send
        + Sync,
{
    // ...
}
```

即使 Server 不需要 context，也必须注册一个显式返回 `Ok(None)` 的 builder。这样
“无 context”和“漏了 context 注册”不会混在一起。

### 5.2 Build-time builder 与不可变 registry

静态模块只应在应用构建阶段注册。建议区分可变 builder 和运行期不可变 registry：

```rust
pub struct GatewayServerRegistryBuilder {
    registrations: HashMap<String, GatewayServerRegistration>,
}

pub struct GatewayServerRegistry {
    registrations: HashMap<String, Arc<GatewayServerRegistration>>,
}
```

- [x] `register(...) -> Result<()>` 使用 `&mut self`，发现重复 key 立即失败；
- [x] `build()` 完成校验并冻结注册表；
- [x] 运行期只通过 `Arc<GatewayServerRegistry>` 共享，不允许继续修改；
- [x] 错误信息包含冲突的 `server type`；如注册项携带模块名，还应同时显示两个来源；
- [x] 提供排序后的 `registered_server_types()`，用于诊断日志和未知类型错误。

不要以 Cargo feature 是否打开作为运行期注册事实；最终编译进入哪个二进制，由该
二进制显式安装了哪些 module/registration 决定。

### 5.3 Runtime context

用一个结构体代替当前 `build_server_context` 的长参数列表：

```rust
pub struct GatewayServerRuntime {
    pub server_manager: ServerManagerWeakRef,
    pub global_process_chains: GlobalProcessChainsRef,
    pub js_externals: JsExternalsManagerRef,
    pub tunnel_manager: TunnelManager,
    pub global_collection_manager: GlobalCollectionManagerRef,
    pub acme_manager: AcmeCertManagerRef,
    pub inner_dns_record_manager: InnerDnsRecordManagerRef,
    pub control_handler: Weak<dyn GatewayControlCmdHandler>,
    pub control_token_verifier: Arc<dyn CyfsTokenVerifier>,
    pub control_token_factory: Arc<dyn CyfsTokenFactory>,
}
```

第一阶段可以先承载当前已有依赖，但需要遵守：

- [x] context builder 只能读取 runtime context，不在其中修改注册表；
- [x] 每次首次启动或 reload 都根据本轮新建的 manager/service 构造新的 runtime；
- [x] 不允许 context builder 捕获上一轮 reload 的 manager 引用；
- [x] 后续抽取可选模块时，再把 DNS 等模块私有依赖迁到 typed capabilities 或模块
  自己的 runtime state；本轮不要为了未来扩展一次性引入通用 service locator。

### 5.4 统一解析入口

`GatewayConfigParser` 不再持有一个独立、可单独注册的
`CyfsServerConfigParser<serde_json::Value>`。它应持有同一个
`Arc<GatewayServerRegistry>`，并调用：

```rust
registry.parse_server_config(server_value)
```

解析流程：

1. 从原始值读取 `type`；
2. 在 registry 中查找完整 registration；
3. 调用该 registration 的 config parser；
4. 未找到时返回 `ConfigErrorCode::InvalidConfig`，错误中包含未知 type 和已编译的
   Server 类型列表。

保持当前 type 比较规则，不在本轮增加大小写折叠、别名或自动规范化。

### 5.5 统一创建入口

registry 提供唯一运行期创建入口：

```rust
pub async fn create_servers(
    &self,
    config: Arc<dyn ServerConfig>,
    runtime: &GatewayServerRuntime,
) -> ServerResult<Vec<Server>>;
```

内部步骤固定为：

1. 使用 `config.server_type()` 找 registration；
2. 使用 registration 的 context builder 创建 `Option<ServerContextRef>`；
3. 使用同一 registration 的 factory 创建 Server；
4. 返回创建结果，由调用者加入 `ServerManager`。

完成后删除应用层的 `build_server_context()` 大 `match`，Gateway 不再分别持有
`CyfsServerFactoryRef` 和 Server config parser registry。

底层 `cyfs-gateway-lib` 中的 `CyfsServerFactory` / `CyfsServerConfigParser` 如果仍有其它
调用者，可以保留；本轮不需要为了清理名字而扩大改动范围。

### 5.6 首次启动与 reload 共用

抽取一个内部 helper，首次创建与 reload 都调用它：

```rust
async fn build_server_manager(
    registry: &GatewayServerRegistry,
    configs: &[Arc<dyn ServerConfig>],
    runtime_inputs: GatewayServerRuntimeInputs,
) -> Result<ServerManagerRef>;
```

helper 负责：

- 创建新的 `ServerManager`；
- 基于该 manager 和本轮 service 构造 `GatewayServerRuntime`；
- 逐项调用 `registry.create_servers(...)`；
- 加入所有创建出的 Server；
- 保持现有 `WelcomeServer` 添加行为；
- 任一 Server 失败时返回错误，不把半成品 manager 提交到运行态。

reload 的 prepare/commit/rollback 行为必须保持现状。统一 helper 不能让旧 Server 在新
配置完全构建成功前被提前停止或替换。

## 6. 实施步骤

### A. 建立 registry 基础设施

- [x] 新增 `src/components/cyfs-gateway-app-lib/src/server_registry.rs`；
- [x] 从 `cyfs-gateway-app-lib/src/lib.rs` 导出必要的 builder/registry/registration 类型；
- [x] 实现重复注册、空 type、未知 type 的结构化错误；
- [x] 实现 closure 形式的 context builder；
- [x] registry build 后不可变。

### B. 接入配置解析

- [x] 让 `GatewayConfigParser::new(...)` 接收 `Arc<GatewayServerRegistry>`；
- [x] 删除应用层单独的 `register_server_config_parser(...)` 路径；
- [x] 所有 Server config 只通过统一 registry 解析；
- [x] 保持 Stack parser 注册机制暂时不变；
- [x] 两个 app 的现有 YAML/JSON 配置解析结果保持一致。

### C. 接入运行期创建

- [x] 将当前 9 种 Server 转为完整 registration；
- [x] 删除 `GatewayFactory::register_server_factory(...)`；
- [x] 删除应用层 `build_server_context()`；
- [x] `GatewayFactory` 和 `Gateway` 保存同一个 `Arc<GatewayServerRegistry>`；
- [x] 首次启动和 reload 只调用 registry 的创建入口；
- [x] 启动日志输出排序后的已注册 Server 类型列表。

### D. 两个二进制对齐

- [x] `cyfs_gateway` 和 `web3_gateway` 使用相同 registration helper 或相同静态模块清单；
- [x] 禁止在两个 app 中复制一份新的 `register_all_servers()`；
- [x] `sn` 已迁入公共 helper，不需要应用侧 registration adapter；
- [x] 后续静态模块重构可以直接包装现有 registration，不再修改 registry 核心。

### E. 清理旧入口

- [x] `rg "register_server_config_parser|register_server_factory|build_server_context" src/apps`
  不再匹配生产代码；
- [x] 检查 `CyfsServerFactory` 和 `CyfsServerConfigParser` 的剩余调用者后再决定是否删除，
  不做未经确认的全局清理；
- [x] 更新引用旧注册位置的文档，例如 `doc/ndn_server_usage.md` 和
  `doc/skills/cyfs-gateway-config-spec/references/implementation-checked.md`。

## 7. 测试要求

### 7.1 Registry 单元测试

- [x] 注册完整 descriptor 后，可以通过同一 type 完成 parse 和 create；
- [x] 重复注册返回错误，旧 registration 不被覆盖；
- [x] 空字符串或纯空白 type 注册失败；
- [x] 未知 type 的解析错误包含未知值和已注册类型列表；
- [x] contextless Server 的 builder 明确返回 `None`，factory 能正常收到 `None`；
- [x] contextful Server 收到本轮 `GatewayServerRuntime` 构造出的 context；
- [x] build 后 registry 不再暴露 mutation API；
- [x] `registered_server_types()` 输出稳定排序，避免日志和 snapshot 测试抖动。

### 7.2 能力清单测试

- [x] 对当前 9 种 Server 做 capability snapshot；
- [x] snapshot 同时验证 parser、factory、context builder 都存在；
- [x] `cyfs_gateway` 与 `web3_gateway` 的预期能力清单一致；
- [x] 将来 profile 有意裁剪模块时，差异必须在测试中显式声明。

### 7.3 配置与生命周期回归

- [x] 现有 `test_cyfs_gateway.yaml` 能通过真实加载和解析链路；
- [x] `web3_gateway.yaml`、`web3_dns.yaml`、`web3_relay.yaml`、`web3_sn_api.yaml`
  能通过真实加载和解析链路；
- [x] control server 测试通过；
- [x] 至少一个测试验证 reload 使用 registry 创建新 Server，而不是走遗留 match；
- [x] reload 创建某个 Server 失败时，旧运行态保持可用；
- [x] 使用 `--test-threads=1` 运行共享端口/状态相关测试。

建议验证命令：

```bash
cd src
cargo test -p cyfs-gateway-app-lib -- --test-threads=1
cargo test -p cyfs_gateway -- --test-threads=1
cargo test -p web3_gateway -- --test-threads=1
```

实现完成后再执行工作区级回归：

```bash
cd src
cargo test -- --test-threads=1
```

## 8. 兼容性与风险

### 8.1 注册顺序

当前 HashMap 本身没有稳定顺序。新机制不能让 Server 的启动顺序意外改为按 type 排序；
Server 实例仍应按配置中的既有顺序创建。排序只用于能力列表和诊断输出。

### 8.2 重复注册

当前行为可能静默覆盖。改为 fail-fast 是有意的行为收紧；错误必须在应用 build/start
早期出现，而不是处理业务请求时才出现。

### 8.3 Context 生命周期

reload 会创建新的 manager、process chains、collections、ACME manager 等对象。context
builder 必须使用本轮 runtime，不能把首次启动的对象捕获到 `'static` closure 中。

### 8.4 错误类型边界

- 配置 type 未知或 config parser 失败：`ConfigResult`；
- context/factory 创建失败：`ServerResult`；
- Gateway 生命周期包装错误：在边界转换为 `anyhow::Result` 并添加上下文。

不要把所有错误提前抹平成字符串。

### 8.5 避免扩大重构

本轮允许底层旧 registry 类型暂时存在，也允许 Stack 保持原注册方式。不要在同一改动中
顺便重排 CLI、token、ACME、traffic 或目录结构；先让统一 Server 注册机制经过完整回归。

## 9. 完成标准

以下条件全部满足才可将本 TODO 标记为完成：

- [x] 每个 Server type 只有一个完整 registration 定义；
- [x] Gateway 配置解析和运行期创建读取同一个 registry；
- [x] 首次启动和 reload 共享 Server 创建实现；
- [x] 生产代码不再包含 `build_server_context()` type match；
- [x] 生产代码不再分别调用 `register_server_config_parser` 和
  `register_server_factory`；
- [x] 重复和未知 type 能在早期得到可诊断错误；
- [x] 当前 9 种 Server 的配置、启动、控制面和 reload 回归通过；
- [x] `cyfs_gateway` 与 `web3_gateway` 没有新增注册代码复制；
- [x] 相关文档已更新到 registry/registration 的新入口。

## 10. 完成记录

已于 2026-07-20 完成：

- 统一入口位于 `cyfs-gateway-app-lib/src/server_registry.rs`，默认 registry 显式注册全部
  9 种 Server；
- `cyfs_gateway` 与 `web3_gateway` 的解析、首次启动和 reload 共享同一套 registry API；
- registry 单元测试、能力清单、真实配置、control server、reload 成功/失败回滚和 SN/BNS
  集成回归均已覆盖；
- 工作区级 `cargo test -- --test-threads=1` 通过。

## 11. 后续工作

完成本 TODO 后，按相同原则继续：

1. 建立统一 Stack registration；
2. 定义显式 `GatewayModule::install(&mut GatewayRegistryBuilder)`；
3. 抽取 `dns`、`socks`、`tun`、`sn`、`traffic`、ACME provider 等静态模块；
4. 将完整 Gateway 宿主迁入 `cyfs-gateway-app-lib`；
5. 将两个二进制收敛为 `AppProfile + 静态模块列表`。
