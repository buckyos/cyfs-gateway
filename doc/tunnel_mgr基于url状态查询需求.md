# TunnelManager 基于 Tunnel URL 的状态查询技术需求

本文基于 `/Users/liuzhicong/project/buckyos/doc/arch/gateway/服务的多链路选择.md` 的分层设计，并结合当前 `cyfs-gateway` tunnel 框架实现，整理 `tunnel_mgr` 需要新增的基础设施需求。

目标不是在 `TunnelManager` 内部实现应用级调度器，而是让 Gateway 能对上层给定的一组 Tunnel URL 提供可解释的状态查询、测速与排序能力，为应用层多链路调度和 Gateway Selector 提供稳定输入。

相关代码入口：

- `src/components/cyfs-gateway-lib/src/tunnel_mgr.rs`
- `src/components/cyfs-gateway-lib/src/tunnel.rs`
- `src/components/cyfs-gateway-lib/src/rtcp/rtcp.rs`
- `src/components/cyfs-gateway-lib/src/stack/rtcp_stack.rs`
- `src/components/cyfs-gateway-lib/src/ip/tunnel.rs`
- `src/components/cyfs-gateway-lib/src/socks/tunnel.rs`
- `src/components/cyfs-gateway-lib/src/tls_tunnel.rs`
- `src/components/cyfs-gateway-lib/src/quic_tunnel.rs`

## 1. 背景

当前 tunnel 框架已经用 URL 统一了建链入口：

- `TunnelManager::get_tunnel(url, ...)` 按 scheme 创建 tunnel；
- `TunnelManager::open_stream_by_url(url)` 先创建 tunnel，再按 path 打开 stream；
- `TunnelManager::create_datagram_client_by_url(url)` 先创建 tunnel，再按 path 创建 datagram client；
- RTCP/RUDP 由 `RtcpStack::start()` 动态注册到 `TunnelManager`，并在内部维护 tunnel map 与 keep tunnel。

但是当前框架缺少一个面向 URL 的状态查询层。上层无法只传入一组 Tunnel URL 并获得统一的可达性、RTT、失败原因和排序结果，只能通过真正打开 stream 或调用协议私有能力间接判断。

多链路选择设计要求 Gateway 提供如下基础能力：

```text
输入：一个或一组 Tunnel URL
输出：每个 Tunnel URL 的可达性、RTT、排序结果、可能的失败原因
```

这个能力应以 Tunnel URL 为对象，而不是只对 IP 地址测速；应尽量复用已有 tunnel 的 ping、keepalive、连接历史和 RTCP 直连尝试结果，而不是每次都强制新建业务连接。

## 2. 当前实现边界

### 2.1 Tunnel trait 只有动作，没有状态模型

`Tunnel` 当前只定义：

- `ping()`
- `open_stream_by_dest(...)`
- `open_stream(...)`
- `create_datagram_client_by_dest(...)`
- `create_datagram_client(...)`

其中 `ping()` 返回 `Result<(), std::io::Error>`，不能表达 RTT、状态来源、失败分类、上次成功时间等信息。`IPTunnel` 和 `SocksTunnel` 的 `ping()` 目前也只是记录未实现日志后返回成功，不可作为真实可达性依据。

### 2.2 TunnelManager 不缓存 URL 状态

`TunnelManager` 当前只保存 scheme 到 `TunnelBuilder` 的映射，不维护：

- URL 规范化后的状态表；
- 最近一次 probe 结果；
- 正在进行中的 probe 任务；
- probe 并发限制；
- 状态 TTL；
- RTT 或失败原因历史。

因此上层每次查询都无法得到稳定、可复用的结果。

### 2.3 RTCP 有运行态，但没有统一暴露

RTCP 当前已经有一些状态基础：

- `RTcpInner::create_tunnel()` 会按本端 DID、远端 DID 和 bootstrap URL 生成 tunnel key 并复用已有 tunnel；
- direct 连接会对候选地址做 250ms stagger 的并发尝试；
- direct attempt 会记录连接结果和应用层 RTT；
- `RTcpTunnelMap` 保存运行中的 `RTcpTunnel`；
- `RtcpStack::start_keep_tunnel()` 会定期 `get_tunnel()` 并 `ping()`。

这些状态目前都留在 RTCP 内部或日志/私有记录中，`TunnelManager` 无法按原始 Tunnel URL 查询到“这个 URL 是否已有 tunnel、最近 RTT 是多少、上次失败原因是什么”。

### 2.4 URL 语义是协议相关的

Tunnel URL 的外形统一，但 authority/path 语义仍由协议解释：

- `rtcp://remote.dev.did/:80` 的 authority 是远端设备，path 是远端服务；
- `tcp:///127.0.0.1:9000` 的 path 是本地目标；
- `socks://user:pass@127.0.0.1:1080/google.com:443` 的 authority 是 SOCKS 代理，path 是目标；
- 嵌套 URL 需要 percent-encoding。

状态查询层必须尊重协议差异，不能假设所有 scheme 的 authority/path 有相同含义。

## 3. 目标

### 3.1 对上层提供统一查询能力

`TunnelManager` 必须新增按 URL 查询状态的统一入口：

- 查询单个 Tunnel URL 的状态；
- 批量查询多个 Tunnel URL 的状态；
- 批量结果可按可达性、RTT、稳定性、调用方给定优先级排序；
- 结果必须包含失败原因，便于诊断“不走直连”“为什么走中转”等问题。

### 3.2 支持复用已有状态

状态查询不应等价于“每次新建连接”。当协议已有运行态时，应优先复用：

- 已存在 tunnel 的最新 ping/keepalive 结果；
- 最近一次 probe 的缓存结果；
- RTCP direct attempt 的连接 RTT；
- RTCP tunnel 运行状态；
- keep_tunnel 的最近成功/失败记录。

当缓存过期或调用方要求强制探测时，才触发新的 probe。

### 3.3 支持显式 URL 集合，不做隐式路径扩散

Gateway 只对调用方传入或配置中允许的 URL 集合做状态查询与排序。若 URL 中没有明确包含中转路径，`TunnelManager` 不应自行扩展到某个 relay 或其它隐式路径。

这条约束是排障可解释性的核心：如果上一次调度结果里没有 relay URL，则运行时不应意外走 relay；如果调度结果里没有 direct URL，则不走直连也是正确行为。

### 3.4 为 Selector 和应用调度器提供基础数据

新增能力服务于两类上层：

- Gateway 内部 Selector：对已配置的一组 URL 做稳定选择和 failover；
- 应用层调度器：周期性生产 URL 集合，调用 Gateway 查询状态，结合业务成本和可靠性要求刷新服务映射。

`TunnelManager` 不承担应用业务调度职责，不自动发现所有可能 URL。

## 4. 非目标

本需求不要求：

- 在 `TunnelManager` 中实现设备发现、DeviceInfo 搜索或 relay 自动发现；
- 让 Selector 隐式生产新的 Tunnel URL；
- 暴露 Gateway 内部已知的全部底层 URL 列表给任意上层；
- 把所有协议的 URL authority/path 语义统一成同一种格式；
- 用状态查询替代真正业务 `open_stream` 的最终成功判断；
- 一次性为所有协议实现高精度 RTT，允许按协议分阶段支持。

## 5. 新增核心模型

### 5.1 TunnelUrlStatus

需要新增一个面向上层返回的状态结构，建议字段如下：

```rust
pub struct TunnelUrlStatus {
    pub url: String,
    pub normalized_url: String,
    pub scheme: String,
    pub category: ProtocolCategory,
    pub state: TunnelUrlState,
    pub rtt_ms: Option<u64>,
    pub last_success_at_ms: Option<u64>,
    pub last_failure_at_ms: Option<u64>,
    pub failure_reason: Option<String>,
    pub source: TunnelUrlStatusSource,
    pub cached: bool,
    pub expires_at_ms: Option<u64>,
}
```

状态枚举建议：

```rust
pub enum TunnelUrlState {
    Reachable,
    Unreachable,
    Unknown,
    Probing,
    Unsupported,
}
```

状态来源建议：

```rust
pub enum TunnelUrlStatusSource {
    ExistingTunnel,
    KeepAlive,
    CachedProbe,
    FreshProbe,
    BusinessConnect,
    BuilderValidation,
    Unsupported,
}
```

说明：

- `Unknown` 表示还没有足够信息，不等同于不可达；
- `Unsupported` 表示对应协议尚未实现有效 probe；
- `BusinessConnect` 表示状态来自真实业务建链或业务流失败/成功的回写，必须与主动 probe、keepalive 区分，便于排障判断“实流信号”和“探测信号”的差异；
- `cached` 和 `expires_at_ms` 用来让上层判断结果新鲜度；
- `failure_reason` 应保留协议层原始错误摘要，但不能泄露敏感认证信息。

### 5.2 TunnelProbeOptions

查询入口需要支持调用方控制成本：

```rust
pub struct TunnelProbeOptions {
    pub force_probe: bool,
    pub max_age_ms: Option<u64>,
    pub timeout_ms: Option<u64>,
    pub sort: TunnelUrlSortPolicy,
    pub include_unsupported: bool,
}
```

排序策略建议：

```rust
pub enum TunnelUrlSortPolicy {
    None,
    ReachableFirst,
    RttAscending,
    CallerPriorityThenRtt,
}
```

排序规则必须固定，避免 Selector 对 `Unknown`、`Unsupported` 产生相反解释：

- `Reachable` 优先于 `Unknown` / `Probing`；
- `Unknown` 和 `Probing` 表示信息不足，应保留调用方原始顺序或 caller priority，不应被当成可达；
- `Unsupported` 和 `Unreachable` 默认沉底，且 `Unreachable` 可排在 `Unsupported` 前面，以便诊断明确失败优先于“不支持探测”；
- `Reachable` 但 `rtt_ms = None` 时，应排在有 RTT 的 `Reachable` 之后、`Unknown` 之前；
- `RttAscending` 只在同 scheme、同 RTT 语义的 URL 之间比较 RTT；跨 scheme 时必须回退到调用方顺序或显式 scheme priority；
- `CallerPriorityThenRtt` 先保留调用方传入的优先级分组，再在同一优先级、同一 scheme 内按 RTT 排序；
- `include_unsupported = false` 时，`Unsupported` 仍应出现在 `statuses` 中用于诊断，但不进入 `sorted_urls`。

RTT 只能作为同口径指标使用。RTCP existing tunnel 的 RTT 可能来自 ping；TCP probe 的 RTT 是 TCP connect 耗时；TLS/QUIC probe 的 RTT 可能包含握手成本。因此默认要求是：RTT 仅在同 scheme 或明确声明同一测量口径的 URL 之间可比，跨协议排序不能直接用裸 `rtt_ms` 得出“更快”的结论。

### 5.3 TunnelUrlHistory

URL 状态的主数据结构应是 `url -> history`，而不是 `url -> tunnel_instance`。

原因：

- tunnel instance 是运行期对象，生命周期可能短于 URL 的调度周期；
- 同一个 URL 可能多次创建、复用、断开、重连不同 tunnel instance；
- 上层真正关心的是“这个 URL 最近是否可用、历史 RTT 和失败原因是什么”，不是某个具体实例对象；
- 状态需要支持可选落盘，落盘内容不能依赖内存里的 trait object 或连接句柄。

建议新增历史结构：

```rust
pub struct TunnelUrlHistory {
    pub normalized_url: String,
    pub scheme: String,
    pub category: ProtocolCategory,
    pub current: TunnelUrlStatus,
    pub last_reachable: Option<TunnelUrlStatus>,
    pub last_unreachable: Option<TunnelUrlStatus>,
    pub recent_rtt_ms: Vec<u64>,
    pub success_count: u64,
    pub failure_count: u64,
    pub updated_at_ms: u64,
    pub persisted_at_ms: Option<u64>,
}
```

说明：

- `TunnelUrlStatus` 是某一次状态观测的快照；
- `TunnelUrlHistory` 是该 URL 的长期状态记录；
- 运行期可以临时关联 tunnel key 或 instance id 用于快速命中已有 tunnel，但该关联只能作为 history 的派生字段或内存索引，不能成为状态模型的主结构；
- `ExistingTunnel` 只能表示状态来源，不表示状态绑定到 tunnel instance。

### 5.4 TunnelProbeResult

批量查询结果应保留原始顺序和排序结果：

```rust
pub struct TunnelProbeResult {
    pub statuses: Vec<TunnelUrlStatus>,
    pub sorted_urls: Vec<String>,
}
```

这样上层既能做诊断展示，也能直接取得排序后的候选 URL。

## 6. TunnelManager 必须新增的接口

### 6.1 单 URL 查询

建议新增：

```rust
impl TunnelManager {
    pub async fn query_tunnel_url_status(
        &self,
        url: &Url,
        options: TunnelProbeOptions,
    ) -> TunnelResult<TunnelUrlStatus>;
}
```

行为要求：

- 先规范化 URL；
- 查询 URL history 中的当前状态；
- 若 history 中的当前状态满足 `max_age_ms` 且 `force_probe == false`，直接返回；
- 否则找到对应 scheme 的 builder/prober；
- 在超时控制内执行 probe；
- 记录并返回结果。

### 6.2 批量查询与排序

建议新增：

```rust
impl TunnelManager {
    pub async fn query_tunnel_url_statuses(
        &self,
        urls: &[Url],
        options: TunnelProbeOptions,
    ) -> TunnelResult<TunnelProbeResult>;
}
```

行为要求：

- 对每个 URL 独立返回状态，不能因为单个 URL 失败导致整个批量查询失败；
- URL 解析失败应形成该 URL 的 `Unreachable` 或 `Unsupported` 结果，并带失败原因；
- 批量 probe 必须有并发上限，避免上层一次传入大量 URL 打爆网络；
- 排序只在返回结果中体现，不改变 URL history 里的原始记录。

### 6.3 状态失效与清理

建议新增：

```rust
impl TunnelManager {
    pub async fn invalidate_tunnel_url_status(&self, url: &Url);
    pub async fn clear_tunnel_url_status_cache(&self);
}
```

用途：

- 配置变更后主动失效；
- 权限变更后清理旧状态；
- 测试中重置状态。

## 7. TunnelBuilder/Tunnel 需要扩展的能力

### 7.1 新增协议级 prober 抽象

不建议直接把高阶状态查询塞进现有 `Tunnel::ping()`。现有 `ping()` 语义太弱，且部分 tunnel 的 `ping()` 当前是假成功。

建议新增独立 trait：

```rust
#[async_trait]
pub trait TunnelUrlProber: Send + Sync {
    async fn probe_url(
        &self,
        url: &Url,
        options: &TunnelProbeOptions,
    ) -> TunnelResult<TunnelUrlStatus>;
}
```

`TunnelBuilder` 可以可选实现或返回一个 prober：

```rust
#[async_trait]
pub trait TunnelBuilder: Send + Sync + 'static {
    async fn create_tunnel(
        &self,
        tunnel_stack_id: Option<&str>,
    ) -> TunnelResult<Box<dyn TunnelBox>>;

    fn url_prober(&self) -> Option<Arc<dyn TunnelUrlProber>> {
        None
    }
}
```

这样已有协议不需要一次性全部修改；未实现 prober 的 scheme 返回 `Unsupported` 或只做 builder validation。

### 7.2 probe 不能破坏业务 tunnel

协议级 prober 必须满足：

- 查询已有状态时不影响正在承载业务的 stream/datagram；
- force probe 的具体动作由协议决定，但不得替换已有健康 tunnel；
- probe 失败不能关闭已有 tunnel；
- probe 产生的新状态必须标记来源和时间。

force probe 的协议语义必须明确：

- RTCP/RUDP 这类按设备对复用 tunnel 的协议：如果已有 tunnel，force probe 应在已有 tunnel 上发送 ping 或等价控制包测 RTT，不新建第二条同 key tunnel；
- RTCP/RUDP 如果没有已有 tunnel，force probe 可以触发一次建链尝试，但成功后按正常 tunnel 复用规则进入 tunnel map；
- tcp/tls/quic/socks 这类连接器协议：force probe 可以创建临时连接，探测完成后立即关闭；
- udp 这类无通用可达性语义的协议：没有专用 probe 时，即使 force probe 也只能返回 `Unsupported`。

### 7.3 ping 语义需要逐步收敛

长期看，`Tunnel::ping()` 应返回 RTT 或底层状态，但短期不强制修改现有 trait，以避免大范围破坏。第一阶段可由 prober 在内部测量 `ping().await` 耗时，并把 `IPTunnel`、`SocksTunnel` 这类未实现 ping 的协议标记为 `Unsupported`，避免假成功污染排序。

## 8. 状态历史与缓存需求

`TunnelManager` 需要新增共享状态。主状态表必须是 URL 历史表：

```rust
pub struct TunnelManager {
    tunnel_builder_manager: Arc<Mutex<HashMap<String, Arc<dyn TunnelBuilder>>>>,
    tunnel_history: Arc<tokio::sync::RwLock<HashMap<String, TunnelUrlHistory>>>,
    in_flight_probes: Arc<tokio::sync::Mutex<HashMap<String, SharedProbeHandle>>>,
    runtime_tunnel_index: Arc<tokio::sync::RwLock<HashMap<String, RuntimeTunnelRef>>>,
    probe_limiter: Arc<tokio::sync::Semaphore>,
}
```

其中：

- `tunnel_history` 是 `normalized_url -> TunnelUrlHistory`，是查询、排序、落盘的主数据；
- `in_flight_probes` 是 `normalized_url -> probe task`，用于合并同一 URL 的并发 probe；
- `runtime_tunnel_index` 只是可选的内存加速索引，用于从 normalized URL 或协议私有 tunnel key 快速找到当前已有 tunnel；
- `runtime_tunnel_index` 不落盘，进程重启后可为空；
- 若一个 tunnel instance 关闭，只应更新对应 URL 的 history，不应删除 URL 历史。

规范化 key 使用：

```text
scheme + authority + normalized path + normalized query
```

要求：

- scheme 和 hostname 必须小写；
- DID/域名类 authority 按大小写不敏感处理，保留原始 URL 只用于展示；
- IPv6 字面量必须统一为带方括号 authority 形式；
- 默认端口是否省略必须按 scheme 明确定义，未定义默认端口的 scheme 不做端口折叠；
- path 需要规范化空 path 与 `/` 的关系：对 tunnel URL，空 path 与 `/` 不能随意合并，必须遵守各 scheme 的 target 语义；
- query 参数顺序必须排序后进入 key；同名多值参数保持值列表顺序或按字节序排序，但实现必须固定；
- 不把 fragment 纳入状态 key；
- 对 path 中的 percent-encoding 保持可逆，不能破坏嵌套 URL；
- 认证信息进入日志前必须脱敏；
- 缓存 TTL 默认可配置，初始建议 `reachable_ttl = 30s`、`unknown_ttl = 10s`、`unreachable_ttl = 5s`、`unsupported_ttl = 60s`；
- 同一个 URL 的并发 probe 应尽量合并，避免重复探测；
- 每次 probe、keepalive 或业务建链结果都应追加/合并到 `TunnelUrlHistory`，再从 history 生成当前 `TunnelUrlStatus`。

内存 history 必须有上限，不能只限制落盘条数。建议：

- `max_memory_history_entries` 默认 10000，可配置；
- 超过上限时按 `updated_at_ms` 做 LRU 淘汰；
- 正在 probe 的 URL、最近被 Selector 使用的 URL、配置中固定声明的 URL 可标记为 pinned，pinned 记录不参与普通淘汰；
- 动态 path、session id、临时端口类 URL 必须依赖淘汰策略回收，避免进程级 HashMap 无界增长。

查询与 in-flight 合并顺序必须固定：

1. 命中 URL history 且状态新鲜，直接返回；
2. 存在同一 normalized URL 的 in-flight probe，复用该 probe 结果，不再占用新的 `probe_limiter` 配额；
3. 没有可用 history 且没有 in-flight probe 时，才申请 `probe_limiter` 配额并发起新 probe；
4. 批量查询中，不同 URL 的新 probe 受 `probe_limiter` 限制；复用 in-flight probe 的等待者不计入新 probe 并发；
5. 等待 in-flight probe 超过本次调用 timeout 时，可返回当前 history 的旧状态并标记 `cached = true`，若没有旧状态则返回 `Probing` 或 `Unknown`。

### 8.1 状态落盘需求

URL history 需要支持可选落盘，默认开启。

建议配置项：

```rust
pub struct TunnelStatusStoreConfig {
    pub enable_persist: bool, // 默认 true
    pub persist_path: Option<String>,
    pub flush_interval_ms: u64,
    pub max_history_entries: usize,
    pub max_memory_history_entries: usize,
    pub reachable_ttl_ms: u64,
    pub unknown_ttl_ms: u64,
    pub unreachable_ttl_ms: u64,
    pub unsupported_ttl_ms: u64,
}
```

落盘要求：

- 默认保存 `TunnelUrlHistory`，以便 Gateway 重启后保留最近 RTT、成功率和失败原因；
- 调用方或配置可以关闭落盘，关闭后只保留内存 history；
- 落盘内容只能包含 URL history、统计值、时间戳和脱敏后的失败摘要；
- 不能落盘 tunnel instance、socket、trait object、密钥、token、明文 userinfo 等运行期敏感对象；
- 保存前必须对 URL 中的 userinfo 和敏感 query 参数脱敏或拆分存储；
- 加载历史时状态应标记为 `cached`，并根据 `max_age_ms` 或默认 TTL 决定是否需要 fresh probe；
- 落盘失败不能影响业务建链，只能记录告警并继续使用内存状态。

## 9. RTCP/RUDP 必须提供的状态能力

RTCP 是第一优先级，因为它最接近真实“设备级 tunnel”语义。

### 9.1 按 URL 定位 tunnel key

RTCP prober 必须复用 `RTcpInner::create_tunnel()` 当前的 tunnel key 规则：

- direct tunnel：`{local_did}_{remote_did}`；
- bootstrap tunnel：`{local_did}_{remote_did}|bootstrap={bootstrap_url}`。

同一个输入 URL 在 `create_tunnel()` 和 `query_tunnel_url_status()` 中必须命中同一个逻辑 key，避免状态查询显示 A，业务连接实际使用 B。

### 9.2 查询已有 tunnel

当 tunnel map 中已存在对应 tunnel 时：

- 不需要重新建 tunnel；
- 只有最近 keepalive/ping 在阈值内成功，或本次 force probe 在该 tunnel 上成功，才可以返回 `Reachable`，来源为 `ExistingTunnel`；
- 如果 tunnel map 中存在实例，但最近连续 ping 超时或超过健康阈值没有成功记录，应返回 `Unknown` 或 `Unreachable`，不能只因 map 中有对象就认为可达；
- 如有最近 ping RTT，则返回 `rtt_ms`；
- 若无 RTT，可返回 `Reachable` + `rtt_ms = None`，并在后台或 force probe 时补充 ping。
- 该结果必须写回 `normalized_url -> TunnelUrlHistory`；
- tunnel map 与 tunnel key 只作为 RTCP prober 的运行期索引，不能替代 URL history。

同一个 RTCP tunnel key 可能服务多个 URL，例如 `rtcp://device.did/:80` 和 `rtcp://device.did/:9000` 共享同一条设备级 tunnel，但必须拥有两条独立 URL history。tunnel-level 事件的传播规则是：

- tunnel 建立成功、keepalive 成功、tunnel 关闭、控制面 ping 超时这类 tunnel-level 事件，应传播到所有已知共享该 tunnel key 的 normalized URL history；
- 具体 target 的 `open_stream(:80)` 或 `open_stream(:9000)` 失败，只能回写对应 URL history，不能扩散为整个 tunnel 不可达；
- 若 tunnel-level 事件发生时只有部分 URL 曾被查询或配置过，只更新已知 URL history，不主动枚举或创建新的 URL history。

### 9.3 支持带 RTT 的 ping/probe

RTCP prober 应提供带超时的 ping 测量：

- 记录发送前时间；
- 等待可确认的 pong 或等价响应；
- 返回 RTT；
- 超时返回 `Unreachable`，失败原因标记为 ping timeout。

当前 `RTcpTunnel::ping()` 只发送 Ping 包，不等待 Pong，因此不能直接作为 RTT 依据。需要新增能关联 Ping/Pong seq 的等待机制，或新增专用状态 probe 包。

### 9.4 复用 direct attempt 结果

RTCP direct 建链已有候选地址并发尝试和 `DIRECT_CONNECT_ATTEMPT_DELAY = 250ms` 逻辑。状态层应复用这些结果：

- 成功建链时记录 URL 级 `Reachable`、RTT、remote addr；
- 所有候选失败时记录 URL 级 `Unreachable` 和聚合失败原因；
- 地址级 RTT 可继续保留在 name_client/RTCP 内部，URL 状态只暴露汇总结果。

### 9.5 keep_tunnel 状态进入 URL history

`RtcpStack::start_keep_tunnel()` 的循环应把最近结果写入 `TunnelManager` 的 URL history：

- `get_tunnel()` 失败：记录 `Unreachable`；
- `ping()` 成功：记录 `Reachable`；
- ping 失败：记录 `Unreachable`；
- 记录最近成功/失败时间。

这样上层查询 keep tunnel URL 时可以直接复用后台保活结果。即使 keep tunnel 当前实例断开，URL history 也应保留最近一次成功和失败记录，供排序和诊断使用。

### 9.6 嵌套 URL 的状态语义

多链路场景中，不同 relay 或 bootstrap 路径必须表现为不同 normalized URL。对于嵌套/中转 URL，`Reachable` 的语义必须是端到端可用，而不是只证明某一段可达。

要求：

- `rtcp://device.did/:80` 的 `Reachable` 表示本端到 `device.did` 的 RTCP tunnel 控制面可用，并且在需要 target 级 probe 时 `:80` 可打开；
- 带 bootstrap/relay 的 RTCP URL 的 `Reachable` 表示 bootstrap/relay 段和最终 RTCP 控制面都可用；
- 如果 probe 只验证了 relay 自身可达，状态不能标记为该端到端 URL 的 `Reachable`，只能作为内部诊断字段或独立 relay URL 的状态；
- failure_reason 必须尽量标记失败阶段，例如 `bootstrap_connect_failed`、`relay_handshake_failed`、`rtcp_key_confirm_timeout`、`target_open_failed`；
- 排序时只能比较同一语义层级的 URL：端到端 RTCP URL 与 relay 节点自身健康 URL 不能混在同一个 Selector 候选集合里比较。

### 9.7 业务建链结果回写

业务 `open_stream_by_url()` / `create_datagram_client_by_url()` 的成功或失败必须回写 URL history，状态来源为 `BusinessConnect`。

要求：

- 业务建链成功可以更新 `last_reachable`、成功计数和最近 RTT/耗时；
- 业务建链失败应更新对应 URL 的失败计数和 `failure_reason`；
- 如果失败发生在 tunnel 控制面，应按 9.2 的 tunnel-level 传播规则更新共享 tunnel 的 URL history；
- 如果失败发生在 target 层，只更新当前 URL history；
- 业务回写不能触发新的隐式 URL 发现。

## 10. 其它协议的最小支持要求

### 10.1 tcp/ptcp/tls/quic

这些协议可以第一阶段用“轻量连接 probe”实现：

- 解析 URL path 得到目标 host/port；
- 在 probe timeout 内尝试建立对应连接；
- 成功后立即关闭；
- 返回连接耗时作为 RTT。

限制：

- TLS/QUIC 的 RTT 可以先定义为“连接建立耗时”，不等同业务首包 RTT；
- tcp/tls/quic 的连接建立耗时不能直接与 RTCP ping RTT 做跨协议优劣判断；
- probe 不发送业务数据；
- 对没有明确目标端口的 URL 返回 `Unreachable` 或 `Unsupported`。

### 10.2 udp/rudp

UDP 没有通用可达性语义，第一阶段建议：

- 若协议无专用 ping，返回 `Unsupported`；
- 如果 RUDP 由 RTCP 栈提供可靠控制面，则按 RTCP/RUDP 专用 prober 实现；
- 不应通过发送任意 UDP 包假装可达。

### 10.3 socks

SOCKS 可以分两层：

- 只测试 SOCKS 服务器可连通；
- 测试经 SOCKS CONNECT 到目标可连通。

第一阶段建议按完整 URL 测试目标 CONNECT，因为多链路排序关心的是这条 URL 到目标服务是否可达，而不只是代理本身是否在线。

## 11. 安全与权限

状态查询会暴露网络拓扑和可达性信息，必须受控：

- 控制 API 只能查询调用方配置或授权范围内的 URL；
- 不提供“列出所有内部 tunnel URL”的默认能力；
- 日志和返回错误中需要脱敏 URL userinfo、token、bootstrap 参数中的敏感字段；
- failure_reason 必须通过统一脱敏 helper 处理，peer IP、证书 subject、ALPN、bootstrap 节点 DID、relay DID 是否可返回应由同一策略判断，不能由各 prober 拼接原始错误直接外露；
- 对批量查询设置数量上限和并发上限；
- force probe 应受权限或配置限制，避免被滥用为扫描工具。

## 12. 与控制面/API 的关系

本需求主要定义 `cyfs-gateway-lib` 内部能力。对外 API 可以后续在控制服务器中包装，建议形态为：

```text
POST /tunnels/probe
{
  "urls": ["rtcp://device.dev.did/:80", "socks://127.0.0.1:1080/example.com:443"],
  "force_probe": false,
  "max_age_ms": 30000,
  "timeout_ms": 3000,
  "sort": "rtt_ascending"
}
```

返回：

```text
{
  "statuses": [
    {
      "url": "rtcp://device.dev.did/:80",
      "state": "reachable",
      "rtt_ms": 20,
      "source": "existing_tunnel",
      "cached": true
    }
  ],
  "sorted_urls": ["rtcp://device.dev.did/:80"]
}
```

控制面只负责鉴权、参数校验和 JSON 序列化，不应重新实现 probe 逻辑。

Selector 不应在每个业务请求路径上同步调用批量 probe。推荐方式是：

- 应用调度器或 Gateway 后台任务定期刷新 URL history；
- Selector 在请求路径上读取最近的排序结果或新鲜 history；
- 只有配置变更、显式诊断、强制刷新等控制面操作才触发 force probe。

## 13. 观测与排障

每次状态变化应有结构化日志，至少包含：

- normalized URL 或脱敏 URL；
- scheme；
- 状态；
- RTT；
- 状态来源；
- 失败原因摘要；
- 是否命中 URL history 缓存；
- probe 耗时。

需要支持回答以下问题：

- 某个 URL 上一次状态是什么？
- 状态来自 URL history、keepalive、已有 tunnel、业务建链还是 fresh probe？
- 为什么某个 direct URL 被判定不可达？
- 为什么排序结果选择了 relay URL？
- 上一次调度传入的 URL 集合里是否包含 direct URL？
- relay/bootstrap URL 失败发生在哪一段？

## 14. 测试需求

### 14.1 单元测试

`tunnel_mgr.rs` 需要覆盖：

- URL 规范化与 history key；
- URL history 命中和过期；
- force probe 绕过 URL history；
- URL history 默认落盘、关闭落盘、加载过期历史；
- tunnel instance 关闭后 history 仍然保留；
- 内存 history 超过上限后的 LRU 淘汰；
- in-flight probe 复用不占用新的并发配额；
- 批量查询中单个 URL 失败不影响其它 URL；
- 排序策略，尤其是 `Unknown`、`Probing`、`Unsupported`、`Unreachable` 和 `Reachable + rtt_ms = None` 的顺序；
- 跨 scheme RTT 不直接比较，回退到 caller priority 或 scheme priority；
- 未实现 prober 的 scheme 返回 `Unsupported`；
- 敏感 URL 和 failure_reason 脱敏。

### 14.2 RTCP 集成测试

需要覆盖：

- 已有 RTCP tunnel 的状态查询不重新建链；
- direct URL fresh probe 成功后返回 RTT；
- 无法解析远端设备时返回 `Unreachable` 和失败原因；
- bootstrap URL 与 direct URL 的 tunnel key 不混淆；
- keep_tunnel 后台结果可被查询复用。
- existing tunnel 连续 ping 超时后不再仅凭 map 存在返回 `Reachable`；
- 同一 RTCP tunnel key 下多个 URL 的 tunnel-level 事件传播；
- target-level 业务失败只回写当前 URL history；
- 嵌套 URL 能区分 bootstrap/relay/control-plane/target 阶段失败。

### 14.3 协议最小 probe 测试

需要覆盖：

- tcp URL 对本地 ephemeral listener 返回 reachable；
- tcp URL 对关闭端口返回 unreachable；
- socks URL 对可用 SOCKS server 的 CONNECT probe；
- udp 无专用 probe 时返回 unsupported。

## 15. 分阶段落地建议

### 阶段一：框架、URL history 与缓存

- 新增 `TunnelUrlStatus`、`TunnelProbeOptions`、`TunnelProbeResult`；
- 新增 `TunnelUrlProber` 可选扩展；
- `TunnelManager` 新增 URL history、状态缓存、可选落盘、内存上限、in-flight 合并、单 URL 查询、批量查询和排序；
- 未实现 prober 的协议返回 `Unsupported`；
- 完成 `tunnel_mgr.rs` 单元测试。

### 阶段二：RTCP/RUDP 优先接入

- RTCP builder 提供 prober；
- 按当前 tunnel key 规则查询 existing tunnel；
- direct create/probe 成功或失败写入 URL history；
- keep_tunnel 循环写入 URL history；
- 业务建链结果以 `BusinessConnect` 来源回写 URL history；
- tunnel-level 事件传播到共享 tunnel key 的已知 URL history；
- 实现带 RTT 的 ping 或等价 probe。

### 阶段三：本地连接类协议接入

- tcp/ptcp/tls/quic 增加轻量连接 probe；
- socks 增加 CONNECT probe；
- udp 无专用语义时保持 unsupported；
- 控制面增加 `/tunnels/probe` 类 API。

### 阶段四：Selector 集成

- Gateway Selector 使用批量状态查询结果；
- Selector 读取后台刷新结果或新鲜 history，不在每个业务请求上同步 force probe；
- Failover 只在配置允许 URL 集合内切换；
- Selector 不做设备搜索或 relay 自动发现；
- 应用调度器负责刷新 URL 集合。

## 16. 验收标准

最小可验收版本应满足：

- 调用方传入多个 Tunnel URL 后，能得到每个 URL 的状态、RTT 或失败原因；
- 状态主结构是 `normalized_url -> TunnelUrlHistory`，不是 `url -> tunnel_instance`；
- URL history 默认落盘，且可以通过配置关闭；
- Gateway 重启后能加载已落盘 history，并按 TTL 决定是否继续使用或重新 probe；
- 批量结果能给出状态优先、同 scheme RTT 升序的排序，且不直接比较异质 RTT；
- `Unsupported`、`Unknown`、`Probing`、`Unreachable` 的排序位置有确定实现；
- RTCP 已有 tunnel 的状态查询能复用现有 tunnel；
- RTCP force probe 在已有 tunnel 上发 ping，不新建同 key 临时 tunnel；
- RTCP tunnel instance 断开后，对应 URL history 不会被删除；
- 同一 RTCP tunnel key 的 tunnel-level 事件能传播到所有已知共享 URL history；
- `BusinessConnect` 能区分真实业务建链回写与主动 probe；
- URL history 内存表有上限和淘汰策略；
- 同一 URL 的 in-flight probe 会合并；
- 未实现 probe 的协议不会假成功；
- 状态查询不会隐式新增 relay/direct URL；
- 日志和返回结果可以解释 URL 被选中或被排除的原因；
- 所有新增核心逻辑有单元测试或集成测试覆盖。
