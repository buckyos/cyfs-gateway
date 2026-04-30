# CYFS Gateway forward 机制升级需求

> **实现状态（2026-04-29）：本需求已完成落地。**
>
> 主要实现位置：
>
> - 数据模型（`ForwardPlan` / `ForwardTarget` / `NextUpstreamPolicy` / `BalanceMethod` / `ForwardServer` / `ProviderPolicy`）：[plan.rs](src/components/cyfs-gateway-lib/src/forward/plan.rs)
> - selector（primary/backup 排序、fail_timeout 跳过、provider 邻接、least_time 重排）：[selector.rs](src/components/cyfs-gateway-lib/src/forward/selector.rs)
> - group 内失败状态（§6.6，进程内、不落盘）：[failure_state.rs](src/components/cyfs-gateway-lib/src/forward/failure_state.rs)
> - least_time / RTT 排序（消费 tunnel_mgr 历史，§4.1 / §8 阶段 4）：[least_time.rs](src/components/cyfs-gateway-lib/src/forward/least_time.rs)
> - process-chain `forward` 命令（兼容单 URL 与 group 形态，支持 `--map` / `--backup-map` / `--server-map` / `--next-upstream` / `--tries` / `--next-upstream-timeout` / `--max-fails` / `--fail-timeout` / `--hash-key` / `--max-body-buffer` / `--provider-retry-scope` 等）：[cmds/forward.rs](src/components/cyfs-gateway-lib/src/cmds/forward.rs)
> - stream / datagram 执行层连接阶段 next_upstream（§6.4 / §6.5）：[stack/mod.rs](src/components/cyfs-gateway-lib/src/stack/mod.rs)
> - HTTP 入口连接阶段 retry 与受限的状态码 retry + 请求体缓冲（§6.3 / 阶段 3）：[server/http_server.rs](src/components/cyfs-gateway-lib/src/server/http_server.rs)
> - tunnel_mgr URL history 业务回写（§6.7：`open_stream_by_url` / datagram client 创建时调用 `record_business_success` / `record_business_failure`，并按 §6.7.3 分类失败原因）：[tunnel_mgr.rs](src/components/cyfs-gateway-lib/src/tunnel_mgr.rs)
>
> 下文保留需求背景，同时已按当前实现修正用户可见命令、内部模型和执行边界。

## 1. 背景

升级前，`forward` 命令已经支持多个 upstream URL、权重、`round_robin` 和 `ip_hash`，但执行语义仍是：

```text
process-chain 执行 forward 命令
forward 从候选 upstream 中选择一个 URL
返回 forward "<selected_url>"
HTTP server / stream stack / datagram stack 只消费这个单一 URL
```

这意味着升级前的 group forward 本质上是“请求前选择一个 URL”。如果该 URL 在执行阶段连接失败，gateway 不会在同一次 forward 中尝试下一个候选 URL，只能依赖客户端重试，或依赖下一次请求重新进入 selector 后避开失败 URL。

本次升级已经把 group forward 从“只返回一个 URL 的 selector”升级为“Nginx upstream 风格的候选组 + 执行阶段 next upstream”，同时保留现有单 URL forward 的简单语义和兼容性。

## 2. 设计原则

1. 保留 `forward <url>`，它是最小、明确、可排障的单目标转发 primitive。
2. 新增 group forward，设计尽量继承 Nginx upstream 的成熟概念，不引入过多新术语。
3. group 中的候选目标必须显式配置；gateway 不自动发现、发明或扩散到未配置的 relay / route。
4. group forward 默认面向无状态服务池；有状态服务需要应用或调度器显式声明选择 key、亲和策略或单 provider。
5. 执行阶段 retry 只在安全边界内发生。连接建立前的 retry 是第一优先级；请求体或流数据已发送后的 retry 必须保守。
6. 单 URL forward 是 group forward 的退化形态，但仍应作为用户可见语义长期保留。

## 3. 保留单 URL forward

### 3.1 语法

现有写法继续有效：

```text
forward "http://127.0.0.1:8080"
forward "tcp:///127.0.0.1:9000"
forward "rtcp://device.example.zone/:7001"
```

### 3.2 语义

单 URL forward 的语义保持简单：

```text
forward <url> == candidates=[url], next_upstream=off, tries=1
```

执行层只尝试该 URL。失败后返回失败，不自动换目标。

### 3.3 保留原因

- 兼容已有 process-chain 配置、测试和用户习惯。
- 支持强制指定目标的调试和运维场景。
- 支持有状态或不可重试请求的明确失败语义。
- 作为 group forward 内部执行单个 candidate 的基础 primitive。

## 4. 支持 forward 到 group

### 4.1 用户模型

group forward 使用 Nginx 用户熟悉的 upstream 模型：

```text
upstream group
  balance method
  server / peer list
  weight
  backup
  max_fails
  fail_timeout
  next_upstream
```

当前实现已经覆盖 Nginx OSS 级别的成熟语义，并补齐了受限的 RTT 排序：

- weighted round robin
- ip_hash / hash key / consistent_hash
- backup peer
- max_fails / fail_timeout
- next_upstream on error / timeout
- max tries / retry timeout budget
- least_time：执行入口用 tunnel_mgr URL history 做短预算重排，失败或超时退回原顺序

cost-first 等更复杂策略仍属于后续增强。

### 4.2 配置形态

逻辑模型仍是 upstream group：

```yaml
upstreams:
  control-panel:
    balance: round_robin
    next_upstream:
      conditions:
        - error
        - timeout
      tries: 3
      timeout: 5s

    peers:
      - url: rtcp://ood1.example.zone/:3202
        weight: 100
        max_fails: 1
        fail_timeout: 10s

      - url: rtcp://ood2.example.zone/:3202
        weight: 100
        max_fails: 1
        fail_timeout: 10s

      - url: rtcp://relay-a/ood1.example.zone/:3202
        backup: true
        weight: 100
        max_fails: 1
        fail_timeout: 10s
```

当前 process-chain 不存在“按名字引用预定义 upstream”的 `forward --group <name>` 形态。`--group` 已落地为失败状态分组名，不是 upstream registry lookup。当前用户可见构造方式是把 peer 放入 process-chain map，然后调用 `forward` 生成内部 `ForwardPlan`：

```text
map-create primary_peers;
map-create backup_peers;

map-add primary_peers "rtcp://ood1.example.zone/:3202" 100;
map-add primary_peers "rtcp://ood2.example.zone/:3202" 100;
map-add backup_peers "rtcp://rtcp%3A%2F%2Fsn.example.org%2F@ood1.example.zone/:3202" 100;

forward round_robin --map $primary_peers \
                    --backup-map $backup_peers \
                    --group control-panel \
                    --next-upstream error,timeout \
                    --tries 3 \
                    --fail-timeout 10s;
```

`forward` 命令返回给执行层的结果不再只是单一 URL，而是：

```text
forward-group "<base64-json-forward-plan>"
```

单 URL 或未启用 group 选项的旧多 URL 语法仍可以退化为 `forward "<selected-url>"`，保持兼容。

### 4.3 ForwardPlan

内部统一表示当前为：

```rust
struct ForwardPlan {
    group: Option<String>,
    balance: BalanceMethod,
    next_upstream: NextUpstreamPolicy,
    candidates: Vec<ForwardTarget>,
    hash_key_value: Option<String>,
    servers: Vec<ForwardServer>,
    provider_policy: ProviderPolicy,
}

struct ForwardTarget {
    url: String,
    weight: u32,
    backup: bool,
    max_fails: u32,
    fail_timeout: Duration,
    server_id: Option<String>,
}
```

`forward <url>` 解析后也应进入同一模型：

```text
ForwardPlan {
  candidates: [url],
  next_upstream: off,
}
```

编码格式是 `base64(JSON)`，由 `ForwardPlan::encode()` / `ForwardPlan::decode()` 处理；process-chain 用户不直接拼 JSON。

### 4.4 选择和失败处理

group forward 分两步：

1. selector 根据 balance method、weight、backup、失败历史选择有序 candidate list。
2. executor 根据 `next_upstream` 在执行阶段尝试 candidate。

候选顺序应遵循：

- primary peer 优先于 backup peer。
- 处于 `fail_timeout` 窗口内的失败 peer 应被降级或跳过。
- backup peer 只有在 primary peer 不可用或全部失败时才进入尝试集合。
- 所有尝试都必须来自显式配置的 candidate。

## 5. 有状态服务与 provider-first 扩展

Nginx upstream 默认是一层无状态服务池。当前 cyfs-gateway 的服务转发也基本符合这个模型：多个 provider 被看作等价服务实例，有状态 app service 通常是单 provider。

当前实现已经提供 provider-first 的基础模型：`ForwardServer` 表示一个逻辑 provider，`routes` 表示这个 provider 的多条传输路径。用户解释是：

```text
Nginx upstream: hash key -> server
CYFS Gateway extension: hash key -> server -> route
```

process-chain 中的当前落地入口是 `--server-map`：外层 map 是 `server_id -> route-map`，内层 route-map 是 `url -> weight`。

```text
map-create node_a_routes;
map-add node_a_routes "rtcp://node-a.example.zone/:7001" 100;
map-add node_a_routes "rtcp://rtcp%3A%2F%2Fsn.example.org%2F@node-a.example.zone/:7001" 100;

map-create node_b_routes;
map-add node_b_routes "rtcp://node-b.example.zone/:7001" 100;

map-create servers;
map-add servers node-a $node_a_routes;
map-add servers node-b $node_b_routes;

forward consistent_hash --hash-key "$cookie_session_id" \
        --server-map $servers \
        --next-upstream error,timeout \
        --tries 3 \
        --provider-retry-scope routes_only;
```

上面的命令会构造 provider-first plan，并让同一个 `server_id` 的 routes 在尝试顺序中保持相邻。`--provider-retry-scope routes_only|across_servers` 当前会被解析并序列化进 `ForwardPlan`，但执行层尚未按该字段硬性截断 provider 边界；实际 retry 仍按 selector 产出的扁平候选顺序和 `--tries` 预算前进。因此它目前更接近 provider-first 排序/建模能力，而不是完整的“禁止跨 provider retry”执行保证。

对应的内部模型是：

```yaml
upstreams:
  user-profile:
    balance:
      method: hash
      key: $cookie_session_id

    next_upstream:
      route:
        conditions:
          - error
          - timeout
      server: off

    servers:
      node-a:
        weight: 100
        port: 7001
        routes:
          - url: rtcp://node-a.example.zone/
          - url: rtcp://relay-a/node-a.example.zone/
            backup: true

      node-b:
        weight: 100
        port: 7001
        routes:
          - url: rtcp://node-b.example.zone/
```

设计目标仍然是：默认不允许 route 失败后自动换 provider。是否能换 provider 必须由服务显式声明，因为 gateway 无法应用无关地判断有状态请求能否迁移。按当前实现，如果有状态服务需要严格避免跨 provider retry，应使用单 provider 候选、合适的 hash / consistent_hash key、较小的 `--tries`，或等待执行层补齐 `ProviderPolicy` 的硬边界 enforcement。

需要注意：当前 `--server-map` 入口是面向 process-chain 的基础形态，只表达 `server_id -> url/weight routes`；更复杂的 per-route `backup`、per-server `backup` 等字段存在于内部 `ForwardServer` / `ForwardTarget` 模型中，但还没有作为结构化 `forward --plan` 用户命令暴露。

## 6. 消费 forward 语义的实现注意事项

### 6.1 process-chain command

`forward` 命令需要区分两类输出：

- 单 URL：继续输出 `forward "<url>"`。
- group：输出可被执行层识别的 group forward / ForwardPlan。

当前实现使用独立动作：

```text
forward-group "<base64-json-forward-plan>"
```

HTTP server、stream stack、datagram stack 都已识别 `forward-group` 并通过 `ForwardPlan::decode()` 还原候选组。普通 `forward "<url>"` 仍只携带单 URL；不会通过 `forward "url1" "url2"` 这种返回形式传递候选组。

### 6.2 process-chain 中动态构造 ForwardPlan

`ForwardPlan` 不能只支持静态配置。BuckyOS 的 gateway 场景里，转发目标通常是在 process-chain 中根据请求、`SERVICE_INFO`、`ROUTES` 以及兼容用的 `NODE_ROUTE_MAP` 动态构造出来的。

旧的 `boot_gateway.yaml` 曾使用这种模式：

```yaml
forward_to_service:
  block: |
    if match-include $TARGET_SERVICE_INFO.selector $THIS_NODE_ID then
      local port=$TARGET_SERVICE_INFO.selector[$THIS_NODE_ID].port;
      forward "http://127.0.0.1:${port}";
    else
      map-create target_node_map;
      for node_id, node_info in $TARGET_SERVICE_INFO.selector then
          local target_rtcp_url = ${NODE_ROUTE_MAP[$node_id]}
          if !eq target_rtcp_url "" then
            local target_rtcp_url_with_port = "${target_rtcp_url}:${node_info.port}";
            map-add target_node_map $target_rtcp_url_with_port $node_info.weight;
          end
      end
      forward round_robin --map $target_node_map;
    end
```

这段逻辑的本质是：

```text
根据请求找到 TARGET_SERVICE_INFO
遍历 selector 中的 provider
用 node route + service port 拼出 candidate URL
把 candidate URL 和 weight 放入 map
交给 forward 选择
```

升级后的 group forward 保留了这个构造习惯：process-chain 仍构造 `url -> weight` map，`forward` 命令负责把 map 转成 `ForwardPlan` 并编码为 `forward-group`。

#### 6.2.1 最小兼容构造

当前继续支持简单 map：

```text
map-create target_peer_map;
map-add target_peer_map "rtcp://ood1.example.zone/:3202" 100;
map-add target_peer_map "rtcp://ood2.example.zone/:3202" 100;
forward round_robin --map $target_peer_map --next-upstream error,timeout --tries 3;
```

该形态等价于所有 peer 都是 primary，只包含 `url` 和 `weight`。它适合从当前 `selector + node_route_map` 平滑迁移。

#### 6.2.2 primary / backup 构造

为了表达 Nginx 的 `backup` 语义，process-chain 应能分别构造 primary 和 backup candidate：

```text
map-create primary_peers;
map-create backup_peers;

map-add primary_peers "rtcp://ood1.example.zone/:3202" 100;
map-add primary_peers "rtcp://ood2.example.zone/:3202" 100;
map-add backup_peers "rtcp://relay-a/ood1.example.zone/:3202" 100;

forward round_robin --map $primary_peers \
        --backup-map $backup_peers \
        --next-upstream error,timeout \
        --tries 3 \
        --fail-timeout 10s;
```

这是一种对 process-chain 友好的形态：不要求脚本构造复杂嵌套对象，但已经能覆盖 `primary + backup + next_upstream`。

#### 6.2.3 结构化 ForwardPlan 与 provider-first 构造

当前没有 `forward --plan $forward_plan` 这种用户命令。`ForwardPlan` 的 JSON/base64 是 `forward` 命令内部生成、执行层内部消费的协议，不要求 process-chain 脚本拼结构化 JSON。

如果 process-chain collection 支持把 map 作为 value，当前已落地的结构化入口是 `--server-map`：

```text
map-create node_a_routes;
map-add node_a_routes "rtcp://node-a.example.zone/:7001" 100;
map-add node_a_routes "rtcp://rtcp%3A%2F%2Fsn.example.org%2F@node-a.example.zone/:7001" 100;

map-create node_b_routes;
map-add node_b_routes "rtcp://node-b.example.zone/:7001" 100;

map-create servers;
map-add servers node-a $node_a_routes;
map-add servers node-b $node_b_routes;

forward hash --hash-key "$cookie_session_id" \
        --server-map $servers \
        --next-upstream error,timeout \
        --tries 3 \
        --provider-retry-scope routes_only;
```

如果只需要无状态服务池或 BuckyOS 当前的 service forwarding，使用 `--map` / `--backup-map` 这种扁平 map 输入即可。

#### 6.2.4 从 service selector 和 routes 构造

面向 BuckyOS service forwarding，推荐的动态构造流程是：

```text
1. 根据请求解析 SERVICE_ID 和 TARGET_SERVICE_INFO。
2. 如果 selector 命中 THIS_NODE_ID，继续直接 forward 到 127.0.0.1:port。
3. 否则遍历 TARGET_SERVICE_INFO.selector。
4. 对每个 node_id：
   - 优先读取 ROUTES[node_id] 中的 route candidates。
   - 如果 ROUTES 不存在，fallback 到 NODE_ROUTE_MAP[node_id]。
   - 用 route.url + node_info.port 拼出 candidate URL。
   - direct route 放入 primary peers。
   - relay / backup route 放入 backup peers。
   - weight 默认继承 node_info.weight，route 可覆盖。
5. 调用 group forward。
```

示例：

```yaml
forward_to_service:
  block: |
    if match-include $TARGET_SERVICE_INFO.selector $THIS_NODE_ID then
      local port=$TARGET_SERVICE_INFO.selector[$THIS_NODE_ID].port;
      forward "http://127.0.0.1:${port}";
    else
      map-create primary_peers;
      map-create backup_peers;

      for node_id, node_info in $TARGET_SERVICE_INFO.selector then
        if match-include $ROUTES $node_id then
          for route_id, route in $ROUTES[$node_id] then
            local target_url="${route.url}:${node_info.port}";
            if eq $route.backup true then
              map-add backup_peers $target_url $node_info.weight;
            else
              map-add primary_peers $target_url $node_info.weight;
            end
          end
        else
          local target_rtcp_url=${NODE_ROUTE_MAP[$node_id]};
          if !eq $target_rtcp_url "" then
            local target_url="${target_rtcp_url}:${node_info.port}";
            map-add primary_peers $target_url $node_info.weight;
          end
        end
      end

      forward round_robin --map $primary_peers \
              --backup-map $backup_peers \
              --group "service:${SERVICE_ID}" \
              --next-upstream error,timeout \
              --tries 3;
    end
```

上面的语法是当前实现形态；需求重点是执行层支持 process-chain 动态构造 group，而不是只支持预定义 upstream 名称。

### 6.3 HTTP server

HTTP 入口消费 group forward 时需要特别保守：

- 可以在连接失败、TCP connect 失败、tunnel open 失败、TLS handshake 失败时尝试下一个 candidate。
- 不应在请求体已经发送给上游后默认重试。
- 如果要支持 502 / 503 / 504 后 retry，需要确认请求体可重放，或设置明确的 body buffer 限制。
- 对非幂等方法，如 `POST`、`PUT`、`PATCH`，默认只做连接建立前 retry。
- `--tries` 和 `--next-upstream-timeout` 必须限制单次请求的最大尝试成本。

### 6.4 Stream stack

TCP / TLS / RTCP / QUIC stream 入口消费 group forward 时，当前支持连接阶段 retry：

```text
open target stream failed -> try next candidate
open target stream success -> start copy_bidirectional
copy_bidirectional started -> no transparent retry
```

流已经建立并开始双向复制后，任意一侧断开都应按当前连接失败处理，不应静默切到另一个 upstream。

### 6.5 Datagram stack

UDP / RUDP datagram forward 的 retry 语义比 stream 更复杂。当前实现边界是：

- 支持创建 datagram client 失败时尝试下一个 candidate。
- datagram session 建立后不自动切换 candidate。
- datagram route migration 尚未定义；如需支持，需要单独定义 session 迁移、乱序和重复包语义。

### 6.6 失败历史

group forward 需要一个共享的 upstream failure state：

```text
key: upstream group + candidate url
state: fail count, last failure time, ejection deadline, last error
```

要求：

- selector 在下一次请求时能避开处于 `fail_timeout` 内的失败 candidate。
- executor 在本次 forward 尝试失败时更新 failure state。
- 成功连接后应清理或衰减该 candidate 的失败状态。
- failure state 只影响显式配置的 candidate，不生成新 candidate。

### 6.7 向 tunnel_mgr 回写 URL history

group forward 内部的失败状态（6.6）只服务于本 group 的 `max_fails / fail_timeout` 剔除决策，作用域是 group + candidate。Gateway 还需要一份全局的、跨 group 的 URL 健康视图，用于 tunnel_mgr 的状态查询、Probe API 复用和应用调度器排序。该视图由 tunnel_mgr 维护为 `normalized_url -> TunnelUrlHistory`，详见 `tunnel_mgr基于url状态查询需求.md` 第 5.3、8 节。

forward executor 是业务流量的实际发起方，也是唯一能区分"连接阶段失败 / TLS 握手失败 / 流中断开 / 上游应用错"的位置。业务建链结果是比主动 probe 和 keepalive 都更高质量的信号源，因此 executor 必须在每次 candidate attempt 结束时回写 tunnel_mgr 的 URL history。

#### 6.7.1 回写时机

executor 在以下时刻调用 tunnel_mgr 的 history 上报接口：

- candidate 的 stream / datagram client 建立成功时；
- candidate 的连接阶段失败时（connect / TLS handshake / tunnel open 失败 / timeout）；
- 已建立的 stream / datagram session 关闭时（用于补充字节数、持续时间、是否异常断开）。

#### 6.7.2 回写内容

| forward 侧观测 | 写入 TunnelUrlHistory |
|---|---|
| open_stream / create_datagram_client 成功 + 耗时 | `Reachable`，`rtt_ms` 取连接建立耗时，`last_success_at_ms`，source 标记为业务建链 |
| 连接阶段失败（pre-connect / connect / TLS / open tunnel / timeout） | `Unreachable`，`failure_reason` 取协议层错误摘要，`last_failure_at_ms` |
| stream / datagram session 已建立后中途断开 | **不写 Unreachable**，仅更新 success_count、累计字节数、持续时间。已建链 URL 不应因为业务侧主动关闭或长连接超时被错误标记不可达 |
| 上游应用层错误（HTTP 5xx、上游业务错） | **不回写 tunnel history**。这是 upstream 服务健康问题，不是 URL 可达性问题，应由 group 内部的 6.6 失败状态处理 |
| 通过复用已有 tunnel 完成的 attempt | 仍需回写以更新 `last_success_at_ms`，但 source 应区别于 fresh connect，避免污染 RTT 历史 |

#### 6.7.3 失败原因分类

回写 `failure_reason` 时应使用一组统一的错误类别枚举，至少包含：

```text
pre_connect_dns
pre_connect_route
connect_refused
connect_timeout
tls_handshake
tunnel_open
unsupported_scheme
```

这些类别需要与 tunnel_mgr 的 prober 失败原因协调一致，避免业务回写和主动 probe 写出语义重叠但不可比对的字符串。

#### 6.7.4 与 group 内部失败状态的关系

两份状态各自独立，不要尝试合并：

- **forward group 内部 failure state（6.6）**：服务于本 group 的 `max_fails / fail_timeout` 剔除，作用域 group + candidate，进程内存即可，不落盘。
- **tunnel_mgr URL history（6.7）**：服务于全局 URL 健康视图、Probe API 复用、应用调度器排序，作用域是 normalized URL，按 `tunnel_mgr基于url状态查询需求.md` 第 8.1 节默认落盘。

普通 selector 不依赖 tunnel_mgr history；`least_time` 策略已在执行入口通过 tunnel_mgr 的批量 query 接口消费 URL history 做短预算重排，而不是维护独立 RTT 表。cost-aware 策略仍属后续扩展。

#### 6.7.5 回写不能阻塞业务路径

- 回写必须是非阻塞调用或异步任务，不能让业务请求等 history 写入完成。
- tunnel_mgr 的 history 写入失败只能记录告警，不能影响 forward 的成功返回或失败语义。
- 高频 attempt 时允许 executor 内部做合并/采样，避免每个失败都立刻产生一次锁竞争。

### 6.8 日志和调试

每次 group forward 至少应能解释：

- group 名称。
- balance method。
- 初始候选列表。
- 被跳过的 candidate 及原因。
- 实际尝试顺序。
- 每个失败 candidate 的错误。
- 最终选中的 URL 或最终失败原因。

这对排查“为什么走 relay 而不是 direct”非常重要。

## 7. 与当前实现的关系

当前实现中的：

```text
forward round_robin url1 url2
forward ip_hash --map $UPSTREAMS
```

继续作为兼容语法，但是否进入 group 语义取决于是否声明 group 选项或使用 hash / consistent_hash / least_time 等需要计划化的算法：

未启用 group 选项时：

```text
select one url -> return forward "<url>"
```

启用 `--backup-map` / `--next-upstream` / `--tries` / `--group` / `--server-map` 等 group 选项时：

```text
build ordered ForwardPlan -> return forward-group "<base64-json-forward-plan>" -> executor applies next_upstream policy
```

兼容策略：

1. 单 URL 行为不变。
2. 旧多 URL 语法在未声明 `next_upstream` 时，可以继续只选择一个 URL。
3. group forward 显式启用执行阶段 retry。
4. `--force-group` 可强制单 URL plan 也输出 `forward-group`；默认单 URL group plan 会退化为普通 `forward "<url>"`，保持老执行层兼容。

## 8. 分阶段落地

### 阶段 1：数据模型和单 URL 兼容 — 已完成

- 定义 `ForwardPlan`、`ForwardTarget`、`NextUpstreamPolicy`，见 [plan.rs](src/components/cyfs-gateway-lib/src/forward/plan.rs)。
- 保留并测试 `forward <url>`，单 URL 经 `ForwardPlan::single_url()` 退化为 `tries=1`、`next_upstream=off`。
- group forward 已支持 primary / backup / weight / max_fails / fail_timeout 解析。
- selector 已根据 `ForwardFailureRegistry` 在 `fail_timeout` 窗口内跳过候选。

### 阶段 2：连接阶段 next upstream — 已完成

- stream stack 在 `stream_forward_group()` 中按候选顺序 retry，连接成功后开始 `copy_bidirectional`，建立后不再透明切换。
- datagram stack 在 `datagram_forward_group()` 中支持创建 datagram client 阶段 retry，session 建立后不再切换。
- HTTP tunnel / direct upstream 在 `handle_forward_group()` 中支持连接 / TLS handshake / tunnel open 阶段 retry。
- executor 在每次尝试结束时更新 group 内失败状态。

### 阶段 3：HTTP proxy_next_upstream 增强 — 已完成

- `handle_forward_group_with_status_retry()` 支持受限的 5xx 状态码 retry。
- `--max-body-buffer` 控制请求体缓冲上限，超过即禁用状态码 retry。
- 通过 `HttpMethodClass` 区分幂等 / 非幂等方法，非幂等默认只在连接建立前 retry。
- `next_upstream_timeout` 限制单次请求的总尝试预算。

### 阶段 4：高级选择策略 — 已完成（基础部分）

- `hash $key`、`consistent_hash` 已纳入 `BalanceMethod` 并在解析阶段校验。
- provider-first 的 `server -> routes` 扩展：`ForwardServer` / `ProviderPolicy` 已建模，`--server-map` 支持构造带 `server_id` 的 plan，selector 会保持同一 provider 的 routes 相邻；`--provider-retry-scope` 已解析和序列化，但执行层尚未按 provider 边界硬截断 retry。
- RTT / least-time 策略：`apply_least_time_via_tunnel_mgr()` 在执行入口以受限预算（默认 50ms）查询 tunnel_mgr URL history 后对候选重排，超时或失败退化为原顺序，不在 forward 内部维护独立 RTT 表。
- Gateway Probe API 与 selector 通过 tunnel_mgr 共享同一份 URL history，详见 [tunnel_mgr基于url状态查询需求.md](doc/tunnel_mgr基于url状态查询需求.md)。
