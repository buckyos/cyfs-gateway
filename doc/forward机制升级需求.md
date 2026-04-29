# CYFS Gateway forward 机制升级需求

## 1. 背景

当前 `forward` 命令已经支持多个 upstream URL、权重、`round_robin` 和 `ip_hash`，但执行语义仍是：

```text
process-chain 执行 forward 命令
forward 从候选 upstream 中选择一个 URL
返回 forward "<selected_url>"
HTTP server / stream stack / datagram stack 只消费这个单一 URL
```

这意味着 group forward 当前本质上是“请求前选择一个 URL”。如果该 URL 在执行阶段连接失败，gateway 不会在同一次 forward 中尝试下一个候选 URL，只能依赖客户端重试，或依赖下一次请求重新进入 selector 后避开失败 URL。

升级目标是把 group forward 从“只返回一个 URL 的 selector”升级为“Nginx upstream 风格的候选组 + 执行阶段 next upstream”，同时保留现有单 URL forward 的简单语义和兼容性。

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

第一阶段不追求“最优路径”或主动 RTT 选择，先实现 Nginx OSS 级别的成熟语义：

- weighted round robin
- ip_hash / hash key
- backup peer
- max_fails / fail_timeout
- next_upstream on error / timeout
- max tries / retry timeout budget

`least_time`、RTT-first、cost-first 等策略可作为后续增强，不进入第一阶段核心需求。

### 4.2 配置形态

建议的逻辑模型：

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

对应 process-chain 动作可以是：

```text
forward --group control-panel
```

或在 process-chain 中引用已构造的 group collection：

```text
forward --group $TARGET_UPSTREAM
```

具体命令名可在实现阶段确定，但返回给执行层的内部结果应不再只是单一 URL，而是一个 `ForwardPlan`。

### 4.3 ForwardPlan

内部统一表示建议为：

```rust
struct ForwardPlan {
    candidates: Vec<ForwardTarget>,
    balance: BalanceMethod,
    next_upstream: NextUpstreamPolicy,
}

struct ForwardTarget {
    url: String,
    weight: u32,
    backup: bool,
    max_fails: u32,
    fail_timeout: Duration,
}
```

`forward <url>` 解析后也应进入同一模型：

```text
ForwardPlan {
  candidates: [url],
  next_upstream: off,
}
```

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

如果未来需要明确支持有状态服务，可以在 Nginx upstream 模型上做最小扩展：

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

该扩展的用户解释是：

```text
Nginx upstream: hash key -> server
CYFS Gateway extension: hash key -> server -> route
```

默认不允许 route 失败后自动换 provider。是否能换 provider 必须由服务显式声明，因为 gateway 无法应用无关地判断有状态请求能否迁移。

第一阶段可以不实现 provider-first，只要求 group forward 的数据模型不要阻塞后续扩展。

## 6. 消费 forward 语义的实现注意事项

### 6.1 process-chain command

`forward` 命令需要区分两类输出：

- 单 URL：继续输出 `forward "<url>"`。
- group：输出可被执行层识别的 group forward / ForwardPlan。

为了兼容已有执行层，第一阶段可以新增独立动作，例如：

```text
forward-group "<serialized-plan-id-or-json>"
```

也可以扩展 `forward` 返回多个参数，例如：

```text
forward "url1" "url2" --next-upstream error,timeout
```

无论具体语法如何，执行层不能再只读取 `list[1]` 后丢弃剩余候选。

### 6.2 process-chain 中动态构造 ForwardPlan

`ForwardPlan` 不能只支持静态配置。BuckyOS 的 gateway 场景里，转发目标通常是在 process-chain 中根据请求、`SERVICE_INFO`、`NODE_ROUTE_MAP`、未来的 `ROUTES` 动态构造出来的。

当前 `tests/buckyos/boot_gateway.yaml` 已经使用了这种模式：

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

升级后的 group forward 应保留这个构造习惯，只是把 `url -> weight` map 扩展为 `ForwardPlan`。

#### 6.2.1 最小兼容构造

第一阶段可以继续支持简单 map：

```text
map-create target_peer_map;
map-add target_peer_map "rtcp://ood1.example.zone/:3202" 100;
map-add target_peer_map "rtcp://ood2.example.zone/:3202" 100;
forward --group-map $target_peer_map --next-upstream error,timeout --tries 3;
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

forward --group-map $primary_peers \
        --backup-map $backup_peers \
        --next-upstream error,timeout \
        --tries 3 \
        --fail-timeout 10s;
```

这是一种对 process-chain 友好的形态：不要求脚本构造复杂嵌套对象，但已经能覆盖 `primary + backup + next_upstream`。

#### 6.2.3 结构化 ForwardPlan 构造

如果 process-chain collection 支持把 map 作为 value，推荐支持更完整的结构化 plan：

```text
map-create forward_plan;
map-create forward_peers;
map-create peer_ood1_direct;
map-create peer_ood1_relay;

map-add peer_ood1_direct url "rtcp://ood1.example.zone/:3202";
map-add peer_ood1_direct weight 100;
map-add peer_ood1_direct backup false;
map-add peer_ood1_direct max_fails 1;
map-add peer_ood1_direct fail_timeout "10s";

map-add peer_ood1_relay url "rtcp://relay-a/ood1.example.zone/:3202";
map-add peer_ood1_relay weight 100;
map-add peer_ood1_relay backup true;
map-add peer_ood1_relay max_fails 1;
map-add peer_ood1_relay fail_timeout "10s";

map-add forward_peers ood1_direct $peer_ood1_direct;
map-add forward_peers ood1_relay $peer_ood1_relay;

map-add forward_plan balance "round_robin";
map-add forward_plan next_upstream "error,timeout";
map-add forward_plan tries 3;
map-add forward_plan peers $forward_peers;

forward --plan $forward_plan;
```

如果当前 collection 实现不适合嵌套 map，执行层应至少支持 `--group-map` / `--backup-map` 这种扁平 map 输入，避免要求用户在 process-chain 中拼接 JSON 字符串。

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

      forward --group-map $primary_peers \
              --backup-map $backup_peers \
              --next-upstream error,timeout \
              --tries 3;
    end
```

上面的语法是目标形态，具体命令参数可在实现阶段调整；需求重点是执行层必须支持 process-chain 动态构造 group，而不是只支持预定义 upstream 名称。

### 6.3 HTTP server

HTTP 入口消费 group forward 时需要特别保守：

- 可以在连接失败、TCP connect 失败、tunnel open 失败、TLS handshake 失败时尝试下一个 candidate。
- 不应在请求体已经发送给上游后默认重试。
- 如果要支持 502 / 503 / 504 后 retry，需要确认请求体可重放，或设置明确的 body buffer 限制。
- 对非幂等方法，如 `POST`、`PUT`、`PATCH`，默认只做连接建立前 retry。
- `next_upstream_tries` 和 `next_upstream_timeout` 必须限制单次请求的最大尝试成本。

### 6.4 Stream stack

TCP / TLS / RTCP / QUIC stream 入口消费 group forward 时，第一阶段只要求支持连接阶段 retry：

```text
open target stream failed -> try next candidate
open target stream success -> start copy_bidirectional
copy_bidirectional started -> no transparent retry
```

流已经建立并开始双向复制后，任意一侧断开都应按当前连接失败处理，不应静默切到另一个 upstream。

### 6.5 Datagram stack

UDP / RUDP datagram forward 的 retry 语义比 stream 更复杂。第一阶段建议：

- 支持创建 datagram client 失败时尝试下一个 candidate。
- datagram session 建立后不自动切换 candidate。
- 如果未来支持 datagram route migration，需要单独定义 session 迁移、乱序和重复包语义。

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

forward selector 在第一阶段不依赖 tunnel_mgr 的 history 做选择；在阶段 4 引入 RTT / least-time / cost-aware 策略时，再通过 tunnel_mgr 的批量 query 接口消费 history，而不是各自维护一份独立的 RTT 表。

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

可以继续作为兼容语法，但语义需要逐步升级：

当前：

```text
select one url -> return forward "<url>"
```

目标：

```text
build ordered candidate list -> executor applies next_upstream policy
```

兼容策略：

1. 单 URL 行为不变。
2. 旧多 URL 语法在未声明 `next_upstream` 时，可以继续只选择一个 URL。
3. 新 group forward 显式启用执行阶段 retry。
4. 旧语法可以逐步映射到默认 group，但不能突然改变不可重试请求的行为。

## 8. 分阶段落地

### 阶段 1：数据模型和单 URL 兼容

- 定义 `ForwardPlan`、`ForwardTarget`、`NextUpstreamPolicy`。
- 保留并测试 `forward <url>`。
- group forward 先能解析 primary / backup / weight / max_fails / fail_timeout。
- selector 能根据失败历史避开 candidate。

### 阶段 2：连接阶段 next upstream

- stream stack 支持 candidate list 的连接阶段 retry。
- HTTP tunnel upstream 支持连接阶段 retry。
- HTTP direct upstream 支持 connect / TLS handshake 阶段 retry。
- executor 更新 failure state。

### 阶段 3：HTTP proxy_next_upstream 增强

- 支持受限的 HTTP 状态码 retry。
- 增加 body replay 策略和大小限制。
- 区分幂等和非幂等请求默认策略。

### 阶段 4：高级选择策略

- `hash $key` / consistent hash。
- provider-first 的 `server -> routes` 扩展。
- RTT / least-time / cost-aware 策略，通过 tunnel_mgr 的批量 query 接口消费 URL history，不在 forward 内部重复维护 RTT 表。
- Gateway Probe API（由 tunnel_mgr 提供，详见 `tunnel_mgr基于url状态查询需求.md`）与 selector 统计联动。

## 9. 非目标

第一阶段不做：

- 自动发现 direct IP。
- 自动发现 relay。
- direct 失败后隐式扩散到任意 relay。
- 复杂业务成本判断。
- 流已经转发后的透明迁移。
- 不受限制的 HTTP request body replay。

这些能力如果需要，应由调度器、应用层或后续显式需求提供，而不是塞进 forward 的默认行为。
