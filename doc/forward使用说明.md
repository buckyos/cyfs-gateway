# CYFS Gateway `forward` 使用说明

本文档说明 Beta2.2 新版 `forward` 机制的用户可见语法、重试边界和推荐配置。设计与实现背景见 [forward 机制升级需求](forward机制升级需求.md)。

## 1. 先选择单目标还是候选组

### 1.1 单目标：不自动切换

```text
forward "http://127.0.0.1:8080"
forward "tcp:///127.0.0.1:9000"
forward "rtcp://device.example.zone/:7001"
```

单 URL 的语义保持不变：只尝试该目标一次，失败后直接返回错误。

### 1.2 旧多目标语法：只选择一个目标

```text
forward round_robin tcp:///10.0.0.1:9000 tcp:///10.0.0.2:9000
forward ip_hash tcp:///10.0.0.1:9000,weight=3 tcp:///10.0.0.2:9000,weight=1
```

如果没有使用任何 group 选项，这仍是兼容模式：`forward` 先选出一个 URL，再返回普通的 `forward "<url>"` 动作。所选目标建链失败时，同一次请求不会尝试另一个目标。

### 1.3 候选组：执行阶段自动尝试下一个目标

需要同一次请求内故障切换时，显式配置 `--next-upstream`，并建议同时配置尝试次数和总时间预算：

```text
map-create primary_peers;
map-add primary_peers "tcp:///10.0.0.1:9000" 100;
map-add primary_peers "tcp:///10.0.0.2:9000" 100;

map-create backup_peers;
map-add backup_peers "rtcp://backup.example.zone/:9000" 100;

forward round_robin \
        --map $primary_peers \
        --backup-map $backup_peers \
        --group app-api \
        --next-upstream error,timeout \
        --tries 3 \
        --next-upstream-timeout 5s \
        --max-fails 1 \
        --fail-timeout 10s;
```

这个命令会生成内部 `ForwardPlan`。执行层按计划中的候选顺序建链；当前候选发生允许重试的错误时，才继续尝试下一个候选。

`--group app-api` 只是失败状态的分组名，不是预定义 upstream 的查找名称。候选 URL 仍必须通过 inline 参数、`--map` 或 `--backup-map` 显式提供。

## 2. 命令语法

```text
forward [round_robin|rr|ip_hash|hash|consistent_hash|least_time] \
        [<url>[,weight=N] ...] \
        [--map <primary_map>] \
        [--backup-map <backup_map>] \
        [--group <name>] \
        [--next-upstream <conditions>|off] \
        [--tries <count>] \
        [--next-upstream-timeout <duration>] \
        [--max-fails <count>] \
        [--fail-timeout <duration>] \
        [--hash-key <value>] \
        [--max-body-buffer <size>] \
        [--force-group]
```

### 2.1 upstream 输入

| 写法 | 含义 |
| --- | --- |
| `<url>` | inline 主候选，权重默认为 1 |
| `<url>,weight=N` | 带正整数权重的 inline 主候选 |
| `--map <map>` | map 的 key 是主候选 URL，value 是正整数权重 |
| `--backup-map <map>` | map 的 key 是备用候选 URL，value 是正整数权重 |

upstream 必须是带 scheme 的合法 URL，例如：

```text
http://127.0.0.1:8080
https://api.example.com
tcp:///127.0.0.1:9000
udp:///127.0.0.1:2300
tls:///example.com:443
rtcp://remote-stack-id/:80
rudp://remote-stack-id:2998/test:80
socks://user:pass@127.0.0.1:1080
```

URL 能被解析不代表当前入口一定支持该 scheme。HTTP、stream、datagram 入口的实际支持范围见 [数据转发说明](skills/cyfs-gateway-config-spec/references/data-forwarding.md)。

### 2.2 选择算法

| 算法 | 行为与适用场景 |
| --- | --- |
| `round_robin` / `rr` | 默认算法。按权重轮换首选候选，适合普通无状态服务池 |
| `ip_hash` | 按来源 IP 稳定选择首选候选；依次读取 `REQ.real_source_ip`、`REQ.source_ip`、`REQ_remote_ip` |
| `hash` | 按 `--hash-key` 的值做加权 hash，适合已有业务亲和键的场景 |
| `consistent_hash` | 按 `--hash-key` 的值做一致性 hash，候选变化时减少 key 重映射 |
| `least_time` | 根据 tunnel manager 已有 URL 历史中的 RTT 排序；查询失败、超时或数据不足时保留原顺序 |

`hash` 和 `consistent_hash` 必须提供 `--hash-key`。传入的是 process chain 已经解析出的值，而不是让执行层稍后求值的表达式：

```text
forward consistent_hash \
        --hash-key "$session_id" \
        --map $primary_peers \
        --next-upstream error,timeout \
        --tries 2;
```

`least_time` 只读取已有历史，不会在每个业务请求上强制发起主动探测：

```text
forward least_time \
        --map $primary_peers \
        --next-upstream error,timeout \
        --tries 3;
```

### 2.3 重试与失败状态参数

| 参数 | 说明 |
| --- | --- |
| `--next-upstream` | 允许继续尝试的条件，逗号分隔；`off` 表示关闭 |
| `--tries` | 单次请求最多尝试的候选数；配置重试条件但省略该项时，最多尝试全部候选 |
| `--next-upstream-timeout` | 所有候选尝试共享的总墙钟时间预算，不是每个候选各自的预算 |
| `--max-fails` | 候选进入临时失败窗口前的失败次数，默认 1 |
| `--fail-timeout` | 临时失败窗口，默认 10 秒 |
| `--group` | 失败状态分组名；省略时根据候选集合自动生成稳定 key |
| `--force-group` | 即使计划退化为单 URL，也强制输出内部 `forward-group` 动作；通常无需使用 |

duration 支持 `ms`、`s`、`m`、`h`，裸整数按毫秒处理。

可用的 `--next-upstream` 条件：

| 条件 | 适用入口 | 含义 |
| --- | --- | --- |
| `error` | HTTP、stream、datagram | 建链或请求准备阶段发生错误 |
| `timeout` | HTTP、stream、datagram | 总重试预算耗尽或一次尝试被剩余预算截断 |
| `http_5xx` | HTTP | 任意 5xx 响应 |
| `http_502` / `http_503` / `http_504` | HTTP | 指定状态码响应 |
| `non_idempotent` | HTTP | 允许非幂等方法参与状态码重试；它是权限修饰条件，不会单独触发重试 |
| `invalid_header` | 暂不建议使用 | 当前只保留了解析和计划格式，执行层尚未实现对应触发判断 |

只有“配置了非空重试条件、`tries > 1`、并且至少有两个候选”时，执行层才可能切换候选。仅配置 `--group`、`--tries` 或 `--max-fails` 不会自动开启重试。

## 3. 不同入口的重试边界

### 3.1 Stream 转发

TCP、TLS、RTCP 等 stream 入口只在打开目标 stream 的阶段重试。某个目标成功建链并开始双向复制后，后续断流会直接返回，不会静默切换到另一个目标。

### 3.2 Datagram 转发

UDP、RUDP 等 datagram 入口只在创建目标 datagram client 的阶段重试。client 创建成功并开始转发后，不会在同一个 session 内切换目标。

### 3.3 HTTP 转发

HTTP 有两种重试方式：

1. `error` / `timeout`：在请求体尚未被上游消费时，可以切换候选。
2. HTTP 状态码条件：需要缓冲并重放请求体，受方法和缓冲上限约束。

推荐的幂等请求配置：

```text
forward round_robin \
        --map $http_peers \
        --next-upstream error,timeout,http_502,http_504 \
        --tries 3 \
        --next-upstream-timeout 5s \
        --max-body-buffer 64KB;
```

状态码重试默认只允许 `GET`、`HEAD`、`PUT`、`DELETE`、`OPTIONS`、`TRACE`。`POST`、`PATCH` 和自定义方法默认只走建链阶段重试。确实能接受重复提交风险时，才显式加入 `non_idempotent`：

```text
--next-upstream error,timeout,http_502,http_504,non_idempotent
```

当配置了 HTTP 状态码条件而未设置 `--max-body-buffer` 时，默认上限为 64 KiB；设置为 `0` 会关闭状态码重试。size 支持 `B`、`K`/`KB`、`M`/`MB`、`G`/`GB`，裸整数按字节处理。

如果请求体超过已启用的缓冲上限，当前实现会返回请求错误，不会丢弃请求体后继续转发。因此应根据业务请求体大小设置足够的上限，或不启用状态码重试。

## 4. Primary、backup 与临时失败窗口

候选排序遵循以下规则：

1. 健康的 primary 候选优先。
2. 健康的 primary 不可用时进入 backup 候选。
3. 达到 `max_fails` 的候选在 `fail_timeout` 内被排到健康候选之后，但仍保留为最终兜底。
4. 一次成功会清除该 group 下该 URL 的失败状态。

失败状态只保存在当前 gateway 进程内，不落盘，也不在多个 gateway 实例之间同步。相同的 `--group` 名会共享同一组 `group + URL` 失败状态；不同服务池不要复用同一个名字。

## 5. Provider-first 高级形态的当前限制

实现中已经存在 `--server-map` 和 `--provider-retry-scope routes_only|across_servers`，用于表达 `hash key -> provider -> route`。当前版本能解析模型并让同一 provider 的 routes 在候选顺序中相邻，但执行层尚未按 `provider-retry-scope` 强制截断跨 provider 重试；命令预检目前也仍要求同时存在 inline upstream、`--map` 或 `--backup-map`，因此不能只配置 `--server-map`。

因此，对必须严格保持 provider 亲和的有状态业务，不要把该参数当成隔离保证。当前应使用单 provider 候选、合适的 hash key 和受限的 `--tries`；普通无状态服务池优先使用 `--map` / `--backup-map`。

## 6. 排查清单

- 确认每个 upstream 都是带 scheme 的 URL。
- 确认入口支持目标 scheme，而不只是 URL 解析成功。
- 确认配置了 `--next-upstream`，且 `--tries` 大于 1。
- 确认 `--tries` 没有超过业务允许的重试成本，并设置总时间预算。
- HTTP 状态码重试时，确认方法可重放、请求体不超过缓冲上限。
- 检查 primary、backup、weight、`max_fails` 和 `fail_timeout` 是否符合预期。
- `ip_hash` 没有命中预期目标时，检查 process chain 中的来源 IP 字段。
- `least_time` 没有改变顺序时，检查 tunnel manager 是否已有对应 URL 的 RTT 历史。
