# BuckyOS 边缘 Region 的探测需求

## 1. 文档定位

本文定义 BuckyOS 在首次激活前选择边缘 Region 的整体协议和流程，重点描述
`cyfs-sn` 服务端与 SN 客户端之间的职责边界。

本文包含两个主要部分：

1. **协议设计**：`cyfs-sn` 通过一个匿名可读的 JSON 配置文件，发布它当前支持的
   Region，以及它认为可以代表这些 Region 的公共探测 URL；客户端把手工选择或自动
   探测得到的 Region 通过 `auth.register.region` 传回 SN。
2. **区域自动探测流程**：BuckyOS `node_active` 在调用 `auth.register` 前获取配置、
   测量候选 Region、选择结果并完成降级的流程。

`node_active` 的实现不在 `cyfs-gateway` 工程内。本文对这部分只定义调用时机、输入、
输出、算法下限和异常语义，供 BuckyOS 客户端实现。

### 1.1 当前实现基础与新增范围

当前代码已经具备注册时提交区域偏好的能力：

- [`SnAuthRegisterReq`](../../src/components/cyfs-gateway-api/src/sn_client.rs) 已包含可选的
  `region: Option<String>`；
- `SnClient::register` 会把该字段作为 `auth.register` 参数发送给 `cyfs-sn`；
- `cyfs-sn` 将其规范化后作为 relay 调度的**非可信区域偏好**，而不是用户真实地理位置
  或权限依据；
- 未传、非法或未知 Region 不应导致注册失败，服务端仍可使用请求源 IP 的 GeoIP 结果
  和自身 fallback 策略完成 relay 分配。

本文新增定义的是：

- SN 如何发布 Region 探测配置；
- 配置中的 Region 与 `auth.register.region` 如何使用同一命名空间；
- `node_active` 如何在注册前产生该可选字段；
- 手工选择、自动探测、缓存和失败降级之间的优先级。

当前 `cyfs-gateway` 已实现 Region 配置 DTO/校验、`sn_client` 匿名 GET helper，以及
`cyfs-sn` 的文件加载、匿名发布、ETag/缓存和失败降级；`node_active` 探测器仍不在本仓库
实现。

---

## 2. 目标与非目标

### 2.1 目标

- 允许用户在激活时手工选择 Region。
- 在用户选择“自动”时，客户端可根据当前网络出口自动选择 Region。
- SN 可通过修改配置文件增加、删除或调整 Region 和探测 URL，客户端不需要升级。
- Region 探测不受某一台 BuckyOS 业务节点的 CPU、负载或应用处理时间直接影响。
- 配置获取或探测失败时，Region 选择本身不阻断账号注册。
- 客户端和服务端对 `region_id`、缺省值、未知值和重试行为有一致理解。

### 2.2 非目标

本机制不负责：

- 判断用户真实所在的国家、城市或经纬度；
- 恢复 VPN、代理或 Private Relay 背后的真实位置；
- 将 Region 作为身份、权限、合规、计费或访问控制依据；
- 精确测量端到端带宽；
- 选择 Region 内的具体 relay、SN 或 Gateway 节点；
- 代替业务节点的健康检查和负载均衡。

本机制回答的是：

> 在当前 SN 发布的候选 Region 中，当前客户端的网络出口连接哪个 Region 的公共网络
> 锚点更近？

这个答案是调度偏好，不是地理事实。

### 2.3 客户端简单性原则

Region 探测配置不是让客户端自行发现全球网络拓扑，而是由配置构造者把复杂的运营判断
预先整理成一组可以机械执行的候选项。责任边界是：

> 配置构造者负责保证 `region_id -> probe_urls` 映射准确；客户端只负责按固定、简单、
> 可预测的规则执行配置。

因此客户端不负责：

- 判断一个 URL 实际位于哪个 Region；
- 对同一 URL 解析出的多个 IP 做竞速、聚类、投票或地理归因；
- 使用 GeoIP、traceroute、ASN 等信息修复错误配置；
- 自动发现配置外的新 Region 或探测地址；
- 根据复杂启发式规则猜测配置构造者的意图。

配置越复杂，越应由配置生成、发布前校验和运维流程消化，而不是增加所有客户端的实现
复杂度。客户端只需实现一套与 Region 数量和 URL 数量无关的通用流程。

---

## 3. 术语和角色

### 3.1 Region

BuckyOS 的逻辑服务区域，由稳定的 `region_id` 标识，例如 `jp`、`us-west`、
`eu-central`。Region 不要求与国家或行政区一一对应。

### 3.2 公共探测 URL

SN 运维方认为可以代表某个 Region 网络路径的公共 URL。第一版客户端只使用 URL 的
scheme、host 和 port 建立 TCP 连接，不把 HTTP 响应体或业务处理时间计入 Region 评分。

配置中的映射表达的是 SN 的运营判断：

```text
region_id -> 一组可代表该 Region 的公共 URL
```

它不意味着公共 URL 的提供方认可或保证该 Region 归属。

### 3.3 Region 探测配置

由 `cyfs-sn` 匿名发布的 JSON 文档，包含 schema 版本、配置版本、有效期、候选 Region、
公共探测 URL 和客户端探测策略。

### 3.4 手工 Region

用户在 `node_active` 界面中明确选择的 Region。手工选择优先于自动探测，但传给 SN 后
仍然只是非可信偏好。

### 3.5 自动 Region

客户端依据 Region 探测配置和当前网络测量结果选择的 Region。

### 3.6 Region 与 Service Node

Region 探测只决定逻辑区域，具体节点由服务端调度：

```text
选择 Region -> auth.register(region?) -> SN relay manager -> 选择具体 relay
```

客户端不得通过注册参数指定具体 relay node。

---

# 第一部分：协议设计

## 4. 端到端协议

目标流程如下：

```text
node_active 已获得目标 SN 地址
        |
        |  GET Region 探测配置（匿名）
        v
cyfs-sn 返回 Region 列表和每个 Region 的公共探测 URL
        |
        v
用户手工选择，或 node_active 并行探测并选择 Region
        |
        |  auth.register(..., region?)
        v
cyfs-sn 规范化 region，并把它作为 relay 调度偏好
        |
        v
relay manager 结合 region、可信 source IP、健康度和 fallback 选择具体 relay
```

配置获取发生在 `auth.register` 之前，因此配置接口必须匿名可读，不依赖 access token、
已创建账号或已激活设备。

### 4.1 可选增强与直接注册路径

Region 自动探测是注册前的**可选增强**，不是注册协议的必选握手。以下情况都允许客户端
跳过整个配置和探测流程，直接进入 `auth.register`：

- SN 没有发布配置文件；
- 客户端版本不支持该配置 schema；
- 配置获取、解析、DNS 或测速失败；
- 客户端因启动时序、总超时或产品策略没有执行该流程；
- 旧客户端根本没有实现 Region 自动探测。

直接注册时沿用现有可选字段逻辑：客户端已有用户手工选择或其他可信的 `region_id` 就
提交 `Some(region_id)`；没有就提交 `None`，即在 JSON 中省略 `region`。服务端随后按现有
source IP / GeoIP 和 relay fallback 流程确定区域及具体 relay。

客户端不得为了等待 Region 配置而无限重试或阻塞注册。配置获取和探测只能占用一个有界
时间窗口；窗口结束仍无结果时必须 fail open，继续调用注册接口。SN 也不得要求注册请求
携带配置版本、探测证明或非空 `region`。

## 5. Region 探测配置的发布

### 5.1 推荐访问方式

第一版定义一个独立于 kRPC 的静态 JSON 资源：

```http
GET /kapi/sn/region-probe-config.json HTTP/1.1
Host: <sn-host>
Accept: application/json
```

推荐响应：

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: public, max-age=300
ETag: "<config-version-or-content-hash>"
```

使用静态 GET 而不是 `auth.*` RPC 的原因是：该文档在激活前读取、无需会话、适合 HTTP
缓存，并且可以由运维工具独立生成和校验。

服务端应支持 `If-None-Match`，内容未变化时可返回 `304 Not Modified`。响应不得设置账号
cookie，也不得根据未认证用户返回包含敏感信息的差异化内容。

状态码语义：

| 状态 | 客户端语义 |
|---|---|
| `200` | 解析并校验配置 |
| `304` | 使用与 ETag 对应的本地缓存配置 |
| `404` | 当前 SN 没有启用 Region 探测配置；直接注册，有已有 Region 就沿用，否则省略 |
| `5xx`、超时或网络错误 | 尝试未过期缓存；无缓存时直接注册，有已有 Region 就沿用，否则省略 |

### 5.2 服务端配置来源

`cyfs-sn` 的目标实现应从独立文件加载该 JSON 文档，例如由服务配置指定：

```yaml
region_probe_config_path: /etc/cyfs-sn/region-probe-config.json
```

字段名称可以在实现阶段与现有 `SNServerConfig` 风格统一，但必须满足以下行为：

- Region 和公共 URL 的事实来源是该文件，不在 handler 中硬编码；
- 服务端在启动或热加载时完成 schema、Region 唯一性、URL 和时间字段校验；
- 文件无效时不得发布半解析配置；对外返回明确不可用状态并记录诊断日志；
- 文件更新应原子替换，客户端在一次请求中只能看到完整旧版本或完整新版本；
- Region 集合应与 relay manager 使用同一 `region_id` 命名空间；
- 配置只包含公开信息，不得包含 relay 内网地址、密钥、token 或运维备注。

配置可以由每个 SN 独立维护。不同 SN 如覆盖不同服务区域，可以发布不同 Region 集合；
客户端必须以本次实际注册的目标 SN 返回的配置为准。

## 6. 配置格式

### 6.1 示例

```json
{
  "schema_version": 1,
  "config_version": "2026-08-02.1",
  "generated_at": "2026-08-02T12:00:00Z",
  "expires_at": "2026-08-03T12:00:00Z",
  "policy": {
    "probe_method": "tcp_connect",
    "samples_per_url": 2,
    "connect_timeout_ms": 1500,
    "round_timeout_ms": 3000,
    "max_concurrency": 8,
    "ip_family": "ipv4",
    "minimum_valid_urls": 2,
    "confident_ratio": 0.75,
    "cache_ttl_sec": 21600
  },
  "regions": [
    {
      "region_id": "jp",
      "priority": 100,
      "probe_urls": [
        {
          "id": "jp-provider-a",
          "url": "https://jp-a.probe.example/",
          "provider": "provider-a"
        },
        {
          "id": "jp-provider-b",
          "url": "https://jp-b.probe.example/",
          "provider": "provider-b"
        }
      ]
    },
    {
      "region_id": "us-west",
      "priority": 90,
      "probe_urls": [
        {
          "id": "us-west-provider-a",
          "url": "https://us-west-a.probe.example/",
          "provider": "provider-a"
        },
        {
          "id": "us-west-provider-b",
          "url": "https://us-west-b.probe.example/",
          "provider": "provider-b"
        }
      ]
    }
  ]
}
```

示例中的 `.example` URL 只用于说明格式，不能直接用于生产探测。

### 6.2 顶层字段

| 字段 | 必选 | 语义 |
|---|---:|---|
| `schema_version` | 是 | 协议结构主版本；第一版固定为整数 `1` |
| `config_version` | 是 | 本 SN 配置修订号；内容变化时必须变化 |
| `generated_at` | 是 | RFC 3339 生成时间 |
| `expires_at` | 是 | RFC 3339 失效时间 |
| `policy` | 是 | 本轮探测的统一策略 |
| `regions` | 是 | 当前 SN 允许客户端选择的候选 Region，至少一项 |

`schema_version` 用于判断客户端能否理解文档，`config_version` 用于缓存失效和诊断，二者
不能混用。

客户端遇到未知字段必须忽略；遇到不支持的 `schema_version`、缺少必选字段、重复 ID 或
非法值时，应将整份配置视为不可用，不得猜测字段含义。

### 6.3 Region 字段

| 字段 | 必选 | 语义 |
|---|---:|---|
| `region_id` | 是 | 可直接放入 `auth.register.region` 的 canonical ID |
| `priority` | 否 | 分数相同时的稳定排序依据；数值越大优先级越高，缺省为 `0` |
| `probe_urls` | 是 | 代表该 Region 的公共探测 URL，生产配置至少两项 |

`region_id` 必须：

- 在同一份配置内唯一；
- 使用小写 ASCII 字母、数字和单个连字符；
- 符合 `[a-z0-9]+(?:-[a-z0-9]+)*`；
- 长度不超过 128 字节；
- 与 SN relay 配置中的 Region label 使用相同语义。

服务端必须发布 canonical ID；客户端成功解析后应原样回传，不自行翻译为国家名、城市名
或本地化文本。

### 6.4 Probe URL 字段

| 字段 | 必选 | 语义 |
|---|---:|---|
| `id` | 是 | 配置内唯一且稳定的锚点 ID，用于缓存和诊断 |
| `url` | 是 | 公共探测 URL；第一版只允许 `https` URL |
| `provider` | 否 | 公共基础设施提供方，仅用于诊断和锚点分散 |

`url` 必须是 absolute URL，不得包含 userinfo。客户端第一版应只允许本地安全策略认可的
端口，默认只允许 `443`。同一个规范化后的 origin 不应同时代表多个 Region，否则该锚点
不能提供区域区分能力。

第一版 `tcp_connect` 探测从 URL 派生目标：

```text
https://host[:port]/path -> TCP connect(host, port 或 443)
```

客户端不发送 HTTP 请求，不下载响应体，也不把 TLS 或 HTTP 处理时间计入评分。保留完整
URL 是为了使配置可读、可扩展，并为未来增加 `http_head` 等探测方法留下空间；第一版的
path 不参与 TCP 评分。

一个 URL 即使解析出多个 IP，也仍然只算一个 URL 锚点。第一版规定如下简单默认逻辑：

1. 每轮探测开始时只解析一次该 URL；
2. 按系统 resolver 返回顺序，选择第一个符合 `ip_family` 且通过公网地址安全检查的 IP；
3. 本轮该 URL 的所有样本固定使用这个 IP；
4. 该 IP 连接失败时把本 URL 记为失败，不再对其余 IP 竞速或逐个重试。

客户端不得把同一域名的多个 IP 计成满足 `minimum_valid_urls` 的多个独立锚点，也不得选择
其中最快的 IP 作为该 URL 的结果。这样一个测量结果始终能明确归因到“配置中的一个 URL”，
不会再展开成客户端自行生成的第二层探测集合。

### 6.5 Policy 字段

| 字段 | 第一版建议值 | 约束 |
|---|---:|---|
| `probe_method` | `tcp_connect` | 未知方法不能静默按 TCP 执行 |
| `samples_per_url` | `2` | 建议范围 `1..=3` |
| `connect_timeout_ms` | `1500` | 单次连接超时 |
| `round_timeout_ms` | `3000` | 整轮探测硬超时 |
| `max_concurrency` | `8` | 限制同时连接数 |
| `ip_family` | `ipv4` | 第一版统一为 `ipv4` |
| `minimum_valid_urls` | `2` | Region 获得正常置信度所需的不同 URL 数 |
| `confident_ratio` | `0.75` | 最优分数与次优分数的明确差异阈值 |
| `cache_ttl_sec` | `21600` | 自动探测结果最长缓存 6 小时 |

客户端应对策略值设置本地安全上限。例如，即使配置给出更大数值，也不能突破本地的最大
URL 数、最大并发数、单次超时和整轮超时。

## 7. 公共探测 URL 的运营要求

每个 Region 应配置至少两个、推荐三个来自不同服务或提供方的 URL。URL 应满足：

- 网络落点明确位于目标 Region；
- 不使用全球 Anycast、全球 CDN、Global Accelerator 或自动就近入口；
- 公网可解析且目标 TCP 端口长期开放；
- 完成 TCP 建连不需要认证；
- 域名和区域属性相对稳定；
- 不把解析得到的临时 IP 固化到配置；
- 单个 URL 故障时，其余 URL 仍能代表该 Region；
- 已确认公共服务的使用方式和频率不会违反提供方规则。

配置构造者必须承担 URL 准确性和 DNS 复杂性：

- 发布前检查 URL 当前和可能轮转出的所有 A/AAAA 记录都具有相同的 Region 语义；
- 不得配置可能跨 Region 返回地址的全局负载均衡域名；
- 如果需要表达多个独立落点，应显式配置为多个 `probe_urls`，而不是依赖一个域名背后的
  多 IP 让客户端自行展开；
- 确保任意一个可被客户端默认选中的 IP 都足以代表该 URL 所属 Region；
- 定期复核 DNS、Anycast/CDN 属性、端口可达性和实际网络落点，变化时更新
  `config_version`；
- 在发布前通过离线工具或灰度探测发现错误映射，不把纠错责任转移给客户端算法。

如果某个 URL 无法满足这些条件，应更换为区域属性更明确的 URL。客户端无需为不准确的
URL 增加更复杂的推断或补偿逻辑。

BuckyOS 自有业务节点可以作为补充锚点，但不能成为某个 Region 的唯一锚点。业务节点的
HTTP、TLS、WebSocket 或应用健康状态必须在 Region 选择之后单独判断。

## 8. `auth.register.region` 契约

### 8.1 请求格式

有有效选择结果时，客户端在现有注册请求中设置：

```json
{
  "method": "auth.register",
  "params": {
    "name": "alice",
    "email": "alice@example.com",
    "pwd_hash": "...",
    "active_code": "...",
    "region": "jp"
  }
}
```

没有有效结果时必须省略 `region` 或发送 JSON `null`，不得发送空字符串、`unknown`、
`auto`、`nearest` 或客户端自造的 fallback ID。

当前协议只传最终 `region_id`，不传以下信息：

- `manual` 或 `automatic` 来源；
- 各 Region 分数；
- 公网 IP 或网络标识；
- 探测 URL 和逐次样本；
- 客户端希望指定的具体 relay。

以后如需这些信息，应新增独立、可选且经过隐私评审的字段，不能改变 `region` 的既有语义。

### 8.2 客户端语义

`region` 可以来自：

1. 用户本次明确的手工选择；
2. 同一目标 SN、同一配置版本和同一网络环境下的有效缓存；
3. 本次自动探测结果。

正常情况下，客户端只能提交当前 SN 配置中出现的 canonical `region_id`。唯一例外是本次
配置暂时不可用、但用户此前明确保存了一个由该 SN 有效配置验证过的手工值；此时可以继续
提交该值。没有这种手工值时，客户端应省略该字段。

### 8.3 服务端语义

`cyfs-sn` 必须继续遵守现有注册语义：

- `region` 是 relay 调度偏好，不是账号所在地字段；
- 服务端 trim 输入、转为小写，并把空白、`_`、`/`、`.` 和重复分隔符规范为 `-`；
- 非法、过长、未知或当前没有匹配节点的值只使该提示失效，不使注册失败；
- 服务端不能因为客户端提交了 `region` 而信任客户端 IP、身份或地理位置；
- 注册请求的 source IP 只能来自服务端可信连接上下文，不能由 RPC params 指定；
- relay manager 负责在可用节点中选择具体 relay，客户端不能指定 relay ID；
- relay 暂时不可用时，账号注册仍成功，分配可进入现有 pending/补偿流程。

服务端调度时的概念优先级为：

```text
仍有效的 sticky assignment
    -> 客户端 preferred region
    -> 服务端观察到的 source IP / GeoIP 规则
    -> relay manager fallback
    -> 暂无分配，进入补偿流程
```

Region 探测配置与 relay 配置发生短暂不一致时，也必须按上述降级语义处理，不能把部署
配置漂移转化为注册错误。

### 8.4 未执行探测时的兼容语义

服务端不能区分“客户端没有探测能力”“配置未下发”“探测失败”和“客户端主动跳过”，也
不需要区分。当前注册协议只关心最终是否有 `region`：

```text
有 region    -> 作为非可信 preferred region 参与调度
没有 region  -> 忽略客户端区域偏好，直接执行服务端 GeoIP / fallback
```

这保证了配置发布端、支持自动探测的新客户端和旧客户端可以独立升级。Region 配置接口
下线或异常也不会改变 `auth.register` 的可用性和兼容性。

---

# 第二部分：区域自动探测流程

## 9. `node_active` 中的调用时机

自动探测属于 BuckyOS `node_active`，应位于“已选定目标 SN、网络可用”之后，
`auth.register` 之前：

```text
读取激活参数和目标 SN
        -> 读取手工/自动 Region 设置
        -> 获取并校验 Region 探测配置
        -> 必要时执行自动探测
        -> 生成 Option<region_id>
        -> 固定到本次激活上下文
        -> 调用 auth.register(region?)
```

Region 探测不是注册的前置成功条件。只要 SN 注册接口可达，即使配置接口、DNS 或所有
探测 URL 失败，客户端也应使用已有手工 Region；没有手工 Region 时省略 `region`，然后
继续注册。是否成功完成 Region 探测不能成为 `node_active` 状态机中的阻塞状态。

## 10. 手工选择与自动选择的优先级

`node_active` 应提供“自动”和当前配置中各 Region 的手工选项。决策顺序为：

1. **本次手工选择**：直接使用所选 canonical `region_id`，可以跳过自动测速。
2. **已保存的手工选择**：若仍存在于当前配置中，则继续使用；若已下线，提示用户重新
   选择或切回自动。
3. **有效自动缓存**：仅在目标 SN、`config_version` 和网络环境均未变化时使用。
4. **本次自动探测**：按第 11 节执行。
5. **无结果**：返回 `None`，注册时省略 `region`。

手工值来自先前有效配置、但本次配置暂时无法获取时，可以作为用户明确偏好继续提交；
客户端必须在本地标记其配置状态未知，不能将其描述为本次自动探测结果。

手工选择不代表 SN 必须在该 Region 分配 relay。最终调度仍受服务端节点健康、容量、
Region 配置和 fallback 约束。

## 11. 自动探测算法

### 11.1 配置获取与校验

客户端：

1. 从本次将要调用 `auth.register` 的同一个 SN 获取配置；
2. 校验 HTTPS 来源、HTTP 状态、JSON、schema 版本、有效期、字段范围和 ID 唯一性；
3. 只保留客户端支持的探测方法和 IP family；
4. 对 URL 数、并发、超时和总时长应用本地安全上限；
5. 配置无效时尝试未过期缓存，否则返回无结果。

客户端不得把一个 SN 的配置用于另一个 SN，缓存键至少包含规范化后的 SN base URL 和
`config_version`。

### 11.2 DNS 解析

客户端并行解析所有候选 URL 的 host。DNS 解析耗时不计入 TCP Region Score，以减少
本地 DNS 缓存、DoH 和解析器差异造成的偏差。

DNS 失败只使对应 URL 本轮失败。解析结果必须再次进行地址安全检查，拒绝连接到：

- loopback；
- link-local；
- RFC 1918 / ULA 等私网地址；
- unspecified、multicast 和其他非公网保留地址。

该检查必须在 DNS 解析后执行，防止配置错误或 DNS rebinding 把客户端变成内网探测器。

安全过滤完成后，客户端只选择第一个符合条件的 IP，并将它固定到本轮探测；不探测同一
URL 的其他 IP。URL 背后的所有 IP 是否具有一致的区域含义，由配置构造者保证。

### 11.3 并行 TCP 测量

第一版统一使用 IPv4 TCP connect：

```text
解析得到公网 IPv4 socket address
        -> start timer
        -> connect()
        -> TCP handshake 完成
        -> stop timer
        -> 立即关闭 socket
```

客户端不发送 HTTP 请求、不进行 TLS handshake，也不下载数据。以下时间不计入评分：

- DNS 解析；
- TLS 证书校验；
- HTTP 响应；
- WebSocket upgrade；
- 服务端业务处理；
- 响应体下载。

所有 Region 应交错并行探测，不能先完成一个 Region 的全部样本再探测下一个。并发数和
整轮时间必须受 `max_concurrency`、`connect_timeout_ms` 和 `round_timeout_ms` 限制。

### 11.4 URL 与 Region 评分

每个 URL 产生 `samples_per_url` 个样本。连接成功的毫秒数为有效样本，超时、DNS 失败、
连接错误和任务取消为失败样本。

为避免同一 URL 的重复样本主导结果，先计算：

```text
URL Score = 该 URL 所有有效样本中的最小值
```

再计算：

```text
Region Score = 不同 URL Score 中的第二小值
```

使用第二小值可避免某个异常快、位置错误或路由特殊的单一 URL 决定整个 Region。

- 至少两个 URL 有效：Region 正常可评分；
- 只有一个 URL 有效：可降级使用该 URL Score，但结果必须标记低置信度；
- 没有 URL 有效：Region 不可评分。

### 11.5 选择与置信度

从可评分 Region 中按以下顺序稳定排序：

1. `region_score` 升序；
2. `priority` 降序；
3. `region_id` 字典序升序。

第一项为最佳 Region。若同时存在最佳和次优 Region，可计算：

```text
confidence_ratio = best_score / second_score
```

当 `confidence_ratio <= policy.confident_ratio` 且最佳 Region 有足够的不同有效 URL 时，
结果可标记为高置信度；否则标记为低置信度。低置信度仍可以作为 `region` 提交，因为该
字段本身只是服务端调度提示。

如果所有 Region 都不可评分，则自动探测返回 `None`，不得把列表第一项伪装成测速结果。

## 12. 缓存和激活重试

### 12.1 配置缓存

客户端可按 HTTP `ETag` 和 `expires_at` 缓存配置。只有未过期且 schema 仍受支持的缓存
才能用于新的自动探测。

### 12.2 结果缓存

自动结果缓存至少包含：

- SN base URL；
- `config_version`；
- 选中的 `region_id`；
- 各 Region Score 和置信度；
- 测量时间和失效时间；
- 不含 SSID 明文、公网 IP 的网络环境摘要。

以下情况使自动结果缓存失效：

- 配置版本变化或 Region 被删除；
- 默认路由或主要网络接口变化；
- Wi-Fi、蜂窝、VPN 或代理状态变化；
- 缓存超过 `cache_ttl_sec`；
- 当前网络连接所选 Region 连续失败。

### 12.3 单次激活的一致性

一旦 `node_active` 为某次激活生成了 Region，应将该结果固定到本次激活上下文。因超时、
响应丢失或可重试错误再次发送同一个 `auth.register` 请求时，应继续使用同一个 `region`
和 `request_id`，不要在未知提交结果的情况下重新测速并改变 Region。

新发起的一次激活尝试可以重新读取配置和探测。

## 13. 客户端内部输出

建议 `node_active` 的 Region 选择模块输出类似结构：

```rust
struct RegionSelection {
    region: Option<String>,
    source: RegionSelectionSource,
    config_version: Option<String>,
    confidence: RegionConfidence,
    measured_at: Option<SystemTime>,
    regions: Vec<RegionMeasurement>,
}

enum RegionSelectionSource {
    Manual,
    Cache,
    Probe,
    None,
}
```

只有 `RegionSelection.region` 映射到 `SnAuthRegisterReq.region`。其他字段用于本地 UI、日志
和诊断，不属于当前 SN 注册协议。

## 14. 异常与降级矩阵

| 场景 | `node_active` 行为 | `auth.register.region` |
|---|---|---|
| 用户选择有效 Region | 跳过或忽略自动探测 | 提交手工 Region |
| 配置成功、探测成功 | 提交最佳 Region | `Some(region_id)` |
| 配置成功、结果低置信度 | 可提交最佳 Region并记录低置信度 | `Some(region_id)` |
| 配置 `404` | 不把它当注册错误，直接进入注册 | 有手工值则提交，否则省略 |
| 客户端未实现或主动跳过探测 | 直接进入注册 | 有手工值则提交，否则省略 |
| 配置超时或 `5xx`，有未过期缓存 | 使用缓存配置/结果 | 缓存有效时提交 |
| 配置无效或不支持，无缓存 | 记录错误并继续注册 | 有手工值则提交，否则省略 |
| 部分 URL 失败 | 用其余 URL 评分 | 有 Region 结果时提交 |
| 所有 Region 失败 | 不伪造 fallback 测速结果 | 省略 |
| SN 不认识客户端提交的 Region | 客户端无需重试注册 | 服务端忽略提示并 fallback |
| 目标 Region 暂无 relay | 客户端无需更换账号 Region | 注册成功，服务端 pending/补偿 |
| 网络完全离线 | 整体激活等待网络恢复 | 不单独归因于 Region 探测 |

## 15. 安全与隐私

### 15.1 配置可信性

- 配置必须从目标 SN 的可信 HTTPS 来源获取；
- 客户端不得接受重定向到不受信任 origin 后继续读取配置；
- 如 BuckyOS 已有配置签名机制，应复用签名和防回滚能力；
- `config_version` 和时间字段用于新鲜度判断，不能代替 TLS 或签名；
- 客户端必须限制 URL scheme、端口、数量、并发和超时。

### 15.2 隐私边界

完成 Region 选择不要求客户端向 SN 上传：

- 各 URL 的原始样本；
- GPS、国家、城市或经纬度；
- Wi-Fi SSID；
- 客户端看到的公网 IP；
- 手工或自动的选择来源。

当前 `auth.register` 只上传最终可选的 `region_id`。SN 自己从连接上下文观察到的 source IP
属于现有注册与 relay 调度边界，不能由客户端参数覆盖。

### 15.3 公共服务保护

- 默认每次激活最多探测配置允许的有限样本；
- 连接成功后立即关闭；
- 不发送无必要的 HTTP 请求；
- 不在后台高频持续探测；
- 运维方应定期检查 URL 的可用性、落点和服务条款。

## 16. 可观测性

### 16.1 客户端本地诊断

客户端应记录：

- SN base URL 的脱敏标识；
- schema/config version；
- 配置来自网络还是缓存；
- 各 URL 的解析/连接状态和耗时；
- 各 Region Score；
- 最终 Region、来源和置信度；
- 是否因错误省略 `region`。

默认日志不得包含 token、密码、激活码、完整公网 IP 或 Wi-Fi SSID。

### 16.2 SN 服务端诊断

服务端应记录和统计：

- 配置文件加载版本、成功/失败和最后更新时间；
- 配置 GET 的 `200`、`304`、`404`、`5xx` 数量；
- 注册请求中 Region 缺省、规范化成功、非法、未知和命中的数量；
- preferred Region、GeoIP 和 fallback 各自命中 relay 的比例；
- 因无可用 relay 进入 pending 的数量。

日志不得记录密码、token、激活码或完整 source IP。

---

## 17. 工程边界与实施项

### 17.1 `cyfs-gateway` / `cyfs-sn` 范围

- 定义 Region 探测配置 DTO 和 schema 校验；
- 为 `SNServerConfig` 增加外部配置文件入口；
- 在匿名 GET 路径发布配置，支持 ETag 和缓存；
- 校验配置 Region 与 relay Region 命名空间的一致性并提供诊断；
- 保持现有 `SnAuthRegisterReq.region` 和服务端非可信调度提示语义；
- 增加配置发布、非法配置、缓存、Region 规范化和 fallback 测试。

如 BuckyOS 客户端希望复用 Rust DTO，可以在 `cyfs-gateway-api` 中提供配置解析和 GET
helper；实际测速和 UI 不应因此放入 `cyfs-sn`。

### 17.2 BuckyOS `node_active` 范围（不在本仓库实现）

- 激活界面的“自动/手工 Region”选择；
- 配置获取、校验和缓存；
- DNS 解析、并发 TCP connect 测量和评分；
- 网络变化感知、结果缓存和激活重试固定；
- 将最终 `Option<region_id>` 写入 `SnAuthRegisterReq.region`；
- 客户端本地日志、诊断 UI 和隐私保护。

---

## 18. 验收标准

### 18.1 协议与 SN 服务端

- SN 启用 Region 配置时，未登录客户端能从目标 SN 获取有效配置。
- 启用的配置明确返回 Region 列表及每个 Region 的至少两个公共探测 URL。
- 新增 Region 或替换 URL 后，支持 schema v1 的客户端无需升级。
- 配置无效时不会发布部分内容，且不影响 `auth.register` 基本可用性。
- 配置中的 canonical `region_id` 可直接用于 `auth.register.region`。
- `region` 缺省、非法、未知或无匹配 relay 都不导致账号注册失败。
- SN 未配置 Region 文件时，旧客户端和新客户端都能直接完成注册。
- 服务端不要求客户端提交配置版本、探测证明或非空 `region`。
- 客户端不能通过注册参数指定 source IP 或具体 relay。

### 18.2 `node_active` 客户端

- 手工选择优先于自动探测，并原样提交 canonical ID。
- 自动模式在典型网络中稳定选择明显更近的 Region。
- 任意单个 URL 失败不会直接使整个 Region 或整轮探测失败。
- 同一 URL 解析出多个 IP 时只使用第一个符合条件的 IP，不进行多 IP 竞速或投票。
- 所有探测失败时省略 `region`，仍继续调用可达的注册接口。
- 客户端未执行探测时，有手工 Region 就沿用，没有就省略并让 SN fallback。
- DNS 解析到私网、回环或保留地址时不会发起连接。
- 配置版本或网络环境变化会使旧自动结果失效。
- 同一次注册重试不会改变已固定的 Region。

### 18.3 联调

- 使用可控延迟的多个测试 URL，验证客户端选择结果出现在
  `auth.register.region` 中。
- SN 能用该 Region 优先选择匹配 relay；无匹配时按 GeoIP/fallback 降级。
- 动态增加一个 Region 后，旧客户端能展示并探测它。
- 客户端不上传逐 URL 样本，SN 也不把 Region 当作身份或权限依据。

---

## 19. 结论

整个机制形成一个简单闭环：

```text
cyfs-sn 用配置声明“有哪些 Region、哪些公共 URL 可以代表它们”
        -> node_active 手工选择或自动测量
        -> auth.register 可选提交 region_id
        -> cyfs-sn 将其作为非可信调度偏好选择具体 relay
```

协议以 `region` 可选为重要的失败边界：能测出或用户明确选择时就提交；无法可靠判断时就
省略，由 SN 使用可信 source IP、relay 健康状态和 fallback 完成后续调度。这样既允许
客户端主动选择区域，也不会让区域探测成为首次激活的新单点故障。URL 是否准确代表某个
Region、DNS 后面的任意地址是否具有相同区域语义，由配置构造者保证；客户端不为配置错误
增加多 IP 竞速、地理推断或其他复杂补偿逻辑。
