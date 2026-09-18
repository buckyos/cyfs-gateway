# RTCP / name-client 地址解析中的 DeviceInfo 范围约束 TODO

状态：**DONE（代码与回归测试）**

优先级：**P1**（安全边界 + 建链关键路径延迟）

主负责人：**`buckyos-base/name-client`**

接入负责人：**`cyfs-gateway` RTCP**

## 结论

这不是只在 RTCP 中调整一次地址来源优先级的问题。`DeviceInfo`（`info.json`）的可见
范围必须由 `name-client` 的地址解析 API 统一约束：

- 只有目标已经被可信上下文证明为**同 zone 的 device**时，才允许读取
  `DidDocType::Info`；
- 跨 zone、zone 关系未知、或目标不是 device 时，必须完全跳过 `Info`；
- “跳过”要求网络侧 **zero request**，不能先请求再把 404/超时当作正常结果；
- `Info` 是同 zone 的私有发现信息，不得通过公开的 `did:web` well-known 或 upper
  resolver 回退链路探测。

RTCP 负责把已经验证的目标类型/zone 关系传给 name-client，并在首次建 tunnel 和 stream
reconnect 两条路径上使用同一解析策略；它不应在本地复制一套 name-client provider
选择逻辑。

## 现场现象

客户端日志 `/opt/buckyos/logs/cyfs_gateway/cyfs_gateway.17737.log` 中：

1. `12:24:24.025`，DNS 已把 `us01.buckyos.ai` 解析为 `45.76.64.86`；
2. 同一时刻仍发起
   `GET /1.0/identifiers/did:web:us01.buckyos.ai?type=info`；
3. `12:24:24.179`，well-known miss 后又回退到
   `https://buckyos.ai/1.0/identifiers/did:web:us01.buckyos.ai?type=info`；
4. 直到 `12:25:39.254` 才注册 outbound tunnel。

从 DNS 已有可用 IP 到 tunnel 注册之间约有 **75.2 秒**。该时间间隔与串行等待
`Info` 的 upper-resolver 请求一致；它不是 RTCP TCP connect 或握手自身的超时。
当前 `WebProvider` 使用默认 `reqwest::Client`，该请求也没有 name-client 自己定义的明确
deadline。

`us01.buckyos.ai` 是跨 zone 的 SN/zone 目标，不是同 zone device；按设计不应发生任何
`Info` 请求。

## 修正前调用链

修正前 `name-client::NameClient::resolve_ips()` 的执行顺序是：

```text
DeviceDocument fixed IP
  -> NameInfo / DNS
  -> DeviceInfo(type=info)
  -> merge + sort
```

只要 DeviceDocument 没有提供 fixed IP，旧 `resolve_ips()` 就会在 DNS 之后无条件
`await resolve_device_info_ips()`。因此即使 DNS 已经拿到可用地址，跨 zone 的
`info.json` 404、upper-resolver 回退或网络超时仍会阻塞返回。

RTCP 有两个调用点：

- `RTcpInner::create_direct_tunnel()`：首次建立 control tunnel；
- `RTcpTunnel::collect_reconnect_candidates()`：每次 direct stream reconnect 重新解析。

后者曾让同一个错误请求在 tunnel 存活期间重复进入业务 stream 的关键路径。

## 设计约束

### 1. 先证明作用域，再选择 Info

是否读取 `Info` 不能根据目标自声明字段、普通 DNS、名字长相或 `Info` 请求结果来判断。
必须先从可信上下文得到以下两个事实：

1. 目标确实是 device；
2. 目标与本机属于同一个 zone。

两者缺任意一个都按 `InfoDisabled` 处理。裸 `did:dev` 本身不能表达 zone 关系；除非调用
方另有已经验证的 same-zone evidence，否则也不得读取 `Info`。

### 2. Info 只能走同 zone 私有信道

允许读取 `Info` 时，也只能查询可信的本地/zone resolver（`LocalAndZone` 或后续等价的
专用私有 provider）。禁止：

- `https://<did:web-host>/.well-known/info.json`；
- `did:web` upper resolver 的 `?type=info` 回退；
- BNS / 公网 method authority 的 Info 探测；
- 因本地/zone resolver miss，再降级到上述公网信道。

`Info` 当前属于 no-proof / unauthenticated 文档，更不能用公开 provider 的
best-available 行为扩大其读取范围。

### 3. 地址排序与访问权限分开

先修访问权限，再讨论地址候选优先级：

| 目标关系 | 是否允许 Info | 允许的 Info 来源 | 其它可用地址 |
| --- | --- | --- | --- |
| verified same-zone device | 是 | 仅 local/zone resolver | 可与 DNS 等候选合并后按现有 RTT 策略排序 |
| verified cross-zone device | 否 | 无 | DeviceDocument fixed IP、NameInfo/DNS 等 |
| zone / SN / owner 等非 device | 否 | 无 | 对应的公开地址来源 |
| unknown | 否（fail closed） | 无 | 不依赖私有 Info 的公开地址来源 |

同 zone 下 `Info` miss、错误或 deadline 到期，不得抹掉 DNS / DeviceDocument 已得到的
可用地址。允许的 `Info` 查询仍需一个短且明确的 deadline，避免本地 resolver 故障无限
扩大关键路径；缩短 timeout 只是纵深防御，不能替代跨 zone 的 zero-request 规则。

## name-client 主任务

- [x] 给地址解析增加显式的、可审计的作用域 API；示意：

  ```rust
  enum DeviceInfoPolicy {
      Disabled,
      VerifiedSameZone(/* trusted relation/evidence */),
  }

  async fn resolve_ips_with_options(
      &self,
      name: &str,
      options: ResolveIpOptions,
  ) -> NSResult<Vec<IpAddr>>;
  ```

  最终命名可调整，但不能只传一个容易被误用的 `include_info: bool`。

- [x] 没有 zone 上下文的通用 `resolve_ips(name)` 默认 `DeviceInfoPolicy::Disabled`。Beta2.2
  允许 breaking change；不要为旧行为保留跨 zone 的隐式 Info fallback。
- [x] 把 `DidDocType::Info` 的 provider 范围限制在 local/zone resolver；在 provider 路由
  层阻止 WebProvider、upper resolver 或公网 authority 被选中，而不是只靠调用者记得
  不调用。
- [x] 为允许的 Info 查询增加独立、短且可配置的 deadline。已有其它可用地址时，Info
  失败只记 channel outcome，不改变成功结果。
- [x] 增加结构化日志/metrics：target、target kind、zone relation、Info policy、skip reason、
  各地址信道耗时。不得记录 Info 文档正文或私网地址集合。
- [x] 明确 same-zone evidence 的生产者和生命周期。它必须来自本机可信 zone 配置、已验证
  的 Owner/Zone/Device 关系或等价权威结果，不能来自待解析目标的自声明内容。

### name-client 验收测试

- [x] cross-zone + DNS success：返回 DNS 地址，Info provider 调用次数为 0；
- [x] cross-zone + DNS miss：返回正常 NotFound/error，Info provider 调用次数仍为 0；
- [x] unknown relation：与 cross-zone 一样禁止 Info；
- [x] non-device（zone/SN/owner）：禁止 Info；
- [x] verified same-zone device：只命中 local/zone Info provider，并合并候选；
- [x] same-zone Info timeout + DNS success：在明确 deadline 内返回 DNS 地址；
- [x] `did:web` cross-zone：断言没有 `/.well-known/info.json` 和 upper resolver
  `?type=info` HTTP 请求。

## RTCP 接入任务

- [x] `resolve_handshake_identity()` 的结果补充经过验证的 target kind 和 zone relation，
  或由同一可信身份结果生成 name-client 可消费的地址解析上下文。不能为了判断 same-zone
  先读取 Info，形成循环依赖。
- [x] `create_direct_tunnel()` 改用带 policy 的地址解析 API。`keep_tunnel` 指向 SN/zone
  （例如 `did:web:us01.buckyos.ai`）时必须显式禁用 Info。
- [x] `collect_reconnect_candidates()` 复用 tunnel 建立时保存的解析 policy/evidence，不能
  退回无上下文的全局 `resolve_ips()`。
- [x] 上游 API 已完成，RTCP 未引入 WebProvider/provider 过滤分叉；所有无法生成可信
  same-zone evidence 的分支都通过上游 scoped API 显式使用 no-Info 安全策略。
- [x] 回归测试首次建 tunnel 和 stream reconnect：跨 zone 解析均零 Info 请求，DNS 已有
  地址时不再出现约 75 秒的等待。

## 完成记录

- `name-client`：仓库当前锁定的 `buckyos-base` revision
  `b101e8940830428d7b8cf8568b2f6f29e743e952` 已提供 scoped resolve API、安全默认、
  local/zone-only Info provider 路由、独立 deadline、结构化日志/metrics 及对应测试。
- RTCP：`resolve_handshake_identity()` 现在产出绑定目标 DID 的
  `RtcpAddressResolutionContext`。只有权威解析出的 DeviceDocument 同时匹配本机可信
  owner 和 zone anchor 时才生成 `VerifiedSameZoneDevice`；其它情况全部 fail closed。
- 首次 direct tunnel 解析和 stream reconnect 均调用同一个 context 的
  `resolve_ips_with_options()`；context 在 tunnel 创建时按值保存，不会从名字重新推断，
  也没有退回无上下文 `resolve_ips()` 的旁路。
- RTCP 回归覆盖 same-zone、cross-zone、unknown、zone/SN 非 device 以及建链到 reconnect
  的 policy 复用；现有 direct stream 建链/重连测试一并通过。
- 生产部署后的 `us01.buckyos.ai` 日志观测属于发布验证：预期只出现
  `info_policy=disabled` / 对应 skip reason，不再出现公开 Info HTTP 请求或约 75 秒等待。

## 完成标准

以下条件需要同时满足：

1. 跨 zone、unknown 和 non-device 的地址解析在测试与实际日志中都没有任何 Info 网络
   请求；
2. same-zone DeviceInfo 只通过可信 local/zone resolver 读取；
3. DNS 已有地址时，跨 zone RTCP 建链不会等待 Info deadline；
4. 首次建 tunnel 与 reconnect 使用相同 policy，不存在绕过路径；
5. `name-client` API 默认安全，新增调用者不提供可信 same-zone context 就无法意外开启
   Info。
