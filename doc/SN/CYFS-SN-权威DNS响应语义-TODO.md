# CYFS-SN 权威 DNS 响应语义补全 TODO

> 状态：已完成（2026-07-22）。实现采用结构化 `NameServer::query_dns` 结果传递 authority
> metadata，不再根据查询名外形、错误文本或额外 A probe 推断权威语义。

## 1. 目标

让 `cyfs-sn` 对自己实际管理的 DNS zone 返回完整、可被递归 DNS 正确理解的权威响应，
并严格区分以下结果：

1. 名称和请求的 RRset 都存在；
2. 名称存在，但请求的 RRset 不存在（NODATA）；
3. 名称不存在（NXDOMAIN）；
4. 名称不属于本 SN 管理的 zone；
5. 权威数据源暂时不可用（SERVFAIL）。

本 TODO 只补齐权威响应和 zone 边界，不要求在本轮实现 HTTPS/SVCB、MX、CAA 等记录的
实际存储。对于已管理名称上尚未支持或未配置的类型，正确结果应是权威
`NOERROR/NODATA + SOA`，而不是 `SERVFAIL`。

## 2. 当前问题

### P1：普通成功响应没有权威标志

文件：`src/components/cyfs-dns/src/dns_server.rs`

`ProcessChainDnsServer::name_info_to_buffer` 生成 A/AAAA/TXT 等普通成功响应时只设置
`ResponseCode::NoError`，没有根据 zone ownership 设置 `AA=true`。当前只有专门的
NS/SOA 和部分负响应分支通过 `authoritative_zone_response_to_buffer` 设置 AA。

这会出现同一个权威 zone 中，NS/SOA 或部分 NODATA 响应带 AA，而正常 A/AAAA/TXT
answer 不带 AA 的不一致行为。

### P1：user_domain 的负响应没有完整 SOA 语义

SN 管理的传统 `user_domain` 不一定包含 `web3` 标签。当前权威 zone 推导只识别
`web3`，因此 user_domain 的 NXDOMAIN/NODATA 可能走通用错误映射，只返回 RCODE，
没有 `AA=true`，authority section 也没有该 user_domain zone 的 SOA。

递归 DNS 因而无法可靠确认这是权威否定，也不能按 SOA TTL/MINIMUM 做标准负缓存。

### P1：未知或未实现的 RR type 仍可能变成 SERVFAIL

文件：

- `src/components/cyfs-sn/src/sn_resolver.rs`
- `src/components/cyfs-dns/src/dns_server.rs`

`SnResolver` 的 DNS 入口目前只接受 A、AAAA、TXT。浏览器和递归 DNS 还可能查询
HTTPS/SVCB、CAA、MX、NS、SOA 等类型。当前 DNS 层只对部分错误字符串和部分 web3
场景做 NODATA fallback；其他路径仍可能落到通用 `SERVFAIL`。

“记录类型暂未实现”不是服务故障。只要名称属于权威 zone 且名称存在，就必须返回
`NOERROR/NODATA + SOA`。只有数据库、BNS/indexer 或其他必需后端确实不可用时才返回
`SERVFAIL`。

### P1：web3 权威 zone 识别过宽

文件：`src/components/cyfs-dns/src/dns_server.rs`

`detect_web3_zone_authority` 会从查询名中第一个 `web3` 标签开始推导 zone。它没有校验
该 zone 是否严格等于当前 SN 配置对应的 `web3.<sn_host>`，因此类似
`alice.web3.example.net` 的域名也可能被本服务错误地设置 AA，并得到伪造的 NS/SOA。

权威性不能由查询名的字符串形状推断。web3 zone 必须来自配置；传统 user_domain
必须来自当前 active binding/权威数据源。

### P2：当前补丁路径耦合错误文本和额外 A probe

当前实现通过匹配 `unsupported record type` 错误文本，再用同名 A 查询探测名称是否存在。
这不能作为正式的权威协议边界：

- 一个只配置 TXT、没有 A 的名称仍然存在；
- A 的解析可能依赖设备在线状态，不能代表 DNS name existence；
- 错误文案变化会改变 wire response；
- probe 失败可能把 NODATA 重新降级成 SERVFAIL，并增加一次后端查询。

需要让 resolver 以结构化结果直接表达 zone ownership、name existence 和失败类别。

## 3. 目标响应矩阵

| 查询情况 | RCODE | AA | Answer | Authority |
| --- | --- | --- | --- | --- |
| 属于权威 zone，名称和 RRset 存在 | NOERROR | 1 | 对应 RRset | 可为空 |
| 属于权威 zone，名称存在但 RRset 不存在/未实现 | NOERROR | 1 | 空 | 该 zone 的 SOA |
| 属于权威 zone，名称不存在 | NXDOMAIN | 1 | 空 | 该 zone 的 SOA |
| 不属于本 SN 管理的 zone | 沿用非权威解析策略 | 0 | 不得伪造权威记录 | 不得伪造该域 SOA |
| 权威后端暂时不可用 | SERVFAIL | 不依赖 AA 判定 | 空 | 不得伪装成 NODATA/NXDOMAIN |

补充约束：

- NODATA 是 `RCODE=NOERROR` 且 answer 为空，不是一个独立 RCODE。
- NXDOMAIN 表示 owner name 不存在，而不是“请求类型没有记录”。
- NXDOMAIN/NODATA 的 SOA owner 必须是实际所属 zone apex。
- web3 zone 只能是配置得到的 `web3.<sn_host>`；不得接受任意包含 `web3` 标签的域名。
- active user_domain 以绑定域名本身作为 zone apex。子域负响应也返回该 apex 的 SOA。
- zone apex 的 NS/SOA 查询返回 answer；apex 之外缺失 NS/SOA RRset 时返回 NODATA + SOA。
- UDP 与 TCP 必须返回相同 RCODE、AA、Answer/Authority 语义，仅传输层截断行为可以不同。

## 4. 实施任务

### A. 建立显式的权威 zone 来源

文件：

- `src/components/cyfs-dns/src/dns_server.rs`
- `src/components/cyfs-sn/src/sn_resolver.rs`
- `src/components/cyfs-sn/src/sn_server.rs`
- 对应 server/config 模型

- [x] 删除基于“查询名中存在 `web3` 标签”的权威判定。
- [x] 从 SN 配置的规范化 `server_host` 生成唯一 web3 zone：
  `web3.<server_host>`；处理大小写和结尾点后再做 DNS label 边界匹配。
- [x] 从 active `user_domain` binding 获取传统权威 zone；revoked、superseded、
  suspended/deleted user 对应域名不得继续作为权威 zone。
- [x] 对多个候选 zone 使用 longest-suffix match，但必须按完整 DNS label 匹配，禁止普通
  字符串 `ends_with` 导致 `notexample.com` 命中 `example.com`。
- [x] 明确 authority 信息如何从 SN resolver 传到通用 DNS server。建议返回结构化
  authority metadata，而不是让 `cyfs-dns` 读取 SN 数据库或重复解析业务配置。
- [x] 未配置权威 zone 时保持通用 DNS/process-chain 的现有非权威行为，避免把
  `ProcessChainDnsServer` 全局变成权威服务器。

建议的最小 authority metadata 至少包含：

```text
zone_apex
primary_ns
responsible_mailbox
soa_serial
soa_refresh / retry / expire / minimum
positive_ttl
```

SOA 字段应来自配置或稳定状态；`serial` 不要在每次查询时用当前秒数临时生成，否则同一
zone 的 SOA 会随每次请求无条件变化。

### B. 让 resolver 返回结构化的 DNS 结果

文件：

- `src/components/cyfs-sn/src/sn_resolver.rs`
- resolver 与 `cyfs-dns` 之间的 adapter/command

- [x] 将“是否管理该 zone”“owner name 是否存在”“该类型 RRset 是否存在”拆成独立字段
  或 enum，不再用空 address、错误码或错误字符串间接推断。
- [x] 支持把任意合法 DNS query type 传入权威判定路径。A/AAAA/TXT 继续执行现有真实
  解析；未实现类型在 name existence 已确认时返回结构化 NODATA。
- [x] name existence 必须由 zone/owner 数据模型判断，不能通过额外 A 查询探测。
- [x] 明确 wildcard、显式 control TXT（例如 `_acme-challenge`）和子域的存在性规则；
  删除 TXT 后，如果该 owner name 没有任何其他 RRset，应按模型返回 NXDOMAIN，而不是
  永久 NODATA。
- [x] 保留 `NotManaged`、`NameNotFound`、`NoData`、`BackendUnavailable` 的可区分性，
  不要在转成 `ServerError` 时丢失语义。
- [x] 缓存同时保存 authority/name-existence 结果；负缓存 key 不能只按当前支持的
  A/AAAA/TXT 结果推导。

建议的结果形状（名称可按现有风格调整）：

```text
NotManaged
AuthoritativeAnswer { zone, records, ttl }
AuthoritativeNoData { zone }
AuthoritativeNxDomain { zone }
TemporaryFailure { cause }
```

### C. 统一构造权威成功与负响应

文件：`src/components/cyfs-dns/src/dns_server.rs`

- [x] `name_info_to_buffer`（或替代的 response builder）接收显式 authority context；
  权威 A/AAAA/TXT/其他已支持记录的成功响应设置 `AA=true`。
- [x] 权威 NODATA 统一返回 `NOERROR + AA + authority SOA`。
- [x] 权威 NXDOMAIN 统一返回 `NXDOMAIN + AA + authority SOA`。
- [x] NS/SOA apex answer 复用同一 zone metadata，不再从任意 query name 临时拼接。
- [x] 非权威 process-chain、inner record 和上游 DNS 响应不得因为名称外形而被设置 AA。
- [x] 删除 `unsupported record type` 文本匹配、A probe 和针对个别类型的兜底分支。
- [x] `BackendUnavailable`、超时、数据损坏和编码失败继续返回 SERVFAIL，不得转换为
  NODATA/NXDOMAIN。
- [x] 保证 negative response 中 SOA 位于 authority section，且 TTL/MINIMUM 满足预期的
  负缓存策略。

### D. 补齐测试

文件：

- `src/components/cyfs-dns/src/dns_server.rs` 的测试模块
- `src/components/cyfs-sn/src/sn_resolver.rs` 的测试模块
- 必要时增加 `src/apps/cyfs_gateway/tests/` 集成测试

- [x] web3 权威 zone 的 A、AAAA、TXT 成功响应均为 `AA=true`。
- [x] active user_domain 的成功响应为 `AA=true`。
- [x] 已存在 web3 名称与 user_domain 名称查询 HTTPS/SVCB、CAA、MX 等未配置类型时，
  返回 `NOERROR/NODATA + AA + SOA`。
- [x] 不存在的 web3/user_domain 名称返回 `NXDOMAIN + AA + SOA`。
- [x] user_domain 的子域负响应中，SOA owner 是 user_domain apex，而不是查询名。
- [x] web3 zone apex 的 NS/SOA 返回正确 answer；非 apex 缺失 NS/SOA 返回 NODATA + SOA。
- [x] `alice.web3.<其他域>`、`web3.example.net`、`foo.web3.evil.test` 等非配置 zone
  不设置 AA、不返回本 SN 拼出的 SOA。
- [x] revoked/superseded user_domain 不再被视为权威 zone。
- [x] 后端超时/不可用返回 SERVFAIL，不能伪装为 NXDOMAIN/NODATA。
- [x] 只存在 TXT、没有 A 的 owner name 查询 MX 时仍返回 NODATA，而不是 NXDOMAIN。
- [x] UDP 与 TCP 对上述所有 case 的 RCODE、AA、Answer/Authority 内容一致。

建议保留一组 wire-level table test，直接解析最终 DNS message 断言 header 和 section，
不要只测试 resolver 内部 enum。

## 5. 验收标准

- 所有由当前 SN 明确管理的 web3 zone 和 active user_domain，正向响应都设置 `AA=true`。
- 权威名称的未知/未配置类型不再返回 SERVFAIL，而是标准 NODATA + SOA。
- 权威 zone 内能稳定区分 NXDOMAIN 与 NODATA，二者均携带正确 zone SOA。
- 任意包含 `web3` 标签、但不属于配置 `web3.<sn_host>` 的域名都不会被声明为权威。
- 后端真实故障仍可观测为 SERVFAIL，不会被负响应掩盖。
- 不再依赖错误字符串或同名 A probe 决定 DNS wire response。
- UDP/TCP 集成测试覆盖上述语义，并使用 `--test-threads=1` 稳定运行。

建议验证命令：

```bash
cd src
cargo test -p cyfs-dns -- --test-threads=1
cargo test -p cyfs-sn -- --test-threads=1
cargo test -p cyfs_gateway --test test_dns_over_tcp -- --test-threads=1
```

实际验证结果：

- `cargo test -p cyfs-dns -- --test-threads=1`：24 passed；
- `cargo test -p cyfs-sn -- --test-threads=1`：150 passed，3 ignored；集成测试另有 6 passed、
  1 ignored；
- `cargo test -p cyfs_gateway --test test_dns_over_tcp -- --test-threads=1`：1 passed。

实现约定：

- web3 authority 仅来自规范化配置的 `web3.<server_host>`，配置 aliases 不自动扩展为
  权威 zone；
- active `user_domain` 按完整 DNS label 做最长后缀匹配，匹配结果同时返回真实 binding
  apex；非 active user/binding 不进入 authority 候选；
- 普通 user_domain 子域沿用既有 wildcard gateway 模型；下划线 control owner（例如
  `_acme-challenge`）仅在 compatibility store 中至少存在一个显式 RRset 时存在；
- SOA 参数保存在 `SnResolverConfig`，默认 serial 为稳定值 `1`，不会按查询时间变化；
- 结构化权威结果按 `(owner name, query type)` 缓存；owner RRset 变更时会失效该 owner 的
  所有 query type，避免 TXT 变化后 MX 等负响应沿用旧的 name-existence 结论。

## 6. 非目标

- 本轮不要求实现 DNSSEC、AXFR/IXFR、dynamic update 或完整通用权威 DNS 数据库。
- 本轮不要求真正发布 HTTPS/SVCB、MX、CAA RRset；只要求缺失类型的权威否定语义正确。
- 不把任意上游递归查询结果标为 SN 权威结果。
- 不改变 BNS 合约与 indexer 的权威数据边界；本 TODO 只定义 SN 对 DNS client 的响应
  语义和 zone ownership 映射。
