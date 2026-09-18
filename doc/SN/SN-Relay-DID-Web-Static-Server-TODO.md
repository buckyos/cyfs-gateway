# SN Relay `did:web` 静态发布 TODO

## 1. 背景

当前 `web3_gateway` 的单机 all-in-one 部署同时包含 DNS、Relay 和 `web3_sn`
API/DID Resolver。现有测试主要通过集中式接口查询 DID：

```http
GET https://sn.{sn-host}/1.0/identifiers/{did}
```

因此，all-in-one 部署可以直接在同一进程内调用 `web3_sn` 完成查询，没有暴露
生产拆分部署中的 `did:web` 权威发布缺口。

真实部署中的 Relay Node 是用户域名的公网 HTTP/HTTPS 入口。外部客户端按
`did:web` 规则解析：

```text
did:web:us1.{sn-host}
```

时，权威请求会发往：

```http
GET https://us1.{sn-host}/.well-known/did.json
```

该请求不是 `sn.{sn-host}/1.0/identifiers/*`，也不应该依赖用户 Gateway/OOD
已经在线。独立 Relay Node 必须在进入普通 RTCP 转发逻辑之前，本地返回对应的
DID Document。

## 2. 当前缺口

当前 all-in-one HTTP 规则对 `sn.{sn-host}`、`bns.{sn-host}` 和
`web3.{sn-host}` 做特殊处理，其它 Host 会继续执行：

```text
deviceinfo.resolve_ood_by_hostname
→ forward rtcp://{gateway-device}/:80
```

在独立 Relay Node 上，这会导致
`https://us1.{sn-host}/.well-known/did.json` 被当作普通用户业务流量：

- 用户 Gateway 未上线时，DID 无法解析；
- DID 解析依赖待验证主体自身已经可访问，形成启动循环；
- Relay 无法为 SN 托管的 `did:web:<username>.{sn-host}` 提供稳定权威入口；
- 集中式 SN-DID-Resolver 的 supplement 响应被误当成 `did:web` 权威发布面。

`cyfs-sn` 的 `/1.0/identifiers/*` 仍可保留用于内部验证、启动期补充和兼容
fallback，但不能替代 `did:web` 的 HTTPS origin。

## 3. 目标

- Relay Node 本地提供
  `https://<username>.{sn-host}/.well-known/did.json`。
- `.well-known/did.json` 在用户 Gateway/OOD 离线时仍可访问。
- 请求在普通 Host/SNI 解析、relay assignment 检查和 RTCP 转发之前完成。
- DID Document 的 `id`、controller 和 verification method 与请求 DID 一致。
- DID Document 由可信控制面生成并分发；Relay 只负责发布，不自行决定 owner key。
- 多 Relay 部署和 relay assignment 迁移期间不出现 DID Document 短暂丢失。
- all-in-one 与 split deployment 对外行为最终保持一致。

## 4. 非目标

- 不把 BNS indexer 或 SN-DID-Resolver 搬进 Relay Node。
- 不允许 Relay 根据请求参数临时拼装未经验证的 DID Document。
- 不在第一阶段实现任意外部 `user_domain` 的静态托管。
- 不在第一阶段覆盖带 DID path 的复杂 `did:web` 标识。
- 不让 `/.well-known/did.json` 请求回落到用户 RTCP tunnel。

第一阶段只处理 SN 自有命名空间：

```text
did:web:<username>.{sn-host}
```

设备 DID、外部 `user_domain` 和多级子域名另行设计。特别是
`did:web:<device>.<username>.{sn-host}` 需要多级通配符 DNS/TLS 或改用 DID path，
不能隐式纳入第一阶段。

## 5. 目标请求链路

```text
name-client / browser
        |
        | DNS: us1.{sn-host} -> assigned Relay IP
        | TLS SNI: us1.{sn-host}
        v
SN Relay Node
        |
        | Host 属于 SN 自有 did:web namespace
        | Path == /.well-known/did.json
        v
local DID static server
        |
        v
<did-root>/us1/did.json
```

普通业务请求继续走原有路径：

```text
Host/SNI
→ sn_resolver
→ relay assignment/admission
→ local RTCP tunnel
→ user Gateway
```

## 6. 静态文件布局

建议使用不直接暴露 Host 字符串的受控目录：

```text
<did-root>/
├── us1/
│   └── did.json
├── us2/
│   └── did.json
└── ...
```

Relay 路由先把 Host 严格解析为合法、已注册的 `<username>`，再将固定请求
`/.well-known/did.json` 映射为 `/<username>/did.json`。

不能把未经校验的 `Host`、URL path 或 percent-decoded 内容直接拼接进文件系统路径。
需要拒绝：

- 不属于 `.{sn-host}` 的 Host；
- 保留 Host：`sn`、`bns`、`web3`、`dns` 和 Relay 自身名称；
- 空 label、包含路径字符、非法 IDNA 或不符合 username 规则的 label；
- 除 `GET`、`HEAD` 之外的方法；
- `/.well-known/did.json` 之外的路径回退到该静态目录。

现有 `type: dir` server 可以承担最终文件读取、ETag 和
`If-Modified-Since`；Host 到安全文件路径的映射可在 process-chain 中完成。如果现有
process-chain 无法安全完成 Host capture 和 path rewrite，则增加一个最小的
`did_web_static` HTTP server，不能通过放宽目录服务器路径校验来实现。

## 7. DID Document 生成与同步

### 7.1 数据来源

DID Document 的 owner key 必须来自 SN 已认可的身份数据，优先级与现有
SN-DID-Resolver owner document 约束保持一致：

1. BNS owner/owner_config；
2. 已验证的 SN 用户 owner public key；
3. 明确标注的兼容 key 来源。

不得使用 Relay Node 自身 TLS key、Relay device key 或请求携带的任意 key 作为用户
DID owner key。

### 7.2 最小一致性要求

以 `us1` 为例，生成结果至少满足：

```json
{
  "id": "did:web:us1.{sn-host}",
  "verificationMethod": [],
  "authentication": [],
  "assertionMethod": []
}
```

具体 verification method 类型和 JWK 编码必须复用现有 DID/owner document builder，
不得在发布器中另写一套不兼容格式。所有 controller、verification method fragment
和引用必须锚定 `did:web:us1.{sn-host}`，不能泄漏为
`did:bns:us1` 的自述身份；`did:bns:us1` 只能作为 provenance/canonical-zone
扩展信息。

响应至少包含：

```http
Content-Type: application/did+json
ETag: "..."
Cache-Control: public, max-age=<bounded-ttl>
```

最终 Content-Type 需要用现有 `name-client` 做兼容验证；如果消费者要求
`application/did+ld+json`，应统一调整，不允许不同 Relay 返回不同类型。

### 7.3 发布方式

- 控制面生成完整文件到同目录临时文件。
- 完成 JSON 解析、DID 自述一致性和 key 校验。
- `fsync` 后通过原子 rename 替换 `did.json`。
- 更新失败时保留上一份有效文档。
- key rotation 后主动刷新文件，并使用有界 HTTP cache TTL。
- 用户撤销、删除或更名时定义明确的 404/410 和缓存失效策略。

第一版建议把所有 SN 自有 username 的 DID Document 同步到所有 Relay Node。这样
relay assignment 迁移只改变 DNS/流量归属，不需要等待目标 Relay 临时拉取文档。
后续规模需要按 assignment 分片时，必须遵守：

```text
目标 Relay 文档 ready
→ DNS/assignment 切换
→ 旧 Relay 文档经过迁移窗口后清理
```

## 8. DNS 与 TLS

- SN 权威 DNS 必须让 `<username>.{sn-host}` 指向该 zone 当前分配的 Relay Node。
- 每个可能承载该名字的 Relay Node 必须具备覆盖 `*.{sn-host}` 的有效证书。
- HTTP 80 可以只做 HTTPS redirect，不得在明文响应中返回不同 DID Document。
- TLS SNI 和 HTTP Host 必须一致；不一致时拒绝请求，避免跨 Host 读取文档。
- wildcard 证书只覆盖单 label。多级设备名字不属于第一阶段。
- Relay 迁移时必须在切 DNS 前验证目标节点的证书和 DID 文件均已就绪。

## 9. 配置改造

### 9.1 split Relay

在生产 `web3_relay.yaml` 中增加：

- DID 静态根目录参数，例如 `did_web_root`；
- 本地 `type: dir` 或专用 `did_web_static` server；
- `*.{sn-host}` TLS termination；
- 精确的 `/.well-known/did.json` HTTP 路由；
- 位于普通 hostname QA/RTCP forward 之前的优先级。

目标顺序：

```text
reserved SN/BNS/API hosts
→ managed did:web + /.well-known/did.json
→ ordinary hostname resolve/admission
→ RTCP forward
```

### 9.2 all-in-one

all-in-one 当前集中式 resolver 可继续工作，但应增加同样的外部
`did:web` 验收测试，避免两种部署对外行为漂移。第一阶段允许复用相同静态目录和路由；
不能只在 all-in-one 中通过进程内 `web3_sn` 特判返回动态结果。

### 9.3 部署生成器

`make_sn_config.ts` 和部署模板需要生成/注入：

- `did_web_root`；
- SN-owned DID hostname suffix；
- 静态文档同步或初始 materialize 配置；
- wildcard DNS/TLS 所需参数；
- Relay readiness check。

## 10. 实施任务

### Phase 1：协议与单节点发布

- [ ] 固化第一阶段 DID 形式：`did:web:<username>.{sn-host}`。
- [ ] 明确与现有 `did:bns:<username>`、`<username>.web3.{sn-host}` 的关系。
- [ ] 用当前 `name-client` 验证标准请求 URL、Content-Type 和最小文档字段。
- [ ] 提取或复用现有 owner document builder，生成自述一致的 `did:web` 文档。
- [ ] 定义静态目录、文件权限、原子更新和损坏恢复策略。
- [ ] 在 Relay 配置中增加本地 static server。
- [ ] 增加 Host capture/validation 和固定 path rewrite。
- [ ] 将 `.well-known/did.json` 路由放到普通 RTCP forward 之前。
- [ ] 增加 wildcard DNS 和 TLS 配置。

### Phase 2：控制面同步

- [ ] 定义 DID artifact revision、checksum 和更新时间。
- [ ] 用户创建/激活时生成文档。
- [ ] owner key rotation 时更新文档。
- [ ] 用户撤销、删除和更名时清理或发布明确 tombstone。
- [ ] 将文档同步到所有有效 Relay Node。
- [ ] Relay 启动时先完成初始同步，再通过 readiness。
- [ ] 同步失败时保留 last-known-good 文件并上报 metrics。

### Phase 3：多 Relay 与迁移

- [ ] assignment 切换前检查目标 Relay 的文档 revision。
- [ ] 验证 DNS TTL、HTTP cache TTL 和迁移窗口的组合不会产生空窗。
- [ ] 旧 Relay 在迁移窗口内继续提供相同 DID Document。
- [ ] Relay 不健康时，备用 Relay 已有可发布副本。
- [ ] 增加跨 Relay revision 一致性检查和告警。

### Phase 4：部署一致性

- [ ] all-in-one 增加相同权威 URL，不再只测 `/1.0/identifiers/*`。
- [ ] split relay 增加独立端到端测试。
- [ ] 更新 `src/web3-gateway/readme.md`、`SN-Relay.md` 和部署文档。
- [ ] 明确 SN-DID-Resolver 只是 supplement/internal fallback，不是该
  `did:web` namespace 的 HTTPS origin。

## 11. 验收测试

### 11.1 基本解析

```bash
curl --resolve us1.${SN_HOST}:443:${RELAY_IP} \
  https://us1.${SN_HOST}/.well-known/did.json
```

必须满足：

- HTTP 200；
- Content-Type 正确；
- JSON 可解析；
- `id == "did:web:us1.${SN_HOST}"`；
- verification method/controller 引用一致；
- `name-client` 能完成解析和 key 提取。

### 11.2 用户 Gateway 离线

- 停止 us1 Gateway/OOD 或断开 RTCP tunnel；
- `/.well-known/did.json` 仍返回 200；
- 普通业务路径按现有语义返回 503 或离线错误；
- Relay 日志证明 DID 请求没有调用 RTCP forward。

### 11.3 路由隔离

- 未注册 username 返回 404，不读取其它用户文件；
- `Host` 注入、路径穿越和 percent-encoding 变体不能越权；
- SNI/Host 不一致时拒绝；
- `POST`/`PUT`/`DELETE` 不允许修改静态文件；
- `sn.{sn-host}`、`bns.{sn-host}`、`web3.{sn-host}` 不被 username 路由截获。

### 11.4 更新与缓存

- owner key rotation 后所有 Relay 最终得到相同 revision；
- 更新过程中请求只看到旧完整文档或新完整文档；
- 不会读到半文件、空文件或临时文件；
- ETag/304 行为正确；
- 删除/撤销后旧 200 不超过规定 TTL。

### 11.5 Relay 迁移

- us1 从 relay-a 迁移到 relay-b；
- DNS 切换前 relay-b 已能返回正确 revision；
- 迁移期间从两个 Relay 查询均得到同一 DID Document；
- 用户 Gateway 离线不影响两个 Relay 的 DID 响应。

## 12. 完成标准

- 独立 Relay Node 能权威响应
  `https://<username>.{sn-host}/.well-known/did.json`。
- 响应不依赖 `web3_sn` 进程内调用，不依赖用户 Gateway 在线，也不经过 RTCP tunnel。
- DNS、TLS、静态文件和 relay assignment 迁移形成无空窗闭环。
- all-in-one 和 split deployment 通过同一套外部 DID 解析测试。
- `did:web` 权威发布、SN supplement resolver 和 BNS authoritative resolver 的职责在
  配置与文档中明确分离。

## 13. 相关实现

- `src/web3-gateway/web3_gateway.yaml`：当前 all-in-one HTTP 路由。
- `src/web3-gateway/readme.md`：all-in-one 与 split deployment 说明。
- `src/components/cyfs-gateway-lib/src/server/dir_server.rs`：现有静态目录服务器。
- `src/components/cyfs-sn/src/sn_did_resolver.rs`：SN supplement/internal DID Resolver。
- `src/components/cyfs-sn/src/sn_server.rs`：`/1.0/identifiers/*` HTTP 入口。
- `src/components/bns-server/src/lib.rs`：`did:bns:*` 权威 Resolver。
- `doc/SN/SN-DID-Resolver.md`：SN-DID-Resolver 的定位与非目标。
- `doc/SN/SN-Relay.md`：独立 Relay Node 数据面设计。
