# NamedInboxCacheServer 使用说明

`named-inbox-cache` 是标准 HTTP server，可通过现有 `call-server` 调用，无需 BuckyOS。配置了 upstream 时，新请求先同步投递，只有连接、传输故障或超时才尝试本地缓存。明确的 rejected（包括 retryable）和普通 HTTP 500 都不触发首次缓存。后台 worker 直接投同一 upstream。

`200/201 + accepted` 表示 upstream 已持久接收；`202 + cached` 只表示本次缓存写入完成。发送方须保留原对象，只有 accepted 才能结束重试。缓存满但未发出请求时返回 `503/rejected/cache-full` 和 `Retry-After`；可能已发出请求而缓存失败时返回 `504` 与 `cyfs-dispatch-error: upstream-outcome-unknown`，不声称 rejected。

## Gateway 配置

以下路由块放在站点已有的认证规则之后。认证成功后必须通过 `export AUTH_principal = $verified_identity.sub;` 等规则，将**已验证**主体写入内部变量；`verified_identity` 的名称由站点认证规则决定。不要直接把 `REQ.cyfs-original-user` 赋给此变量。

```yaml
servers:
  zone_http:
    type: http
    hook_point:
      main:
        priority: 1
        blocks:
          route:
            priority: 1
            block: |
              # 此处之前须完成认证，并 export AUTH_principal。
              ne $REQ.host "alice.example" && reject;
              ne $REQ.path "/messages/inbox" && error 404 "no-handler";
              ne $REQ.method "PUT" && error 405 "method-not-allowed";
              ne $REQ_content_type "application/cyfs-named-object+json" && error 415 "unsupported-content-type";
              call-server alice_inbox_cache;

  alice_inbox_cache:
    type: named-inbox-cache
    target_zone: alice.example
    accepted_paths: [/messages/inbox]
    upstream: "http://10.0.0.2:4050"
    upstream_timeout: 3s
    poll_interval: 5s
    concurrency: 2
    retry_backoff: [5s, 30s, 2m, 10m]
    cache_path: /var/lib/cyfs-gateway/inbox/alice
    max_object_bytes: 65536
    max_entries: 10000
    max_bytes: 268435456
    per_principal_quota:
      max_entries: 1000
      max_bytes: 16777216
    cache_ttl: 24h
```

此处 `4050` 是新增 CYFS 接收适配与原 KRPC 共用的 msg-center HTTP 监听端口；PUT 由 CYFS 适配处理，不会交给 KRPC。通用宿主可以配置任何实现该协议的 HTTP upstream。

`upstream` 只允许 HTTP/HTTPS origin，不带路径、用户信息、query 或 fragment；原 Zone 通过 Host 保留，原规范化语义路径作为请求路径，禁止自动跟随重定向。物理地址可通过重载改变，缓存记录的逻辑目标保持不变。不要将 upstream 指回该缓存的公开入口。

省略 upstream 即纯暂存，无 worker。`drain_enabled: false` 仅暂停后台排空；新请求仍先投 upstream。`drain_enabled: true` 缺少 upstream、空路径列表、零额度、零并发、无效时间或带 inner_path 的路径均为配置错误。时间支持 `ms/s/m/h`。默认单对象 64 KiB、10000 条、正文合计 256 MiB、超时 3 秒、轮询 5 秒、并发 1，退避为 5 秒、30 秒、2 分钟、10 分钟。

## 对象、认证与存储

- 请求正文必须是原始 canonical JSON 对象。普通 JSON 未带 `cyfs-obj-id` 时使用 `jobj`；MsgObject 等类型化对象必须带其实际 ObjectId，服务端核对类型与正文哈希。拒绝非 canonical JSON、重复 JSON key、超限流式正文以及 Chunk。
- Zone 转小写并移除末尾点；path 解码 unreserved 字符、统一百分号转义大小写。拒绝点路径、重复或尾随斜杠、编码分隔符和 inner_path；路径本身大小写敏感。去重身份为规范化 target 和 ObjectId，同对象不同路径分别计额。
- HTTP 宿主通过进程内 `VerifiedDispatchContext` 传递主体、原目标、接收时间和可信入口。只保存并重放必要的原始 `authorization`、`cyfs-proofs`、`cyfs-cascades`、`cyfs-access-code`；这些原始凭据在规则执行前取得。凭据总量限制为 16 KiB，避免 header 元数据无界增长。匿名网络 header 不会创建可信上下文。
- 本版在 `cache_path` 中为每份投递保存独立完整 JSON 记录，通过临时文件写入、flush 和 rename 完成写入。Unix 记录文件权限为 0600。不使用 OOD 存储，不抓取附件，不删除 NamedDataMgr 的共享对象。
- 额度按正文大小计算，实例与主体额度在同一把本地锁内检查；重复项不重复计额，成功写入的新认证上下文可替换旧凭据。正常 upstream 接收不读取或检查缓存，缓存满、目录损坏都不会阻止同步投递。
- worker 在 accepted 后删除记录；永久拒绝记录原因后清理；临时失败、可重试拒绝和 upstream 返回 cached 时保留并退避。仅记录当前状态，不提供长期终态回执。
- 启动时恢复并校验完整记录，丢弃无效、过期或超额条目；残缺临时文件不进入索引。实例停止时取消 worker，同目录重载共享额度与排空协调。TTL、进程故障或目录损坏可能造成缓存丢失。

Gateway 缓存本地 GET 状态查询为可选能力，本版未开放；GET 会返回 method-not-allowed。状态解析库及下述 msg-center upstream 查询已实现。发送方使用原对象重新 PUT 即可，不依赖查询。

## BuckyOS 接收与发送

msg-center settings 中新增 `cyfs_dispatch`，随服务启动与 `reload_settings` 生效。接收路径精确映射到一个已由本 Zone 托管的 DID；不会因消息正文包含其他收件人而一并写入其他收件箱。

```json
{
  "cyfs_dispatch": {
    "target_zone": "alice.example",
    "accepted_paths": {
      "/messages/inbox": "did:bns:alice"
    },
    "principal_dids": {
      "bob": "did:bns:bob"
    },
    "max_object_bytes": 65536,
    "outgoing": {
      "did:bns:carol": {
        "target": "cyfs://carol.example/messages/inbox",
        "upstream": "https://carol.example",
        "authorization": "Bearer <目标 Zone 接受的 session token>",
        "timeout_ms": 3000
      }
    }
  }
}
```

接收适配使用目标 Zone 的 `verify_trusted_session_token` 验证 Authorization，再核对 token 主体对应的 DID 与 `MsgObject.from`。已验证的 DID subject 可直接使用；普通账号 subject 通过管理员配置的 `principal_dids` 映射。请求中的 `cyfs-original-user` 不承担认证作用。此版跨 Zone 路由与接收端接受的会话凭据须显式配置，不自动发现路由或签发跨 Zone 授权。短期凭据按原有效期验证，可通过 settings 重载更新发送凭据。

接收端在现有数据库事务中按主体、规范化 target、ObjectId 去重，并只写入本次接收者的记录；原 MsgObject 保持完整。群接收点仍由既有群收件业务处理，不能把其他群作为当前目标确认。只有事务成功返回 accepted，事务结果不确定时返回网关错误。

`GET /messages/inbox?dispatch-status=<ObjectId>` 使用同样的认证，查询只对该主体、该接收点生效。有记录时返回 HTTP 200、dispatch 状态及 `source: upstream`；无记录返回 404 与 `cyfs-dispatch-error: unknown-dispatch`。

MessageHub 创建投递时将逻辑目标保存到 DeliveryEnvelope；重载可以更新物理 upstream 和凭据，逻辑目标变化不会静默转投。执行器发送相同的 canonical 正文与 ObjectId；cached 产生 `ok=false/retryable=true` 的投递报告，使用既有队列退避（cached 默认 30 秒）和最大重试次数。达到发送方重试上限仍记为失败，不能把 cached 转成成功。只有 accepted 才置为 Sent；数据库条件更新防止迟到的 cached/失败报告覆盖 Sent。

## 开发与验证

本次协议与消费者跨 `cyfs-ndn`、`cyfs-gateway`、`buckyos` 三个仓库联动。Gateway 和 BuckyOS 的 Cargo workspace 使用本地 `[patch]` 指向同级 `cyfs-ndn`，保证编译到新协议；独立发布时应将协议提交发布后更新 git revision。

```bash
cd cyfs-ndn/src
cargo test -p ndn-lib cyfs_dispatch -- --test-threads=1

cd ../../cyfs-gateway/src
cargo test -p cyfs-gateway-lib server:: -- --test-threads=1
cargo test -p cyfs-gateway-app-lib --lib -- --test-threads=1

cd ../../buckyos/src
cargo test -p msg_center -- --test-threads=1
```

故障测试使用临时目录与本地随机端口 HTTP upstream，覆盖同步优先、拒绝不 fallback、断连/响应超时、缓存失败时的未知结果、重复与并发额度、恢复排空、TTL、暂停/停止/重载、入口拒绝、直接 forward、单接收点事务去重和同对象发送重试。
