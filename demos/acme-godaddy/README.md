# GoDaddy DNS-01 ACME demo（Deno）

这是一个可直接运行的 Let’s Encrypt DNS-01 客户端。它使用 GoDaddy Personal Access Token（PAT）和
Domains v3 API 临时创建 `_acme-challenge` TXT 记录，等待所有权威 DNS 可见后完成签发，再用 GoDaddy
返回的 `recordId` 精确删除本次记录。

默认连接 **Let’s Encrypt staging**，避免调试时消耗生产环境速率限额。确认 staging 流程成功后才应增加
`--production`。

## 前置条件

- Deno 2.x。
- 域名必须使用 GoDaddy 的权威 DNS。如果只在 GoDaddy 注册、DNS 已托管到其他服务商，则不能使用此
  provider。
- GoDaddy PAT 至少具有 `domains.dns:update` scope。PAT 只通过 `GODADDY_PAT`
  环境变量注入，不接受命令行参数，避免出现在 shell history 或进程列表中。Deno 任务需要
  `--allow-env`，因为 `acme-client` 的日志依赖会枚举 `DEBUG_*` 环境变量；demo 代码本身只会读取
  `GODADDY_PAT`。

GoDaddy 当前推荐 PAT Bearer 鉴权和 v3 DNS API；旧的 `sso-key key:secret` 已进入弃用流程，本 demo
不兼容旧凭据。

## 运行

先在 GoDaddy 创建 PAT，并从安全存储临时注入当前 shell：

```bash
cd demos/acme-godaddy
export GODADDY_PAT='<YOUR_GODADDY_PAT>'

deno task start \
  --zone example.com \
  --domain example.com \
  --domain '*.example.com' \
  --email admin@example.com \
  --accept-terms
```

staging 成功后签发生产证书：

```bash
deno task start \
  --zone example.com \
  --domain example.com \
  --domain '*.example.com' \
  --email admin@example.com \
  --accept-terms \
  --production \
  --output ./certs/production
```

申请 `*.buckyos.io` 可以直接使用快捷脚本：

```bash
# 先编辑脚本中的 GODADDY_PAT，然后申请生产证书
./acme_buckyos_io.sh

# 如需再次测试 staging
ACME_PRODUCTION=0 ./acme_buckyos_io.sh
```

快捷脚本默认连接 Let’s Encrypt production，并使用 `ops@buckyos.ai` 作为 ACME 联系邮箱；可通过
`ACME_EMAIL` 覆盖。staging 和 production 证书分别输出到 `certs/buckyos.io/staging` 与
`certs/buckyos.io/production`。额外参数会原样转发，例如 `./acme_buckyos_io.sh --force --verbose`。

`--domain` 可以重复。每个域名必须等于 `--zone` 或位于其下；通配符只能出现在最左侧。运行
`deno task start --help` 查看传播超时、自定义 ACME directory、强制签发等参数。

## 输出与续期

默认输出到 `./certs`：

- `account.key.pem`：持久化 ACME 账号密钥；不要删除或提交。
- `privkey.pem`：证书私钥。
- `cert.pem`：叶证书。
- `chain.pem`：中间证书链。
- `fullchain.pem`：叶证书和中间证书链。
- `state.json`：签发环境、域名集合、到期时间和文件摘要，用于安全判断续期并检测落盘中断。

脚本默认在证书剩余有效期大于 30 天时直接退出，因此可以由 cron/systemd timer 每天调用。用
`--renew-before-days` 调整阈值；用 `--force` 忽略阈值。staging 与 production
应使用不同输出目录，避免测试证书覆盖生产证书。

私钥文件按 `0600` 写入，证书按 `0644` 写入；在不支持 POSIX mode 的平台上，应另外通过系统 ACL
限制目录访问。`.gitignore` 已忽略本目录常见证书输出，但自定义输出路径仍需自行保护。

## Provider 参考边界

[`dns_provider.ts`](./dns_provider.ts) 只定义两个操作：

```ts
interface Dns01Provider {
  present(record: Dns01ChallengeRecord): Promise<Dns01RecordHandle>;
  cleanup(record: Dns01RecordHandle): Promise<void>;
}
```

未来接入另一个 DNS 服务商时，只需实现这两个方法，再替换 [`main.ts`](./main.ts) 中创建 provider
的位置。ACME 账号、CSR、订单、权威 DNS 传播检查、证书落盘和续期判断都不需要复制。

注意：`acme-client` 的 DNS-01 `challengeCreateFn` 第三个参数虽然名为
`keyAuthorization`，但它已经是最终的 `BASE64URL(SHA256(keyAuthorization))` TXT 值。provider
必须直接写入，不能再次计算 SHA-256。

GoDaddy 实现使用 `POST /v3/domains/zones/{zone}/dns-records` 追加单个 TXT 值。它不使用会替换整个
RRset 的接口，因此根域和 wildcard 同时验证时不会互相覆盖；清理时则用创建响应里的稳定 `recordId`
删除且只删除本次值。POST 不做自动重试，因为官方明确说明它不是幂等操作。

## 开发检查

```bash
deno task test
deno task check
```

测试不会请求 GoDaddy 或 Let’s Encrypt，使用模拟 HTTP 响应验证 provider 的请求和精确清理行为。

## 参考

- [GoDaddy API 用户指南](https://developer.godaddy.com/en/docs/api-users)
- [GoDaddy DNS records v3 指南](https://developer.godaddy.com/en/docs/api-users/manage-domains/dns)
- [GoDaddy PAT 鉴权](https://developer.godaddy.com/en/docs/api-users/auth)
- [Let’s Encrypt challenge types](https://letsencrypt.org/docs/challenge-types/)
- [ACME RFC 8555](https://www.rfc-editor.org/rfc/rfc8555)
