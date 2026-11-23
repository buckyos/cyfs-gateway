# 用自己的账号测一家 DNS 服务商

`cyfs-dns-provider`（`src/components/cyfs-dns-provider`）支持 20 家 DNS 服务商。代码按官方文档写，用 mock 服务器测过，但没有各家的真实账号。没人测过的服务商 `tested = false`，激活页会标“实验”。

有账号的贡献者可以用自测工具测一遍，把结果提交回来。工具是 `examples/selftest.rs`。

## 测什么

工具在你的域名下写临时记录，测完删掉。每一步都从服务商接口读回，再直接问每台权威 NS（测试环境除外）。

| 步骤 | 通过标准 |
| --- | --- |
| 记下测试名字周围的记录 | 能读 |
| 加 TXT 值 A，再加 B，再加一次 A | A、B 都在，没有重复，原有的值还在（`<域名>` 和 `*.<域名>` 的 ACME 挑战共用一个名字，不能互相覆盖） |
| 删 A，再删一次 A，最后删 B | 只删掉指定的值，重复删不报错 |
| 写 CNAME、换成另一个值、删除 | 每步读回一致 |
| 写、换、删通配名的 CNAME（`*.<随机名>.<域名>`） | 同上，用随机子名字查询能命中 |
| 再读一遍周围的记录 | 与开始时相同 |

“周围的记录”是主域名和 `--domain` 的 A / AAAA / TXT / NS / CNAME，以及 `www`、`mail`、`_dmarc`、`_acme-challenge`、`_pkx`、`*`、`ood1`、`sys`（后者只问权威 NS）。

## 准备

1. 用一个不重要的域名，或单独的子域名。不要用正在收发邮件、跑网站的域名。
2. 先在服务商后台导出或截图全部记录，出错时能恢复。整份读写的接口（例如さくらのクラウド）写错会影响其它记录。
3. 按 [doc/user/dns-providers](https://github.com/buckyos/buckyos/tree/main/doc/user/dns-providers) 里那一家的说明申请 token，权限按说明收到最窄。这样能同时验证说明里的权限够不够用。
4. 写凭据文件。`schema` 必填，`provider` 和字段 id 见 `src/table.rs`，`endpoint` 可选：

   ```json
   {
     "schema": "buckyos.dns_credential.v1",
     "provider": "cloudflare",
     "fields": { "api_token": "…" }
   }
   ```

   ```bash
   chmod 600 cred.json
   ```

token 只放在这个文件里。不要写进命令行参数、环境变量或仓库里的文件。

## 运行

在 `cyfs-gateway/src` 下：

```bash
cargo run -p cyfs-dns-provider --example selftest -- \
  --credential cred.json --domain example.com --report report.json
```

| 选项 | 说明 |
| --- | --- |
| `--credential <文件>` | 必填，凭据文件 |
| `--domain <域名>` | 必填，账号里的域名或它下面的名字。主域名沿它向上查 SOA 得到 |
| `--txt-name <名字>` | TXT 用的名字，默认随机。已有的值会保留并核对 |
| `--cname-name <名字>` | CNAME 用的名字，默认随机。必须没被占用，可以是 `*.…`。给了它就只测这一个名字 |
| `--endpoint <地址>` | 官方测试环境的接口地址，覆盖凭据文件里的 |
| `--zone <主域名>` | 主域名。测试环境查不到 SOA 时用，要和 `--api-only` 或 `--accept-only` 一起 |
| `--api-only` | 不问权威 NS，测试环境用 |
| `--accept-only` | 服务商只校验、不生效时用（TransIP demo token） |
| `--ttl <秒>` | 默认 600 |
| `--timeout <秒>` | 等权威 NS 生效的时间，默认 300 |
| `--report <文件>` | JSON 报告写到文件，默认写到标准输出 |

人读的进度在标准错误。退出码：0 通过，1 失败，2 参数错。

### token 限定了记录名

例如 Route 53 的策略只允许四个名字，随机名会被拒绝。指定允许的名字，并保证 CNAME 的名字没被占用：

```bash
cargo run -p cyfs-dns-provider --example selftest -- \
  --credential cred.json --domain home.example.com \
  --txt-name _acme-challenge.home.example.com --cname-name '*.home.example.com'
```

### 官方测试环境

测试环境不解析到公网，只能验证接口：

```bash
cargo run -p cyfs-dns-provider --example selftest -- \
  --credential cred.json --domain example.com \
  --endpoint https://api.dev.name.com --zone example.com --api-only
```

| 服务商 | 地址 | 说明 |
| --- | --- | --- |
| Porkbun | 与正式环境相同 | 用 `pk1_sb_` 开头的 key，不用 `--endpoint` |
| Name.com | `https://api.dev.name.com` | 用户名加 `-test`，单独的测试 token，域名先在测试环境注册 |
| Gandi | `https://api.sandbox.gandi.net/v5` | PAT 在 `admin.sandbox.gandi.net` 创建 |
| INWX | `https://api.ote.domrobot.com/jsonrpc/` | 账号在 `ote.inwx.com` 注册 |
| TransIP | `https://api.transip.nl/v6`（正式地址） | 官方公开的 demo token，加 `--accept-only` |

Porkbun、IONOS、Azure、deSEC、阿里云、DNSPod 的接口地址是固定的，给了 `--endpoint` 会报错。

只在测试环境跑过的，`tested` 仍然是 `false`，可以提交报告，注明“测试环境”。

## 结果

报告不含 token，域名换成 `<domain>`、`<zone>`。报告里如果会出现某个密钥字段的值，工具不写报告并报错。服务商返回的错误文字可能带账户标识，提交前自己再看一遍。标准错误的第一行有真实域名，不要贴。

被打断时临时记录可能留下，名字是 `_buckyos-test-…`、`buckyos-test-…`，手工删掉。

通过的，提一个 PR：

1. 把 `src/components/cyfs-dns-provider/src/table.rs` 里这一家的 `tested` 改成 `true`。
2. PR 描述里贴 JSON 报告，写明：
   - 服务商和套餐，测试日期；
   - token 的权限是怎么收窄的，与用户文档是否一致；
   - 报告里 `detected_as` 不是这一家的，写出它的 NS 名字。
3. 用户文档里的步骤与后台不一致的，同时改 `buckyos/doc/user/dns-providers/<id>.md` 和 `buckyos/src/kernel/node_active/res/dns_providers/*.json`（9 种语言），把“没有用真实账号操作”“未核对”改掉。

不通过的，提 issue，贴报告。能看到服务商返回的错误码的一起贴，先去掉账户标识。

## 再进一步

接口通过后，用这个 token 真的激活一个 Zone（或在已有 Zone 的“设置”>“Zone 配置”里换成 DNS API），确认证书能签发、强制续期一次成功。ACME 可以先用 Let's Encrypt staging：激活前在节点的 `$BUCKYOS_ROOT/bin/node-active/active_config.json` 里加 `"acme_issuer": "https://acme-staging-v02.api.letsencrypt.org/directory"`。
