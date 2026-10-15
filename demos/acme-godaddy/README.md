# GoDaddy DNS-01 ACME service（Deno）

使用 GoDaddy Personal Access Token（PAT）和 DNS v3 API 完成 ACME DNS-01 验证，签发后按 BuckyOS
identity 规范安装 HTTPS 服务端证书。支持命令行执行，也提供 Linux systemd 服务和定时续期。

需要 Deno 2.x；域名的权威 DNS 必须托管于 GoDaddy。PAT 需要 `domains.dns:update` scope， 通过环境变量
`GODADDY_PAT` 读取，不作为命令行参数传递。

## 安装服务

在 Linux systemd 主机上执行：

```bash
cd demos/acme-godaddy

# 交互输入 PAT，输入不回显；也用于以后更新 token。
sudo ./setup_godaddy_token.sh

# 使用 root 拥有的 Deno 路径；域名可重复传入。
sudo ./install_service.sh --deno /usr/local/bin/deno \
  --zone buckyos.io \
  --domain '*.buckyos.io' \
  --email ops@buckyos.ai \
  --accept-terms --production

# 安装脚本只安装并 enable 定时器；显式启动服务申请第一张证书。
sudo systemctl start acme-godaddy.service
sudo systemctl start acme-godaddy.timer
sudo journalctl -u acme-godaddy.service -n 50 --no-pager
```

`setup_godaddy_token.sh` 将凭据原子写入 `/etc/buckyos/acme-godaddy.env`，权限为
`root:root 0600`。systemd 用 `EnvironmentFile` 在每次启动时注入 `GODADDY_PAT`，不依赖登录 shell 的
`.bashrc`、`.profile` 或执行 `sudo` 前的环境。更新 token 后，下次服务启动即生效。 该文件按 systemd
环境文件语法写入，不要用 shell `source` 加载。

`--deno` 应指向 root 拥有且其他用户不可改写的 Deno 可执行文件，其父目录也需由 root 管理。 如果 Deno
当前安装在普通用户家目录，需先部署到例如 `/usr/local/bin/deno`，再安装 root 服务。

服务是以 root 运行的系统级 `Type=oneshot` 服务，以便写入共享 identity/security 目录并保持私钥
`0600`；每次检查续期后退出，定时器每 12 小时运行一次。服务代码安装到
`$BUCKYOS_ROOT/libexec/acme-godaddy`，依赖缓存位于 `$BUCKYOS_ROOT/var/cache/acme-godaddy`，
不依赖仓库工作目录。首次运行需要能下载 `deno.lock` 锁定的 npm 依赖。

安装时可用 `--unit-name <name>` 管理多个 zone 的独立服务；每个服务的 `--domain` 参数对应一组 SAN
证书。部署根目录通过 `--buckyos-root` 指定，默认 `/opt/buckyos`。如需不同凭据文件，给
两个脚本都传入相同的 `--env-file <absolute-path>`。具体选项见各脚本的 `--help`。

若 CA 的多地验证尚未看到新 TXT，可在安装或手动运行命令中加入
`--propagation-delay 180 --propagation-timeout 600`。客户端确认权威 DNS 可见后额外等待 180 秒并复查，
通过后再提交 CA 验证；`--propagation-delay` 单位为秒，默认 `0`（不额外等待）。
`--propagation-timeout` 覆盖整个传播检查过程，必须大于额外等待时间。

## 手动运行

可以让进程从已有环境读取 `GODADDY_PAT`。交互测试时，用隐藏输入避免 token 进入命令历史：

```bash
read -r -s -p 'GoDaddy PAT: ' GODADDY_PAT; echo
export GODADDY_PAT

deno task start \
  --zone example.com \
  --domain example.com \
  --domain '*.example.com' \
  --email admin@example.com \
  --accept-terms \
  --buckyos-root /tmp/acme-demo

unset GODADDY_PAT
```

默认使用 Let's Encrypt staging；加 `--production` 才签发并安装生产证书。 `--domain`
可重复，每个域名必须等于 `--zone` 或位于其下；通配符只能出现在最左侧。 运行 `deno task start --help`
查看完整参数。

`./acme_buckyos_io.sh` 是申请 `*.buckyos.io` 的快捷入口，默认 production，邮箱默认
`ops@buckyos.ai`，可通过 `ACME_EMAIL` 覆盖；`ACME_PRODUCTION=0` 切换到 staging。
它同样从进程环境读取 token，额外参数直接转交 CLI，例如
`./acme_buckyos_io.sh --buckyos-root /opt/buckyos --force`。

## Identity 目录与续期

生产环境默认路径，以 `--domain '*.buckyos.io'` 为例：

```text
$BUCKYOS_ROOT/local/identity/_.buckyos.io/
  server.cert.pem
  server.chain.pem
  server.fullchain.pem
  server.meta.json

$BUCKYOS_ROOT/security/_.buckyos.io/
  server.private.pem

$BUCKYOS_ROOT/var/identity/state/acme/acme-godaddy/
  ... ACME account.key.pem、续期 state.json
```

普通域名直接作为目录名，`*.example.com` 映射为 `_.example.com`。指定多个域名时，签发一张 包含这些
SAN 的证书，并在每个域名对应的目录安装证书及私钥；每个目录有独立的 identity metadata。 ACME
账号和续期状态按 CA 与排序后的域名集合区分，放在状态目录，公开身份目录不含私钥。

| CLI 参数          | 环境变量 / 默认值                                     |
| ----------------- | ----------------------------------------------------- |
| `--buckyos-root`  | `BUCKYOS_ROOT`，否则 `/opt/buckyos`                   |
| `--identity-root` | `BUCKYOS_IDENTITY_ROOT`，否则 `<root>/local/identity` |
| `--security-root` | `BUCKYOS_SECURITY_ROOT`，否则 `<root>/security`       |
| `--state-root`    | `<root>/var/identity/state/acme/acme-godaddy`         |

CLI 参数优先于环境变量。staging 和 `--directory-url` 指定的非 Let's Encrypt production CA
始终在状态目录下按 CA 分隔，使用独立的 identity/security 目录，不写入正式公开身份及私钥根目录。
实际路径会在启动日志中输出。原来的 `--output` 和 `ACME_OUTPUT_DIR` 已移除。

激活前检查证书有效期、DNS SAN 和私钥匹配，并生成 `buckyos.identity.x509.metadata.v1`
metadata；所有新文件先暂存再替换正式文件。申请或校验失败不替换现有证书。文件替换是逐个 rename，
跨目录不具备整体原子性；续期状态最后写入，下次运行会检查文件一致性。

每次运行检查所有域名的安装材料，剩余有效期超过 30 天且材料一致时直接退出。 用 `--renew-before-days`
调整阈值，用 `--force` 强制签发。公开证书文件为 `0644`，私钥及 ACME 状态文件为
`0600`。消费证书的网关需能读取对应私钥，并自行 watch 或 reload；此服务不重启网关。

## Provider 接口与检查

[`dns_provider.ts`](./dns_provider.ts) 定义 `present` / `cleanup` 两个操作。GoDaddy provider 通过
POST 追加 TXT 记录，再按返回的 `recordId` 精确清理，允许同一名称的多个挑战值共存。 `acme-client` 的
DNS-01 回调传入的 `keyAuthorization` 已经是最终 TXT 值，不再重复做 SHA-256。

```bash
deno task test
deno task check
bash -n setup_godaddy_token.sh install_service.sh acme_buckyos_io.sh
python3 service_scripts_test.py
```

测试使用临时目录、本地证书材料及模拟 HTTP/systemctl，不申请真实证书，也不改动主机服务。 脚本测试覆盖
token 文件权限、环境文件转义和服务安装参数；需要 root 的用例在普通用户下会跳过。

目录和 metadata 约定见
[`did-identity-certificate-manager.md`](../../../buckyos-base/doc/did-identity-certificate-manager.md)。
