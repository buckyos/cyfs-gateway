# HTTPS + RTCP 过渡节点快速部署

本文面向最常见的生产迁移场景：

- 一台服务器已经拥有稳定域名和正常的 HTTPS 服务；
- 保留现有 `https://<domain>` 入口；
- 同时增加 `rtcp://did:web:<domain>` 入口；
- RTCP 收到的 80/443 流量仍转发给本机原有 Web 服务。

示例使用：

```text
域名：edge.example.com
DID： did:web:edge.example.com
HTTPS：TCP 443
RTCP： TCP 2980
```

完整协议和安全模型见 [rtcp.md](rtcp.md)。本文只覆盖单机、单域名、已有 HTTPS 的
最小可运行闭环。

## 1. 部署完成后的链路

```text
普通 HTTPS 客户端
  -> edge.example.com:443
  -> 原有 Web Server

RTCP 客户端
  -> GET https://edge.example.com/.well-known/did.json
  -> 取得并锚定 edge.example.com 的设备公钥
  -> edge.example.com:2980 建立 RTCP tunnel
  -> cyfs-gateway RTCP process-chain
  -> 127.0.0.1:80 / 127.0.0.1:443
  -> 原有 Web Server
```

HTTPS 是 `did:web` 的身份发布面；RTCP 2980 是数据通道。两者必须同时可达，但互不
抢占端口，也不要求把原有 Web 服务迁入 cyfs-gateway。

## 2. `did:web` 在这里是 device，不是 zone

RTCP 解析 `did:web:edge.example.com` 时，首先从 `did:web` 的默认发布位置读取：

```text
https://edge.example.com/.well-known/did.json
```

名字解析层把不带显式 `doc_type` 的查询放在默认 `Zone` 槽位，但 RTCP 拿到文档后会
根据文档形状做最终分类：

- 包含 `device_type`：按 `DeviceDocument` 处理，把逻辑 DID 绑定到文档中的设备公钥；
- 不含 `device_type`、但包含 `hostname`：按 `ZoneDocument` 处理，使用其中的默认
  zone gateway 设备公钥；
- 两者都没有：拒绝；
- 两者都有：`device_type` 优先。

一台已有 HTTPS 服务的单机过渡节点应发布 `DeviceDocument`。只有当域名代表一个包含
多台设备的 zone，并且已经维护默认 gateway 文档时，才应发布 `ZoneDocument`。

## 3. 最小身份资产

目标机器需要三个 RTCP 身份文件：

| 文件 | 保密性 | 用途 |
| --- | --- | --- |
| `did.json` | PUBLIC | 通过 HTTPS 向远端发布设备 DID Document |
| `device_doc.jwt` 或 `device.jwt` | PUBLIC | 本机 RTCP stack 启动，并在需要时随 Hello 发送设备证明 |
| `authentication.private.pem` | SECRET | 签署 RTCP Hello/HelloAck，证明持有设备密钥 |

推荐只部署 `device_doc.jwt`，不要同时保留两份 JWT。当前探测顺序是
`device.jwt` → `device_doc.jwt` → `did.json`；两份 JWT 并存时，陈旧的
`device.jwt` 可能遮蔽新文件。

默认 identity roots 下的布局：

```text
/opt/buckyos/local/identity/edge.example.com/
├── did.json
└── device_doc.jwt

/opt/buckyos/security/edge.example.com/
└── authentication.private.pem
```

其中：

- `authentication.private.pem` 是 Ed25519 PKCS#8 PEM 私钥；
- `did.json` 是 JSON 编码的 `DeviceDocument`；
- `device_doc.jwt` 是同一个 `DeviceDocument` 的 compact JWT，正式环境由可信 owner
  key 签名；
- owner 私钥只在签发/控制面使用，不应部署到过渡节点；
- JWT 不含私钥，可以作为 PUBLIC 资产分发，但没有必要通过 Web 暴露。

如果进程设置了 `BUCKYOS_ROOT`、`BUCKYOS_IDENTITY_ROOT` 或
`BUCKYOS_SECURITY_ROOT`，实际根目录会随之改变。也可以在 gateway 配置中显式指定
`identity_manager` roots，避免依赖运行环境。

已有 Web 服务器的 TLS 证书和私钥可以继续使用，不要求复制到上述 RTCP identity
目录。只有让 cyfs-gateway 自己终止 HTTPS 时，才需要按 TLS identity 路径另外部署
`server.fullchain.pem` 和 `server.private.pem`。

以下材料不是 target-only 场景的最小要求：

- `authentication.public.jwk`：RTCP 会从私钥推导公钥，并与 DeviceDocument 校验；
- DNS TXT `DEV=` / `PKX=`：权威 HTTPS 正常时不需要，生产配置也不应开启
  `dns_txt_bootstrap`；
- `owner.json`：仅作为 RTCP target 被解析时不需要；作为具名 source 主动连接严格
  准入节点时，需要完整、可验证的 owner authority/binding。

## 4. DeviceDocument 合同

下面是结构示例，不要直接复制其中的公钥、时间戳或 owner：

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://buckyos.org/ns/device/v1"
  ],
  "id": "did:web:edge.example.com",
  "verificationMethod": [
    {
      "id": "#main_key",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:web:edge.example.com",
      "publicKeyJwk": {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "<base64url-ed25519-public-key>"
      }
    }
  ],
  "authentication": [
    "#main_key"
  ],
  "capabilityInvocation": [
    "#main_key"
  ],
  "owner": "<owner-did>",
  "device_type": "server",
  "name": "edge",
  "rtcp_port": 2980,
  "iat": 1767225600,
  "exp": 1798761600,
  "version_seq": 1
}
```

硬性要求：

1. `id` 必须逐字等于 RTCP 配置中的 `identity`；
2. `device_type` 必须存在，否则 RTCP 不会把它识别成一台 device；
3. authentication/default key 必须是有效的 Ed25519 JWK；
4. JWK 的 `x` 必须与 `authentication.private.pem` 推导出的公钥一致；
5. `iat`、`exp` 必须有效，轮换时 `version_seq`/时间线应单调推进；
6. `device_doc.jwt` 解码后的 `id`、公钥、owner、zone、有效期和 revision 必须与
   `did.json` 表达同一份身份。

本机加载优先选择 JWT，远端 `did:web` resolver 读取 `did.json`。因此两者应由同一次
签发生成并一起发布；不要分别手工编辑。当前仓库没有面向运维的通用身份签发 CLI，
生产部署应由现有 identity provisioner/控制面生成这三个文件。

## 5. 通过现有 HTTPS 发布 `did.json`

必须让公网请求：

```http
GET /.well-known/did.json HTTP/1.1
Host: edge.example.com
```

返回 `/opt/buckyos/local/identity/edge.example.com/did.json`。推荐响应：

```http
HTTP/1.1 200 OK
Content-Type: application/did+json
Cache-Control: public, max-age=300
```

Nginx 示例：

```nginx
location = /.well-known/did.json {
    alias /opt/buckyos/local/identity/edge.example.com/did.json;
    types { }
    default_type application/did+json;
    add_header Cache-Control "public, max-age=300" always;
}
```

只发布这一份 PUBLIC JSON；不要把整个 identity 或 security 目录配置成静态目录。

发布后验证：

```bash
curl -fsS -D - \
  https://edge.example.com/.well-known/did.json

curl -fsS \
  https://edge.example.com/.well-known/did.json |
  jq -e '
    .id == "did:web:edge.example.com" and
    (.device_type | type == "string") and
    (.verificationMethod | length > 0) and
    (.authentication | length > 0)
  '
```

这里必须使用公网域名和正常证书链。`curl -k` 成功不能证明 WebProvider 能成功解析。

## 6. 增加 RTCP stack

下面的配置保持原有 HTTPS 服务不变，在 TCP 2980 增加 RTCP，并只允许可信具名来源访问
本机 80/443：

```yaml
identity_manager:
  public_root_path: /opt/buckyos/local/identity
  security_root_path: /opt/buckyos/security

stacks:
  transition_rtcp:
    protocol: rtcp
    bind: 0.0.0.0:2980
    identity: did:web:edge.example.com

    peer_identity:
      requirement: authority_current
      dns_txt_bootstrap: false

    inbound_admission:
      anonymous: reject
      named_min_relation: any
      authority_reconfirm_max_age: unlimited

    hook_point:
      main:
        priority: 1
        blocks:
          allow_http:
            priority: 1
            block: |
              oneof ${REQ.source_identity_trust} "trusted_host_snapshot" "trusted_zone_snapshot" "method_authority_current" || reject;
              eq ${REQ.protocol} "tcp" && eq ${REQ.dest_port} "80" && return "forward tcp:///127.0.0.1:80";

          allow_https:
            priority: 2
            block: |
              oneof ${REQ.source_identity_trust} "trusted_host_snapshot" "trusted_zone_snapshot" "method_authority_current" || reject;
              eq ${REQ.protocol} "tcp" && eq ${REQ.dest_port} "443" && return "forward tcp:///127.0.0.1:443";

          default:
            priority: 100
            block: |
              reject;
```

`named_min_relation: any` 不是匿名放行：来源仍必须完成具名身份验证，只是不额外要求与
本机属于同一 owner/zone。面向同一组织内部设备时，应按实际模型收紧为
`known_owner` 或 `same_zone`。

如果使用默认 `/opt/buckyos` roots，可以省略顶层 `identity_manager`。显式配置更适合
容器、systemd 和多版本部署，能避免环境变量或可执行文件位置改变身份根目录。

启动：

```bash
cyfs_gateway --config_file /etc/cyfs_gateway.yaml
```

启动阶段会同时检查：

- 私钥文件可读且是支持的 Ed25519 私钥；
- JWT/JSON 能解析成 `DeviceDocument`；
- 文档 `id` 与 `identity` 一致；
- 文档 authentication key 与私钥匹配；
- 逻辑 DID 存在非空 `device_doc_jwt`。

## 7. 上线验收

### 7.1 身份发布面

```bash
dig +short A edge.example.com
dig +short AAAA edge.example.com

curl -fsS \
  https://edge.example.com/.well-known/did.json |
  jq -r '.id, .device_type, .rtcp_port'
```

预期：

```text
did:web:edge.example.com
server
2980
```

### 7.2 RTCP 端口

RTCP 当前监听 TCP：

```bash
nc -vz edge.example.com 2980
```

端口连通只证明 listener/firewall 正常，不代表身份握手已经通过。

### 7.3 身份加载

启动日志中不应出现：

```text
device_doc_jwt is required
public key not match
id ... does not match configured identity
```

如果 `did.json` 可访问但 gateway 启动失败，优先检查本机 JWT；如果 gateway 已启动但
远端不能解析 target，优先检查 DNS、HTTPS 证书和 `/.well-known/did.json`。

### 7.4 端到端 RTCP

客户端 target 使用：

```text
rtcp://did:web:edge.example.com/:80
rtcp://did:web:edge.example.com/:443
```

省略 RTCP stack 端口时默认连接 2980。业务目标端口仍由 URL path 中的 `:80`/`:443`
传给远端 process-chain。

可以使用 [RTCP SOCKS Proxy 配置示例](rtcp_socks_proxy_example.md) 建立客户端测试入口，
然后确认：

1. 客户端日志通过 `web-provider` 解析 `did:web:edge.example.com`；
2. 解析出的 canonical identity 是 `did:dev:<document-key>`；
3. tunnel 的 identity trust 不是 `dns_txt_bootstrap` 或匿名 `key_did`；
4. 80/443 请求到达原有 Web Server；
5. 非白名单端口被 process-chain 拒绝。

## 8. 常见失败

### 只有 `did.json` 和私钥

失败：

```text
rtcp stack did did:web:edge.example.com is not did:dev;
device_doc_jwt is required
```

补齐同目录的 `device_doc.jwt` 或 `device.jwt`。

### 公网 `did.json` 是 ZoneDocument

如果文档有 `hostname` 而没有 `device_type`，RTCP 会把域名当作 zone，并取默认 zone
gateway 的设备 key。对于单机过渡节点，这通常不是期望结果；应发布
`DeviceDocument`。

### HTTPS 成功，RTCP 2980 超时

检查安全组、防火墙、NAT 和 `bind`。HTTPS 443 与 RTCP 2980 是两个独立监听端口。

### RTCP 已监听，但远端报解析失败

依次检查：

1. DNS 是否指向当前节点；
2. TLS 证书是否受系统 CA 信任且覆盖当前域名；
3. `/.well-known/did.json` 是否返回 200；
4. JSON 的 `id` 是否与请求 DID 完全一致；
5. 是否包含 `device_type` 和可用的 Ed25519 authentication key；
6. CDN/反向代理是否仍缓存旧文档。

### 轮换后出现身份冲突

RTCP 把逻辑 DID 映射到由公钥得到的 canonical `did:dev`。轮换私钥意味着 canonical
device identity 改变。应把私钥、`did.json` 和 `device_doc.jwt` 作为同一个发布事务，
先保证 HTTPS 新文档可达，再滚动重启 RTCP，并为旧缓存和存量 tunnel 留出收敛时间。

## 9. 最小上线检查表

- [ ] 当前域名 HTTPS 正常，证书链受公共 CA 信任；
- [ ] `/.well-known/did.json` 返回 200 和正确的 `id`；
- [ ] `did.json` 是带 `device_type` 的 `DeviceDocument`；
- [ ] `did.json`、JWT、私钥三者使用同一 Ed25519 设备公钥；
- [ ] `device_doc.jwt` 由可信 owner 签发且仍在有效期内；
- [ ] security root 只有 gateway 运行用户可读；
- [ ] TCP 2980 对预期客户端开放；
- [ ] process-chain 只转发明确允许的协议、端口和 identity trust；
- [ ] `dns_txt_bootstrap` 保持关闭；
- [ ] 已完成一次真实 RTCP handshake 和 80/443 端到端请求。
