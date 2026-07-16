# cyfs-gateway Process Chain External Commands

本文档补充说明 `cyfs_gateway` 运行时默认注册的 process_chain external command。

说明：
- `src/components/cyfs-process-chain/doc/COMMAND_REFERENCE.md` 主要覆盖 `cyfs-process-chain` REPL 默认环境。
- `cyfs_gateway` 运行时会额外注册网关相关 external command。
- 如果需要当前构建下的完整命令帮助，建议直接导出：

```bash
cd src
cargo run -p cyfs_gateway -- process_chain --all --file /tmp/cyfs-gateway-process-chain-command-ref.md
```

## `forward`

把请求、stream 或 datagram 直接转发到 upstream URL。新版机制同时支持：

- 单 URL 转发：失败后不自动换目标
- 多候选选择：`round_robin`、`ip_hash`、`hash`、`consistent_hash`、`least_time`
- group 执行阶段故障切换：`--next-upstream`、`--tries`、`--next-upstream-timeout`
- primary / backup 和临时失败窗口：`--map`、`--backup-map`、`--max-fails`、`--fail-timeout`
- HTTP 受限状态码重试：`http_5xx`、`http_502`、`http_503`、`http_504`、`--max-body-buffer`

最小 group 示例：

```text
map-create PRIMARY;
map-add PRIMARY "tcp:///10.0.0.1:9000" 1;
map-add PRIMARY "tcp:///10.0.0.2:9000" 1;

map-create BACKUP;
map-add BACKUP "rtcp://backup.example.zone/:9000" 1;

forward round_robin \
        --map $PRIMARY \
        --backup-map $BACKUP \
        --next-upstream error,timeout \
        --tries 3 \
        --next-upstream-timeout 5s;
```

旧多 URL 写法如果没有 group 选项，仍只会预先选择一个 URL，不会在建链失败后自动尝试下一个。完整参数、map 构造示例和各入口的重试边界见 [forward 使用说明](forward使用说明.md)。

## `verify-jwt`

校验 JWT，并返回 payload map。

用法：

```text
verify-jwt <jwt-string> <public_key_map>
```

参数：
- `<jwt-string>`: 要校验的 JWT 字符串。
- `<public_key_map>`: `map<iss-id, pubkey_string>`。
  - key 是 JWT payload 中的 `iss`。
  - value 支持两种格式：
    - JWK JSON 字符串
    - Ed25519 公钥的 `x` 值字符串

行为：
- 先读取 JWT payload 中的 `iss`。
- 再从 `<public_key_map>` 中按 `iss` 取公钥。
- 复用现有 JWT 基础设施完成验签。
- 成功时返回 JWT payload，对应类型是 `map`。
- 失败时返回错误。

返回值：
- success: `map`
- error: 错误字符串

示例：

```text
local payload = $(verify-jwt $REQ.headers.authorization $JWT_PUBLIC_KEYS);
eq $payload.iss "did:example:alice" && eq $payload.sub "alice" && accept;
```

```text
local payload = $(verify-jwt $user_jwt $public_key_map);
match $payload.role "admin" && return --from lib "ok";
return --from lib "forbidden";
```

注意：
- 当前命令要求 payload 中存在 `iss`。
- `<public_key_map>` 必须是 `MapCollection`，不能是普通字符串。

## `parse-cookie`

解析 HTTP `Cookie` 头字符串，并返回 `map<field, value>`。

用法：

```text
parse-cookie <cookie-string>
```

参数：
- `<cookie-string>`: 例如 `sid=abc; theme=dark; lang=zh-CN`

行为：
- 按 `;` 分割 cookie field。
- 每个 field 按第一个 `=` 拆分为 key/value。
- 成功时返回 `map<field, value>`。
- 如果同一个 field 重复出现，后一个值覆盖前一个值。
- 如果某个 field 不是 `key=value` 格式，则返回错误。

返回值：
- success: `map`
- error: 错误字符串

示例：

```text
local cookie = $(parse-cookie $REQ.headers.cookie);
eq $cookie.session_id "abc123" && accept;
```

```text
local cookie = $(parse-cookie $raw_cookie);
match $cookie.theme "dark" && return --from lib "use-dark-theme";
```
