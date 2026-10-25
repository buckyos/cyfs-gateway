# DirServer 使用文档

## 概述

`type: dir` 把一个本地目录发布成静态文件服务，适用于网站、下载和目录浏览。

- 实现：buckyos-base `src/buckyos-http-server/src/dir_server.rs`（`DirServer`）
- gateway 接入：`src/components/cyfs-gateway-lib/src/server/dir_server.rs`（`DirServerConfig` / `DirServerFactory`）
- 通常由 `type: http` server 的 `hook_point` 用 `call-server <id>` 调用；压缩等响应处理留在 `http` 层（见下文“压缩”）。

## 配置

```yaml
servers:
  main_http:
    type: http
    gzip: true
    gzip_types: [text/html, text/css, application/javascript]
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              call-server www;

  www:
    type: dir
    root_path: /var/www/html
    # base_url: /static            # 挂载前缀，解析前从请求 path 剥离
    # index_file: index.html
    # fallback_file: index.html    # 文件不存在时返回它（SPA）
    # autoindex: false
    # etag: true
    # if_modified_since: exact     # exact | before | off
    # cache_policy: html-revalidate
    # html_cache_control: no-cache
    # cache_control: "public, max-age=3600"
```

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `root_path` | 必填 | 根目录，启动时 canonicalize |
| `version` | `HTTP/1.1` | `HTTP/1.0`、`HTTP/1.1`、`HTTP/2`、`HTTP/3` |
| `base_url` | `/` | 挂载前缀，按整段剥离；不带前缀的 path 仍按根目录解析（是 rewrite，不是访问控制） |
| `index_file` | `index.html` | 目录的索引文件 |
| `fallback_file` | 无 | 目标不存在时返回的文件（相对 `root_path`，不能含 `..`），状态码 200 |
| `autoindex` | `false` | 目录没有索引文件时返回目录列表 |
| `etag` | `true` | 生成 `ETag` |
| `if_modified_since` | `exact` | `If-Modified-Since` 判定：`exact` 秒级相等、`before` 不晚于、`off` 不用 |
| `cache_policy` | `html-revalidate` | 预设：`html-revalidate` 给 HTML 响应加 `Cache-Control: no-cache`，其它文件不加；`none` 都不加 |
| `html_cache_control` | 由预设决定 | 覆盖 HTML 响应（含目录列表）的 `Cache-Control` |
| `cache_control` | 由预设决定 | 覆盖非 HTML 文件响应的 `Cache-Control` |

`Cache-Control` 随 200、206、304 和目录列表一起发送；取值在启动时校验，非法值或未知预设会让配置报 `InvalidConfig`。

## 请求处理

只支持 `GET` 和 `HEAD`，其它方法返回 405 并带 `Allow: GET, HEAD`。

### 路径解析

1. 请求 path 按 `/` 分段，每段百分号解码一次：`/a%20b.txt` → `a b.txt`，`/%2541.txt` → 字面文件名 `%41.txt`。
2. 空段和 `.` 忽略；`..`（包括 `%2e%2e`）返回 403；解码后含 `/`、NUL 的段（Windows 下还有 `\`、`:`、盘符）返回 400。非 UTF-8 字节在 Unix 上按原样作为文件名。
3. 剥离 `base_url` 的各段后拼到根目录下，再 canonicalize（跟随符号链接）；结果不在根目录内返回 403。
4. `Content-Type` 按请求选中的逻辑文件名推断（普通文件用请求里的名字，索引用 `index_file`，回退用 `fallback_file`），不按符号链接目标名推断。指向无扩展名文件的 `app.js` 仍是 JavaScript。

### 目录与回退

- 目标是目录，且有索引文件或开启了 `autoindex`：
  - 请求 path 不以 `/` 结尾时返回 301，`Location: ./<最后一段>/`，保留 query。使用相对地址，经过 `base_url` 或 process chain 的前缀 `rewrite` 后仍指向客户端看到的 URL。
  - 以 `/` 结尾时返回索引文件，没有索引文件时返回目录列表。
- 目录列表跳过 `.` 开头的条目；链接是相对的 `./<名字>`（目录带 `/`），名字按 URL 段编码（Unix 上按原始字节编码），点击即可解析回列出的文件。
- 以 `/` 结尾的 path 只表示目录，不会选中同名文件。
- 其余情况（不存在、目录没有可返回内容、以 `/` 结尾却是文件）：配置了 `fallback_file` 则返回它，否则 404。

### Range（RFC 9110 §14）

只对 `GET` 生效，只支持单个 `bytes` 范围。以 10 字节文件 `0123456789` 为例：

| `Range` | 结果 |
| --- | --- |
| `bytes=0-1` | 206，`01`，`Content-Range: bytes 0-1/10` |
| `bytes=-3` | 206，`789`（最后 3 字节） |
| `bytes=5-` | 206，`56789` |
| `bytes=5-999` | 206，`56789`（结束位置截到文件末尾） |
| `bytes=10-`、`bytes=-0` | 416，`Content-Range: bytes */10` |
| `bytes=0-1,7-8` | 不支持多段：200 返回完整文件 |
| `bytes=3-1`、`items=0-1` 等无效或未知单位 | 忽略：200 返回完整文件 |

空文件：`bytes=0-0`、`bytes=0-` 返回 416（`bytes */0`）；`bytes=-5` 返回 200 空内容。

### 条件请求（RFC 9110 §13）

- ETag 形如 `"<大小>-<mtime 秒>-<mtime 纳秒>"`（十六进制）。mtime 不晚于 Unix 纪元（可复现归档常见）时既不发 `ETag` 也不发 `Last-Modified`，因为这样的时间戳无法区分内容变化。
- 判定顺序：
  1. `If-Match`（强比较，`*` 只要文件存在即成立）不成立 → 412；没有 `If-Match` 时看 `If-Unmodified-Since`，文件更新过 → 412。
  2. `If-None-Match`（弱比较，`*` 只要文件存在即成立，与 `etag` 开关无关）成立 → 304；没有 `If-None-Match` 时按 `if_modified_since` 模式判断 `If-Modified-Since` → 304。
  3. 带 `Range` 的 `GET` 再看 `If-Range`：实体标签须强匹配、日期须与 `Last-Modified` 相等，否则返回完整的当前文件（200），断点续传不会拼出两个版本。
- 304 带 `ETag`、`Last-Modified` 和 `Cache-Control`。

### HEAD

返回与对应 `GET` 200 相同的头（含完整 `Content-Length`、`Accept-Ranges`、校验器），不读取文件内容，也不构造文件流；HEAD 忽略 `Range`。

### 内存

文件内容经固定 64 KiB 的读缓冲流式发送，单个请求的内存不随文件或范围大小增长。

### 压缩

`dir` 不做动态压缩，由 `type: http` server 在响应返回前处理（`post_hook_point` → `apply_response_compression`，配置项 `gzip` / `brotli` 等）。该层对静态文件的约束：

- 206、带 `Content-Range` 的响应（含 416）以及 `Cache-Control: no-transform` 的响应不压缩；
- 压缩后的响应去掉 `Accept-Ranges`，强 ETag 变为弱 ETag（`W/"..."`）。客户端拿弱 ETag 发 `If-None-Match` 仍得到 304；发 `If-Range` 时拿到完整的 200，不会把压缩缓存和原始字节的范围拼在一起。

### 状态码

- `200` 完整文件、索引、目录列表或回退文件
- `206` 单段 Range
- `301` 目录补尾部 `/`
- `304` 条件 GET/HEAD 未修改
- `400` 无效的 path 段
- `403` 路径穿越或目标在根目录外
- `404` 不存在
- `405` 方法不支持
- `412` `If-Match` / `If-Unmodified-Since` 不成立
- `416` Range 无法满足

## 代码使用

直接使用 `DirServer`：

```rust
use buckyos_http_server::DirServer;

let server = DirServer::builder()
    .id("www")
    .root_path("/var/www/html")
    .fallback_file("index.html")
    .cache_control("public, max-age=3600")
    .build()
    .await?;
```

通过 gateway 的工厂创建：

```rust
use cyfs_gateway_lib::{DirServerConfig, DirServerFactory, ServerFactory};
use std::sync::Arc;

let config: DirServerConfig = serde_yaml_ng::from_str(
    "id: www\ntype: dir\nroot_path: /var/www/html\ncache_policy: none\n",
)?;
let servers = DirServerFactory::new().create(Arc::new(config), None).await?;
```

## 测试

```bash
# DirServer 本身（buckyos-base）
cd buckyos-base/src && cargo test -p buckyos-http-server --lib dir_server

# gateway 配置透传与 call-server 链路（含压缩层）
cd cyfs-gateway/src && cargo test -p cyfs-gateway-lib --lib server::dir_server
```

联调未发布的 buckyos-base 时，用 `cargo --config <patch.toml>` 把 `[patch."https://github.com/buckyos/buckyos-base.git"]` 指向本地路径，不要改仓库里的 `Cargo.toml`。
