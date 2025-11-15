# DirServer 使用文档

## 概述

`DirServer` 是一个基于本地文件夹的 HTTP 静态文件服务器，用于通过 HTTP 协议提供本地文件系统中的文件。

## 核心功能

1. **静态文件服务**: 从指定的根目录提供文件
2. **Range 请求支持**: 支持 HTTP Range 请求，适用于视频流、断点续传等场景
3. **MIME 类型自动检测**: 根据文件扩展名自动设置正确的 Content-Type
4. **目录索引**: 当请求目录时，自动提供 index.html（可配置）
5. **路径安全**: 防止路径遍历攻击，确保只能访问根目录内的文件

## 配置示例

### YAML 配置格式

```yaml
# 基本配置
id: static_files
type: dir
root_dir: /var/www/html
index_file: index.html  # 可选，默认为 index.html
version: HTTP/1.1       # 可选，默认为 HTTP/1.1

# 支持的 HTTP 版本
# - HTTP/0.9
# - HTTP/1.0
# - HTTP/1.1
# - HTTP/2
# - HTTP/3
```

### JSON 配置格式

```json
{
  "id": "static_files",
  "type": "dir",
  "root_dir": "/var/www/html",
  "index_file": "index.html",
  "version": "HTTP/1.1"
}
```

## 代码使用示例

### 示例 1: 基本使用

```rust
use cyfs_gateway_lib::{DirServer, DirServerFactory, ServerFactory};
use std::path::PathBuf;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 创建 DirServer
    let server = DirServer::builder()
        .id("my_static_server")
        .root_dir(PathBuf::from("/var/www/html"))
        .index_file("index.html")
        .version("HTTP/1.1")
        .build()
        .await?;

    println!("DirServer created: {}", server.id());
    
    Ok(())
}
```

### 示例 2: 使用工厂模式

```rust
use cyfs_gateway_lib::{DirServerConfig, DirServerFactory, ServerFactory};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 创建配置
    let config = DirServerConfig {
        id: "static_files".to_string(),
        ty: "dir".to_string(),
        version: Some("HTTP/1.1".to_string()),
        root_dir: "/var/www/html".to_string(),
        index_file: Some("index.html".to_string()),
    };

    // 使用工厂创建服务器
    let factory = DirServerFactory::new();
    let server = factory.create(Arc::new(config)).await?;

    println!("Server created successfully!");
    
    Ok(())
}
```

### 示例 3: 配合 ServerManager 使用

```rust
use cyfs_gateway_lib::{ServerManager, DirServerConfig, DirServerFactory};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 创建 ServerManager
    let server_mgr = Arc::new(ServerManager::new());

    // 注册 DirServer 工厂
    let factory = Arc::new(DirServerFactory::new());
    server_mgr.register_factory("dir", factory).await;

    // 创建配置
    let config = Arc::new(DirServerConfig {
        id: "static_files".to_string(),
        ty: "dir".to_string(),
        version: Some("HTTP/1.1".to_string()),
        root_dir: "/var/www/html".to_string(),
        index_file: Some("index.html".to_string()),
    });

    // 添加服务器
    server_mgr.add_server(config).await?;

    println!("DirServer registered and started!");
    
    Ok(())
}
```

## 特性说明

### 1. Range 请求支持

DirServer 完全支持 HTTP Range 请求，这对于大文件下载、视频流播放非常重要。

**客户端示例**:

```bash
# 请求文件的前 1024 字节
curl -H "Range: bytes=0-1023" http://localhost/large_file.bin

# 请求从第 1024 字节到文件末尾
curl -H "Range: bytes=1024-" http://localhost/large_file.bin
```

**响应头示例**:

```
HTTP/1.1 206 Partial Content
Content-Type: application/octet-stream
Content-Length: 1024
Content-Range: bytes 0-1023/10485760
Accept-Ranges: bytes
```

### 2. MIME 类型检测

DirServer 会根据文件扩展名自动设置正确的 Content-Type：

| 文件类型 | Content-Type |
|---------|-------------|
| .html   | text/html   |
| .css    | text/css    |
| .js     | application/javascript |
| .json   | application/json |
| .png    | image/png   |
| .jpg    | image/jpeg  |
| .mp4    | video/mp4   |
| .pdf    | application/pdf |
| 其他    | application/octet-stream |

### 3. 目录访问

当请求路径指向一个目录时，DirServer 会自动查找该目录下的索引文件（默认 `index.html`）：

```
请求: GET /docs/
实际文件: /var/www/html/docs/index.html
```

### 4. 路径安全

DirServer 包含路径遍历防护，防止访问根目录之外的文件：

```rust
// 这些请求会被拒绝（返回 403 Forbidden）
GET /../etc/passwd
GET /../../etc/passwd
GET /docs/../../etc/passwd
```

### 5. 错误处理

DirServer 会返回适当的 HTTP 状态码：

- `200 OK`: 成功返回完整文件
- `206 Partial Content`: 成功返回部分文件（Range 请求）
- `403 Forbidden`: 路径遍历尝试
- `404 Not Found`: 文件不存在
- `405 Method Not Allowed`: 不支持的 HTTP 方法（只支持 GET 和 HEAD）

## 核心实现参考

DirServer 的核心逻辑参考了 `router.rs` 中的 `handle_local_dir` 方法：

```rust:456:523:src/components/cyfs-warp/src/router.rs
async fn handle_local_dir(&self, req: Request<Incoming>, local_dir: &str, route_path: &str) -> RouterResult<Response<UnsyncBoxBody<Bytes, anyhow::Error>>> {
    let path = req.uri().path();
    let sub_path = buckyos_kit::get_relative_path(route_path, path);
    let file_path = if sub_path.starts_with("/") {
        Path::new(local_dir).join(&sub_path[1..])
    } else {
        Path::new(local_dir).join(&sub_path)
    };
    info!("handle_local_dir will load file:{}", file_path.to_string_lossy().to_string());
    let path = file_path.as_path();

    if path.is_file() {
        let file = tokio::fs::File::open(&path).await.map_err(|e| {
            warn!("Failed to open file: {}", e);
            RouterError::Internal(format!("Failed to open file: {}", e))
        })?;

        let file_meta = file.metadata().await.map_err(|e| {
            warn!("Failed to get file metadata: {}", e);
            RouterError::Internal(format!("Failed to get file metadata: {}", e))
        })?;
        let file_size = file_meta.len();
        let mime_type = mime_guess::from_path(&file_path).first_or_octet_stream();
        // 处理Range请求
        if let Some(range_header) = req.headers().get(hyper::header::RANGE) {
            if let Ok(range_str) = range_header.to_str() {
                if let Ok((start, end)) = parse_range(range_str, file_size) {
                    let mut file = tokio::io::BufReader::new(file);
                    // 设置读取位置
                    tokio::io::AsyncSeekExt::seek(&mut file, std::io::SeekFrom::Start(start)).await.map_err(|e| {
                        RouterError::Internal(format!("Failed to seek file: {}", e))
                    })?;

                    let content_length = end - start + 1;
                    let stream = tokio_util::io::ReaderStream::with_capacity(
                        file.take(content_length),
                        content_length as usize
                    );
                    let stream_body = StreamBody::new(stream.map_ok(Frame::data));

                    return Ok(Response::builder()
                        .status(StatusCode::PARTIAL_CONTENT)
                        .header("Content-Type", mime_type.as_ref())
                        .header("Content-Length", content_length)
                        .header("Content-Range", format!("bytes {}-{}/{}", start, end, file_size))
                        .header("Accept-Ranges", "bytes")
                        .body(BodyExt::map_err(stream_body, |e| anyhow::Error::from(e)).boxed_unsync()).map_err(|e| {
                            RouterError::Internal(format!("Failed to build response: {}", e))
                        })?);
                }
            }
        }

        // 非Range请求返回完整文件
        let stream = tokio_util::io::ReaderStream::with_capacity(file, file_size as usize);
        let stream_body = StreamBody::new(stream.map_ok(Frame::data));
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", mime_type.as_ref())
            .header("Content-Length", file_size)
            .header("Accept-Ranges", "bytes")
            .body(BodyExt::map_err(stream_body, |e| anyhow::Error::from(e)).boxed_unsync()).map_err(|e| {
                RouterError::Internal(format!("Failed to build response: {}", e))
            })?)
    } else {
        return Err(RouterError::NotFound(format!("File not found: {}", file_path.to_string_lossy().to_string())));
    }
}
```

## 性能优化建议

1. **使用合适的缓冲区大小**: DirServer 会根据文件大小自动调整缓冲区
2. **启用 HTTP/2 或 HTTP/3**: 对于多个小文件，启用多路复用可以提高性能
3. **配合反向代理**: 可以在前面加上 Nginx 等反向代理，提供缓存和负载均衡

## 最佳实践

1. **设置合理的根目录**: 确保根目录只包含需要公开的文件
2. **使用相对路径**: 在配置中使用相对路径可以提高可移植性
3. **日志监控**: 关注日志中的 404 和 403 错误，及时发现问题
4. **文件权限**: 确保 DirServer 运行用户有读取文件的权限

## 测试

项目包含完整的单元测试，覆盖以下场景：

- 服务器创建和配置验证
- 文件存在性检查
- Range 请求处理
- 错误处理（404、403、405）
- 工厂模式创建

运行测试：

```bash
cd src
cargo test --package cyfs-gateway-lib --lib server::dir_server
```

## 完整网关配置示例

```yaml
servers:
  - id: static_web
    type: dir
    root_dir: /var/www/html
    index_file: index.html
    version: HTTP/1.1

stacks:
  - id: http_stack
    type: tcp
    bind: 0.0.0.0:8080
    server: static_web
```

这样就可以在 8080 端口启动一个静态文件服务器！

