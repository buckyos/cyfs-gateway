# NdnServer 使用文档

## 概述

`NdnServer` 是一个基于 Named Data Network (NDN) 的 HTTP 服务器实现，用于提供命名数据对象的访问服务。它实现了 `HttpServer` trait，可以集成到 cyfs-gateway-lib 的服务器框架中。

## 核心功能

NdnServer 支持以下功能：

1. **GET 请求** - 获取 NDN 对象（chunk、chunk list、named object）
2. **PUT/PATCH 请求** - 上传 chunk 数据
3. **HEAD 请求** - 查询 chunk 状态
4. **范围请求** - 支持 HTTP Range 请求进行部分内容下载
5. **路径解析** - 支持多种对象 ID 解析方式（hostname、path、mgr path）

## 配置说明

### NamedDataMgrRouteConfig

```rust
pub struct NamedDataMgrRouteConfig {
    pub named_data_mgr_id: String,     // NamedDataMgr 实例的 ID
    pub read_only: bool,                // 是否只读模式
    pub guest_access: bool,             // 是否允许 zone 外访问
    pub is_object_id_in_path: bool,    // 对象 ID 是否在路径中
    pub enable_mgr_file_path: bool,    // 是否启用 mgr 文件路径模式
    pub enable_zone_put_chunk: bool,   // 是否允许上传 chunk
}
```

### NdnServerConfig

```rust
pub struct NdnServerConfig {
    pub id: String,                     // 服务器 ID
    pub ty: String,                     // 类型（应为 "ndn"）
    pub version: Option<String>,        // HTTP 版本（可选）
    pub named_mgr: NamedDataMgrRouteConfig,  // NDN 管理器配置
}
```

## 使用示例

### 1. 使用 Builder 模式创建服务器

```rust
use cyfs_gateway_lib::{NdnServer, NamedDataMgrRouteConfig};

let config = NamedDataMgrRouteConfig {
    named_data_mgr_id: "default".to_string(),
    read_only: false,
    guest_access: true,
    is_object_id_in_path: true,
    enable_mgr_file_path: true,
    enable_zone_put_chunk: true,
};

let server = NdnServer::builder()
    .id("ndn_server_1")
    .version("HTTP/1.1")
    .config(config)
    .build()
    .await?;
```

### 2. 使用 Factory 模式创建服务器

```rust
use cyfs_gateway_lib::{NdnServerConfig, NdnServerFactory, ServerFactory};
use std::sync::Arc;

let config = NdnServerConfig {
    id: "ndn_server_1".to_string(),
    ty: "ndn".to_string(),
    version: Some("HTTP/1.1".to_string()),
    named_mgr: NamedDataMgrRouteConfig::default(),
};

let factory = NdnServerFactory;
let server = factory.create(Arc::new(config)).await?;
```

### 3. JSON 配置示例

```json
{
  "id": "ndn_server_1",
  "type": "ndn",
  "version": "HTTP/1.1",
  "named_mgr": {
    "named_data_mgr_id": "default",
    "read_only": false,
    "guest_access": true,
    "is_object_id_in_path": true,
    "enable_mgr_file_path": true,
    "enable_zone_put_chunk": true
  }
}
```

## 请求处理流程

### GET 请求

1. **对象 ID 解析**：
   - 从 hostname 中解析对象 ID
   - 从路径中解析对象 ID
   - 使用 mgr 文件路径模式解析

2. **对象加载**：
   - Chunk：直接读取 chunk 数据
   - ChunkList：读取 chunk list 数据
   - NamedObject：读取命名对象的 JSON 数据

3. **响应构建**：
   - 设置适当的 Content-Type
   - 支持范围请求（206 Partial Content）
   - 添加 cyfs 相关的自定义 headers

### PUT/PATCH 请求

上传 chunk 数据到 NamedDataMgr：

```http
PUT /ndn/{chunk_id}
Headers:
  cyfs-chunk-size: 1048576
Body:
  <chunk binary data>
```

### HEAD 请求

查询 chunk 状态：

```http
HEAD /ndn/{chunk_id}

Response Headers:
  Content-Length: 1048576
  cyfs-chunk-status: completed
  cyfs-chunk-progress: 100
```

## 响应 Headers

NdnServer 返回的响应包含以下自定义 headers：

- `cyfs-obj-id`: 对象 ID（base32 编码）
- `cyfs-root-obj-id`: 根对象 ID（当使用 inner path 时）
- `cyfs-proof`: 验证证明（可选）
- `cyfs-path-obj`: 路径对象 JWT（可选）
- `cyfs-obj-size`: 对象大小（对于 chunk/chunk list）
- `cyfs-chunk-status`: Chunk 状态（对于 HEAD 请求）
- `cyfs-chunk-progress`: Chunk 下载进度（对于 HEAD 请求）

## URL 模式

NdnServer 支持多种 URL 模式来访问 NDN 对象：

### 1. 对象 ID 在路径中

```
GET /ndn/{obj_id}
GET /ndn/{obj_id}/{inner_path}
```

示例：
```
GET /ndn/5aSixgLwnWbmcSKvpiaLTqJzg7bxqoPYRCZSPu6Y6p5K
GET /ndn/5aSixgLwnWbmcSKvpiaLTqJzg7bxqoPYRCZSPu6Y6p5K/content
```

### 2. 对象 ID 在 hostname 中

```
GET https://{obj_id}.ndn.example.com/
```

示例：
```
GET https://5aSixgLwnWbmcSKvpiaLTqJzg7bxqoPYRCZSPu6Y6p5K.ndn.example.com/
```

### 3. Mgr 文件路径模式

```
GET /ndn/path/to/file
```

示例：
```
GET /ndn/test/my_file.txt
```

## 错误处理

NdnServer 返回标准的 HTTP 状态码：

- `200 OK`: 成功返回完整内容
- `201 Created`: Chunk 创建成功
- `206 Partial Content`: 返回部分内容（范围请求）
- `400 Bad Request`: 请求参数错误
- `403 Forbidden`: 权限不足或功能被禁用
- `404 Not Found`: 对象不存在
- `405 Method Not Allowed`: 不支持的 HTTP 方法
- `500 Internal Server Error`: 服务器内部错误

## 架构说明

### SyncChunkReader

为了使 `ChunkReader` 能够在多线程环境中安全使用（满足 `Sync` trait），NdnServer 实现了一个 `SyncChunkReader` 包装器：

```rust
struct SyncChunkReader {
    reader: Arc<tokio::sync::Mutex<ChunkReader>>,
}
```

这个包装器：
- 使用 `Arc<tokio::sync::Mutex<>>` 来包装 `ChunkReader`
- 实现了 `tokio::io::AsyncRead` trait
- 允许 `ChunkReader` 在服务器框架中安全使用

### 与 ndn_router 的区别

`NdnServer` 是基于 `cyfs-warp` 中的 `ndn_router` 实现的，但有以下关键区别：

1. **返回类型**：
   - `ndn_router`: 返回 `UnsyncBoxBody<Bytes, anyhow::Error>`
   - `NdnServer`: 返回 `BoxBody<Bytes, ServerError>`

2. **错误处理**：
   - `ndn_router`: 使用 `RouterError`
   - `NdnServer`: 使用 `ServerError` 和 `ServerErrorCode`

3. **集成方式**：
   - `ndn_router`: 直接处理 `hyper::Request<Incoming>`
   - `NdnServer`: 实现 `HttpServer` trait，集成到服务器框架

## 测试

NdnServer 包含单元测试来验证配置的序列化和反序列化：

```bash
cargo test --package cyfs-gateway-lib ndn_server
```

## 注册到服务器工厂

要在应用程序中使用 NdnServer，需要将其注册到 `CyfsServerFactory`：

```rust
use cyfs_gateway_lib::{CyfsServerFactory, NdnServerFactory};

let factory = CyfsServerFactory::new();
factory.register("ndn".to_string(), Arc::new(NdnServerFactory));
```

## 最佳实践

1. **只读模式**：对于公共访问的 NDN 服务，建议启用 `read_only` 模式
2. **访问控制**：使用 `guest_access` 控制是否允许 zone 外访问
3. **上传控制**：谨慎启用 `enable_zone_put_chunk`，避免滥用存储空间
4. **路径模式**：根据应用场景选择合适的对象 ID 解析模式
5. **缓存控制**：NdnServer 自动为 chunk 数据设置长期缓存（max-age=31536000）

## 相关文档

- [DIR Server 使用文档](dir_server_usage.md)
- [NDN Router 实现总结](dir_server_implementation_summary.md)
- [Process Chain 命令](process_chain_cmd.md)

