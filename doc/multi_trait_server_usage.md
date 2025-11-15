# ServerManager 多 Trait 支持使用指南

## 概述

ServerManager 现在支持一个 Server 实例同时实现多个 Server Trait，通过 `$server_id.$trait_type` 的命名方式实现。

## 核心特性

### 1. Server Key 格式

- **Full Key**: `$id.$trait_type`
  - 例如: `my-server.http`, `my-server.stream`, `my-server.qa`
- **基础 ID**: 不含类型后缀的 server id
  - 例如: `my-server`

### 2. Server 新增方法

```rust
impl Server {
    /// 获取 server 的基础 id
    pub fn id(&self) -> String;
    
    /// 获取 server 的 trait 类型名称
    /// 返回: "http", "stream", "datagram", "qa", "nameserver"
    pub fn trait_type(&self) -> &'static str;
    
    /// 获取完整的 server key: $id.$trait_type
    pub fn full_key(&self) -> String;
    
    /// 根据 id 和 trait_type 构建完整 key
    pub fn build_key(id: &str, trait_type: &str) -> String;
}
```

## 使用场景

### 场景 1: 单一 Trait 实现（向后兼容）

```rust
// 创建只实现 HttpServer 的服务
let http_server = Arc::new(MyHttpServer {
    id: "web-server".to_string(),
    // ...
});

let server = Server::Http(http_server);
server_manager.add_server(server)?;

// 查询（兼容旧代码）
let server = server_manager.get_server("web-server"); // ✅ 可以工作
```

### 场景 2: 多 Trait 实现

假设你有一个同时实现多个 trait 的结构体：

```rust
struct MyMultiServer {
    id: String,
    // ... 其他字段
}

impl StreamServer for MyMultiServer {
    async fn serve_connection(&self, stream: Box<dyn AsyncStream>, info: StreamInfo) -> ServerResult<()> {
        // 处理流连接
        Ok(())
    }
    
    fn id(&self) -> String {
        self.id.clone()
    }
}

impl HttpServer for MyMultiServer {
    async fn serve_request(&self, req: Request, info: StreamInfo) -> ServerResult<Response> {
        // 处理 HTTP 请求
        Ok(response)
    }
    
    fn id(&self) -> String {
        self.id.clone()
    }
    
    fn http_version(&self) -> http::Version {
        http::Version::HTTP_11
    }
    
    fn http3_port(&self) -> Option<u16> {
        None
    }
}

impl QAServer for MyMultiServer {
    async fn query(&self, query: &str) -> ServerResult<String> {
        // 处理查询
        Ok("answer".to_string())
    }
    
    fn id(&self) -> String {
        self.id.clone()
    }
}
```

#### 注册多个 Trait

```rust
let multi_server = Arc::new(MyMultiServer {
    id: "my-multi-server".to_string(),
    // ...
});

// 将同一个实例注册为不同的 trait 类型
server_manager.add_server(Server::Stream(multi_server.clone() as Arc<dyn StreamServer>))?;
server_manager.add_server(Server::Http(multi_server.clone() as Arc<dyn HttpServer>))?;
server_manager.add_server(Server::QA(multi_server.clone() as Arc<dyn QAServer>))?;

// 现在 ServerManager 内部存储了三个 entry:
// - "my-multi-server.stream" -> Server::Stream(...)
// - "my-multi-server.http" -> Server::Http(...)
// - "my-multi-server.qa" -> Server::QA(...)
```

### 场景 3: 查询 Server

#### 3.1 通过完整 Key 查询

```rust
// 精确查询特定 trait
if let Some(Server::Http(http_server)) = 
    server_manager.get_server_by_key("my-multi-server.http") {
    http_server.serve_request(req, info).await?;
}

if let Some(Server::Stream(stream_server)) = 
    server_manager.get_server_by_key("my-multi-server.stream") {
    stream_server.serve_connection(stream, info).await?;
}
```

#### 3.2 通过 ID 和类型查询

```rust
// 更安全的方式
if let Some(Server::Http(http_server)) = 
    server_manager.get_server_by_type("my-multi-server", "http") {
    http_server.serve_request(req, info).await?;
}
```

#### 3.3 获取某个 ID 的所有能力

```rust
// 获取 "my-multi-server" 的所有 trait 实现
let all_servers = server_manager.get_all_servers_by_id("my-multi-server");

for server in all_servers {
    match server {
        Server::Http(http_server) => {
            println!("有 HTTP 能力: {}", http_server.id());
        }
        Server::Stream(stream_server) => {
            println!("有 Stream 能力: {}", stream_server.id());
        }
        Server::QA(qa_server) => {
            println!("有 QA 能力: {}", qa_server.id());
        }
        _ => {}
    }
}
```

#### 3.4 兼容旧接口

```rust
// 向后兼容：返回第一个匹配的 server
let server = server_manager.get_server("my-multi-server");
// 返回 "my-multi-server.http" 或 "my-multi-server.stream" 或 "my-multi-server.qa" 中的任意一个
```

### 场景 4: 管理 Server

#### 4.1 替换 Server

```rust
let new_http_server = Arc::new(MyHttpServer { /* ... */ });
server_manager.replace_server(Server::Http(new_http_server));
// 只替换 "my-multi-server.http"，其他 trait 不受影响
```

#### 4.2 删除特定 Trait

```rust
// 只删除 HTTP 能力
server_manager.remove_server("my-multi-server.http");

// "my-multi-server.stream" 和 "my-multi-server.qa" 仍然存在
```

#### 4.3 删除所有 Trait

```rust
// 删除 "my-multi-server" 的所有能力
server_manager.remove_servers_by_id("my-multi-server");
```

### 场景 5: 遍历和过滤

```rust
// 获取所有 HTTP 类型的 server
let http_servers: Vec<_> = server_manager.get_all_servers()
    .into_iter()
    .filter(|s| s.trait_type() == "http")
    .collect();

// 保留特定条件的 server
server_manager.retain(|key| {
    // 保留所有 HTTP 和 Stream 类型，删除其他
    key.ends_with(".http") || key.ends_with(".stream")
});
```

## ServerFactory 适配

在实现 ServerFactory 时，可以返回多个 Server 实例：

```rust
#[async_trait::async_trait]
impl ServerFactory for MyMultiServerFactory {
    async fn create(&self, config: Arc<dyn ServerConfig>) -> ServerResult<Server> {
        let server = Arc::new(MyMultiServer::new(config)?);
        
        // 只能返回一个，需要在外部多次调用或者返回包装
        Ok(Server::Http(server.clone() as Arc<dyn HttpServer>))
    }
}

// 使用时需要手动注册其他 trait
let server_instance = factory.create(config).await?;
server_manager.add_server(server_instance)?;

// 手动注册其他能力
let http_server = server_instance.clone(); // 假设可以获取到原始实例
server_manager.add_server(Server::Stream(http_server as Arc<dyn StreamServer>))?;
```

## 最佳实践

### 1. 命名约定

- 使用 `get_server_by_type(id, type)` 而不是直接拼接字符串
- 使用 `server.full_key()` 获取完整 key

```rust
// ✅ 推荐
let key = Server::build_key("my-server", "http");
let server = server_manager.get_server_by_type("my-server", "http");

// ❌ 不推荐
let key = format!("my-server.http"); // 硬编码
```

### 2. 类型安全

```rust
// ✅ 使用模式匹配确保类型安全
if let Some(Server::Http(http_server)) = 
    server_manager.get_server_by_type(id, "http") {
    // 确保是 Http 类型
    http_server.serve_request(req, info).await?;
}

// ❌ 假设一定是某个类型
let server = server_manager.get_server(id).unwrap();
match server {
    Server::Http(s) => { /* ... */ }
    _ => panic!("Expected Http server"), // 可能 panic
}
```

### 3. 查询策略

```rust
// 场景：需要特定类型
// ✅ 使用 get_server_by_type
let http = server_manager.get_server_by_type(id, "http");

// 场景：接受任意类型
// ✅ 使用 get_server（兼容模式）
let any = server_manager.get_server(id);

// 场景：需要检查所有能力
// ✅ 使用 get_all_servers_by_id
let all = server_manager.get_all_servers_by_id(id);
```

## 优势

1. **类型安全**: 保持 enum 的类型检查优势
2. **灵活性**: 支持一个实例多个 trait
3. **向后兼容**: 旧代码仍然可以工作
4. **清晰语义**: `$id.$trait_type` 明确表达 "这是 id 的某个能力"
5. **独立管理**: 每个 trait 可以独立更新、删除

## 示例：DNS + QA 双重服务

```rust
struct DnsQaServer {
    id: String,
    dns_records: HashMap<String, String>,
}

impl NameServer for DnsQaServer { /* ... */ }
impl QAServer for DnsQaServer { /* ... */ }

// 注册
let server = Arc::new(DnsQaServer::new());
server_manager.add_server(Server::NameServer(server.clone() as Arc<dyn NameServer>))?;
server_manager.add_server(Server::QA(server.clone() as Arc<dyn QAServer>))?;

// 使用
// DNS 功能
if let Some(Server::NameServer(ns)) = 
    server_manager.get_server_by_type("dns-server", "nameserver") {
    ns.resolve(domain).await?;
}

// QA 功能
if let Some(Server::QA(qa)) = 
    server_manager.get_server_by_type("dns-server", "qa") {
    let status = qa.query("status").await?;
}
```

## 迁移指南

### 从旧代码迁移

旧代码无需修改即可工作：

```rust
// 旧代码 - 仍然可以工作
let server = server_manager.get_server("my-server");
```

### 使用新功能

```rust
// 新代码 - 明确指定类型
let http_server = server_manager.get_server_by_type("my-server", "http");
let stream_server = server_manager.get_server_by_type("my-server", "stream");
```

## 总结

通过 `$server_id.$trait_type` 的设计，ServerManager 现在可以：

- ✅ 支持一个实例注册多个 trait
- ✅ 保持 enum 的类型安全
- ✅ 向后兼容现有代码
- ✅ 提供灵活的查询接口
- ✅ 独立管理每个 trait 能力

