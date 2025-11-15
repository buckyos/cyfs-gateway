// 多 Trait Server 实现示例

use std::sync::Arc;
use cyfs_gateway_lib::*;

// 示例 1: 实现多个 Server Trait 的结构体
struct UniversalServer {
    id: String,
    bind_addr: String,
}

impl UniversalServer {
    pub fn new(id: String, bind_addr: String) -> Self {
        Self { id, bind_addr }
    }
}

// 实现 StreamServer trait
#[async_trait::async_trait]
impl StreamServer for UniversalServer {
    async fn serve_connection(&self, stream: Box<dyn AsyncStream>, info: StreamInfo) -> ServerResult<()> {
        info!("UniversalServer {} handling stream connection from {:?}", 
              self.id, info.src_addr);
        
        // 处理流连接...
        Ok(())
    }
    
    fn id(&self) -> String {
        self.id.clone()
    }
}

// 实现 HttpServer trait
#[async_trait::async_trait]
impl HttpServer for UniversalServer {
    async fn serve_request(
        &self, 
        req: http::Request<BoxBody<Bytes, ServerError>>, 
        info: StreamInfo
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        info!("UniversalServer {} handling HTTP request: {} {}", 
              self.id, req.method(), req.uri());
        
        // 处理 HTTP 请求...
        let response = http::Response::builder()
            .status(200)
            .body(BoxBody::default())
            .unwrap();
        
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

// 实现 QAServer trait
#[async_trait::async_trait]
impl QAServer for UniversalServer {
    async fn query(&self, query: &str) -> ServerResult<String> {
        info!("UniversalServer {} handling query: {}", self.id, query);
        
        match query {
            "status" => Ok("running".to_string()),
            "id" => Ok(self.id.clone()),
            "bind" => Ok(self.bind_addr.clone()),
            _ => Ok(format!("Unknown query: {}", query)),
        }
    }
    
    fn id(&self) -> String {
        self.id.clone()
    }
}

// 使用示例
pub async fn example_multi_trait_server() -> ServerResult<()> {
    let server_manager = Arc::new(ServerManager::new());
    
    // 创建一个多功能服务器实例
    let universal = Arc::new(UniversalServer::new(
        "universal-server".to_string(),
        "0.0.0.0:8080".to_string(),
    ));
    
    // 注册不同的能力
    info!("Registering universal-server with multiple traits...");
    
    // 注册 Stream 能力
    let stream_server = Server::Stream(universal.clone() as Arc<dyn StreamServer>);
    server_manager.add_server(stream_server)?;
    info!("✓ Registered as Stream: universal-server.stream");
    
    // 注册 HTTP 能力
    let http_server = Server::Http(universal.clone() as Arc<dyn HttpServer>);
    server_manager.add_server(http_server)?;
    info!("✓ Registered as HTTP: universal-server.http");
    
    // 注册 QA 能力
    let qa_server = Server::QA(universal.clone() as Arc<dyn QAServer>);
    server_manager.add_server(qa_server)?;
    info!("✓ Registered as QA: universal-server.qa");
    
    // 查询示例
    info!("\n=== Query Examples ===");
    
    // 1. 通过完整 key 查询
    if let Some(Server::Http(http)) = 
        server_manager.get_server_by_key("universal-server.http") {
        info!("Found HTTP server: {}", http.id());
    }
    
    // 2. 通过 id 和 type 查询
    if let Some(Server::Stream(stream)) = 
        server_manager.get_server_by_type("universal-server", "stream") {
        info!("Found Stream server: {}", stream.id());
    }
    
    // 3. 获取所有能力
    let all_servers = server_manager.get_all_servers_by_id("universal-server");
    info!("universal-server has {} capabilities:", all_servers.len());
    for server in &all_servers {
        info!("  - {} (full_key: {})", server.trait_type(), server.full_key());
    }
    
    // 4. 使用不同的能力
    info!("\n=== Using Different Capabilities ===");
    
    // 使用 HTTP 能力
    if let Some(Server::Http(http)) = 
        server_manager.get_server_by_type("universal-server", "http") {
        let req = http::Request::builder()
            .method("GET")
            .uri("/")
            .body(BoxBody::default())
            .unwrap();
        
        let info = StreamInfo::new("127.0.0.1:12345".to_string());
        let _resp = http.serve_request(req, info).await?;
        info!("✓ HTTP request handled");
    }
    
    // 使用 QA 能力
    if let Some(Server::QA(qa)) = 
        server_manager.get_server_by_type("universal-server", "qa") {
        let status = qa.query("status").await?;
        info!("✓ QA query result: {}", status);
    }
    
    Ok(())
}

// 示例 2: 专用服务器（只实现一个 trait）
struct SimpleHttpServer {
    id: String,
}

#[async_trait::async_trait]
impl HttpServer for SimpleHttpServer {
    async fn serve_request(
        &self, 
        _req: http::Request<BoxBody<Bytes, ServerError>>, 
        _info: StreamInfo
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        let response = http::Response::builder()
            .status(200)
            .body(BoxBody::default())
            .unwrap();
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

pub async fn example_single_trait_server() -> ServerResult<()> {
    let server_manager = Arc::new(ServerManager::new());
    
    // 创建只实现 HTTP 的服务器
    let simple = Arc::new(SimpleHttpServer {
        id: "simple-http".to_string(),
    });
    
    // 只注册 HTTP 能力
    server_manager.add_server(Server::Http(simple))?;
    info!("Registered simple-http.http");
    
    // 查询
    if let Some(server) = server_manager.get_server("simple-http") {
        info!("Found server: {} with type: {}", server.id(), server.trait_type());
    }
    
    // 尝试查询不存在的能力
    if server_manager.get_server_by_type("simple-http", "stream").is_none() {
        info!("simple-http does not have stream capability (as expected)");
    }
    
    Ok(())
}

// 示例 3: 动态能力管理
pub async fn example_dynamic_capability_management() -> ServerResult<()> {
    let server_manager = Arc::new(ServerManager::new());
    
    let universal = Arc::new(UniversalServer::new(
        "dynamic-server".to_string(),
        "0.0.0.0:9090".to_string(),
    ));
    
    // 初始只注册 HTTP
    server_manager.add_server(Server::Http(universal.clone() as Arc<dyn HttpServer>))?;
    info!("Initial: only HTTP capability");
    
    // 后续动态添加 Stream 能力
    server_manager.add_server(Server::Stream(universal.clone() as Arc<dyn StreamServer>))?;
    info!("Added: Stream capability");
    
    // 检查所有能力
    let caps = server_manager.get_all_servers_by_id("dynamic-server");
    info!("Now has {} capabilities", caps.len());
    
    // 删除特定能力
    server_manager.remove_server("dynamic-server.http");
    info!("Removed: HTTP capability");
    
    // 再次检查
    let caps = server_manager.get_all_servers_by_id("dynamic-server");
    info!("Now has {} capabilities", caps.len());
    
    // 清除所有能力
    server_manager.remove_servers_by_id("dynamic-server");
    info!("Removed all capabilities");
    
    let caps = server_manager.get_all_servers_by_id("dynamic-server");
    assert_eq!(caps.len(), 0);
    
    Ok(())
}

// 示例 4: 批量操作
pub async fn example_batch_operations() -> ServerResult<()> {
    let server_manager = Arc::new(ServerManager::new());
    
    // 注册多个服务器
    for i in 0..3 {
        let server = Arc::new(UniversalServer::new(
            format!("server-{}", i),
            format!("0.0.0.0:808{}", i),
        ));
        
        server_manager.add_server(Server::Http(server.clone() as Arc<dyn HttpServer>))?;
        server_manager.add_server(Server::Stream(server.clone() as Arc<dyn StreamServer>))?;
    }
    
    // 获取所有服务器
    let all = server_manager.get_all_servers();
    info!("Total servers: {}", all.len()); // 应该是 6 (3 * 2)
    
    // 只保留 HTTP 类型
    server_manager.retain(|key| key.ends_with(".http"));
    
    let remaining = server_manager.get_all_servers();
    info!("After filtering, remaining: {}", remaining.len()); // 应该是 3
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_multi_trait_registration() {
        let server_manager = Arc::new(ServerManager::new());
        let server = Arc::new(UniversalServer::new(
            "test-server".to_string(),
            "0.0.0.0:8080".to_string(),
        ));
        
        // 注册多个 trait
        server_manager.add_server(Server::Http(server.clone() as Arc<dyn HttpServer>)).unwrap();
        server_manager.add_server(Server::Stream(server.clone() as Arc<dyn StreamServer>)).unwrap();
        server_manager.add_server(Server::QA(server.clone() as Arc<dyn QAServer>)).unwrap();
        
        // 验证
        assert!(server_manager.get_server_by_type("test-server", "http").is_some());
        assert!(server_manager.get_server_by_type("test-server", "stream").is_some());
        assert!(server_manager.get_server_by_type("test-server", "qa").is_some());
        assert!(server_manager.get_server_by_type("test-server", "datagram").is_none());
        
        let all = server_manager.get_all_servers_by_id("test-server");
        assert_eq!(all.len(), 3);
    }
    
    #[tokio::test]
    async fn test_server_key_format() {
        let server = Arc::new(UniversalServer::new(
            "my-server".to_string(),
            "0.0.0.0:8080".to_string(),
        ));
        
        let http_server = Server::Http(server.clone() as Arc<dyn HttpServer>);
        assert_eq!(http_server.id(), "my-server");
        assert_eq!(http_server.trait_type(), "http");
        assert_eq!(http_server.full_key(), "my-server.http");
        
        let stream_server = Server::Stream(server.clone() as Arc<dyn StreamServer>);
        assert_eq!(stream_server.full_key(), "my-server.stream");
    }
    
    #[tokio::test]
    async fn test_dynamic_management() {
        let server_manager = Arc::new(ServerManager::new());
        let server = Arc::new(UniversalServer::new(
            "dynamic".to_string(),
            "0.0.0.0:8080".to_string(),
        ));
        
        // 添加
        server_manager.add_server(Server::Http(server.clone() as Arc<dyn HttpServer>)).unwrap();
        assert_eq!(server_manager.get_all_servers_by_id("dynamic").len(), 1);
        
        // 添加更多
        server_manager.add_server(Server::Stream(server.clone() as Arc<dyn StreamServer>)).unwrap();
        assert_eq!(server_manager.get_all_servers_by_id("dynamic").len(), 2);
        
        // 删除一个
        server_manager.remove_server("dynamic.http");
        assert_eq!(server_manager.get_all_servers_by_id("dynamic").len(), 1);
        assert!(server_manager.get_server_by_type("dynamic", "http").is_none());
        assert!(server_manager.get_server_by_type("dynamic", "stream").is_some());
        
        // 删除所有
        server_manager.remove_servers_by_id("dynamic");
        assert_eq!(server_manager.get_all_servers_by_id("dynamic").len(), 0);
    }
}

