use crate::*;
use buckyos_kit::AsyncStream;
use kRPC::RPCRequest;
use log::*;
use clap::{Arg, Command};
use cyfs_process_chain::{CollectionValue, CommandArgs, CommandHelpType, CommandResult, Context, EnvLevel, ExternalCommand, MapCollectionRef, command_help};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}};


#[async_trait::async_trait]
pub trait QAServer: Send + Sync {
    async fn serve_question(&self, req: &serde_json::Value) -> ServerResult<serde_json::Value>;
    fn id(&self) -> String;
}

const MAX_JSON_QUESTION_SIZE: usize = 10 * 1024 * 1024; // 10MB
pub async fn serve_qa_from_stream(mut stream: Box<dyn AsyncStream>, server: Arc<dyn QAServer>, info: StreamInfo) -> ServerResult<()> {
    // 增量读取并解析 JSON，直到成功解析出完整的 JSON 对象
    // 这种方式可以处理网速慢、数据分片到达的情况
    let mut buffer = Vec::new();
    let mut temp_buf = [0u8; 4096]; // 每次读取 4KB
    
    let request: serde_json::Value = loop {
        // 从流中读取数据块
        match stream.read(&mut temp_buf).await {
            Ok(0) => {
                // 连接关闭，尝试解析已有的数据
                if buffer.is_empty() {
                    error!("Connection closed before receiving any data from {}", 
                           info.src_addr.as_deref().unwrap_or("unknown"));
                    return Err(server_err!(ServerErrorCode::StreamError, "Connection closed before receiving data"));
                }
                
                // 尝试解析
                match serde_json::from_slice::<serde_json::Value>(&buffer) {
                    Ok(req) => break req,
                    Err(e) => {
                        error!("Failed to parse incomplete JSON from {}: {}", 
                               info.src_addr.as_deref().unwrap_or("unknown"), e);
                        
                        let error_response = serde_json::json!({
                            "error": "Invalid JSON",
                            "message": format!("Incomplete or invalid JSON: {}", e)
                        });
                        
                        if let Ok(response_str) = serde_json::to_string(&error_response) {
                            let _ = stream.write_all(response_str.as_bytes()).await;
                            let _ = stream.flush().await;
                        }
                        
                        return Err(server_err!(ServerErrorCode::InvalidData, "Invalid JSON: {}", e));
                    }
                }
            }
            Ok(n) => {
                // 追加读取的数据到缓冲区
                buffer.extend_from_slice(&temp_buf[..n]);
                
                // 尝试解析当前缓冲区中的数据
                match serde_json::from_slice::<serde_json::Value>(&buffer) {
                    Ok(req) => {
                        // 成功解析出完整的 JSON
                        break req;
                    }
                    Err(e) => {
                        // 如果是 EOF 错误，说明 JSON 不完整，继续读取
                        if e.is_eof() {
                            continue;
                        }
                        
                        // 如果是其他错误，可能是 JSON 格式错误
                        // 但也可能只是数据还没传输完，继续尝试
                        // 设置一个合理的大小限制，防止无限读取
                        if buffer.len() > MAX_JSON_QUESTION_SIZE {  // 10MB 限制
                            error!("JSON data too large (>10MB) from {}", 
                                   info.src_addr.as_deref().unwrap_or("unknown"));
                            
                            let error_response = serde_json::json!({
                                "error": "Invalid JSON",
                                "message": "JSON data too large"
                            });
                            
                            if let Ok(response_str) = serde_json::to_string(&error_response) {
                                let _ = stream.write_all(response_str.as_bytes()).await;
                                let _ = stream.flush().await;
                            }
                            
                            return Err(server_err!(ServerErrorCode::InvalidData, "JSON too large"));
                        }
                        
                        // 继续读取更多数据
                        continue;
                    }
                }
            }
            Err(e) => {
                error!("Error reading from stream: {}", e);
                return Err(server_err!(ServerErrorCode::StreamError, "Error reading from stream: {}", e));
            }
        }
    };
    
    let response = server.serve_question(&request).await;
    match response {
        Ok(response) => {
            let response_str = serde_json::to_string(&response).map_err(|e| server_err!(ServerErrorCode::EncodeError, "Failed to serialize response: {}", e))?;
            stream.write_all(response_str.as_bytes()).await.map_err(|e| server_err!(ServerErrorCode::StreamError, "Failed to write response: {}", e))?;
            stream.flush().await.map_err(|e| server_err!(ServerErrorCode::StreamError, "Failed to flush stream: {}", e))?;
            return Ok(())
        }
        Err(e) => {
            stream.shutdown().await.map_err(|e| server_err!(ServerErrorCode::StreamError, "Failed to shutdown stream: {}", e))?;
            return Err(server_err!(ServerErrorCode::StreamError, "Error serving question: {}", e));
        }
    }

}


pub fn qa_json_to_rpc_request(json_req: &serde_json::Value) -> ServerResult<RPCRequest> {
    let method = json_req.get("method").ok_or_else(|| server_err!(ServerErrorCode::InvalidParam, "method is required"))?;
    let method_str = method.as_str().ok_or_else(|| server_err!(ServerErrorCode::InvalidParam, "method is not a string"))?;
    let params = json_req.clone();

    Ok(RPCRequest::new(method_str, params))
}

//impl process chain command : qa
// usage:
//   qa server_id [map_id]    if map_id is not provided, it will use REQ
//
// after qa execute, it will return the result as a map collection,store in ANSWER

const CMD_QA_NAME: &str = "qa";
pub struct CmdQa {
    cmd: Command,
    server_manager: ServerManagerRef,
}

impl CmdQa {
    pub fn new(server_manager: ServerManagerRef) -> Self {
        let cmd = Command::new(CMD_QA_NAME)
            .about("Call QA Server to answer questions")
            .after_help(
                r#"
Call a QA Server to answer questions based on the provided request data.

Usage:
  qa <server_id> [map_id]

Arguments:
  <server_id>   The ID of the QA server to call
  [map_id]      Optional. The ID of the map collection containing the question data.
                If not provided, defaults to "REQ"

Behavior:
  - Retrieves the specified map collection from the environment (defaults to $REQ)
  - Converts the map to JSON format
  - Calls the QA server's serve_question method
  - Stores the result in $ANSWER as a map collection

Examples:
  qa my_qa_server
  qa my_qa_server CUSTOM_REQ
  echo $ANSWER.result_code
"#,
            )
            .arg(Arg::new("server_id")
                .required(true)
                .index(1)
                .help("The ID of the QA server to call"))
            .arg(Arg::new("map_id")
                .required(false)
                .index(2)
                .help("The ID of the map collection containing the question (defaults to REQ)"));

        Self { 
            cmd,
            server_manager 
        }
    }

    pub fn name(&self) -> &str {
        CMD_QA_NAME
    }
}

#[async_trait::async_trait]
impl ExternalCommand for CmdQa {
    fn help(&self, name: &str, help_type: CommandHelpType) -> String {
        assert_eq!(self.cmd.get_name(), name);
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        self.cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid command arguments: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        Ok(())
    }

    async fn exec(
        &self,
        context: &Context,
        _args: &[CollectionValue],
        origin_args: &CommandArgs,
    ) -> Result<CommandResult, String> {
        // Parse arguments
        let matches = self.cmd
            .clone()
            .try_get_matches_from(origin_args.as_str_list())
            .map_err(|e| {
                let msg = format!("Failed to parse arguments: {}", e);
                error!("{}", msg);
                msg
            })?;

        let server_id = matches.get_one::<String>("server_id")
            .ok_or_else(|| {
                let msg = "server_id is required".to_string();
                error!("{}", msg);
                msg
            })?;

        let map_id = matches.get_one::<String>("map_id")
            .map(|s| s.as_str())
            .unwrap_or("REQ");

        info!("will execute qa command: server_id={}, map_id={}", server_id, map_id);

        // Get the QA server
        let server = self.server_manager.get_qa_server(server_id);
        if server.is_none() {
            return Err(format!("QA server '{}' not found", server_id));
        }
        let qa_server = server.unwrap();

        // Get the request map from environment
        let req_value = context.env().get(map_id, None).await?
            .ok_or_else(|| {
                let msg = format!("Map '{}' not found in environment", map_id);
                error!("{}", msg);
                msg
            })?;

        let req_map = req_value.as_map()
            .ok_or_else(|| {
                let msg = format!("'{}' is not a map collection", map_id);
                error!("{}", msg);
                msg
            })?;

        // Convert map to JSON using the trait
        let request_json = req_map.to_json().await
            .map_err(|e| {
                let msg = format!("Failed to convert map '{}' to JSON: {}", map_id, e);
                error!("{}", msg);
                msg.to_string()
            })?;

        info!("Calling QA server '{}' with request: {}", server_id, request_json);

        // Call QA server
        let response_json = qa_server.serve_question(&request_json).await
            .map_err(|e| {
                let msg = format!("QA server '{}' failed: {}", server_id, e);
                error!("{}", msg);
                msg
            })?;

        info!("QA server '{}' response: {}", server_id, response_json);

        // Convert response JSON to map using the trait
        let answer_map = MapCollectionRef::from_json(&response_json).await
            .map_err(|e| {
                let msg = format!("Failed to convert JSON response to map: {}", e);
                error!("{}", msg);
                msg.to_string()
            })?;

        // Store result in ANSWER
        context.env().create("ANSWER", CollectionValue::Map(answer_map), EnvLevel::Global).await
            .map_err(|e| {
                let msg = format!("Failed to create ANSWER in environment: {}", e);
                error!("{}", msg);
                msg
            })?;

        info!("QA command completed successfully");
        Ok(CommandResult::success())
    }
}