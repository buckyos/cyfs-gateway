use std::collections::HashMap;
use chrono::Utc;
use serde::Deserialize;
use serde_json::Value;
use cyfs_gateway_lib::{into_service_err, ServiceErrorCode, ServiceResult};
pub use sfo_result::err as cmd_err;
pub use sfo_result::into_err as into_cmd_err;
use sha2::Digest;
use crate::cyfs_cmd_server::{CmdErrorCode, CmdResult, LoginReq};

pub struct CyfsCmdClient {
    krpc: kRPC::kRPC,
}

impl CyfsCmdClient {
    pub fn new(url: String, token: Option<String>) -> Self {
        Self {
            krpc: kRPC::kRPC::new(url.as_str(), token),
        }
    }

    pub async fn login(&self, user_name: &str, password: &str) -> CmdResult<String> {
        let mut sha256 = sha2::Sha256::new();
        let timestamp = Utc::now().timestamp() as u64;
        sha256.update(format!("{}_{}_{}", user_name, password, timestamp));
        let password = hex::encode(sha256.finalize()).to_lowercase();
        let req = LoginReq {
            user_name: user_name.to_string(),
            password,
            timestamp,
        };
        let result = self.krpc.call("login", serde_json::to_value(&req).unwrap()).await
            .map_err(into_cmd_err!(CmdErrorCode::RpcError))?;
        result.as_str().ok_or_else(|| cmd_err!(CmdErrorCode::Failed)).map(|s| s.to_string())
    }

    pub async fn get_config(&self, config_type: Option<String>, config_id: Option<String>) -> CmdResult<Value> {
        let mut params = HashMap::new();
        if config_type.is_some() {
            params.insert("config_type", config_type.unwrap());
        }
        if config_id.is_some() {
            params.insert("config_id", config_id.unwrap());
        }
        let result = self.krpc.call("get_config", serde_json::to_value(&params).unwrap()).await
            .map_err(into_cmd_err!(CmdErrorCode::RpcError))?;

        Ok(result)
    }

    pub async fn get_connections(&self) -> CmdResult<Value> {
        let result = self.krpc.call("get_connections", Value::Null).await
            .map_err(into_cmd_err!(CmdErrorCode::RpcError))?;
        Ok(result)
    }
}
