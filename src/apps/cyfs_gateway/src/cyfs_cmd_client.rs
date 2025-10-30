use std::collections::HashMap;
use chrono::Utc;
use serde_json::Value;
pub use sfo_result::err as cmd_err;
pub use sfo_result::into_err as into_cmd_err;
use sha2::Digest;
use crate::cyfs_cmd_server::{CmdErrorCode, CmdResult, LoginReq};

pub const CMD_SERVER: &str = "http://127.0.0.1:13451";

pub struct CyfsCmdClient {
    krpc: kRPC::kRPC,
}

impl CyfsCmdClient {
    pub fn new(url: impl Into<String>, token: Option<String>) -> Self {
        Self {
            krpc: kRPC::kRPC::new(url.into().as_str(), token),
        }
    }

    pub async fn get_latest_token(&self) -> Option<String> {
        self.krpc.get_session_token().await
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

    pub async fn del_chain(&self, config_type: &str, config_id: &str, chain_id: &str, hook_point: &str) -> CmdResult<Value> {
        let mut params = HashMap::new();
        params.insert("config_type", config_type);
        params.insert("config_id", config_id);
        params.insert("chain_id", chain_id);
        params.insert("hook_point", hook_point);
        let result = self.krpc.call("del_chain", serde_json::to_value(&params).unwrap()).await
            .map_err(into_cmd_err!(CmdErrorCode::RpcError))?;

        Ok(result)
    }

    pub async fn add_chain(&self, config_type: &str, config_id: &str, hook_point: &str, chain_id: &str, chain_type: &str, chain_params: &str) -> CmdResult<Value> {
        let mut params = HashMap::new();
        params.insert("config_type", config_type);
        params.insert("config_id", config_id);
        params.insert("chain_type", chain_type);
        params.insert("chain_params", chain_params);
        params.insert("hook_point", hook_point);
        params.insert("chain_id", chain_id);
        let result = self.krpc.call("add_chain", serde_json::to_value(&params).unwrap()).await
            .map_err(into_cmd_err!(CmdErrorCode::RpcError))?;

        Ok(result)
    }

    pub async fn get_connections(&self) -> CmdResult<Value> {
        let result = self.krpc.call("get_connections", Value::Null).await
            .map_err(into_cmd_err!(CmdErrorCode::RpcError))?;
        Ok(result)
    }

    pub async fn reload(&self) -> CmdResult<Value> {
        let result = self.krpc.call("reload", Value::Null).await
            .map_err(into_cmd_err!(CmdErrorCode::RpcError))?;
        Ok(result)
    }
}
