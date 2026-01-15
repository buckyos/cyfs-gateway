use log::*;
use std::collections::HashMap;
use chrono::Utc;
use serde_json::Value;
pub use sfo_result::err as cmd_err;
pub use sfo_result::into_err as into_cmd_err;
use sha2::Digest;
use crate::ExternalCmd;
use crate::gateway_control_server::{ControlErrorCode, ControlResult, LoginReq};
//TODO： CmdClient / CmdServer 的名字太通用了，叫gateway_control_panel_client / gateway_control_panel 更好一些？
pub const CONTROL_SERVER: &str = "http://127.0.0.1:13451";

pub struct GatewayControlClient {
    krpc: kRPC::kRPC,
}

impl GatewayControlClient {
    pub fn new(url: impl Into<String>, token: Option<String>) -> Self {
        Self {
            krpc: kRPC::kRPC::new(url.into().as_str(), token),
        }
    }

    pub async fn get_latest_token(&self) -> Option<String> {
        self.krpc.get_session_token().await
    }

    pub async fn login(&self, user_name: &str, password: &str) -> ControlResult<String> {
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
            .map_err(into_cmd_err!(ControlErrorCode::RpcError))?;
        result.as_str().ok_or_else(|| cmd_err!(ControlErrorCode::Failed)).map(|s| s.to_string())
    }

    pub async fn get_config(&self, config_type: Option<String>, config_id: Option<String>) -> ControlResult<Value> {
        let mut params = HashMap::new();
        if config_type.is_some() {
            params.insert("config_type", config_type.unwrap());
        }
        if config_id.is_some() {
            params.insert("config_id", config_id.unwrap());
        }
        let result = self.krpc.call("get_config", serde_json::to_value(&params).unwrap()).await
            .map_err(into_cmd_err!(ControlErrorCode::RpcError))?;

        Ok(result)
    }

    pub async fn del_rule(&self, id: &str) -> ControlResult<Value> {
        let mut params = HashMap::new();
        params.insert("id", id);
        let result = self.krpc.call("del_rule", serde_json::to_value(&params).unwrap()).await
            .map_err(into_cmd_err!(ControlErrorCode::RpcError))?;

        Ok(result)
    }

    pub async fn add_rule(&self, id: &str, rule: &str) -> ControlResult<Value> {
        let mut params = HashMap::new();
        params.insert("id", id);
        params.insert("rule", rule);
        let result = self.krpc.call("add_rule", serde_json::to_value(&params).unwrap()).await
            .map_err(into_cmd_err!(ControlErrorCode::RpcError))?;

        Ok(result)
    }

    pub async fn append_rule(&self, id: &str, rule: &str) -> ControlResult<Value> {
        let mut params = HashMap::new();
        params.insert("id", id);
        params.insert("rule", rule);
        let result = self.krpc.call("append_rule", serde_json::to_value(&params).unwrap()).await
            .map_err(into_cmd_err!(ControlErrorCode::RpcError))?;

        Ok(result)
    }

    pub async fn insert_rule(&self, id: &str, pos: i32, rule: &str) -> ControlResult<Value> {
        let mut params = HashMap::new();
        params.insert("id", id);
        params.insert("rule", rule);
        let pos = format!("{}", pos);
        params.insert("pos", pos.as_str());
        let result = self.krpc.call("insert_rule", serde_json::to_value(&params).unwrap()).await
            .map_err(into_cmd_err!(ControlErrorCode::RpcError))?;

        Ok(result)
    }

    pub async fn move_rule(&self, id: &str, new_pos: i32) -> ControlResult<Value> {
        let mut params = HashMap::new();
        params.insert("id", id);
        let pos = format!("{}", new_pos);
        params.insert("new_pos", pos.as_str());
        let result = self.krpc.call("move_rule", serde_json::to_value(&params).unwrap()).await
            .map_err(into_cmd_err!(ControlErrorCode::RpcError))?;

        Ok(result)
    }

    pub async fn get_connections(&self) -> ControlResult<Value> {
        let result = self.krpc.call("get_connections", Value::Null).await
            .map_err(into_cmd_err!(ControlErrorCode::RpcError))?;
        Ok(result)
    }

    pub async fn reload(&self) -> ControlResult<Value> {
        let result = self.krpc.call("reload", Value::Null).await
            .map_err(into_cmd_err!(ControlErrorCode::RpcError))?;
        Ok(result)
    }
    
    pub async fn get_external_cmds(&self) -> ControlResult<Vec<ExternalCmd>> {
        let result = self.krpc.call("external_cmds", Value::Null).await
            .map_err(into_cmd_err!(ControlErrorCode::RpcError))?;
        Ok(serde_json::from_value(result).map_err(into_cmd_err!(ControlErrorCode::InvalidData))?)
    }
    
    pub async fn get_external_cmd_help(&self, cmd: &str) -> ControlResult<String> {
        let mut params = HashMap::new();
        params.insert("cmd", cmd);
        let result = self.krpc.call("cmd_help", serde_json::to_value(&params).unwrap()).await
            .map_err(into_cmd_err!(ControlErrorCode::RpcError))?;
        Ok(serde_json::from_value(result).map_err(into_cmd_err!(ControlErrorCode::InvalidData))?)
    }
}
