use log::*;
use std::collections::HashMap;
use std::sync::Mutex;
use chrono::Utc;
use serde_json::{json, Value};
pub use sfo_result::err as cmd_err;
pub use sfo_result::into_err as into_cmd_err;
use sha2::Digest;
use crate::ExternalCmd;
use crate::gateway_control_server::{ControlErrorCode, ControlResult, LoginReq};
//TODO： CmdClient / CmdServer 的名字太通用了，叫gateway_control_panel_client / gateway_control_panel 更好一些？
pub const CONTROL_SERVER: &str = "http://127.0.0.1:13451";

pub struct GatewayControlClient {
    url: String,
    token: Mutex<Option<String>>,
}

impl GatewayControlClient {
    pub fn new(url: impl Into<String>, token: Option<String>) -> Self {
        Self {
            url: url.into(),
            token: Mutex::new(token),
        }
    }

    fn build_krpc(&self) -> kRPC::kRPC {
        let token = self.token.lock().unwrap().clone();
        kRPC::kRPC::new(self.url.as_str(), token)
    }

    fn update_token(&self, token: Option<String>) {
        if let Some(token) = token {
            *self.token.lock().unwrap() = Some(token);
        }
    }

    async fn call(&self, method: &str, params: Value) -> ControlResult<Value> {
        let krpc = self.build_krpc();
        let result = krpc.call(method, params).await
            .map_err(into_cmd_err!(ControlErrorCode::RpcError))?;
        Ok(result)
    }

    pub async fn get_latest_token(&self) -> Option<String> {
        let _ = self.refresh().await;
        self.token.lock().unwrap().clone()
    }

    pub async fn refresh(&self) -> ControlResult<Option<String>> {
        let result = self.call("refresh_token", Value::Null).await?;
        let token = result.as_str().map(|s| s.to_string());
        self.update_token(token.clone());
        Ok(token)
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
        let result = self.call("login", serde_json::to_value(&req).unwrap()).await?;
        let token = result.as_str().ok_or_else(|| cmd_err!(ControlErrorCode::Failed))?.to_string();
        self.update_token(Some(token.clone()));
        Ok(token)
    }

    pub async fn get_config_by_id(&self, id: Option<&str>) -> ControlResult<Value> {
        let params = if let Some(id) = id {
            let mut params = HashMap::new();
            params.insert("id", id);
            serde_json::to_value(&params).unwrap()
        } else {
            Value::Null
        };
        self.call("get_config", params).await
    }

    pub async fn get_init_config(&self) -> ControlResult<Value> {
        self.call("get_init_config", Value::Null).await
    }

    pub async fn remove_rule(&self, id: &str) -> ControlResult<Value> {
        let mut params = HashMap::new();
        params.insert("id", id);
        self.call("remove_rule", serde_json::to_value(&params).unwrap()).await
    }

    pub async fn add_rule(&self, id: &str, rule: &str) -> ControlResult<Value> {
        let mut params = HashMap::new();
        params.insert("id", id);
        params.insert("rule", rule);
        self.call("add_rule", serde_json::to_value(&params).unwrap()).await
    }

    pub async fn append_rule(&self, id: &str, rule: &str) -> ControlResult<Value> {
        let mut params = HashMap::new();
        params.insert("id", id);
        params.insert("rule", rule);
        self.call("append_rule", serde_json::to_value(&params).unwrap()).await
    }

    pub async fn insert_rule(&self, id: &str, pos: i32, rule: &str) -> ControlResult<Value> {
        let mut params = HashMap::new();
        params.insert("id", id);
        params.insert("rule", rule);
        let pos = format!("{}", pos);
        params.insert("pos", pos.as_str());
        self.call("insert_rule", serde_json::to_value(&params).unwrap()).await
    }

    pub async fn move_rule(&self, id: &str, new_pos: i32) -> ControlResult<Value> {
        let mut params = HashMap::new();
        params.insert("id", id);
        let pos = format!("{}", new_pos);
        params.insert("new_pos", pos.as_str());
        self.call("move_rule", serde_json::to_value(&params).unwrap()).await
    }

    pub async fn set_rule(&self, id: &str, rule: &str) -> ControlResult<Value> {
        let mut params = HashMap::new();
        params.insert("id", id);
        params.insert("rule", rule);
        self.call("set_rule", serde_json::to_value(&params).unwrap()).await
    }

    pub async fn add_dispatch(&self, local: &str, target: &str, protocol: Option<&str>) -> ControlResult<Value> {
        let mut params = HashMap::new();
        params.insert("local", local);
        params.insert("target", target);
        if let Some(protocol) = protocol {
            params.insert("protocol", protocol);
        }
        self.call("add_dispatch", serde_json::to_value(&params).unwrap()).await
    }

    pub async fn remove_dispatch(&self, local: &str, protocol: Option<&str>) -> ControlResult<Value> {
        let mut params = HashMap::new();
        params.insert("local", local);
        if let Some(protocol) = protocol {
            params.insert("protocol", protocol);
        }
        self.call("remove_dispatch", serde_json::to_value(&params).unwrap()).await
    }

    pub async fn add_router(&self, server_id: Option<&str>, uri: &str, target: &str) -> ControlResult<Value> {
        let mut params = HashMap::new();
        if let Some(id) = server_id {
            params.insert("id", id);
        }
        params.insert("uri", uri);
        params.insert("target", target);
        self.call("add_router", serde_json::to_value(&params).unwrap()).await
    }

    pub async fn remove_router(&self, server_id: Option<&str>, uri: &str, target: &str) -> ControlResult<Value> {
        let mut params = HashMap::new();
        if let Some(id) = server_id {
            params.insert("id", id);
        }
        params.insert("uri", uri);
        params.insert("target", target);
        self.call("remove_router", serde_json::to_value(&params).unwrap()).await
    }

    pub async fn get_connections(&self) -> ControlResult<Value> {
        self.call("get_connections", Value::Null).await
    }

    pub async fn reload(&self) -> ControlResult<Value> {
        self.call("reload", Value::Null).await
    }

    pub async fn save_config(&self, config: Option<&str>) -> ControlResult<Value> {
        let params = if let Some(config) = config {
            let mut params = HashMap::new();
            params.insert("config", config);
            serde_json::to_value(&params).unwrap()
        } else {
            Value::Null
        };
        self.call("save_config", params).await
    }
    
    pub async fn get_external_cmds(&self) -> ControlResult<Vec<ExternalCmd>> {
        let result = self.call("external_cmds", Value::Null).await?;
        Ok(serde_json::from_value(result).map_err(into_cmd_err!(ControlErrorCode::InvalidData))?)
    }
    
    pub async fn get_external_cmd_help(&self, cmd: &str) -> ControlResult<String> {
        let mut params = HashMap::new();
        params.insert("cmd", cmd);
        let result = self.call("cmd_help", serde_json::to_value(&params).unwrap()).await?;
        Ok(serde_json::from_value(result).map_err(into_cmd_err!(ControlErrorCode::InvalidData))?)
    }

    pub async fn start_template(&self, template_id: &str, args: Vec<String>) -> ControlResult<Value> {
        let params = json!({
            "template_id": template_id,
            "args": args,
        });
        self.call("start", params).await
    }
}
