#![allow(unused)]
use crate::sn_db::{self, *};
use ::kRPC::*;
use async_trait::async_trait;
use cyfs_gateway_lib::{into_server_err, server_err};
use cyfs_gateway_lib::{
    qa_json_to_rpc_request, HttpServer, NameServer, ProcessChainConfig, QAServer, Server,
    ServerConfig, ServerContextRef, ServerError, ServerErrorCode, ServerFactory, ServerResult, StreamInfo,
};
use http::{Method, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Collected, Full};
use hyper::body::Bytes;
use jsonwebtoken::DecodingKey;
use lazy_static::lazy_static;
use log::*;
use name_client::*;
use name_lib::*;
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::{
    fmt::format,
    net::{IpAddr, Ipv4Addr},
    result::Result,
};
use tokio::sync::Mutex;
use crate::sqlite_db::SqliteSnDB;

#[derive(Serialize, Deserialize)]
pub struct OODInfo {
    //pub device_info: DeviceInfo,
    pub did_hostname: String,
    pub owner_id: String,
    pub self_cert: bool,
    pub state: String, //active,suspended,disabled,banned
}

#[derive(Clone)]
pub struct SNServer {
    id: String,
    //ipaddress is the ip from update_op's ip_from
    server_host: String,
    server_ip: IpAddr,
    server_aliases: Vec<String>,
    boot_jwt: String,
    owner_pkx: String,
    device_jwt: Vec<String>,
    db: SnDBRef,
}

impl SNServer {
    pub async fn new(server_config: SNServerConfig, db: SnDBRef) -> Self {
        let server_host = server_config.host;
        let server_ip = IpAddr::from_str(server_config.ip.as_str()).unwrap();

        SNServer {
            id: server_config.id,
            server_host: server_host,
            server_ip: server_ip,
            server_aliases: server_config.aliases,
            boot_jwt: server_config.boot_jwt,
            owner_pkx: server_config.owner_pkx,
            device_jwt: server_config.device_jwt,
            db,
        }
    }

    pub async fn check_username(&self, req: RPCRequest) -> Result<RPCResponse, RPCErrors> {
        let username = req.params.get("username");
        if username.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, username is none".to_string(),
            ));
        }
        let username = username.unwrap().as_str();
        let username = username.unwrap();
        let username = username.to_lowercase();

        // 检测用户名是否包含特殊字符
        if Self::contains_special_chars(username.as_str()) {
            return Err(RPCErrors::ParseRequestError(
                "Username contains special characters".to_string(),
            ));
        }

        let ret = self.db.is_user_exist(username.as_str()).await.map_err(|e| {
            error!("Failed to check username: {:?}", e);
            RPCErrors::ReasonError(e.to_string())
        })?;
        let resp = RPCResponse::create_by_req(
            RPCResult::Success(json!({
                "valid":!ret
            })),
            &req,
        );
        return Ok(resp);
    }

    // 辅助函数：检测字符串是否包含特殊字符
    fn contains_special_chars(s: &str) -> bool {
        s.chars()
            .any(|c| !c.is_alphanumeric() && !c.is_whitespace() && c != '_' && c != '-' && c != '.')
    }

    pub async fn check_active_code(&self, req: RPCRequest) -> Result<RPCResponse, RPCErrors> {
        let active_code = req.params.get("active_code");
        if active_code.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, active_code is none".to_string(),
            ));
        }
        let active_code = active_code.unwrap().as_str();
        if active_code.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, active_code is none".to_string(),
            ));
        }
        let active_code = active_code.unwrap();
        let ret = self.db.check_active_code(active_code).await;
        if ret.is_err() {
            return Err(RPCErrors::ReasonError(ret.err().unwrap().to_string()));
        }
        let valid = ret.unwrap();
        let resp = RPCResponse::create_by_req(
            RPCResult::Success(json!({
                "valid":valid
            })),
            &req,
        );
        return Ok(resp);
    }

    pub async fn register_user(&self, req: RPCRequest) -> Result<RPCResponse, RPCErrors> {
        let user_name = req.params.get("user_name");
        let public_key = req.params.get("public_key");
        let active_code = req.params.get("active_code");
        let zone_config_jwt = req.params.get("zone_config");
        let user_domain = req.params.get("user_domain");
        if user_name.is_none() || public_key.is_none() || active_code.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, user_name or public_key or active_code is none".to_string(),
            ));
        }
        let user_name = user_name.unwrap().as_str().unwrap();
        let public_key = public_key.unwrap().as_str().unwrap();
        let active_code = active_code.unwrap().as_str().unwrap();
        let zone_config_jwt = zone_config_jwt
            .and_then(|value| value.as_str())
            .unwrap_or("");

        let mut real_user_domain = None;
        if user_domain.is_some() {
            let user_domain = user_domain.unwrap();
            let user_domain_str = user_domain.as_str();
            if user_domain_str.is_some() {
                real_user_domain = Some(user_domain_str.unwrap().to_string());
            }
        }

        let ret = self.db.register_user(
            active_code,
            user_name,
            public_key,
            zone_config_jwt,
            real_user_domain,
        ).await;
        if ret.is_err() {
            let err_str = ret.err().unwrap().to_string();
            warn!(
                "Failed to register user {}: {:?}",
                user_name,
                err_str.as_str()
            );
            return Err(RPCErrors::ParseRequestError(format!(
                "Failed to register user: {}",
                err_str
            )));
        }

        info!(
            "user {} registered success, public_key: {}, active_code: {}",
            user_name, public_key, active_code
        );

        let resp = RPCResponse::create_by_req(
            RPCResult::Success(json!({
                "code":0
            })),
            &req,
        );
        return Ok(resp);
    }

    pub async fn register_device(&self, req: RPCRequest) -> Result<RPCResponse, RPCErrors> {
        let user_name = req.params.get("user_name");
        let device_name = req.params.get("device_name");
        let device_did = req.params.get("device_did");
        let mini_config_jwt = req.params.get("mini_config_jwt");
        let device_ip = req.params.get("device_ip");
        let device_info = req.params.get("device_info");

        if user_name.is_none()
            || device_name.is_none()
            || device_did.is_none()
            || mini_config_jwt.is_none()
            || device_ip.is_none()
            || device_info.is_none()
        {
            return Err(RPCErrors::ParseRequestError("Invalid params, user_name or device_name or device_did or mini_config_jwt or device_ip or device_info is none".to_string()));
        }
        let user_name = user_name.unwrap().as_str().unwrap();
        let device_name = device_name.unwrap().as_str().unwrap();
        let device_did = device_did.unwrap().as_str().unwrap();
        let mini_config_jwt = mini_config_jwt.unwrap().as_str().unwrap();
        let device_ip = device_ip.unwrap().as_str().unwrap();
        let device_info = device_info.unwrap().as_str().unwrap();

        //check token is valid (verify pub key is user's public key)
        let session_token = req.token.clone();
        if session_token.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, session_token is none".to_string(),
            ));
        }
        let session_token = session_token.unwrap();
        let mut rpc_session_token = RPCSessionToken::from_string(session_token.as_str())?;
        let user_public_key = self.get_user_public_key(user_name).await;
        if user_public_key.is_none() {
            warn!("user {} not found", user_name);
            return Err(RPCErrors::ParseRequestError("user not found".to_string()));
        }
        let user_public_key_str = user_public_key.unwrap();
        let user_public_key: jsonwebtoken::jwk::Jwk =
            serde_json::from_str(user_public_key_str.as_str()).map_err(|e| {
                error!("Failed to parse user public key: {:?}", e);
                RPCErrors::ParseRequestError(e.to_string())
            })?;

        let user_public_key = DecodingKey::from_jwk(&user_public_key).map_err(|e| {
            error!("Failed to decode user public key: {:?}", e);
            RPCErrors::ParseRequestError(e.to_string())
        })?;

        rpc_session_token.verify_by_key(&user_public_key)?;
        if rpc_session_token.aud != Some("sn".to_string()) {
            return Err(RPCErrors::ParseRequestError(format!("invalid aud {} expect sn", rpc_session_token.aud.clone().unwrap_or("None".to_string()))));
        }

        let mini_device_config = DeviceMiniConfig::from_jwt(mini_config_jwt, &user_public_key);
        if mini_device_config.is_err() {
            return Err(RPCErrors::ParseRequestError(format!(
                "Failed to parse mini device config: {}",
                mini_device_config.err().unwrap().to_string()
            )));
        }
        let mini_device_config = mini_device_config.unwrap();
        let dev_did = format!("did:dev:{}", mini_device_config.x.as_str());
        if dev_did.as_str() != device_did {
            return Err(RPCErrors::ParseRequestError(format!(
                "Invalid device did: {} (from jwt) != {} (from request)",
                dev_did, device_did
            )));
        }

        let ret = self.db.register_device(
            user_name,
            device_name,
            device_did,
            mini_config_jwt,
            device_ip,
            device_info,
        ).await;
        if ret.is_err() {
            let err_str = ret.err().unwrap().to_string();
            warn!(
                "Failed to register device {}_{}: {:?}",
                user_name,
                device_name,
                err_str.as_str()
            );
            return Err(RPCErrors::ParseRequestError(format!(
                "Failed to register device: {}",
                err_str
            )));
        }

        info!("device {}_{} registered success", user_name, device_name);

        let resp = RPCResponse::create_by_req(
            RPCResult::Success(json!({
                "code":0
            })),
            &req,
        );
        return Ok(resp);
    }

    pub async fn bind_zone_to_user(&self, req: RPCRequest) -> Result<RPCResponse, RPCErrors> {
        let user_name = req.params.get("user_name");
        let user_domain = req.params.get("user_domain");
        let zone_config_jwt = req.params.get("zone_config");

        if user_name.is_none() || zone_config_jwt.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, user_name or zone_config is none".to_string(),
            ));
        }
        let user_name = user_name.unwrap().as_str().unwrap();
        let zone_config_jwt = zone_config_jwt.unwrap().as_str().unwrap();

        let mut real_user_domain = None;
        if user_domain.is_some() {
            let user_domain = user_domain.unwrap();
            let user_domain_str = user_domain.as_str();
            if user_domain_str.is_some() {
                real_user_domain = Some(user_domain_str.unwrap().to_string());
            }
        }

        //check token is valid (verify pub key is user's public key)
        let session_token = req.token.clone();
        if session_token.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, session_token is none".to_string(),
            ));
        }
        let session_token = session_token.unwrap();
        let mut rpc_session_token = RPCSessionToken::from_string(session_token.as_str())?;
        let user_public_key = self.get_user_public_key(user_name).await;
        if user_public_key.is_none() {
            warn!("user {} not found", user_name);
            return Err(RPCErrors::ParseRequestError("user not found".to_string()));
        }
        let user_public_key_str = user_public_key.unwrap();
        let user_public_key: jsonwebtoken::jwk::Jwk =
            serde_json::from_str(user_public_key_str.as_str()).map_err(|e| {
                error!("Failed to parse user public key: {:?}", e);
                RPCErrors::ParseRequestError(e.to_string())
            })?;

        let user_public_key = DecodingKey::from_jwk(&user_public_key).map_err(|e| {
            error!("Failed to decode user public key: {:?}", e);
            RPCErrors::ParseRequestError(e.to_string())
        })?;

        rpc_session_token.verify_by_key(&user_public_key)?;

        // Update zone_config and user_domain in database
        self.db.update_user_zone_config(user_name, zone_config_jwt).await.map_err(|e| {
            error!("Failed to update zone_config for user {}: {:?}", user_name, e);
            RPCErrors::ParseRequestError(format!("Failed to update zone_config: {}", e))
        })?;

        if let Some(domain) = &real_user_domain {
            self.db.update_user_domain(user_name, Some(domain.clone())).await.map_err(|e| {
                error!("Failed to update user_domain for user {}: {:?}", user_name, e);
                RPCErrors::ParseRequestError(format!("Failed to update user_domain: {}", e))
            })?;
        }

        info!(
            "user {} zone_config and user_domain updated successfully",
            user_name
        );

        let resp = RPCResponse::create_by_req(
            RPCResult::Success(json!({
                "code":0
            })),
            &req,
        );
        return Ok(resp);
    }

    pub async fn update_device(
        &self,
        req: RPCRequest,
        ip_from: IpAddr,
    ) -> Result<RPCResponse, RPCErrors> {
        let device_info_json = req.params.get("device_info");
        let owner_id = req.params.get("owner_id");
        if owner_id.is_none() || device_info_json.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, owner_id or device_info is none".to_string(),
            ));
        }
        let owner_id = owner_id.unwrap().as_str();
        if owner_id.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, owner_id is none".to_string(),
            ));
        }
        let owner_id = owner_id.unwrap();
        let device_info_json = device_info_json.unwrap();
        let device_info =
            serde_json::from_value::<DeviceInfo>(device_info_json.clone()).map_err(|e| {
                error!("Failed to parse device info: {:?}", e);
                RPCErrors::ParseRequestError(e.to_string())
            })?;

        //check session_token is valid (verify pub key is device's public key)

        let old_device_info = self
            .get_device_info(owner_id, device_info.name.as_str())
            .await
            .map_err(|e| RPCErrors::ReasonError(format!("device info error: {}", e)))?;
        if old_device_info.is_none() {
            warn!("device {} not found", owner_id);
            return Err(RPCErrors::ParseRequestError("device not found".to_string()));
        }
        let (old_device_info, _) = old_device_info.unwrap();

        let session_token = req.token.clone();
        if session_token.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, session_token is none".to_string(),
            ));
        }
        let session_token = session_token.unwrap();
        let mut rpc_session_token = RPCSessionToken::from_string(session_token.as_str())?;
        let device_did = device_info.id.clone();

        let verify_public_key =
            DecodingKey::from_ed_components(old_device_info.id.id.as_str()).map_err(|e| {
                error!("Failed to decode device public key: {:?}", e);
                RPCErrors::ParseRequestError(e.to_string())
            })?;
        rpc_session_token.verify_by_key(&verify_public_key)?;

        info!(
            "start update {}_{} ==> {:?}",
            owner_id,
            device_info.name.clone(),
            device_info_json
        );
        let ip_str = ip_from.to_string();

        self.db.update_device_info_by_name(
            owner_id,
            &device_info.name.clone(),
            ip_str.as_str(),
            device_info_json.to_string().as_str(),
        ).await.map_err(|e| RPCErrors::ReasonError(format!("{}", e)));

        let resp = RPCResponse::create_by_req(
            RPCResult::Success(json!({
                "code":0
            })),
            &req,
        );
        

        let key = format!("{}_{}", owner_id, device_info.name.clone());

        info!("update device info done: for {}", key);
        return Ok(resp);
    }

    pub async fn get_device_by_public_key(
        &self,
        req: RPCRequest,
    ) -> Result<RPCResponse, RPCErrors> {
        let public_key = req
            .params
            .get("public_key")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                RPCErrors::ParseRequestError("Invalid params, public_key is none".to_string())
            })?
            .to_string();
        let pk_preview: String = public_key.chars().take(16).collect();
        info!(
            "get_device_by_public_key start: req_id={}, public_key_len={}, pk_preview={}",
            req.seq,
            public_key.len(),
            pk_preview
        );
        let device_name = "ood1";
        let user_info = {
            self.db.get_user_by_public_key(public_key.as_str()).await
                .map_err(|e| {
                    error!(
                        "Failed to query user by public_key {}, err: {:?}",
                        public_key, e
                    );
                    RPCErrors::ReasonError(e.to_string())
                })?
        };

        if user_info.is_none() {
            warn!("user not found for public_key {}", public_key);
            let response_value = json!({
                "user_name": Value::Null,
                "public_key": public_key,
                "device_name": device_name,
                "zone_config": Value::Null,
                "sn_ips": Vec::<String>::new(),
                "device_info": Value::Null,
                "device_sn_ip": Value::Null,
                "found": false,
                "reason": "user not found",
            });
            return Ok(RPCResponse::create_by_req(
                RPCResult::Success(response_value),
                &req,
            ));
        }

        let (username, zone_config, _) = user_info.unwrap();
        info!(
            "get_device_by_public_key matched username={} for req_id={}",
            username, req.seq
        );

        let mut device_info_err: Option<String> = None;
        let device_entry = match self.get_device_info(username.as_str(), device_name).await {
            Ok(entry) => entry,
            Err(e) => {
                warn!(
                    "device info parse failed for {}_{}: {}",
                    username, device_name, e
                );
                device_info_err = Some(e.to_string());
                None
            }
        };
        if device_entry.is_some() {
            info!(
                "device info found for {}_{} when querying by public_key",
                username, device_name
            );
        } else {
            warn!(
                "device info missing for {}_{} when querying by public_key",
                username, device_name
            );
        }

        let sn_ips_vec = self
            .get_user_sn_ips(username.as_str())
            .await
            .into_iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<String>>();
        debug!(
            "get_device_by_public_key collected {} sn_ips for user {}",
            sn_ips_vec.len(),
            username
        );

        let (device_info_value, device_sn_ip_value, reason_value) =
            if let Some((device_info, sn_ip)) = device_entry {
                let device_value = serde_json::to_value(device_info).map_err(|e| {
                    error!(
                        "Failed to serialize device info for {}_{}: {:?}",
                        username, device_name, e
                    );
                    RPCErrors::ReasonError(e.to_string())
                })?;
                (Some(device_value), Some(sn_ip.to_string()), Value::Null)
            } else {
                let reason = device_info_err
                    .unwrap_or_else(|| "device info not found".to_string());
                (None, None, Value::String(reason))
            };
        let found = device_info_value.is_some();

        let response_value = json!({
            "user_name": username,
            "public_key": public_key,
            "device_name": device_name,
            "zone_config": zone_config,
            "sn_ips": sn_ips_vec,
            "device_info": device_info_value,
            "device_sn_ip": device_sn_ip_value,
            "found": found,
            "reason": reason_value,
        });
        info!(
            "get_device_by_public_key success for user={}, device={}, device_found={}, sn_ip_cached={}",
            response_value["user_name"].as_str().unwrap_or_default(),
            response_value["device_name"].as_str().unwrap_or_default(),
            response_value["device_info"].is_object(),
            response_value["device_sn_ip"].is_string()
        );

        Ok(RPCResponse::create_by_req(
            RPCResult::Success(response_value),
            &req,
        ))
    }

    //get device info by device_name and owner_name
    pub async fn get_device(&self, req: RPCRequest) -> Result<RPCResponse, RPCErrors> {
        //verify request.sesion_token is valid (known device token)
        let device_id = req.params.get("device_id");
        let owner_id = req.params.get("owner_id");
        if owner_id.is_none() || device_id.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, owner_id or device_info is none".to_string(),
            ));
        }
        let device_id = device_id.unwrap().as_str();
        let owner_id = owner_id.unwrap().as_str();
        if device_id.is_none() || owner_id.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, device_id or owner_id is none".to_string(),
            ));
        }
        let device_id = device_id.unwrap();
        let owner_id = owner_id.unwrap();
        let device_info = self
            .get_device_info(owner_id, device_id)
            .await
            .map_err(|e| RPCErrors::ReasonError(format!("device info error: {}", e)))?;
        if device_info.is_some() {
            let device_info = device_info.unwrap();
            let device_value = serde_json::to_value(device_info.0).map_err(|e| {
                warn!("Failed to parse device info: {:?}", e);
                RPCErrors::ReasonError(e.to_string())
            })?;
            return Ok(RPCResponse::create_by_req(
                RPCResult::Success(device_value),
                &req,
            ));
        } else {
            warn!("device info not found for {}_{}", owner_id, device_id);
            let device_json = serde_json::to_value(device_info.clone()).unwrap();
            return Ok(RPCResponse::create_by_req(
                RPCResult::Success(device_json),
                &req,
            ));
        }
    }

    async fn get_user_sn_ips(&self, owner_id: &str) -> Vec<IpAddr> {
        let sn_ips = self.db.get_user_sn_ips_as_vec(owner_id).await;
        if sn_ips.is_err() {
            warn!(
                "failed to get user sn ips for {}: {:?}",
                owner_id,
                sn_ips.err().unwrap()
            );
            return vec![];
        }
        let sn_ips = sn_ips.unwrap();
        if sn_ips.is_none() {
            return vec![];
        }
        let sn_ips = sn_ips.unwrap();
        if sn_ips.is_empty() {
            return vec![];
        }
        let mut sn_ip_add: Vec<IpAddr> = Vec::new();
        for ip_str in sn_ips {
            let ip = IpAddr::from_str(ip_str.as_str());
            if ip.is_ok() {
                sn_ip_add.push(ip.unwrap());
            } else {
                warn!("failed to parse ip {} {}", ip_str, ip.err().unwrap());
            }
        }
        return sn_ip_add;
    }

    async fn get_device_info(
        &self,
        owner_id: &str,
        device_name: &str,
    ) -> ServerResult<Option<(DeviceInfo, IpAddr)>> {
        let key = format!("{}_{}", owner_id, device_name);
        let device_json = self.db.query_device_by_name(owner_id, device_name).await;
        if device_json.is_err() {
            warn!(
                    "failed to query device info for {} from db: {:?}",
                    key,
                    device_json.err().unwrap()
                );
            return Ok(None);
        };
        let device_json = device_json.unwrap();
        if device_json.is_none() {
            warn!("device info not found for {} in db", key);
            return Ok(None);
        }
        let device_json = device_json.unwrap();
        let sn_ip = &device_json.ip;
        let sn_ip = IpAddr::from_str(sn_ip.as_str()).unwrap();
        let device_info_json: String = device_json.description.clone();
        //info!("device info json: {}",device_info_json);
        let device_info = serde_json::from_str::<DeviceInfo>(device_info_json.as_str());
        if device_info.is_err() {
            let parse_err = device_info.err().unwrap();
            warn!(
                "failed to parse device info from db for {}: {} (schema/version mismatch, e.g. missing `iss`)",
                key,
                parse_err
            );
            return Err(server_err!(
                ServerErrorCode::InvalidData,
                "device info schema mismatch for {}: {}",
                key,
                parse_err
            ));
        }
        let device_info = device_info.unwrap();
        Ok(Some((device_info.clone(), sn_ip)))
    }
    //return (owner_public_key,zone_config_jwt,device_jwt)
    async fn get_user_zone_config_by_domain(
        &self,
        domain: &str,
    ) -> Option<(String, String, Option<String>)> {
        let user_info = self.db.get_user_info_by_domain(domain).await;

        if user_info.is_err() {
            warn!(
                "failed to get user info by domain {}: {:?}",
                domain,
                user_info.err().unwrap()
            );
            return None;
        }
        let user_info = user_info.unwrap();
        if user_info.is_none() {
            warn!("user info not found for domain {}", domain);
            return None;
        }
        let user_info = user_info.unwrap();
        let username = user_info.username.as_ref().unwrap();
        let zone_config_info = self.get_user_zone_config(username.as_str()).await;
        if zone_config_info.is_none() {
            warn!("zone config not found for user {}", username);
            return None;
        }
        let (public_key, zone_config, _sn_ips, device_jwt) = zone_config_info.unwrap();
        return Some((public_key, zone_config, device_jwt));
    }

    //return (owner_public_key,zone_config_jwt,sn_ip,device_jwt)
    async fn get_user_zone_config(
        &self,
        username: &str,
    ) -> Option<(String, String, Option<String>, Option<String>)> {
        let user_info = self.db.get_user_info(username).await;
        if user_info.is_err() {
            warn!(
                "failed to get user info for {}: {:?}",
                username,
                user_info.err().unwrap()
            );
            return None;
        }
        let user_info = user_info.unwrap();
        if user_info.is_some() {
            let user_info = user_info.unwrap();
            // 只存储前两个字段 (public_key, zone_config)，忽略 sn_ips
            let public_key = user_info.public_key.clone();
            let zone_config = user_info.zone_config.clone();
            let sn_ips = user_info.sn_ips.clone();
            let stored_info = (public_key.clone(), zone_config.clone());

            let device_info = self.db.query_device_by_name(username, "ood1").await;
            if device_info.is_ok() {
                let device_info = device_info.unwrap();
                if device_info.is_some() {
                    let device_info = device_info.unwrap();
                    let device_jwt = device_info.mini_config_jwt.clone();
                    if device_jwt.len() > 3 {
                        return Some((public_key, zone_config, sn_ips, Some(device_jwt)));
                    }
                }
            }

            return Some((public_key, zone_config, sn_ips, None));
        }
        warn!("zone config not found for [{}]", username);
        return None;
    }

    async fn get_user_public_key(&self, username: &str) -> Option<String> {
        let user_info = self.db.get_user_info(username).await;
        if user_info.is_err() {
            warn!(
                "failed to get user info for {}: {:?}",
                username,
                user_info.err().unwrap()
            );
            return None;
        }
        let user_info = user_info.unwrap();
        if user_info.is_some() {
            return Some(user_info.unwrap().public_key.clone());
        }
        return None;
    }

    //return (subhost,username)
    pub fn get_user_subhost_from_host(host: &str, server_host: &str) -> Option<(String, String)> {
        let end_string = format!(".web3.{}", server_host);
        if host.ends_with(&end_string) {
            let sub_name = host[0..host.len() - end_string.len()].to_string();
            if sub_name.contains(".") {
                let sub_name2 = sub_name.clone();
                let subs: Vec<&str> = sub_name.split(".").collect();
                let username = subs.last();
                if username.is_some() {
                    return Some((sub_name2, username.unwrap().to_string()));
                } else {
                    return None;
                }
            } else {
                if sub_name.contains("-") {
                    let sub_name2 = sub_name.clone();
                    let subs: Vec<&str> = sub_name.split("-").collect();
                    let username = subs.last();
                    if username.is_some() {
                        return Some((sub_name2, username.unwrap().to_string()));
                    } else {
                        return None;
                    }
                }
                return Some((sub_name.clone(), sub_name));
            }
        }
        return None;
    }

    async fn get_user_zonegate_address_by_domain(
        &self,
        domain: &str,
        record_type: RecordType,
    ) -> ServerResult<Option<Vec<IpAddr>>> {
        let user_info = self.db.get_user_info_by_domain(domain).await;
        if user_info.is_err() {
            warn!(
                "failed to get user info by domain {}: {:?}",
                domain,
                user_info.err().unwrap()
            );
            return Ok(None);
        }
        let user_info = user_info.unwrap();
        if user_info.is_none() {
            warn!("user info not found for domain {}", domain);
            return Ok(None);
        }
        let user_info = user_info.unwrap();

        return self
            .get_user_zonegate_address(user_info.username.as_ref().unwrap(), record_type)
            .await;
    }

    async fn add_address_to_vec(
        &self,
        address_vec: &mut Vec<IpAddr>,
        ip: IpAddr,
        record_type: RecordType,
    ) {
        if ip.is_loopback() {
            return;
        }
        if record_type == RecordType::A {
            if ip.is_ipv4() {
                address_vec.push(ip);
            }
        } else if record_type == RecordType::AAAA {
            if ip.is_ipv6() {
                address_vec.push(ip);
            }
        }
    }

    async fn get_user_zonegate_address(
        &self,
        username: &str,
        record_type: RecordType,
    ) -> ServerResult<Option<Vec<IpAddr>>> {
        //TODO:需要根据zone_boot_config中的gateway device name来获取gateway device info，而不是写死ood1
        let device_info = self.get_device_info(username, "ood1").await?;

        if device_info.is_some() {
            let (device_info, device_ip) = device_info.unwrap();
            let mut address_vec: Vec<IpAddr> = Vec::new();
            if !device_info.is_wan_device() {
                let sn_ips = self.get_user_sn_ips(username).await;
                if sn_ips.is_empty() {
                    self.add_address_to_vec(&mut address_vec, self.server_ip, record_type)
                        .await;
                } else {
                    for ip in sn_ips {
                        self.add_address_to_vec(&mut address_vec, ip, record_type)
                            .await;
                    }
                }
            }

            self.add_address_to_vec(&mut address_vec, device_ip, record_type).await;

            for device_report_ip in device_info.all_ip.iter() {
                self.add_address_to_vec(&mut address_vec, device_report_ip.clone(), record_type).await;
            }

            return Ok(Some(address_vec));
        }
        return Ok(None);
    }

    async fn add_dns_record(
        &self,
        req: RPCRequest,
    ) -> Result<RPCResponse, RPCErrors> {
        let session_token = req.token.clone();
        if session_token.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, session_token is none".to_string(),
            ));
        }
        let session_token = session_token.unwrap();
        let mut rpc_session_token = RPCSessionToken::from_string(session_token.as_str())?;

        let device_did = req.params.get("device_did");
        if device_did.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, user_name is none".to_string()
            ));
        }
        let device_did = device_did.unwrap().as_str();
        if device_did.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, user_name is none".to_string()
            ));
        }
        let device_did = device_did.unwrap();

        let device_info = self.db.query_device_by_did(device_did).await;
        if device_info.is_err() {
            warn!("device {} not found", device_did);
            return Err(RPCErrors::ParseRequestError("device not found".to_string()));
        }
        let device_info = device_info.unwrap();
        if device_info.is_none() {
            warn!("device {} not found", device_did);
            return Err(RPCErrors::ParseRequestError("device not found".to_string()));
        }
        let device_info = device_info.unwrap();
        let user_name = device_info.owner.as_str();
        let device_did = DID::from_str(device_info.did.as_str());
        if device_did.is_err() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, device_id is invalid".to_string()
            ));
        }
        let device_did = device_did.unwrap();

        let verify_public_key =
            DecodingKey::from_ed_components(device_did.id.as_str()).map_err(|e| {
                error!("Failed to decode device public key: {:?}", e);
                RPCErrors::ParseRequestError(e.to_string())
            })?;
        rpc_session_token.verify_by_key(&verify_public_key)?;
        
        let domain = req.params.get("domain");
        if domain.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, domain is none".to_string()
            ));
        }
        let domain = domain.unwrap().as_str();
        if domain.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, domain is none".to_string()
            ));
        }
        let domain = domain.unwrap();
        let record_type = req.params.get("record_type");
        if record_type.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, record_type is none".to_string()
            ));
        }
        let record_type = record_type.unwrap().as_str();
        if record_type.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, record_type is none".to_string()
            ));
        }
        let record_type = record_type.unwrap();

        let record_value = req.params.get("record");
        if record_value.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, record is none".to_string()
            ));
        }
        let record_value = record_value.unwrap().as_str();
        if record_value.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, record is none".to_string()
            ));
        }
        let record_value = record_value.unwrap();

        let ttl = req.params.get("ttl");
        if ttl.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, ttl is none".to_string()
            ));
        }
        let ttl = ttl.unwrap().as_i64();
        let ttl = if ttl.is_some() {
            ttl.unwrap()
        } else {
            600
        };

        let end_string = format!(".{}.web3.{}", user_name, self.server_host);
        if !domain.ends_with(end_string.as_str()) {
            return Err(RPCErrors::ParseRequestError(
                format!("Invalid params, domain is not end with {}", end_string)
            ));
        }

        let ret = self.db.add_user_domain(user_name, domain, record_type, record_value, ttl as u32).await;
        if ret.is_err() {
            let err_str = ret.err().unwrap().to_string();
            warn!(
                "Failed to add dns record {}_{}: {:?}",
                user_name,
                domain,
                err_str.as_str()
            );
            return Err(RPCErrors::ParseRequestError(format!(
                "Failed to add dns record: {}",
                err_str
            )));
        }

        info!("add dns record {} {} success", user_name, domain);

        let resp = RPCResponse::create_by_req(
            RPCResult::Success(json!({
                "code":0
            })),
            &req,
        );
        Ok(resp)
    }

    async fn remove_dns_record(
        &self,
        req: RPCRequest,
    ) -> Result<RPCResponse, RPCErrors> {
        let session_token = req.token.clone();
        if session_token.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, session_token is none".to_string(),
            ));
        }
        let session_token = session_token.unwrap();
        let mut rpc_session_token = RPCSessionToken::from_string(session_token.as_str())?;

        let device_did = req.params.get("device_did");
        if device_did.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, user_name is none".to_string()
            ));
        }
        let device_did = device_did.unwrap().as_str();
        if device_did.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, user_name is none".to_string()
            ));
        }
        let device_did = device_did.unwrap();

        let device_info = self.db.query_device_by_did(device_did).await;
        if device_info.is_err() {
            warn!("device {} not found", device_did);
            return Err(RPCErrors::ParseRequestError("device not found".to_string()));
        }
        let device_info = device_info.unwrap();
        if device_info.is_none() {
            warn!("device {} not found", device_did);
            return Err(RPCErrors::ParseRequestError("device not found".to_string()));
        }
        let device_info = device_info.unwrap();
        let user_name = device_info.owner.as_str();
        let device_did = DID::from_str(device_info.did.as_str());
        if device_did.is_err() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, device_id is invalid".to_string()
            ));
        }
        let device_did = device_did.unwrap();

        let verify_public_key =
            DecodingKey::from_ed_components(device_did.id.as_str()).map_err(|e| {
                error!("Failed to decode device public key: {:?}", e);
                RPCErrors::ParseRequestError(e.to_string())
            })?;
        rpc_session_token.verify_by_key(&verify_public_key)?;

        let domain = req.params.get("domain");
        if domain.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, domain is none".to_string()
            ));
        }
        let domain = domain.unwrap().as_str();
        if domain.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, domain is none".to_string()
            ));
        }
        let domain = domain.unwrap();
        let record_type = req.params.get("record_type");
        if record_type.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, record_type is none".to_string()
            ));
        }
        let record_type = record_type.unwrap().as_str();
        if record_type.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, record_type is none".to_string()
            ));
        }
        let record_type = record_type.unwrap();

        let has_cert = req.params.get("has_cert");
        if let Some(has_cert) = has_cert {
            let has_cert = has_cert.as_bool();
            if has_cert.is_some() && has_cert.unwrap() {
                let ret = self.db.update_user_self_cert(user_name, true).await;
                if ret.is_err() {
                    let err_str = ret.err().unwrap().to_string();
                    warn!("Failed to update user self cert: {}", err_str);
                    return Err(RPCErrors::ParseRequestError(format!(
                        "Failed to update user self cert: {}",
                        err_str
                    )));
                }
            }
        }

        let end_string = format!(".{}.web3.{}", user_name, self.server_host);
        if !domain.ends_with(end_string.as_str()) {
            return Err(RPCErrors::ParseRequestError(
                format!("Invalid params, domain is not end with {}", end_string)
            ));
        }

        let ret = self.db.remove_user_domain(user_name, domain, record_type).await;
        if ret.is_err() {
            let err_str = ret.err().unwrap().to_string();
            warn!(
                "Failed to remove dns record {}_{}: {:?}",
                user_name,
                domain,
                err_str.as_str()
            );
            return Err(RPCErrors::ParseRequestError(format!(
                "Failed to remove dns record: {}",
                err_str
            )));
        }

        info!("remove dns record {} {} success", user_name, domain);

        let resp = RPCResponse::create_by_req(
            RPCResult::Success(json!({
                "code":0
            })),
            &req,
        );
        Ok(resp)
    }

    async fn set_user_self_cert(&self, req: RPCRequest) -> Result<RPCResponse, RPCErrors> {
        // set_user_self_cert(name:String,self_cert:boolean)
        // `name` is username, but signature must be from any registered device of that user.
        let session_token = req.token.clone().ok_or_else(|| {
            RPCErrors::ParseRequestError("Invalid params, session_token is none".to_string())
        })?;

        let username = req
            .params
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                RPCErrors::ParseRequestError("Invalid params, name is none".to_string())
            })?;

        // self_cert is a bool flag; treat missing/null as false (delete).
        let self_cert = req
            .params
            .get("self_cert")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Parse token once, use token.sub as device_name (e.g. "ood1") to locate the device.
        let mut rpc_session_token = RPCSessionToken::from_string(session_token.as_str())?;
        let device_name = rpc_session_token.sub.clone().ok_or_else(|| {
            RPCErrors::ParseRequestError("Invalid token: sub is none".to_string())
        })?;
        if device_name.trim().is_empty() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid token: sub is empty".to_string(),
            ));
        }

        // Make sure user exists
        let user = self.db.get_user_info(username).await.map_err(|e| {
            RPCErrors::ReasonError(format!("failed to query user {}: {}", username, e))
        })?;
        if user.is_none() {
            return Err(RPCErrors::ParseRequestError("user not found".to_string()));
        }

        // Resolve device by (username, device_name), then verify token signature with that device's key.
        let device = self
            .db
            .query_device_by_name(username, device_name.as_str())
            .await
            .map_err(|e| RPCErrors::ReasonError(format!("query device failed: {}", e)))?;
        let device = device.ok_or_else(|| RPCErrors::ParseRequestError("device not found".to_string()))?;

        if device.owner != username {
            return Err(RPCErrors::ParseRequestError(
                "device has no permission".to_string(),
            ));
        }

        let device_did = DID::from_str(device.did.as_str()).map_err(|_| {
            RPCErrors::ParseRequestError("Invalid params, device_id is invalid".to_string())
        })?;
        let verify_public_key =
            DecodingKey::from_ed_components(device_did.id.as_str()).map_err(|e| {
                error!("Failed to decode device public key: {:?}", e);
                RPCErrors::ParseRequestError(e.to_string())
            })?;
        rpc_session_token.verify_by_key(&verify_public_key)?;

        let ret = self.db.update_user_self_cert(username, self_cert).await;
        if ret.is_err() {
            let err_str = ret.err().unwrap().to_string();
            warn!(
                "Failed to update user self cert for user {}: {}",
                username, err_str
            );
            return Err(RPCErrors::ParseRequestError(format!(
                "Failed to update user self cert: {}",
                err_str
            )));
        }

        info!(
            "set_user_self_cert success: user={}, device={}, self_cert={}",
            username,
            device.did.clone(),
            self_cert
        );
        Ok(RPCResponse::create_by_req(
            RPCResult::Success(json!({ "code": 0 })),
            &req
        ))
    }

    async fn set_user_did_document(&self, req: RPCRequest) -> Result<RPCResponse, RPCErrors> {
        // set_user_did_document(owner_user:String,obj_name:String,did_document:JSON,doc_type:String)
        let session_token = req.token.clone().ok_or_else(|| {
            RPCErrors::ParseRequestError("Invalid params, session_token is none".to_string())
        })?;
        let mut rpc_session_token = RPCSessionToken::from_string(session_token.as_str())?;

        let owner_user = req
            .params
            .get("owner_user")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                RPCErrors::ParseRequestError("Invalid params, owner_user is none".to_string())
            })?;
        if owner_user.trim().is_empty() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, owner_user is empty".to_string(),
            ));
        }

        let obj_name = req
            .params
            .get("obj_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                RPCErrors::ParseRequestError("Invalid params, obj_name is none".to_string())
            })?;
        if obj_name.trim().is_empty() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, obj_name is empty".to_string(),
            ));
        }

        let doc_type = req
            .params
            .get("doc_type")
            .and_then(|v| v.as_str())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        // Allow empty document; stringify to keep stored JSON text.
        let did_document_str = req
            .params
            .get("did_document")
            .map(|v| v.to_string())
            .unwrap_or_else(String::new);

        let user_public_key = self
            .get_user_public_key(owner_user)
            .await
            .ok_or_else(|| RPCErrors::ParseRequestError("user not found".to_string()))?;
        let user_public_key: jsonwebtoken::jwk::Jwk =
            serde_json::from_str(user_public_key.as_str()).map_err(|e| {
                error!("Failed to parse user public key: {:?}", e);
                RPCErrors::ParseRequestError(e.to_string())
            })?;

        let verify_public_key = DecodingKey::from_jwk(&user_public_key).map_err(|e| {
            error!("Failed to decode user public key: {:?}", e);
            RPCErrors::ParseRequestError(e.to_string())
        })?;

        rpc_session_token.verify_by_key(&verify_public_key)?;
        match rpc_session_token.sub.as_deref() {
            Some(sub) if sub == owner_user => {}
            Some(_) => {
                return Err(RPCErrors::ParseRequestError(
                    "token user mismatch".to_string(),
                ))
            }
            None => {
                return Err(RPCErrors::ParseRequestError(
                    "Invalid token: sub is none".to_string(),
                ))
            }
        }
        
        let mut hasher = Sha256::new();
        hasher.update(did_document_str.as_bytes());
        let obj_id = hex::encode(hasher.finalize());

        let ret = self
            .db
            .insert_user_did_document(
                obj_id.as_str(),
                owner_user,
                obj_name,
                did_document_str.as_str(),
                doc_type.as_deref(),
            )
            .await;
        if let Err(e) = ret {
            let err_str = e.to_string();
            warn!(
                "Failed to insert did document owner={}, obj_name={}, err={}",
                owner_user, obj_name, err_str
            );
            return Err(RPCErrors::ReasonError(err_str));
        }

        info!(
            "set_user_did_document success: owner={}, obj_name={}, obj_id={}, doc_type={:?}",
            owner_user, obj_name, obj_id, doc_type
        );

        Ok(RPCResponse::create_by_req(
            RPCResult::Success(json!({ "code": 0, "obj_id": obj_id })),
            &req,
        ))
    }

    async fn handle_rpc_call(
        &self,
        req: RPCRequest,
        ip_from: IpAddr,
    ) -> Result<RPCResponse, RPCErrors> {
        info!("sn server handle rpc call: {}", req.method);
        match req.method.as_str() {
            "check_active_code" => {
                //check active code
                return self.check_active_code(req).await;
            }
            "check_username" => {
                //check username
                return self.check_username(req).await;
            }
            "register_user" => {
                //register user
                return self.register_user(req).await;
            }
            "bind_zone_config" => {
                //bind zone config to user
                return self.bind_zone_to_user(req).await;
            }
            "set_user_self_cert" => {
                //update user self cert
                // set_user_self_cert(name:String,self_cert:boolean) ,如果cert为空，则删除对应的cert
                // 只需要有设备的签名就可以更新用户的self cert
                return self.set_user_self_cert(req).await;
            }
            "set_user_did_document" => {
                //set_user_did_document(owner_user:String,obj_name:String,did_document:JSON,doc_type:String)
                // 保存在数据库中记录为  obj_id(did_document计算得到),owner_user,obj_name,did_document,doc_type(可以为空),update_time
                // 设置成功可以在query_did_document中查询到（查询update_time最新的一条记录）,did是 did:bns:obj_name.user_name
                // 如果document为空，则插入一条did_document为空的记录。数据库不删除记录，保存所有曾经设置过的did_document,给用户提供一定的回滚能力
                // 需要有用户的签名才可以更新用户的did document
                return self.set_user_did_document(req).await;
            }
            "register" => {
                //register device
                return self.register_device(req).await;
            }
            "update" => {
                //update device info
                return self.update_device(req, ip_from).await;
            }
            "get" => {
                //get device info
                return self.get_device(req).await;
            }
            "get_by_pk" => {
                // get ood all info by public_key
                return self.get_device_by_public_key(req).await;
            }
            "query_by_hostname" => {
                //query device by hostname
                let hostname = req.params.get("dest_host");
                if hostname.is_none() {
                    return Err(RPCErrors::ParseRequestError(
                        "Invalid params, hostname is none".to_string(),
                    ));
                }
                let hostname = hostname.unwrap().as_str();
                if hostname.is_none() {
                    return Err(RPCErrors::ParseRequestError(
                        "Invalid params, hostname is none".to_string(),
                    ));
                }
                let hostname = hostname.unwrap();
                let ood_info = self.query_device_by_hostname(hostname).await;
                if ood_info.is_some() {
                    let ood_info = ood_info.unwrap();
                    let ood_json = serde_json::to_value(ood_info).unwrap();
                    return Ok(RPCResponse::create_by_req(
                        RPCResult::Success(ood_json),
                        &req,
                    ));
                } else {
                    return Err(RPCErrors::ParseRequestError(
                        "Invalid params, hostname is none".to_string(),
                    ));
                }
            }
            "query_by_did" => {
                let did = req.params.get("source_device_id");
                if did.is_none() {
                    return Err(RPCErrors::ParseRequestError(
                        "Invalid params, did is none".to_string(),
                    ));
                }
                let did = did.unwrap().as_str();
                if did.is_none() {
                    return Err(RPCErrors::ParseRequestError(
                        "Invalid params, did is none".to_string(),
                    ));
                }
                let did = did.unwrap();
                let ood_info = self.query_by_did(did).await;
                if ood_info.is_some() {
                    let ood_info = ood_info.unwrap();
                    let ood_json = serde_json::to_value(ood_info).unwrap();
                    return Ok(RPCResponse::create_by_req(
                        RPCResult::Success(ood_json),
                        &req,
                    ));
                } else {
                    return Err(RPCErrors::ParseRequestError(
                        "Invalid params, did is none".to_string(),
                    ));
                }
            },
            "add_dns_record" => {
                self.add_dns_record(req).await
            },
            "remove_dns_record" => {
                self.remove_dns_record(req).await
            },
            _ => Err(RPCErrors::UnknownMethod(req.method)),
        }
    }

    async fn query_by_did(&self, did: &str) -> Option<OODInfo> {
        let device_info = self.db.query_device_by_did(did).await;
        if device_info.is_err() {
            warn!("query device by did error: {}", device_info.err().unwrap());
            return None;
        }
        let device_info = device_info.unwrap();
        if device_info.is_none() {
            return None;
        }
        let device_info = device_info.unwrap();
        return Some(OODInfo {
            did_hostname: device_info.did.clone(),
            owner_id: device_info.owner.clone(),
            self_cert: true,
            state: "active".to_string(),
        });
    }

    async fn query_device_by_hostname(&self, req_host: &str) -> Option<OODInfo> {
        let get_result = SNServer::get_user_subhost_from_host(req_host, &self.server_host);
        if get_result.is_some() {
            let (sub_host, username) = get_result.unwrap();
            let user_info = self.db.get_user_info(username.as_str()).await;
            if user_info.is_err() {
                warn!("get user info error: {}", user_info.err().unwrap());
                return None;
            }
            let user_info = user_info.unwrap();
            if user_info.is_none() {
                warn!("user info not found for {}", username);
                return None;
            }
            let user_info = user_info.unwrap();
            
            let device_info = match self.get_device_info(username.as_str(), "ood1").await {
                Ok(info) => info,
                Err(e) => {
                    warn!("ood1 device info parse failed for {}: {}", username, e);
                    None
                }
            };
            if device_info.is_some() {
                info!("ood1 device info found for {} in sn server", username);
                //let device_did = device_info.unwrap().0.did;
                let (device_info, device_ip) = device_info.unwrap();
                let did_hostname = device_info.id.to_host_name();
                let ood_info = OODInfo {
                    did_hostname: did_hostname,
                    owner_id: username.clone(),
                    self_cert: user_info.self_cert,
                    state: "active".to_string(),
                };
                return Some(ood_info);
            } else {
                warn!("ood1 device info not found for {} in sn server", username);
            }
        } else {
            let user_info = self.db.get_user_info_by_domain(req_host).await;
            if user_info.is_err() {
                info!(
                    "failed to get user info by domain: {}",
                    user_info.err().unwrap()
                );
                return None;
            }
            let user_info = user_info.unwrap();
            if user_info.is_none() {
                return None;
            }
            let user_info = user_info.unwrap();
            let username = user_info.username.as_ref().unwrap();
            let public_key = &user_info.public_key;
            let zone_config = &user_info.zone_config;
            let device_info = match self.get_device_info(username.as_str(), "ood1").await {
                Ok(info) => info,
                Err(e) => {
                    warn!("ood1 device info parse failed for {}: {}", username, e);
                    None
                }
            };
            if device_info.is_some() {
                //info!("ood1 device info found for {} in sn server",username);
                //let device_did = device_info.unwrap().0.did;
                let device_did = device_info.as_ref().unwrap().0.id.clone();
                let did_hostname = device_did.to_host_name();
                let ood_info = OODInfo {
                    did_hostname: did_hostname,
                    owner_id: username.to_string(),
                    self_cert: user_info.self_cert,
                    state: "active".to_string(),
                };
                //info!("select device {} for http upstream:{}",device_did.as_str(),result_str.as_str());
                return Some(ood_info);
            } else {
                warn!("ood1 device info not found for {} in sn server", username);
            }
        }

        return None;
    }

    pub fn create_name_info_from_zone_config(
        &self,
        zone_config: &str,
        public_key: &str,
        device_jwt: Option<&String>,
    ) -> NameInfo {
        let mut name_info = NameInfo::default();
        if public_key.starts_with("{") {
            let public_key_json = serde_json::from_str(public_key);
            if public_key_json.is_ok() {
                let public_key_json: Value = public_key_json.unwrap();
                let x = public_key_json.get("x");
                if x.is_some() {
                    let x = x.unwrap().as_str().unwrap();
                    name_info.txt.push(format!("PKX={};", x));
                }
            }
        } else {
            name_info.txt.push(format!("PKX={};", public_key));
        }
        name_info.txt.push(format!("BOOT={};", zone_config));
        if device_jwt.is_some() {
            name_info
                .txt
                .push(format!("DEV={};", device_jwt.as_ref().unwrap().as_str()));
        }
        return name_info;
    }

    fn builder_error_http_response(status: StatusCode, msg: String) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        Ok(Response::builder()
            .status(status)
            .header("Access-Control-Allow-Origin", "*")
            .body(BoxBody::new(
                Full::new(Bytes::from(msg))
                    .map_err(|never| match never {})
                    .boxed(),
            ))
            .unwrap())
    }

    fn builder_json_http_response(
        status: StatusCode,
        value: &serde_json::Value,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        Ok(Response::builder()
            .status(status)
            .header("Access-Control-Allow-Origin", "*")
            .header("Content-Type", "application/json")
            .body(BoxBody::new(
                Full::new(Bytes::from(serde_json::to_string(value).unwrap()))
                    .map_err(|never| match never {})
                    .boxed(),
            ))
            .unwrap())
    }

    fn normalize_resolve_type(resolve_type: Option<String>) -> Option<String> {
        match resolve_type {
            None => None,
            Some(t) if t.trim().is_empty() => None,
            Some(t) => Some(t),
        }
    }

    async fn resolve_user_by_domain(&self, domain: &str) -> ServerResult<SNUserInfo> {
        let user_info = self.db.get_user_info_by_domain(domain).await.map_err(|e| {
            server_err!(
                ServerErrorCode::ProcessChainError,
                "failed to query user by domain {}: {}",
                domain,
                e
            )
        })?;

        match user_info {
            Some(user_info) => Ok(user_info),
            None => Err(server_err!(
                ServerErrorCode::NotFound,
                "user not found for domain {}",
                domain
            )),
        }
    }

    async fn resolve_user_by_username(&self, username: &str) -> ServerResult<SNUserInfo> {
        let user_info = self.db.get_user_info(username).await.map_err(|e| {
            server_err!(
                ServerErrorCode::ProcessChainError,
                "failed to query user {}: {}",
                username,
                e
            )
        })?;

        match user_info {
            Some(user_info) => Ok(user_info),
            None => Err(server_err!(ServerErrorCode::NotFound, "user not found {}", username)),
        }
    }

    async fn resolve_device_by_name(
        &self,
        username: &str,
        device_name: &str,
    ) -> ServerResult<SNDeviceInfo> {
        let device_info = self
            .db
            .query_device_by_name(username, device_name)
            .await
            .map_err(|e| {
                server_err!(
                    ServerErrorCode::ProcessChainError,
                    "failed to query device {}.{}: {}",
                    device_name,
                    username,
                    e
                )
            })?;

        match device_info {
            Some(device_info) => Ok(device_info),
            None => Err(server_err!(
                ServerErrorCode::NotFound,
                "device not found {}.{}",
                device_name,
                username
            )),
        }
    }

    async fn resolve_device_by_did(&self, did: &str) -> ServerResult<SNDeviceInfo> {
        let device_info = self.db.query_device_by_did(did).await.map_err(|e| {
            server_err!(
                ServerErrorCode::ProcessChainError,
                "failed to query device {}: {}",
                did,
                e
            )
        })?;

        match device_info {
            Some(device_info) => Ok(device_info),
            None => Err(server_err!(ServerErrorCode::NotFound, "device not found {}", did)),
        }
    }

    fn build_device_info_json(device: &SNDeviceInfo) -> serde_json::Value {
        // description is a JSON string (serialized DeviceInfo)
        let mut v = serde_json::from_str::<serde_json::Value>(device.description.as_str())
            .unwrap_or_else(|_| json!({ "description": device.description }));

        if let Some(obj) = v.as_object_mut() {
            obj.insert("did".to_string(), Value::String(device.did.clone()));
            obj.insert("ip".to_string(), Value::String(device.ip.clone()));
            obj.insert("owner".to_string(), Value::String(device.owner.clone()));
            obj.insert("device_name".to_string(), Value::String(device.device_name.clone()));
            obj.insert(
                "created_at".to_string(),
                Value::Number(serde_json::Number::from(device.created_at)),
            );
            obj.insert(
                "updated_at".to_string(),
                Value::Number(serde_json::Number::from(device.updated_at)),
            );
        }

        v
    }

    fn build_zone_config_json(username: &str, user: &SNUserInfo) -> serde_json::Value {
        json!({
            "user_name": username,
            "public_key": user.public_key.clone(),
            "boot": user.zone_config.clone(), // stored boot jwt
            "self_cert": user.self_cert,
            "user_domain": user.user_domain.clone(),
            "sn_ips": user.sn_ips.clone(),
            "state": (&user.state).to_string(),
        })
    }

    async fn handle_bns_username_resolve(
        &self,
        username: &str,
        resolve_type: Option<&str>,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        let user = self.resolve_user_by_username(username).await?;
        match resolve_type.unwrap_or("zone") {
            "boot" => {
                let v = json!({ "boot": user.zone_config.clone() });
                Self::builder_json_http_response(StatusCode::OK, &v)
            }
            "zone" => {
                let v = Self::build_zone_config_json(username, &user);
                Self::builder_json_http_response(StatusCode::OK, &v)
            }
            device_name => {
                let device = self.resolve_device_by_name(username, device_name).await?;
                let device_doc = Self::device_config_from_mini_jwt(
                    device.mini_config_jwt.as_str(),
                    user.public_key.as_str(),
                    username,
                )
                .map_err(|msg| server_err!(ServerErrorCode::InvalidParam, "{}", msg))?;
                Self::builder_json_http_response(StatusCode::OK, &device_doc)
            }
        }
    }

    async fn handle_bns_device_resolve(
        &self,
        username: &str,
        device_name: &str,
        resolve_type: Option<&str>,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        let device = self.resolve_device_by_name(username, device_name).await?;
        match resolve_type.unwrap_or("doc") {
            "info" => {
                let device_info = Self::build_device_info_json(&device);
                Self::builder_json_http_response(StatusCode::OK, &device_info)
            }
            "doc" => {
                let user = self.resolve_user_by_username(username).await?;
                let device_doc = Self::device_config_from_mini_jwt(
                    device.mini_config_jwt.as_str(),
                    user.public_key.as_str(),
                    username,
                )
                .map_err(|msg| server_err!(ServerErrorCode::InvalidParam, "{}", msg))?;
                Self::builder_json_http_response(StatusCode::OK, &device_doc)
            }
            other => Self::builder_error_http_response(
                StatusCode::BAD_REQUEST,
                format!(
                    "unsupported type {} for did:bns:{}.{}",
                    other, device_name, username
                ),
            ),
        }
    }

    async fn handle_dev_resolve(
        &self,
        did_str: &str,
        resolve_type: Option<&str>,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        let device = self.resolve_device_by_did(did_str).await?;
        match resolve_type.unwrap_or("doc") {
            "info" => {
                let device_info = Self::build_device_info_json(&device);
                Self::builder_json_http_response(StatusCode::OK, &device_info)
            }
            "doc" => {
                let user = self.resolve_user_by_username(device.owner.as_str()).await?;
                let device_doc = Self::device_config_from_mini_jwt(
                    device.mini_config_jwt.as_str(),
                    user.public_key.as_str(),
                    device.owner.as_str(),
                )
                .map_err(|msg| server_err!(ServerErrorCode::InvalidParam, "{}", msg))?;
                Self::builder_json_http_response(StatusCode::OK, &device_doc)
            }
            other => Self::builder_error_http_response(
                StatusCode::BAD_REQUEST,
                format!("unsupported type {} for {}", other, did_str),
            ),
        }
    }

    fn device_config_from_mini_jwt(
        mini_config_jwt: &str,
        owner_public_key_jwk_str: &str,
        owner_username: &str,
    ) -> Result<serde_json::Value, String> {
        // owner_public_key stored in DB is a JWK JSON string
        let owner_public_key_jwk: jsonwebtoken::jwk::Jwk =
            serde_json::from_str(owner_public_key_jwk_str)
                .map_err(|e| format!("failed to parse owner public key jwk: {}", e))?;

        let decoding_key = DecodingKey::from_jwk(&owner_public_key_jwk)
            .map_err(|e| format!("failed to build decoding key from jwk: {}", e))?;

        let mini = DeviceMiniConfig::from_jwt(mini_config_jwt, &decoding_key)
            .map_err(|e| format!("failed to parse mini_config_jwt: {}", e))?;

        // In this gateway, we use did:bns:<username> as both zone_did and owner did.
        let owner_did_str = format!("did:bns:{}", owner_username);
        let zone_did = DID::from_str(owner_did_str.as_str())
            .map_err(|e| format!("failed to build zone did: {}", e))?;
        let owner_did = DID::from_str(owner_did_str.as_str())
            .map_err(|e| format!("failed to build owner did: {}", e))?;

        let device_config = DeviceConfig::new_by_mini_config(
            &mini_config_jwt.to_string(),
            &mini,
            zone_did,
            owner_did,
        );

        serde_json::to_value(device_config)
            .map_err(|e| format!("failed to encode device_config: {}", e))
    }

    pub async fn handle_http_did_resolve_request(
        &self,
        query_str: &str,
        info: StreamInfo,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        //query_str is like "did:bns:xxxx[?type=boot]"
        let (did_part, query_part) = match query_str.split_once('?') {
            Some((did, query)) => (did, Some(query)),
            None => (query_str, None),
        };

        let did = match DID::from_str(did_part) {
            Ok(did) => did,
            Err(e) => {
                let msg = format!("invalid did '{}': {}", did_part, e);
                warn!("invalid did '{}': {}", did_part, e);
                return Self::builder_error_http_response(StatusCode::BAD_REQUEST, msg);
            }
        };

        let did_method = did.method.as_str();
        if did_method != "bns" && did_method != "dev"  && did_method != "web" {
            let msg = format!("unsupported did method '{}'", did_method);
            warn!("unsupported did method '{}'", did_method);
            return Self::builder_error_http_response(StatusCode::BAD_REQUEST, msg);
        }

        let mut resolve_type: Option<String> = None;
        if let Some(query) = query_part {
            for pair in query.split('&') {
                if pair.is_empty() {
                    continue;
                }
                if let Some((k, v)) = pair.split_once('=') {
                    if k == "type" && !v.is_empty() {
                        resolve_type = Some(v.to_string());
                    }
                } else if pair == "type" {
                    resolve_type = Some(String::new());
                }
            }
        }
        let resolve_type = Self::normalize_resolve_type(resolve_type);

        // Treat HTTP `type` as NameServer::query_did doc_type.
        let doc_type = resolve_type.as_deref();

        // best-effort parse client ip from StreamInfo
        let from_ip = info
            .src_addr
            .as_ref()
            .and_then(|addr| addr.parse::<SocketAddr>().ok())
            .map(|s| s.ip());

        match self.query_did(&did, doc_type, from_ip).await {
            Ok(doc) => {
                let body = doc.to_string();
                let content_type = match doc {
                    EncodedDocument::JsonLd(_) => "application/json",
                    EncodedDocument::Jwt(_) => "application/jwt",
                };
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Access-Control-Allow-Origin", "*")
                    .header("Content-Type", content_type)
                    .body(BoxBody::new(
                        Full::new(Bytes::from(body))
                            .map_err(|never| match never {})
                            .boxed(),
                    ))
                    .unwrap())
            }
            Err(e) => {
                let (status, msg) = match e.code() {
                    ServerErrorCode::NotFound => (StatusCode::NOT_FOUND, e.to_string()),
                    ServerErrorCode::BadRequest | ServerErrorCode::InvalidParam => {
                        (StatusCode::BAD_REQUEST, e.to_string())
                    }
                    _ => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
                };
                Self::builder_error_http_response(status, msg)
            }
        }
    }
}

#[async_trait]
impl QAServer for SNServer {
    async fn serve_question(&self, req: &serde_json::Value) -> ServerResult<serde_json::Value> {
        let rpc_request = qa_json_to_rpc_request(req);
        if rpc_request.is_err() {
            return Err(server_err!(
                ServerErrorCode::InvalidParam,
                "invalid request"
            ));
        }
        let rpc_request = rpc_request.unwrap();
        let rpc_response = self
            .handle_rpc_call(rpc_request, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            .await;
        if rpc_response.is_err() {
            return Err(server_err!(
                ServerErrorCode::ProcessChainError,
                "failed to handle rpc call"
            ));
        }
        let rpc_response = rpc_response.unwrap();
        match rpc_response.result {
            RPCResult::Success(result) => {
                return Ok(result);
            }
            RPCResult::Failed(error) => {
                return Err(server_err!(
                    ServerErrorCode::ProcessChainError,
                    "failed to handle rpc call: {}",
                    error
                ));
            }
        }
    }

    fn id(&self) -> String {
        self.id.clone()
    }
}

#[async_trait]
impl NameServer for SNServer {
    fn id(&self) -> String {
        self.id.clone()
    }

    async fn query(
        &self,
        name: &str,
        record_type: Option<RecordType>,
        from_ip: Option<IpAddr>,
    ) -> ServerResult<NameInfo> {
        info!(
            "sn server process name query: {} record_type: {:?}",
            name, record_type
        );
        let record_type = record_type.unwrap_or_default();
        let from_ip = from_ip.unwrap_or(self.server_ip);
        let mut is_support = false;
        if record_type == RecordType::A
            || record_type == RecordType::AAAA
            || record_type == RecordType::TXT
        {
            is_support = true;
        }

        if !is_support {
            return Err(server_err!(
                ServerErrorCode::NotFound,
                "sn-server not support record type {}",
                record_type.to_string()
            ));
        }
        let mut req_real_name: String = name.to_string();
        if name.ends_with(".") {
            req_real_name = name.trim_end_matches('.').to_string();
        }

        let sn_full_host = format!("sn.{}", self.server_host);
        if req_real_name == sn_full_host
            || req_real_name == self.server_host
            || self.server_aliases.contains(&req_real_name)
        {
            //返回当前服务器的地址
            match record_type {
                RecordType::A => {
                    let result_name_info = NameInfo::from_address(name, self.server_ip);
                    return Ok(result_name_info);
                }
                RecordType::TXT => {
                    let device_jwt = self.device_jwt.get(0);
                    let name_info = self.create_name_info_from_zone_config(
                        self.boot_jwt.as_str(),
                        self.owner_pkx.as_str(),
                        device_jwt,
                    );
                    return Ok(name_info);
                }
                _ => {
                    return Err(server_err!(
                        ServerErrorCode::NotFound,
                        "sn-server not support record type {}",
                        record_type.to_string()
                    ));
                }
            }
        }

        let get_result = SNServer::get_user_subhost_from_host(&req_real_name, &self.server_host);
        if get_result.is_some() {
            let (sub_host, username) = get_result.unwrap();

            // if req_real_name.ends_with(&sn_full_host) {
            //     let sub_name = name[0..name.len() - sn_full_host.len()].to_string();
            //     //split sub_name by "."
            //     let subs: Vec<&str> = sub_name.split(".").collect();
            //     let username = subs.last();
            //     if username.is_none() {
            //         return Err(server_err!(
            //             ServerErrorCode::NotFound,
            //             "{}",
            //             name.to_string()
            //         ));
            //     }
            info!(
                "host {} owner by user {}, sub_host: {}, record_type: {:?}",
                req_real_name, username, sub_host, record_type
            );
            match record_type {
                RecordType::TXT => {
                    let ret = self.db.query_domain_record(req_real_name.as_str(), "TXT").await;
                    if let Ok(Some((record, ttl))) = ret {
                        let mut name_info = NameInfo::default();
                        name_info.ttl = Some(ttl);
                        name_info.txt.push(record);
                        return Ok(name_info);
                    }
                    let zone_config = self.get_user_zone_config(username.as_str()).await;
                    if zone_config.is_some() {
                        let mut name_info = NameInfo::default();
                        let (public_key, zone_config, sn_ips, device_jwt) = zone_config.unwrap();
                        let name_info = self.create_name_info_from_zone_config(
                            zone_config.as_str(),
                            public_key.as_str(),
                            device_jwt.as_ref(),
                        );
                        info!(
                            "<={} zone_config:{} public_key:{} device_jwt:{:?} ",
                            name, zone_config, public_key, device_jwt
                        );
                        Ok(name_info)
                    } else {
                        Err(server_err!(
                            ServerErrorCode::NotFound,
                            "{}",
                            name.to_string()
                        ))
                    }
                }
                RecordType::A | RecordType::AAAA => {
                    let ret = self.db.query_domain_record(req_real_name.as_str(), record_type.to_string().as_str()).await;
                    if let Ok(Some((record, ttl))) = ret {
                        let mut address_vec = Vec::new();
                        record.split(',').for_each(|x| {
                            if let Ok(ip) = IpAddr::from_str(x) {
                                address_vec.push(ip);
                            }
                        });

                        let mut result_name_info = NameInfo::from_address_vec(name, address_vec);
                        result_name_info.ttl = Some(ttl);
                        info!("=>{} result_name_info: {:?}", name, result_name_info);
                        return Ok(result_name_info);
                    }
                    let address_vec = self
                        .get_user_zonegate_address(username.as_str(), record_type)
                        .await?;
                    if address_vec.is_some() {
                        let address_vec = address_vec.unwrap();
                        let result_name_info = NameInfo::from_address_vec(name, address_vec);
                        info!("=>{} result_name_info: {:?}", name, result_name_info);
                        Ok(result_name_info)
                    } else {
                        Err(server_err!(
                            ServerErrorCode::NotFound,
                            "no address found for {}",
                            name.to_string()
                        ))
                    }
                }
                _ => {
                    return Err(server_err!(
                        ServerErrorCode::NotFound,
                        "sn-server not support record type {}",
                        record_type.to_string()
                    ));
                }
            }
        } else {
            info!("get user subhost from host: {} failed", req_real_name);
            let real_domain_name = name[0..name.len() - 1].to_string();
            match record_type {
                RecordType::TXT => {
                    let zone_config_info =
                        self.get_user_zone_config_by_domain(&real_domain_name).await;
                    if zone_config_info.is_some() {
                        let (public_key, zone_config, device_jwt) = zone_config_info.unwrap();
                        let name_info = self.create_name_info_from_zone_config(
                            zone_config.as_str(),
                            public_key.as_str(),
                            device_jwt.as_ref(),
                        );
                        return Ok(name_info);
                    } else {
                        return Err(server_err!(
                            ServerErrorCode::NotFound,
                            "{}",
                            name.to_string()
                        ));
                    }
                }
                RecordType::A | RecordType::AAAA => {
                    let address_vec = self
                        .get_user_zonegate_address_by_domain(&real_domain_name, record_type)
                        .await?;
                    if address_vec.is_some() {
                        let address_vec = address_vec.unwrap();
                        let result_name_info = NameInfo::from_address_vec(name, address_vec);
                        info!("=>{} result_name_info: {:?}", name, result_name_info);
                        return Ok(result_name_info);
                    }
                }
                _ => {
                    return Err(server_err!(
                        ServerErrorCode::NotFound,
                        "sn-server not support record type {}",
                        record_type.to_string()
                    ));
                }
            }

            return Err(server_err!(
                ServerErrorCode::NotFound,
                "no address found for {}",
                name.to_string()
            ));
        }
    }

    async fn query_did(
        &self,
        did: &DID,
        doc_type: Option<&str>,
        from_ip: Option<IpAddr>,
    ) -> ServerResult<EncodedDocument> {
        let doc_type = doc_type.and_then(|t| {
            let t = t.trim();
            if t.is_empty() { None } else { Some(t) }
        });

        match did.method.as_str() {
            // did:web:$user_domain -> resolve user by domain -> treat as did:bns:$username
            // did:web:$device_name.$user_domain -> resolve user by domain -> treat as did:bns:$device_name.$username
            "web" => {
                let id = did.id.as_str();

                // First, try treating the whole id as user_domain (did:web:$user_domain).
                match self.resolve_user_by_domain(id).await {
                    Ok(user_info) => {
                        let username = user_info.username.clone().ok_or(server_err!(
                            ServerErrorCode::NotFound,
                            "user has no username bound for domain {}",
                            id
                        ))?;

                        let bns_did_str = format!("did:bns:{}", username);
                        let bns_did = DID::from_str(bns_did_str.as_str()).map_err(|e| {
                            server_err!(
                                ServerErrorCode::InvalidParam,
                                "invalid mapped bns did: {}",
                                e
                            )
                        })?;
                        return self.query_did(&bns_did, doc_type, from_ip).await;
                    }
                    Err(e) if e.code() == ServerErrorCode::NotFound => {
                        // Then, try did:web:$device_name.$user_domain
                        if let Some((device_name, domain)) = id.split_once('.') {
                            let user_info = self.resolve_user_by_domain(domain).await?;
                            let username = user_info.username.clone().ok_or(server_err!(
                                ServerErrorCode::NotFound,
                                "user has no username bound for domain {}",
                                domain
                            ))?;

                            let bns_did_str = format!("did:bns:{}.{}", device_name, username);
                            let bns_did = DID::from_str(bns_did_str.as_str()).map_err(|e| {
                                server_err!(
                                    ServerErrorCode::InvalidParam,
                                    "invalid mapped bns did: {}",
                                    e
                                )
                            })?;
                            return self.query_did(&bns_did, doc_type, from_ip).await;
                        }

                        Err(server_err!(
                            ServerErrorCode::NotFound,
                            "user not found for domain {}",
                            id
                        ))
                    }
                    Err(e) => Err(e),
                }?
            }

            // did:bns:username
            // did:bns:device_name.username
            "bns" => {
                let id = did.id.as_str();

                if let Some((obj_name, tail)) = id.split_once('.') {
                    let username = if tail.contains('.') {
                        let user_info = self.resolve_user_by_domain(tail).await?;
                        user_info.username.clone().ok_or(server_err!(
                            ServerErrorCode::NotFound,
                            "user has no username bound for domain {}",
                            tail
                        ))?
                    } else {
                        tail.to_string()
                    };

                    // did:bns:$device_name.$username
                    match self.resolve_device_by_name(username.as_str(), obj_name).await {
                        Ok(device) => match doc_type.unwrap_or("doc") {
                            "doc" => {
                                let user = self.resolve_user_by_username(username.as_str()).await?;
                                let v = Self::device_config_from_mini_jwt(
                                    device.mini_config_jwt.as_str(),
                                    user.public_key.as_str(),
                                    username.as_str(),
                                )
                                .map_err(|msg| server_err!(ServerErrorCode::InvalidParam, "{}", msg))?;
                                Ok(EncodedDocument::JsonLd(v))
                            }
                            "info" => {
                                let v = Self::build_device_info_json(&device);
                                Ok(EncodedDocument::JsonLd(v))
                            }
                            other => Err(server_err!(
                                ServerErrorCode::InvalidParam,
                                "unsupported doc_type {} for did:bns:{}.{}",
                                other,
                                obj_name,
                                username
                            )),
                        },
                        Err(e) if e.code() == ServerErrorCode::NotFound => {
                            // Not a device: fallback to user-defined did_document stored in DB.
                            let latest_doc = self
                                .db
                                .query_user_did_document(username.as_str(), obj_name, doc_type)
                                .await
                                .map_err(|err| {
                                    server_err!(
                                        ServerErrorCode::ProcessChainError,
                                        "query did document failed: {}",
                                        err
                                    )
                                })?;

                            if let Some((_obj_id, did_doc_str, _stored_type)) = latest_doc {
                                // Empty string is allowed and should return JSON null.
                                let v = if did_doc_str.trim().is_empty() {
                                    Value::Null
                                } else {
                                    serde_json::from_str::<Value>(did_doc_str.as_str()).map_err(
                                        |e| {
                                            server_err!(
                                                ServerErrorCode::InvalidParam,
                                                "invalid did_document json: {}",
                                                e
                                            )
                                        },
                                    )?
                                };
                                Ok(EncodedDocument::JsonLd(v))
                            } else {
                                Err(server_err!(
                                    ServerErrorCode::NotFound,
                                    "did document not found for did:bns:{}.{}",
                                    obj_name,
                                    username
                                ))
                            }
                        }
                        Err(e) => Err(e),
                    }
                } else {
                    // did:bns:$username
                    let username = id;
                    let user = self.resolve_user_by_username(username).await?;

                    match doc_type.unwrap_or("zone") {
                        "zone" => {
                            let v = Self::build_zone_config_json(username, &user);
                            Ok(EncodedDocument::JsonLd(v))
                        }
                        "boot" => {
                            // Keep HTTP compatibility: still return JSON with "boot" field
                            Ok(EncodedDocument::JsonLd(json!({ "boot": user.zone_config.clone() })))
                        }
                        device_name => {
                            let device = self.resolve_device_by_name(username, device_name).await?;
                            let v = Self::device_config_from_mini_jwt(
                                device.mini_config_jwt.as_str(),
                                user.public_key.as_str(),
                                username,
                            )
                            .map_err(|msg| server_err!(ServerErrorCode::InvalidParam, "{}", msg))?;
                            Ok(EncodedDocument::JsonLd(v))
                        }
                    }
                }
            }

            // did:dev:$public_key
            "dev" => {
                let did_str = did.to_string();
                let device = self.resolve_device_by_did(did_str.as_str()).await?;

                match doc_type.unwrap_or("doc") {
                    "doc" => {
                        let user = self.resolve_user_by_username(device.owner.as_str()).await?;
                        let v = Self::device_config_from_mini_jwt(
                            device.mini_config_jwt.as_str(),
                            user.public_key.as_str(),
                            device.owner.as_str(),
                        )
                        .map_err(|msg| server_err!(ServerErrorCode::InvalidParam, "{}", msg))?;
                        Ok(EncodedDocument::JsonLd(v))
                    }
                    "info" => {
                        let v = Self::build_device_info_json(&device);
                        Ok(EncodedDocument::JsonLd(v))
                    }
                    other => Err(server_err!(
                        ServerErrorCode::InvalidParam,
                        "unsupported doc_type {} for {}",
                        other,
                        did_str
                    )),
                }
            }

            other => Err(server_err!(
                ServerErrorCode::InvalidParam,
                "unsupported did method {}",
                other
            )),
        }
    }
}

#[async_trait]
impl HttpServer for SNServer {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn http_version(&self) -> http::Version {
        http::Version::HTTP_11
    }

    fn http3_port(&self) -> Option<u16> {
        None
    }

    async fn serve_request(
        &self,
        request: http::Request<BoxBody<Bytes, ServerError>>,
        info: StreamInfo,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        // Handle OPTIONS preflight request for CORS
        if request.method() == Method::OPTIONS {
            return Ok(Response::builder()
                .status(StatusCode::NO_CONTENT)
                .header("Access-Control-Allow-Origin", "*")
                .header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                .header(
                    "Access-Control-Allow-Headers",
                    "Content-Type, Authorization",
                )
                .header("Access-Control-Max-Age", "86400")
                .body(BoxBody::new(
                    Full::new(Bytes::new()).map_err(|e| match e {}).boxed(),
                ))
                .unwrap());
        }

        let path = request.uri().path().to_string();
        if path.starts_with("/1.0/identifiers/") && request.method() == Method::GET {
            let did_str = path.trim_start_matches("/1.0/identifiers/").to_string();
            if did_str.is_empty() {
                return Err(server_err!(ServerErrorCode::BadRequest, "invalid did in path"));
            }

            // parse doc_type from query string (?type=xxx)
            let mut doc_type: Option<String> = None;
            if let Some(query) = request.uri().query() {
                for pair in query.split('&') {
                    if pair.is_empty() {
                        continue;
                    }
                    if let Some((k, v)) = pair.split_once('=') {
                        if k == "type" && !v.trim().is_empty() {
                            doc_type = Some(v.trim().to_string());
                        }
                    } else if pair == "type" {
                        doc_type = Some(String::new());
                    }
                }
            }

            let did = DID::from_str(did_str.as_str()).map_err(|e| {
                server_err!(ServerErrorCode::BadRequest, "invalid did '{}': {}", did_str, e)
            })?;

            // best-effort parse client ip from StreamInfo
            let from_ip = info
                .src_addr
                .as_ref()
                .and_then(|addr| addr.parse::<SocketAddr>().ok())
                .map(|s| s.ip());

            let doc = self.query_did(&did, doc_type.as_deref(), from_ip).await;
            match doc {
                Ok(doc) => {
                    let body = doc.to_string();
                    // keep existing behavior: always JSON for JsonLd; JWT is also returned as text
                    let content_type = match doc {
                        EncodedDocument::JsonLd(_) => "application/json",
                        EncodedDocument::Jwt(_) => "application/jwt",
                    };
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("Access-Control-Allow-Origin", "*")
                        .header("Content-Type", content_type)
                        .body(BoxBody::new(
                            Full::new(Bytes::from(body))
                                .map_err(|never| match never {})
                                .boxed(),
                        ))
                        .unwrap());
                }
                Err(e) => {
                    let (status, msg) = match e.code() {
                        ServerErrorCode::NotFound => (StatusCode::NOT_FOUND, e.to_string()),
                        ServerErrorCode::BadRequest | ServerErrorCode::InvalidParam => {
                            (StatusCode::BAD_REQUEST, e.to_string())
                        }
                        _ => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
                    };
                    return Self::builder_error_http_response(status, msg);
                }
            }
        }

        if request.method() != Method::POST {
            return Ok(Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .header("Access-Control-Allow-Origin", "*")
                .body(BoxBody::new(
                    Full::new(Bytes::from_static(b"Method Not Allowed"))
                        .map_err(|e| match e {})
                        .boxed(),
                ))
                .unwrap());
        }

        let client_ip = match info.src_addr {
            Some(addr) => match addr.parse::<SocketAddr>() {
                Ok(socket_addr) => socket_addr.ip(),
                Err(e) => {
                    error!("parse client ip {} err {}", addr.as_str(), e);
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .header("Access-Control-Allow-Origin", "*")
                        .body(
                            BoxBody::new(Full::new(Bytes::from_static(b"Bad Request")))
                                .map_err(|e| match e {})
                                .boxed(),
                        )
                        .unwrap());
                }
            },
            None => {
                error!("Failed to get client ip");
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header("Access-Control-Allow-Origin", "*")
                    .body(
                        BoxBody::new(Full::new(Bytes::from_static(b"Bad Request")))
                            .map_err(|e| match e {})
                            .boxed(),
                    )
                    .unwrap());
            }
        };

        let body_bytes = match request.collect().await {
            Ok(data) => data.to_bytes(),
            Err(e) => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header("Access-Control-Allow-Origin", "*")
                    .body(
                        BoxBody::new(Full::new(Bytes::from(format!(
                            "Failed to read body: {:?}",
                            e
                        ))))
                        .map_err(|e| match e {})
                        .boxed(),
                    )
                    .unwrap());
            }
        };

        let body_str = match String::from_utf8(body_bytes.to_vec()) {
            Ok(s) => s,
            Err(e) => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header("Access-Control-Allow-Origin", "*")
                    .body(
                        BoxBody::new(Full::new(Bytes::from(format!(
                            "Failed to convert body to string: {}",
                            e
                        ))))
                        .map_err(|e| match e {})
                        .boxed(),
                    )
                    .unwrap());
            }
        };

        info!("|==>recv kRPC req: {}", body_str);

        let rpc_request: RPCRequest = match serde_json::from_str(body_str.as_str()) {
            Ok(rpc_request) => rpc_request,
            Err(e) => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header("Access-Control-Allow-Origin", "*")
                    .body(
                        BoxBody::new(Full::new(Bytes::from(format!(
                            "Failed to parse request body to RPCRequest: {}",
                            e
                        ))))
                        .map_err(|e| match e {})
                        .boxed(),
                    )
                    .unwrap());
            }
        };

        let resp = match self.handle_rpc_call(rpc_request, client_ip).await {
            Ok(resp) => resp,
            Err(e) => {
                let msg = format!(
                    "Failed to handle rpc call: {}",
                    e
                );
                error!("{}", msg);
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header("Access-Control-Allow-Origin", "*")
                    .body(
                        BoxBody::new(Full::new(Bytes::from(msg)))
                        .map_err(|e| match e {})
                        .boxed(),
                    )
                    .unwrap());
            }
        };

        //parse resp to Response<Body>
        let mut response_builder = Response::builder()
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            .header(
                "Access-Control-Allow-Headers",
                "Content-Type, Authorization",
            )
            .header("Access-Control-Max-Age", "86400");

        Ok(response_builder
            .body(BoxBody::new(
                Full::new(Bytes::from(serde_json::to_string(&resp).unwrap()))
                    .map_err(|never| match never {})
                    .boxed(),
            ))
            .unwrap())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SNServerConfig {
    pub id: String,
    pub host: String,
    pub ip: String,
    pub boot_jwt: String,
    pub owner_pkx: String,
    pub device_jwt: Vec<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub db_type: Option<String>,
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub db_params: Option<Value>,
}

impl ServerConfig for SNServerConfig {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn server_type(&self) -> String {
        "sn".to_string()
    }

    fn get_config_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    fn add_pre_hook_point_process_chain(
        &self,
        _process_chain: ProcessChainConfig,
    ) -> Arc<dyn ServerConfig> {
        Arc::new(self.clone())
    }

    fn remove_pre_hook_point_process_chain(
        &self,
        _process_chain_id: &str,
    ) -> Arc<dyn ServerConfig> {
        Arc::new(self.clone())
    }

    fn add_post_hook_point_process_chain(
        &self,
        _process_chain: ProcessChainConfig,
    ) -> Arc<dyn ServerConfig> {
        Arc::new(self.clone())
    }

    fn remove_post_hook_point_process_chain(
        &self,
        _process_chain_id: &str,
    ) -> Arc<dyn ServerConfig> {
        Arc::new(self.clone())
    }
}

#[async_trait::async_trait]
#[callback_trait::callback_trait]
pub trait SnDBFactory: Send + Sync + 'static {
    async fn create(&self, params: Value) -> ServerResult<SnDBRef>;
}

pub struct SnServerFactory {
    db_factorys: HashMap<String, Arc<dyn SnDBFactory>>,
}

impl SnServerFactory {
    pub fn new() -> Self {
        SnServerFactory {
            db_factorys: HashMap::new(),
        }
    }

    pub fn register_db_factory(&mut self, db_type: &str, factory: impl SnDBFactory) {
        self.db_factorys.insert(db_type.to_string(), Arc::new(factory));
    }
}

#[async_trait::async_trait]
impl ServerFactory for SnServerFactory {
    async fn create(
        &self,
        config: Arc<dyn ServerConfig>,
        _context: Option<ServerContextRef>,
    ) -> ServerResult<Vec<Server>> {
        let config = config
            .as_any()
            .downcast_ref::<SNServerConfig>()
            .ok_or(server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid SNServer config {}",
                config.server_type()
            ))?;

        let db_type = config.db_type.clone().unwrap_or("sqlite".to_string());
        let db_factory = self.db_factorys.get(db_type.as_str());
        if db_factory.is_none() {
            return Err(server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid db type {}",
                db_type
            ));
        }
        let db = db_factory.unwrap().create(config.db_params.clone().unwrap_or(Value::Null)).await?;

        let sn = Arc::new(SNServer::new(config.clone(), db).await);
        Ok(vec![
            Server::NameServer(sn.clone()),
            Server::Http(sn.clone()),
            Server::QA(sn.clone()),
        ])
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;
    use buckyos_kit::init_logging;
    use hyper_util::rt::TokioIo;
    use cyfs_gateway_lib::hyper_serve_http;
    use crate::SqliteDBFactory;
    use super::*;

    #[test]
    fn test_split_host_name() {
        let req_host = "home.lzc.web3.buckyos.io".to_string();
        let server_host = "web3.buckyos.io".to_string();
        let end_string = format!(".{}", server_host.as_str());
        if req_host.ends_with(&end_string) {
            let sub_name = req_host[0..req_host.len() - end_string.len()].to_string();
            //split sub_name by "."
            let subs: Vec<&str> = sub_name.split(".").collect();
            let username = subs.last();
            if username.is_none() {
                warn!("invalid username for sn tunnel selector {}", req_host);
                return;
            }
            let username = username.unwrap().to_string();
            assert_eq!(username, "lzc".to_string());
            println!("username: {}", username);
        }
    }

    #[test]
    fn test_get_user_subhost_from_host() {
        let server_host = "buckyos.io".to_string();
        let req_host = "home.lzc.web3.buckyos.io".to_string();
        let (sub_host, username) =
            SNServer::get_user_subhost_from_host(&req_host, &server_host).unwrap();
        assert_eq!(sub_host, "home.lzc".to_string());
        assert_eq!(username, "lzc".to_string());

        let req_host = "www-lzc.web3.buckyos.io".to_string();
        let (sub_host, username) =
            SNServer::get_user_subhost_from_host(&req_host, &server_host).unwrap();
        assert_eq!(sub_host, "www-lzc".to_string());
        assert_eq!(username, "lzc".to_string());

        let req_host = "buckyos-filebrowser-lzc.web3.buckyos.io".to_string();
        let (sub_host, username) =
            SNServer::get_user_subhost_from_host(&req_host, &server_host).unwrap();
        assert_eq!(sub_host, "buckyos-filebrowser-lzc".to_string());
        assert_eq!(username, "lzc".to_string());

        let server_host = "devtests.org".to_string();
        let req_host = "alice.web3.devtests.org".to_string();
        let (sub_host, username) =
            SNServer::get_user_subhost_from_host(&req_host, &server_host).unwrap();
        assert_eq!(sub_host, "alice".to_string());
        assert_eq!(username, "alice".to_string());
    }

    #[tokio::test]
    async fn test_sn_api() {
        init_logging("sn", false);
        let (user_signing_key, user_pkcs8_bytes) = generate_ed25519_key();
        let user_public_key = encode_ed25519_sk_to_pk_jwk(&user_signing_key);
        let user_encoding_key = jsonwebtoken::EncodingKey::from_ed_der(user_pkcs8_bytes.as_slice());

        let now = SystemTime::now();
        let zone_boot_config = json!({
            "oods": ["ood1"],
            "exp": now.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() + 3600,
            "iat": now.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
        });
        let zone_boot_config: ZoneBootConfig = serde_json::from_value(zone_boot_config).unwrap();
        let zone_jwt = zone_boot_config.encode(Some(&user_encoding_key)).unwrap().to_string();

        let (user_token, mut user_session) = RPCSessionToken::generate_jwt_token("test", "active_service", None, &user_encoding_key).unwrap();
        user_session.aud = Some("sn".to_string());
        let user_token = user_session.generate_jwt(None, &user_encoding_key).unwrap().to_string();
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("ood1", serde_json::from_value(jwk).unwrap());
        let mini_config_jwt = DeviceMiniConfig::new_by_device_config(&device_config);
        let mini_config_jwt = mini_config_jwt.to_jwt(&user_encoding_key).unwrap().to_string();
        let device_info = DeviceInfo::from_device_doc(&device_config);

        let encoding_key = jsonwebtoken::EncodingKey::from_ed_der(pkcs8_bytes.as_slice());
        // device signed token: userid is device_name (e.g. "ood1")
        let (token, mut session) =
            RPCSessionToken::generate_jwt_token("ood1", "cyfs_gateway", None, &encoding_key)
                .unwrap();
        session.aud = Some("sn".to_string());
        let token = session.generate_jwt(None, &encoding_key).unwrap().to_string();

        // token and user_token are used by different flows below:
        // - token: used for cyfs_gateway (should NOT be allowed to register device)
        // - user_token: used for active_service (should be allowed to register device)

        let (signing_key2, pkcs8_bytes2) = generate_ed25519_key();
        let jwk2 = encode_ed25519_sk_to_pk_jwk(&signing_key2);
        let device_config2 = DeviceConfig::new_by_jwk("ood2", serde_json::from_value(jwk2).unwrap());

        let encoding_key2 = jsonwebtoken::EncodingKey::from_ed_der(pkcs8_bytes2.as_slice());
        let (token2, mut session2) = RPCSessionToken::generate_jwt_token("test", "cyfs_gateway", None, &encoding_key2).unwrap();
        session2.aud = Some("sn".to_string());
        let token2 = session2.generate_jwt(None, &encoding_key2).unwrap().to_string();


        let mut sn_factory = SnServerFactory::new();
        sn_factory.register_db_factory("sqlite", SqliteDBFactory::new());

        let db = tempfile::NamedTempFile::with_suffix(".db").unwrap();

        {
            let db = SqliteSnDB::new_by_path(db.path().to_str().unwrap()).await.unwrap();
            db.initialize_database().await.unwrap();
            db.insert_activation_code("test_code").await.unwrap();
        }
        let config = json!({
            "id": "test",
            "host": "buckyos.ai",
            "ip": "127.0.0.1",
            "boot_jwt": "",
            "owner_pkx": "",
            "device_jwt": [],
            "db_type": "sqlite",
            "db_path": db.path().to_str().unwrap(),
        });
        let config: SNServerConfig = serde_json::from_value(config).unwrap();
        let servers = sn_factory.create(Arc::new(config), None).await.unwrap();
        let mut http_server = None;
        for server in servers.iter() {
            if let Server::Http(server) = server {
                http_server = Some(server.clone());
            }
        }
        let http_server = http_server.unwrap();

        let mut dns_server = None;
        for server in servers.iter() {
            if let Server::NameServer(server) = server {
                dns_server = Some(server.clone());
            }
        }
        let dns_server = dns_server.unwrap();

        tokio::spawn(async move {
            use http_body_util::BodyExt;
            use tokio::net::TcpListener;

            let listener = TcpListener::bind("127.0.0.1:19091").await.unwrap();

            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let http_server = http_server.clone();
                tokio::spawn(async move {
                    let ret = hyper_serve_http(
                        Box::new(stream),
                        http_server,
                        StreamInfo::new("127.0.0.1:19091".to_string()),
                    )
                    .await;
                    if let Err(e) = ret {
                        warn!("hyper_serve_http returned error: {}", e);
                    }
                });
            }
        });

        // 等待服务器启动
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let krpc = kRPC::new("http://127.0.0.1:19091", Some(token.clone()));
        let result = krpc.call("check_username", json!({
            "username": "test"
        })).await.unwrap();
        assert!(result.as_object().unwrap().get("valid").unwrap().as_bool().unwrap());

        let result = krpc.call("register_user", json!({
            "user_name": "test",
            "public_key": user_public_key.to_string(),
            "active_code": "test_code",
            "zone_config": zone_jwt,
            "user_domain": "test.buckyos.ai",
        })).await.unwrap();
        assert_eq!(result.as_object().unwrap().get("code").unwrap().as_i64().unwrap(), 0);

        let result = krpc.call("check_username", json!({
            "username": "test"
        })).await.unwrap();
        assert!(!result.as_object().unwrap().get("valid").unwrap().as_bool().unwrap());

        let result = krpc.call("register", json!({
            "user_name": "test",
            "device_name": "ood1",
            "device_did": device_config.id.clone(),
            "mini_config_jwt": mini_config_jwt.clone(),
            "device_ip": "127.0.0.1",
            "device_info": serde_json::to_string(&device_info).unwrap(),
        })).await;
        assert!(result.is_err());

        let krpc = kRPC::new("http://127.0.0.1:19091", Some(user_token.clone()));
        let result = krpc.call("register", json!({
            "user_name": "test",
            "device_name": "ood1",
            "device_did": device_config.id.clone(),
            "mini_config_jwt": mini_config_jwt.clone(),
            "device_ip": "127.0.0.1",
            "device_info": serde_json::to_string(&device_info).unwrap(),
        })).await;
        assert!(result.is_ok());

        // --- DID resolve HTTP API ---
        let client = reqwest::Client::new();

        // did:bns:username type=boot
        let resp = client
            .get("http://127.0.0.1:19091/1.0/identifiers/did:bns:test?type=boot")
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let v: serde_json::Value = resp.json().await.unwrap();
        assert!(v.get("boot").is_some());

        // did:bns:username type=zone (default)
        let resp = client
            .get("http://127.0.0.1:19091/1.0/identifiers/did:bns:test")
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let v: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(v.get("user_name").unwrap().as_str().unwrap(), "test");
        assert!(v.get("boot").is_some());

        // did:web:domain -> routes to did:bns:username
        let resp = client
            .get("http://127.0.0.1:19091/1.0/identifiers/did:web:test.buckyos.ai")
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let v: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(v.get("user_name").unwrap().as_str().unwrap(), "test");

        // did:bns:device.username type=doc
        let resp = client
            .get("http://127.0.0.1:19091/1.0/identifiers/did:bns:ood1.test?type=doc")
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let v: serde_json::Value = resp.json().await.unwrap();
        assert!(v.get("id").is_some());
        assert!(v.get("device_mini_config_jwt").is_some());

        // did:bns:device.domain -> routes domain -> username -> device
        let resp = client
            .get("http://127.0.0.1:19091/1.0/identifiers/did:bns:ood1.test.buckyos.ai?type=doc")
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let v: serde_json::Value = resp.json().await.unwrap();
        assert!(v.get("id").is_some());

        // did:bns:device.username type=info
        let resp = client
            .get("http://127.0.0.1:19091/1.0/identifiers/did:bns:ood1.test?type=info")
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let v: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(v.get("device_name").unwrap().as_str().unwrap(), "ood1");
        assert_eq!(v.get("owner").unwrap().as_str().unwrap(), "test");
        assert!(v.get("ip").is_some());

        // did:dev:public_key type=doc/info
        let did_dev = device_config.id.to_string();
        let resp = client
            .get(format!(
                "http://127.0.0.1:19091/1.0/identifiers/{}?type=doc",
                did_dev
            ))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let v: serde_json::Value = resp.json().await.unwrap();
        assert!(v.get("id").is_some());

        let resp = client
            .get(format!(
                "http://127.0.0.1:19091/1.0/identifiers/{}?type=info",
                did_dev
            ))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let v: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(v.get("device_name").unwrap().as_str().unwrap(), "ood1");
        assert!(v.get("ip").is_some());

        let krpc = kRPC::new("http://127.0.0.1:19091", Some(token.clone()));
        let result = krpc.call("get", json!({
            "device_id": device_config.name,
            "owner_id": "test"
        })).await;
        assert!(result.is_ok());
        let result = result.unwrap();
        let ret = serde_json::from_value::<DeviceInfo>(result);
        assert!(ret.is_ok());

        let result = krpc.call("get_by_pk", json!({
            "public_key": user_public_key.to_string()
        })).await;
        assert!(result.is_ok());

        let result = krpc.call("add_dns_record", json!({
            "device_did": device_config2.id.to_string(),
            "domain": "test.buckyos.ai",
            "record_type": "A",
            "record": "127.0.0.1",
        })).await;
        assert!(result.is_err());

        let result = krpc.call("add_dns_record", json!({
            "device_did": device_config.id.to_string(),
            "domain": "test.test.web3.buckyos.ai",
            "record_type": "A",
            "record": "127.0.0.1",
            "ttl": 600
        })).await;
        assert!(result.is_ok());

        let result = krpc.call("add_dns_record", json!({
            "device_did": device_config.id.to_string(),
            "domain": "test.buckyos.ai",
            "record_type": "A",
            "record": "127.0.0.1",
            "ttl": 600
        })).await;
        assert!(result.is_err());

        let result = krpc.call("add_dns_record", json!({
            "device_did": device_config.id.to_string(),
            "domain": "_acme-challenge.test.web3.buckyos.ai",
            "record_type": "TXT",
            "record": "ERWSSDFERWERSD",
            "ttl": 600
        })).await;
        assert!(result.is_ok());

        let result = dns_server.query("_acme-challenge.test.web3.buckyos.ai", Some(RecordType::TXT), None).await;
        assert!(result.is_ok());
        let name_info = result.unwrap();
        assert_eq!(name_info.txt.len(), 1);
        assert_eq!(name_info.txt[0], "ERWSSDFERWERSD");

        let result = dns_server.query("test.test.web3.buckyos.ai", Some(RecordType::A), None).await;
        assert!(result.is_ok());
        let name_info = result.unwrap();
        assert_eq!(name_info.address.len(), 1);
        assert_eq!(name_info.address[0].to_string(), "127.0.0.1");

        let result = krpc.call("query_by_hostname", json!({
            "dest_host": "test.test.web3.buckyos.ai"
        })).await;
        assert!(result.is_ok());
        let result = result.unwrap();
        let ood_info = serde_json::from_value::<OODInfo>(result).unwrap();
        assert!(!ood_info.self_cert);
        
        let result = krpc.call("remove_dns_record", json!({
            "device_did": device_config.id.to_string(),
            "domain": "_acme-challenge.test.web3.buckyos.ai",
            "record_type": "TXT",
            "has_cert": true
        })).await;
        assert!(result.is_ok());

        let result = dns_server.query("_acme-challenge.test.web3.buckyos.ai", Some(RecordType::TXT), None).await;
        assert!(result.is_ok());
        let name_info = result.unwrap();
        assert_eq!(name_info.txt.len(), 3);

        let krpc = kRPC::new("http://127.0.0.1:19091", Some(token2.clone()));
        let device_info2 = DeviceInfo::from_device_doc(&device_config2);
        let result = krpc.call("update", json!({
            "device_info": device_info2,
            "owner_id": "test"
        })).await;
        assert!(result.is_err());

        let krpc = kRPC::new("http://127.0.0.1:19091", Some(token.clone()));
        let mut device_info = DeviceInfo::from_device_doc(&device_config);
        device_info.cpu_info = Some("AMD".to_string());
        let result = krpc.call("update", json!({
            "device_info": device_info,
            "owner_id": "test"
        })).await;
        assert!(result.is_ok());

        let krpc = kRPC::new("http://127.0.0.1:19091", Some(token.clone()));
        let result = krpc.call("get", json!({
            "device_id": device_config.name,
            "owner_id": "test"
        })).await;
        assert!(result.is_ok());
        let result = result.unwrap();
        let ret = serde_json::from_value::<DeviceInfo>(result);
        assert!(ret.is_ok());
        let device_info = ret.unwrap();
        assert_eq!(device_info.cpu_info.unwrap(), "AMD");

        let result = krpc.call("query_by_did", json!({
            "source_device_id": device_config.id.to_string(),
        })).await;
        assert!(result.is_ok());

        let result = krpc.call("query_by_hostname", json!({
            "dest_host": "test.test.web3.buckyos.ai"
        })).await;
        assert!(result.is_ok());
        let result = result.unwrap();
        let ood_info = serde_json::from_value::<OODInfo>(result).unwrap();
        assert!(ood_info.self_cert);

        // --- set_user_self_cert (device-signed) ---
        let result = krpc
            .call(
                "set_user_self_cert",
                json!({
                    "name": "test",
                    "self_cert": false
                }),
            )
            .await;
        assert!(result.is_ok());

        let result = krpc.call("query_by_hostname", json!({
            "dest_host": "test.test.web3.buckyos.ai"
        })).await;
        assert!(result.is_ok());
        let result = result.unwrap();
        let ood_info = serde_json::from_value::<OODInfo>(result).unwrap();
        assert!(!ood_info.self_cert);

        let result = krpc
            .call(
                "set_user_self_cert",
                json!({
                    "name": "test",
                    "self_cert": true
                }),
            )
            .await;
        assert!(result.is_ok());
    }
}
