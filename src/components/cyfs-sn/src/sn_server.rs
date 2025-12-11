#![allow(unused)]
use crate::sn_db::{self, *};
use http_body_util::combinators::BoxBody;
use ::kRPC::*;
use async_trait::async_trait;
use cyfs_gateway_lib::{HttpServer, NameServer, ProcessChainConfig, QAServer, Server, ServerConfig, ServerError, ServerErrorCode, ServerFactory, ServerResult, StreamInfo, qa_json_to_rpc_request};
use jsonwebtoken::DecodingKey;
use lazy_static::lazy_static;
use log::*;
use name_client::*;
use name_lib::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use hyper::body::{Bytes};
use std::str::FromStr;
use std::sync::Arc;
use std::{
    fmt::format,
    net::{IpAddr, Ipv4Addr},
    result::Result,
};
use std::net::SocketAddr;
use http::{Method, Response, StatusCode};
use http_body_util::{BodyExt, Collected, Full};
use tokio::sync::Mutex;
use cyfs_gateway_lib::{server_err,into_server_err};


#[derive(Serialize, Deserialize)]
pub struct OODInfo {
    //pub device_info: DeviceInfo,
    pub did_hostname: String,
    pub owner_id: String,
    pub self_cert: bool,
    pub state: String,//active,suspended,disabled,banned
}

#[derive(Clone)]
pub struct SNServer {
    id: String,
    //ipaddress is the ip from update_op's ip_from
    all_device_info: Arc<Mutex<HashMap<String, (DeviceInfo, IpAddr)>>>,
    all_user_zone_config: Arc<Mutex<HashMap<String, (String, String)>>>,
    server_host: String,
    server_ip: IpAddr,
    server_aliases: Vec<String>,
    zone_boot_config: String,
    zone_boot_config_pkx: String,
    zone_gateway_list: Option<Vec<String>>, //device_list is the list of device_did
}

impl SNServer {
    pub fn new(server_config: SNServerConfig) -> Self {
        // let conn = get_sn_db_conn();
        // if conn.is_ok() {
        //     let conn = conn.unwrap();
        //     initialize_database(&conn);
        // } else {
        //     error!("Failed to open sn_db.sqlite3");
        //     panic!("Failed to open sn_db.sqlite3");
        // }

        let mut device_list: Option<Vec<String>> = None;
        let current_device_config = CURRENT_DEVICE_CONFIG.get();
        if current_device_config.is_some() {
            info!(
                "current device config (GATEWAY) is set: {:?}",
                current_device_config.unwrap()
            );
            let current_device_config = current_device_config.unwrap();
            device_list = Some(vec![current_device_config.get_id().to_string()]);
        }

        let server_host = server_config.host;
        let server_ip = IpAddr::from_str(server_config.ip.as_str()).unwrap();
        //TODO:需要改进
        let zone_config = server_config.zone_config_jwt;
        let zone_config_pkx = server_config.zone_config_pkx;

        SNServer {
            id: server_config.id,
            all_device_info: Arc::new(Mutex::new(HashMap::new())),
            all_user_zone_config: Arc::new(Mutex::new(HashMap::new())),
            server_host: server_host,
            server_ip: server_ip,
            server_aliases: server_config.aliases,
            zone_boot_config: zone_config,
            zone_boot_config_pkx: zone_config_pkx,
            zone_gateway_list: device_list,
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

        let db = GLOBAL_SN_DB.lock().await;
        let ret = db.is_user_exist(username.as_str()).map_err(|e| {
            error!("Failed to check username: {:?}", e);
            RPCErrors::ReasonError(e.to_string())
        })?;
        let resp = RPCResponse::new(
            RPCResult::Success(json!({
                "valid":!ret
            })),
            req.id,
        );
        return Ok(resp);
    }

    // 辅助函数：检测字符串是否包含特殊字符
    fn contains_special_chars(s: &str) -> bool {
        s.chars().any(|c| {
            !c.is_alphanumeric() && !c.is_whitespace() && c != '_' && c != '-' && c != '.'
        })
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
        let db = GLOBAL_SN_DB.lock().await;
        let ret = db.check_active_code(active_code);
        if ret.is_err() {
            return Err(RPCErrors::ReasonError(ret.err().unwrap().to_string()));
        }
        let valid = ret.unwrap();
        let resp = RPCResponse::new(
            RPCResult::Success(json!({
                "valid":valid
            })),
            req.id,
        );
        return Ok(resp);
    }

    pub async fn register_user(&self, req: RPCRequest) -> Result<RPCResponse, RPCErrors> {
        let user_name = req.params.get("user_name");
        let public_key = req.params.get("public_key");
        let active_code = req.params.get("active_code");
        let zone_config_jwt = req.params.get("zone_config");
        let user_domain = req.params.get("user_domain");
        if user_name.is_none()
            || public_key.is_none()
            || active_code.is_none()
            || zone_config_jwt.is_none()
        {
            return Err(RPCErrors::ParseRequestError("Invalid params, user_name or public_key or active_code or zone_config (jwt) is none".to_string()));
        }
        let user_name = user_name.unwrap().as_str().unwrap();
        let public_key = public_key.unwrap().as_str().unwrap();
        let active_code = active_code.unwrap().as_str().unwrap();
        let zone_config_jwt = zone_config_jwt.unwrap().as_str().unwrap();

        let mut real_user_domain = None;
        if user_domain.is_some() {
            let user_domain = user_domain.unwrap();
            let user_domain_str = user_domain.as_str();
            if user_domain_str.is_some() {
                real_user_domain = Some(user_domain_str.unwrap().to_string());
            }
        }

        let db = GLOBAL_SN_DB.lock().await;
        let ret = db.register_user(
            active_code,
            user_name,
            public_key,
            zone_config_jwt,
            real_user_domain,
        );
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

        let resp = RPCResponse::new(
            RPCResult::Success(json!({
                "code":0
            })),
            req.id,
        );
        return Ok(resp);
    }

    pub async fn register_device(&self, req: RPCRequest) -> Result<RPCResponse, RPCErrors> {
        let user_name = req.params.get("user_name");
        let device_name = req.params.get("device_name");
        let device_did = req.params.get("device_did");
        let device_ip = req.params.get("device_ip");
        let device_info = req.params.get("device_info");

        if user_name.is_none()
            || device_name.is_none()
            || device_did.is_none()
            || device_ip.is_none()
            || device_info.is_none()
        {
            return Err(RPCErrors::ParseRequestError("Invalid params, user_name or device_name or device_did or device_ip or device_info is none".to_string()));
        }
        let user_name = user_name.unwrap().as_str().unwrap();
        let device_name = device_name.unwrap().as_str().unwrap();
        let device_did = device_did.unwrap().as_str().unwrap();
        let device_ip = device_ip.unwrap().as_str().unwrap();
        let device_info = device_info.unwrap().as_str().unwrap();

        //check token is valid (verify pub key is user's public key)
        let session_token = req.token;
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
        if rpc_session_token.appid.is_none() || rpc_session_token.appid.unwrap() != "active_service"
        {
            return Err(RPCErrors::ParseRequestError("invalid appid".to_string()));
        }

        let db = GLOBAL_SN_DB.lock().await;
        let ret = db.register_device(user_name, device_name, device_did, device_ip, device_info);
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

        let resp = RPCResponse::new(
            RPCResult::Success(json!({
                "code":0
            })),
            req.id,
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

        let session_token = req.token;
        if session_token.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, session_token is none".to_string(),
            ));
        }
        let session_token = session_token.unwrap();
        let mut rpc_session_token = RPCSessionToken::from_string(session_token.as_str())?;
        let device_did = device_info.id.clone();

        let verify_public_key =
            DecodingKey::from_ed_components(device_did.id.as_str()).map_err(|e| {
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
        let db = GLOBAL_SN_DB.lock().await;
        db.update_device_by_name(
            owner_id,
            &device_info.name.clone(),
            ip_str.as_str(),
            device_info_json.to_string().as_str(),
        );
        let resp = RPCResponse::new(
            RPCResult::Success(json!({
                "code":0
            })),
            req.id,
        );

        let mut device_info_map = self.all_device_info.lock().await;
        let key = format!("{}_{}", owner_id, device_info.name.clone());
        device_info_map.insert(key.clone(), (device_info.clone(), ip_from));

        info!("update device info done: for {}", key);
        return Ok(resp);
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
        let device_info = self.get_device_info(device_id, owner_id).await;
        if device_info.is_some() {
            let device_info = device_info.unwrap();
            let device_value = serde_json::to_value(device_info.0).map_err(|e| {
                warn!("Failed to parse device info: {:?}", e);
                RPCErrors::ReasonError(e.to_string())
            })?;
            return Ok(RPCResponse::new(RPCResult::Success(device_value), req.id));
        } else {
            warn!("device info not found for {}_{}", owner_id, device_id);
            let device_json = serde_json::to_value(device_info.clone()).unwrap();
            return Ok(RPCResponse::new(RPCResult::Success(device_json), req.id));
        }
    }

    async fn get_user_sn_ips(&self, owner_id: &str) ->Vec<IpAddr> {
        let db = GLOBAL_SN_DB.lock().await;
        let sn_ips = db.get_user_sn_ips_as_vec(owner_id);
        if sn_ips.is_err() {
            warn!("failed to get user sn ips for {}: {:?}", owner_id, sn_ips.err().unwrap());
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
        let mut sn_ip_add:Vec<IpAddr> = Vec::new();
        for ip_str in sn_ips {
            let ip = IpAddr::from_str(ip_str.as_str());
            if ip.is_ok() {
                sn_ip_add.push(ip.unwrap());
            } else {
                warn!("failed to parse ip {} {}",ip_str,ip.err().unwrap());
            }
        }
        return sn_ip_add;
    }

    async fn get_device_info(
        &self,
        owner_id: &str,
        device_name: &str,
    ) -> Option<(DeviceInfo, IpAddr)> {
        let key = format!("{}_{}", owner_id, device_name);
        let mut device_info_map = self.all_device_info.lock().await;
        let device_info = device_info_map.get(&key);
        if device_info.is_none() {
            warn!(
                "device info not found for {} in memory cache, try to query from db",
                key
            );
            let db = GLOBAL_SN_DB.lock().await;
            let device_json = db.query_device_by_name(owner_id, device_name).unwrap();
            if device_json.is_none() {
                warn!("device info not found for {} in db", key);
                return None;
            }
            let device_json = device_json.unwrap();
            let sn_ip = device_json.3;
            let sn_ip = IpAddr::from_str(sn_ip.as_str()).unwrap();
            let device_info_json: String = device_json.4;
            //info!("device info json: {}",device_info_json);
            let device_info = serde_json::from_str::<DeviceInfo>(device_info_json.as_str());
            if device_info.is_err() {
                warn!(
                    "failed to parse device info from db for {}: {:?}",
                    key,
                    device_info.err().unwrap()
                );
                return None;
            }
            let device_info = device_info.unwrap();
            device_info_map.insert(key.clone(), (device_info.clone(), sn_ip));
            return Some((device_info.clone(), sn_ip));
        } else {
            return device_info.cloned();
        }
    }

    //return (owner_public_key,zone_config_jwt)
    async fn get_user_zone_config(&self, username: &str) -> Option<(String, String, Option<String>)> {
        let mut user_zone_config_map = self.all_user_zone_config.lock().await;
        let zone_config_reuslt = user_zone_config_map.get(username).cloned();
        if zone_config_reuslt.is_none() {
            let db = GLOBAL_SN_DB.lock().await;
            let user_info = db.get_user_info(username).unwrap();
            if user_info.is_some() {
                let user_info = user_info.unwrap();
                // 只存储前两个字段 (public_key, zone_config)，忽略 sn_ips
                let (public_key, zone_config, sn_ips) = user_info.clone();
                let stored_info = (public_key.clone(), zone_config.clone());
                user_zone_config_map.insert(username.to_string(), stored_info);
                return Some(user_info);
            }
            warn!("zone config not found for [{}]", username);
            return None;
        } else {
            // 从缓存中获取的数据只有两个字段，需要添加 None 作为 sn_ips
            let (public_key, zone_config) = zone_config_reuslt.unwrap();
            return Some((public_key, zone_config, None));
        }
    }

    async fn get_user_public_key(&self, username: &str) -> Option<String> {
        let db = GLOBAL_SN_DB.lock().await;
        let user_info = db.get_user_info(username).unwrap();
        if user_info.is_some() {
            return Some(user_info.unwrap().0.clone());
        }
        return None;
    }


    //return (subhost,username)
    pub fn get_user_subhost_from_host(host: &str,server_host: &str) -> Option<(String,String)> {
        let end_string = format!(".{}", server_host);
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

    async fn get_user_zonegate_address(&self, username: &str) -> Option<Vec<IpAddr>> {
        let device_info = self.get_device_info(username, "ood1").await;

        if device_info.is_some() {
            let (device_info, device_ip) = device_info.unwrap();
            let mut address_vec: Vec<IpAddr> = Vec::new();
            let device_report_ip = device_info.ip;
            if device_info.is_wan_device() {
                if device_report_ip.is_some() {
                    let device_report_ip = device_report_ip.unwrap();
                    match device_report_ip {
                        IpAddr::V4(ip) => {
                            if ip.is_private() {
                                address_vec.push(device_ip);
                                address_vec.push(device_report_ip);
                            } else {
                                info!("device {} is wan device with public_v4ip, return report ip {} ",username,device_report_ip);
                                address_vec.push(device_report_ip);
                            }
                        }
                        IpAddr::V6(ip) => {
                            info!(
                                "device {} is wan device with v6, return report ip {} ",
                                username, device_report_ip
                            );
                            address_vec.push(device_report_ip);
                            address_vec.push(device_ip);
                        }
                    }
                } else {
                    info!(
                        "device {} is wan device without self-report ip, return device_ip {}",
                        username, device_ip
                    );
                    address_vec.push(device_ip);
                }
            } else {
                let sn_ips = self.get_user_sn_ips(username).await;
                if sn_ips.is_empty() {
                    address_vec.push(self.server_ip);
                } else {
                    for ip in sn_ips {
                        address_vec.push(ip);
                    }
                }
            }
            return Some(address_vec);
        }
        return None;
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
            "query_by_hostname" => {
                //query device by hostname
                let hostname = req.params.get("dest_host");
                if hostname.is_none() {
                    return Err(RPCErrors::ParseRequestError("Invalid params, hostname is none".to_string()));
                }
                let hostname = hostname.unwrap().as_str();
                if hostname.is_none() {
                    return Err(RPCErrors::ParseRequestError("Invalid params, hostname is none".to_string()));
                }
                let hostname = hostname.unwrap();
                let ood_info= self.query_device_by_hostname(hostname).await;
                if ood_info.is_some() {
                    let ood_info = ood_info.unwrap();
                    let ood_json = serde_json::to_value(ood_info).unwrap();
                    return Ok(RPCResponse::new(RPCResult::Success(ood_json), req.id));
                } else {
                    return Err(RPCErrors::ParseRequestError("Invalid params, hostname is none".to_string()));
                }
            }
            "query_by_did" => {
                let did = req.params.get("source_device_id");
                if did.is_none() {
                    return Err(RPCErrors::ParseRequestError("Invalid params, did is none".to_string()));
                }
                let did = did.unwrap().as_str();
                if did.is_none() {
                    return Err(RPCErrors::ParseRequestError("Invalid params, did is none".to_string()));
                }
                let did = did.unwrap();
                let ood_info = self.query_by_did(did).await;
                if ood_info.is_some() {
                    let ood_info = ood_info.unwrap();
                    let ood_json = serde_json::to_value(ood_info).unwrap();
                    return Ok(RPCResponse::new(RPCResult::Success(ood_json), req.id));
                } else {
                    return Err(RPCErrors::ParseRequestError("Invalid params, did is none".to_string()));
                }
            }
            _ => Err(RPCErrors::UnknownMethod(req.method)),
        }
    }


    async fn query_by_did(
        &self,
        did: &str,
    ) -> Option<OODInfo> {
        let db = GLOBAL_SN_DB.lock().await;
        let device_info = db.query_device_by_did(did).unwrap();
        if device_info.is_none() {
            return None;
        }
        let device_info = device_info.unwrap();
        let (username, device_name, did, ip, description, created_at, updated_at) = device_info;
        return Some(OODInfo {
            did_hostname: did.to_string(),
            owner_id: username.clone(),
            self_cert: true,
            state: "active".to_string(),
        });
    }

    async fn query_device_by_hostname(
        &self,
        req_host: &str,
    ) -> Option<OODInfo> {
        let get_result = SNServer::get_user_subhost_from_host(req_host, &self.server_host);
        if get_result.is_some() {
            let (sub_host,username) = get_result.unwrap();
            let device_info = self.get_device_info(username.as_str(), "ood1").await;
            if device_info.is_some() {
                info!("ood1 device info found for {} in sn server",username);
                //let device_did = device_info.unwrap().0.did;
                let (device_info, device_ip) = device_info.unwrap();
                let did_hostname = device_info.id.to_host_name();
                let ood_info = OODInfo {
                    did_hostname: did_hostname,
                    owner_id: username.clone(),
                    self_cert: false,
                    state: "active".to_string(),
                };
                return Some(ood_info);
            } else {
                warn!("ood1 device info not found for {} in sn server", username);
            }
        } else {
            let db = GLOBAL_SN_DB.lock().await;
            let user_info = db.get_user_info_by_domain(req_host);
            if user_info.is_err() {
                info!("failed to get user info by domain: {}", user_info.err().unwrap());
                return None;
            }
            let user_info = user_info.unwrap();
            if user_info.is_none() {
                return None;
            }
            let (username, public_key, zone_config, _) = user_info.unwrap();
            let device_info = self.get_device_info(username.as_str(), "ood1").await;
            if device_info.is_some() {
                //info!("ood1 device info found for {} in sn server",username);
                //let device_did = device_info.unwrap().0.did;
                let device_did = device_info.as_ref().unwrap().0.id.clone();
                let did_hostname = device_did.to_host_name();
                let ood_info = OODInfo {
                    did_hostname: did_hostname,
                    owner_id: username.clone(),
                    self_cert: true,
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
}

#[async_trait]
impl QAServer for SNServer {
    async fn serve_question(&self, req: &serde_json::Value) -> ServerResult<serde_json::Value> {
        let rpc_request = qa_json_to_rpc_request(req);
        if rpc_request.is_err() {
            return Err(server_err!(ServerErrorCode::InvalidParam, "invalid request"));
        }
        let rpc_request = rpc_request.unwrap();
        let rpc_response = self.handle_rpc_call(rpc_request, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))).await;
        if rpc_response.is_err() {
            return Err(server_err!(ServerErrorCode::ProcessChainError, "failed to handle rpc call"));
        }
        let rpc_response = rpc_response.unwrap();
        return Ok(serde_json::to_value(rpc_response).unwrap());
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
            "sn server process name query: {}, record_type: {:?}",
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
            return Err(server_err!(ServerErrorCode::NotFound,
                "sn-server not support record type {}",
                record_type.to_string()
            ));
        }
        let mut req_real_name:String = name.to_string();
        if name.ends_with(".") {
            req_real_name = name.trim_end_matches('.').to_string();
        }

        if req_real_name == self.server_host
        || self.server_aliases.contains(&req_real_name)

        {
            //返回当前服务器的地址
            match record_type {
                RecordType::A => {
                    let result_name_info = NameInfo::from_address(name, self.server_ip);
                    return Ok(result_name_info);
                }
                //TODO:
                // RecordType::TXT => {
                //     let mut gateway_list = Vec::new();
                //     let current_device_config = CURRENT_DEVICE_CONFIG.get();
                //     if current_device_config.is_some() {
                //         let current_device_config = current_device_config.unwrap();
                //         gateway_list.push(current_device_config.get_id().to_string());
                //     }
                //     let gateway_list = Some(gateway_list);
                //     //返回当前服务器的zoneconfig和auth_key
                //     let result_name_info = NameInfo::from_zone_config_str(
                //         name,
                //         self.zone_boot_config.as_str(),
                //         self.zone_boot_config_pkx.as_str(),
                //         &gateway_list,
                //     );
                //     return Ok(result_name_info);
                // }
                _ => {
                    return Err(server_err!(ServerErrorCode::NotFound,
                        "sn-server not support record type {}",
                        record_type.to_string()
                    ));
                }
            }
        }
        //query A or AAAA record
        //端口映射方案: 如果用户存在 返回设备ood1的IP
        //使用web3桥返连方案:如果用户存在和ood1都存在 返回当前服务器的IP

        //query TXT record
        //如果用户存在，则返回用户的ZoneConfig
        let end_string = format!(".{}.", self.server_host.as_str());
        if name.ends_with(&end_string) {
            let sub_name = name[0..name.len() - end_string.len()].to_string();
            //split sub_name by "."
            let subs: Vec<&str> = sub_name.split(".").collect();
            let username = subs.last();
            if username.is_none() {
                return Err(server_err!(ServerErrorCode::NotFound, "{}", name.to_string()));
            }
            let username = username.unwrap();
            info!(
                "sub zone {},enter sn serverquery: {}, record_type: {:?}",
                username, name, record_type
            );
            match record_type {
                RecordType::TXT => {
                    let zone_config = self.get_user_zone_config(username).await;
                    if zone_config.is_some() {
                        //TODO:
                        // let zone_config = zone_config.unwrap();
                        // let pkx = get_x_from_jwk_string(zone_config.0.as_str()).map_err(|e| {
                        //     error!("failed to get x from jwk string: {:?}", e);
                        //     server_err!(ServerErrorCode::NotFound,
                        //         "failed to get x from jwk string: {}",
                        //         e.to_string()
                        //     )
                        // })?;
                        // let result_name_info = NameInfo::from_zone_config_str(
                        //     name,
                        //     zone_config.1.as_str(),
                        //     pkx.as_str(),
                        //     &None,
                        // );
                        // info!("result_name_info: {:?}", result_name_info);
                        // return Ok(result_name_info);
                        unimplemented!();
                    } else {
                        return Err(server_err!(ServerErrorCode::NotFound, "{}", name.to_string()));
                    }
                }
                RecordType::A | RecordType::AAAA => {
                    let address_vec = self.get_user_zonegate_address(username).await;
                    if address_vec.is_some() {
                        let address_vec = address_vec.unwrap();
                        let result_name_info = NameInfo::from_address_vec(name, address_vec);
                        return Ok(result_name_info);
                    } else {
                        return Err(server_err!(ServerErrorCode::NotFound, "{}", name.to_string()));
                    }
                }
                _ => {
                    return Err(server_err!(ServerErrorCode::NotFound,
                        "sn-server not support record type {}",
                        record_type.to_string()
                    ));
                }
            }
        } else {
            let real_domain_name = name[0..name.len() - 1].to_string();
            let db = GLOBAL_SN_DB.lock().await;
            let user_info = db
                .get_user_info_by_domain(real_domain_name.as_str())
                .unwrap();
            if user_info.is_none() {
                return Err(server_err!(ServerErrorCode::NotFound, "{}", name.to_string()));
            }
            let (username, public_key, zone_config, _) = user_info.unwrap();
            match record_type {
                RecordType::TXT => {
                    //TODO:
                    // let pkx = get_x_from_jwk_string(public_key.as_str())
                    //     .map_err(into_server_err!(ServerErrorCode::InvalidConfig))?;
                    // let result_name_info = NameInfo::from_zone_config_str(
                    //     name,
                    //     zone_config.as_str(),
                    //     pkx.as_str(),
                    //     &None,
                    // );
                    // return Ok(result_name_info);
                    unimplemented!();
                }
                RecordType::A | RecordType::AAAA => {
                    let address_vec = self.get_user_zonegate_address(&username).await;
                    if address_vec.is_some() {
                        let address_vec = address_vec.unwrap();
                        let result_name_info = NameInfo::from_address_vec(name, address_vec);
                        return Ok(result_name_info);
                    }
                }
                _ => {
                    return Err(server_err!(ServerErrorCode::NotFound,
                        "sn-server not support record type {}",
                        record_type.to_string()
                    ));
                }
            }

            return Err(server_err!(ServerErrorCode::NotFound, "{}", name.to_string()));
        }
    }

    async fn query_did(
        &self,
        did: &DID,
        fragment: Option<&str>,
        from_ip: Option<IpAddr>,
    ) -> ServerResult<EncodedDocument> {
        return Err(server_err!(ServerErrorCode::NotFound,
            "sn-server not support did query"
        ));
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

    async fn serve_request(&self, request: http::Request<BoxBody<Bytes, ServerError>>, info: StreamInfo) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        if request.method() != Method::POST {
            return Ok(Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(BoxBody::new(Full::new(Bytes::from_static(b"Method Not Allowed"))
                    .map_err(|e| match e {}).boxed())).unwrap());
        }

        let client_ip = match info.src_addr {
            Some(addr) => {
                match addr.parse::<SocketAddr>() {
                    Ok(socket_addr) => socket_addr.ip(),
                    Err(e) => {
                        error!("parse client ip {} err {}", addr.as_str(), e);
                        return Ok(Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(BoxBody::new(Full::new(Bytes::from_static(b"Bad Request")))
                                .map_err(|e| match e {}).boxed())
                            .unwrap());
                    }
                }
            }
            None => {
                error!("Failed to get client ip");
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(BoxBody::new(Full::new(Bytes::from_static(b"Bad Request")))
                        .map_err(|e| match e {}).boxed())
                    .unwrap());
            }
        };

        let body_bytes = match request.collect().await {
            Ok(data) => {
                data.to_bytes()
            }
            Err(e) => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(BoxBody::new(Full::new(Bytes::from(format!("Failed to read body: {:?}", e))))
                        .map_err(|e| match e {}).boxed())
                    .unwrap());
            }
        };

        let body_str = match String::from_utf8(body_bytes.to_vec()) {
            Ok(s) => s,
            Err(e) => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(BoxBody::new(Full::new(Bytes::from(format!("Failed to convert body to string: {}", e))))
                        .map_err(|e| match e {}).boxed())
                    .unwrap());
            }
        };

        info!("|==>recv kRPC req: {}",body_str);

        let rpc_request: RPCRequest = match serde_json::from_str(body_str.as_str()) {
            Ok(rpc_request) => rpc_request,
            Err(e) => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(BoxBody::new(Full::new(Bytes::from(format!("Failed to parse request body to RPCRequest: {}", e))))
                        .map_err(|e| match e {}).boxed())
                    .unwrap());
            }
        };

        let resp = match self.handle_rpc_call(rpc_request, client_ip).await {
            Ok(resp) => resp,
            Err(e) => {
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(BoxBody::new(Full::new(Bytes::from(format!("Failed to handle rpc call: {}", e))))
                        .map_err(|e| match e {}).boxed())
                    .unwrap());
            }
        };

        //parse resp to Response<Body>
        Ok(Response::new(Full::new(Bytes::from(serde_json::to_string(&resp).unwrap()))
            .map_err(|never| match never {}).boxed()))
    }
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SNServerConfig {
    id: String,
    host: String,
    ip: String,
    zone_config_jwt: String,
    zone_config_pkx: String,
    #[serde(default)]
    aliases: Vec<String>,
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


    fn add_pre_hook_point_process_chain(&self, _process_chain: ProcessChainConfig) -> Arc<dyn ServerConfig> {
        Arc::new(self.clone())
    }

    fn remove_pre_hook_point_process_chain(&self, _process_chain_id: &str) -> Arc<dyn ServerConfig> {
        Arc::new(self.clone())
    }

    fn add_post_hook_point_process_chain(&self, _process_chain: ProcessChainConfig) -> Arc<dyn ServerConfig> {
        Arc::new(self.clone())
    }

    fn remove_post_hook_point_process_chain(&self, _process_chain_id: &str) -> Arc<dyn ServerConfig> {
        Arc::new(self.clone())
    }
}

pub struct SNServerFactory {}

impl SNServerFactory {
    pub fn new() -> Self {
        SNServerFactory {}
    }
}

#[async_trait::async_trait]
impl ServerFactory for SNServerFactory {
    async fn create(&self, config: Arc<dyn ServerConfig>) -> ServerResult<Vec<Server>> {
        let config = config.as_any().downcast_ref::<SNServerConfig>()
            .ok_or(server_err!(ServerErrorCode::InvalidConfig, "invalid SNServer config {}", config.server_type()))?;

        let sn = Arc::new(SNServer::new(config.clone()));
        Ok(vec![Server::NameServer(sn.clone()), Server::Http(sn.clone()), Server::QA(sn.clone())])
    }
}

#[cfg(test)]
mod tests {
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
        let server_host = "web3.buckyos.io".to_string();
        let req_host = "home.lzc.web3.buckyos.io".to_string();
        let (sub_host,username) = SNServer::get_user_subhost_from_host(&req_host, &server_host).unwrap();
        assert_eq!(sub_host, "home.lzc".to_string());
        assert_eq!(username, "lzc".to_string());

        let req_host = "www-lzc.web3.buckyos.io".to_string();
        let (sub_host,username) = SNServer::get_user_subhost_from_host(&req_host, &server_host).unwrap();
        assert_eq!(sub_host, "www-lzc".to_string());
        assert_eq!(username, "lzc".to_string());

        let req_host = "buckyos-filebrowser-lzc.web3.buckyos.io".to_string();
        let (sub_host,username) = SNServer::get_user_subhost_from_host(&req_host, &server_host).unwrap();
        assert_eq!(sub_host, "buckyos-filebrowser-lzc".to_string());
        assert_eq!(username, "lzc".to_string());
    }
}
