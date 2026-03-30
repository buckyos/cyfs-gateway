use super::auth::handle_auth;
use super::common::RpcCallResult;
use super::device::handle_device;
use super::did::handle_did;
use super::dns::handle_dns;
use super::query::handle_query;
use super::user::handle_user;
use super::zone::handle_zone;
use crate::SNServer;
use ::kRPC::{RPCRequest, RPCResponse, RPCErrors};

pub(crate) fn parse_v2_module(path: &str) -> Option<&str> {
    path.strip_prefix("/kapi/sn/v2/")
        .or_else(|| path.strip_prefix("/v2/"))
        .map(|rest| rest.split('/').next().unwrap_or(""))
        .filter(|module| !module.is_empty())
}

pub(crate) async fn handle_rpc_call_v2(
    server: &SNServer,
    module: &str,
    req: RPCRequest,
    ip_from: std::net::IpAddr,
) -> RpcCallResult<RPCResponse> {
    match module {
        "auth" => handle_auth(server, req).await,
        "user" => handle_user(server, req).await,
        "zone" => handle_zone(server, req).await,
        "device" => handle_device(server, req).await,
        "dns" => handle_dns(server, req).await,
        "did" => handle_did(server, req).await,
        "query" => handle_query(server, req, ip_from).await,
        other => Err(RPCErrors::UnknownMethod(format!(
            "unknown sn v2 module {}",
            other
        ))),
    }
}
