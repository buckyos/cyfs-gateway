use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Bytes;
use ndn_lib::{CYFS_HEADER_DISPATCH_ERROR, CyfsDispatchResult, normalize_cyfs_dispatch_target};
use serde::{Deserialize, Serialize};

use crate::ServerError;

pub(crate) type DispatchBody = BoxBody<Bytes, ServerError>;

/// Set only by an authenticated in-process caller or the HTTP host after its
/// authentication rules set AUTH_principal. Wire headers cannot create this.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifiedDispatchContext {
    pub principal: String,
    pub target: String,
    pub credentials: Vec<(String, String)>,
    pub received_at_ms: u64,
    pub ingress: String,
}

impl VerifiedDispatchContext {
    pub fn validate(&self) -> bool {
        !self.principal.is_empty()
            && self.principal.len() <= 1024
            && !self.ingress.is_empty()
            && self.ingress.len() <= 1024
            && http::HeaderValue::from_str(&self.principal).is_ok()
            && self
                .credentials
                .iter()
                .map(|(k, v)| k.len() + v.len())
                .sum::<usize>()
                <= 16384
            && self
                .credentials
                .iter()
                .all(|(k, v)| replay_header(k) && http::HeaderValue::from_str(v).is_ok())
    }
}

pub(crate) fn replay_header(name: &str) -> bool {
    matches!(
        name,
        "authorization" | "cyfs-proofs" | "cyfs-cascades" | "cyfs-access-code"
    )
}

pub(crate) fn dispatch_target<B>(req: &Request<B>) -> Result<String, String> {
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .or_else(|| req.uri().authority().map(|a| a.as_str()))
        .ok_or("missing dispatch host")?;
    let target =
        normalize_cyfs_dispatch_target(host, req.uri().path()).map_err(|e| e.to_string())?;
    if let Some(authority) = req.uri().authority() {
        if normalize_cyfs_dispatch_target(authority.as_str(), req.uri().path())
            .map_err(|e| e.to_string())?
            != target
        {
            return Err("dispatch Host disagrees with URI authority".into());
        }
    }
    Ok(target)
}

pub(crate) fn is_dispatch<B>(req: &Request<B>) -> bool {
    (req.method() == http::Method::PUT
        && req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(ndn_lib::is_cyfs_named_object_content_type))
        || (req.method() == http::Method::GET
            && req.uri().query().is_some_and(|q| {
                url::form_urlencoded::parse(q.as_bytes()).any(|(k, _)| k == "dispatch-status")
            }))
}

pub(crate) fn dispatch_response(
    status: StatusCode,
    result: &CyfsDispatchResult,
) -> Response<DispatchBody> {
    let mut response = Response::new(
        Full::new(Bytes::from(serde_json::to_vec(result).unwrap()))
            .map_err(|e| match e {})
            .boxed(),
    );
    *response.status_mut() = status;
    result.apply_headers(response.headers_mut());
    response
}

pub(crate) fn dispatch_error(
    status: StatusCode,
    target: &str,
    reason: &str,
) -> Response<DispatchBody> {
    let mut response = Response::new(
        Full::new(Bytes::from(
            serde_json::json!({
                "target": target, "error": reason
            })
            .to_string(),
        ))
        .map_err(|e| match e {})
        .boxed(),
    );
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert("content-type", "application/json".parse().unwrap());
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert(CYFS_HEADER_DISPATCH_ERROR, reason.parse().unwrap());
    response
}

pub(crate) fn dispatch_rejected(
    status: StatusCode,
    target: &str,
    reason: &str,
) -> Response<DispatchBody> {
    dispatch_response(
        status,
        &CyfsDispatchResult::rejected(None, target.into(), reason, status.is_server_error()),
    )
}
