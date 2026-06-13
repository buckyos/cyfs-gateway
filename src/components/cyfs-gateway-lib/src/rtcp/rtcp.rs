use super::package::*;
use super::protocol::*;
use super::stream_helper::RTcpStreamBuildHelper;
use std::collections::HashMap;

use crate::rtcp::datagram::RTcpTunnelDatagramClient;
use crate::tunnel::TunnelBox;
use crate::tunnel_url_status::{
    TunnelProbeOptions, TunnelUrlStatus, TunnelUrlStatusSource, normalize_tunnel_url,
    reachable_status, unreachable_status,
};
use crate::{
    DatagramClientBox, EncryptedStream, EncryptionRole, Tunnel, TunnelEndpoint, TunnelError,
    TunnelManager, TunnelResult, get_dest_info_from_url_path, has_scheme,
};
use anyhow::Result;
use async_trait::async_trait;
use buckyos_kit::{AsyncStream, buckyos_get_unix_timestamp};
use futures_util::stream::{FuturesUnordered, StreamExt};
use hex::ToHex;
use hkdf::Hkdf;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use log::*;
use name_client::*;
use name_lib::*;
use percent_encoding::percent_decode_str;
use rand::Rng;
use sha2::Sha256;
use std::fmt;
use std::io::ErrorKind;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::fd::{FromRawFd, IntoRawFd};
#[cfg(windows)]
use std::os::windows::io::{FromRawSocket, IntoRawSocket};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32};
use std::time::{Duration, Instant};
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore, TryAcquireError, oneshot};
use tokio::task;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use url::Url;
use x25519_dalek::{EphemeralSecret, PublicKey};

pub struct RTcp {
    inner: Arc<RTcpInner>,
    handle: Option<JoinHandle<()>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RTcpSourceDeviceInfo {
    pub device_doc_jwt: Option<String>,
    pub name: Option<String>,
    pub owner: Option<String>,
    pub zone_did: Option<String>,
}

impl Drop for RTcp {
    fn drop(&mut self) {
        log::debug!("RTcp {} drop", self.inner.this_device_did.to_string());
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

impl RTcp {
    pub fn new(
        this_device_did: DID,
        bind_addr: String,
        private_key_pkcs8_bytes: Option<[u8; 48]>,
        this_device_doc_jwt: Option<String>,
        listener: RTcpListenerRef,
    ) -> RTcp {
        RTcp {
            inner: Arc::new(RTcpInner::new(
                this_device_did,
                bind_addr,
                private_key_pkcs8_bytes,
                this_device_doc_jwt,
                listener,
            )),
            handle: None,
        }
    }

    pub fn set_reuse_address(&mut self, reuse_address: bool) {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.reuse_address = reuse_address;
        } else {
            warn!("set_reuse_address ignored: rtcp already shared");
        }
    }

    // Provides the tunnel framework entry point that create_tunnel uses when the
    // RTCP stack id carries a `params@remote` bootstrap URL. Must be called
    // before the stack is cloned into an Arc, otherwise the setter is a no-op.
    pub fn set_tunnel_manager(&mut self, tunnel_manager: TunnelManager) {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.tunnel_manager = Some(tunnel_manager);
        } else {
            warn!("set_tunnel_manager ignored: rtcp already shared");
        }
    }

    pub async fn start(&mut self) -> TunnelResult<()> {
        let inner = self.inner.clone();
        let handle = inner.start().await?;
        self.handle = Some(handle);
        Ok(())
    }

    pub async fn create_tunnel(
        &self,
        tunnel_stack_id: Option<&str>,
    ) -> TunnelResult<Box<dyn TunnelBox>> {
        self.inner.create_tunnel(tunnel_stack_id).await
    }

    pub async fn probe_url(
        &self,
        url: &Url,
        options: &TunnelProbeOptions,
    ) -> TunnelResult<TunnelUrlStatus> {
        self.inner.probe_url(url, options).await
    }
}

// §14.2 anti-replay: tunnel_token lifetime. The signed token carries this
// exp; the responder accepts it within [exp - leeway, exp + leeway] (see
// JWT_LEEWAY_SECS below). A legitimate Hello thus tolerates ~60s of clock
// skew either way while still closing the replay window aggressively
// compared to the old 2h value.
const TUNNEL_TOKEN_EXP_SECS: u64 = 60;

// JWT validation leeway used when decoding `tunnel_token`. The nonce cache
// must outlive the full acceptance window (`exp + JWT_LEEWAY_SECS`), or a
// replay between `exp` and `exp + leeway` would still pass signature
// validation while finding a freshly-evicted nonce slot. The constant is
// referenced both when constructing `Validation` and when computing the
// nonce-cache retain deadline, so the two windows stay in lock-step.
const JWT_LEEWAY_SECS: u64 = 60;

// Max time the responder will wait for the initiator's HelloAckConfirm, and
// the initiator will wait for the responder's HelloAck. Keeps stuck
// handshakes from pinning an (aes_key, nonce_base) slot.
const HELLO_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

// Happy Eyeballs style stagger between direct RTCP connection attempts. The
// address order still matters, but a slow first candidate no longer blocks the
// next one until it fully fails.
const DIRECT_CONNECT_ATTEMPT_DELAY: Duration = Duration::from_millis(250);
const DIRECT_TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

// Upper bound on NonceCache size. Each entry is ~100 bytes, so 16k entries
// caps memory at roughly 1.6 MiB. A healthy peer hits nowhere near this;
// hitting the cap implies sustained abuse, at which point we evict the
// oldest pending entries to avoid unbounded growth. Eviction under abuse
// is acceptable: eviction only re-opens replay for tokens that would
// otherwise also be expiring shortly, and the attacker still needs a valid
// signed token to get past signature verification.
const NONCE_CACHE_CAP: usize = 16 * 1024;

// Tracks (from_id, nonce) pairs from successfully-verified Hello tokens
// so a replayed token -- identical bytes, same signature -- is rejected
// before we do any expensive crypto beyond the signature check. Entries
// are evicted once the associated token's `exp` has passed (plus a small
// grace), since a token that can no longer be validated is no longer a
// replay vector.
struct NonceCache {
    seen: Mutex<HashMap<(String, String), u64>>,
}

impl NonceCache {
    fn new() -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
        }
    }

    // Returns true if this (from_id, nonce) had not been seen while still
    // within its retention window. `retain_until_ts` must be the last
    // timestamp at which the corresponding JWT is still signature-valid
    // (i.e. `exp + leeway`); keeping the cache aligned with the signature
    // acceptance window is what makes replay-rejection airtight.
    async fn insert_if_fresh(
        &self,
        from_id: &str,
        nonce: &str,
        retain_until_ts: u64,
        now_ts: u64,
    ) -> bool {
        let mut seen = self.seen.lock().await;
        // Opportunistic cleanup: drop entries whose retention has passed.
        // This is O(n) but only runs when we're already taking the lock
        // to insert, and n is capped below.
        seen.retain(|_, retain_until| *retain_until > now_ts);

        let key = (from_id.to_owned(), nonce.to_owned());
        if seen.contains_key(&key) {
            return false;
        }

        if seen.len() >= NONCE_CACHE_CAP {
            // Evict whatever entry will expire soonest. Under sustained
            // abuse this gives up the strongest anti-replay guarantee on
            // the oldest entries, but prevents unbounded memory growth.
            if let Some(soonest) = seen
                .iter()
                .min_by_key(|(_, retain_until)| *retain_until)
                .map(|(k, _)| k.clone())
            {
                seen.remove(&soonest);
            }
        }

        seen.insert(key, retain_until_ts);
        true
    }
}

// Captures the initiator's per-handshake state from the moment the Hello
// is signed until HelloAck is verified and the session keys are derived.
//
// Held by-value across the network round-trip rather than by reference so
// `EphemeralSecret` (move-only, single-use) can be consumed exactly once
// when ECDH runs against the responder's ephemeral public key.
struct InitiatorHandshakeState {
    token: String,
    my_secret: EphemeralSecret,
    my_xpub_bytes: [u8; 32],
    my_xpub_hex: String,
    my_nonce_hex: String,
    responder_ed25519_pk_der: Vec<u8>,
    responder_did: String,
}

struct ResolvedHandshakeIdentity {
    did: DID,
    ed25519_pk_der: [u8; 32],
}

// Decode a hex-encoded 32-byte X25519 public key. Used by both Hello and
// HelloAck JWT verification paths.
fn decode_x25519_pub_hex(hex_str: &str) -> Result<[u8; 32], TunnelError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| TunnelError::ReasonError(format!("decode x25519 pub hex error:{}", e)))?;
    bytes.try_into().map_err(|_| {
        TunnelError::ReasonError("x25519 pub key must be exactly 32 bytes".to_string())
    })
}

struct RTcpInner {
    tunnel_map: RTcpTunnelMap,
    stream_helper: RTcpStreamBuildHelper,
    listener: RTcpListenerRef,

    bind_addr: String,
    reuse_address: bool,
    this_device_did: DID, //name or did
    this_device_ed25519_sk: Option<EncodingKey>,
    this_device_doc_jwt: Option<String>,
    // Used by create_tunnel to build a bootstrap stream through the tunnel
    // framework when the stack id carries a `params@remote` prefix. None means
    // only direct TCP bootstrap is available (backward compatible path).
    tunnel_manager: Option<TunnelManager>,
    // §14.2: reject replayed Hello tokens by their embedded nonce.
    nonce_cache: NonceCache,
}

struct DirectTunnelAttempt {
    remote_addr: SocketAddr,
    tunnel: RTcpTunnel,
}

impl Drop for RTcpInner {
    fn drop(&mut self) {
        log::debug!("RTcpInner {} drop", self.this_device_did.to_string());
    }
}

impl RTcpInner {
    fn extract_missing_field_name(err: &str) -> Option<String> {
        for marker in ["missing field `", "missing field '"] {
            if let Some(start) = err.find(marker) {
                let value_start = start + marker.len();
                let tail = &err[value_start..];
                if let Some(end) = tail.find(['`', '\'']) {
                    let field = tail[..end].trim();
                    if !field.is_empty() {
                        return Some(field.to_string());
                    }
                }
            }
        }

        None
    }

    fn extract_txt_value(record: &str, key: &str) -> Option<String> {
        let prefix = format!("{}=", key);
        for segment in record.split(';') {
            let segment = segment.trim();
            if segment.is_empty() {
                continue;
            }
            if let Some(value) = segment.strip_prefix(prefix.as_str()) {
                let value = value.trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
        None
    }

    async fn resolve_handshake_identity_by_web_name_info(
        remote_did: &DID,
    ) -> Result<Option<ResolvedHandshakeIdentity>, String> {
        if remote_did.method != "web" {
            return Ok(None);
        }

        let web_host = remote_did
            .id
            .split(':')
            .next()
            .unwrap_or(remote_did.id.as_str())
            .trim();
        if web_host.is_empty() {
            return Ok(None);
        }

        debug!(
            "try resolve remote device {} exchange key by TXT records of {}",
            remote_did.to_string(),
            web_host
        );

        let name_info = resolve(web_host, Some(RecordType::TXT))
            .await
            .map_err(|e| format!("resolve {} TXT failed: {}", web_host, e))?;

        if name_info.txt.is_empty() {
            return Ok(None);
        }

        debug!(
            "resolve {} TXT for {} got {} records",
            web_host,
            remote_did.to_string(),
            name_info.txt.len()
        );

        let mut parse_errors = Vec::new();

        for (idx, record) in name_info.txt.iter().enumerate() {
            if let Some(dev_jwt) = Self::extract_txt_value(record.as_str(), "DEV") {
                let claims = match decode_jwt_claim_without_verify(dev_jwt.as_str()) {
                    Ok(v) => v,
                    Err(e) => {
                        if parse_errors.len() < 6 {
                            parse_errors.push(format!("TXT[{}] DEV jwt decode failed: {}", idx, e));
                        }
                        continue;
                    }
                };

                let x = match claims.get("x").and_then(|v| v.as_str()) {
                    Some(v) if !v.is_empty() => v,
                    _ => {
                        if parse_errors.len() < 6 {
                            parse_errors.push(format!("TXT[{}] DEV jwt has no x", idx));
                        }
                        continue;
                    }
                };

                let dev_did = DID::new("dev", x);
                if let Some(exchange_key) = dev_did.get_ed25519_auth_key() {
                    debug!(
                        "resolve remote device {} handshake identity as {} by {} TXT DEV",
                        remote_did.to_string(),
                        dev_did.to_string(),
                        web_host
                    );
                    return Ok(Some(ResolvedHandshakeIdentity {
                        did: dev_did,
                        ed25519_pk_der: exchange_key,
                    }));
                }
            }
        }

        for (idx, record) in name_info.txt.iter().enumerate() {
            if let Some(pkx) = Self::extract_txt_value(record.as_str(), "PKX") {
                let x = pkx.split(':').next().unwrap_or(pkx.as_str());
                if !x.is_empty() {
                    let dev_did = DID::new("dev", x);
                    if let Some(exchange_key) = dev_did.get_ed25519_auth_key() {
                        debug!(
                            "resolve remote device {} handshake identity as {} by {} TXT PKX",
                            remote_did.to_string(),
                            dev_did.to_string(),
                            web_host
                        );
                        return Ok(Some(ResolvedHandshakeIdentity {
                            did: dev_did,
                            ed25519_pk_der: exchange_key,
                        }));
                    }
                } else if parse_errors.len() < 6 {
                    parse_errors.push(format!("TXT[{}] PKX is empty", idx));
                }
            }
        }

        if !parse_errors.is_empty() {
            return Err(parse_errors.join("; "));
        }

        Ok(None)
    }

    async fn resolve_handshake_identity(
        remote_did: &DID,
    ) -> Result<ResolvedHandshakeIdentity, String> {
        debug!(
            "resolve handshake identity for remote device {}",
            remote_did.to_string()
        );

        if remote_did.method == "web" {
            debug!(
                "try resolve handshake identity for {} by web TXT records",
                remote_did.to_string()
            );

            match Self::resolve_handshake_identity_by_web_name_info(remote_did).await {
                Ok(Some(identity)) => {
                    debug!(
                        "resolve handshake identity for {} as {} by web TXT records success",
                        remote_did.to_string(),
                        identity.did.to_string()
                    );
                    return Ok(identity);
                }
                Ok(None) => {}
                Err(fallback_err) => {
                    warn!(
                        "resolve handshake identity for {} by web TXT records failed: {}",
                        remote_did.to_string(),
                        fallback_err
                    );
                }
            }
        }

        match resolve_ed25519_exchange_key(remote_did).await {
            Ok(exchange_key) => {
                debug!(
                    "resolve exchange key for {} by DID doc success",
                    remote_did.to_string()
                );
                Ok(ResolvedHandshakeIdentity {
                    did: remote_did.clone(),
                    ed25519_pk_der: exchange_key,
                })
            }
            Err(primary_err) => {
                let primary_err_str = primary_err.to_string();
                warn!(
                    "resolve exchange key for {} by DID doc failed: {}",
                    remote_did.to_string(),
                    primary_err_str
                );

                if let Some(field) = Self::extract_missing_field_name(primary_err_str.as_str()) {
                    warn!(
                        "[schema_compat] DID doc for {} is missing required field `{}`; keeping fallback path enabled and recommend regenerating activation/config data",
                        remote_did.to_string(),
                        field
                    );
                }

                if remote_did.method == "web" {
                    debug!(
                        "try resolve exchange key for {} by web TXT fallback",
                        remote_did.to_string()
                    );

                    match Self::resolve_handshake_identity_by_web_name_info(remote_did).await {
                        Ok(Some(identity)) => {
                            debug!(
                                "resolve exchange key for {} by web TXT fallback success",
                                remote_did.to_string()
                            );
                            return Ok(identity);
                        }
                        Ok(None) => {
                            return Err(format!(
                                "resolve_ed25519_exchange_key failed: {}; web did TXT fallback has no DEV/PKX",
                                primary_err_str
                            ));
                        }
                        Err(fallback_err) => {
                            return Err(format!(
                                "resolve_ed25519_exchange_key failed: {}; web did TXT fallback failed: {}",
                                primary_err_str, fallback_err
                            ));
                        }
                    }
                }

                Err(primary_err_str)
            }
        }
    }

    async fn validate_hello_target(token_to: &str, this_host: &str) -> Result<(), String> {
        if token_to == this_host {
            return Ok(());
        }

        let target_did = DID::from_str(token_to)
            .map_err(|e| format!("token.to {} is not a valid DID: {}", token_to, e))?;
        if target_did.method != "web" {
            return Err(format!(
                "token.to {} is not this device {} and is not a web alias",
                token_to, this_host
            ));
        }

        let resolved_identity = Self::resolve_handshake_identity(&target_did).await?;
        let resolved_host = resolved_identity.did.to_host_name();
        if resolved_host == this_host {
            Ok(())
        } else {
            Err(format!(
                "token.to {} resolves to {}, not this device {}",
                token_to, resolved_host, this_host
            ))
        }
    }

    fn record_direct_attempt_outcome(
        local_addr: Option<SocketAddr>,
        remote_addr: SocketAddr,
        outcome: ConnectionOutcome,
    ) {
        let Some(local_addr) = local_addr else {
            return;
        };

        if let Err(e) = record_connection_outcome(local_addr.ip(), remote_addr, outcome) {
            debug!(
                "record direct RTCP attempt outcome {} -> {} failed: {}",
                local_addr, remote_addr, e
            );
        }
    }

    async fn create_direct_tunnel_attempt(
        &self,
        remote_stack: &RTcpTargetStackEP,
        remote_device_id: &str,
        remote_addr: SocketAddr,
    ) -> Result<DirectTunnelAttempt, String> {
        debug!(
            "Will open tunnel to {}, remote addr is {}",
            remote_device_id, remote_addr
        );

        let tunnel_stream =
            timeout(DIRECT_TCP_CONNECT_TIMEOUT, TcpStream::connect(remote_addr)).await;
        let mut tunnel_stream = match tunnel_stream {
            Ok(Ok(stream)) => stream,
            Ok(Err(connect_err)) => {
                if connect_err.kind() == std::io::ErrorKind::ConnectionRefused {
                    warn!(
                        "connect to {} refused when opening tunnel to {} (did resolved, but rtcp port {} is unreachable/refused)",
                        remote_addr, remote_device_id, remote_stack.stack_port
                    );
                } else {
                    warn!("connect to {} error: {}", remote_addr, connect_err);
                }
                return Err(format!("{} => {}", remote_addr, connect_err));
            }
            Err(_) => {
                return Err(format!(
                    "{} => tcp connect timed out after {:?}",
                    remote_addr, DIRECT_TCP_CONNECT_TIMEOUT
                ));
            }
        };

        let local_addr = tunnel_stream.local_addr().ok();
        let peer_addr = tunnel_stream.peer_addr().ok();

        let state = self
            .generate_tunnel_token(remote_device_id.to_string())
            .await
            .map_err(|e| {
                let msg = format!("generate tunnel token error: {}, {}", remote_device_id, e);
                error!("{}", msg);
                msg
            })?;
        let initiator_did = self.this_device_did.to_host_name();

        let addr: SocketAddr = self.bind_addr.parse().unwrap();
        let hello_package = RTcpHelloPackage::new(
            0,
            self.this_device_did.to_string(),
            remote_device_id.to_string(),
            addr.port(),
            Some(state.token.clone()),
            self.this_device_doc_jwt.clone(),
        );
        let hello_started_at = Instant::now();
        let send_result =
            RTcpTunnelPackage::send_package(Pin::new(&mut tunnel_stream), hello_package).await;
        if let Err(send_err) = send_result {
            warn!("send hello package to {} error:{}", remote_addr, send_err);
            Self::record_direct_attempt_outcome(
                local_addr,
                remote_addr,
                ConnectionOutcome::Unreachable,
            );
            return Err(format!(
                "{} => send hello package error: {}",
                remote_addr, send_err
            ));
        }

        // v2 §14.2 key confirmation: read plaintext HelloAck, verify the
        // responder's signed ack token, derive session keys via HKDF,
        // wrap the stream, then send the AEAD-protected confirm. A
        // direct attempt only wins after this completes.
        let bearing: RTcpBearingStream = Box::new(tunnel_stream);
        let (encrypted_stream, aes_key) =
            match initiator_complete_handshake(bearing, state, &initiator_did).await {
                Ok(v) => v,
                Err(e) => {
                    warn!("key confirmation to {} error: {}", remote_addr, e);
                    let outcome = if e.is_timeout() {
                        ConnectionOutcome::Timeout {
                            elapsed: hello_started_at.elapsed(),
                        }
                    } else {
                        ConnectionOutcome::Unreachable
                    };
                    Self::record_direct_attempt_outcome(local_addr, remote_addr, outcome);
                    return Err(format!("{} => key confirmation error: {}", remote_addr, e));
                }
            };

        Self::record_direct_attempt_outcome(
            local_addr,
            remote_addr,
            ConnectionOutcome::Success {
                rtt: hello_started_at.elapsed(),
                layer: MeasurementLayer::Application,
            },
        );

        Ok(DirectTunnelAttempt {
            remote_addr,
            tunnel: RTcpTunnel::new(
                self.stream_helper.clone(),
                self.this_device_did.clone(),
                remote_stack,
                true,
                encrypted_stream,
                peer_addr,
                None,
                aes_key,
                self.listener.clone(),
            ),
        })
    }

    pub fn new(
        this_device_did: DID,
        bind_addr: String,
        private_key_pkcs8_bytes: Option<[u8; 48]>,
        this_device_doc_jwt: Option<String>,
        listener: RTcpListenerRef,
    ) -> RTcpInner {
        // v2 handshake: the device's long-term Ed25519 key is used only
        // to sign Hello / HelloAck JWTs. ECDH is run between freshly-
        // generated ephemeral X25519 keys on each side, so there is no
        // long-term X25519 secret to keep around any more. (See §14.2 of
        // doc/rtcp.md: dropping the static X25519 is what gives the
        // session forward secrecy against future Ed25519 key exposure.)
        let this_device_ed25519_sk = private_key_pkcs8_bytes
            .as_ref()
            .map(|bytes| EncodingKey::from_ed_der(bytes));

        let result = RTcpInner {
            tunnel_map: RTcpTunnelMap::new(),
            stream_helper: RTcpStreamBuildHelper::new(),

            listener,
            bind_addr,
            reuse_address: false,
            this_device_did,
            this_device_ed25519_sk, //for sign tunnel token
            this_device_doc_jwt,
            tunnel_manager: None,
            nonce_cache: NonceCache::new(),
        };
        return result;
    }

    fn fresh_ephemeral() -> (EphemeralSecret, [u8; 32], String) {
        let secret = EphemeralSecret::random();
        let public = PublicKey::from(&secret);
        let public_bytes = public.to_bytes();
        let public_hex: String = public.encode_hex();
        (secret, public_bytes, public_hex)
    }

    fn fresh_nonce_hex() -> String {
        let mut nonce_bytes = [0u8; 16];
        rand::thread_rng().fill(&mut nonce_bytes);
        nonce_bytes.encode_hex()
    }

    fn sign_jwt<T: serde::Serialize>(
        ed25519_sk: &EncodingKey,
        payload: &T,
    ) -> Result<String, TunnelError> {
        let payload_value = serde_json::to_value(payload)
            .map_err(|e| TunnelError::ReasonError(format!("encode jwt payload error:{}", e)))?;
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = None;
        header.typ = None;
        encode(&header, &payload_value, ed25519_sk)
            .map_err(|e| TunnelError::ReasonError(format!("sign jwt error:{}", e)))
    }

    // Generate the initiator's Hello token (signed JWT carrying the
    // initiator's *ephemeral* X25519 public key). Also resolves the
    // responder's long-term Ed25519 verifying key here so the same key
    // can be used to verify HelloAck without a second resolve round-trip.
    async fn generate_tunnel_token(
        &self,
        remote_hostname: String,
    ) -> Result<InitiatorHandshakeState, TunnelError> {
        let ed25519_sk = self.this_device_ed25519_sk.as_ref().ok_or_else(|| {
            TunnelError::DocumentError("this device ed25519 sk is none".to_string())
        })?;
        let remote_did = DID::from_str(remote_hostname.as_str()).map_err(|op| {
            TunnelError::DocumentError(format!("invalid remote device is not did: {}", op))
        })?;

        let responder_identity = Self::resolve_handshake_identity(&remote_did)
            .await
            .map_err(|op| {
                let msg = format!(
                    "cann't resolve remote device {} ed25519 verifying key: {}",
                    remote_hostname.as_str(),
                    op
                );
                error!("{}", msg);
                TunnelError::DocumentError(msg)
            })?;
        let responder_did = responder_identity.did.to_host_name();
        let responder_ed25519_pk_der = responder_identity.ed25519_pk_der.to_vec();

        let (my_secret, my_public_bytes, my_public_hex) = Self::fresh_ephemeral();

        // §14.2: embed a fresh 16-byte random nonce and use a short exp
        // (default 60s). The responder keeps a nonce cache for the exp
        // window, so any captured token cannot be replayed as-is to stand
        // up a second tunnel. An attacker that replays an already-used
        // token will be rejected at the nonce check even before the key-
        // confirmation handshake kicks in.
        let nonce_hex = Self::fresh_nonce_hex();

        let tunnel_token_payload = TunnelTokenPayload {
            aud: RTCP_HELLO_AUD.to_string(),
            to: responder_did.clone(),
            from: self.this_device_did.to_host_name(),
            xpub: my_public_hex.clone(),
            exp: buckyos_get_unix_timestamp() + TUNNEL_TOKEN_EXP_SECS,
            nonce: nonce_hex.clone(),
        };
        debug!(
            "generated v2 hello token for {} -> {}",
            tunnel_token_payload.from, tunnel_token_payload.to
        );
        let tunnel_token = Self::sign_jwt(ed25519_sk, &tunnel_token_payload)?;

        Ok(InitiatorHandshakeState {
            token: tunnel_token,
            my_secret,
            my_xpub_bytes: my_public_bytes,
            my_xpub_hex: my_public_hex,
            my_nonce_hex: nonce_hex,
            responder_ed25519_pk_der,
            responder_did,
        })
    }

    // Generate the responder's HelloAck JWT, binding the responder's
    // fresh ephemeral X25519 public key to the initiator's `peer_pub_hex`
    // from the Hello (so the ack can't be spliced into a different
    // session).
    async fn generate_ack_token(
        &self,
        initiator_hostname: &str,
        peer_pub_hex: &str,
    ) -> Result<(String, EphemeralSecret, [u8; 32], String), TunnelError> {
        let ed25519_sk = self.this_device_ed25519_sk.as_ref().ok_or_else(|| {
            TunnelError::DocumentError("this device ed25519 sk is none".to_string())
        })?;
        let (my_secret, my_public_bytes, my_public_hex) = Self::fresh_ephemeral();
        let nonce_hex = Self::fresh_nonce_hex();

        let payload = TunnelAckTokenPayload {
            aud: RTCP_HELLO_ACK_AUD.to_string(),
            to: initiator_hostname.to_owned(),
            from: self.this_device_did.to_host_name(),
            xpub: my_public_hex,
            peer_xpub: peer_pub_hex.to_owned(),
            exp: buckyos_get_unix_timestamp() + TUNNEL_TOKEN_EXP_SECS,
            nonce: nonce_hex.clone(),
        };
        let token = Self::sign_jwt(ed25519_sk, &payload)?;
        Ok((token, my_secret, my_public_bytes, nonce_hex))
    }

    fn jwt_validation_for(aud: &str) -> Validation {
        // Explicit leeway pinned to JWT_LEEWAY_SECS so the nonce-cache
        // retention window stays aligned with the signature acceptance
        // window (see §14.2 anti-replay fix).
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.leeway = JWT_LEEWAY_SECS;
        validation.set_audience(&[aud]);
        validation.set_required_spec_claims(&["exp", "aud"]);
        validation
    }

    // Verify a Hello token's JWT signature, audience, and `from` binding.
    // Does NOT touch any X25519 secret; the ephemeral DH is finished by
    // the caller after it generates its own ephemeral key for HelloAck.
    fn verify_hello_token(
        token: &str,
        from_public_key: &DecodingKey,
        expected_from: Option<&str>,
    ) -> Result<([u8; 32], TunnelTokenPayload), TunnelError> {
        let validation = Self::jwt_validation_for(RTCP_HELLO_AUD);
        let decoded = decode::<TunnelTokenPayload>(token, from_public_key, &validation)
            .map_err(|e| TunnelError::DocumentError(format!("decode hello token error:{}", e)))?;
        let payload = decoded.claims;
        if let Some(expected_from) = expected_from {
            if payload.from != expected_from {
                return Err(TunnelError::DocumentError(format!(
                    "hello token from {} not match expected {}",
                    payload.from, expected_from
                )));
            }
        }
        let xpub_bytes = decode_x25519_pub_hex(&payload.xpub)?;
        Ok((xpub_bytes, payload))
    }

    // Verify HelloAck JWT: signature against responder's Ed25519 key,
    // `aud`, `from`/`to` binding, and -- crucially -- that `peer_xpub`
    // matches the initiator's ephemeral public key from this same
    // handshake. Without that last check, an attacker could splice an
    // ack from any past or parallel session that the same responder
    // signed.
    fn verify_ack_token(
        token: &str,
        responder_public_key: &DecodingKey,
        expected_from: &str,
        expected_to: &str,
        expected_peer_xpub_hex: &str,
    ) -> Result<([u8; 32], TunnelAckTokenPayload), TunnelError> {
        let validation = Self::jwt_validation_for(RTCP_HELLO_ACK_AUD);
        let decoded = decode::<TunnelAckTokenPayload>(token, responder_public_key, &validation)
            .map_err(|e| TunnelError::DocumentError(format!("decode ack token error:{}", e)))?;
        let payload = decoded.claims;
        if payload.from != expected_from {
            return Err(TunnelError::DocumentError(format!(
                "ack token from {} not match expected {}",
                payload.from, expected_from
            )));
        }
        if payload.to != expected_to {
            return Err(TunnelError::DocumentError(format!(
                "ack token to {} not match expected {}",
                payload.to, expected_to
            )));
        }
        if payload.peer_xpub != expected_peer_xpub_hex {
            return Err(TunnelError::DocumentError(
                "ack token peer_xpub not match initiator's ephemeral key (replay/splice)"
                    .to_string(),
            ));
        }
        let xpub_bytes = decode_x25519_pub_hex(&payload.xpub)?;
        Ok((xpub_bytes, payload))
    }

    async fn resolve_source_device_info(
        hello_body: &RTcpHelloBody,
    ) -> Result<(String, Option<RTcpSourceDeviceInfo>, DecodingKey), TunnelError> {
        if let Some(device_doc_jwt) = hello_body.device_doc_jwt.as_ref() {
            let unverified_doc =
                DeviceConfig::decode(&EncodedDocument::Jwt(device_doc_jwt.clone()), None).map_err(
                    |e| {
                        TunnelError::DocumentError(format!(
                            "decode device_doc_jwt without verify failed:{}",
                            e
                        ))
                    },
                )?;
            let owner_public_key = resolve_auth_key(&unverified_doc.owner, None)
                .await
                .map_err(|e| {
                    TunnelError::DocumentError(format!(
                        "resolve owner auth key for {} failed:{}",
                        unverified_doc.owner.to_string(),
                        e
                    ))
                })?;
            let verified_doc = DeviceConfig::decode(
                &EncodedDocument::Jwt(device_doc_jwt.clone()),
                Some(&owner_public_key),
            )
            .map_err(|e| {
                TunnelError::DocumentError(format!("verify device_doc_jwt failed:{}", e))
            })?;
            //注意:此时不能使用did:dev:xxx的形式，必须用name did的形式
            if verified_doc.id.to_string() != hello_body.from_id {
                return Err(TunnelError::DocumentError(format!(
                    "hello from_id {} not match device_doc_jwt id {}",
                    hello_body.from_id,
                    verified_doc.id.to_string()
                )));
            }
            let default_key = verified_doc.get_default_key().ok_or_else(|| {
                TunnelError::DocumentError("device_doc_jwt missing default key".to_string())
            })?;
            let ed25519_pk = jwk_to_ed25519_pk(&default_key).map_err(|e| {
                TunnelError::DocumentError(format!("decode device_doc_jwt public key failed:{}", e))
            })?;
            let from_public_key = DecodingKey::from_ed_der(&ed25519_pk);
            return Ok((
                verified_doc.id.to_string(),
                Some(RTcpSourceDeviceInfo {
                    device_doc_jwt: Some(device_doc_jwt.clone()),
                    name: Some(verified_doc.name.clone()),
                    owner: Some(verified_doc.owner.to_string()),
                    zone_did: verified_doc.zone_did.map(|did| did.to_string()),
                }),
                from_public_key,
            ));
        }

        let from_did = DID::from_str(hello_body.from_id.as_str()).map_err(|_e| {
            TunnelError::DocumentError("invalid from device is not did".to_string())
        })?;
        let ed25519_pk = resolve_ed25519_exchange_key(&from_did)
            .await
            .map_err(|op| {
                TunnelError::DocumentError(format!(
                    "cann't resolve from device {} auth key:{}",
                    hello_body.from_id.as_str(),
                    op
                ))
            })?;
        let from_public_key = DecodingKey::from_ed_der(&ed25519_pk);
        Ok((hello_body.from_id.clone(), None, from_public_key))
    }

    // v2 session-key derivation. Replaces the old SHA256(shared_secret)
    // construction with a real HKDF-Extract+Expand and binds the output
    // to the full handshake context, including:
    //   - protocol identifier ("buckyos-rtcp-v2") for domain separation,
    //     so the same Ed25519/X25519 keys can be safely reused by a future
    //     non-RTCP protocol without producing a colliding key.
    //   - both DIDs, both ephemeral public keys, and both nonces, so
    //     mismatched / replayed ack tokens that somehow pass signature
    //     checks still produce a key the peer cannot reproduce.
    //
    // Two independent keys are expanded from the same PRK -- the AES key
    // and the IV salt -- so the IV is no longer derived from a public key
    // prefix (the old construction was vulnerable to nonce-reuse if the
    // initiator's RNG ever produced a colliding ephemeral, since the same
    // ephemeral controlled both the key and the IV).
    fn derive_session_secrets(
        my_secret: EphemeralSecret,
        peer_pub_bytes: [u8; 32],
        initiator_did: &str,
        responder_did: &str,
        initiator_xpub_hex: &str,
        responder_xpub_hex: &str,
        initiator_nonce: &str,
        responder_nonce: &str,
    ) -> ([u8; 32], [u8; 16]) {
        let peer_pub = x25519_dalek::PublicKey::from(peer_pub_bytes);
        let shared = my_secret.diffie_hellman(&peer_pub);
        let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());

        let info_tail = [
            b"|",
            initiator_did.as_bytes(),
            b"|",
            responder_did.as_bytes(),
            b"|",
            initiator_xpub_hex.as_bytes(),
            b"|",
            responder_xpub_hex.as_bytes(),
            b"|",
            initiator_nonce.as_bytes(),
            b"|",
            responder_nonce.as_bytes(),
        ]
        .concat();

        let mut aes_key = [0u8; 32];
        let mut aes_info = b"buckyos-rtcp-v2 aes256-key".to_vec();
        aes_info.extend_from_slice(&info_tail);
        hk.expand(&aes_info, &mut aes_key)
            .expect("HKDF expand for aes256-key must succeed for 32-byte output");

        let mut iv = [0u8; 16];
        let mut iv_info = b"buckyos-rtcp-v2 iv-salt".to_vec();
        iv_info.extend_from_slice(&info_tail);
        hk.expand(&iv_info, &mut iv)
            .expect("HKDF expand for iv-salt must succeed for 16-byte output");

        (aes_key, iv)
    }

    pub async fn start(self: &Arc<Self>) -> TunnelResult<JoinHandle<()>> {
        let addr: SocketAddr = self.bind_addr.parse().map_err(|e| {
            let msg = format!("invalid bind address {}: {}", self.bind_addr, e);
            error!("{}", msg);
            TunnelError::BindError(msg)
        })?;
        let sockaddr: socket2::SockAddr = addr.into();
        let domain = match addr {
            std::net::SocketAddr::V4(_) => socket2::Domain::IPV4,
            std::net::SocketAddr::V6(_) => socket2::Domain::IPV6,
        };
        let socket =
            socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))
                .map_err(|e| {
                    let msg = format!("create socket error:{}", e);
                    error!("{}", msg);
                    TunnelError::BindError(msg)
                })?;
        socket.set_nonblocking(true).map_err(|e| {
            let msg = format!("set nonblocking error:{}", e);
            error!("{}", msg);
            TunnelError::BindError(msg)
        })?;
        #[cfg(target_os = "linux")]
        {
            if self.reuse_address {
                socket.set_reuse_address(true).map_err(|e| {
                    let msg = format!("set reuse address error:{}", e);
                    error!("{}", msg);
                    TunnelError::BindError(msg)
                })?;
            }
        }
        socket.bind(&sockaddr).map_err(|e| {
            let msg = format!("bind rtcp listener error:{}", e);
            error!("{}", msg);
            TunnelError::BindError(msg)
        })?;
        socket.listen(1024).map_err(|e| {
            let msg = format!("listen rtcp listener error:{}", e);
            error!("{}", msg);
            TunnelError::BindError(msg)
        })?;
        #[cfg(unix)]
        let std_listener = unsafe { std::net::TcpListener::from_raw_fd(socket.into_raw_fd()) };
        #[cfg(windows)]
        let std_listener =
            unsafe { std::net::TcpListener::from_raw_socket(socket.into_raw_socket()) };
        let rtcp_listener = TcpListener::from_std(std_listener).map_err(|e| {
            let msg = format!("bind rtcp listener error:{}", e);
            error!("{}", msg);
            TunnelError::BindError(msg)
        })?;

        info!(
            "RTcp stack {} start ok: {}",
            self.this_device_did.to_string(),
            self.bind_addr
        );

        let this = self.clone();
        let handle = task::spawn(async move {
            loop {
                let (stream, addr) = rtcp_listener.accept().await.unwrap();
                debug!("RTcp stack accept new tcp stream from {}", addr.clone());

                let this = this.clone();
                task::spawn(async move {
                    this.serve_connection(stream, addr).await;
                });
            }
        });

        Ok(handle)
    }

    pub async fn serve_connection(&self, mut stream: TcpStream, addr: SocketAddr) {
        let source_info = addr.to_string();
        let first_package =
            RTcpTunnelPackage::read_package(Pin::new(&mut stream), true, source_info.as_str())
                .await;
        if first_package.is_err() {
            error!(
                "Read first package error: {}, {}",
                addr,
                first_package.err().unwrap()
            );
            return;
        }

        debug!(
            "RTcp stream {} read first package ok",
            self.this_device_did.to_string()
        );
        let package = first_package.unwrap();
        match package {
            RTcpTunnelPackage::HelloStream(session_key) => {
                debug!(
                    "RTcp stack {} accept new stream: {}, {}",
                    self.this_device_did.to_string(),
                    addr,
                    session_key
                );
                self.on_new_stream(stream, session_key).await;
            }
            RTcpTunnelPackage::Hello(hello_package) => {
                debug!(
                    "RTcp stack {} accept new tunnel: {}, {} -> {}",
                    self.this_device_did.to_string(),
                    addr,
                    hello_package.body.from_id,
                    hello_package.body.to_id
                );

                self.on_new_tunnel(stream, hello_package).await;
            }
            _ => {
                error!("Unsupported first package type for rtcp stack: {}", addr);
            }
        }
    }

    async fn on_new_stream(&self, stream: TcpStream, session_key: String) {
        // find waiting ropen stream by session_key
        let real_key = format!(
            "{}_{}",
            self.this_device_did.to_string(),
            session_key.as_str()
        );

        self.stream_helper
            .notify_ropen_stream(stream, real_key.as_str())
            .await;
    }

    async fn on_new_tunnel(&self, stream: TcpStream, hello_package: RTcpHelloPackage) {
        let source_addr = match stream.peer_addr() {
            Ok(addr) => Some(addr),
            Err(e) => {
                warn!("get tunnel peer addr before validation failed: {}", e);
                None
            }
        };
        let source_addr_log = source_addr
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "<unknown>".to_string());

        if hello_package.body.tunnel_token.is_none() {
            warn!(
                "reject rtcp tunnel from {}: hello.body.tunnel_token is none",
                source_addr_log
            );
            return;
        }
        let source_device = RTcpInner::resolve_source_device_info(&hello_package.body).await;
        if source_device.is_err() {
            warn!(
                "reject rtcp tunnel from {}: resolve source device info error:{}",
                source_addr_log,
                source_device.err().unwrap()
            );
            return;
        }
        let (source_device_id, source_device_info, source_public_key) = source_device.unwrap();
        let token = hello_package.body.tunnel_token.as_ref().unwrap().clone();
        let source_did = match DID::from_str(source_device_id.as_str()) {
            Ok(did) => did,
            Err(e) => {
                warn!(
                    "reject rtcp tunnel from {} {}: parser remote did error:{}",
                    source_device_id, source_addr_log, e
                );
                return;
            }
        };
        let (initiator_xpub_bytes, hello_payload) = match RTcpInner::verify_hello_token(
            &token,
            &source_public_key,
            Some(source_did.to_host_name().as_str()),
        ) {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    "reject rtcp tunnel from {} {}: verify hello token error:{}",
                    source_device_id, source_addr_log, e
                );
                return;
            }
        };

        // §14.2 anti-replay: every Hello token must bind this responder
        // and must not be replayed within its exp window.
        let this_host = self.this_device_did.to_host_name();
        if let Err(e) = Self::validate_hello_target(&hello_payload.to, &this_host).await {
            warn!(
                "reject rtcp tunnel from {} {}: token.to {} not accepted for this device {}: {}",
                source_device_id, source_addr_log, hello_payload.to, this_host, e
            );
            return;
        }
        let now_ts = buckyos_get_unix_timestamp();
        // Retain the nonce for the FULL signature-acceptance window, not
        // just until `exp`. jsonwebtoken accepts a token up to
        // `exp + JWT_LEEWAY_SECS`, so if we only kept the nonce until
        // `exp`, a replay captured within that leeway would pass
        // signature validation *and* find a freshly-evicted slot --
        // defeating the anti-replay guarantee. See regression test
        // nonce_cache_retains_entry_past_exp_within_leeway.
        let retain_until = hello_payload.exp.saturating_add(JWT_LEEWAY_SECS);
        let fresh = self
            .nonce_cache
            .insert_if_fresh(
                &source_device_id,
                &hello_payload.nonce,
                retain_until,
                now_ts,
            )
            .await;
        if !fresh {
            warn!(
                "reject rtcp tunnel from {} {}: replayed Hello nonce {}",
                source_device_id, source_addr_log, hello_payload.nonce
            );
            return;
        }

        let source_addr = match source_addr {
            Some(addr) => addr,
            None => {
                warn!(
                    "reject rtcp tunnel from {}: peer addr unavailable",
                    source_device_id
                );
                return;
            }
        };

        let remote_stack = RTcpTargetStackEP::new(source_did, hello_package.body.my_port);
        if remote_stack.is_err() {
            error!("parser remote did error:{}", remote_stack.err().unwrap());
            return;
        }
        let remote_stack = remote_stack.unwrap();

        // v2 §14.2: generate a fresh ephemeral X25519 keypair, sign an
        // ack JWT binding it to the initiator's xpub, ship HelloAck in
        // the clear, then derive (aes_key, iv) from ECDH(my_eph,
        // peer_eph) via HKDF and wrap the stream. Only after the AEAD-
        // protected HelloAckConfirm is verified do we admit the tunnel.
        //
        // hello_payload.from is the JWT-verified host-name form; using
        // it (rather than the raw `did:dev:...` form returned by
        // resolve_source_device_info) keeps the ack token's `to` field
        // aligned with what the initiator will check against its own
        // host_name.
        let initiator_hostname = hello_payload.from.clone();
        let ack_state = match self
            .generate_ack_token(initiator_hostname.as_str(), &hello_payload.xpub)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    "reject rtcp tunnel from {} {}: generate ack token error:{}",
                    source_device_id, source_addr, e
                );
                return;
            }
        };
        let (ack_token, my_secret, my_xpub_bytes, my_nonce_hex) = ack_state;
        let my_xpub_hex: String = my_xpub_bytes.encode_hex();

        let mut challenge_bytes = [0u8; 16];
        rand::thread_rng().fill(&mut challenge_bytes);
        let challenge_hex: String = challenge_bytes.encode_hex();

        let mut bearing: RTcpBearingStream = Box::new(stream);
        let ack_pkg =
            RTcpHelloAckPackage::new(0, ack_token, challenge_hex.clone(), this_host.clone());
        if let Err(e) = timeout(
            HELLO_HANDSHAKE_TIMEOUT,
            RTcpTunnelPackage::send_package(Pin::new(&mut bearing), ack_pkg),
        )
        .await
        .map_err(|_| TunnelError::ReasonError("HelloAck send timed out".to_string()))
        .and_then(|r| {
            r.map_err(|e| TunnelError::ReasonError(format!("HelloAck send error: {}", e)))
        }) {
            warn!(
                "reject rtcp tunnel from {} {}: {}",
                source_device_id, source_addr, e
            );
            return;
        }

        let (aes_key, iv) = RTcpInner::derive_session_secrets(
            my_secret,
            initiator_xpub_bytes,
            &initiator_hostname,
            &this_host,
            &hello_payload.xpub,
            &my_xpub_hex,
            &hello_payload.nonce,
            &my_nonce_hex,
        );
        let mut encrypted_stream =
            EncryptedStream::new(bearing, &aes_key, &iv, EncryptionRole::Responder);

        if let Err(e) = responder_key_confirmation(&mut encrypted_stream, &challenge_hex).await {
            warn!(
                "reject rtcp tunnel from {} {}: key confirmation failed: {}",
                source_device_id, source_addr, e
            );
            return;
        }

        let endpoint = TunnelEndpoint {
            device_id: source_device_id.clone(),
            port: hello_package.body.my_port,
        };
        if let Err(e) = self
            .listener
            .on_new_tunnel(endpoint.clone(), source_addr, source_device_info)
            .await
        {
            warn!(
                "reject rtcp tunnel from {} {}: {}",
                endpoint.device_id, source_addr, e
            );
            return;
        }

        let tunnel = RTcpTunnel::new(
            self.stream_helper.clone(),
            self.this_device_did.clone(),
            &remote_stack,
            false,
            encrypted_stream,
            Some(source_addr),
            None,
            aes_key,
            self.listener.clone(),
        );

        //TODO:这里是否应该归一化成，必须使用devcie公钥来做key？
        let tunnel_key = format!(
            "{}_{}",
            self.this_device_did.to_string(),
            source_device_id.as_str()
        );
        {
            //info!("accept tunnel from {} try get lock",hello_package.body.from_id.as_str());
            if self
                .tunnel_map
                .on_new_tunnel(&tunnel_key, tunnel.clone())
                .await
                .is_err()
            {
                // Duplicate tunnel key: a live tunnel already holds this
                // (aes_key, iv) space. Drop the just-built tunnel rather
                // than racing it against the live one. Shutting it down
                // here also sends a FIN to the replayer/peer so they see
                // the rejection promptly.
                tunnel.close().await;
                return;
            }
            // info!("Accept tunnel from {}", hello_package.body.from_id.as_str());
        }

        info!(
            "Tunnel {} accept from {} OK,start running",
            source_device_id.as_str(),
            tunnel_key.as_str()
        );
        tunnel.run().await;

        info!("Tunnel {} end", tunnel_key.as_str());

        self.tunnel_map.remove_tunnel(&tunnel_key).await;
    }

    pub async fn create_tunnel(
        &self,
        tunnel_stack_id: Option<&str>,
    ) -> TunnelResult<Box<dyn TunnelBox>> {
        // lookup existing tunnel and resue it
        if tunnel_stack_id.is_none() {
            return Err(TunnelError::ReasonError(
                "rtcp remote stack id is none".to_string(),
            ));
        }
        let tunnel_stack_id = tunnel_stack_id.unwrap();
        let remote_stack = parse_rtcp_stack_id(tunnel_stack_id);
        if remote_stack.is_none() {
            return Err(TunnelError::ConnectError(format!(
                "invalid remote stack id:{:?}",
                remote_stack
            )));
        }
        let remote_stack: RTcpTargetStackEP = remote_stack.unwrap();
        let remote_device_id = remote_stack.did.to_string();

        // Bootstrap-backed tunnels must NOT collide with direct ones (or with
        // each other across different bootstrap transports), or routing,
        // credentials and isolation semantics from one bootstrap path could
        // bleed into another reusing the same remote did. Tag the reuse key
        // with the bootstrap URL when present.
        let tunnel_key = match remote_stack.bootstrap_stream_url.as_ref() {
            Some(bootstrap_url) => format!(
                "{}_{}|bootstrap={}",
                self.this_device_did.to_string(),
                remote_device_id.as_str(),
                bootstrap_url
            ),
            None => format!(
                "{}_{}",
                self.this_device_did.to_string(),
                remote_device_id.as_str()
            ),
        };
        debug!(
            "will create tunnel to {} ,tunnel key is {},try reuse",
            remote_device_id.as_str(),
            tunnel_key.as_str()
        );

        // First check if the tunnel already exists, then we can reuse it
        let tunnels = self.tunnel_map.tunnel_map().clone();
        let all_tunnel = tunnels.lock().await;
        let tunnel = all_tunnel.get(tunnel_key.as_str());
        if tunnel.is_some() {
            debug!("Reuse tunnel {}", tunnel_key.as_str());
            return Ok(Box::new(tunnel.unwrap().clone()));
        }
        drop(all_tunnel);

        // `params@remote` bootstrap: build the tunnel's bearing stream through
        // the tunnel framework instead of opening a direct TCP connection.
        if let Some(bootstrap_url) = remote_stack.bootstrap_stream_url.as_ref() {
            let tunnel_manager = self.tunnel_manager.clone().ok_or_else(|| {
                TunnelError::ReasonError(
                    "rtcp bootstrap URL present but tunnel_manager is not set".to_string(),
                )
            })?;
            let bootstrap_url_parsed = Url::parse(bootstrap_url).map_err(|e| {
                TunnelError::ReasonError(format!(
                    "invalid bootstrap stream url '{}': {}",
                    bootstrap_url, e
                ))
            })?;

            let bearing = tunnel_manager
                .open_stream_by_url(&bootstrap_url_parsed)
                .await
                .map_err(|e| {
                    let msg = format!(
                        "open bootstrap stream '{}' for {} failed: {}",
                        bootstrap_url, remote_device_id, e
                    );
                    error!("{}", msg);
                    TunnelError::ConnectError(msg)
                })?;

            let state = self
                .generate_tunnel_token(remote_device_id.clone())
                .await
                .map_err(|e| {
                    let msg = format!("generate tunnel token error: {}, {}", remote_device_id, e);
                    error!("{}", msg);
                    e
                })?;
            let initiator_did = self.this_device_did.to_host_name();

            let addr: SocketAddr = self.bind_addr.parse().unwrap();
            let hello_package = RTcpHelloPackage::new(
                0,
                self.this_device_did.to_string(),
                remote_device_id.clone(),
                addr.port(),
                Some(state.token.clone()),
                self.this_device_doc_jwt.clone(),
            );

            let mut bearing: RTcpBearingStream = bearing;
            RTcpTunnelPackage::send_package(Pin::new(&mut bearing), hello_package)
                .await
                .map_err(|e| {
                    let msg = format!(
                        "send hello over bootstrap stream '{}' for {} failed: {}",
                        bootstrap_url, remote_device_id, e
                    );
                    error!("{}", msg);
                    TunnelError::ConnectError(msg)
                })?;

            // v2 §14.2 key confirmation: read plaintext HelloAck off the
            // bearing, verify the responder's signed ack_token, derive
            // session keys, wrap, and ship the AEAD-protected confirm
            // before the tunnel is registered. A responder that didn't
            // actually derive the same AES key (or a MitM splicing in a
            // stale ack) is dropped here before any user traffic flows.
            let (encrypted_stream, aes_key) =
                initiator_complete_handshake(bearing, state, &initiator_did)
                    .await
                    .map_err(|e| {
                        let msg = format!(
                            "key confirmation over bootstrap stream '{}' for {} failed: {}",
                            bootstrap_url, remote_device_id, e
                        );
                        error!("{}", msg);
                        TunnelError::ConnectError(msg)
                    })?;

            // peer_addr is None for bootstrap-backed tunnels. Instead, we hand
            // the tunnel a bootstrap context so that subsequent Open/ROpen
            // reconnects replay the same nested transport via the tunnel
            // framework (see section 14.5 of doc/rtcp.md).
            let bootstrap_ctx = RTcpBootstrapCtx {
                url: bootstrap_url_parsed,
                tunnel_manager: tunnel_manager.clone(),
            };
            let tunnel = RTcpTunnel::new(
                self.stream_helper.clone(),
                self.this_device_did.clone(),
                &remote_stack,
                true,
                encrypted_stream,
                None,
                Some(bootstrap_ctx),
                aes_key,
                self.listener.clone(),
            );
            let mut all_tunnel = tunnels.lock().await;
            if let Some(existing) = all_tunnel.get(tunnel_key.as_str()).cloned() {
                debug!(
                    "Reuse tunnel {} after bootstrap build raced with another creator",
                    tunnel_key.as_str()
                );
                drop(all_tunnel);
                tunnel.close().await;
                return Ok(Box::new(existing));
            }
            all_tunnel.insert(tunnel_key.clone(), tunnel.clone());
            info!(
                "create tunnel {} ok via bootstrap url {}",
                tunnel_key.as_str(),
                bootstrap_url
            );
            drop(all_tunnel);

            let result: TunnelResult<Box<dyn TunnelBox>> = Ok(Box::new(tunnel.clone()));
            let tunnel_map = self.tunnel_map.clone();
            task::spawn(async move {
                debug!(
                    "RTcp tunnel {} established (bootstrap), tunnel running",
                    tunnel_key.as_str()
                );
                tunnel.run().await;
                tunnel_map.remove_tunnel(&tunnel_key).await;
                info!("RTcp tunnel {} end", tunnel_key.as_str());
            });

            return result;
        }

        // 1） resolve remote ip list. name_client::resolve_ips already applies
        // address ordering based on its RFC 8305 / addr-rtt policy.
        let resolve_name = remote_stack.did.to_string();
        debug!(
            "resolve remote device {} ips by {}",
            remote_device_id, resolve_name
        );

        let candidate_ips = match resolve_ips(resolve_name.as_str()).await {
            Ok(ips) if !ips.is_empty() => ips,
            Ok(_) => {
                let msg = format!(
                    "cann't resolve remote device {} ip by {}: empty address list",
                    remote_device_id, resolve_name
                );
                error!("{}", msg);
                return Err(TunnelError::DocumentError(msg));
            }
            Err(err) => {
                let msg = format!(
                    "cann't resolve remote device {} ip by {}: {}",
                    remote_device_id, resolve_name, err
                );
                error!("{}", msg);
                return Err(TunnelError::DocumentError(msg));
            }
        };

        let port = remote_stack.stack_port;
        let candidate_addrs: Vec<SocketAddr> = candidate_ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect();
        let mut connect_errors = Vec::new();

        let mut attempts = FuturesUnordered::new();
        let mut next_addr_index = 0usize;
        if let Some(remote_addr) = candidate_addrs.get(next_addr_index).copied() {
            attempts.push(self.create_direct_tunnel_attempt(
                &remote_stack,
                remote_device_id.as_str(),
                remote_addr,
            ));
            next_addr_index += 1;
        }

        while !attempts.is_empty() || next_addr_index < candidate_addrs.len() {
            let attempt_result = if next_addr_index < candidate_addrs.len() {
                tokio::select! {
                    result = attempts.next(), if !attempts.is_empty() => result,
                    _ = tokio::time::sleep(DIRECT_CONNECT_ATTEMPT_DELAY) => {
                        let remote_addr = candidate_addrs[next_addr_index];
                        attempts.push(self.create_direct_tunnel_attempt(
                            &remote_stack,
                            remote_device_id.as_str(),
                            remote_addr,
                        ));
                        next_addr_index += 1;
                        continue;
                    }
                }
            } else {
                attempts.next().await
            };

            match attempt_result {
                Some(Ok(attempt)) => {
                    let tunnel = attempt.tunnel;
                    let mut all_tunnel = tunnels.lock().await;
                    if let Some(existing) = all_tunnel.get(tunnel_key.as_str()).cloned() {
                        debug!(
                            "Reuse tunnel {} after direct build raced with another creator",
                            tunnel_key.as_str()
                        );
                        drop(all_tunnel);
                        tunnel.close().await;
                        return Ok(Box::new(existing));
                    }
                    all_tunnel.insert(tunnel_key.clone(), tunnel.clone());
                    info!(
                        "create tunnel {} ok, remote addr is {}",
                        tunnel_key.as_str(),
                        attempt.remote_addr
                    );
                    drop(all_tunnel);

                    let result: TunnelResult<Box<dyn TunnelBox>> = Ok(Box::new(tunnel.clone()));
                    let tunnel_map = self.tunnel_map.clone();
                    task::spawn(async move {
                        debug!(
                            "RTcp tunnel {} established, tunnel running",
                            tunnel_key.as_str()
                        );
                        tunnel.run().await;

                        // remove tunnel from manager
                        tunnel_map.remove_tunnel(&tunnel_key).await;

                        info!("RTcp tunnel {} end", tunnel_key.as_str());
                    });

                    return result;
                }
                Some(Err(err)) => connect_errors.push(err),
                None => {}
            }
        }

        Err(TunnelError::ConnectError(format!(
            "connect to remote {} failed after trying all candidates: {}",
            remote_device_id,
            connect_errors.join("; ")
        )))
    }

    fn compute_tunnel_key(&self, remote_stack: &RTcpTargetStackEP) -> String {
        match remote_stack.bootstrap_stream_url.as_ref() {
            Some(bootstrap_url) => format!(
                "{}_{}|bootstrap={}",
                self.this_device_did.to_string(),
                remote_stack.did.to_string(),
                bootstrap_url
            ),
            None => format!(
                "{}_{}",
                self.this_device_did.to_string(),
                remote_stack.did.to_string()
            ),
        }
    }

    pub async fn probe_url(
        &self,
        url: &Url,
        options: &TunnelProbeOptions,
    ) -> TunnelResult<TunnelUrlStatus> {
        let normalized = normalize_tunnel_url(url);
        let now = crate::tunnel_mgr::now_ms();
        let stack_id = url.authority();
        if stack_id.is_empty() {
            return Ok(unreachable_status(
                url,
                &normalized,
                now,
                TunnelUrlStatusSource::FreshProbe,
                "rtcp url has no remote stack id".to_string(),
            ));
        }
        let remote_stack = match parse_rtcp_stack_id(stack_id) {
            Some(s) => s,
            None => {
                return Ok(unreachable_status(
                    url,
                    &normalized,
                    now,
                    TunnelUrlStatusSource::FreshProbe,
                    format!("invalid rtcp stack id '{}'", stack_id),
                ));
            }
        };
        let tunnel_key = self.compute_tunnel_key(&remote_stack);
        let timeout_dur = Duration::from_millis(options.timeout_ms_or_default());

        // 1. Existing tunnel: ping it (force_probe just bypasses the
        //    manager-level cache freshness check; we still ping the same
        //    tunnel rather than building a second one).
        if let Some(tunnel) = self.tunnel_map.get_tunnel(&tunnel_key).await {
            if !tunnel.is_closed() {
                match tunnel.ping_rtt(timeout_dur).await {
                    Ok(d) => {
                        let mut s = reachable_status(
                            url,
                            &normalized,
                            now,
                            TunnelUrlStatusSource::ExistingTunnel,
                            Some(d.as_millis() as u64),
                        );
                        s.runtime_tunnel_key = Some(tunnel_key);
                        return Ok(s);
                    }
                    Err(e) => {
                        let mut s = unreachable_status(
                            url,
                            &normalized,
                            now,
                            TunnelUrlStatusSource::ExistingTunnel,
                            format!("ping_rtt: {}", e),
                        );
                        s.runtime_tunnel_key = Some(tunnel_key);
                        return Ok(s);
                    }
                }
            }
        }

        // 2. No existing tunnel: try to build one and ping it.
        match self.create_tunnel(Some(stack_id)).await {
            Ok(_tunnel_box) => {
                // Tunnel-instance presence alone is not proof of reachability:
                // the requirement (§9.3) demands a ping/pong-confirmed RTT
                // before we mark the URL Reachable. Build-then-ping fail
                // must surface as Unreachable with the ping reason.
                let tunnel = match self.tunnel_map.get_tunnel(&tunnel_key).await {
                    Some(t) => t,
                    None => {
                        let mut s = unreachable_status(
                            url,
                            &normalized,
                            now,
                            TunnelUrlStatusSource::FreshProbe,
                            "tunnel created but not registered in tunnel_map".to_string(),
                        );
                        s.runtime_tunnel_key = Some(tunnel_key);
                        return Ok(s);
                    }
                };
                match tunnel.ping_rtt(timeout_dur).await {
                    Ok(d) => {
                        let mut s = reachable_status(
                            url,
                            &normalized,
                            now,
                            TunnelUrlStatusSource::FreshProbe,
                            Some(d.as_millis() as u64),
                        );
                        s.runtime_tunnel_key = Some(tunnel_key);
                        Ok(s)
                    }
                    Err(e) => {
                        let mut s = unreachable_status(
                            url,
                            &normalized,
                            now,
                            TunnelUrlStatusSource::FreshProbe,
                            format!("ping_rtt after create: {}", e),
                        );
                        s.runtime_tunnel_key = Some(tunnel_key);
                        Ok(s)
                    }
                }
            }
            Err(e) => {
                let mut s = unreachable_status(
                    url,
                    &normalized,
                    now,
                    TunnelUrlStatusSource::FreshProbe,
                    format!("create_tunnel: {}", e),
                );
                s.runtime_tunnel_key = Some(tunnel_key);
                Ok(s)
            }
        }
    }
}

#[derive(Debug)]
enum InitiatorKeyConfirmationError {
    Timeout(TunnelError),
    Failed(TunnelError),
}

impl InitiatorKeyConfirmationError {
    fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout(_))
    }

    fn as_tunnel_error(&self) -> &TunnelError {
        match self {
            Self::Timeout(e) | Self::Failed(e) => e,
        }
    }
}

impl fmt::Display for InitiatorKeyConfirmationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_tunnel_error())
    }
}

// v2 §14.2 initiator-side handshake completion.
//
// Runs after the initiator has sent the plaintext Hello. Reads HelloAck
// in the clear off the still-unwrapped bearing stream, verifies the
// responder's signed ack_token (audience tag, identity, and the
// `peer_xpub` binding to *this* initiator's ephemeral key), derives the
// session keys via HKDF, wraps the stream, and then sends an AEAD-
// protected HelloAckConfirm echoing the challenge.
//
// On success returns the wrapped EncryptedStream and the AES key.
async fn initiator_complete_handshake(
    bearing: RTcpBearingStream,
    state: InitiatorHandshakeState,
    initiator_did: &str,
) -> Result<(EncryptedStream<RTcpBearingStream>, [u8; 32]), InitiatorKeyConfirmationError> {
    let mut bearing = bearing;

    let pkg = timeout(
        HELLO_HANDSHAKE_TIMEOUT,
        RTcpTunnelPackage::read_package(Pin::new(&mut bearing), false, "hello_ack"),
    )
    .await
    .map_err(|_| {
        InitiatorKeyConfirmationError::Timeout(TunnelError::ReasonError(
            "HelloAck read timed out; peer did not complete v2 handshake".to_string(),
        ))
    })?
    .map_err(|e| {
        let detail = if e.kind() == ErrorKind::UnexpectedEof {
            format!(
                "{}; peer closed before sending HelloAck, likely because it rejected the Hello or uses an incompatible RTCP handshake",
                e
            )
        } else {
            e.to_string()
        };
        InitiatorKeyConfirmationError::Failed(TunnelError::ReasonError(format!(
            "HelloAck read error: {}",
            detail
        )))
    })?;

    let ack = match pkg {
        RTcpTunnelPackage::HelloAck(p) => p,
        other => {
            return Err(InitiatorKeyConfirmationError::Failed(
                TunnelError::ReasonError(format!("expected HelloAck, got {:?}", other)),
            ));
        }
    };

    // Cross-check: the responder's self-reported id must match the
    // `to` we signed into the tunnel token. A mismatch here would
    // indicate either a misconfigured peer or a MitM trying to stand
    // up a tunnel under a different identity than we asked for.
    if ack.body.responder_id != state.responder_did {
        return Err(InitiatorKeyConfirmationError::Failed(
            TunnelError::ReasonError(format!(
                "HelloAck responder_id {} not equal to expected {}",
                ack.body.responder_id, state.responder_did
            )),
        ));
    }

    // Verify the responder's signed ack_token. This is what binds the
    // responder's ephemeral X25519 public key to its long-term Ed25519
    // identity (the only key the initiator could have looked up before
    // the handshake started).
    let responder_pk = DecodingKey::from_ed_der(&state.responder_ed25519_pk_der);
    let (responder_xpub_bytes, ack_payload) = RTcpInner::verify_ack_token(
        &ack.body.ack_token,
        &responder_pk,
        &state.responder_did,
        initiator_did,
        &state.my_xpub_hex,
    )
    .map_err(|e| InitiatorKeyConfirmationError::Failed(e))?;

    let responder_xpub_hex: String = responder_xpub_bytes.encode_hex();

    let (aes_key, iv) = RTcpInner::derive_session_secrets(
        state.my_secret,
        responder_xpub_bytes,
        initiator_did,
        &state.responder_did,
        &state.my_xpub_hex,
        &responder_xpub_hex,
        &state.my_nonce_hex,
        &ack_payload.nonce,
    );
    let mut encrypted_stream =
        EncryptedStream::new(bearing, &aes_key, &iv, EncryptionRole::Initiator);

    let confirm = RTcpHelloAckConfirmPackage::new(ack.seq, ack.body.challenge.clone());
    timeout(
        HELLO_HANDSHAKE_TIMEOUT,
        RTcpTunnelPackage::send_package(Pin::new(&mut encrypted_stream), confirm),
    )
    .await
    .map_err(|_| {
        InitiatorKeyConfirmationError::Timeout(TunnelError::ReasonError(
            "HelloAckConfirm send timed out".to_string(),
        ))
    })?
    .map_err(|e| {
        InitiatorKeyConfirmationError::Failed(TunnelError::ReasonError(format!(
            "HelloAckConfirm send error: {}",
            e
        )))
    })?;

    Ok((encrypted_stream, aes_key))
}

// v2 §14.2 responder-side key confirmation, post-key-derivation.
//
// Runs after the responder has shipped HelloAck plaintext, derived the
// session keys, and wrapped the bearing stream. Reads HelloAckConfirm
// (an AEAD record) and rejects any echo that doesn't match the
// `expected_challenge` the responder sent in HelloAck. A peer without
// the right session key cannot decrypt the confirm record at all, let
// alone produce one with a matching echo.
async fn responder_key_confirmation(
    stream: &mut EncryptedStream<RTcpBearingStream>,
    expected_challenge: &str,
) -> Result<(), TunnelError> {
    let pkg = timeout(
        HELLO_HANDSHAKE_TIMEOUT,
        RTcpTunnelPackage::read_package(Pin::new(stream), false, "hello_ack_confirm"),
    )
    .await
    .map_err(|_| {
        TunnelError::ReasonError(
            "HelloAckConfirm read timed out; peer may be a replayer without the AEAD key"
                .to_string(),
        )
    })?
    .map_err(|e| TunnelError::ReasonError(format!("HelloAckConfirm read error: {}", e)))?;

    let confirm = match pkg {
        RTcpTunnelPackage::HelloAckConfirm(p) => p,
        other => {
            return Err(TunnelError::ReasonError(format!(
                "expected HelloAckConfirm, got {:?}",
                other
            )));
        }
    };
    if confirm.body.challenge_echo != expected_challenge {
        return Err(TunnelError::ReasonError(
            "HelloAckConfirm challenge_echo mismatch; key confirmation failed".to_string(),
        ));
    }

    Ok(())
}

// Per-tunnel cap on concurrent inbound stream establishments (Open packets
// waiting for the peer's HelloStream). Protocol-level quota: prevents a
// malicious or misbehaving peer from exhausting memory by initiating
// streams and never completing them.
const MAX_PENDING_INBOUND_OPENS: usize = 64;

// Alias for the RTCP tunnel bearing stream. It's a boxed trait object so the
// tunnel can be carried by either a direct TcpStream (the classic path) or by
// an arbitrary stream produced by the tunnel framework (the `params@remote`
// bootstrap path).
type RTcpBearingStream = Box<dyn AsyncStream>;

// Captures the ingredients needed to rebuild a new stream leg over the same
// nested transport that brought up the tunnel itself: the bootstrap URL
// (parsed once to avoid reparsing on every Open/ROpen) and the tunnel
// framework entry point used to materialize new streams from it.
#[derive(Clone)]
struct RTcpBootstrapCtx {
    url: Url,
    tunnel_manager: TunnelManager,
}

#[derive(Clone)]
struct RTcpTunnel {
    build_helper: RTcpStreamBuildHelper,
    remote_stack: RTcpTargetStackEP,
    can_direct: bool,
    // Direct reconnect target for tunnels carried by a direct TCP socket. None
    // when the tunnel was bootstrapped through a nested stream URL and the
    // bootstrap transport must be replayed instead of opening TCP to peer_addr.
    //
    // The inner address is mutated by build_reconnect_stream when a fresh
    // OpenStream successfully races to a different IP than the one that won
    // the original tunnel handshake. This is what gives every OpenStream a
    // chance to re-select among the device's currently advertised IPs (see
    // doc/arch/gateway/服务的多链路选择.md §6.5 / §17.1) instead of being
    // permanently locked to whichever IP the first race picked.
    peer_addr: Option<Arc<std::sync::Mutex<SocketAddr>>>,
    // When set, Open/ROpen reconnect paths build new stream legs via
    // `tunnel_manager.open_stream_by_url(bootstrap_stream_url)` instead of a
    // direct TCP connect. This is the transport rebinding mandated by
    // §14.5 of doc/rtcp.md: the same bootstrap that brought up the tunnel is
    // reused to bring up each subsequent business stream so nested-remote
    // tunnels keep working end-to-end.
    bootstrap: Option<RTcpBootstrapCtx>,
    this_device: DID,
    aes_key: [u8; 32],
    write_stream: Arc<Mutex<WriteHalf<EncryptedStream<RTcpBearingStream>>>>,
    read_stream: Arc<Mutex<ReadHalf<EncryptedStream<RTcpBearingStream>>>>,

    // Set by close() to force the run() loop to exit at the next read boundary
    // and to make any subsequent send_package fail quickly. This is what makes
    // a replaced / superseded tunnel actually stop using its (aes_key, nonce)
    // space, so a replayed Hello cannot run concurrently with the original.
    closed: Arc<AtomicBool>,

    next_seq: Arc<AtomicU32>,
    listener: RTcpListenerRef,

    // Use to deliver the OpenResp result code back to the open stream waiter.
    // The result code (0 = success, non-zero = rejection, e.g. quota
    // exhausted) must reach the initiator so it can fail fast instead of
    // optimistically connecting and producing a "late HelloStream" on the peer.
    open_resp_waiters: Arc<Mutex<HashMap<u32, oneshot::Sender<u32>>>>,

    // Same fail-fast channel for the ROpen path: a non-zero ROpenResp tells
    // the initiator that no HelloStream is coming, so it can drop its
    // wait-HelloStream slot immediately instead of stalling for the full
    // 30s STREAM_WAIT_TIMEOUT.
    ropen_resp_waiters: Arc<Mutex<HashMap<u32, oneshot::Sender<u32>>>>,

    // Per-tunnel concurrency quota for inbound Open requests.
    inbound_open_slots: Arc<Semaphore>,

    // Pong waiters for RTT-aware probes. `ping_rtt` registers a waiter
    // keyed by the ping seq before sending; when the matching Pong
    // arrives, `process_package` notifies the waiter. The classic
    // `ping()` path still uses seq 0 with no waiter, so its Pongs are
    // simply dropped here (preserving existing behaviour).
    pong_waiters: Arc<Mutex<HashMap<u32, oneshot::Sender<()>>>>,
}

impl RTcpTunnel {
    // The EncryptedStream wrapping happens in create_tunnel / on_new_tunnel
    // so the §14.2 key-confirmation handshake (HelloAck / HelloAckConfirm)
    // can run over AEAD records before the tunnel is published to the map.
    // The caller is therefore responsible for picking the correct
    // EncryptionRole when building `encrypted_stream`.
    pub fn new(
        build_helper: RTcpStreamBuildHelper,
        this_device: DID,
        remote_stack: &RTcpTargetStackEP,
        can_direct: bool,
        encrypted_stream: EncryptedStream<RTcpBearingStream>,
        peer_addr: Option<SocketAddr>,
        bootstrap: Option<RTcpBootstrapCtx>,
        aes_key: [u8; 32],
        listener: RTcpListenerRef,
    ) -> Self {
        let (read_stream, write_stream) = tokio::io::split(encrypted_stream);
        //let (read_stream,write_stream) =  tokio::io::split(stream);
        let this_remote_stack = remote_stack.clone();

        //this_remote_stack.stack_port = 0;
        let peer_addr = peer_addr.map(|addr| Arc::new(std::sync::Mutex::new(addr)));

        Self {
            build_helper,
            remote_stack: this_remote_stack,
            can_direct, //Considering the limit of port mapping, the default configuration is configured as "NoDirect" mode
            peer_addr,
            bootstrap,
            this_device: this_device,
            aes_key: aes_key,
            read_stream: Arc::new(Mutex::new(read_stream)),
            write_stream: Arc::new(Mutex::new(write_stream)),

            closed: Arc::new(AtomicBool::new(false)),
            next_seq: Arc::new(AtomicU32::new(0)),
            listener,
            open_resp_waiters: Arc::new(Mutex::new(HashMap::new())),
            ropen_resp_waiters: Arc::new(Mutex::new(HashMap::new())),
            inbound_open_slots: Arc::new(Semaphore::new(MAX_PENDING_INBOUND_OPENS)),
            pong_waiters: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn close(&self) {
        // Flag first so any in-flight send_package / process_package
        // observes the closed state. Then shut down the write half: this
        // prevents the superseded tunnel from ever producing another
        // authenticated record under the shared (aes_key, nonce_base) pair.
        //
        // Shutting down the write side also sends FIN to the peer; in
        // practice the read loop will then wake with UnexpectedEof and
        // exit via run()'s error branch. The `closed` flag is a belt-
        // and-suspenders check in case the read side is still readable.
        self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
        let mut ws = self.write_stream.lock().await;
        use tokio::io::AsyncWriteExt;
        let _ = Pin::new(&mut *ws).shutdown().await;
    }

    fn is_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn get_key(&self) -> &[u8; 32] {
        return &self.aes_key;
    }

    fn next_seq(&self) -> u32 {
        self.next_seq
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    async fn process_package(&self, package: RTcpTunnelPackage) -> Result<(), anyhow::Error> {
        match package {
            RTcpTunnelPackage::Ping(ping_package) => {
                //send pong
                let pong_package = RTcpPongPackage::new(ping_package.seq, 0);
                let mut write_stream = self.write_stream.lock().await;
                let write_stream = Pin::new(&mut *write_stream);
                let _ = RTcpTunnelPackage::send_package(write_stream, pong_package).await?;
                return Ok(());
            }
            RTcpTunnelPackage::ROpen(ropen_package) => self.on_ropen(ropen_package).await,
            RTcpTunnelPackage::ROpenResp(ropen_resp_package) => {
                // Deliver the result code to the post_ropen waiter. A
                // non-zero result tells the initiator no HelloStream is
                // coming, so it can release its wait-HelloStream slot
                // immediately instead of stalling for the full 30s timeout.
                let waiter = self
                    .ropen_resp_waiters
                    .lock()
                    .await
                    .remove(&ropen_resp_package.seq);
                if let Some(sender) = waiter {
                    let _ = sender.send(ropen_resp_package.body.result);
                }
                Ok(())
            }
            RTcpTunnelPackage::Open(open_package) => self.on_open(open_package).await,
            RTcpTunnelPackage::OpenResp(open_resp_package) => {
                // Deliver the result code to the open_stream waiter so it
                // can distinguish success (0) from rejection (non-zero).
                let waiter = self
                    .open_resp_waiters
                    .lock()
                    .await
                    .remove(&open_resp_package.seq);
                if let Some(sender) = waiter {
                    let _ = sender.send(open_resp_package.body.result);
                } else {
                    warn!(
                        "Tunnel open stream waiter not found: seq={}",
                        open_resp_package.seq
                    );
                }

                Ok(())
            }
            RTcpTunnelPackage::Pong(pong_package) => {
                // Deliver to a registered RTT waiter if one exists for this
                // seq. Pongs from the classic `ping()` (seq 0, no waiter)
                // simply drop here.
                if let Some(sender) = self.pong_waiters.lock().await.remove(&pong_package.seq) {
                    let _ = sender.send(());
                }
                Ok(())
            }
            pkg_type @ _ => {
                error!("Unsupport tunnel package type: {:?}", pkg_type);
                Ok(())
            }
        }
    }

    // Builds a fresh stream leg to the remote RTCP listener so the caller can
    // send a HelloStream on it. This is the single choke point for §14.5's
    // "rebind transport semantics after remote nesting": bootstrap-backed
    // tunnels replay their nested transport via the tunnel framework, while
    // direct tunnels keep the classic `TcpStream::connect(peer_addr)` fast
    // path. Returns (stream, remote_addr, local_addr). `remote_addr` and
    // `local_addr` are synthetic placeholders on the bootstrap path because
    // there is no single authoritative TCP peer for a nested transport.
    async fn build_reconnect_stream(
        &self,
    ) -> Result<(Box<dyn AsyncStream>, SocketAddr, SocketAddr), std::io::Error> {
        if let Some(bootstrap) = self.bootstrap.as_ref() {
            let stream = bootstrap
                .tunnel_manager
                .open_stream_by_url(&bootstrap.url)
                .await
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        format!(
                            "open bootstrap stream '{}' for rtcp reconnect failed: {}",
                            bootstrap.url, e
                        ),
                    )
                })?;
            // No meaningful TCP peer/local addrs exist for a nested-transport
            // stream; upstream uses these only for logging and endpoint tags.
            let placeholder = SocketAddr::from(([0, 0, 0, 0], 0));
            return Ok((stream, placeholder, placeholder));
        }

        let peer_addr_handle = self.peer_addr.as_ref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "rtcp tunnel has neither a direct peer address nor a bootstrap transport",
            )
        })?;

        // §6.5 of doc/arch/gateway/服务的多链路选择.md: every OpenStream is a
        // chance to re-select among the device's currently advertised IPs.
        // Re-resolve here so newly published IPs (e.g. a fresh DeviceInfo
        // upload) become reachable without tearing down the control tunnel,
        // and reorder so the previously-winning IP is tried first. The
        // resolve_ips lookup is cache-backed in name_client and degrades to
        // the cached `peer_addr` if it fails, so we never lose the fast path
        // when DNS hiccups.
        let last_addr = *peer_addr_handle.lock().unwrap();
        let candidates = self.collect_reconnect_candidates(last_addr).await;

        self.race_reconnect_candidates(peer_addr_handle, candidates)
            .await
    }

    // Build the ordered candidate list used by build_reconnect_stream.
    // Always returns at least the cached `last_addr` so that a DNS hiccup
    // can never strip the only known good path.
    async fn collect_reconnect_candidates(&self, last_addr: SocketAddr) -> Vec<SocketAddr> {
        let port = self.remote_stack.stack_port;
        let resolve_name = self.remote_stack.did.to_string();
        let resolved = match resolve_ips(resolve_name.as_str()).await {
            Ok(ips) => ips,
            Err(e) => {
                debug!(
                    "rtcp reconnect resolve_ips({}) failed: {} -- falling back to cached peer addr {}",
                    resolve_name, e, last_addr
                );
                Vec::new()
            }
        };

        let mut candidates: Vec<SocketAddr> = resolved
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect();

        // Last-successful IP must be tried first (§6.5: "后续 OpenStream
        // 优先尝试上一次成功 IP").
        if let Some(pos) = candidates.iter().position(|a| *a == last_addr) {
            if pos != 0 {
                candidates.remove(pos);
                candidates.insert(0, last_addr);
            }
        } else {
            candidates.insert(0, last_addr);
        }

        candidates
    }

    // Happy-Eyeballs across the candidate IP list with `DIRECT_CONNECT_ATTEMPT_DELAY`
    // (250ms) stagger. Updates the tunnel's tracked peer_addr to whichever
    // candidate wins, so the next OpenStream prefers it. Records per-IP
    // outcomes into the addr-rtt history so resolve_ips can rank future
    // candidates.
    async fn race_reconnect_candidates(
        &self,
        peer_addr_handle: &Arc<std::sync::Mutex<SocketAddr>>,
        candidates: Vec<SocketAddr>,
    ) -> Result<(Box<dyn AsyncStream>, SocketAddr, SocketAddr), std::io::Error> {
        if candidates.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "rtcp tunnel has no reconnect candidates",
            ));
        }

        let mut attempts = FuturesUnordered::new();
        let mut next_index = 0usize;
        let mut errors: Vec<String> = Vec::new();

        attempts.push(Self::connect_reconnect_addr(candidates[next_index]));
        next_index += 1;

        loop {
            let attempt_result = if next_index < candidates.len() {
                tokio::select! {
                    result = attempts.next(), if !attempts.is_empty() => result,
                    _ = tokio::time::sleep(DIRECT_CONNECT_ATTEMPT_DELAY) => {
                        attempts.push(Self::connect_reconnect_addr(candidates[next_index]));
                        next_index += 1;
                        continue;
                    }
                }
            } else if !attempts.is_empty() {
                attempts.next().await
            } else {
                None
            };

            match attempt_result {
                Some(Ok((tcp_stream, remote_addr, local_addr, rtt))) => {
                    Self::record_reconnect_outcome(
                        local_addr,
                        remote_addr,
                        ConnectionOutcome::Success {
                            rtt,
                            layer: MeasurementLayer::Tcp,
                        },
                    );
                    if let Ok(mut slot) = peer_addr_handle.lock() {
                        *slot = remote_addr;
                    }
                    return Ok((
                        Box::new(tcp_stream) as Box<dyn AsyncStream>,
                        remote_addr,
                        local_addr,
                    ));
                }
                Some(Err((addr, err))) => {
                    errors.push(format!("{} => {}", addr, err));
                }
                None => break,
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!(
                "rtcp reconnect to {} failed after trying all candidates: {}",
                self.remote_stack.did.to_string(),
                errors.join("; ")
            ),
        ))
    }

    async fn connect_reconnect_addr(
        addr: SocketAddr,
    ) -> Result<(TcpStream, SocketAddr, SocketAddr, Duration), (SocketAddr, std::io::Error)> {
        let started_at = Instant::now();
        let connect_result = timeout(DIRECT_TCP_CONNECT_TIMEOUT, TcpStream::connect(addr)).await;
        let tcp_stream = match connect_result {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                let outcome = match e.kind() {
                    std::io::ErrorKind::ConnectionRefused => ConnectionOutcome::Refused,
                    _ => ConnectionOutcome::Unreachable,
                };
                Self::record_reconnect_outcome_for_failed_connect(addr, outcome);
                return Err((addr, e));
            }
            Err(_) => {
                Self::record_reconnect_outcome_for_failed_connect(
                    addr,
                    ConnectionOutcome::Timeout {
                        elapsed: started_at.elapsed(),
                    },
                );
                return Err((
                    addr,
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!(
                            "tcp connect timed out after {:?}",
                            DIRECT_TCP_CONNECT_TIMEOUT
                        ),
                    ),
                ));
            }
        };
        let rtt = started_at.elapsed();
        let remote_addr = tcp_stream.peer_addr().unwrap_or(addr);
        let local_addr = match tcp_stream.local_addr() {
            Ok(addr) => addr,
            Err(e) => return Err((addr, e)),
        };
        Ok((tcp_stream, remote_addr, local_addr, rtt))
    }

    fn record_reconnect_outcome(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        outcome: ConnectionOutcome,
    ) {
        if let Err(e) = record_connection_outcome(local_addr.ip(), remote_addr, outcome) {
            debug!(
                "record rtcp reconnect outcome {} -> {} failed: {}",
                local_addr, remote_addr, e
            );
        }
    }

    // Failed-connect path has no usable local_addr; addr-rtt history is keyed
    // on (local_ip, remote_addr), so without a local_ip we can only log.
    fn record_reconnect_outcome_for_failed_connect(
        remote_addr: SocketAddr,
        outcome: ConnectionOutcome,
    ) {
        debug!(
            "rtcp reconnect attempt to {} failed: {:?}",
            remote_addr, outcome
        );
    }

    async fn on_ropen(&self, ropen_package: RTcpROpenPackage) -> Result<(), anyhow::Error> {
        debug!(
            "RTcp tunnel ropen request: {:?}:{}, {:?}",
            ropen_package.body.dest_host, ropen_package.body.dest_port, ropen_package.body.purpose
        );

        // 1. Build a reconnect stream to the remote's RTCP listener. For a
        // bootstrap-backed tunnel this replays the nested transport (§14.5);
        // for a direct tunnel it opens TCP to peer_addr:stack_port. Any
        // failure is reported back as ROpenResp(result=2) so the initiator
        // releases its wait-HelloStream slot immediately.
        let (mut rtcp_stream, remote_addr, local_addr) = match self.build_reconnect_stream().await {
            Ok(triple) => triple,
            Err(e) => {
                warn!(
                    "ropen reject: build reconnect stream to {} failed: {}",
                    self.remote_stack.did.to_string(),
                    e
                );
                let ropen_resp_package = RTcpROpenRespPackage::new(ropen_package.seq, 2);
                let mut write_stream = self.write_stream.lock().await;
                let write_stream = Pin::new(&mut *write_stream);
                RTcpTunnelPackage::send_package(write_stream, ropen_resp_package).await?;
                return Ok(());
            }
        };

        // 2. send ropen_resp
        {
            let mut write_stream = self.write_stream.lock().await;
            let write_stream = Pin::new(&mut *write_stream);
            let ropen_resp_package = RTcpROpenRespPackage::new(ropen_package.seq, 0);
            RTcpTunnelPackage::send_package(write_stream, ropen_resp_package).await?;
        }

        // 3. send hello stream
        RTcpTunnelPackage::send_hello_stream(
            rtcp_stream.as_mut(),
            ropen_package.body.stream_id.as_str(),
        )
        .await?;

        let nonce_bytes: [u8; 16] = hex::decode(ropen_package.body.stream_id.as_str())
            .map_err(|op| anyhow::format_err!("decode stream_id error:{}", op))?
            .try_into()
            .map_err(|_op| anyhow::format_err!("decode stream_id error"))?;
        let aes_key = self.get_key().clone();
        // This side opened the reconnect stream and sent HelloStream, so it is
        // the stream-layer initiator regardless of whether the transport is a
        // direct TCP socket or a bootstrap-backed nested stream.
        let aes_stream = EncryptedStream::new(
            rtcp_stream,
            &aes_key,
            &nonce_bytes,
            EncryptionRole::Initiator,
        );

        debug!(
            "RTcp stream encryption initialized for ropen stream {}",
            ropen_package.body.stream_id
        );

        let purpose = ropen_package.body.purpose.clone().unwrap_or_default();
        match purpose {
            StreamPurpose::Stream => {
                self.on_stream_ropen(
                    ropen_package.body.dest_host,
                    ropen_package.body.dest_port,
                    remote_addr,
                    local_addr,
                    Box::new(aes_stream),
                )
                .await
            }
            StreamPurpose::Datagram => {
                self.on_datagram_ropen(
                    ropen_package.body.dest_host,
                    ropen_package.body.dest_port,
                    remote_addr,
                    local_addr,
                    Box::new(aes_stream),
                )
                .await
            }
        }
    }

    async fn on_stream_ropen(
        &self,
        dest_host: Option<String>,
        dest_port: u16,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        stream: Box<dyn AsyncStream>,
    ) -> Result<(), anyhow::Error> {
        //TODO: bug?
        let end_point = TunnelEndpoint {
            device_id: self.remote_stack.did.to_string(),
            port: self.remote_stack.stack_port,
        };
        self.listener
            .on_new_stream(
                stream,
                dest_host,
                dest_port,
                end_point,
                remote_addr,
                local_addr,
            )
            .await?;
        Ok(())
    }

    async fn on_datagram_ropen(
        &self,
        dest_host: Option<String>,
        dest_port: u16,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        stream: Box<dyn AsyncStream>,
    ) -> Result<(), anyhow::Error> {
        let end_point = TunnelEndpoint {
            device_id: self.remote_stack.did.to_string(),
            port: self.remote_stack.stack_port,
        };
        self.listener
            .on_new_datagram(
                stream,
                dest_host,
                dest_port,
                end_point,
                remote_addr,
                local_addr,
            )
            .await?;
        Ok(())
    }

    async fn on_open(&self, open_package: RTcpOpenPackage) -> Result<(), anyhow::Error> {
        debug!(
            "RTcp tunnel open request: {:?}:{}, {:?}",
            open_package.body.dest_host, open_package.body.dest_port, open_package.body.purpose
        );

        // 1. Enforce per-tunnel concurrency quota for pending inbound opens.
        // try_acquire is non-blocking: if the tunnel already has too many
        // streams waiting for HelloStream, reject immediately with a non-zero
        // OpenResp code rather than queuing up and letting the waiting table
        // grow. This also keeps the read loop responsive.
        let permit = match self.inbound_open_slots.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(TryAcquireError::NoPermits) => {
                warn!(
                    "RTcp tunnel inbound open quota exhausted ({} pending), rejecting stream {}",
                    MAX_PENDING_INBOUND_OPENS, open_package.body.stream_id
                );
                let mut write_stream = self.write_stream.lock().await;
                let write_stream = Pin::new(&mut *write_stream);
                let open_resp_package = RTcpOpenRespPackage::new(open_package.seq, 1);
                RTcpTunnelPackage::send_package(write_stream, open_resp_package).await?;
                return Ok(());
            }
            Err(TryAcquireError::Closed) => {
                return Err(anyhow::format_err!("inbound open semaphore closed"));
            }
        };

        // 2. Prepare wait for the new stream before send open_resp.
        let real_key = format!(
            "{}_{}",
            self.this_device.to_string(),
            open_package.body.stream_id
        );
        self.build_helper.new_wait_stream(&real_key).await;

        // 3. send open_resp with success (synchronous: keeps seq/response
        // ordering intact on the read loop).
        {
            let mut write_stream = self.write_stream.lock().await;
            let write_stream = Pin::new(&mut *write_stream);
            let open_resp_package = RTcpOpenRespPackage::new(open_package.seq, 0);
            RTcpTunnelPackage::send_package(write_stream, open_resp_package).await?;
        }

        // 4. Wait for the new stream in a detached task so a slow / never-
        // arriving HelloStream does not stall the tunnel read loop. The
        // permit is dropped when the task exits, releasing the quota slot.
        let this = self.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = this.finish_open(open_package, real_key).await {
                error!("RTcp on_open background task error: {}", e);
            }
        });

        Ok(())
    }

    async fn finish_open(
        &self,
        open_package: RTcpOpenPackage,
        real_key: String,
    ) -> Result<(), anyhow::Error> {
        let stream = match self.wait_ropen_stream(&open_package.body.stream_id).await {
            Ok(s) => s,
            Err(e) => {
                // wait_ropen_stream already removes the waiting entry on
                // timeout; no further cleanup needed here.
                return Err(anyhow::format_err!(
                    "wait HelloStream for {} failed: {}",
                    real_key,
                    e
                ));
            }
        };

        let remote_addr = stream
            .peer_addr()
            .map_err(|e| anyhow::format_err!("get peer_addr error: {}", e))?;
        let local_addr = stream
            .local_addr()
            .map_err(|e| anyhow::format_err!("get local_addr error: {}", e))?;

        let nonce_bytes: [u8; 16] = hex::decode(open_package.body.stream_id.as_str())
            .map_err(|op| anyhow::format_err!("decode stream_id error:{}", op))?
            .try_into()
            .map_err(|_op| anyhow::format_err!("decode stream_id error"))?;
        let aes_key = self.get_key().clone();
        // This side received an Open and waited for the peer to connect back
        // with HelloStream, so it is the stream-layer responder.
        let aes_stream =
            EncryptedStream::new(stream, &aes_key, &nonce_bytes, EncryptionRole::Responder);

        debug!(
            "RTcp stream encryption initialized for open stream {}",
            open_package.body.stream_id
        );

        let purpose = open_package.body.purpose.clone().unwrap_or_default();
        match purpose {
            StreamPurpose::Stream => {
                self.on_stream_ropen(
                    open_package.body.dest_host,
                    open_package.body.dest_port,
                    remote_addr,
                    local_addr,
                    Box::new(aes_stream),
                )
                .await
            }
            StreamPurpose::Datagram => {
                self.on_datagram_ropen(
                    open_package.body.dest_host,
                    open_package.body.dest_port,
                    remote_addr,
                    local_addr,
                    Box::new(aes_stream),
                )
                .await
            }
        }
    }

    pub async fn run(self) {
        let source_info = self.remote_stack.did.to_string();
        let mut read_stream = self.read_stream.lock().await;
        //let read_stream = self.read_stream.clone();
        loop {
            if self.is_closed() {
                info!("RTcp tunnel {} closed, exit run loop", source_info);
                break;
            }
            //等待超时 或 收到一个package
            //超时，基于last_active发送ping包,3倍超时时间后，关闭连接
            //收到一个package，处理package
            //   如果是req包，则处理逻辑后，发送resp包
            //   如果是resp包，则先找到对应的req包，然后处理逻辑

            let read_stream = Pin::new(&mut *read_stream);
            //info!("rtcp tunnel try read package from {}",self.peer_addr.to_string());

            let ret =
                RTcpTunnelPackage::read_package(read_stream, false, source_info.as_str()).await;
            //info!("rtcp tunnel read package from {} ok",source_info.as_str());
            if ret.is_err() {
                error!(
                    "Read package from tunnel error: {}, {:?}",
                    source_info,
                    ret.err().unwrap()
                );
                break;
            }

            let package = ret.unwrap();
            let result = self.process_package(package).await;
            if result.is_err() {
                error!(
                    "process package error: {}, {}",
                    source_info,
                    result.err().unwrap()
                );
                break;
            }
        }
    }

    async fn post_ropen(
        &self,
        seq: u32,
        purpose: Option<StreamPurpose>,
        dest_port: u16,
        dest_host: Option<String>,
        session_key: &str,
    ) -> Result<(), std::io::Error> {
        let ropen_package =
            RTcpROpenPackage::new(seq, session_key.to_string(), purpose, dest_port, dest_host);
        let mut write_stream = self.write_stream.lock().await;
        let write_stream = Pin::new(&mut *write_stream);
        RTcpTunnelPackage::send_package(write_stream, ropen_package)
            .await
            .map_err(|e| {
                let msg = format!("send ropen package error:{}", e);
                error!("{}", msg);
                std::io::Error::new(std::io::ErrorKind::Other, msg)
            })
    }

    async fn post_open(
        &self,
        seq: u32,
        purpose: Option<StreamPurpose>,
        dest_port: u16,
        dest_host: Option<String>,
        session_key: &str,
    ) -> Result<(), std::io::Error> {
        let ropen_package =
            RTcpOpenPackage::new(seq, session_key.to_string(), purpose, dest_port, dest_host);
        let mut write_stream = self.write_stream.lock().await;
        let write_stream = Pin::new(&mut *write_stream);
        RTcpTunnelPackage::send_package(write_stream, ropen_package)
            .await
            .map_err(|e| {
                let msg = format!("send open package error:{}", e);
                error!("{}", msg);
                std::io::Error::new(std::io::ErrorKind::Other, msg)
            })
    }

    async fn wait_ropen_stream(&self, session_key: &str) -> Result<TcpStream, std::io::Error> {
        let real_key = format!("{}_{}", self.this_device.to_string(), session_key);
        self.build_helper.wait_ropen_stream(&real_key).await
    }

    async fn request_open_stream(
        &self,
        purpose: Option<StreamPurpose>,
        dest_port: u16,
        dest_host: Option<String>,
    ) -> Result<Box<dyn AsyncStream>, std::io::Error> {
        // Tunnels carried neither by a direct TCP socket nor by a bootstrap
        // transport cannot fulfil either the Open or ROpen path (both need a
        // way to produce a fresh stream leg to the remote RTCP listener).
        // Reject up front so the peer is never asked to allocate a 30s pending
        // Open / wait-HelloStream slot.
        if self.peer_addr.is_none() && self.bootstrap.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "rtcp tunnel has neither a direct peer address nor a bootstrap transport",
            ));
        }

        // First generate 32byte session_key
        let random_bytes: [u8; 16] = rand::rng().random();
        let session_key = hex::encode(random_bytes);
        let real_key = format!("{}_{}", self.this_device.to_string(), session_key);
        let seq = self.next_seq();

        debug!(
            "RTcp tunnel open stream to {}:{}, can_direct:{}",
            dest_host.clone().unwrap_or("127.0.0.1".to_string()),
            dest_port,
            self.can_direct
        );

        if self.can_direct {
            let (tx, rx) = oneshot::channel::<u32>();
            self.open_resp_waiters.lock().await.insert(seq, tx);

            // Send open to remote stack to build a direct stream
            if let Err(e) = self
                .post_open(seq, purpose, dest_port, dest_host, session_key.as_str())
                .await
            {
                self.open_resp_waiters.lock().await.remove(&seq);
                return Err(e);
            }

            // Wait for OpenResp with the result code. Fail fast on a
            // non-zero code so we don't optimistically connect + send a
            // HelloStream that the peer has already refused (which would
            // show up on the peer as a "late or unknown HelloStream").
            let wait_result = timeout(Duration::from_secs(60), rx).await;
            let result_code = match wait_result {
                Ok(Ok(code)) => code,
                Ok(Err(_)) => {
                    // Sender dropped — tunnel dropped the waiter.
                    self.open_resp_waiters.lock().await.remove(&seq);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "tunnel dropped open resp waiter",
                    ));
                }
                Err(_) => {
                    self.open_resp_waiters.lock().await.remove(&seq);
                    error!(
                        "Timeout: open stream {} was not found within the time limit.",
                        real_key.as_str()
                    );
                    return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "Timeout"));
                }
            };

            if result_code != 0 {
                warn!(
                    "RTcp open stream {} rejected by peer, result={}",
                    real_key.as_str(),
                    result_code
                );
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    format!("peer rejected open stream, result={}", result_code),
                ));
            }

            // Build a fresh stream leg to the remote RTCP listener. Direct
            // tunnels open TCP to peer_addr; bootstrap-backed tunnels replay
            // the nested transport via the tunnel framework (§14.5).
            let (mut stream, _remote_addr, _local_addr) =
                self.build_reconnect_stream().await.map_err(|e| {
                    error!(
                        "RTcp tunnel open stream to {} error: {}",
                        self.remote_stack.did.to_string(),
                        e
                    );
                    e
                })?;

            // Send hello stream
            RTcpTunnelPackage::send_hello_stream(stream.as_mut(), session_key.as_str())
                .await
                .map_err(|e| {
                    let msg = format!(
                        "send hello stream error to {}: {}",
                        self.remote_stack.did.to_string(),
                        e
                    );
                    error!("{}", msg);
                    std::io::Error::new(std::io::ErrorKind::Other, msg)
                })?;

            // Direct-open path: this side opened the reconnect stream and sent
            // HelloStream, so it is the stream-layer initiator. The transport
            // can be a direct TCP socket or a bootstrap-backed nested stream.
            let aes_stream: EncryptedStream<Box<dyn AsyncStream>> = EncryptedStream::new(
                stream,
                &self.get_key(),
                &random_bytes,
                EncryptionRole::Initiator,
            );

            debug!(
                "RTcp tunnel open stream to {} ok",
                self.remote_stack.did.to_string()
            );

            Ok(Box::new(aes_stream))
        } else {
            //send ropen to remote stack

            // Register the ROpenResp waiter BEFORE posting so a fast peer
            // reply can never lose the race. A non-zero result lets us bail
            // out of the wait_ropen_stream slot immediately instead of
            // burning the full 30s STREAM_WAIT_TIMEOUT.
            let (resp_tx, resp_rx) = oneshot::channel::<u32>();
            self.ropen_resp_waiters.lock().await.insert(seq, resp_tx);

            self.build_helper.new_wait_stream(&real_key).await;

            //info!("insert session_key {} to wait ropen stream map",real_key.as_str());
            if let Err(e) = self
                .post_ropen(seq, purpose, dest_port, dest_host, session_key.as_str())
                .await
            {
                // Send failed: no HelloStream will ever arrive for this key,
                // so the waiting slot must be reclaimed now rather than
                // relying on the 30s timeout path.
                self.ropen_resp_waiters.lock().await.remove(&seq);
                self.build_helper.remove_wait_stream(&real_key).await;
                return Err(e);
            }

            // Race the HelloStream wait against ROpenResp. Either:
            //  - HelloStream arrives -> success path.
            //  - ROpenResp(0) arrives first -> peer accepted, fall through
            //    and keep waiting for HelloStream.
            //  - ROpenResp(non-zero) arrives -> peer rejected, abort now.
            // (wait_ropen_stream reclaims its own slot on timeout internally.)
            let stream = tokio::select! {
                res = self.wait_ropen_stream(&session_key.as_str()) => {
                    self.ropen_resp_waiters.lock().await.remove(&seq);
                    res?
                }
                resp = resp_rx => {
                    match resp {
                        Ok(0) => {
                            // Accepted; HelloStream is en route.
                            self.wait_ropen_stream(&session_key.as_str()).await?
                        }
                        Ok(code) => {
                            warn!(
                                "RTcp ropen stream {} rejected by peer, result={}",
                                real_key.as_str(),
                                code
                            );
                            self.build_helper.remove_wait_stream(&real_key).await;
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::ConnectionRefused,
                                format!("peer rejected ropen, result={}", code),
                            ));
                        }
                        Err(_) => {
                            // Tunnel dropped the waiter (likely tunnel closed).
                            self.build_helper.remove_wait_stream(&real_key).await;
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::BrokenPipe,
                                "tunnel dropped ropen resp waiter",
                            ));
                        }
                    }
                }
            };
            // ROpen path: this side sent ROpen and the peer connected back
            // with HelloStream, so it is the stream-layer responder.
            let aes_stream: EncryptedStream<TcpStream> = EncryptedStream::new(
                stream,
                &self.get_key(),
                &random_bytes,
                EncryptionRole::Responder,
            );
            //info!("wait ropen stream ok,return aes stream: aes_key:{},nonce_bytes:{}",hex::encode(self.get_key()),hex::encode(random_bytes));
            Ok(Box::new(aes_stream))
        }
    }
}

#[async_trait]
impl Tunnel for RTcpTunnel {
    async fn ping(&self) -> Result<(), std::io::Error> {
        let timestamp = buckyos_get_unix_timestamp();
        let ping_package = RTcpPingPackage::new(0, timestamp);
        let mut write_stream = self.write_stream.lock().await;
        let write_stream = Pin::new(&mut *write_stream);
        let _ = RTcpTunnelPackage::send_package(write_stream, ping_package).await;
        Ok(())
    }

    async fn open_stream_by_dest(
        &self,
        dest_port: u16,
        dest_host: Option<String>,
    ) -> Result<Box<dyn AsyncStream>, std::io::Error> {
        self.request_open_stream(Some(StreamPurpose::Stream), dest_port, dest_host)
            .await
    }

    async fn open_stream(&self, stream_id: &str) -> Result<Box<dyn AsyncStream>, std::io::Error> {
        //TODO: support stream_id is a tunnel url like rtcp://sn.buckyos.ai/google.com:443/
        let real_stream_id = percent_decode_str(stream_id.trim_start_matches('/')).decode_utf8();
        if real_stream_id.is_ok() {
            let real_stream_id = real_stream_id.unwrap();
            if has_scheme(real_stream_id.as_ref()) {
                let stream_url = Url::parse(&real_stream_id);
                if stream_url.is_ok() {
                    debug!("will request open stream by url: {}", real_stream_id);
                    return self
                        .open_stream_by_dest(0, Some(real_stream_id.to_string()))
                        .await;
                }
            }
        }
        debug!("will rquest open stream by dest: {}", stream_id);
        let (dest_host, dest_port) = get_dest_info_from_url_path(stream_id)?;
        self.open_stream_by_dest(dest_port, dest_host).await
    }

    async fn create_datagram_client_by_dest(
        &self,
        dest_port: u16,
        dest_host: Option<String>,
    ) -> Result<Box<dyn DatagramClientBox>, std::io::Error> {
        //todo 是否可以支持配置成udp session,而不是强制使用tcp stream
        let stream = self
            .request_open_stream(Some(StreamPurpose::Datagram), dest_port, dest_host)
            .await?;
        let client = RTcpTunnelDatagramClient::new(Box::new(stream));
        Ok(Box::new(client) as Box<dyn DatagramClientBox>)
    }

    async fn create_datagram_client(
        &self,
        session_id: &str,
    ) -> Result<Box<dyn DatagramClientBox>, std::io::Error> {
        let real_stream_id = percent_decode_str(session_id.trim_start_matches('/')).decode_utf8();
        if real_stream_id.is_ok() {
            let real_stream_id = real_stream_id.unwrap();
            if has_scheme(real_stream_id.as_ref()) {
                let stream_url = Url::parse(&real_stream_id);
                if stream_url.is_ok() {
                    debug!("will request open stream by url: {}", real_stream_id);
                    return self
                        .create_datagram_client_by_dest(0, Some(real_stream_id.to_string()))
                        .await;
                }
            }
        }
        let (dest_host, dest_port) = get_dest_info_from_url_path(session_id)?;
        self.create_datagram_client_by_dest(dest_port, dest_host)
            .await
    }
}

impl RTcpTunnel {
    // RTT-aware ping. Sends a Ping with a fresh seq and waits for the
    // matching Pong on a per-seq oneshot. Distinct from `Tunnel::ping`,
    // which only flushes a control packet without measuring response.
    pub(crate) async fn ping_rtt(&self, timeout_dur: Duration) -> Result<Duration, std::io::Error> {
        if self.is_closed() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "rtcp tunnel closed",
            ));
        }
        // The classic ping path uses seq 0; pick a non-zero seq here so
        // a stray Pong from `ping()` cannot satisfy our waiter.
        let mut seq = self.next_seq();
        if seq == 0 {
            seq = self.next_seq();
        }

        let (tx, rx) = oneshot::channel::<()>();
        self.pong_waiters.lock().await.insert(seq, tx);

        let timestamp = buckyos_get_unix_timestamp();
        let ping_package = RTcpPingPackage::new(seq, timestamp);
        let send_result = {
            let mut write_stream = self.write_stream.lock().await;
            let write_stream = Pin::new(&mut *write_stream);
            RTcpTunnelPackage::send_package(write_stream, ping_package).await
        };
        if let Err(e) = send_result {
            self.pong_waiters.lock().await.remove(&seq);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("send ping failed: {}", e),
            ));
        }

        let started = std::time::Instant::now();
        match timeout(timeout_dur, rx).await {
            Ok(Ok(())) => Ok(started.elapsed()),
            Ok(Err(_)) => {
                self.pong_waiters.lock().await.remove(&seq);
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "tunnel dropped pong waiter",
                ))
            }
            Err(_) => {
                self.pong_waiters.lock().await.remove(&seq);
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "rtcp ping timeout",
                ))
            }
        }
    }
}

#[async_trait::async_trait]
pub trait RTcpListener: 'static + Send + Sync {
    async fn on_new_tunnel(
        &self,
        _endpoint: TunnelEndpoint,
        _source_addr: SocketAddr,
        _source_device_info: Option<RTcpSourceDeviceInfo>,
    ) -> TunnelResult<()> {
        Ok(())
    }

    async fn on_new_stream(
        &self,
        stream: Box<dyn AsyncStream>,
        dest_host: Option<String>,
        dest_port: u16,
        endpoint: TunnelEndpoint,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> TunnelResult<()>;
    async fn on_new_datagram(
        &self,
        stream: Box<dyn AsyncStream>,
        dest_host: Option<String>,
        dest_port: u16,
        endpoint: TunnelEndpoint,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> TunnelResult<()>;
}
pub type RTcpListenerRef = Arc<dyn RTcpListener>;

#[derive(Clone)]
struct RTcpTunnelMap {
    tunnel_map: Arc<Mutex<HashMap<String, RTcpTunnel>>>,
}

impl RTcpTunnelMap {
    pub fn new() -> Self {
        RTcpTunnelMap {
            tunnel_map: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn tunnel_map(&self) -> Arc<Mutex<HashMap<String, RTcpTunnel>>> {
        self.tunnel_map.clone()
    }

    pub async fn get_tunnel(&self, tunnel_key: &str) -> Option<RTcpTunnel> {
        let all_tunnel = self.tunnel_map.lock().await;
        if let Some(tunnel) = all_tunnel.get(tunnel_key) {
            Some(tunnel.clone())
        } else {
            None
        }
    }

    // Returns Err(()) if a tunnel for `tunnel_key` is already present.
    //
    // A silent replace here would let a replayed Hello stand up a second
    // tunnel under the same (aes_key, iv) as the live one. The AEAD record
    // layer starts its per-direction sequence counter at 0 for every new
    // tunnel, so two concurrent tunnels with the same key would reuse the
    // same (key, nonce) pairs — catastrophic for AES-GCM. Rejecting the
    // replay keeps the (key, nonce) space owned by a single tunnel at a
    // time. The existing tunnel will be cleaned up by `remove_tunnel` once
    // its read loop exits (e.g. on TCP close); a genuine reconnect will
    // succeed on retry after that.
    //
    // Across-time nonce reuse (attacker replays Hello after the original
    // tunnel has ended) is a separate concern addressed by §14.2 of
    // doc/rtcp.md.
    pub async fn on_new_tunnel(&self, tunnel_key: &str, tunnel: RTcpTunnel) -> Result<(), ()> {
        let mut all_tunnel = self.tunnel_map.lock().await;
        if all_tunnel.contains_key(tunnel_key) {
            warn!(
                "tunnel {} already exists, rejecting duplicate Hello to avoid (key, nonce) reuse",
                tunnel_key
            );
            return Err(());
        }
        all_tunnel.insert(tunnel_key.to_owned(), tunnel);
        Ok(())
    }

    pub async fn remove_tunnel(&self, tunnel_key: &str) {
        let mut all_tunnel = self.tunnel_map.lock().await;
        all_tunnel.remove(tunnel_key);
    }
}
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::rtcp::AsyncStreamWithDatagram;
    use crate::rtcp::rtcp::RTcp;
    use crate::{TunnelBuilder, TunnelEndpoint, TunnelResult};
    use buckyos_kit::AsyncStream;
    use jsonwebtoken::EncodingKey;
    use name_lib::{DID, DIDDocumentTrait};
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};

    // §14.2 regression: the nonce cache retention window must cover the
    // full signature-acceptance window (`exp + JWT_LEEWAY_SECS`), not just
    // `exp`. Before this fix the cache evicted the entry at `exp`, while
    // jsonwebtoken's default leeway kept the token itself signature-valid
    // until `exp + 60s` -- opening a replay gap of one full leeway window.
    //
    // This test feeds the cache with the same (retain_until_ts, now_ts)
    // values on_new_tunnel computes in production and verifies that a
    // replay at `exp + 1s` (firmly inside the leeway) is still rejected.
    #[tokio::test]
    async fn nonce_cache_retains_entry_past_exp_within_leeway() {
        let cache = NonceCache::new();
        let from = "did:dev:test-peer";
        let nonce = "deadbeefdeadbeefdeadbeefdeadbeef";
        let exp: u64 = 1_000_000;
        let retain_until = exp + JWT_LEEWAY_SECS;

        // Initial admission succeeds at issue time.
        let now_issue = exp - TUNNEL_TOKEN_EXP_SECS;
        assert!(
            cache
                .insert_if_fresh(from, nonce, retain_until, now_issue)
                .await
        );

        // Replay at exp + 1s -- past the token's exp claim but still
        // inside the JWT leeway window where signature validation would
        // ACCEPT the token. The nonce cache MUST still reject it.
        let now_replay = exp + 1;
        assert!(
            !cache
                .insert_if_fresh(from, nonce, retain_until, now_replay)
                .await,
            "replay within JWT leeway must be rejected; cache was pruning at exp instead of exp+leeway"
        );

        // Also verify the boundary: at exactly `retain_until` the entry
        // should still be present (retain_until is the last valid
        // timestamp).
        let now_boundary = retain_until - 1;
        assert!(
            !cache
                .insert_if_fresh(from, nonce, retain_until, now_boundary)
                .await,
            "replay at retain_until-1 must be rejected"
        );

        // Once we move strictly past the retention window the entry is
        // allowed to be evicted -- a fresh Hello with a newly-signed
        // token (and therefore a future exp/retain_until) can then reuse
        // the same (from, nonce) slot. This side of the boundary is
        // harmless because by then the original signature would also
        // have failed validation.
        let now_after = retain_until + 1;
        let new_retain_until = now_after + TUNNEL_TOKEN_EXP_SECS + JWT_LEEWAY_SECS;
        assert!(
            cache
                .insert_if_fresh(from, nonce, new_retain_until, now_after)
                .await,
            "after retain window, the same nonce bundled with a fresh token should be admissible"
        );
    }

    #[tokio::test]
    async fn web_target_token_uses_resolved_dev_identity() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;

        let (client_signing_key, client_pkcs8_bytes) = generate_ed25519_key();
        let client_jwk = encode_ed25519_sk_to_pk_jwk(&client_signing_key);
        let client_device_config =
            DeviceConfig::new_by_jwk("client", serde_json::from_value(client_jwk).unwrap());

        let (server_signing_key, _server_pkcs8_bytes) = generate_ed25519_key();
        let server_jwk = encode_ed25519_sk_to_pk_jwk(&server_signing_key);
        let server_device_config =
            DeviceConfig::new_by_jwk("server", serde_json::from_value(server_jwk).unwrap());
        let server_id = server_device_config.id.clone();

        let mut name_info = NameInfo::new("sn.devtests.org");
        name_info.txt.push(format!("PKX={};", server_id.id));
        add_nameinfo_cache("sn.devtests.org", name_info)
            .await
            .unwrap();

        let client_inner = RTcpInner::new(
            client_device_config.id,
            "127.0.0.1:19083".to_string(),
            Some(client_pkcs8_bytes),
            None,
            Arc::new(MockRTcpListener::new()),
        );

        let state = client_inner
            .generate_tunnel_token("did:web:sn.devtests.org".to_string())
            .await
            .unwrap();
        let claims = decode_jwt_claim_without_verify(&state.token).unwrap();

        assert_eq!(
            claims.get("to").and_then(|v| v.as_str()),
            Some(server_id.to_host_name().as_str())
        );
        assert_eq!(state.responder_did, server_id.to_host_name());
        RTcpInner::validate_hello_target("sn.devtests.org", server_id.to_host_name().as_str())
            .await
            .unwrap();
    }

    #[test]
    fn test_rtcp_struct_creation() {
        // 测试RTcp结构体的创建
        let did = DID::new("test", "device1");
        let listener = Arc::new(MockRTcpListener {});

        let _rtcp = RTcp::new(
            did.clone(),
            "127.0.0.1:8000".to_string(),
            None,
            None,
            listener,
        );

        // 由于RTcp的大部分功能通过公共方法暴露
        // 这里可以添加更多针对公共方法的测试
        // 目前只验证基本创建
        assert!(true);
    }

    // Mock实现用于测试
    struct MockRTcpListener;

    impl MockRTcpListener {
        fn new() -> Self {
            MockRTcpListener {}
        }
    }

    struct RelayRTcpListener {
        routes: HashMap<String, SocketAddr>,
    }

    impl RelayRTcpListener {
        fn new(routes: HashMap<String, SocketAddr>) -> Self {
            RelayRTcpListener { routes }
        }
    }

    struct TestRtcpTunnelBuilder {
        inner: Arc<RTcpInner>,
    }

    #[async_trait::async_trait]
    impl TunnelBuilder for TestRtcpTunnelBuilder {
        async fn create_tunnel(
            &self,
            tunnel_stack_id: Option<&str>,
        ) -> TunnelResult<Box<dyn TunnelBox>> {
            self.inner.create_tunnel(tunnel_stack_id).await
        }
    }

    #[async_trait::async_trait]
    impl RTcpListener for MockRTcpListener {
        async fn on_new_stream(
            &self,
            mut stream: Box<dyn AsyncStream>,
            _dest_host: Option<String>,
            _dest_port: u16,
            _endpoint: TunnelEndpoint,
            _remote_addr: SocketAddr,
            _local_addr: SocketAddr,
        ) -> TunnelResult<()> {
            loop {
                let mut buf = [0u8; 1024];
                match stream.read(&mut buf).await {
                    Ok(n) => {
                        if n == 0 {
                            break;
                        }
                        stream.write_all(&buf[0..n]).await.unwrap();
                    }
                    Err(e) => {
                        error!("read error: {}", e);
                        break;
                    }
                }
            }
            Ok(())
        }

        async fn on_new_datagram(
            &self,
            stream: Box<dyn AsyncStream>,
            _dest_host: Option<String>,
            _dest_port: u16,
            _endpoint: TunnelEndpoint,
            _remote_addr: SocketAddr,
            _local_addr: SocketAddr,
        ) -> TunnelResult<()> {
            let datagram_stream = AsyncStreamWithDatagram::new(stream);
            let mut buf = [0u8; 1024];
            loop {
                let len = datagram_stream.recv_datagram(&mut buf).await.unwrap();
                datagram_stream.send_datagram(&buf[..len]).await.unwrap();
            }
        }
    }

    #[async_trait::async_trait]
    impl RTcpListener for RelayRTcpListener {
        async fn on_new_stream(
            &self,
            stream: Box<dyn AsyncStream>,
            dest_host: Option<String>,
            dest_port: u16,
            _endpoint: TunnelEndpoint,
            _remote_addr: SocketAddr,
            _local_addr: SocketAddr,
        ) -> TunnelResult<()> {
            let dest_host = dest_host.ok_or_else(|| {
                TunnelError::ReasonError("relay listener requires dest_host".to_string())
            })?;
            let target_addr = self.routes.get(&dest_host).copied();
            tokio::spawn(async move {
                let mut stream = stream;
                let target_addr = match target_addr {
                    Some(addr) => addr,
                    None => {
                        let dest_ip = match resolve_ip(dest_host.as_str()).await {
                            Ok(ip) => ip,
                            Err(e) => {
                                error!("relay listener resolve {} failed: {}", dest_host, e);
                                return;
                            }
                        };
                        SocketAddr::new(dest_ip, dest_port)
                    }
                };
                let mut upstream = match TcpStream::connect(target_addr).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        error!(
                            "relay listener connect {} via {} failed: {}",
                            dest_host, target_addr, e
                        );
                        return;
                    }
                };
                if let Err(e) = copy_bidirectional(&mut stream, &mut upstream).await {
                    error!("relay listener forward failed: {}", e);
                }
            });
            Ok(())
        }

        async fn on_new_datagram(
            &self,
            _stream: Box<dyn AsyncStream>,
            _dest_host: Option<String>,
            _dest_port: u16,
            _endpoint: TunnelEndpoint,
            _remote_addr: SocketAddr,
            _local_addr: SocketAddr,
        ) -> TunnelResult<()> {
            Err(TunnelError::ReasonError(
                "relay listener does not support datagram in this test".to_string(),
            ))
        }
    }

    #[tokio::test]
    async fn test_rtcp_err() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let mut rtcp1 = RTcp::new(
            device_config.id,
            "127.0.0.1:19023".to_string(),
            Some(pkcs8_bytes),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        rtcp1.start().await.unwrap();

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test2", serde_json::from_value(jwk).unwrap());
        let id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let mut rtcp2 = RTcp::new(
            device_config.id,
            "127.0.0.1:19024".to_string(),
            Some(pkcs8_bytes),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        rtcp2.start().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Historically this test first created a tunnel, dropped rtcp2,
        // and then called create_tunnel again expecting it to fail. That
        // worked by accident: the original (§14.1) code's Hello was one-
        // way, so `drop(rtcp2)` could race ahead of rtcp2 processing
        // Hello; no tunnel entry survived on rtcp2 and the peer's TCP
        // reset let rtcp1's stale tunnel get evicted within the 2s wait.
        //
        // The §14.2 key-confirmation handshake is synchronous -- the
        // initiator only returns from create_tunnel after the AEAD
        // challenge-response completes. That removes the race and, with
        // it, the cheap way to force rtcp1's cached tunnel to clear.
        // Since the cached-reuse path is already covered elsewhere, we
        // restrict this test to its core assertion: create_tunnel to a
        // target whose RTCP listener is gone must fail.
        drop(rtcp2);
        tokio::time::sleep(Duration::from_secs(1)).await;
        {
            let ret = rtcp1
                .create_tunnel(Some(format!("{}:19024", id2.to_host_name()).as_str()))
                .await;
            assert!(ret.is_err());
        }
    }

    #[tokio::test]
    async fn test_rtcp_ping() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let mut rtcp1 = RTcp::new(
            device_config.id,
            "127.0.0.1:19033".to_string(),
            Some(pkcs8_bytes),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        rtcp1.start().await.unwrap();

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test2", serde_json::from_value(jwk).unwrap());
        let id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let mut rtcp2 = RTcp::new(
            device_config.id,
            "127.0.0.1:19034".to_string(),
            Some(pkcs8_bytes),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        rtcp2.start().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;

        for _ in 0..10 {
            let tunnel = rtcp1
                .create_tunnel(Some(format!("{}:19034", id2.to_host_name()).as_str()))
                .await
                .unwrap();
            let ret = tunnel.ping().await;
            assert!(ret.is_ok());
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    // Brings up two RTCP stacks, probes the URL `rtcp://<id2>:19064`, and
    // verifies the prober returns a measured RTT via the new ping_rtt
    // path. Then re-probes and asserts the second call hits the existing
    // tunnel (source = ExistingTunnel).
    #[tokio::test]
    async fn test_rtcp_probe_url_measures_rtt_and_reuses_tunnel() {
        use crate::tunnel_url_status::TunnelProbeOptions;

        let _ = init_name_lib_for_test(&HashMap::new()).await;

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("probe1", serde_json::from_value(jwk).unwrap());
        let _id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let mut rtcp1 = RTcp::new(
            device_config.id,
            "127.0.0.1:19063".to_string(),
            Some(pkcs8_bytes),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        rtcp1.start().await.unwrap();

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("probe2", serde_json::from_value(jwk).unwrap());
        let id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let mut rtcp2 = RTcp::new(
            device_config.id,
            "127.0.0.1:19064".to_string(),
            Some(pkcs8_bytes),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        rtcp2.start().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;

        let url = Url::parse(format!("rtcp://{}:19064/", id2.to_host_name()).as_str()).unwrap();

        let opts = TunnelProbeOptions::default();
        let s1 = rtcp1.probe_url(&url, &opts).await.unwrap();
        assert_eq!(
            s1.state,
            crate::tunnel_url_status::TunnelUrlState::Reachable,
            "first probe should be reachable, got {:?} reason={:?}",
            s1.state,
            s1.failure_reason,
        );
        assert!(s1.rtt_ms.is_some(), "rtt must be measured");
        assert!(s1.runtime_tunnel_key.is_some());

        let s2 = rtcp1.probe_url(&url, &opts).await.unwrap();
        assert_eq!(
            s2.source,
            crate::tunnel_url_status::TunnelUrlStatusSource::ExistingTunnel,
            "second probe should reuse existing tunnel"
        );
        assert!(s2.rtt_ms.is_some());

        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    #[tokio::test]
    async fn test_rtcp_tunnel_accepts_device_doc_jwt_for_unknown_source() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;

        let (server_signing_key, server_pkcs8_bytes) = generate_ed25519_key();
        let server_jwk = encode_ed25519_sk_to_pk_jwk(&server_signing_key);
        let server_device_config =
            DeviceConfig::new_by_jwk("server", serde_json::from_value(server_jwk).unwrap());
        let server_id = server_device_config.id.clone();

        let (owner_signing_key, owner_pkcs8_bytes) = generate_ed25519_key();
        let owner_jwk = encode_ed25519_sk_to_pk_jwk(&owner_signing_key);
        let owner_config =
            DeviceConfig::new_by_jwk("owner", serde_json::from_value(owner_jwk).unwrap());
        let owner_did = owner_config.id.clone();
        let owner_private_key = EncodingKey::from_ed_der(&owner_pkcs8_bytes);

        let (client_signing_key, client_pkcs8_bytes) = generate_ed25519_key();
        let client_jwk = encode_ed25519_sk_to_pk_jwk(&client_signing_key);
        let mut client_device_config =
            DeviceConfig::new_by_jwk("client", serde_json::from_value(client_jwk).unwrap());
        client_device_config.owner = owner_did.clone();
        let client_id = client_device_config.id.clone();
        let client_device_doc_jwt = match client_device_config
            .encode(Some(&owner_private_key))
            .unwrap()
        {
            EncodedDocument::Jwt(jwt) => jwt,
            _ => panic!("device config encode should return jwt"),
        };

        let client_inner = RTcpInner::new(
            client_id.clone(),
            "127.0.0.1:19063".to_string(),
            Some(client_pkcs8_bytes),
            Some(client_device_doc_jwt.clone()),
            Arc::new(MockRTcpListener::new()),
        );
        let server_inner = RTcpInner::new(
            server_id,
            "127.0.0.1:19064".to_string(),
            Some(server_pkcs8_bytes),
            None,
            Arc::new(MockRTcpListener::new()),
        );

        let state = client_inner
            .generate_tunnel_token(server_device_config.id.to_string())
            .await
            .unwrap();
        let hello_body = RTcpHelloBody {
            from_id: client_id.to_string(),
            to_id: server_device_config.id.to_string(),
            my_port: 19063,
            tunnel_token: Some(state.token.clone()),
            device_doc_jwt: Some(client_device_doc_jwt),
        };
        let (source_device_id, source_device_info, source_public_key) =
            RTcpInner::resolve_source_device_info(&hello_body)
                .await
                .unwrap();
        assert_eq!(source_device_id, client_id.to_string());
        assert_eq!(
            source_device_info.unwrap().owner,
            Some(owner_did.to_string())
        );
        // server_inner is exercised here just to make sure the test
        // device boots without the long-term X25519 key (v2 dropped it).
        assert!(server_inner.this_device_ed25519_sk.is_some());

        RTcpInner::verify_hello_token(
            &state.token,
            &source_public_key,
            Some(client_id.to_host_name().as_str()),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn test_rtcp_stream() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let mut rtcp1 = RTcp::new(
            device_config.id,
            "127.0.0.1:19053".to_string(),
            Some(pkcs8_bytes),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        rtcp1.start().await.unwrap();

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test2", serde_json::from_value(jwk).unwrap());
        let id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let mut rtcp2 = RTcp::new(
            device_config.id,
            "127.0.0.1:19054".to_string(),
            Some(pkcs8_bytes),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        rtcp2.start().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;

        {
            let tunnel = rtcp1
                .create_tunnel(Some(format!("{}:19054", id2.to_host_name()).as_str()))
                .await
                .unwrap();
            let mut stream = tunnel.open_stream("www.baidu.com:80").await.unwrap();
            stream.write_all(b"test").await.unwrap();
            let mut buf = [0u8; 1024];
            let ret = stream.read(&mut buf).await;
            assert!(ret.is_ok());
            let len = ret.unwrap();
            assert_eq!(len, 4);
            assert_eq!(&buf[..len], b"test");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        {
            let tunnel = rtcp2
                .create_tunnel(Some(format!("{}:19053", id1.to_host_name()).as_str()))
                .await
                .unwrap();
            let mut stream = tunnel.open_stream("www.baidu.com:80").await.unwrap();
            stream.write_all(b"test").await.unwrap();
            let mut buf = [0u8; 1024];
            let ret = stream.read(&mut buf).await;
            assert!(ret.is_ok());
            let len = ret.unwrap();
            assert_eq!(len, 4);
            assert_eq!(&buf[..len], b"test");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    #[tokio::test]
    async fn test_rtcp_nested_remote_rebinds_transport_via_rtcp_relay() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test-a", serde_json::from_value(jwk).unwrap());
        let id_a = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let mut rtcp_a = RTcp::new(
            device_config.id,
            "127.0.0.1:19073".to_string(),
            Some(pkcs8_bytes),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        let tunnel_manager = TunnelManager::new();
        rtcp_a.set_tunnel_manager(tunnel_manager.clone());
        tunnel_manager.register_tunnel_builder(
            "rtcp",
            Arc::new(TestRtcpTunnelBuilder {
                inner: rtcp_a.inner.clone(),
            }),
        );
        rtcp_a.start().await.unwrap();

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test-b", serde_json::from_value(jwk).unwrap());
        let id_b = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let mut rtcp_b = RTcp::new(
            device_config.id,
            "127.0.0.1:19074".to_string(),
            Some(pkcs8_bytes),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        rtcp_b.start().await.unwrap();

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test-c", serde_json::from_value(jwk).unwrap());
        let id_c = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let relay_routes =
            HashMap::from([(id_b.to_host_name(), "127.0.0.1:19074".parse().unwrap())]);
        let mut rtcp_c = RTcp::new(
            device_config.id,
            "127.0.0.1:19075".to_string(),
            Some(pkcs8_bytes),
            None,
            Arc::new(RelayRTcpListener::new(relay_routes)),
        );
        rtcp_c.start().await.unwrap();

        tokio::time::sleep(Duration::from_secs(1)).await;

        let bootstrap_url = Url::parse(
            format!(
                "rtcp://{}:19075/{}:19074",
                id_c.to_host_name(),
                id_b.to_host_name()
            )
            .as_str(),
        )
        .unwrap();
        let nested_remote_stack_id =
            build_rtcp_nested_remote_stack_id(&bootstrap_url, &id_b.to_host_name(), Some(19074));

        let tunnel = tokio::time::timeout(
            Duration::from_secs(10),
            rtcp_a.create_tunnel(Some(nested_remote_stack_id.as_str())),
        )
        .await
        .expect("nested remote tunnel creation timed out")
        .expect("A should build the outer tunnel to B through C");

        tokio::time::timeout(Duration::from_secs(10), tunnel.ping())
            .await
            .expect("nested remote tunnel ping timed out")
            .expect("nested remote tunnel ping failed");

        let mut stream =
            tokio::time::timeout(Duration::from_secs(10), tunnel.open_stream("test:80"))
                .await
                .expect("nested remote stream open timed out")
                .expect("A should reach B through C with nested remote rtcp");
        tokio::time::timeout(Duration::from_secs(10), stream.write_all(b"test"))
            .await
            .expect("nested remote stream write timed out")
            .unwrap();

        let mut buf = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
            .await
            .expect("nested remote stream read timed out")
            .unwrap();
        assert_eq!(&buf, b"test");

        assert_ne!(id_a, id_b);
        assert_ne!(id_b, id_c);
    }

    #[tokio::test]
    async fn test_rtcp_datagram() {
        let _ = init_name_lib_for_test(&HashMap::new()).await.unwrap();
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let mut rtcp1 = RTcp::new(
            device_config.id,
            "127.0.0.1:19043".to_string(),
            Some(pkcs8_bytes),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        rtcp1.start().await.unwrap();

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test2", serde_json::from_value(jwk).unwrap());
        let id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let mut rtcp2 = RTcp::new(
            device_config.id,
            "127.0.0.1:19044".to_string(),
            Some(pkcs8_bytes),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        rtcp2.start().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;

        {
            let tunnel = rtcp1
                .create_tunnel(Some(format!("{}:19044", id2.to_host_name()).as_str()))
                .await
                .unwrap();
            let stream = tunnel
                .create_datagram_client("www.baidu.com:80")
                .await
                .unwrap();
            stream.send_datagram(b"test").await.unwrap();
            let mut buf = [0u8; 1024];
            let ret = stream.recv_datagram(&mut buf).await;
            assert!(ret.is_ok());
            let len = ret.unwrap();
            assert_eq!(len, 4);
            assert_eq!(&buf[..len], b"test");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        log::info!("test_rtcp_datagram end");

        {
            let tunnel = rtcp2
                .create_tunnel(Some(format!("{}:19043", id1.to_host_name()).as_str()))
                .await
                .unwrap();
            let stream = tunnel
                .create_datagram_client("www.baidu.com:80")
                .await
                .unwrap();
            stream.send_datagram(b"test").await.unwrap();
            let mut buf = [0u8; 1024];
            let ret = stream.recv_datagram(&mut buf).await;
            assert!(ret.is_ok());
            let len = ret.unwrap();
            assert_eq!(len, 4);
            assert_eq!(&buf[..len], b"test");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        log::info!("test_rtcp_datagram2 end");
    }
}
