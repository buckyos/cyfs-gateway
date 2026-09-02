use super::package::*;
use super::protocol::*;
use super::stream_helper::RTcpStreamBuildHelper;
use std::collections::{HashMap, HashSet};

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
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
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
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore, TryAcquireError, oneshot};
use tokio::task;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use url::Url;
use x25519_dalek::{EphemeralSecret, PublicKey};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RtcpPeerIdentityRequirement {
    #[default]
    AuthorityCurrent,
    TrustedSnapshot,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RtcpPeerIdentityConfig {
    pub requirement: RtcpPeerIdentityRequirement,
    pub dns_txt_bootstrap: bool,
}

impl Default for RtcpPeerIdentityConfig {
    fn default() -> Self {
        Self {
            requirement: RtcpPeerIdentityRequirement::AuthorityCurrent,
            dns_txt_bootstrap: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RtcpAnonymousAdmission {
    Allow,
    #[default]
    Reject,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RtcpNamedMinRelation {
    #[default]
    SameZone,
    KnownOwner,
    Any,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum RtcpAuthorityReconfirmMaxAge {
    Seconds(u64),
    Text(String),
}

impl Default for RtcpAuthorityReconfirmMaxAge {
    fn default() -> Self {
        Self::Text("unlimited".to_string())
    }
}

impl RtcpAuthorityReconfirmMaxAge {
    fn as_secs(&self) -> Result<Option<u64>, String> {
        match self {
            Self::Seconds(value) => Ok(Some(*value)),
            Self::Text(value) if value.eq_ignore_ascii_case("unlimited") => Ok(None),
            Self::Text(value) => value
                .parse::<u64>()
                .map(Some)
                .map_err(|_| format!("invalid authority_reconfirm_max_age '{}'", value)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RtcpInboundAdmissionConfig {
    pub anonymous: RtcpAnonymousAdmission,
    pub named_min_relation: RtcpNamedMinRelation,
    pub authority_reconfirm_max_age: RtcpAuthorityReconfirmMaxAge,
}

impl Default for RtcpInboundAdmissionConfig {
    fn default() -> Self {
        Self {
            anonymous: RtcpAnonymousAdmission::Reject,
            named_min_relation: RtcpNamedMinRelation::SameZone,
            authority_reconfirm_max_age: RtcpAuthorityReconfirmMaxAge::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RtcpLivenessConfig {
    pub ping_interval_secs: u64,
    pub pong_timeout_secs: u64,
    pub max_missed_pongs: u32,
}

impl Default for RtcpLivenessConfig {
    fn default() -> Self {
        Self {
            ping_interval_secs: 30,
            pong_timeout_secs: 10,
            max_missed_pongs: 3,
        }
    }
}

// A configurable operational limit keeps ordinary tunnels small, while the
// hard ceiling prevents a configuration mistake from restoring unbounded
// per-tunnel replay state. Stream IDs remain remembered for the whole key
// epoch; reaching the limit retires the tunnel instead of evicting history.
const DEFAULT_MAX_STREAM_IDS_PER_TUNNEL: usize = 1 << 16;
const MAX_STREAM_IDS_PER_TUNNEL_HARD_LIMIT: usize = 1 << 20;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RtcpLimitsConfig {
    pub max_pending_handshakes: usize,
    pub handshake_requests_per_second: u32,
    pub handshake_request_burst: u32,
    pub max_pending_stream_builds_per_tunnel: usize,
    pub max_stream_ids_per_tunnel: usize,
    pub max_datagram_bytes: usize,
    pub handshake_timeout_secs: u64,
    pub stream_requests_per_second: u32,
    pub stream_request_burst: u32,
}

impl Default for RtcpLimitsConfig {
    fn default() -> Self {
        Self {
            max_pending_handshakes: 256,
            handshake_requests_per_second: 16,
            handshake_request_burst: 32,
            max_pending_stream_builds_per_tunnel: 64,
            max_stream_ids_per_tunnel: DEFAULT_MAX_STREAM_IDS_PER_TUNNEL,
            max_datagram_bytes: super::datagram::MAX_RTCP_DATAGRAM_BYTES,
            handshake_timeout_secs: 15,
            stream_requests_per_second: 32,
            stream_request_burst: 64,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RtcpSecurityConfig {
    pub peer_identity: RtcpPeerIdentityConfig,
    pub inbound_admission: RtcpInboundAdmissionConfig,
    pub liveness: RtcpLivenessConfig,
    pub limits: RtcpLimitsConfig,
}

impl RtcpSecurityConfig {
    pub fn validate(&self) -> Result<(), String> {
        let _ = self
            .inbound_admission
            .authority_reconfirm_max_age
            .as_secs()?;
        if self.liveness.ping_interval_secs == 0
            || self.liveness.pong_timeout_secs == 0
            || self.liveness.max_missed_pongs == 0
        {
            return Err("rtcp liveness values must be greater than zero".to_string());
        }
        if self.limits.max_pending_handshakes == 0
            || self.limits.handshake_requests_per_second == 0
            || self.limits.handshake_request_burst == 0
            || self.limits.max_pending_stream_builds_per_tunnel == 0
            || self.limits.max_stream_ids_per_tunnel == 0
            || self.limits.handshake_timeout_secs == 0
            || self.limits.stream_requests_per_second == 0
            || self.limits.stream_request_burst == 0
        {
            return Err("rtcp limits must be greater than zero".to_string());
        }
        if self.limits.max_stream_ids_per_tunnel > MAX_STREAM_IDS_PER_TUNNEL_HARD_LIMIT {
            return Err(format!(
                "rtcp max_stream_ids_per_tunnel must be in 1..={}",
                MAX_STREAM_IDS_PER_TUNNEL_HARD_LIMIT
            ));
        }
        if self.limits.max_datagram_bytes == 0
            || self.limits.max_datagram_bytes > super::datagram::MAX_RTCP_DATAGRAM_BYTES
        {
            return Err(format!(
                "rtcp max_datagram_bytes must be in 1..={}",
                super::datagram::MAX_RTCP_DATAGRAM_BYTES
            ));
        }
        Ok(())
    }
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RtcpIdentityTrust {
    DnsTxtBootstrap,
    KeyDid,
    TrustedHostSnapshot,
    TrustedZoneSnapshot,
    MethodAuthorityCurrent,
}

impl fmt::Display for RtcpIdentityTrust {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::DnsTxtBootstrap => "dns_txt_bootstrap",
            Self::KeyDid => "key_did",
            Self::TrustedHostSnapshot => "trusted_host_snapshot",
            Self::TrustedZoneSnapshot => "trusted_zone_snapshot",
            Self::MethodAuthorityCurrent => "method_authority_current",
        };
        f.write_str(value)
    }
}

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
    pub identity_trust: Option<RtcpIdentityTrust>,
    pub canonical_device_id: Option<String>,
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

    pub fn set_security_config(&mut self, security: RtcpSecurityConfig) -> Result<(), String> {
        security.validate()?;
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.pending_handshakes =
                Arc::new(Semaphore::new(security.limits.max_pending_handshakes));
            inner.security = security;
            Ok(())
        } else {
            Err("set_security_config must be called before RTcp is shared".to_string())
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

    pub async fn close_tunnel_for_url(&self, url: &Url, reason: &str) {
        self.inner.close_tunnel_for_url(url, reason).await;
    }
}

// v4 anti-replay: tunnel_token lifetime. The signed token carries iat/exp;
// the responder applies JWT expiry leeway plus an explicit future-iat bound.
// A legitimate Hello thus tolerates bounded clock skew while keeping the
// replay window short.
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

// Stable process-local identity for compare-and-remove in RTcpTunnelMap.
// Tunnel keys identify a peer/path and are intentionally reused across
// reconnects; they cannot distinguish a superseded instance from its
// replacement.
static NEXT_RTCP_TUNNEL_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

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
    initiator_canonical_did: String,
    responder_did: String,
    responder_canonical_did: String,
    responder_trust: RtcpIdentityTrust,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RtcpAddressResolutionContext {
    target_did: DID,
    options: ResolveIpOptions,
}

impl RtcpAddressResolutionContext {
    fn without_device_info(
        target_did: DID,
        target_kind: ResolveIpTargetKind,
        zone_relation: ResolveIpZoneRelation,
    ) -> Self {
        Self {
            target_did,
            options: ResolveIpOptions::without_device_info(target_kind, zone_relation),
        }
    }

    fn verified_same_zone_device(
        target_did: DID,
        zone_did: DID,
        source: SameZoneEvidenceSource,
    ) -> Self {
        let evidence =
            VerifiedSameZoneDevice::from_verified_relation(target_did.clone(), zone_did, source);
        Self {
            target_did,
            options: ResolveIpOptions::verified_same_zone_device(evidence),
        }
    }

    async fn resolve_ips(&self) -> NSResult<Vec<std::net::IpAddr>> {
        resolve_ips_with_options(self.target_did.to_string().as_str(), self.options.clone()).await
    }
}

enum ResolvedHandshakeDocument {
    Device(DeviceDocument),
    Zone(ZoneDocument),
}

#[derive(Clone, Debug)]
struct ResolvedHandshakeIdentity {
    semantic_did: DID,
    canonical_dev_did: DID,
    ed25519_pk_der: [u8; 32],
    trust: RtcpIdentityTrust,
    resolver_id: Option<String>,
    address_resolution: RtcpAddressResolutionContext,
    // True when the semantic DID is a logical *device* name whose resolution
    // must obey the one-to-one binding to its canonical DEV DID: DeviceDocument
    // resolutions and DNS TXT bootstrap hints. False for direct did:dev
    // targets and for ZoneDocument targets -- a zone delegating to its default
    // gateway is zone addressing, not a second device name.
    binds_logical_name: bool,
}

impl ResolvedHandshakeIdentity {
    fn logical_name_binding(&self) -> Option<OutboundNameBinding> {
        if !self.binds_logical_name {
            return None;
        }
        Some(OutboundNameBinding {
            logical_did: self.semantic_did.to_string(),
            canonical_dev_did: self.canonical_dev_did.to_string(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifiedTunnelIdentity {
    logical_did: String,
    // The canonical did:dev derived from the verified document's default key.
    // It is the subject of the one-to-one binding arbitration: at any moment
    // a canonical DEV DID may belong to at most one verified logical name.
    canonical_dev_did: String,
    document_revision: DocumentRevision,
}

#[derive(Clone)]
struct PendingVerifiedCacheEntry {
    did: DID,
    document: EncodedDocument,
    identity: VerifiedTunnelIdentity,
}

struct VerifiedSourceDevice {
    source_device_id: String,
    canonical_dev_did: DID,
    source_device_info: Option<RTcpSourceDeviceInfo>,
    public_key: DecodingKey,
    identity_trust: RtcpIdentityTrust,
    // A document that passed name-client's expected-owner verification.  It is
    // deliberately not cached yet: the responder first requires the peer to
    // prove possession of the device key and pass application authorization.
    verified_cache_entry: Option<PendingVerifiedCacheEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AuthorityConfirmationTicket {
    generation: u64,
    document_revision: DocumentRevision,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AuthorityNegativeState {
    completed_at: u64,
    generation: u64,
    reason: String,
    rejected_revision: Option<DocumentRevision>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AuthorityConfirmationState {
    InFlight(AuthorityConfirmationTicket),
    Confirmed {
        completed_at: u64,
        document_revision: DocumentRevision,
    },
    Negative(AuthorityNegativeState),
    Unavailable {
        completed_at: u64,
        document_revision: DocumentRevision,
    },
}

struct HandshakeRateState {
    tokens: f64,
    last_refill: Instant,
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

fn canonical_dev_did_from_ed25519_pk(ed25519_pk_der: &[u8; 32]) -> DID {
    let pkx = URL_SAFE_NO_PAD.encode(ed25519_pk_der);
    DID::new("dev", &pkx)
}

struct RTcpInner {
    tunnel_map: RTcpTunnelMap,
    stream_helper: RTcpStreamBuildHelper,
    listener: RTcpListenerRef,

    bind_addr: String,
    reuse_address: bool,
    this_device_did: DID, //name or did
    this_device_dev_did: DID,
    this_device_ed25519_sk: Option<EncodingKey>,
    this_device_doc_jwt: Option<String>,
    this_owner_did: Option<DID>,
    this_zone_did: Option<DID>,
    security: RtcpSecurityConfig,
    pending_handshakes: Arc<Semaphore>,
    handshake_rates: Arc<Mutex<HashMap<std::net::IpAddr, HandshakeRateState>>>,
    authority_confirmation_slots: Arc<Semaphore>,
    // Used by create_tunnel to build a bootstrap stream through the tunnel
    // framework when the stack id carries a `params@remote` prefix. None means
    // only direct TCP bootstrap is available (backward compatible path).
    tunnel_manager: Option<TunnelManager>,
    // v4: reject replayed Hello tokens by their embedded nonce.
    nonce_cache: NonceCache,
    // Coalesces concurrent create_tunnel calls after canonical target
    // resolution. Waiters re-check tunnel_map after the active creator exits.
    create_flights: RTcpCreateFlights,
}

struct DirectTunnelAttempt {
    remote_addr: SocketAddr,
    tunnel: RTcpTunnel,
}

#[derive(Clone, Default)]
struct RTcpCreateFlights {
    active: Arc<std::sync::Mutex<HashSet<String>>>,
    notify: Arc<Notify>,
}

struct RTcpCreateFlightPermit {
    key: String,
    flights: RTcpCreateFlights,
}

impl RTcpCreateFlights {
    async fn acquire(&self, key: String) -> RTcpCreateFlightPermit {
        loop {
            // Enable the waiter before checking the set so notify_waiters()
            // cannot be lost if the active creator exits between the check
            // and await.
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let acquired = self
                .active
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(key.clone());
            if acquired {
                return RTcpCreateFlightPermit {
                    key,
                    flights: self.clone(),
                };
            }
            notified.await;
        }
    }
}

impl Drop for RTcpCreateFlightPermit {
    fn drop(&mut self) {
        self.flights
            .active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.key);
        self.flights.notify.notify_waiters();
    }
}

struct EstablishedInboundTunnel {
    tunnel: RTcpTunnel,
    tunnel_key: String,
    source_device_id: String,
    source_addr: SocketAddr,
    registration: InboundTunnelRegistration,
    authority_confirmation: Option<(DID, String, std::net::IpAddr, DocumentRevision)>,
}

impl Drop for RTcpInner {
    fn drop(&mut self) {
        log::debug!("RTcpInner {} drop", self.this_device_did.to_string());
    }
}

impl RTcpInner {
    fn configure_tcp_keepalive(stream: &TcpStream) -> std::io::Result<()> {
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(30))
            .with_interval(Duration::from_secs(10));
        socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive)
    }

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
                        "parsed non-authoritative bootstrap hint for {} as {} from {} TXT DEV (JWT signature intentionally not trusted)",
                        remote_did.to_string(),
                        dev_did.to_string(),
                        web_host
                    );
                    return Ok(Some(ResolvedHandshakeIdentity {
                        semantic_did: remote_did.clone(),
                        canonical_dev_did: dev_did,
                        ed25519_pk_der: exchange_key,
                        trust: RtcpIdentityTrust::DnsTxtBootstrap,
                        resolver_id: Some(format!("dns-txt:{}", web_host)),
                        address_resolution: RtcpAddressResolutionContext::without_device_info(
                            remote_did.clone(),
                            ResolveIpTargetKind::Unknown,
                            ResolveIpZoneRelation::Unknown,
                        ),
                        binds_logical_name: true,
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
                            semantic_did: remote_did.clone(),
                            canonical_dev_did: dev_did,
                            ed25519_pk_der: exchange_key,
                            trust: RtcpIdentityTrust::DnsTxtBootstrap,
                            resolver_id: Some(format!("dns-txt:{}", web_host)),
                            address_resolution: RtcpAddressResolutionContext::without_device_info(
                                remote_did.clone(),
                                ResolveIpTargetKind::Unknown,
                                ResolveIpZoneRelation::Unknown,
                            ),
                            binds_logical_name: true,
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

    // Returns the exchange key together with the authority-validated target
    // document kind. The parsed document is also used to derive the address
    // resolution scope without consulting DeviceInfo.
    fn exchange_key_from_resolved_document(
        resolved: &ResolvedDocument,
    ) -> Result<([u8; 32], ResolvedHandshakeDocument), String> {
        let document_value = resolved
            .document
            .clone()
            .to_json_value()
            .map_err(|e| format!("decode resolved DID document failed: {}", e))?;
        let (exchange_key, target_document) = if document_value.get("device_type").is_some() {
            let device_document = DeviceDocument::decode(&resolved.document, None)
                .map_err(|e| format!("decode resolved DeviceDocument failed: {}", e))?;
            let exchange_key = device_document.get_exchange_key(None);
            (
                exchange_key,
                ResolvedHandshakeDocument::Device(device_document),
            )
        } else if document_value.get("hostname").is_some() {
            let zone_document = ZoneDocument::decode(&resolved.document, None)
                .map_err(|e| format!("decode resolved ZoneDocument failed: {}", e))?;
            let exchange_key = zone_document
                .get_default_zone_gateway()
                .and_then(|gateway| zone_document.get_device_document(&gateway))
                .and_then(|device| device.get_exchange_key(None));
            (exchange_key, ResolvedHandshakeDocument::Zone(zone_document))
        } else {
            return Err("resolved DID document is neither DeviceDocument nor ZoneDocument".into());
        };
        let (_, jwk) =
            exchange_key.ok_or_else(|| "resolved DID document has no exchange key".to_string())?;
        let key = jwk_to_ed25519_pk(&jwk)
            .map_err(|e| format!("decode resolved Ed25519 exchange key failed: {}", e))?;
        Ok((key, target_document))
    }

    fn address_resolution_for_document(
        &self,
        target_did: &DID,
        target_document: &ResolvedHandshakeDocument,
    ) -> RtcpAddressResolutionContext {
        match target_document {
            ResolvedHandshakeDocument::Device(device_document) => {
                let Some(local_zone_did) = self.this_zone_did.as_ref() else {
                    return RtcpAddressResolutionContext::without_device_info(
                        target_did.clone(),
                        ResolveIpTargetKind::Device,
                        ResolveIpZoneRelation::Unknown,
                    );
                };
                let Some(target_zone_did) = device_document.zone_did.as_ref() else {
                    return RtcpAddressResolutionContext::without_device_info(
                        target_did.clone(),
                        ResolveIpTargetKind::Device,
                        ResolveIpZoneRelation::Unknown,
                    );
                };
                if target_zone_did != local_zone_did {
                    return RtcpAddressResolutionContext::without_device_info(
                        target_did.clone(),
                        ResolveIpTargetKind::Device,
                        ResolveIpZoneRelation::CrossZone,
                    );
                }
                let Some(local_owner_did) = self.this_owner_did.as_ref() else {
                    return RtcpAddressResolutionContext::without_device_info(
                        target_did.clone(),
                        ResolveIpTargetKind::Device,
                        ResolveIpZoneRelation::Unknown,
                    );
                };
                if device_document.owner != *local_owner_did {
                    return RtcpAddressResolutionContext::without_device_info(
                        target_did.clone(),
                        ResolveIpTargetKind::Device,
                        ResolveIpZoneRelation::CrossZone,
                    );
                }

                RtcpAddressResolutionContext::verified_same_zone_device(
                    target_did.clone(),
                    local_zone_did.clone(),
                    SameZoneEvidenceSource::VerifiedHandshakeIdentity,
                )
            }
            ResolvedHandshakeDocument::Zone(zone_document) => {
                let zone_relation = match self.this_zone_did.as_ref() {
                    Some(local_zone_did) if zone_document.id == *local_zone_did => {
                        ResolveIpZoneRelation::SameZone
                    }
                    Some(_) => ResolveIpZoneRelation::CrossZone,
                    None => ResolveIpZoneRelation::Unknown,
                };
                RtcpAddressResolutionContext::without_device_info(
                    target_did.clone(),
                    ResolveIpTargetKind::Zone,
                    zone_relation,
                )
            }
        }
    }

    fn authority_error_allows_txt_bootstrap(err: &NSError) -> bool {
        matches!(
            err,
            NSError::Failed(_)
                | NSError::InvalidState(_)
                | NSError::VerifyAndPromoteUnavailable(_)
                | NSError::DNSProtoError(_)
        )
    }

    async fn resolve_handshake_identity(
        &self,
        remote_did: &DID,
    ) -> Result<ResolvedHandshakeIdentity, String> {
        validate_rtcp_hostname_form_did(remote_did, "rtcp handshake did")?;
        debug!(
            "resolve handshake identity for remote device {}",
            remote_did.to_string()
        );

        if let Some(exchange_key) = remote_did.get_ed25519_auth_key() {
            let canonical_dev_did = canonical_dev_did_from_ed25519_pk(&exchange_key);
            return Ok(ResolvedHandshakeIdentity {
                semantic_did: remote_did.clone(),
                canonical_dev_did,
                ed25519_pk_der: exchange_key,
                trust: RtcpIdentityTrust::KeyDid,
                resolver_id: None,
                address_resolution: RtcpAddressResolutionContext::without_device_info(
                    remote_did.clone(),
                    ResolveIpTargetKind::Device,
                    ResolveIpZoneRelation::Unknown,
                ),
                binds_logical_name: false,
            });
        }

        let mut policy = ResolvePolicy::default();
        policy.allow_self_signed_when_missing = false;
        policy.allow_unverified_cache_when_unavailable = false;
        policy.allow_stale_cache = false;
        policy.source = match self.security.peer_identity.requirement {
            RtcpPeerIdentityRequirement::AuthorityCurrent => ResolveSourcePolicy::RemoteAuthority,
            RtcpPeerIdentityRequirement::TrustedSnapshot => ResolveSourcePolicy::LocalAndZone,
        };

        match resolve_did_ex(remote_did, None, policy).await {
            Ok(resolved) => {
                let metadata = &resolved.resolution_metadata;
                let trust = match self.security.peer_identity.requirement {
                    RtcpPeerIdentityRequirement::AuthorityCurrent => {
                        if metadata.evidence != Some(BodyEvidence::Anchored) {
                            return Err(format!(
                                "authority_current resolve for {} returned non-anchored evidence {:?}",
                                remote_did.to_string(),
                                metadata.evidence
                            ));
                        }
                        RtcpIdentityTrust::MethodAuthorityCurrent
                    }
                    RtcpPeerIdentityRequirement::TrustedSnapshot => {
                        if matches!(
                            metadata.cache_status,
                            Some(CacheStatus::Fallback | CacheStatus::ObservedFallback)
                        ) {
                            return Err(format!(
                                "trusted_snapshot resolve for {} returned stale/observed cache status {:?}",
                                remote_did.to_string(),
                                metadata.cache_status
                            ));
                        }
                        match metadata.evidence {
                            Some(BodyEvidence::Anchored) => {}
                            Some(BodyEvidence::NeedProof)
                                if metadata.verification_status
                                    == Some(VerificationStatus::Passed) => {}
                            other => {
                                return Err(format!(
                                    "trusted_snapshot resolve for {} returned untrusted evidence {:?}/{:?}",
                                    remote_did.to_string(),
                                    other,
                                    metadata.verification_status
                                ));
                            }
                        }
                        if metadata.cache_status == Some(CacheStatus::ZoneHit)
                            || metadata.source == Some(UpdateSource::ZoneResolver)
                        {
                            RtcpIdentityTrust::TrustedZoneSnapshot
                        } else {
                            RtcpIdentityTrust::TrustedHostSnapshot
                        }
                    }
                };
                let (exchange_key, target_document) =
                    Self::exchange_key_from_resolved_document(&resolved)?;
                let canonical_dev_did = canonical_dev_did_from_ed25519_pk(&exchange_key);
                let address_resolution =
                    self.address_resolution_for_document(remote_did, &target_document);
                let binds_logical_name =
                    matches!(target_document, ResolvedHandshakeDocument::Device(_));
                info!(
                    "resolved RTCP peer {} as {} with trust {} via {:?}",
                    remote_did.to_string(),
                    canonical_dev_did.to_string(),
                    trust,
                    metadata.resolver_id
                );
                Ok(ResolvedHandshakeIdentity {
                    semantic_did: remote_did.clone(),
                    canonical_dev_did,
                    ed25519_pk_der: exchange_key,
                    trust,
                    resolver_id: metadata.resolver_id.clone(),
                    address_resolution,
                    binds_logical_name,
                })
            }
            Err(primary_err) => {
                let primary_err_str = primary_err.to_string();
                warn!(
                    "resolve RTCP peer {} with {:?} policy failed: {}",
                    remote_did.to_string(),
                    self.security.peer_identity.requirement,
                    primary_err
                );
                if self.security.peer_identity.dns_txt_bootstrap
                    && remote_did.method == "web"
                    && Self::authority_error_allows_txt_bootstrap(&primary_err)
                {
                    match Self::resolve_handshake_identity_by_web_name_info(remote_did).await {
                        Ok(Some(identity)) => {
                            warn!(
                                "using non-authoritative DNS TXT bootstrap for RTCP peer {} as {}",
                                remote_did.to_string(),
                                identity.canonical_dev_did.to_string()
                            );
                            return Ok(identity);
                        }
                        Ok(None) => {
                            return Err(format!(
                                "{}; non-authoritative DNS TXT bootstrap has no DEV/PKX",
                                primary_err_str
                            ));
                        }
                        Err(fallback_err) => {
                            return Err(format!(
                                "{}; non-authoritative DNS TXT bootstrap failed: {}",
                                primary_err_str, fallback_err
                            ));
                        }
                    }
                }
                Err(primary_err_str)
            }
        }
    }

    async fn resolve_remote_tunnel_identity(
        &self,
        remote_did: &DID,
    ) -> TunnelResult<ResolvedHandshakeIdentity> {
        self.resolve_handshake_identity(remote_did)
            .await
            .map_err(|e| {
                TunnelError::DocumentError(format!(
                    "resolve remote device {} canonical did:dev failed: {}",
                    remote_did.to_string(),
                    e
                ))
            })
    }

    async fn resolve_remote_tunnel_dev_did(&self, remote_did: &DID) -> TunnelResult<DID> {
        let identity = self.resolve_remote_tunnel_identity(remote_did).await?;
        let canonical_dev_did = identity.canonical_dev_did;
        if identity.semantic_did.to_string() != canonical_dev_did.to_string() {
            debug!(
                "rtcp remote {} resolved to canonical tunnel device {}",
                remote_did.to_string(),
                canonical_dev_did.to_string()
            );
        }
        Ok(canonical_dev_did)
    }

    fn format_tunnel_key(
        &self,
        remote_dev_did: &DID,
        bootstrap_stream_url: Option<&str>,
    ) -> String {
        match bootstrap_stream_url {
            Some(bootstrap_url) => format!(
                "{}_{}|bootstrap={}",
                self.this_device_dev_did.to_string(),
                remote_dev_did.to_string(),
                bootstrap_url
            ),
            None => format!(
                "{}_{}",
                self.this_device_dev_did.to_string(),
                remote_dev_did.to_string()
            ),
        }
    }

    fn validate_hello_target(
        token_to: &str,
        token_canonical_to: &str,
        hello_to_id: &str,
        _this_host: &str,
        this_dev_did: &DID,
    ) -> Result<(), String> {
        // Signed identity bindings must compare semantic DIDs, not their
        // bridge hostnames. `to_host_name()` depends on the process-local
        // web3 bridge config, so the same did:bns value may map to different
        // hosts on an OOD and its SN.
        let token_to_did = DID::from_str(token_to)
            .map_err(|e| format!("token.to {} is not a valid DID: {}", token_to, e))?;
        let hello_to_did = DID::from_str(hello_to_id)
            .map_err(|e| format!("Hello.to_id {} is not a valid DID: {}", hello_to_id, e))?;
        if token_to_did != hello_to_did {
            return Err(format!(
                "signed token.to {} does not match Hello.to_id {}",
                token_to, hello_to_id
            ));
        }
        let canonical_to = DID::from_str(token_canonical_to).map_err(|e| {
            format!(
                "canonical_to {} is not a valid DID: {}",
                token_canonical_to, e
            )
        })?;
        if canonical_to != *this_dev_did {
            return Err(format!(
                "signed canonical_to {} is not this device {}",
                canonical_to.to_string(),
                this_dev_did.to_string()
            ));
        }

        // A semantic alias need not be configured as this stack's local DID.
        // Its signed canonical binding above is the authoritative target
        // check; the initiator will additionally verify HelloAck using the
        // key from which canonical_to was derived.
        Ok(())
    }

    fn validate_hello_signed_bindings(
        claims: &TunnelTokenPayload,
        hello: &RTcpHelloBody,
    ) -> Result<(), String> {
        let claims_from = DID::from_str(&claims.from)
            .map_err(|e| format!("invalid token.from {}: {}", claims.from, e))?;
        let hello_from = DID::from_str(&hello.from_id)
            .map_err(|e| format!("invalid Hello.from_id {}: {}", hello.from_id, e))?;
        if claims_from != hello_from {
            return Err(format!(
                "token.from {} does not match Hello.from_id {}",
                claims.from, hello.from_id
            ));
        }
        if claims.listen_port != hello.my_port {
            return Err(format!(
                "signed listen_port {} does not match Hello.my_port {}",
                claims.listen_port, hello.my_port
            ));
        }
        Ok(())
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
        responder_identity: &ResolvedHandshakeIdentity,
        remote_addr: SocketAddr,
    ) -> Result<DirectTunnelAttempt, String> {
        let remote_device_id = responder_identity.semantic_did.to_string();
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
        if let Err(e) = Self::configure_tcp_keepalive(&tunnel_stream) {
            debug!("cannot configure TCP keepalive for {}: {}", remote_addr, e);
        }

        let local_addr = tunnel_stream.local_addr().ok();
        let peer_addr = tunnel_stream.peer_addr().ok();

        let state = self
            .generate_tunnel_token_for_identity(responder_identity.clone())
            .map_err(|e| {
                let msg = format!("generate tunnel token error: {}, {}", remote_device_id, e);
                error!("{}", msg);
                msg
            })?;
        let responder_trust = state.responder_trust;
        let responder_canonical_did = DID::from_str(&state.responder_canonical_did)
            .map_err(|e| format!("invalid canonical responder DID: {}", e))?;
        let initiator_did = self.this_device_did.to_string();

        let addr: SocketAddr = self.bind_addr.parse().unwrap();
        let hello_package = RTcpHelloPackage::new(
            0,
            self.this_device_did.to_string(),
            remote_device_id.clone(),
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

        // v4 key confirmation: read plaintext HelloAck, verify the
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

        let tunnel = RTcpTunnel::new(
            self.stream_helper.clone(),
            self.this_device_did.clone(),
            remote_stack,
            responder_identity.address_resolution.clone(),
            true,
            encrypted_stream,
            peer_addr,
            None,
            aes_key,
            &self.security.limits,
            self.listener.clone(),
        );
        tunnel.set_identity(&responder_canonical_did, responder_trust);
        Ok(DirectTunnelAttempt {
            remote_addr,
            tunnel,
        })
    }

    pub fn new(
        this_device_did: DID,
        bind_addr: String,
        private_key_pkcs8_bytes: Option<[u8; 48]>,
        this_device_doc_jwt: Option<String>,
        listener: RTcpListenerRef,
    ) -> RTcpInner {
        // v4 handshake: the device's long-term Ed25519 key is used only
        // to sign Hello / HelloAck JWTs. ECDH is run between freshly-
        // generated ephemeral X25519 keys on each side, so there is no
        // long-term X25519 secret to keep around any more. Dropping the
        // static X25519 key gives session forward secrecy against future
        // Ed25519 key exposure.
        let this_device_ed25519_sk = private_key_pkcs8_bytes
            .as_ref()
            .map(|bytes| EncodingKey::from_ed_der(bytes));
        let this_device_dev_did = private_key_pkcs8_bytes
            .as_ref()
            .map(|bytes| DID::new("dev", &encode_ed25519_pkcs8_sk_to_pk(bytes)))
            .unwrap_or_else(|| {
                if this_device_did.method != "dev" {
                    warn!(
                        "rtcp {} has no private key; tunnel key local side cannot be canonicalized to did:dev",
                        this_device_did.to_string()
                    );
                }
                this_device_did.clone()
            });
        let local_device_document = this_device_doc_jwt.as_ref().and_then(|jwt| {
            DeviceDocument::decode(&EncodedDocument::Jwt(jwt.clone()), None)
                .map_err(|e| {
                    warn!(
                        "cannot inspect local RTCP device document for admission anchors: {}",
                        e
                    )
                })
                .ok()
        });
        let this_owner_did = local_device_document
            .as_ref()
            .map(|document| document.owner.clone());
        let this_zone_did = local_device_document
            .as_ref()
            .and_then(|document| document.zone_did.clone());
        let security = RtcpSecurityConfig::default();

        let result = RTcpInner {
            tunnel_map: RTcpTunnelMap::new(),
            stream_helper: RTcpStreamBuildHelper::new(),

            listener,
            bind_addr,
            reuse_address: false,
            this_device_did,
            this_device_dev_did,
            this_device_ed25519_sk, //for sign tunnel token
            this_device_doc_jwt,
            this_owner_did,
            this_zone_did,
            pending_handshakes: Arc::new(Semaphore::new(security.limits.max_pending_handshakes)),
            handshake_rates: Arc::new(Mutex::new(HashMap::new())),
            security,
            authority_confirmation_slots: Arc::new(Semaphore::new(16)),
            tunnel_manager: None,
            nonce_cache: NonceCache::new(),
            create_flights: RTcpCreateFlights::default(),
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
        rand::rng().fill(&mut nonce_bytes);
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
        let remote_did = DID::from_str(remote_hostname.as_str()).map_err(|op| {
            TunnelError::DocumentError(format!("invalid remote device is not did: {}", op))
        })?;

        let responder_identity =
            self.resolve_handshake_identity(&remote_did)
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
        self.generate_tunnel_token_for_identity(responder_identity)
    }

    fn generate_tunnel_token_for_identity(
        &self,
        responder_identity: ResolvedHandshakeIdentity,
    ) -> Result<InitiatorHandshakeState, TunnelError> {
        let ed25519_sk = self.this_device_ed25519_sk.as_ref().ok_or_else(|| {
            TunnelError::DocumentError("this device ed25519 sk is none".to_string())
        })?;
        let responder_did = responder_identity.semantic_did.to_string();
        let responder_ed25519_pk_der = responder_identity.ed25519_pk_der.to_vec();
        let responder_canonical_did = responder_identity.canonical_dev_did.to_string();
        let responder_trust = responder_identity.trust;

        let (my_secret, my_public_bytes, my_public_hex) = Self::fresh_ephemeral();

        // v4: embed a fresh 16-byte random nonce and use a short exp
        // (default 60s). The responder keeps a nonce cache for the exp
        // window, so any captured token cannot be replayed as-is to stand
        // up a second tunnel. An attacker that replays an already-used
        // token will be rejected at the nonce check even before the key-
        // confirmation handshake kicks in.
        let nonce_hex = Self::fresh_nonce_hex();

        let now = buckyos_get_unix_timestamp();
        let listen_port = self
            .bind_addr
            .parse::<SocketAddr>()
            .map_err(|e| TunnelError::ReasonError(format!("invalid local RTCP bind: {}", e)))?
            .port();
        let tunnel_token_payload = TunnelTokenPayload {
            aud: RTCP_HELLO_AUD.to_string(),
            to: responder_did.clone(),
            canonical_to: responder_canonical_did.clone(),
            from: self.this_device_did.to_string(),
            listen_port,
            xpub: my_public_hex.clone(),
            iat: now,
            exp: now + TUNNEL_TOKEN_EXP_SECS,
            nonce: nonce_hex.clone(),
        };
        debug!(
            "generated v4 hello token for {} -> {} ({})",
            tunnel_token_payload.from, tunnel_token_payload.to, tunnel_token_payload.canonical_to
        );
        let tunnel_token = Self::sign_jwt(ed25519_sk, &tunnel_token_payload)?;

        Ok(InitiatorHandshakeState {
            token: tunnel_token,
            my_secret,
            my_xpub_bytes: my_public_bytes,
            my_xpub_hex: my_public_hex,
            my_nonce_hex: nonce_hex,
            responder_ed25519_pk_der,
            initiator_canonical_did: self.this_device_dev_did.to_string(),
            responder_did,
            responder_canonical_did,
            responder_trust,
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
        responder_semantic_did: &str,
    ) -> Result<(String, EphemeralSecret, [u8; 32], String), TunnelError> {
        let ed25519_sk = self.this_device_ed25519_sk.as_ref().ok_or_else(|| {
            TunnelError::DocumentError("this device ed25519 sk is none".to_string())
        })?;
        let (my_secret, my_public_bytes, my_public_hex) = Self::fresh_ephemeral();
        let nonce_hex = Self::fresh_nonce_hex();

        let now = buckyos_get_unix_timestamp();
        let payload = TunnelAckTokenPayload {
            aud: RTCP_HELLO_ACK_AUD.to_string(),
            to: initiator_hostname.to_owned(),
            from: responder_semantic_did.to_owned(),
            xpub: my_public_hex,
            peer_xpub: peer_pub_hex.to_owned(),
            iat: now,
            exp: now + TUNNEL_TOKEN_EXP_SECS,
            nonce: nonce_hex.clone(),
        };
        let token = Self::sign_jwt(ed25519_sk, &payload)?;
        Ok((token, my_secret, my_public_bytes, nonce_hex))
    }

    fn jwt_validation_for(aud: &str) -> Validation {
        // Explicit leeway pinned to JWT_LEEWAY_SECS so the nonce-cache
        // retention window stays aligned with the signature acceptance
        // window (see the v4 anti-replay contract).
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.leeway = JWT_LEEWAY_SECS;
        validation.set_audience(&[aud]);
        validation.set_required_spec_claims(&["exp", "iat", "aud"]);
        validation
    }

    fn validate_token_times(iat: u64, exp: u64) -> Result<(), TunnelError> {
        let now = buckyos_get_unix_timestamp();
        if exp < iat {
            return Err(TunnelError::DocumentError(
                "token exp is earlier than iat".to_string(),
            ));
        }
        if exp.saturating_sub(iat) > TUNNEL_TOKEN_EXP_SECS {
            return Err(TunnelError::DocumentError(format!(
                "token lifetime exceeds {} seconds",
                TUNNEL_TOKEN_EXP_SECS
            )));
        }
        if iat > now.saturating_add(JWT_LEEWAY_SECS) {
            return Err(TunnelError::DocumentError(
                "token iat is too far in the future".to_string(),
            ));
        }
        Ok(())
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
        Self::validate_token_times(payload.iat, payload.exp)?;
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
        Self::validate_token_times(payload.iat, payload.exp)?;
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

    // A definite verification rejection may never degrade to anonymous
    // KeyDid admission. Only resolver/dependency unavailability is eligible,
    // and only when inbound_admission.anonymous is explicitly Allow.
    fn is_definite_verify_rejection(err: &ResolveVerifyError) -> bool {
        match err {
            ResolveVerifyError::Resolve(_) => false,
            ResolveVerifyError::Verify(err) => matches!(
                err,
                VerifyError::InvalidDocument { .. }
                    | VerifyError::DocumentIdMismatch { .. }
                    | VerifyError::OwnerMismatch { .. }
                    | VerifyError::DetachedOwnerRejected { .. }
                    | VerifyError::SignatureRejected { .. }
                    | VerifyError::RevokedByOwnerPolicy { .. }
                    | VerifyError::RejectedByNegativeState { .. }
            ),
        }
    }

    // RTCP owns anti-rollback admission policy.  A successfully verified
    // document can still be unusable when it is older than this Host/Zone's
    // accepted high-water mark, conflicts at the same iat, or a fresh authority
    // receipt identifies another current document.  Missing/Expired/Migrated
    // authority status remains eligible for the bootstrap/offline behavior used
    // by unpublished logical DeviceDocuments.
    fn freshness_rejection(verified: &VerifiedDidDocument) -> Option<String> {
        match &verified.freshness.local {
            LocalFreshness::OlderThanLatestKnown {
                scope,
                candidate,
                latest,
            } => {
                return Some(format!(
                    "candidate {:?} is older than {:?} in {} scope",
                    candidate, latest, scope
                ));
            }
            LocalFreshness::ConflictAtSameRevision {
                scope,
                expected,
                candidate,
            } => {
                return Some(format!(
                    "candidate {:?} conflicts with {:?} in {} scope",
                    candidate, expected, scope
                ));
            }
            _ => {}
        }

        match &verified.freshness.authority {
            AuthorityFreshness::NotCurrent {
                reason:
                    AuthorityNotCurrentReason::DifferentDocument | AuthorityNotCurrentReason::Superseded,
                current_document_iat,
                ..
            } => Some(format!(
                "authority rejected candidate as current (current document iat {:?})",
                current_document_iat
            )),
            _ => None,
        }
    }

    // A remote authority lookup for an unpublished logical DeviceDocument
    // reports NotCurrent(NegativeStatus(Missing)).  That is not a revocation:
    // the OwnerDocument can still authenticate the candidate and the trusted
    // Host/Zone snapshot remains the admission evidence.  Only an authority
    // receipt proving that another document is current is a definite reason to
    // tear down tunnels here.  Terminal negative states are returned as
    // VerifyError::RejectedByNegativeState and handled by the error branch in
    // maybe_spawn_authority_confirmation.
    fn authority_confirmation_rejects_snapshot(authority: &AuthorityFreshness) -> bool {
        matches!(
            authority,
            AuthorityFreshness::NotCurrent {
                reason: AuthorityNotCurrentReason::DifferentDocument
                    | AuthorityNotCurrentReason::Superseded
                    | AuthorityNotCurrentReason::NegativeStatus(
                        DocumentStatus::Revoked | DocumentStatus::Tombstoned,
                    ),
                ..
            }
        )
    }

    // A remembered authority Negative is fail-closed. Recovery is deliberately
    // synchronous and exceptional: only a fresh RemoteAuthority answer whose
    // exact DocumentRevision matches the presented candidate may clear it.
    // The normal LocalAndZone path is not allowed to clear or age out this
    // state, even if name-client's surrounding cache state changes.
    async fn recover_negative_authority_candidate(
        &self,
        logical_did: &DID,
        candidate_jwt: &str,
    ) -> Result<(), TunnelError> {
        let identity_key = logical_did.to_string();
        let Some(negative) = self
            .tunnel_map
            .authority_negative_snapshot(&identity_key)
            .await
        else {
            return Ok(());
        };

        let candidate_document = EncodedDocument::Jwt(candidate_jwt.to_string());
        let candidate_revision = DocumentRevision::of(&candidate_document).ok_or_else(|| {
            TunnelError::DocumentError(format!(
                "authority Negative recovery candidate {} has no document revision",
                identity_key
            ))
        })?;
        info!(
            "RTCP authority Negative recovery check for {} revision {:?}: state at {}, reason {}",
            identity_key, candidate_revision, negative.completed_at, negative.reason
        );

        let permit = self
            .authority_confirmation_slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| {
                TunnelError::DocumentError(format!(
                    "authority recovery unavailable for {}: confirmation slots closed",
                    identity_key
                ))
            })?;
        let _permit = permit;
        let mut policy = ResolvePolicy::default();
        policy.source = ResolveSourcePolicy::RemoteAuthority;
        policy.allow_stale_cache = false;
        policy.allow_unverified_cache_when_unavailable = false;
        policy.allow_self_signed_when_missing = false;
        let budget = Duration::from_secs(self.security.limits.handshake_timeout_secs.max(1));
        let resolved = timeout(
            budget,
            resolve_did_ex(logical_did, Some(DidDocType::Device), policy),
        )
        .await
        .map_err(|_| {
            TunnelError::DocumentError(format!(
                "authority recovery for {} timed out after {:?}; Negative remains active",
                identity_key, budget
            ))
        })?
        .map_err(|err| {
            TunnelError::DocumentError(format!(
                "authority recovery for {} failed: {}; Negative remains active",
                identity_key, err
            ))
        })?;

        if resolved.resolution_metadata.evidence != Some(BodyEvidence::Anchored) {
            return Err(TunnelError::DocumentError(format!(
                "authority recovery for {} returned non-anchored evidence {:?}",
                identity_key, resolved.resolution_metadata.evidence
            )));
        }
        let authority_revision = DocumentRevision::of(&resolved.document).ok_or_else(|| {
            TunnelError::DocumentError(format!(
                "authority Current document for {} has no document revision",
                identity_key
            ))
        })?;
        if authority_revision != candidate_revision {
            return Err(TunnelError::DocumentError(format!(
                "authority Negative rejects {} candidate revision {:?}; Current revision is {:?}",
                identity_key, candidate_revision, authority_revision
            )));
        }

        if !self
            .tunnel_map
            .clear_authority_negative_if_current(
                &identity_key,
                negative.generation,
                &candidate_revision,
                buckyos_get_unix_timestamp(),
            )
            .await
        {
            return Err(TunnelError::DocumentError(format!(
                "authority state changed while recovering {}; retry required",
                identity_key
            )));
        }
        Ok(())
    }

    fn commit_verified_cache_entry(
        entry: Option<PendingVerifiedCacheEntry>,
    ) -> NSResult<Option<(VerifiedTunnelIdentity, CacheWriteOutcome)>> {
        let Some(entry) = entry else {
            return Ok(None);
        };
        let client = GLOBAL_NAME_CLIENT
            .get()
            .ok_or_else(|| NSError::InvalidState("name client not initialized".to_string()))?;
        let outcome =
            client.add_verified_cache(entry.did, Some(DidDocType::Device), entry.document)?;
        Ok(Some((entry.identity, outcome)))
    }

    fn parse_source_candidate(
        &self,
        hello_body: &RTcpHelloBody,
    ) -> Result<(DID, [u8; 32], Option<DeviceDocument>), TunnelError> {
        let from_did = DID::from_str(hello_body.from_id.as_str()).map_err(|e| {
            TunnelError::DocumentError(format!(
                "hello from_id {} is not a valid DID: {}",
                hello_body.from_id, e
            ))
        })?;
        validate_rtcp_hostname_form_did(&from_did, "rtcp hello from_id")
            .map_err(TunnelError::DocumentError)?;

        if let Some(device_doc_jwt) = hello_body.device_doc_jwt.as_ref() {
            let document =
                DeviceDocument::decode(&EncodedDocument::Jwt(device_doc_jwt.clone()), None)
                    .map_err(|e| {
                        TunnelError::DocumentError(format!(
                            "parse candidate device_doc_jwt failed: {}",
                            e
                        ))
                    })?;
            if document.id.to_string() != hello_body.from_id {
                return Err(TunnelError::DocumentError(format!(
                    "hello from_id {} not match device_doc_jwt id {}",
                    hello_body.from_id,
                    document.id.to_string()
                )));
            }
            if self.security.inbound_admission.named_min_relation == RtcpNamedMinRelation::SameZone
            {
                let expected_owner = self.this_owner_did.as_ref().ok_or_else(|| {
                    TunnelError::DocumentError(
                        "same_zone admission requires a local owner anchor".to_string(),
                    )
                })?;
                if document.owner != *expected_owner {
                    return Err(TunnelError::DocumentError(format!(
                        "candidate owner {} does not match local owner {}",
                        document.owner.to_string(),
                        expected_owner.to_string()
                    )));
                }
            }
            let default_key = document.get_default_key().ok_or_else(|| {
                TunnelError::DocumentError("device_doc_jwt missing default key".to_string())
            })?;
            let key = jwk_to_ed25519_pk(&default_key).map_err(|e| {
                TunnelError::DocumentError(format!(
                    "decode candidate device_doc_jwt public key failed: {}",
                    e
                ))
            })?;
            return Ok((from_did, key, Some(document)));
        }

        if from_did.method != "dev" {
            return Err(TunnelError::DocumentError(format!(
                "hello from_id {} is a logical name (not did:dev), device_doc_jwt is required",
                hello_body.from_id
            )));
        }
        let key = from_did.get_ed25519_auth_key().ok_or_else(|| {
            TunnelError::DocumentError(format!(
                "did:dev {} does not contain a valid Ed25519 key",
                from_did.to_string()
            ))
        })?;
        Ok((from_did, key, None))
    }

    fn trust_from_verified(verified: &VerifiedDidDocument) -> RtcpIdentityTrust {
        if matches!(
            verified.freshness.authority,
            AuthorityFreshness::Current { .. }
        ) {
            return RtcpIdentityTrust::MethodAuthorityCurrent;
        }
        match verified.validity.scope {
            LocalTrustScope::Zone => RtcpIdentityTrust::TrustedZoneSnapshot,
            _ => RtcpIdentityTrust::TrustedHostSnapshot,
        }
    }

    fn validate_named_relation(
        &self,
        device_document: &DeviceDocument,
        verified: &VerifiedDidDocument,
    ) -> Result<(), TunnelError> {
        match self.security.inbound_admission.named_min_relation {
            RtcpNamedMinRelation::Any => Ok(()),
            RtcpNamedMinRelation::KnownOwner => {
                if !verified.usable_as_authz_subject
                    || verified.authz_owner.is_none()
                    || verified.validity.owner_document_source.is_none()
                {
                    return Err(TunnelError::DocumentError(format!(
                        "verified identity {} has no trusted owner evidence",
                        verified.subject_did.to_string()
                    )));
                }
                Ok(())
            }
            RtcpNamedMinRelation::SameZone => {
                let expected_owner = self.this_owner_did.as_ref().ok_or_else(|| {
                    TunnelError::DocumentError(
                        "same_zone admission requires a local owner anchor".to_string(),
                    )
                })?;
                let expected_zone = self.this_zone_did.as_ref().ok_or_else(|| {
                    TunnelError::DocumentError(
                        "same_zone admission requires a local zone anchor".to_string(),
                    )
                })?;
                if !verified.usable_as_authz_subject
                    || verified.validity.owner_document_source.is_none()
                    || verified.authz_owner.as_ref() != Some(expected_owner)
                    || device_document.zone_did.as_ref() != Some(expected_zone)
                {
                    return Err(TunnelError::DocumentError(format!(
                        "verified identity {} is outside local owner/zone",
                        verified.subject_did.to_string()
                    )));
                }
                Ok(())
            }
        }
    }

    async fn resolve_source_device_info(
        &self,
        hello_body: &RTcpHelloBody,
        from_did: &DID,
        candidate_key: [u8; 32],
        candidate_document: Option<&DeviceDocument>,
    ) -> Result<VerifiedSourceDevice, TunnelError> {
        let canonical_dev_did = canonical_dev_did_from_ed25519_pk(&candidate_key);
        let from_public_key = DecodingKey::from_ed_der(&candidate_key);

        let Some(device_doc_jwt) = hello_body.device_doc_jwt.as_ref() else {
            return Ok(VerifiedSourceDevice {
                source_device_id: hello_body.from_id.clone(),
                canonical_dev_did,
                source_device_info: None,
                public_key: from_public_key,
                identity_trust: RtcpIdentityTrust::KeyDid,
                verified_cache_entry: None,
            });
        };

        let mut policy = ResolvePolicy::default();
        policy.source = ResolveSourcePolicy::LocalAndZone;
        policy.allow_stale_cache = true;
        policy.allow_unverified_cache_when_unavailable = false;
        policy.allow_self_signed_when_missing = false;
        let options = ResolveVerifyOptions {
            purpose: VerifyPurpose::AuthSubject,
            policy,
        };
        match resolve_and_verify_device_document_jwt(from_did, device_doc_jwt, &options).await {
            Ok((device_doc, verified)) => {
                if verified.subject_did.to_string() != hello_body.from_id {
                    return Err(TunnelError::DocumentError(format!(
                        "hello from_id {} not match verified device document id {}",
                        hello_body.from_id,
                        verified.subject_did.to_string()
                    )));
                }
                if let Some(reason) = Self::freshness_rejection(&verified) {
                    return Err(TunnelError::DocumentError(format!(
                        "device_doc_jwt for {} rejected by freshness policy: {}",
                        hello_body.from_id, reason
                    )));
                }
                let verified_key = device_doc
                    .get_default_key()
                    .ok_or_else(|| {
                        TunnelError::DocumentError(
                            "verified device document missing default key".to_string(),
                        )
                    })
                    .and_then(|jwk| {
                        jwk_to_ed25519_pk(&jwk).map_err(|e| {
                            TunnelError::DocumentError(format!(
                                "decode verified device public key failed: {}",
                                e
                            ))
                        })
                    })?;
                if verified_key != candidate_key {
                    return Err(TunnelError::DocumentError(
                        "verified device key differs from possession key".to_string(),
                    ));
                }

                self.validate_named_relation(&device_doc, &verified)?;

                let mut identity_trust = Self::trust_from_verified(&verified);
                if self
                    .tunnel_map
                    .authority_confirmed_revision(
                        &verified.subject_did.to_string(),
                        &verified.revision,
                    )
                    .await
                {
                    identity_trust = RtcpIdentityTrust::MethodAuthorityCurrent;
                }
                let verified_cache_entry = Some(PendingVerifiedCacheEntry {
                    did: verified.subject_did.clone(),
                    document: verified.document.clone(),
                    identity: VerifiedTunnelIdentity {
                        logical_did: verified.subject_did.to_string(),
                        canonical_dev_did: canonical_dev_did.to_string(),
                        document_revision: verified.revision.clone(),
                    },
                });
                Ok(VerifiedSourceDevice {
                    source_device_id: verified.subject_did.to_string(),
                    canonical_dev_did: canonical_dev_did.clone(),
                    source_device_info: Some(RTcpSourceDeviceInfo {
                        device_doc_jwt: Some(device_doc_jwt.clone()),
                        name: Some(device_doc.name.clone()),
                        owner: verified.authz_owner.map(|did| did.to_string()),
                        zone_did: device_doc.zone_did.map(|did| did.to_string()),
                        identity_trust: Some(identity_trust),
                        canonical_device_id: Some(canonical_dev_did.to_string()),
                    }),
                    public_key: from_public_key,
                    identity_trust,
                    verified_cache_entry,
                })
            }
            Err(err) if Self::is_definite_verify_rejection(&err) => {
                Err(TunnelError::DocumentError(format!(
                    "verify device_doc_jwt for {} rejected: {}",
                    hello_body.from_id, err
                )))
            }
            Err(err)
                if self.security.inbound_admission.anonymous == RtcpAnonymousAdmission::Allow =>
            {
                info!(
                    "RTCP named identity {} verification unavailable; admit only canonical key {} with KeyDid trust: {}",
                    hello_body.from_id,
                    canonical_dev_did.to_string(),
                    err
                );
                let _ = candidate_document;
                Ok(VerifiedSourceDevice {
                    source_device_id: canonical_dev_did.to_string(),
                    canonical_dev_did,
                    source_device_info: None,
                    public_key: from_public_key,
                    identity_trust: RtcpIdentityTrust::KeyDid,
                    verified_cache_entry: None,
                })
            }
            Err(err) => Err(TunnelError::DocumentError(format!(
                "verify device_doc_jwt for {} unavailable and anonymous admission is rejected: {}",
                hello_body.from_id, err
            ))),
        }
    }

    // v4 session-key derivation. Replaces the old SHA256(shared_secret)
    // construction with a real HKDF-Extract+Expand and binds the output
    // to the full handshake context, including:
    //   - protocol identifier ("buckyos-rtcp-v4") for domain separation,
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
        initiator_canonical_did: &str,
        responder_canonical_did: &str,
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
            initiator_canonical_did.as_bytes(),
            b"|",
            responder_canonical_did.as_bytes(),
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
        let mut aes_info = b"buckyos-rtcp-v4 aes256-key".to_vec();
        aes_info.extend_from_slice(&info_tail);
        hk.expand(&aes_info, &mut aes_key)
            .expect("HKDF expand for aes256-key must succeed for 32-byte output");

        let mut iv = [0u8; 16];
        let mut iv_info = b"buckyos-rtcp-v4 iv-salt".to_vec();
        iv_info.extend_from_slice(&info_tail);
        hk.expand(&iv_info, &mut iv)
            .expect("HKDF expand for iv-salt must succeed for 16-byte output");

        (aes_key, iv)
    }

    async fn admit_handshake_source(&self, ip: std::net::IpAddr) -> bool {
        const MAX_TRACKED_HANDSHAKE_IPS: usize = 4096;
        let now = Instant::now();
        let mut rates = self.handshake_rates.lock().await;
        if !rates.contains_key(&ip) && rates.len() >= MAX_TRACKED_HANDSHAKE_IPS {
            if let Some(oldest) = rates
                .iter()
                .min_by_key(|(_, state)| state.last_refill)
                .map(|(ip, _)| *ip)
            {
                rates.remove(&oldest);
            }
        }
        let state = rates.entry(ip).or_insert_with(|| HandshakeRateState {
            tokens: f64::from(self.security.limits.handshake_request_burst),
            last_refill: now,
        });
        let elapsed = now.duration_since(state.last_refill).as_secs_f64();
        state.tokens = (state.tokens
            + elapsed * f64::from(self.security.limits.handshake_requests_per_second))
        .min(f64::from(self.security.limits.handshake_request_burst));
        state.last_refill = now;
        if state.tokens < 1.0 {
            return false;
        }
        state.tokens -= 1.0;
        true
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
        crate::stack::try_enable_dual_stack(&socket, addr);
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
                let (stream, addr) = match rtcp_listener.accept().await {
                    Ok(value) => value,
                    Err(e) => {
                        error!("RTcp listener accept failed: {}", e);
                        continue;
                    }
                };
                debug!("RTcp stack accept new tcp stream from {}", addr.clone());

                let Some(initial_permit) = this.try_acquire_initial_handshake_permit(addr) else {
                    continue;
                };
                if let Err(e) = Self::configure_tcp_keepalive(&stream) {
                    debug!("cannot configure TCP keepalive for {}: {}", addr, e);
                }
                let this = this.clone();
                task::spawn(async move {
                    this.serve_connection_with_permit(stream, addr, initial_permit)
                        .await;
                });
            }
        });

        Ok(handle)
    }

    pub async fn serve_connection(self: &Arc<Self>, stream: TcpStream, addr: SocketAddr) {
        let Some(initial_permit) = self.try_acquire_initial_handshake_permit(addr) else {
            return;
        };
        self.serve_connection_with_permit(stream, addr, initial_permit)
            .await;
    }

    fn try_acquire_initial_handshake_permit(
        &self,
        addr: SocketAddr,
    ) -> Option<OwnedSemaphorePermit> {
        match self.pending_handshakes.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                warn!(
                    "reject RTcp connection from {}: pending initial-handshake quota exhausted",
                    addr
                );
                None
            }
        }
    }

    async fn serve_connection_with_permit(
        self: &Arc<Self>,
        stream: TcpStream,
        addr: SocketAddr,
        initial_permit: OwnedSemaphorePermit,
    ) {
        let deadline = Duration::from_secs(self.security.limits.handshake_timeout_secs);
        let established = match timeout(
            deadline,
            self.establish_connection(stream, addr, initial_permit),
        )
        .await
        {
            Ok(established) => established,
            Err(_) => {
                warn!(
                    "reject RTcp connection from {}: handshake deadline {:?} exceeded",
                    addr, deadline
                );
                return;
            }
        };

        let Some(established) = established else {
            return;
        };

        self.run_established_inbound(established).await;
    }

    async fn establish_connection(
        self: &Arc<Self>,
        mut stream: TcpStream,
        addr: SocketAddr,
        initial_permit: OwnedSemaphorePermit,
    ) -> Option<EstablishedInboundTunnel> {
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
            return None;
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
                // HelloStream only needs the shared quota while its first
                // packet is unclassified. A valid stream must not consume a
                // tunnel-handshake slot while it is delivered to its waiter.
                drop(initial_permit);
                self.on_new_stream(stream, session_key).await;
                None
            }
            RTcpTunnelPackage::Hello(hello_package) => {
                if !self.admit_handshake_source(addr.ip()).await {
                    warn!(
                        "reject RTcp tunnel handshake from {}: per-IP rate exceeded",
                        addr
                    );
                    return None;
                }
                debug!(
                    "RTcp stack {} accept new tunnel: {}, {} -> {}",
                    self.this_device_did.to_string(),
                    addr,
                    hello_package.body.from_id,
                    hello_package.body.to_id
                );

                // The initial-read permit becomes the tunnel-handshake permit
                // and remains scoped to this future. It is released as soon
                // as establishment returns, before the accepted tunnel enters
                // its long-running control read loop.
                let _handshake_permit = initial_permit;
                self.on_new_tunnel(stream, hello_package).await
            }
            _ => {
                error!("Unsupported first package type for rtcp stack: {}", addr);
                None
            }
        }
    }

    async fn run_established_inbound(self: &Arc<Self>, established: EstablishedInboundTunnel) {
        let EstablishedInboundTunnel {
            tunnel,
            tunnel_key,
            source_device_id,
            source_addr,
            registration,
            authority_confirmation,
        } = established;

        if !registration.accepted {
            RTcpTunnelMap::finish_authenticated_registration(registration).await;
            warn!(
                "reject rtcp tunnel from {} {} after verified-cache arbitration",
                source_device_id, source_addr
            );
            return;
        }

        // Publication is the final operation inside the handshake timeout.
        // Cleanup of replaced instances must not delay the new tunnel's read
        // loop, and cancellation of either cleanup task cannot unpublish the
        // newly accepted instance.
        task::spawn(async move {
            RTcpTunnelMap::finish_authenticated_registration(registration).await;
        });

        info!(
            "Tunnel {} accept from {} OK, instance {}, start running",
            source_device_id.as_str(),
            tunnel_key.as_str(),
            tunnel.instance_id()
        );

        if let Some((logical_did, candidate_jwt, source_ip, document_revision)) =
            authority_confirmation
        {
            let this = self.clone();
            task::spawn(async move {
                this.maybe_spawn_authority_confirmation(
                    logical_did,
                    candidate_jwt,
                    source_ip,
                    document_revision,
                )
                .await;
            });
        }

        tunnel.run().await;

        info!(
            "Tunnel {} instance {} end",
            tunnel_key.as_str(),
            tunnel.instance_id()
        );

        self.tunnel_map
            .remove_if_current(&tunnel_key, &tunnel)
            .await;
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

    async fn on_new_tunnel(
        self: &Arc<Self>,
        stream: TcpStream,
        hello_package: RTcpHelloPackage,
    ) -> Option<EstablishedInboundTunnel> {
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

        let Some(token) = hello_package.body.tunnel_token.as_ref() else {
            warn!(
                "reject rtcp tunnel from {}: hello.body.tunnel_token is none",
                source_addr_log
            );
            return None;
        };

        // I1 steps ①–②: parse the signed claims without verification only to
        // reject obvious binding mismatches. No resolver or network access is
        // allowed before possession proof.
        let unverified_claims = match decode_jwt_claim_without_verify(token).and_then(|value| {
            serde_json::from_value::<TunnelTokenPayload>(value)
                .map_err(|e| NSError::DecodeJWTError(e.to_string()))
        }) {
            Ok(claims) => claims,
            Err(e) => {
                warn!(
                    "reject rtcp tunnel from {}: parse tunnel_token claims failed: {}",
                    source_addr_log, e
                );
                return None;
            }
        };
        if let Err(err) =
            Self::validate_hello_signed_bindings(&unverified_claims, &hello_package.body)
        {
            warn!("reject rtcp tunnel from {}: {}", source_addr_log, err);
            return None;
        }
        let claimed_from = unverified_claims.from.clone();

        // I1 step ③: parse the candidate document/key and perform same-zone
        // string prefiltering. This is rejection-only; trust is established
        // later by name-client.
        let (claimed_source_did, candidate_key, candidate_document) =
            match self.parse_source_candidate(&hello_package.body) {
                Ok(candidate) => candidate,
                Err(e) => {
                    warn!(
                        "reject rtcp tunnel from {}: candidate identity invalid: {}",
                        source_addr_log, e
                    );
                    return None;
                }
            };
        let candidate_public_key = DecodingKey::from_ed_der(&candidate_key);

        // I1 step ④: prove possession before any LocalAndZone resolution.
        let (initiator_xpub_bytes, hello_payload) = match RTcpInner::verify_hello_token(
            token,
            &candidate_public_key,
            Some(claimed_from.as_str()),
        ) {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    "reject rtcp tunnel from {}: verify hello possession token error:{}",
                    source_addr_log, e
                );
                return None;
            }
        };

        // v4 anti-replay: every Hello token must bind this responder
        // and must not be replayed within its exp window.
        let this_host = self.this_device_did.to_host_name();
        if let Err(e) = Self::validate_hello_target(
            &hello_payload.to,
            &hello_payload.canonical_to,
            &hello_package.body.to_id,
            &this_host,
            &self.this_device_dev_did,
        ) {
            warn!(
                "reject rtcp tunnel from {}: token.to {} not accepted for this device {}: {}",
                source_addr_log, hello_payload.to, this_host, e
            );
            return None;
        }

        // A previously denied logical identity cannot re-enter through a
        // LocalAndZone snapshot. The only recovery path is an exact fresh
        // Current document from RemoteAuthority, and it completes before the
        // application listener can observe the candidate.
        if claimed_source_did.method != "dev" {
            let Some(candidate_jwt) = hello_package.body.device_doc_jwt.as_deref() else {
                warn!(
                    "reject rtcp tunnel from {}: logical identity has no recovery candidate",
                    source_addr_log
                );
                return None;
            };
            if let Err(err) = self
                .recover_negative_authority_candidate(&claimed_source_did, candidate_jwt)
                .await
            {
                warn!(
                    "reject rtcp tunnel from {} {} before LocalAndZone/listener: {}",
                    claimed_source_did.to_string(),
                    source_addr_log,
                    err
                );
                return None;
            }
        }

        // I1 step ⑤: now and only now may LocalAndZone assemble the trusted
        // snapshot and verify the owner-backed document.
        let source_device = match self
            .resolve_source_device_info(
                &hello_package.body,
                &claimed_source_did,
                candidate_key,
                candidate_document.as_ref(),
            )
            .await
        {
            Ok(source_device) => source_device,
            Err(e) => {
                warn!(
                    "reject rtcp tunnel from {}: verify source device info error:{}",
                    source_addr_log, e
                );
                return None;
            }
        };
        let source_device_id = source_device.source_device_id;
        let source_device_info = source_device.source_device_info;
        let source_dev_did = source_device.canonical_dev_did;
        let identity_trust = source_device.identity_trust;
        let verified_cache_entry = source_device.verified_cache_entry;
        let authority_candidate_revision = verified_cache_entry
            .as_ref()
            .map(|entry| entry.identity.document_revision.clone());

        // One-to-one binding pre-check before HelloAck, listener authorization
        // and publication: a named identity whose canonical DEV DID is bound
        // to a different verified logical name cannot be admitted. This early
        // read is rejection-only; the authoritative arbitration re-runs inside
        // the map/verified-cache commit sequence.
        if let Some(entry) = verified_cache_entry.as_ref() {
            if let Some(bound_logical) = self
                .tunnel_map
                .find_conflicting_binding(
                    &entry.identity.logical_did,
                    &entry.identity.canonical_dev_did,
                )
                .await
            {
                warn!(
                    "reject rtcp tunnel from {} {}: canonical device {} is already bound to \
                     verified logical name {}",
                    source_device_id,
                    source_addr_log,
                    entry.identity.canonical_dev_did,
                    bound_logical
                );
                return None;
            }
        }

        let source_did = match DID::from_str(source_device_id.as_str()) {
            Ok(did) => did,
            Err(e) => {
                warn!(
                    "reject rtcp tunnel from {} {}: parser remote did error:{}",
                    source_device_id, source_addr_log, e
                );
                return None;
            }
        };
        let now_ts = buckyos_get_unix_timestamp();
        // Retain the nonce for the FULL signature-acceptance window, not
        // just until `exp`. jsonwebtoken accepts a token up to
        // `exp + JWT_LEEWAY_SECS`, so if we only kept the nonce until
        // `exp`, a replay captured within that leeway would pass
        // signature validation *and* find a freshly-evicted slot --
        // defeating the anti-replay guarantee. See regression test
        // nonce_cache_retains_entry_past_exp_within_leeway.
        let retain_until = hello_payload.exp.saturating_add(JWT_LEEWAY_SECS);
        let source_dev_device_id = source_dev_did.to_string();
        let fresh = self
            .nonce_cache
            .insert_if_fresh(
                source_dev_device_id.as_str(),
                &hello_payload.nonce,
                retain_until,
                now_ts,
            )
            .await;
        if !fresh {
            warn!(
                "reject rtcp tunnel from {} {}: replayed Hello nonce",
                source_device_id, source_addr_log
            );
            return None;
        }

        let source_addr = match source_addr {
            Some(addr) => addr,
            None => {
                warn!(
                    "reject rtcp tunnel from {}: peer addr unavailable",
                    source_device_id
                );
                return None;
            }
        };

        let remote_stack = RTcpTargetStackEP::new(source_did, hello_package.body.my_port);
        if remote_stack.is_err() {
            error!("parser remote did error:{}", remote_stack.err().unwrap());
            return None;
        }
        let remote_stack = remote_stack.unwrap();

        // v4: generate a fresh ephemeral X25519 keypair, sign an
        // ack JWT binding it to the initiator's xpub, ship HelloAck in
        // the clear, then derive (aes_key, iv) from ECDH(my_eph,
        // peer_eph) via HKDF and wrap the stream. Only after the AEAD-
        // protected HelloAckConfirm is verified do we admit the tunnel.
        //
        // hello_payload.from is the JWT-verified semantic DID. Keep the
        // ack token bound to that canonical wire identity instead of an
        // environment-dependent bridge hostname.
        let initiator_hostname = hello_payload.from.clone();
        let ack_state = match self
            .generate_ack_token(
                initiator_hostname.as_str(),
                &hello_payload.xpub,
                &hello_payload.to,
            )
            .await
        {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    "reject rtcp tunnel from {} {}: generate ack token error:{}",
                    source_device_id, source_addr, e
                );
                return None;
            }
        };
        let (ack_token, my_secret, my_xpub_bytes, my_nonce_hex) = ack_state;
        let my_xpub_hex: String = my_xpub_bytes.encode_hex();

        let mut challenge_bytes = [0u8; 16];
        rand::rng().fill(&mut challenge_bytes);
        let challenge_hex: String = challenge_bytes.encode_hex();

        let mut bearing: RTcpBearingStream = Box::new(stream);
        let ack_pkg = RTcpHelloAckPackage::new(
            0,
            ack_token,
            challenge_hex.clone(),
            hello_payload.to.clone(),
        );
        let handshake_seq = ack_pkg.seq;
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
            return None;
        }

        let (aes_key, iv) = RTcpInner::derive_session_secrets(
            my_secret,
            initiator_xpub_bytes,
            &initiator_hostname,
            &hello_payload.to,
            &source_dev_did.to_string(),
            &self.this_device_dev_did.to_string(),
            &hello_payload.xpub,
            &my_xpub_hex,
            &hello_payload.nonce,
            &my_nonce_hex,
        );
        let mut encrypted_stream =
            EncryptedStream::new_control(bearing, &aes_key, &iv, EncryptionRole::Responder);

        if let Err(e) = responder_key_confirmation(&mut encrypted_stream, &challenge_hex).await {
            warn!(
                "reject rtcp tunnel from {} {}: key confirmation failed: {}",
                source_device_id, source_addr, e
            );
            return None;
        }

        let endpoint = TunnelEndpoint {
            device_id: source_device_id.clone(),
            port: hello_package.body.my_port,
            canonical_device_id: Some(source_dev_did.to_string()),
            identity_trust: Some(identity_trust.to_string()),
        };
        if let Err(e) = self
            .listener
            .on_new_tunnel(endpoint.clone(), source_addr, source_device_info)
            .await
        {
            let reason = format!("listener rejected tunnel: {}", e);
            warn!(
                "reject rtcp tunnel from {} {}: {}",
                endpoint.device_id, source_addr, e
            );
            if let Err(send_err) =
                responder_send_tunnel_result(&mut encrypted_stream, handshake_seq, false, reason)
                    .await
            {
                debug!(
                    "send listener rejection to {} {} failed: {}",
                    endpoint.device_id, source_addr, send_err
                );
            }
            return None;
        }

        let tunnel = RTcpTunnel::new(
            self.stream_helper.clone(),
            self.this_device_did.clone(),
            &remote_stack,
            RtcpAddressResolutionContext::without_device_info(
                remote_stack.did.clone(),
                ResolveIpTargetKind::Device,
                ResolveIpZoneRelation::Unknown,
            ),
            false,
            encrypted_stream,
            Some(source_addr),
            None,
            aes_key,
            &self.security.limits,
            self.listener.clone(),
        );
        tunnel.set_identity(&source_dev_did, identity_trust);
        let tunnel_key = self.format_tunnel_key(&source_dev_did, None);

        // The document is accepted only after the peer has proved possession
        // of its device key, completed key confirmation, and passed the
        // application listener's authorization.  Commit it now as RTCP's
        // high-water/CAS step.  A concurrent newer or conflicting acceptance
        // wins in name-client's DocumentRevision merge.  RTcpTunnelMap holds
        // a dedicated commit guard across this cache CAS and the subsequent
        // map/index publication, closing the gap where an old successful CAS
        // could otherwise resume after a newer tunnel's index scan.
        let registration = match self
            .tunnel_map
            .register_authenticated_inbound(&tunnel_key, tunnel.clone(), verified_cache_entry)
            .await
        {
            Ok(registration) => registration,
            Err(err) => {
                let reason = format!("cannot commit accepted device document: {}", err);
                warn!(
                    "reject rtcp tunnel from {} {}: cannot commit accepted device document: {}",
                    source_device_id, source_addr, err
                );
                if let Err(send_err) = tunnel
                    .send_tunnel_result(handshake_seq, false, reason)
                    .await
                {
                    debug!(
                        "send cache-arbitration rejection to {} {} failed: {}",
                        source_device_id, source_addr, send_err
                    );
                }
                tunnel.mark_closed();
                return None;
            }
        };

        let accepted = registration.accepted;
        let result_reason = registration.rejection_reason.clone().unwrap_or_default();
        let publication_guard = PublishedInboundGuard::new(
            self.tunnel_map.clone(),
            tunnel_key.clone(),
            tunnel.clone(),
            registration,
        );
        if let Err(err) = tunnel
            .send_tunnel_result(handshake_seq, accepted, result_reason)
            .await
        {
            warn!(
                "finalize rtcp tunnel from {} {} failed: {}",
                source_device_id, source_addr, err
            );
            return None;
        }
        if !accepted {
            warn!(
                "reject duplicate rtcp tunnel from {} {} after map arbitration",
                source_device_id, source_addr
            );
            return None;
        }
        let registration = publication_guard.disarm();

        let authority_confirmation = if matches!(
            identity_trust,
            RtcpIdentityTrust::TrustedHostSnapshot | RtcpIdentityTrust::TrustedZoneSnapshot
        ) && claimed_source_did.method != "dev"
        {
            hello_package
                .body
                .device_doc_jwt
                .clone()
                .and_then(|candidate_jwt| {
                    authority_candidate_revision.map(|document_revision| {
                        (
                            claimed_source_did,
                            candidate_jwt,
                            source_addr.ip(),
                            document_revision,
                        )
                    })
                })
        } else {
            None
        };

        // TunnelResult is the last await after publication. The publication
        // guard removes the candidate if that send is cancelled or fails; once
        // it succeeds, disarming and returning happen in the same future poll.
        Some(EstablishedInboundTunnel {
            tunnel,
            tunnel_key,
            source_device_id,
            source_addr,
            registration,
            authority_confirmation,
        })
    }

    async fn maybe_spawn_authority_confirmation(
        self: &Arc<Self>,
        logical_did: DID,
        candidate_jwt: String,
        source_ip: std::net::IpAddr,
        document_revision: DocumentRevision,
    ) {
        let now = buckyos_get_unix_timestamp();
        let max_age = match self
            .security
            .inbound_admission
            .authority_reconfirm_max_age
            .as_secs()
        {
            Ok(value) => value,
            Err(err) => {
                error!(
                    "skip RTCP authority confirmation for {}: invalid max age: {}",
                    logical_did.to_string(),
                    err
                );
                return;
            }
        };
        let identity_key = logical_did.to_string();
        let Some(ticket) = self
            .tunnel_map
            .begin_authority_confirmation(&identity_key, &document_revision, now, max_age)
            .await
        else {
            return;
        };

        let this = self.clone();
        tokio::spawn(async move {
            let permit = match this
                .authority_confirmation_slots
                .clone()
                .acquire_owned()
                .await
            {
                Ok(permit) => permit,
                Err(_) => {
                    this.tunnel_map
                        .complete_authority_unavailable_if_current(
                            &identity_key,
                            &ticket,
                            buckyos_get_unix_timestamp(),
                        )
                        .await;
                    return;
                }
            };
            let _permit = permit;
            let mut policy = ResolvePolicy::default();
            policy.source = ResolveSourcePolicy::RemoteAuthority;
            policy.allow_stale_cache = false;
            policy.allow_unverified_cache_when_unavailable = false;
            policy.allow_self_signed_when_missing = false;
            let options = ResolveVerifyOptions {
                purpose: VerifyPurpose::AuthSubject,
                policy,
            };
            let budget = Duration::from_secs(this.security.limits.handshake_timeout_secs.max(1));
            let confirmation = timeout(
                budget,
                resolve_and_verify_device_document_jwt(&logical_did, &candidate_jwt, &options),
            )
            .await;

            let completed_at = buckyos_get_unix_timestamp();
            match confirmation {
                Ok(Ok((_document, verified)))
                    if matches!(
                        &verified.freshness.authority,
                        AuthorityFreshness::Current { .. }
                    ) =>
                {
                    if verified.revision != ticket.document_revision {
                        let reason = format!(
                            "authority Current revision {:?} differs from admitted revision {:?}",
                            verified.revision, ticket.document_revision
                        );
                        warn!(
                            "RTCP authority confirmation rejected {} from {}: {}",
                            identity_key, source_ip, reason
                        );
                        this.tunnel_map
                            .complete_authority_negative_if_current(
                                &identity_key,
                                &ticket,
                                completed_at,
                                &reason,
                            )
                            .await;
                        return;
                    }
                    let cache_result = GLOBAL_NAME_CLIENT
                        .get()
                        .ok_or_else(|| {
                            NSError::InvalidState("name client not initialized".to_string())
                        })
                        .and_then(|client| {
                            client.add_verified_cache(
                                verified.subject_did.clone(),
                                Some(DidDocType::Device),
                                verified.document.clone(),
                            )
                        });
                    match cache_result {
                        Ok(outcome) if outcome.stored() => {
                            let upgraded = this
                                .tunnel_map
                                .complete_authority_confirmed_if_current(
                                    &identity_key,
                                    &ticket,
                                    completed_at,
                                )
                                .await;
                            info!(
                                "RTCP authority confirmation passed for {} from {}; upgraded {} tunnel(s), cache={:?}",
                                identity_key, source_ip, upgraded, outcome
                            );
                        }
                        Ok(outcome) => {
                            let reason =
                                format!("authority cache arbitration rejected: {:?}", outcome);
                            warn!(
                                "RTCP authority confirmation cache arbitration rejected {} from {}: {:?}",
                                identity_key, source_ip, outcome
                            );
                            this.tunnel_map
                                .complete_authority_negative_if_current(
                                    &identity_key,
                                    &ticket,
                                    completed_at,
                                    &reason,
                                )
                                .await;
                        }
                        Err(err) => {
                            warn!(
                                "RTCP authority confirmation for {} passed but cache commit failed: {}",
                                identity_key, err
                            );
                            this.tunnel_map
                                .complete_authority_unavailable_if_current(
                                    &identity_key,
                                    &ticket,
                                    completed_at,
                                )
                                .await;
                        }
                    }
                }
                Ok(Ok((_document, verified))) => {
                    if Self::authority_confirmation_rejects_snapshot(&verified.freshness.authority)
                    {
                        warn!(
                            "RTCP authority confirmation denied {} from {}: {:?}",
                            identity_key, source_ip, verified.freshness.authority
                        );
                        let reason =
                            format!("AuthorityNotCurrent: {:?}", verified.freshness.authority);
                        this.tunnel_map
                            .complete_authority_negative_if_current(
                                &identity_key,
                                &ticket,
                                completed_at,
                                &reason,
                            )
                            .await;
                    } else if matches!(
                        &verified.freshness.authority,
                        AuthorityFreshness::NotCurrent { .. }
                    ) {
                        info!(
                            "RTCP authority confirmation did not establish a current published device document for {} from {}; retaining snapshot trust: {:?}",
                            identity_key, source_ip, verified.freshness.authority
                        );
                        this.tunnel_map
                            .complete_authority_unavailable_if_current(
                                &identity_key,
                                &ticket,
                                completed_at,
                            )
                            .await;
                    } else {
                        warn!(
                            "RTCP authority confirmation for {} returned no current receipt",
                            identity_key
                        );
                        this.tunnel_map
                            .complete_authority_unavailable_if_current(
                                &identity_key,
                                &ticket,
                                completed_at,
                            )
                            .await;
                    }
                }
                Ok(Err(err)) if Self::is_definite_verify_rejection(&err) => {
                    warn!(
                        "RTCP authority confirmation definitively rejected {} from {}: {}",
                        identity_key, source_ip, err
                    );
                    let reason = format!("definite authority rejection: {}", err);
                    this.tunnel_map
                        .complete_authority_negative_if_current(
                            &identity_key,
                            &ticket,
                            completed_at,
                            &reason,
                        )
                        .await;
                }
                Ok(Err(err)) => {
                    warn!(
                        "RTCP authority confirmation unavailable for {} from {}: {}",
                        identity_key, source_ip, err
                    );
                    this.tunnel_map
                        .complete_authority_unavailable_if_current(
                            &identity_key,
                            &ticket,
                            completed_at,
                        )
                        .await;
                }
                Err(_) => {
                    warn!(
                        "RTCP authority confirmation for {} from {} timed out after {:?}",
                        identity_key, source_ip, budget
                    );
                    this.tunnel_map
                        .complete_authority_unavailable_if_current(
                            &identity_key,
                            &ticket,
                            completed_at,
                        )
                        .await;
                }
            }
        });
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
        let remote_stack = parse_rtcp_stack_id_checked(tunnel_stack_id).map_err(|e| {
            TunnelError::ConnectError(format!(
                "invalid remote stack id '{}': {}",
                tunnel_stack_id, e
            ))
        })?;
        let target_device_id = remote_stack.did.to_string();
        // Resolve once and carry the exact identity snapshot through the
        // tunnel key and every connection attempt. Re-resolving while
        // constructing Hello could otherwise register a handshake completed
        // with a newly-rotated key under a key derived from the old one.
        let responder_identity = self
            .resolve_remote_tunnel_identity(&remote_stack.did)
            .await?;
        let remote_dev_did = responder_identity.canonical_dev_did.clone();
        let remote_device_id = remote_dev_did.to_string();
        let tunnel_key = self.format_tunnel_key(
            &remote_dev_did,
            remote_stack.bootstrap_stream_url.as_deref(),
        );
        let name_binding = responder_identity.logical_name_binding();
        debug!(
            "will create tunnel to {} (canonical {}), tunnel key is {}, try reuse",
            target_device_id.as_str(),
            remote_device_id.as_str(),
            tunnel_key.as_str()
        );

        // Reuse an existing tunnel only after the one-to-one arbitration: a
        // named target whose canonical DEV DID is bound to a different
        // verified logical name is rejected instead of silently sharing the
        // earlier tunnel. Direct did:dev addressing carries no name binding
        // and keeps sharing the device tunnel by design.
        match self
            .tunnel_map
            .acquire_outbound(tunnel_key.as_str(), name_binding.as_ref())
            .await
        {
            Ok(Some(tunnel)) => {
                debug!("Reuse tunnel {}", tunnel_key.as_str());
                return Ok(Box::new(tunnel));
            }
            Ok(None) => {}
            Err(conflict) => {
                let msg = format!(
                    "rtcp target {} rejected by one-to-one name binding: {}",
                    target_device_id, conflict
                );
                warn!("{}", msg);
                return Err(TunnelError::DocumentError(msg));
            }
        }

        // Only one creator per canonical tunnel key may proceed into bootstrap
        // or Happy-Eyeballs connection establishment. Concurrent callers wait
        // here, then reuse the winner published by the active creator.
        let _create_permit = self.create_flights.acquire(tunnel_key.clone()).await;
        match self
            .tunnel_map
            .acquire_outbound(tunnel_key.as_str(), name_binding.as_ref())
            .await
        {
            Ok(Some(tunnel)) => {
                debug!(
                    "Reuse tunnel {} after waiting for concurrent creator",
                    tunnel_key.as_str()
                );
                return Ok(Box::new(tunnel));
            }
            Ok(None) => {}
            Err(conflict) => {
                let msg = format!(
                    "rtcp target {} rejected by one-to-one name binding: {}",
                    target_device_id, conflict
                );
                warn!("{}", msg);
                return Err(TunnelError::DocumentError(msg));
            }
        }

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
                        bootstrap_url, target_device_id, e
                    );
                    error!("{}", msg);
                    TunnelError::ConnectError(msg)
                })?;

            let state = self
                .generate_tunnel_token_for_identity(responder_identity.clone())
                .map_err(|e| {
                    let msg = format!("generate tunnel token error: {}, {}", remote_device_id, e);
                    error!("{}", msg);
                    e
                })?;
            let responder_trust = state.responder_trust;
            let responder_canonical_did =
                DID::from_str(&state.responder_canonical_did).map_err(|e| {
                    TunnelError::DocumentError(format!("invalid canonical responder DID: {}", e))
                })?;
            let initiator_did = self.this_device_did.to_string();

            let addr: SocketAddr = self.bind_addr.parse().unwrap();
            let hello_package = RTcpHelloPackage::new(
                0,
                self.this_device_did.to_string(),
                target_device_id.clone(),
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

            // v4 key confirmation: read plaintext HelloAck off the
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
            // framework (the RTCP v4 bootstrap transport rule).
            let bootstrap_ctx = RTcpBootstrapCtx {
                url: bootstrap_url_parsed,
                tunnel_manager: tunnel_manager.clone(),
            };
            let tunnel = RTcpTunnel::new(
                self.stream_helper.clone(),
                self.this_device_did.clone(),
                &remote_stack,
                responder_identity.address_resolution.clone(),
                true,
                encrypted_stream,
                None,
                Some(bootstrap_ctx),
                aes_key,
                &self.security.limits,
                self.listener.clone(),
            );
            tunnel.set_identity(&responder_canonical_did, responder_trust);
            if let Err(err) = self
                .tunnel_map
                .register_outbound_if_absent(&tunnel_key, tunnel.clone(), name_binding.as_ref())
                .await
            {
                tunnel.close().await;
                match err {
                    OutboundRegisterError::Existing(existing) => {
                        debug!(
                            "Reuse tunnel {} after bootstrap build raced with another creator",
                            tunnel_key.as_str()
                        );
                        return Ok(Box::new(existing));
                    }
                    OutboundRegisterError::BindingConflict(conflict) => {
                        let msg = format!(
                            "rtcp target {} rejected by one-to-one name binding: {}",
                            target_device_id, conflict
                        );
                        warn!("{}", msg);
                        return Err(TunnelError::DocumentError(msg));
                    }
                    OutboundRegisterError::AuthorityNegative(reason) => {
                        let msg = format!(
                            "rtcp target {} rejected by authority admission: {}",
                            target_device_id, reason
                        );
                        warn!("{}", msg);
                        return Err(TunnelError::DocumentError(msg));
                    }
                }
            }
            info!(
                "create tunnel {} instance {} ok via bootstrap url {}",
                tunnel_key.as_str(),
                tunnel.instance_id(),
                bootstrap_url
            );

            let result: TunnelResult<Box<dyn TunnelBox>> = Ok(Box::new(tunnel.clone()));
            let tunnel_map = self.tunnel_map.clone();
            task::spawn(async move {
                debug!(
                    "RTcp tunnel {} established (bootstrap), tunnel running",
                    tunnel_key.as_str()
                );
                tunnel.run().await;
                tunnel_map.remove_if_current(&tunnel_key, &tunnel).await;
                info!("RTcp tunnel {} end", tunnel_key.as_str());
            });

            return result;
        }

        // 1） Resolve with the scope produced by the verified handshake
        // identity. name-client applies its RFC 8305 / addr-rtt ordering after
        // enforcing the DeviceInfo policy.
        let resolve_name = responder_identity.address_resolution.target_did.to_string();
        debug!(
            "resolve remote device {} (canonical {}) ips by {} with target_kind={:?}, zone_relation={:?}",
            target_device_id,
            remote_device_id,
            resolve_name,
            responder_identity.address_resolution.options.target_kind(),
            responder_identity
                .address_resolution
                .options
                .zone_relation(),
        );

        let candidate_ips = match responder_identity.address_resolution.resolve_ips().await {
            Ok(ips) if !ips.is_empty() => ips,
            Ok(_) => {
                let msg = format!(
                    "cann't resolve remote device {} ip by {}: empty address list",
                    target_device_id, resolve_name
                );
                error!("{}", msg);
                return Err(TunnelError::DocumentError(msg));
            }
            Err(err) => {
                let msg = format!(
                    "cann't resolve remote device {} ip by {}: {}",
                    target_device_id, resolve_name, err
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
                &responder_identity,
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
                            &responder_identity,
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
                    if let Err(err) = self
                        .tunnel_map
                        .register_outbound_if_absent(
                            &tunnel_key,
                            tunnel.clone(),
                            name_binding.as_ref(),
                        )
                        .await
                    {
                        tunnel.close().await;
                        match err {
                            OutboundRegisterError::Existing(existing) => {
                                debug!(
                                    "Reuse tunnel {} after direct build raced with another creator",
                                    tunnel_key.as_str()
                                );
                                return Ok(Box::new(existing));
                            }
                            OutboundRegisterError::BindingConflict(conflict) => {
                                let msg = format!(
                                    "rtcp target {} rejected by one-to-one name binding: {}",
                                    target_device_id, conflict
                                );
                                warn!("{}", msg);
                                return Err(TunnelError::DocumentError(msg));
                            }
                            OutboundRegisterError::AuthorityNegative(reason) => {
                                let msg = format!(
                                    "rtcp target {} rejected by authority admission: {}",
                                    target_device_id, reason
                                );
                                warn!("{}", msg);
                                return Err(TunnelError::DocumentError(msg));
                            }
                        }
                    }
                    info!(
                        "create tunnel {} instance {} ok, remote addr is {}",
                        tunnel_key.as_str(),
                        tunnel.instance_id(),
                        attempt.remote_addr
                    );

                    let result: TunnelResult<Box<dyn TunnelBox>> = Ok(Box::new(tunnel.clone()));
                    let tunnel_map = self.tunnel_map.clone();
                    task::spawn(async move {
                        debug!(
                            "RTcp tunnel {} established, tunnel running",
                            tunnel_key.as_str()
                        );
                        tunnel.run().await;

                        // remove tunnel from manager
                        tunnel_map.remove_if_current(&tunnel_key, &tunnel).await;

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
            target_device_id,
            connect_errors.join("; ")
        )))
    }

    async fn compute_tunnel_key(&self, remote_stack: &RTcpTargetStackEP) -> TunnelResult<String> {
        let remote_dev_did = self
            .resolve_remote_tunnel_dev_did(&remote_stack.did)
            .await?;
        Ok(self.format_tunnel_key(
            &remote_dev_did,
            remote_stack.bootstrap_stream_url.as_deref(),
        ))
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
        let remote_stack = match parse_rtcp_stack_id_checked(stack_id) {
            Ok(s) => s,
            Err(e) => {
                return Ok(unreachable_status(
                    url,
                    &normalized,
                    now,
                    TunnelUrlStatusSource::FreshProbe,
                    format!("invalid rtcp stack id '{}': {}", stack_id, e),
                ));
            }
        };
        let tunnel_key = match self.compute_tunnel_key(&remote_stack).await {
            Ok(key) => key,
            Err(e) => {
                return Ok(unreachable_status(
                    url,
                    &normalized,
                    now,
                    TunnelUrlStatusSource::FreshProbe,
                    format!("compute_tunnel_key: {}", e),
                ));
            }
        };
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

    async fn close_tunnel_for_url(&self, url: &Url, reason: &str) {
        let stack_id = url.authority();
        let remote_stack = match parse_rtcp_stack_id_checked(stack_id) {
            Ok(stack) => stack,
            Err(err) => {
                warn!("cannot close RTCP tunnel for invalid URL {}: {}", url, err);
                return;
            }
        };
        let tunnel_key = match self.compute_tunnel_key(&remote_stack).await {
            Ok(key) => key,
            Err(err) => {
                warn!("cannot compute RTCP tunnel key for close {}: {}", url, err);
                return;
            }
        };
        if let Some(tunnel) = self.tunnel_map.get_tunnel(&tunnel_key).await {
            warn!(
                "closing RTCP tunnel {} instance {} after {} (age {:?})",
                tunnel_key,
                tunnel.instance_id(),
                reason,
                tunnel.created_at.elapsed()
            );
            tunnel.close().await;
            self.tunnel_map
                .remove_if_current(&tunnel_key, &tunnel)
                .await;
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

// v4 initiator-side handshake completion.
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
            "HelloAck read timed out; peer did not complete v4 handshake".to_string(),
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
        &state.initiator_canonical_did,
        &state.responder_canonical_did,
        &state.my_xpub_hex,
        &responder_xpub_hex,
        &state.my_nonce_hex,
        &ack_payload.nonce,
    );
    let mut encrypted_stream =
        EncryptedStream::new_control(bearing, &aes_key, &iv, EncryptionRole::Initiator);

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

    let final_result = timeout(
        HELLO_HANDSHAKE_TIMEOUT,
        RTcpTunnelPackage::read_package(Pin::new(&mut encrypted_stream), false, "tunnel_result"),
    )
    .await
    .map_err(|_| {
        InitiatorKeyConfirmationError::Timeout(TunnelError::ReasonError(
            "TunnelResult read timed out; responder did not finish admission".to_string(),
        ))
    })?
    .map_err(|e| {
        InitiatorKeyConfirmationError::Failed(TunnelError::ReasonError(format!(
            "TunnelResult read error: {}",
            e
        )))
    })?;

    let final_result = match final_result {
        RTcpTunnelPackage::TunnelResult(result) if result.seq == ack.seq => result,
        RTcpTunnelPackage::TunnelResult(result) => {
            return Err(InitiatorKeyConfirmationError::Failed(
                TunnelError::ReasonError(format!(
                    "TunnelResult seq {} does not match HelloAck seq {}",
                    result.seq, ack.seq
                )),
            ));
        }
        other => {
            return Err(InitiatorKeyConfirmationError::Failed(
                TunnelError::ReasonError(format!("expected TunnelResult, got {:?}", other)),
            ));
        }
    };
    if !final_result.body.accepted {
        let reason = if final_result.body.reason.is_empty() {
            "responder rejected tunnel".to_string()
        } else {
            final_result.body.reason
        };
        return Err(InitiatorKeyConfirmationError::Failed(
            TunnelError::ConnectError(reason),
        ));
    }

    Ok((encrypted_stream, aes_key))
}

async fn responder_send_tunnel_result(
    stream: &mut EncryptedStream<RTcpBearingStream>,
    seq: u32,
    accepted: bool,
    reason: impl Into<String>,
) -> Result<(), TunnelError> {
    let package = if accepted {
        RTcpTunnelResultPackage::accepted(seq)
    } else {
        RTcpTunnelResultPackage::rejected(seq, reason)
    };
    timeout(
        HELLO_HANDSHAKE_TIMEOUT,
        RTcpTunnelPackage::send_package(Pin::new(stream), package),
    )
    .await
    .map_err(|_| TunnelError::ReasonError("TunnelResult send timed out".to_string()))?
    .map_err(|e| TunnelError::ReasonError(format!("TunnelResult send error: {}", e)))
}

// v4 responder-side key confirmation, post-key-derivation.
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
const OPEN_RESULT_OK: u32 = 0;
const OPEN_RESULT_QUOTA: u32 = 1;
const OPEN_RESULT_RECONNECT_FAILED: u32 = 2;
const OPEN_RESULT_WRONG_DIRECTION: u32 = 3;
const OPEN_RESULT_TIMEOUT: u32 = 4;
const OPEN_RESULT_AUTHORIZATION_REJECTED: u32 = 5;
const OPEN_RESULT_INVALID_STREAM_ID: u32 = 6;
const OPEN_RESULT_DUPLICATE_STREAM_ID: u32 = 7;
const OPEN_RESULT_RATE_LIMITED: u32 = 8;
const OPEN_RESULT_KEY_EPOCH_EXHAUSTED: u32 = 9;
const MAX_RTCP_TUNNEL_AGE: Duration = Duration::from_secs(24 * 60 * 60);

struct StreamRequestRateState {
    tokens: f64,
    last_refill: Instant,
}

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
    instance_id: u64,
    build_helper: RTcpStreamBuildHelper,
    remote_stack: RTcpTargetStackEP,
    // Bound to the verified handshake identity and copied unchanged from the
    // initial address lookup. Reconnects must not reconstruct scope from the
    // target name or fall back to the context-free resolver API.
    address_resolution: RtcpAddressResolutionContext,
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
    // direct TCP connect. The same bootstrap that brought up the tunnel is
    // reused to bring up each subsequent business stream so nested-remote
    // tunnels keep working end-to-end.
    bootstrap: Option<RTcpBootstrapCtx>,
    this_device: DID,
    canonical_remote_did: Arc<std::sync::RwLock<String>>,
    identity_trust: Arc<std::sync::RwLock<RtcpIdentityTrust>>,
    aes_key: [u8; 32],
    write_stream: Arc<Mutex<WriteHalf<EncryptedStream<RTcpBearingStream>>>>,
    read_stream: Arc<Mutex<ReadHalf<EncryptedStream<RTcpBearingStream>>>>,

    // Set before an authenticated inbound replacement is published. Every
    // operation checks it before allocating waiters, reconnecting, or sending
    // another control record.
    closed: Arc<AtomicBool>,
    close_notify: Arc<Notify>,

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

    // Keys registered in the stack-wide RTcpStreamBuildHelper by this tunnel.
    // Closing the tunnel removes them so waiters wake promptly instead of
    // waiting for STREAM_WAIT_TIMEOUT.
    pending_wait_stream_keys: Arc<Mutex<HashSet<String>>>,

    // Per-tunnel concurrency quota for inbound Open requests.
    inbound_build_slots: Arc<Semaphore>,
    inbound_request_rate: Arc<Mutex<StreamRequestRateState>>,
    stream_requests_per_second: u32,
    stream_request_burst: u32,
    max_datagram_bytes: usize,
    max_stream_ids_per_tunnel: usize,
    used_stream_ids: Arc<Mutex<HashSet<[u8; 16]>>>,
    created_at: Instant,

    // Pong waiters for RTT-aware probes. `ping_rtt` registers a waiter
    // keyed by the ping seq before sending; when the matching Pong
    // arrives, `process_package` notifies the waiter. The classic
    // `ping()` path still uses seq 0 with no waiter, so its Pongs are
    // simply dropped here (preserving existing behaviour).
    pong_waiters: Arc<Mutex<HashMap<u32, oneshot::Sender<()>>>>,
}

impl RTcpTunnel {
    // The EncryptedStream wrapping happens in create_tunnel / on_new_tunnel
    // so the v4 key-confirmation handshake (HelloAck / HelloAckConfirm)
    // can run over AEAD records before the tunnel is published to the map.
    // The caller is therefore responsible for picking the correct
    // EncryptionRole when building `encrypted_stream`.
    pub fn new(
        build_helper: RTcpStreamBuildHelper,
        this_device: DID,
        remote_stack: &RTcpTargetStackEP,
        address_resolution: RtcpAddressResolutionContext,
        can_direct: bool,
        encrypted_stream: EncryptedStream<RTcpBearingStream>,
        peer_addr: Option<SocketAddr>,
        bootstrap: Option<RTcpBootstrapCtx>,
        aes_key: [u8; 32],
        limits: &RtcpLimitsConfig,
        listener: RTcpListenerRef,
    ) -> Self {
        let (read_stream, write_stream) = tokio::io::split(encrypted_stream);
        //let (read_stream,write_stream) =  tokio::io::split(stream);
        let this_remote_stack = remote_stack.clone();

        //this_remote_stack.stack_port = 0;
        let peer_addr = peer_addr.map(|addr| Arc::new(std::sync::Mutex::new(addr)));

        Self {
            instance_id: NEXT_RTCP_TUNNEL_INSTANCE_ID.fetch_add(1, Ordering::Relaxed),
            build_helper,
            remote_stack: this_remote_stack,
            address_resolution,
            can_direct, //Considering the limit of port mapping, the default configuration is configured as "NoDirect" mode
            peer_addr,
            bootstrap,
            this_device: this_device,
            canonical_remote_did: Arc::new(std::sync::RwLock::new(remote_stack.did.to_string())),
            identity_trust: Arc::new(std::sync::RwLock::new(RtcpIdentityTrust::KeyDid)),
            aes_key: aes_key,
            read_stream: Arc::new(Mutex::new(read_stream)),
            write_stream: Arc::new(Mutex::new(write_stream)),

            closed: Arc::new(AtomicBool::new(false)),
            close_notify: Arc::new(Notify::new()),
            next_seq: Arc::new(AtomicU32::new(0)),
            listener,
            open_resp_waiters: Arc::new(Mutex::new(HashMap::new())),
            ropen_resp_waiters: Arc::new(Mutex::new(HashMap::new())),
            pending_wait_stream_keys: Arc::new(Mutex::new(HashSet::new())),
            inbound_build_slots: Arc::new(Semaphore::new(
                limits.max_pending_stream_builds_per_tunnel,
            )),
            inbound_request_rate: Arc::new(Mutex::new(StreamRequestRateState {
                tokens: f64::from(limits.stream_request_burst),
                last_refill: Instant::now(),
            })),
            stream_requests_per_second: limits.stream_requests_per_second,
            stream_request_burst: limits.stream_request_burst,
            max_datagram_bytes: limits.max_datagram_bytes,
            max_stream_ids_per_tunnel: limits.max_stream_ids_per_tunnel,
            used_stream_ids: Arc::new(Mutex::new(HashSet::new())),
            created_at: Instant::now(),
            pong_waiters: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn instance_id(&self) -> u64 {
        self.instance_id
    }

    fn is_same_instance(&self, other: &RTcpTunnel) -> bool {
        self.instance_id == other.instance_id
    }

    fn set_identity(&self, canonical_remote_did: &DID, trust: RtcpIdentityTrust) {
        *self.canonical_remote_did.write().unwrap() = canonical_remote_did.to_string();
        *self.identity_trust.write().unwrap() = trust;
    }

    fn identity_trust(&self) -> RtcpIdentityTrust {
        *self.identity_trust.read().unwrap()
    }

    fn upgrade_identity_trust(&self, trust: RtcpIdentityTrust) {
        let mut current = self.identity_trust.write().unwrap();
        if trust > *current {
            info!(
                "upgrade RTCP tunnel {} instance {} identity trust {} -> {}",
                self.remote_stack.did.to_string(),
                self.instance_id,
                *current,
                trust
            );
            *current = trust;
        }
    }

    // Synchronous first half of close. RTcpTunnelMap invokes this while
    // replacing the map entry so no caller can observe the new current tunnel
    // while the old instance still accepts new operations.
    fn mark_closed(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.inbound_build_slots.close();
            // notify_one stores a permit when run() has not entered notified()
            // yet, avoiding a lost wake-up between its closed check and select.
            self.close_notify.notify_one();
        }
    }

    pub async fn close(&self) {
        // Flag and wake the read loop before awaiting any locks or network I/O.
        self.mark_closed();

        // A closed tunnel can never accept another stream ID, so its replay
        // history is no longer security-sensitive. Clear it explicitly rather
        // than waiting for every cloned RTcpTunnel handle to be dropped.
        self.used_stream_ids.lock().await.clear();

        // Dropping the senders makes in-flight Open/ROpen/Ping callers fail
        // immediately. Removing this tunnel's HelloStream slots also wakes the
        // ROpen path after a successful ROpenResp has already consumed its
        // response waiter.
        self.open_resp_waiters.lock().await.clear();
        self.ropen_resp_waiters.lock().await.clear();
        self.pong_waiters.lock().await.clear();
        let wait_keys: Vec<String> = self.pending_wait_stream_keys.lock().await.drain().collect();
        for key in wait_keys {
            self.build_helper.remove_wait_stream(&key).await;
        }

        // Shutting down the write side sends FIN to the peer. The local run
        // loop exits independently through close_notify, even if the peer
        // keeps its write half open.
        let mut ws = self.write_stream.lock().await;
        use tokio::io::AsyncWriteExt;
        let _ = Pin::new(&mut *ws).shutdown().await;
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn ensure_active(&self) -> std::io::Result<()> {
        if self.is_closed() {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "rtcp tunnel closed",
            ))
        } else {
            Ok(())
        }
    }

    async fn send_tunnel_result(
        &self,
        seq: u32,
        accepted: bool,
        reason: impl Into<String>,
    ) -> Result<(), TunnelError> {
        let package = if accepted {
            RTcpTunnelResultPackage::accepted(seq)
        } else {
            RTcpTunnelResultPackage::rejected(seq, reason)
        };
        let mut write_stream = self.write_stream.lock().await;
        timeout(
            HELLO_HANDSHAKE_TIMEOUT,
            RTcpTunnelPackage::send_package(Pin::new(&mut *write_stream), package),
        )
        .await
        .map_err(|_| TunnelError::ReasonError("TunnelResult send timed out".to_string()))?
        .map_err(|e| TunnelError::ReasonError(format!("TunnelResult send error: {}", e)))
    }

    fn ensure_accepts_new_streams(&self) -> std::io::Result<()> {
        self.ensure_active()?;
        if self.created_at.elapsed() >= MAX_RTCP_TUNNEL_AGE {
            self.mark_closed();
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "rtcp tunnel key-use age budget exhausted",
            ));
        }
        Ok(())
    }

    pub fn get_key(&self) -> &[u8; 32] {
        return &self.aes_key;
    }

    fn next_seq(&self) -> u32 {
        self.next_seq.fetch_add(1, Ordering::SeqCst)
    }

    fn validate_stream_id(stream_id: &str) -> Result<[u8; 16], std::io::Error> {
        if stream_id.len() != 32 || !stream_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "RTCP stream id must be exactly 32 hexadecimal characters",
            ));
        }
        hex::decode(stream_id)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?
            .try_into()
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "RTCP stream id must decode to 16 bytes",
                )
            })
    }

    fn derive_stream_secrets(
        &self,
        stream_id: &str,
        purpose: StreamPurpose,
    ) -> Result<([u8; 32], [u8; 16]), std::io::Error> {
        let stream_id = Self::validate_stream_id(stream_id)?;
        let purpose_byte = match purpose {
            StreamPurpose::Stream => 0,
            StreamPurpose::Datagram => 1,
        };
        let hk = Hkdf::<Sha256>::new(None, self.get_key());
        let context = [&[RTCP_PROTOCOL_VERSION][..], &stream_id, &[purpose_byte]].concat();
        let mut stream_key = [0u8; 32];
        let mut key_info = b"buckyos-rtcp stream key|".to_vec();
        key_info.extend_from_slice(&context);
        hk.expand(&key_info, &mut stream_key).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "RTCP stream key KDF failed",
            )
        })?;
        let mut stream_iv = [0u8; 16];
        let mut iv_info = b"buckyos-rtcp stream iv|".to_vec();
        iv_info.extend_from_slice(&context);
        hk.expand(&iv_info, &mut stream_iv).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "RTCP stream IV KDF failed",
            )
        })?;
        Ok((stream_key, stream_iv))
    }

    async fn consume_stream_request_token(&self) -> bool {
        let mut state = self.inbound_request_rate.lock().await;
        let now = Instant::now();
        let elapsed = now.duration_since(state.last_refill).as_secs_f64();
        state.tokens = (state.tokens + elapsed * f64::from(self.stream_requests_per_second))
            .min(f64::from(self.stream_request_burst));
        state.last_refill = now;
        if state.tokens < 1.0 {
            return false;
        }
        state.tokens -= 1.0;
        true
    }

    async fn admit_inbound_stream_build(
        &self,
        stream_id: &str,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, u32> {
        self.ensure_accepts_new_streams()
            .map_err(|_| OPEN_RESULT_RECONNECT_FAILED)?;
        let stream_id =
            Self::validate_stream_id(stream_id).map_err(|_| OPEN_RESULT_INVALID_STREAM_ID)?;
        if self.used_stream_ids.lock().await.contains(&stream_id) {
            return Err(OPEN_RESULT_DUPLICATE_STREAM_ID);
        }
        if !self.consume_stream_request_token().await {
            return Err(OPEN_RESULT_RATE_LIMITED);
        }
        let permit = self
            .inbound_build_slots
            .clone()
            .try_acquire_owned()
            .map_err(|err| match err {
                TryAcquireError::NoPermits => OPEN_RESULT_QUOTA,
                TryAcquireError::Closed => OPEN_RESULT_RECONNECT_FAILED,
            })?;
        let mut used = self.used_stream_ids.lock().await;
        // Re-check active state under the same lock used for the final insert.
        // close() marks the tunnel first and then takes this lock to clear the
        // set, so no reservation can survive a concurrent close.
        self.ensure_accepts_new_streams()
            .map_err(|_| OPEN_RESULT_RECONNECT_FAILED)?;
        if used.contains(&stream_id) {
            return Err(OPEN_RESULT_DUPLICATE_STREAM_ID);
        }
        if used.len() >= self.max_stream_ids_per_tunnel {
            warn!(
                "RTCP tunnel {} instance {} stream ID key epoch exhausted at {} entries",
                self.remote_stack.did.to_string(),
                self.instance_id,
                used.len()
            );
            return Err(OPEN_RESULT_KEY_EPOCH_EXHAUSTED);
        }
        used.insert(stream_id);
        self.maybe_log_stream_id_usage(used.len());
        Ok(permit)
    }

    async fn reserve_outbound_stream_id(&self) -> Result<(String, [u8; 16]), std::io::Error> {
        self.ensure_accepts_new_streams()?;
        for _ in 0..16 {
            let bytes: [u8; 16] = rand::rng().random();
            let mut used = self.used_stream_ids.lock().await;
            // See the matching inbound check: close() clears only after
            // marking closed, and this final re-check prevents a late insert.
            self.ensure_accepts_new_streams()?;
            if used.len() >= self.max_stream_ids_per_tunnel {
                let used_count = used.len();
                drop(used);
                warn!(
                    "RTCP tunnel {} instance {} stream ID key epoch exhausted at {} entries; reconnect required",
                    self.remote_stack.did.to_string(),
                    self.instance_id,
                    used_count
                );
                self.close().await;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "rtcp tunnel stream ID key epoch exhausted; reconnect required",
                ));
            }
            if used.insert(bytes) {
                self.maybe_log_stream_id_usage(used.len());
                return Ok((hex::encode(bytes), bytes));
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate a unique RTCP stream id",
        ))
    }

    fn maybe_log_stream_id_usage(&self, used: usize) {
        let warn_at = self.max_stream_ids_per_tunnel.saturating_mul(9) / 10;
        if used == warn_at.max(1) {
            warn!(
                "RTCP tunnel {} instance {} stream ID key epoch is nearing exhaustion: {}/{}",
                self.remote_stack.did.to_string(),
                self.instance_id,
                used,
                self.max_stream_ids_per_tunnel
            );
        }
    }

    async fn send_open_result(&self, seq: u32, code: u32) -> Result<(), anyhow::Error> {
        let mut write_stream = self.write_stream.lock().await;
        self.ensure_active()?;
        RTcpTunnelPackage::send_package(
            Pin::new(&mut *write_stream),
            RTcpOpenRespPackage::new(seq, code),
        )
        .await
    }

    async fn send_ropen_result(&self, seq: u32, code: u32) -> Result<(), anyhow::Error> {
        let mut write_stream = self.write_stream.lock().await;
        self.ensure_active()?;
        RTcpTunnelPackage::send_package(
            Pin::new(&mut *write_stream),
            RTcpROpenRespPackage::new(seq, code),
        )
        .await
    }

    async fn process_package(&self, package: RTcpTunnelPackage) -> Result<(), anyhow::Error> {
        self.ensure_active()?;
        match package {
            RTcpTunnelPackage::Ping(ping_package) => {
                //send pong
                let pong_package = RTcpPongPackage::new(ping_package.seq, 0);
                let mut write_stream = self.write_stream.lock().await;
                self.ensure_active()?;
                let write_stream = Pin::new(&mut *write_stream);
                let _ = RTcpTunnelPackage::send_package(write_stream, pong_package).await?;
                return Ok(());
            }
            RTcpTunnelPackage::ROpen(ropen_package) => {
                if !self.can_direct {
                    self.send_ropen_result(ropen_package.seq, OPEN_RESULT_WRONG_DIRECTION)
                        .await?;
                    return Ok(());
                }
                let permit = match self
                    .admit_inbound_stream_build(&ropen_package.body.stream_id)
                    .await
                {
                    Ok(permit) => permit,
                    Err(code) => {
                        let send_result = self.send_ropen_result(ropen_package.seq, code).await;
                        if code == OPEN_RESULT_KEY_EPOCH_EXHAUSTED {
                            self.close().await;
                        }
                        send_result?;
                        return Ok(());
                    }
                };
                // ROpen may build a new transport leg and then hand the
                // stream to a long-lived listener. Keep the tunnel control
                // read loop free so concurrent Open/ROpen responses are not
                // head-of-line blocked behind that business stream.
                let this = self.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = this.on_ropen(ropen_package).await {
                        error!("RTcp on_ropen background task error: {}", e);
                    }
                });
                Ok(())
            }
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
                if ropen_resp_package.body.result == OPEN_RESULT_KEY_EPOCH_EXHAUSTED {
                    warn!(
                        "peer reports exhausted RTCP stream ID key epoch for tunnel {} instance {}; reconnect required",
                        self.remote_stack.did.to_string(),
                        self.instance_id
                    );
                    self.close().await;
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

                if open_resp_package.body.result == OPEN_RESULT_KEY_EPOCH_EXHAUSTED {
                    warn!(
                        "peer reports exhausted RTCP stream ID key epoch for tunnel {} instance {}; reconnect required",
                        self.remote_stack.did.to_string(),
                        self.instance_id
                    );
                    self.close().await;
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
    // send a HelloStream on it. This is the single choke point for v4's
    // "rebind transport semantics after remote nesting": bootstrap-backed
    // tunnels replay their nested transport via the tunnel framework, while
    // direct tunnels keep the classic `TcpStream::connect(peer_addr)` fast
    // path. Returns (stream, remote_addr, local_addr). `remote_addr` and
    // `local_addr` are synthetic placeholders on the bootstrap path because
    // there is no single authoritative TCP peer for a nested transport.
    async fn build_reconnect_stream(
        &self,
        stream_id: &str,
    ) -> Result<(Box<dyn AsyncStream>, SocketAddr, SocketAddr), std::io::Error> {
        self.ensure_active()?;
        if let Some(bootstrap) = self.bootstrap.as_ref() {
            let mut stream = bootstrap
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
            self.ensure_active()?;
            RTcpTunnelPackage::send_hello_stream(stream.as_mut(), stream_id)
                .await
                .map_err(|err| std::io::Error::new(ErrorKind::Other, err.to_string()))?;
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
        // Re-resolve here so newly published permitted addresses become
        // reachable without tearing down the control tunnel, and reorder so
        // the previously-winning IP is tried first. The exact scope/evidence
        // from the verified handshake is reused; notably, cross-zone and
        // non-device targets remain no-Info for the tunnel's whole lifetime.
        let last_addr = *peer_addr_handle.lock().unwrap();
        let candidates = self.collect_reconnect_candidates(last_addr).await;

        let stream = self
            .race_reconnect_candidates(peer_addr_handle, candidates, stream_id)
            .await?;
        self.ensure_active()?;
        Ok(stream)
    }

    // Build the ordered candidate list used by build_reconnect_stream.
    // Always returns at least the cached `last_addr` so that a DNS hiccup
    // can never strip the only known good path.
    async fn collect_reconnect_candidates(&self, last_addr: SocketAddr) -> Vec<SocketAddr> {
        let port = self.remote_stack.stack_port;
        let resolve_name = self.address_resolution.target_did.to_string();
        let resolved = match self.address_resolution.resolve_ips().await {
            Ok(ips) => ips,
            Err(e) => {
                debug!(
                    "rtcp reconnect scoped resolve_ips({}) failed: {} -- falling back to cached peer addr {}",
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
        stream_id: &str,
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

        attempts.push(Self::connect_reconnect_addr(
            candidates[next_index],
            stream_id,
        ));
        next_index += 1;

        loop {
            let attempt_result = if next_index < candidates.len() {
                tokio::select! {
                    result = attempts.next(), if !attempts.is_empty() => result,
                    _ = tokio::time::sleep(DIRECT_CONNECT_ATTEMPT_DELAY) => {
                        attempts.push(Self::connect_reconnect_addr(
                            candidates[next_index],
                            stream_id,
                        ));
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
                            layer: MeasurementLayer::Application,
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
        stream_id: &str,
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
        if let Err(e) = RTcpInner::configure_tcp_keepalive(&tcp_stream) {
            debug!(
                "cannot configure TCP keepalive for reconnect {}: {}",
                addr, e
            );
        }
        let remote_addr = tcp_stream.peer_addr().unwrap_or(addr);
        let local_addr = match tcp_stream.local_addr() {
            Ok(addr) => addr,
            Err(e) => return Err((addr, e)),
        };
        let mut tcp_stream = tcp_stream;
        if let Err(e) = RTcpTunnelPackage::send_hello_stream(&mut tcp_stream, stream_id).await {
            Self::record_reconnect_outcome(local_addr, remote_addr, ConnectionOutcome::Unreachable);
            return Err((addr, std::io::Error::new(ErrorKind::Other, e.to_string())));
        }
        let rtt = started_at.elapsed();
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
        self.ensure_active()?;
        debug!(
            "RTcp tunnel ropen request: {:?}:{}, {:?}",
            ropen_package.body.dest_host, ropen_package.body.dest_port, ropen_package.body.purpose
        );

        // 1. Build a reconnect stream to the remote's RTCP listener. For a
        // bootstrap-backed tunnel this replays the nested transport;
        // for a direct tunnel it opens TCP to peer_addr:stack_port. Any
        // failure is reported back as ROpenResp(result=2) so the initiator
        // releases its wait-HelloStream slot immediately.
        let (rtcp_stream, remote_addr, local_addr) = match self
            .build_reconnect_stream(&ropen_package.body.stream_id)
            .await
        {
            Ok(triple) => triple,
            Err(e) => {
                self.ensure_active()?;
                warn!(
                    "ropen reject: build reconnect stream to {} failed: {}",
                    self.remote_stack.did.to_string(),
                    e
                );
                let ropen_resp_package = RTcpROpenRespPackage::new(ropen_package.seq, 2);
                let mut write_stream = self.write_stream.lock().await;
                self.ensure_active()?;
                let write_stream = Pin::new(&mut *write_stream);
                RTcpTunnelPackage::send_package(write_stream, ropen_resp_package).await?;
                return Ok(());
            }
        };

        // 2. send ropen_resp
        {
            let mut write_stream = self.write_stream.lock().await;
            self.ensure_active()?;
            let write_stream = Pin::new(&mut *write_stream);
            let ropen_resp_package = RTcpROpenRespPackage::new(ropen_package.seq, 0);
            RTcpTunnelPackage::send_package(write_stream, ropen_resp_package).await?;
        }

        let purpose = ropen_package.body.purpose.unwrap_or_default();
        let (stream_key, stream_iv) =
            self.derive_stream_secrets(&ropen_package.body.stream_id, purpose)?;
        // This side opened the reconnect stream and sent HelloStream, so it is
        // the stream-layer initiator regardless of whether the transport is a
        // direct TCP socket or a bootstrap-backed nested stream.
        let aes_stream = EncryptedStream::new(
            rtcp_stream,
            &stream_key,
            &stream_iv,
            EncryptionRole::Initiator,
        );

        debug!(
            "RTcp stream encryption initialized for ropen stream {}",
            ropen_package.body.stream_id
        );

        self.ensure_active()?;
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
        self.ensure_active()?;
        //TODO: bug?
        let end_point = TunnelEndpoint {
            device_id: self.remote_stack.did.to_string(),
            port: self.remote_stack.stack_port,
            canonical_device_id: Some(self.canonical_remote_did.read().unwrap().clone()),
            identity_trust: Some(self.identity_trust().to_string()),
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
        self.ensure_active()?;
        let end_point = TunnelEndpoint {
            device_id: self.remote_stack.did.to_string(),
            port: self.remote_stack.stack_port,
            canonical_device_id: Some(self.canonical_remote_did.read().unwrap().clone()),
            identity_trust: Some(self.identity_trust().to_string()),
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
        self.ensure_active()?;
        debug!(
            "RTcp tunnel open request: {:?}:{}, {:?}",
            open_package.body.dest_host, open_package.body.dest_port, open_package.body.purpose
        );

        if self.can_direct {
            self.send_open_result(open_package.seq, OPEN_RESULT_WRONG_DIRECTION)
                .await?;
            return Ok(());
        }
        let permit = match self
            .admit_inbound_stream_build(&open_package.body.stream_id)
            .await
        {
            Ok(permit) => permit,
            Err(code) => {
                let send_result = self.send_open_result(open_package.seq, code).await;
                if code == OPEN_RESULT_KEY_EPOCH_EXHAUSTED {
                    self.close().await;
                }
                send_result?;
                return Ok(());
            }
        };

        // 2. Prepare wait for the new stream before send open_resp.
        let real_key = format!(
            "{}_{}",
            self.this_device.to_string(),
            open_package.body.stream_id
        );
        self.register_wait_stream(&real_key).await?;

        // 3. send open_resp with success (synchronous: keeps seq/response
        // ordering intact on the read loop).
        {
            let mut write_stream = self.write_stream.lock().await;
            if let Err(e) = self.ensure_active() {
                self.remove_wait_stream(&real_key).await;
                return Err(e.into());
            }
            let write_stream = Pin::new(&mut *write_stream);
            let open_resp_package = RTcpOpenRespPackage::new(open_package.seq, OPEN_RESULT_OK);
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
        self.ensure_active()?;

        let remote_addr = stream
            .peer_addr()
            .map_err(|e| anyhow::format_err!("get peer_addr error: {}", e))?;
        let local_addr = stream
            .local_addr()
            .map_err(|e| anyhow::format_err!("get local_addr error: {}", e))?;

        let purpose = open_package.body.purpose.unwrap_or_default();
        let (stream_key, stream_iv) =
            self.derive_stream_secrets(&open_package.body.stream_id, purpose)?;
        // This side received an Open and waited for the peer to connect back
        // with HelloStream, so it is the stream-layer responder.
        let aes_stream =
            EncryptedStream::new(stream, &stream_key, &stream_iv, EncryptionRole::Responder);

        debug!(
            "RTcp stream encryption initialized for open stream {}",
            open_package.body.stream_id
        );

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

    pub async fn run(&self) {
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

            let ret = tokio::select! {
                _ = self.close_notify.notified() => {
                    info!("RTcp tunnel {} instance {} closed, exit run loop", source_info, self.instance_id);
                    break;
                }
                ret = RTcpTunnelPackage::read_package(read_stream, false, source_info.as_str()) => ret,
            };
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
        drop(read_stream);
        self.close().await;
    }

    async fn post_ropen(
        &self,
        seq: u32,
        purpose: Option<StreamPurpose>,
        dest_port: u16,
        dest_host: Option<String>,
        session_key: &str,
    ) -> Result<(), std::io::Error> {
        self.ensure_active()?;
        let ropen_package =
            RTcpROpenPackage::new(seq, session_key.to_string(), purpose, dest_port, dest_host);
        let mut write_stream = self.write_stream.lock().await;
        self.ensure_active()?;
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
        self.ensure_active()?;
        let ropen_package =
            RTcpOpenPackage::new(seq, session_key.to_string(), purpose, dest_port, dest_host);
        let mut write_stream = self.write_stream.lock().await;
        self.ensure_active()?;
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
        let result = self.build_helper.wait_ropen_stream(&real_key).await;
        self.pending_wait_stream_keys.lock().await.remove(&real_key);
        result
    }

    async fn register_wait_stream(&self, real_key: &str) -> Result<(), std::io::Error> {
        self.ensure_active()?;
        self.build_helper.new_wait_stream(real_key).await?;
        self.pending_wait_stream_keys
            .lock()
            .await
            .insert(real_key.to_string());
        if let Err(e) = self.ensure_active() {
            self.remove_wait_stream(real_key).await;
            return Err(e);
        }
        Ok(())
    }

    async fn remove_wait_stream(&self, real_key: &str) {
        self.pending_wait_stream_keys.lock().await.remove(real_key);
        self.build_helper.remove_wait_stream(real_key).await;
    }

    async fn request_open_stream(
        &self,
        purpose: Option<StreamPurpose>,
        dest_port: u16,
        dest_host: Option<String>,
    ) -> Result<Box<dyn AsyncStream>, std::io::Error> {
        self.ensure_accepts_new_streams()?;
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

        let (session_key, _) = self.reserve_outbound_stream_id().await?;
        let effective_purpose = purpose.unwrap_or_default();
        let (stream_key, stream_iv) =
            self.derive_stream_secrets(&session_key, effective_purpose)?;
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
            if let Err(e) = self.ensure_active() {
                self.open_resp_waiters.lock().await.remove(&seq);
                return Err(e);
            }

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
                let (kind, message) = if result_code == OPEN_RESULT_KEY_EPOCH_EXHAUSTED {
                    (
                        std::io::ErrorKind::ConnectionAborted,
                        "peer exhausted RTCP stream ID key epoch; reconnect required".to_string(),
                    )
                } else {
                    (
                        std::io::ErrorKind::ConnectionRefused,
                        format!("peer rejected open stream, result={}", result_code),
                    )
                };
                return Err(std::io::Error::new(kind, message));
            }

            // Build a fresh stream leg to the remote RTCP listener. Direct
            // tunnels open TCP to peer_addr; bootstrap-backed tunnels replay
            // the nested transport via the tunnel framework.
            let (stream, _remote_addr, _local_addr) = self
                .build_reconnect_stream(session_key.as_str())
                .await
                .map_err(|e| {
                    error!(
                        "RTcp tunnel open stream to {} error: {}",
                        self.remote_stack.did.to_string(),
                        e
                    );
                    e
                })?;

            // Direct-open path: this side opened the reconnect stream and sent
            // HelloStream, so it is the stream-layer initiator. The transport
            // can be a direct TCP socket or a bootstrap-backed nested stream.
            let aes_stream: EncryptedStream<Box<dyn AsyncStream>> =
                EncryptedStream::new(stream, &stream_key, &stream_iv, EncryptionRole::Initiator);

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

            if let Err(e) = self.register_wait_stream(&real_key).await {
                self.ropen_resp_waiters.lock().await.remove(&seq);
                return Err(e);
            }

            //info!("insert session_key {} to wait ropen stream map",real_key.as_str());
            if let Err(e) = self
                .post_ropen(seq, purpose, dest_port, dest_host, session_key.as_str())
                .await
            {
                // Send failed: no HelloStream will ever arrive for this key,
                // so the waiting slot must be reclaimed now rather than
                // relying on the 30s timeout path.
                self.ropen_resp_waiters.lock().await.remove(&seq);
                self.remove_wait_stream(&real_key).await;
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
                            self.remove_wait_stream(&real_key).await;
                            let (kind, message) = if code == OPEN_RESULT_KEY_EPOCH_EXHAUSTED {
                                (
                                    std::io::ErrorKind::ConnectionAborted,
                                    "peer exhausted RTCP stream ID key epoch; reconnect required"
                                        .to_string(),
                                )
                            } else {
                                (
                                    std::io::ErrorKind::ConnectionRefused,
                                    format!("peer rejected ropen, result={}", code),
                                )
                            };
                            return Err(std::io::Error::new(
                                kind,
                                message,
                            ));
                        }
                        Err(_) => {
                            // Tunnel dropped the waiter (likely tunnel closed).
                            self.remove_wait_stream(&real_key).await;
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::BrokenPipe,
                                "tunnel dropped ropen resp waiter",
                            ));
                        }
                    }
                }
            };
            self.ensure_active()?;
            // ROpen path: this side sent ROpen and the peer connected back
            // with HelloStream, so it is the stream-layer responder.
            let aes_stream: EncryptedStream<TcpStream> =
                EncryptedStream::new(stream, &stream_key, &stream_iv, EncryptionRole::Responder);
            //info!("wait ropen stream ok,return aes stream: aes_key:{},nonce_bytes:{}",hex::encode(self.get_key()),hex::encode(random_bytes));
            Ok(Box::new(aes_stream))
        }
    }
}

#[async_trait]
impl Tunnel for RTcpTunnel {
    async fn ping(&self) -> Result<(), std::io::Error> {
        self.ensure_active()?;
        let timestamp = buckyos_get_unix_timestamp();
        let ping_package = RTcpPingPackage::new(0, timestamp);
        let mut write_stream = self.write_stream.lock().await;
        self.ensure_active()?;
        let write_stream = Pin::new(&mut *write_stream);
        RTcpTunnelPackage::send_package(write_stream, ping_package)
            .await
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    format!("send rtcp ping failed: {}", e),
                )
            })
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
        let client = RTcpTunnelDatagramClient::new_with_limit(stream, self.max_datagram_bytes);
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
        if let Err(e) = self.ensure_active() {
            self.pong_waiters.lock().await.remove(&seq);
            return Err(e);
        }

        let timestamp = buckyos_get_unix_timestamp();
        let ping_package = RTcpPingPackage::new(seq, timestamp);
        let send_result = {
            let mut write_stream = self.write_stream.lock().await;
            if let Err(e) = self.ensure_active() {
                self.pong_waiters.lock().await.remove(&seq);
                return Err(e);
            }
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
    tunnel_map: Arc<Mutex<RTcpTunnelMapState>>,
    // Serializes the verified-cache CAS result with publication into the
    // primary/secondary indexes.  Without this guard, old A could receive
    // Inserted, pause before indexing, let new B commit + scan, then resume
    // and publish itself after B's scan.  The map mutex is never held during
    // the cache write, and this guard is dropped before transport shutdown.
    authenticated_commit_lock: Arc<Mutex<()>>,
    // Terminal authority decisions and authenticated publication use the same
    // commit lock, closing the gap where a tunnel could be published after a
    // negative scan but before the Negative state became visible.
    authority_confirmations: Arc<Mutex<HashMap<String, AuthorityConfirmationState>>>,
    authority_state_generation: Arc<AtomicU64>,
}

#[derive(Default)]
struct RTcpTunnelMapState {
    tunnels: HashMap<String, RTcpTunnel>,
    verified_by_logical_did: HashMap<String, HashMap<u64, VerifiedTunnelIndexEntry>>,
    // Every instance currently holding a logical-name binding. Inbound
    // instances with a committed verified document and outbound instances
    // created for a named target both appear here; only the former also carry
    // a revision entry in verified_by_logical_did.
    binding_by_instance: HashMap<u64, InstanceNameBinding>,
    // Reverse uniqueness index for the one-to-one model: at any moment a
    // canonical DEV DID belongs to at most one verified logical name.
    // Addressing the same device directly by its did:dev is not a second
    // logical name and never appears here.
    binding_by_canonical_dev: HashMap<String, CanonicalDevBinding>,
}

#[derive(Clone)]
struct VerifiedTunnelIndexEntry {
    instance_id: u64,
    canonical_key: String,
    document_revision: DocumentRevision,
    tunnel: RTcpTunnel,
}

#[derive(Clone)]
struct InstanceNameBinding {
    logical_did: String,
    canonical_dev_did: String,
    canonical_key: String,
    tunnel: RTcpTunnel,
}

struct CanonicalDevBinding {
    logical_did: String,
    instances: HashSet<u64>,
}

struct InboundTunnelRegistration {
    accepted: bool,
    rejection_reason: Option<String>,
    replaced: Option<RTcpTunnel>,
    superseded: Vec<RTcpTunnel>,
    rejected: Option<RTcpTunnel>,
}

// Map publication precedes the final encrypted TunnelResult. If the handshake
// future is cancelled or the send fails in that narrow interval, Drop removes
// and closes the published candidate so create_tunnel can never observe a
// server-side entry whose acceptance was not delivered.
struct PublishedInboundGuard {
    tunnel_map: RTcpTunnelMap,
    tunnel_key: String,
    tunnel: RTcpTunnel,
    registration: Option<InboundTunnelRegistration>,
}

impl PublishedInboundGuard {
    fn new(
        tunnel_map: RTcpTunnelMap,
        tunnel_key: String,
        tunnel: RTcpTunnel,
        registration: InboundTunnelRegistration,
    ) -> Self {
        Self {
            tunnel_map,
            tunnel_key,
            tunnel,
            registration: Some(registration),
        }
    }

    fn disarm(mut self) -> InboundTunnelRegistration {
        self.registration
            .take()
            .expect("published inbound guard must own a registration")
    }
}

impl Drop for PublishedInboundGuard {
    fn drop(&mut self) {
        let Some(registration) = self.registration.take() else {
            return;
        };
        let accepted = registration.accepted;
        let tunnel_map = self.tunnel_map.clone();
        let tunnel_key = self.tunnel_key.clone();
        let tunnel = self.tunnel.clone();
        tunnel.mark_closed();
        task::spawn(async move {
            tunnel_map.remove_if_current(&tunnel_key, &tunnel).await;
            RTcpTunnelMap::finish_authenticated_registration(registration).await;
            if accepted {
                tunnel.close().await;
            }
        });
    }
}

// A named outbound target's verified resolution snapshot, used to arbitrate
// the one-to-one logical-name binding. Direct did:dev targets and zone
// (ZoneDocument) targets never produce one: a zone delegating to its gateway
// device is zone addressing, not a second device name.
#[derive(Clone, Debug)]
struct OutboundNameBinding {
    logical_did: String,
    canonical_dev_did: String,
}

enum OutboundRegisterError {
    // First-wins race: another creator registered this key; reuse its tunnel.
    Existing(RTcpTunnel),
    // One-to-one arbitration: the canonical DEV DID is bound to another
    // verified logical name. The new tunnel must be closed, not registered.
    BindingConflict(String),
    // A prior authority decision denied this logical identity. Outbound
    // publication shares the same final gate as authenticated inbound.
    AuthorityNegative(String),
}

impl RTcpTunnelMapState {
    fn remove_instance_binding(&mut self, instance_id: u64) -> bool {
        let Some(binding) = self.binding_by_instance.remove(&instance_id) else {
            return false;
        };
        let remove_logical_bucket =
            if let Some(entries) = self.verified_by_logical_did.get_mut(&binding.logical_did) {
                entries.remove(&instance_id);
                entries.is_empty()
            } else {
                false
            };
        if remove_logical_bucket {
            self.verified_by_logical_did.remove(&binding.logical_did);
        }
        let remove_reverse = if let Some(reverse) = self
            .binding_by_canonical_dev
            .get_mut(&binding.canonical_dev_did)
        {
            reverse.instances.remove(&instance_id);
            reverse.instances.is_empty()
        } else {
            false
        };
        if remove_reverse {
            self.binding_by_canonical_dev
                .remove(&binding.canonical_dev_did);
        }
        true
    }

    // Register both binding directions for an instance. The caller must have
    // arbitrated with conflicting_logical_binding() in the same critical
    // section; an existing binding here is therefore for the same name.
    fn record_instance_binding(
        &mut self,
        tunnel: &RTcpTunnel,
        logical_did: &str,
        canonical_dev_did: &str,
        canonical_key: &str,
    ) {
        self.binding_by_instance.insert(
            tunnel.instance_id(),
            InstanceNameBinding {
                logical_did: logical_did.to_string(),
                canonical_dev_did: canonical_dev_did.to_string(),
                canonical_key: canonical_key.to_string(),
                tunnel: tunnel.clone(),
            },
        );
        self.binding_by_canonical_dev
            .entry(canonical_dev_did.to_string())
            .or_insert_with(|| CanonicalDevBinding {
                logical_did: logical_did.to_string(),
                instances: HashSet::new(),
            })
            .instances
            .insert(tunnel.instance_id());
    }

    // One-to-one arbitration: returns the logical name a live binding already
    // reserves this canonical DEV DID for, when that name differs from the
    // candidate. A binding whose instances are all closed no longer defends
    // its name and is pruned here so delayed run-loop cleanup cannot block a
    // legitimate new binding.
    fn conflicting_logical_binding(
        &mut self,
        logical_did: &str,
        canonical_dev_did: &str,
    ) -> Option<String> {
        let binding = self.binding_by_canonical_dev.get(canonical_dev_did)?;
        if binding.logical_did == logical_did {
            return None;
        }
        let bound_logical = binding.logical_did.clone();
        let has_live_instance = binding.instances.iter().any(|instance_id| {
            self.binding_by_instance
                .get(instance_id)
                .map(|entry| !entry.tunnel.is_closed())
                .unwrap_or(false)
        });
        if has_live_instance {
            return Some(bound_logical);
        }
        let stale: Vec<u64> = binding.instances.iter().copied().collect();
        for instance_id in stale {
            self.remove_instance_binding(instance_id);
        }
        None
    }

    fn remove_primary_if_instance(&mut self, tunnel_key: &str, instance_id: u64) -> bool {
        let is_current = self
            .tunnels
            .get(tunnel_key)
            .map(|current| current.instance_id() == instance_id)
            .unwrap_or(false);
        if is_current {
            self.tunnels.remove(tunnel_key);
        }
        is_current
    }
}

// DocumentRevision deliberately exposes no total ordering: iat orders
// revisions, while the content hash distinguishes identity from a same-iat
// conflict.  "Strictly older" therefore follows name-client's own documented
// semantics and never uses the hash as a tie-breaker.
fn document_revision_is_strictly_older(
    candidate: &DocumentRevision,
    current: &DocumentRevision,
) -> bool {
    candidate.iat < current.iat
}

impl RTcpTunnelMap {
    pub fn new() -> Self {
        RTcpTunnelMap {
            tunnel_map: Arc::new(Mutex::new(RTcpTunnelMapState::default())),
            authenticated_commit_lock: Arc::new(Mutex::new(())),
            authority_confirmations: Arc::new(Mutex::new(HashMap::new())),
            authority_state_generation: Arc::new(AtomicU64::new(1)),
        }
    }

    async fn begin_authority_confirmation(
        &self,
        logical_did: &str,
        document_revision: &DocumentRevision,
        now: u64,
        max_age: Option<u64>,
    ) -> Option<AuthorityConfirmationTicket> {
        let mut states = self.authority_confirmations.lock().await;
        let should_start = match states.get(logical_did) {
            None => true,
            Some(AuthorityConfirmationState::InFlight(_))
            | Some(AuthorityConfirmationState::Negative(_)) => false,
            Some(AuthorityConfirmationState::Confirmed {
                completed_at,
                document_revision: confirmed_revision,
            })
            | Some(AuthorityConfirmationState::Unavailable {
                completed_at,
                document_revision: confirmed_revision,
            }) => {
                confirmed_revision != document_revision
                    || max_age
                        .map(|age| now.saturating_sub(*completed_at) >= age)
                        .unwrap_or(false)
            }
        };
        if !should_start {
            return None;
        }

        let ticket = AuthorityConfirmationTicket {
            generation: self
                .authority_state_generation
                .fetch_add(1, Ordering::Relaxed),
            document_revision: document_revision.clone(),
        };
        states.insert(
            logical_did.to_string(),
            AuthorityConfirmationState::InFlight(ticket.clone()),
        );
        Some(ticket)
    }

    async fn authority_negative_snapshot(
        &self,
        logical_did: &str,
    ) -> Option<AuthorityNegativeState> {
        match self.authority_confirmations.lock().await.get(logical_did) {
            Some(AuthorityConfirmationState::Negative(negative)) => Some(negative.clone()),
            _ => None,
        }
    }

    async fn authority_confirmed_revision(
        &self,
        logical_did: &str,
        document_revision: &DocumentRevision,
    ) -> bool {
        matches!(
            self.authority_confirmations.lock().await.get(logical_did),
            Some(AuthorityConfirmationState::Confirmed {
                document_revision: confirmed_revision,
                ..
            }) if confirmed_revision == document_revision
        )
    }

    async fn clear_authority_negative_if_current(
        &self,
        logical_did: &str,
        negative_generation: u64,
        document_revision: &DocumentRevision,
        completed_at: u64,
    ) -> bool {
        let _commit_guard = self.authenticated_commit_lock.lock().await;
        let mut states = self.authority_confirmations.lock().await;
        let can_clear = match states.get(logical_did) {
            Some(AuthorityConfirmationState::Negative(negative)) => {
                negative.generation == negative_generation
            }
            Some(AuthorityConfirmationState::Confirmed {
                document_revision: confirmed_revision,
                ..
            }) => return confirmed_revision == document_revision,
            _ => false,
        };
        if !can_clear {
            return false;
        }
        states.insert(
            logical_did.to_string(),
            AuthorityConfirmationState::Confirmed {
                completed_at,
                document_revision: document_revision.clone(),
            },
        );
        info!(
            "RTCP authority Negative recovered for {} with Current revision {:?}",
            logical_did, document_revision
        );
        true
    }

    async fn complete_authority_unavailable_if_current(
        &self,
        logical_did: &str,
        ticket: &AuthorityConfirmationTicket,
        completed_at: u64,
    ) {
        let mut states = self.authority_confirmations.lock().await;
        if matches!(
            states.get(logical_did),
            Some(AuthorityConfirmationState::InFlight(current)) if current == ticket
        ) {
            states.insert(
                logical_did.to_string(),
                AuthorityConfirmationState::Unavailable {
                    completed_at,
                    document_revision: ticket.document_revision.clone(),
                },
            );
        }
    }

    async fn complete_authority_confirmed_if_current(
        &self,
        logical_did: &str,
        ticket: &AuthorityConfirmationTicket,
        completed_at: u64,
    ) -> usize {
        let _commit_guard = self.authenticated_commit_lock.lock().await;
        let mut states = self.authority_confirmations.lock().await;
        if !matches!(
            states.get(logical_did),
            Some(AuthorityConfirmationState::InFlight(current)) if current == ticket
        ) {
            return 0;
        }
        states.insert(
            logical_did.to_string(),
            AuthorityConfirmationState::Confirmed {
                completed_at,
                document_revision: ticket.document_revision.clone(),
            },
        );
        drop(states);
        self.upgrade_verified_identity_revision_trust(
            logical_did,
            &ticket.document_revision,
            RtcpIdentityTrust::MethodAuthorityCurrent,
        )
        .await
    }

    pub async fn get_tunnel(&self, tunnel_key: &str) -> Option<RTcpTunnel> {
        let all_tunnel = self.tunnel_map.lock().await;
        all_tunnel.tunnels.get(tunnel_key).cloned()
    }

    // Outbound reuse with one-to-one arbitration: before reusing (or deciding
    // to build) a canonical tunnel for a named target, verify the canonical
    // DEV DID is not already bound to a different verified logical name. A
    // successful named reuse records the binding on the reused instance so a
    // later second name cannot silently share the tunnel either.
    pub async fn acquire_outbound(
        &self,
        tunnel_key: &str,
        binding: Option<&OutboundNameBinding>,
    ) -> Result<Option<RTcpTunnel>, String> {
        let _commit_guard = if binding.is_some() {
            Some(self.authenticated_commit_lock.lock().await)
        } else {
            None
        };
        if let Some(binding) = binding {
            if let Some(negative) = self.authority_negative_snapshot(&binding.logical_did).await {
                return Err(format!(
                    "authority Negative rejects logical identity {}: {}",
                    binding.logical_did, negative.reason
                ));
            }
        }
        let mut all_tunnel = self.tunnel_map.lock().await;
        if let Some(binding) = binding {
            if let Some(bound_logical) = all_tunnel
                .conflicting_logical_binding(&binding.logical_did, &binding.canonical_dev_did)
            {
                return Err(Self::binding_conflict_message(
                    &binding.logical_did,
                    &binding.canonical_dev_did,
                    &bound_logical,
                ));
            }
        }
        let Some(existing) = all_tunnel.tunnels.get(tunnel_key).cloned() else {
            return Ok(None);
        };
        if existing.is_closed() {
            all_tunnel.remove_primary_if_instance(tunnel_key, existing.instance_id());
            all_tunnel.remove_instance_binding(existing.instance_id());
            return Ok(None);
        }
        if let Some(binding) = binding {
            all_tunnel.record_instance_binding(
                &existing,
                &binding.logical_did,
                &binding.canonical_dev_did,
                tunnel_key,
            );
        }
        Ok(Some(existing))
    }

    // Rejection-only pre-check used before the expensive handshake steps.
    // The authoritative arbitration runs again inside the commit sequence
    // (replace_authenticated_inbound); this early answer can only reject a
    // handshake, never admit one.
    pub async fn find_conflicting_binding(
        &self,
        logical_did: &str,
        canonical_dev_did: &str,
    ) -> Option<String> {
        self.tunnel_map
            .lock()
            .await
            .conflicting_logical_binding(logical_did, canonical_dev_did)
    }

    fn binding_conflict_message(
        logical_did: &str,
        canonical_dev_did: &str,
        bound_logical: &str,
    ) -> String {
        format!(
            "canonical device {} is already bound to verified logical name {}; \
             one-to-one binding rejects logical name {}",
            canonical_dev_did, bound_logical, logical_did
        )
    }

    // Outbound creators retain first-wins semantics: concurrent local dials
    // reuse whichever tunnel registered first and close their extra tunnel.
    // A named creator additionally re-arbitrates the one-to-one binding under
    // the map lock; losing that arbitration rejects the new tunnel outright
    // instead of reusing a tunnel that belongs to another logical name.
    pub async fn register_outbound_if_absent(
        &self,
        tunnel_key: &str,
        tunnel: RTcpTunnel,
        binding: Option<&OutboundNameBinding>,
    ) -> Result<(), OutboundRegisterError> {
        let _commit_guard = if binding.is_some() {
            Some(self.authenticated_commit_lock.lock().await)
        } else {
            None
        };
        if let Some(binding) = binding {
            if let Some(negative) = self.authority_negative_snapshot(&binding.logical_did).await {
                return Err(OutboundRegisterError::AuthorityNegative(format!(
                    "authority Negative rejects logical identity {}: {}",
                    binding.logical_did, negative.reason
                )));
            }
        }
        let mut all_tunnel = self.tunnel_map.lock().await;
        if let Some(binding) = binding {
            if let Some(bound_logical) = all_tunnel
                .conflicting_logical_binding(&binding.logical_did, &binding.canonical_dev_did)
            {
                return Err(OutboundRegisterError::BindingConflict(
                    Self::binding_conflict_message(
                        &binding.logical_did,
                        &binding.canonical_dev_did,
                        &bound_logical,
                    ),
                ));
            }
        }
        if let Some(existing) = all_tunnel.tunnels.get(tunnel_key).cloned() {
            if !existing.is_closed() {
                if let Some(binding) = binding {
                    all_tunnel.record_instance_binding(
                        &existing,
                        &binding.logical_did,
                        &binding.canonical_dev_did,
                        tunnel_key,
                    );
                }
                return Err(OutboundRegisterError::Existing(existing));
            }
            debug!(
                "replace closed outbound RTcp tunnel {} instance {} with instance {}",
                tunnel_key,
                existing.instance_id(),
                tunnel.instance_id()
            );
            all_tunnel.remove_instance_binding(existing.instance_id());
        }
        info!(
            "register outbound RTcp tunnel {} instance {}",
            tunnel_key,
            tunnel.instance_id()
        );
        if let Some(binding) = binding {
            all_tunnel.record_instance_binding(
                &tunnel,
                &binding.logical_did,
                &binding.canonical_dev_did,
                tunnel_key,
            );
        }
        all_tunnel.tunnels.insert(tunnel_key.to_owned(), tunnel);
        Ok(())
    }

    // Authenticated inbound tunnels use first-accepted-wins while the indexed
    // instance is live. This keeps the responder's admission decision aligned
    // with the initiator's final TunnelResult. A closed indexed instance may be
    // replaced in the same critical section.
    pub async fn replace_authenticated_inbound(
        &self,
        tunnel_key: &str,
        tunnel: RTcpTunnel,
        verified_identity: Option<VerifiedTunnelIdentity>,
    ) -> InboundTunnelRegistration {
        let mut all_tunnel = self.tunnel_map.lock().await;
        if tunnel.is_closed() {
            // A delayed handshake-completion callback may race with an
            // authority/supersession kick.  It must not republish the closed
            // instance or scan and kick unrelated tunnels.
            all_tunnel.remove_primary_if_instance(tunnel_key, tunnel.instance_id());
            all_tunnel.remove_instance_binding(tunnel.instance_id());
            return InboundTunnelRegistration {
                accepted: false,
                rejection_reason: Some("candidate tunnel is already closed".to_string()),
                replaced: None,
                superseded: Vec::new(),
                rejected: Some(tunnel),
            };
        }

        if let Some(identity) = verified_identity.as_ref() {
            // One-to-one gate 1: the canonical DEV DID must not be bound to a
            // different live verified logical name. A conflicting connection
            // is rejected before the primary insert so it can never replace
            // the legitimate binding's tunnel.
            if let Some(bound_logical) = all_tunnel
                .conflicting_logical_binding(&identity.logical_did, &identity.canonical_dev_did)
            {
                warn!(
                    "reject authenticated inbound RTcp tunnel {} instance {}: {}",
                    tunnel_key,
                    tunnel.instance_id(),
                    Self::binding_conflict_message(
                        &identity.logical_did,
                        &identity.canonical_dev_did,
                        &bound_logical,
                    )
                );
                return InboundTunnelRegistration {
                    accepted: false,
                    rejection_reason: Some(Self::binding_conflict_message(
                        &identity.logical_did,
                        &identity.canonical_dev_did,
                        &bound_logical,
                    )),
                    replaced: None,
                    superseded: Vec::new(),
                    rejected: Some(tunnel),
                };
            }
            // One-to-one gate 2: a live same-name tunnel whose committed
            // document shares the candidate's revision iat but not its
            // content is a same-version conflict. name-client's CAS rejects
            // this ordering with RejectedConflict before we get here; this
            // in-map re-check keeps the race window fail-closed instead of
            // letting two bindings stay current.
            if let Some(entries) = all_tunnel
                .verified_by_logical_did
                .get(&identity.logical_did)
            {
                let conflicting = entries.values().find(|entry| {
                    !entry.tunnel.is_closed()
                        && entry.document_revision.iat == identity.document_revision.iat
                        && entry.document_revision != identity.document_revision
                });
                if let Some(entry) = conflicting {
                    error!(
                        "reject authenticated inbound RTcp tunnel {} instance {}: verified \
                         document for {} conflicts at the same revision iat {} with active \
                         instance {} under {}",
                        tunnel_key,
                        tunnel.instance_id(),
                        identity.logical_did,
                        identity.document_revision.iat,
                        entry.instance_id,
                        entry.canonical_key
                    );
                    return InboundTunnelRegistration {
                        accepted: false,
                        rejection_reason: Some(format!(
                            "verified document for {} conflicts at revision {}",
                            identity.logical_did, identity.document_revision.iat
                        )),
                        replaced: None,
                        superseded: Vec::new(),
                        rejected: Some(tunnel),
                    };
                }
            }
        }

        if let Some(existing) = all_tunnel.tunnels.get(tunnel_key).cloned() {
            if !existing.is_closed() {
                let reason = format!(
                    "tunnel {} already has active instance {}; first accepted tunnel wins",
                    tunnel_key,
                    existing.instance_id()
                );
                info!(
                    "reject duplicate authenticated inbound RTcp tunnel {} instance {}: {}",
                    tunnel_key,
                    tunnel.instance_id(),
                    reason
                );
                return InboundTunnelRegistration {
                    accepted: false,
                    rejection_reason: Some(reason),
                    replaced: None,
                    superseded: Vec::new(),
                    rejected: Some(tunnel),
                };
            }
        }

        let old_tunnel = all_tunnel
            .tunnels
            .insert(tunnel_key.to_owned(), tunnel.clone());
        if let Some(old_tunnel) = old_tunnel.as_ref() {
            old_tunnel.mark_closed();
            all_tunnel.remove_instance_binding(old_tunnel.instance_id());
            info!(
                "replace authenticated inbound RTcp tunnel {}: instance {} -> {}",
                tunnel_key,
                old_tunnel.instance_id(),
                tunnel.instance_id()
            );
        } else {
            info!(
                "register authenticated inbound RTcp tunnel {} instance {}",
                tunnel_key,
                tunnel.instance_id()
            );
        }

        let mut superseded = Vec::new();
        if let Some(identity) = verified_identity {
            let logical_did = identity.logical_did.clone();
            let new_revision = identity.document_revision.clone();
            let new_entry = VerifiedTunnelIndexEntry {
                instance_id: tunnel.instance_id(),
                canonical_key: tunnel_key.to_owned(),
                document_revision: new_revision.clone(),
                tunnel: tunnel.clone(),
            };
            all_tunnel
                .verified_by_logical_did
                .entry(logical_did.clone())
                .or_default()
                .insert(tunnel.instance_id(), new_entry);
            all_tunnel.record_instance_binding(
                &tunnel,
                &logical_did,
                &identity.canonical_dev_did,
                tunnel_key,
            );

            let indexed: Vec<VerifiedTunnelIndexEntry> = all_tunnel
                .verified_by_logical_did
                .get(&logical_did)
                .map(|entries| entries.values().cloned().collect())
                .unwrap_or_default();
            let mut stale_instance_ids = Vec::new();

            for entry in indexed {
                if entry.instance_id == tunnel.instance_id() {
                    continue;
                }

                if entry.tunnel.is_closed() {
                    stale_instance_ids.push(entry.instance_id);
                    all_tunnel.remove_primary_if_instance(&entry.canonical_key, entry.instance_id);
                    continue;
                }

                if document_revision_is_strictly_older(&entry.document_revision, &new_revision) {
                    // Mark under the map lock so no operation can start on the
                    // superseded key after the new revision is published.
                    // Waiter cleanup and transport shutdown remain lock-free.
                    // Removing the entry below also releases the old canonical
                    // key's reverse binding, completing the name's move to the
                    // new canonical DEV DID in the same critical section.
                    entry.tunnel.mark_closed();
                    stale_instance_ids.push(entry.instance_id);
                    all_tunnel.remove_primary_if_instance(&entry.canonical_key, entry.instance_id);
                    info!(
                        "close superseded verified RTcp tunnel for {}: key {}, instance {}, \
                         revision {:?} -> {:?}",
                        logical_did,
                        entry.canonical_key,
                        entry.instance_id,
                        entry.document_revision,
                        new_revision
                    );
                    superseded.push(entry.tunnel);
                    continue;
                }

                if entry.document_revision == new_revision && entry.canonical_key != tunnel_key {
                    // One document implies one default key and thus one
                    // canonical tunnel key. If this impossible-looking state
                    // is observed, log it but do not invent an ordering.
                    // A same-iat *different* revision cannot reach this scan:
                    // gate 2 rejects it before the primary insert.
                    warn!(
                        "same verified document revision for {} is active under different \
                         canonical keys: {} (instance {}) and {} (instance {}); keep both",
                        logical_did,
                        entry.canonical_key,
                        entry.instance_id,
                        tunnel_key,
                        tunnel.instance_id()
                    );
                }
            }

            for instance_id in stale_instance_ids {
                all_tunnel.remove_instance_binding(instance_id);
            }
        }

        InboundTunnelRegistration {
            accepted: true,
            rejection_reason: None,
            replaced: old_tunnel,
            superseded,
            rejected: None,
        }
    }

    // Complete the post-authentication handshake milestone. The dedicated
    // commit lock serializes name-client's cache CAS together with map/index
    // publication:
    //
    // - if old A is indexed before new B commits, B's scan closes A;
    // - if B commits first, A cannot have received a successful old outcome
    //   outside the lock; its later add_verified_cache returns IgnoredOlder
    //   and A closes without indexing.
    //
    // This also closes the "A got Inserted but paused before indexing" gap:
    // B cannot commit or scan until A has published and released the guard.
    pub async fn complete_authenticated_inbound(
        &self,
        tunnel_key: &str,
        tunnel: RTcpTunnel,
        verified_cache_entry: Option<PendingVerifiedCacheEntry>,
    ) -> NSResult<bool> {
        let registration = self
            .register_authenticated_inbound(tunnel_key, tunnel, verified_cache_entry)
            .await?;

        // The commit guard and map mutex are both gone before close() clears
        // waiters or shuts down a transport.
        Ok(Self::finish_authenticated_registration(registration).await)
    }

    // Register and return immediately after the atomic map publication. This
    // is the final await in the timeout-bounded inbound handshake path: all
    // transport shutdown and waiter cleanup happens after timeout returns.
    async fn register_authenticated_inbound(
        &self,
        tunnel_key: &str,
        tunnel: RTcpTunnel,
        verified_cache_entry: Option<PendingVerifiedCacheEntry>,
    ) -> NSResult<InboundTunnelRegistration> {
        let registration = if let Some(entry) = verified_cache_entry {
            let _commit_guard = self.authenticated_commit_lock.lock().await;
            let logical_did = entry.identity.logical_did.clone();
            let document_revision = entry.identity.document_revision.clone();
            let (negative, authority_confirmed) = {
                let states = self.authority_confirmations.lock().await;
                match states.get(&logical_did) {
                    Some(AuthorityConfirmationState::Negative(negative)) => {
                        (Some(negative.clone()), false)
                    }
                    Some(AuthorityConfirmationState::Confirmed {
                        document_revision: confirmed_revision,
                        ..
                    }) if confirmed_revision == &document_revision => (None, true),
                    _ => (None, false),
                }
            };
            if let Some(negative) = negative {
                let reason = format!(
                    "authority Negative rejects identity {}: {} (at {}, rejected revision {:?})",
                    logical_did, negative.reason, negative.completed_at, negative.rejected_revision
                );
                warn!(
                    "reject authenticated inbound RTcp tunnel {} instance {} before cache commit: {}",
                    tunnel_key,
                    tunnel.instance_id(),
                    reason
                );
                tunnel.mark_closed();
                return Ok(InboundTunnelRegistration {
                    accepted: false,
                    rejection_reason: Some(reason),
                    replaced: None,
                    superseded: Vec::new(),
                    rejected: Some(tunnel),
                });
            }

            let mut verified_commit = RTcpInner::commit_verified_cache_entry(Some(entry))?;
            if authority_confirmed {
                if let Some((_, outcome)) = verified_commit.as_mut() {
                    // Recovery first stores the exact Current document with
                    // Published evidence. The later handshake commit carries
                    // lower Verified evidence and is therefore IgnoredOlder;
                    // the matching authority revision proves the content is
                    // already present at a stronger evidence level.
                    if *outcome == CacheWriteOutcome::IgnoredOlder {
                        *outcome = CacheWriteOutcome::AlreadyPresent;
                    }
                }
            }
            if let Some((identity, outcome)) = verified_commit.as_ref() {
                debug!(
                    "verified-cache arbitration for accepted device document {}: {:?}",
                    identity.logical_did, outcome
                );
            }
            self.arbitrate_authenticated_inbound(tunnel_key, tunnel, verified_commit)
                .await
        } else {
            self.arbitrate_authenticated_inbound(tunnel_key, tunnel, None)
                .await
        };

        Ok(registration)
    }

    #[cfg(test)]
    async fn complete_authenticated_inbound_with_outcome(
        &self,
        tunnel_key: &str,
        tunnel: RTcpTunnel,
        verified_commit: Option<(VerifiedTunnelIdentity, CacheWriteOutcome)>,
    ) -> bool {
        let registration = if verified_commit.is_some() {
            let _commit_guard = self.authenticated_commit_lock.lock().await;
            let negative = if let Some((identity, _)) = verified_commit.as_ref() {
                match self
                    .authority_confirmations
                    .lock()
                    .await
                    .get(&identity.logical_did)
                    .cloned()
                {
                    Some(AuthorityConfirmationState::Negative(negative)) => {
                        Some((identity.logical_did.clone(), negative))
                    }
                    _ => None,
                }
            } else {
                None
            };
            if let Some((logical_did, negative)) = negative {
                let reason = format!(
                    "authority Negative rejects identity {}: {}",
                    logical_did, negative.reason
                );
                tunnel.mark_closed();
                InboundTunnelRegistration {
                    accepted: false,
                    rejection_reason: Some(reason),
                    replaced: None,
                    superseded: Vec::new(),
                    rejected: Some(tunnel),
                }
            } else {
                self.arbitrate_authenticated_inbound(tunnel_key, tunnel, verified_commit)
                    .await
            }
        } else {
            self.arbitrate_authenticated_inbound(tunnel_key, tunnel, None)
                .await
        };
        Self::finish_authenticated_registration(registration).await
    }

    async fn arbitrate_authenticated_inbound(
        &self,
        tunnel_key: &str,
        tunnel: RTcpTunnel,
        verified_commit: Option<(VerifiedTunnelIdentity, CacheWriteOutcome)>,
    ) -> InboundTunnelRegistration {
        let verified_identity = match verified_commit {
            Some((identity, outcome)) if outcome.stored() => {
                match DID::from_str(&identity.logical_did) {
                    Ok(did) if did.method != "dev" => Some(identity),
                    _ => {
                        // A cryptographically verified key DID may still be
                        // cached, but it is not a logical/named identity and
                        // must not gain a bucket in the revocation index.
                        debug!(
                            "do not index non-named verified RTcp identity {}",
                            identity.logical_did
                        );
                        None
                    }
                }
            }
            Some((identity, outcome)) => {
                warn!(
                    "reject authenticated inbound RTcp tunnel {} instance {} for verified \
                     identity {} after cache arbitration: {:?}",
                    tunnel_key,
                    tunnel.instance_id(),
                    identity.logical_did,
                    outcome
                );
                // The instance may already have been marked closed by a
                // concurrent kick. compare-and-remove makes this cleanup safe.
                tunnel.mark_closed();
                self.remove_if_current(tunnel_key, &tunnel).await;
                return InboundTunnelRegistration {
                    accepted: false,
                    rejection_reason: Some(format!(
                        "verified cache arbitration rejected identity {}: {:?}",
                        identity.logical_did, outcome
                    )),
                    replaced: None,
                    superseded: Vec::new(),
                    rejected: Some(tunnel),
                };
            }
            None => None,
        };

        self.replace_authenticated_inbound(tunnel_key, tunnel, verified_identity)
            .await
    }

    async fn finish_authenticated_registration(registration: InboundTunnelRegistration) -> bool {
        if let Some(rejected) = registration.rejected {
            rejected.close().await;
        }
        if let Some(replaced) = registration.replaced {
            replaced.close().await;
        }
        for superseded in registration.superseded {
            superseded.close().await;
        }
        registration.accepted
    }

    // Remove only when the map still points at the exact instance whose run
    // loop is exiting. A superseded tunnel must never delete its replacement.
    // Its secondary-index entry is independently compare-removed even when
    // the primary slot has already moved to a newer instance.
    pub async fn remove_if_current(&self, tunnel_key: &str, tunnel: &RTcpTunnel) -> bool {
        let mut all_tunnel = self.tunnel_map.lock().await;
        let is_current = all_tunnel
            .tunnels
            .get(tunnel_key)
            .map(|current| current.is_same_instance(tunnel))
            .unwrap_or(false);
        if is_current {
            all_tunnel.tunnels.remove(tunnel_key);
            debug!(
                "remove current RTcp tunnel {} instance {}",
                tunnel_key,
                tunnel.instance_id()
            );
        } else {
            debug!(
                "skip removing stale RTcp tunnel {} instance {}",
                tunnel_key,
                tunnel.instance_id()
            );
        }
        all_tunnel.remove_instance_binding(tunnel.instance_id());
        is_current
    }

    async fn detach_verified_identity_instances(
        &self,
        logical_did: &str,
        reason: &str,
    ) -> Vec<RTcpTunnel> {
        let mut all_tunnel = self.tunnel_map.lock().await;
        let bound_instance_ids: Vec<u64> = all_tunnel
            .binding_by_instance
            .iter()
            .filter(|(_, binding)| binding.logical_did == logical_did)
            .map(|(instance_id, _)| *instance_id)
            .collect();
        let mut tunnels = Vec::with_capacity(bound_instance_ids.len());
        for instance_id in bound_instance_ids {
            let Some(binding) = all_tunnel.binding_by_instance.get(&instance_id).cloned() else {
                continue;
            };
            let revision = all_tunnel
                .verified_by_logical_did
                .get(logical_did)
                .and_then(|entries| entries.get(&instance_id))
                .map(|entry| entry.document_revision.clone());
            binding.tunnel.mark_closed();
            all_tunnel.remove_primary_if_instance(&binding.canonical_key, instance_id);
            all_tunnel.remove_instance_binding(instance_id);
            info!(
                "close verified RTcp tunnel for {} after {}: key {}, instance {}, revision {:?}",
                logical_did, reason, binding.canonical_key, instance_id, revision
            );
            tunnels.push(binding.tunnel);
        }
        tunnels
    }

    async fn complete_authority_negative_if_current(
        &self,
        logical_did: &str,
        ticket: &AuthorityConfirmationTicket,
        completed_at: u64,
        reason: &str,
    ) -> usize {
        let commit_guard = self.authenticated_commit_lock.lock().await;
        let mut states = self.authority_confirmations.lock().await;
        if !matches!(
            states.get(logical_did),
            Some(AuthorityConfirmationState::InFlight(current)) if current == ticket
        ) {
            debug!(
                "ignore stale RTCP authority Negative for {} revision {:?}",
                logical_did, ticket.document_revision
            );
            return 0;
        }
        states.insert(
            logical_did.to_string(),
            AuthorityConfirmationState::Negative(AuthorityNegativeState {
                completed_at,
                generation: ticket.generation,
                reason: reason.to_string(),
                rejected_revision: Some(ticket.document_revision.clone()),
            }),
        );
        drop(states);

        let tunnels = self
            .detach_verified_identity_instances(logical_did, reason)
            .await;
        drop(commit_guard);
        let count = tunnels.len();
        for tunnel in tunnels {
            tunnel.close().await;
        }
        count
    }

    #[cfg(test)]
    async fn force_authority_negative(
        &self,
        logical_did: &str,
        rejected_revision: Option<DocumentRevision>,
        reason: &str,
    ) -> usize {
        let commit_guard = self.authenticated_commit_lock.lock().await;
        let generation = self
            .authority_state_generation
            .fetch_add(1, Ordering::Relaxed);
        self.authority_confirmations.lock().await.insert(
            logical_did.to_string(),
            AuthorityConfirmationState::Negative(AuthorityNegativeState {
                completed_at: buckyos_get_unix_timestamp(),
                generation,
                reason: reason.to_string(),
                rejected_revision,
            }),
        );
        let tunnels = self
            .detach_verified_identity_instances(logical_did, reason)
            .await;
        drop(commit_guard);
        let count = tunnels.len();
        for tunnel in tunnels {
            tunnel.close().await;
        }
        count
    }

    // Generic identity shutdown remains available for non-authority callers.
    // Authority negatives use complete_authority_negative_if_current so the
    // state write and this detach share one commit-lock critical section.
    pub async fn close_verified_identity(&self, logical_did: &str, reason: &str) -> usize {
        let commit_guard = self.authenticated_commit_lock.lock().await;
        let tunnels = self
            .detach_verified_identity_instances(logical_did, reason)
            .await;
        drop(commit_guard);
        let count = tunnels.len();
        for tunnel in tunnels {
            tunnel.close().await;
        }
        count
    }

    async fn upgrade_verified_identity_revision_trust(
        &self,
        logical_did: &str,
        document_revision: &DocumentRevision,
        trust: RtcpIdentityTrust,
    ) -> usize {
        let tunnels: Vec<RTcpTunnel> = self
            .tunnel_map
            .lock()
            .await
            .verified_by_logical_did
            .get(logical_did)
            .map(|entries| {
                entries
                    .values()
                    .filter(|entry| {
                        !entry.tunnel.is_closed() && &entry.document_revision == document_revision
                    })
                    .map(|entry| entry.tunnel.clone())
                    .collect()
            })
            .unwrap_or_default();
        for tunnel in &tunnels {
            tunnel.upgrade_identity_trust(trust);
        }
        tunnels.len()
    }

    #[cfg(test)]
    async fn primary_len(&self) -> usize {
        self.tunnel_map.lock().await.tunnels.len()
    }

    #[cfg(test)]
    async fn verified_identity_len(&self, logical_did: &str) -> usize {
        self.tunnel_map
            .lock()
            .await
            .verified_by_logical_did
            .get(logical_did)
            .map(HashMap::len)
            .unwrap_or(0)
    }

    #[cfg(test)]
    async fn is_verified_instance_indexed(&self, tunnel: &RTcpTunnel) -> bool {
        self.tunnel_map
            .lock()
            .await
            .binding_by_instance
            .contains_key(&tunnel.instance_id())
    }

    #[cfg(test)]
    async fn bound_logical_for_dev(&self, canonical_dev_did: &str) -> Option<String> {
        self.tunnel_map
            .lock()
            .await
            .binding_by_canonical_dev
            .get(canonical_dev_did)
            .map(|binding| binding.logical_did.clone())
    }

    #[cfg(test)]
    async fn binding_len(&self) -> usize {
        let state = self.tunnel_map.lock().await;
        debug_assert_eq!(
            state.binding_by_instance.len(),
            state
                .binding_by_canonical_dev
                .values()
                .map(|binding| binding.instances.len())
                .sum::<usize>(),
            "binding index directions must stay consistent"
        );
        state.binding_by_instance.len()
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};

    fn test_tunnel(seed: u8) -> (RTcpTunnel, tokio::io::DuplexStream) {
        test_tunnel_with_limits(seed, &RtcpLimitsConfig::default())
    }

    fn test_tunnel_with_limits(
        seed: u8,
        limits: &RtcpLimitsConfig,
    ) -> (RTcpTunnel, tokio::io::DuplexStream) {
        let (bearing, peer) = tokio::io::duplex(64 * 1024);
        let bearing: RTcpBearingStream = Box::new(bearing);
        let encrypted_stream = EncryptedStream::new(
            bearing,
            &[seed; 32],
            &[seed.wrapping_add(1); 16],
            EncryptionRole::Initiator,
        );
        let remote_stack = RTcpTargetStackEP {
            did: DID::new("dev", "rtcp-map-test-peer"),
            stack_port: DEFAULT_RTCP_STACK_PORT,
            bootstrap_stream_url: None,
        };
        (
            RTcpTunnel::new(
                RTcpStreamBuildHelper::new(),
                DID::new("dev", "rtcp-map-test-local"),
                &remote_stack,
                RtcpAddressResolutionContext::without_device_info(
                    remote_stack.did.clone(),
                    ResolveIpTargetKind::Unknown,
                    ResolveIpZoneRelation::Unknown,
                ),
                false,
                encrypted_stream,
                None,
                None,
                [seed; 32],
                limits,
                Arc::new(MockRTcpListener::new()),
            ),
            peer,
        )
    }

    fn assert_device_info_disabled(
        context: &RtcpAddressResolutionContext,
        target_kind: ResolveIpTargetKind,
        zone_relation: ResolveIpZoneRelation,
    ) {
        assert_eq!(context.options.target_kind(), target_kind);
        assert_eq!(context.options.zone_relation(), zone_relation);
        assert!(matches!(
            context.options.device_info_policy(),
            DeviceInfoPolicy::Disabled
        ));
    }

    #[test]
    fn address_resolution_scope_requires_verified_same_zone_device_relation() {
        let owner_did = DID::from_str("did:web:owner.scope.test").unwrap();
        let local_zone_did = DID::from_str("did:web:zone.scope.test").unwrap();
        let target_did = DID::from_str("did:web:device.scope.test").unwrap();
        let mut inner = RTcpInner::new(
            DID::new("dev", "scope-local"),
            "127.0.0.1:0".to_string(),
            None,
            None,
            Arc::new(MockRTcpListener::new()),
        );
        inner.this_owner_did = Some(owner_did.clone());
        inner.this_zone_did = Some(local_zone_did.clone());

        let (mut same_zone_device, _) = test_device_config("scope-same-zone");
        same_zone_device.owner = owner_did.clone();
        same_zone_device.zone_did = Some(local_zone_did.clone());
        let same_zone_context = inner.address_resolution_for_document(
            &target_did,
            &ResolvedHandshakeDocument::Device(same_zone_device.clone()),
        );
        assert_eq!(
            same_zone_context.options.target_kind(),
            ResolveIpTargetKind::Device
        );
        assert_eq!(
            same_zone_context.options.zone_relation(),
            ResolveIpZoneRelation::SameZone
        );
        match same_zone_context.options.device_info_policy() {
            DeviceInfoPolicy::VerifiedSameZone(evidence) => {
                assert_eq!(evidence.target_did(), &target_did);
                assert_eq!(evidence.zone_did(), &local_zone_did);
                assert_eq!(
                    evidence.source(),
                    SameZoneEvidenceSource::VerifiedHandshakeIdentity
                );
            }
            DeviceInfoPolicy::Disabled => panic!("verified same-zone device must allow Info"),
        }

        let mut cross_zone_device = same_zone_device.clone();
        cross_zone_device.zone_did = Some(DID::from_str("did:web:other-zone.scope.test").unwrap());
        let cross_zone_context = inner.address_resolution_for_document(
            &target_did,
            &ResolvedHandshakeDocument::Device(cross_zone_device),
        );
        assert_device_info_disabled(
            &cross_zone_context,
            ResolveIpTargetKind::Device,
            ResolveIpZoneRelation::CrossZone,
        );

        let mut unknown_zone_device = same_zone_device;
        unknown_zone_device.zone_did = None;
        let unknown_context = inner.address_resolution_for_document(
            &target_did,
            &ResolvedHandshakeDocument::Device(unknown_zone_device),
        );
        assert_device_info_disabled(
            &unknown_context,
            ResolveIpTargetKind::Device,
            ResolveIpZoneRelation::Unknown,
        );

        let (zone_signing_key, _) = generate_ed25519_key();
        let zone_jwk = serde_json::from_value(encode_ed25519_sk_to_pk_jwk(&zone_signing_key))
            .expect("test zone JWK");
        let remote_zone_did = DID::from_str("did:web:sn.remote-zone.scope.test").unwrap();
        let remote_zone_document =
            ZoneDocument::new(remote_zone_did.clone(), owner_did, zone_jwk);
        let zone_context = inner.address_resolution_for_document(
            &remote_zone_did,
            &ResolvedHandshakeDocument::Zone(remote_zone_document),
        );
        assert_device_info_disabled(
            &zone_context,
            ResolveIpTargetKind::Zone,
            ResolveIpZoneRelation::CrossZone,
        );
    }

    #[test]
    fn cross_zone_scope_is_preserved_for_initial_and_reconnect_resolution() {
        let remote_did = DID::from_str("did:web:sn.cross-zone.test").unwrap();
        let initial_context = RtcpAddressResolutionContext::without_device_info(
            remote_did.clone(),
            ResolveIpTargetKind::Zone,
            ResolveIpZoneRelation::CrossZone,
        );
        assert_device_info_disabled(
            &initial_context,
            ResolveIpTargetKind::Zone,
            ResolveIpZoneRelation::CrossZone,
        );

        let (bearing, _peer) = tokio::io::duplex(64 * 1024);
        let encrypted_stream = EncryptedStream::new(
            Box::new(bearing) as RTcpBearingStream,
            &[41; 32],
            &[42; 16],
            EncryptionRole::Initiator,
        );
        let remote_stack = RTcpTargetStackEP {
            did: remote_did,
            stack_port: DEFAULT_RTCP_STACK_PORT,
            bootstrap_stream_url: None,
        };
        let tunnel = RTcpTunnel::new(
            RTcpStreamBuildHelper::new(),
            DID::new("dev", "scope-reuse-local"),
            &remote_stack,
            initial_context.clone(),
            true,
            encrypted_stream,
            Some(SocketAddr::from(([127, 0, 0, 1], DEFAULT_RTCP_STACK_PORT))),
            None,
            [41; 32],
            &RtcpLimitsConfig::default(),
            Arc::new(MockRTcpListener::new()),
        );

        assert_eq!(tunnel.address_resolution, initial_context);
        assert_device_info_disabled(
            &tunnel.address_resolution,
            ResolveIpTargetKind::Zone,
            ResolveIpZoneRelation::CrossZone,
        );
    }

    // The canonical DEV DID follows the content hash: rotating to a new
    // revision hash models a key rotation, while cloning the same identity
    // keeps the same canonical device, matching how production derives the
    // canonical DID from the verified document's default key.
    fn verified_test_identity(logical_did: &str, iat: u64, hash: &str) -> VerifiedTunnelIdentity {
        verified_test_identity_bound(logical_did, iat, hash, &format!("did:dev:{}", hash))
    }

    fn verified_test_identity_bound(
        logical_did: &str,
        iat: u64,
        hash: &str,
        canonical_dev_did: &str,
    ) -> VerifiedTunnelIdentity {
        VerifiedTunnelIdentity {
            logical_did: logical_did.to_string(),
            canonical_dev_did: canonical_dev_did.to_string(),
            document_revision: DocumentRevision {
                iat,
                content_hash: hash.to_string(),
            },
        }
    }

    fn authority_not_current(reason: AuthorityNotCurrentReason) -> AuthorityFreshness {
        AuthorityFreshness::NotCurrent {
            reason,
            authority_seq: None,
            current_document_iat: None,
            checked_at: 1,
            source: "test-authority".to_string(),
        }
    }

    #[test]
    fn authority_confirmation_keeps_unpublished_device_snapshot() {
        for status in [
            DocumentStatus::Missing,
            DocumentStatus::Expired,
            DocumentStatus::Migrated,
        ] {
            let authority =
                authority_not_current(AuthorityNotCurrentReason::NegativeStatus(status));
            assert!(
                !RTcpInner::authority_confirmation_rejects_snapshot(&authority),
                "non-terminal authority status must retain trusted snapshot: {:?}",
                authority
            );
        }

        for reason in [
            AuthorityNotCurrentReason::DifferentDocument,
            AuthorityNotCurrentReason::Superseded,
            AuthorityNotCurrentReason::NegativeStatus(DocumentStatus::Revoked),
            AuthorityNotCurrentReason::NegativeStatus(DocumentStatus::Tombstoned),
        ] {
            let authority = authority_not_current(reason);
            assert!(
                RTcpInner::authority_confirmation_rejects_snapshot(&authority),
                "a conflicting, superseded, or terminal document must reject the snapshot: {:?}",
                authority
            );
        }
    }

    #[test]
    fn stream_kdf_separates_id_purpose_and_rejects_noncanonical_ids() {
        let (tunnel, _peer) = test_tunnel(91);
        let id_a = "00112233445566778899aabbccddeeff";
        let id_b = "10112233445566778899aabbccddeeff";
        let stream_a = tunnel
            .derive_stream_secrets(id_a, StreamPurpose::Stream)
            .unwrap();
        assert_eq!(
            stream_a,
            tunnel
                .derive_stream_secrets(id_a, StreamPurpose::Stream)
                .unwrap()
        );
        assert_ne!(
            stream_a,
            tunnel
                .derive_stream_secrets(id_b, StreamPurpose::Stream)
                .unwrap()
        );
        assert_ne!(
            stream_a,
            tunnel
                .derive_stream_secrets(id_a, StreamPurpose::Datagram)
                .unwrap()
        );
        for invalid in ["", "abcd", "00112233445566778899aabbccddeefg"] {
            assert!(
                tunnel
                    .derive_stream_secrets(invalid, StreamPurpose::Stream)
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn inbound_stream_ids_are_unique_and_share_one_build_quota() {
        let (bearing, peer) = tokio::io::duplex(64 * 1024);
        let bearing: RTcpBearingStream = Box::new(bearing);
        let encrypted_stream =
            EncryptedStream::new_control(bearing, &[92; 32], &[93; 16], EncryptionRole::Initiator);
        let remote_stack = RTcpTargetStackEP {
            did: DID::new("dev", "rtcp-quota-peer"),
            stack_port: DEFAULT_RTCP_STACK_PORT,
            bootstrap_stream_url: None,
        };
        let mut limits = RtcpLimitsConfig::default();
        limits.max_pending_stream_builds_per_tunnel = 1;
        let tunnel = RTcpTunnel::new(
            RTcpStreamBuildHelper::new(),
            DID::new("dev", "rtcp-quota-local"),
            &remote_stack,
            RtcpAddressResolutionContext::without_device_info(
                remote_stack.did.clone(),
                ResolveIpTargetKind::Unknown,
                ResolveIpZoneRelation::Unknown,
            ),
            false,
            encrypted_stream,
            None,
            None,
            [92; 32],
            &limits,
            Arc::new(MockRTcpListener::new()),
        );
        let first_id = "00112233445566778899aabbccddeeff";
        let second_id = "10112233445566778899aabbccddeeff";
        let permit = tunnel.admit_inbound_stream_build(first_id).await.unwrap();
        assert_eq!(
            tunnel
                .admit_inbound_stream_build(first_id)
                .await
                .unwrap_err(),
            OPEN_RESULT_DUPLICATE_STREAM_ID
        );
        assert_eq!(
            tunnel
                .admit_inbound_stream_build(second_id)
                .await
                .unwrap_err(),
            OPEN_RESULT_QUOTA
        );
        drop(permit);
        drop(peer);
    }

    #[tokio::test]
    async fn inbound_stream_id_history_stops_at_configured_epoch_limit() {
        let mut limits = RtcpLimitsConfig::default();
        limits.max_stream_ids_per_tunnel = 3;
        limits.stream_requests_per_second = 100_000;
        limits.stream_request_burst = 1024;
        let (tunnel, _peer) = test_tunnel_with_limits(93, &limits);
        let accepted = [
            "00112233445566778899aabbccddeeff",
            "10112233445566778899aabbccddeeff",
            "20112233445566778899aabbccddeeff",
        ];

        for stream_id in accepted {
            let permit = tunnel.admit_inbound_stream_build(stream_id).await.unwrap();
            drop(permit);
        }
        assert_eq!(tunnel.used_stream_ids.lock().await.len(), 3);

        // Canonical byte storage rejects an uppercase replay even at the cap.
        assert_eq!(
            tunnel
                .admit_inbound_stream_build("00112233445566778899AABBCCDDEEFF")
                .await
                .unwrap_err(),
            OPEN_RESULT_DUPLICATE_STREAM_ID
        );

        for value in 10u128..138 {
            let stream_id = format!("{value:032x}");
            assert_eq!(
                tunnel
                    .admit_inbound_stream_build(&stream_id)
                    .await
                    .unwrap_err(),
                OPEN_RESULT_KEY_EPOCH_EXHAUSTED
            );
        }
        assert_eq!(tunnel.used_stream_ids.lock().await.len(), 3);
    }

    #[tokio::test]
    async fn unused_outbound_reservations_consume_limit_and_close_releases_history() {
        let mut limits = RtcpLimitsConfig::default();
        limits.max_stream_ids_per_tunnel = 2;
        let (tunnel, _peer) = test_tunnel_with_limits(94, &limits);
        let retained_clone = tunnel.clone();

        // Reserving IDs is enough to consume the budget even though no stream
        // leg is built; failed connection attempts must never make an ID
        // reusable within this key epoch.
        tunnel.reserve_outbound_stream_id().await.unwrap();
        tunnel.reserve_outbound_stream_id().await.unwrap();
        assert_eq!(tunnel.used_stream_ids.lock().await.len(), 2);

        let error = tunnel.reserve_outbound_stream_id().await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
        assert!(tunnel.is_closed());
        assert!(retained_clone.used_stream_ids.lock().await.is_empty());
    }

    #[tokio::test]
    async fn stream_id_can_be_reused_only_after_tunnel_key_epoch_closes() {
        let mut limits = RtcpLimitsConfig::default();
        limits.max_stream_ids_per_tunnel = 1;
        let stream_id = "00112233445566778899aabbccddeeff";
        let (old_tunnel, _old_peer) = test_tunnel_with_limits(95, &limits);

        let permit = old_tunnel
            .admit_inbound_stream_build(stream_id)
            .await
            .unwrap();
        drop(permit);
        assert_eq!(
            old_tunnel
                .admit_inbound_stream_build(stream_id)
                .await
                .unwrap_err(),
            OPEN_RESULT_DUPLICATE_STREAM_ID
        );
        old_tunnel.close().await;
        assert!(old_tunnel.used_stream_ids.lock().await.is_empty());

        let (new_tunnel, _new_peer) = test_tunnel_with_limits(96, &limits);
        let permit = new_tunnel
            .admit_inbound_stream_build(stream_id)
            .await
            .unwrap();
        drop(permit);
    }

    #[tokio::test]
    async fn inbound_epoch_exhaustion_is_reported_before_tunnel_closes() {
        let mut limits = RtcpLimitsConfig::default();
        limits.max_stream_ids_per_tunnel = 1;
        let (bearing, peer) = tokio::io::duplex(64 * 1024);
        let encrypted_stream = EncryptedStream::new_control(
            Box::new(bearing) as RTcpBearingStream,
            &[97; 32],
            &[98; 16],
            EncryptionRole::Initiator,
        );
        let mut encrypted_peer =
            EncryptedStream::new_control(peer, &[97; 32], &[98; 16], EncryptionRole::Responder);
        let remote_stack = RTcpTargetStackEP {
            did: DID::new("dev", "rtcp-exhaustion-peer"),
            stack_port: DEFAULT_RTCP_STACK_PORT,
            bootstrap_stream_url: None,
        };
        let tunnel = RTcpTunnel::new(
            RTcpStreamBuildHelper::new(),
            DID::new("dev", "rtcp-exhaustion-local"),
            &remote_stack,
            RtcpAddressResolutionContext::without_device_info(
                remote_stack.did.clone(),
                ResolveIpTargetKind::Unknown,
                ResolveIpZoneRelation::Unknown,
            ),
            false,
            encrypted_stream,
            None,
            None,
            [97; 32],
            &limits,
            Arc::new(MockRTcpListener::new()),
        );

        let permit = tunnel
            .admit_inbound_stream_build("00112233445566778899aabbccddeeff")
            .await
            .unwrap();
        drop(permit);
        tunnel
            .process_package(RTcpTunnelPackage::Open(RTcpOpenPackage::new(
                42,
                "10112233445566778899aabbccddeeff".to_string(),
                Some(StreamPurpose::Stream),
                443,
                Some("service.example".to_string()),
            )))
            .await
            .unwrap();

        let response = timeout(
            Duration::from_secs(1),
            RTcpTunnelPackage::read_package(Pin::new(&mut encrypted_peer), false, "test-peer"),
        )
        .await
        .unwrap()
        .unwrap();
        match response {
            RTcpTunnelPackage::OpenResp(response) => {
                assert_eq!(response.seq, 42);
                assert_eq!(response.body.result, OPEN_RESULT_KEY_EPOCH_EXHAUSTED);
            }
            other => panic!("unexpected exhaustion response: {:?}", other),
        }
        assert!(tunnel.is_closed());
        assert!(tunnel.used_stream_ids.lock().await.is_empty());
    }

    #[tokio::test]
    async fn peer_epoch_exhaustion_result_closes_local_tunnel_after_waking_waiter() {
        let (tunnel, _peer) = test_tunnel(99);
        tunnel.used_stream_ids.lock().await.insert([1; 16]);
        let (sender, receiver) = oneshot::channel();
        tunnel.open_resp_waiters.lock().await.insert(7, sender);

        tunnel
            .process_package(RTcpTunnelPackage::OpenResp(RTcpOpenRespPackage::new(
                7,
                OPEN_RESULT_KEY_EPOCH_EXHAUSTED,
            )))
            .await
            .unwrap();

        assert_eq!(receiver.await.unwrap(), OPEN_RESULT_KEY_EPOCH_EXHAUSTED);
        assert!(tunnel.is_closed());
        assert!(tunnel.used_stream_ids.lock().await.is_empty());
    }

    #[test]
    fn stream_id_epoch_limit_has_a_non_configurable_hard_ceiling() {
        let mut security = RtcpSecurityConfig::default();
        security.limits.max_stream_ids_per_tunnel = MAX_STREAM_IDS_PER_TUNNEL_HARD_LIMIT + 1;
        assert!(security.validate().is_err());
    }

    #[tokio::test]
    async fn inbound_tunnel_registration_keeps_first_live_instance() {
        let map = RTcpTunnelMap::new();
        let key = "local_remote";
        let (old_tunnel, _old_peer) = test_tunnel(1);
        let (new_tunnel, _new_peer) = test_tunnel(2);

        let first = map
            .replace_authenticated_inbound(key, old_tunnel.clone(), None)
            .await;
        assert!(first.accepted);
        assert!(first.replaced.is_none());
        assert!(
            map.get_tunnel(key)
                .await
                .unwrap()
                .is_same_instance(&old_tunnel)
        );

        let duplicate = map
            .replace_authenticated_inbound(key, new_tunnel.clone(), None)
            .await;
        assert!(!duplicate.accepted);
        assert!(duplicate.replaced.is_none());
        assert!(duplicate.rejection_reason.is_some());
        assert!(RTcpTunnelMap::finish_authenticated_registration(duplicate).await == false);
        assert!(new_tunnel.is_closed());
        assert!(!old_tunnel.is_closed());
        assert!(
            map.get_tunnel(key)
                .await
                .unwrap()
                .is_same_instance(&old_tunnel)
        );

        assert!(!map.remove_if_current(key, &new_tunnel).await);
        assert!(map.remove_if_current(key, &old_tunnel).await);
        assert!(map.get_tunnel(key).await.is_none());
    }

    #[tokio::test]
    async fn concurrent_authenticated_inbound_registrations_keep_first_instance() {
        const TUNNEL_COUNT: usize = 8;

        let map = RTcpTunnelMap::new();
        let key = "local_concurrent-remote";
        let barrier = Arc::new(tokio::sync::Barrier::new(TUNNEL_COUNT));
        let mut tunnels = Vec::new();
        let mut peers = Vec::new();
        let mut tasks = Vec::new();

        for index in 0..TUNNEL_COUNT {
            let (tunnel, peer) = test_tunnel(index as u8 + 10);
            tunnels.push(tunnel.clone());
            peers.push(peer);
            let map = map.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                tokio::time::sleep(Duration::from_millis(index as u64 * 5)).await;
                let registration = map.replace_authenticated_inbound(key, tunnel, None).await;
                RTcpTunnelMap::finish_authenticated_registration(registration).await
            }));
        }

        let mut accepted = 0;
        for task in tasks {
            accepted += usize::from(task.await.unwrap());
        }

        let current = map.get_tunnel(key).await.unwrap();
        assert_eq!(accepted, 1);
        assert!(current.is_same_instance(tunnels.first().unwrap()));
        assert_eq!(map.primary_len().await, 1);
        assert!(!tunnels.first().unwrap().is_closed());
        for tunnel in &tunnels[1..] {
            assert!(tunnel.is_closed());
        }
    }

    #[tokio::test]
    async fn newer_verified_revision_closes_old_key_and_old_cleanup_is_safe() {
        let map = RTcpTunnelMap::new();
        let logical_did = "did:web:rotation.example";
        let old_key = "local_did:dev:old-key";
        let new_key = "local_did:dev:new-key";
        let (old_tunnel, _old_peer) = test_tunnel(40);
        let (new_tunnel, _new_peer) = test_tunnel(41);

        assert!(
            map.complete_authenticated_inbound_with_outcome(
                old_key,
                old_tunnel.clone(),
                Some((
                    verified_test_identity(logical_did, 1, "rev-1"),
                    CacheWriteOutcome::Inserted,
                )),
            )
            .await
        );
        assert!(
            map.complete_authenticated_inbound_with_outcome(
                new_key,
                new_tunnel.clone(),
                Some((
                    verified_test_identity(logical_did, 2, "rev-2"),
                    CacheWriteOutcome::ReplacedOlder,
                )),
            )
            .await
        );

        assert!(old_tunnel.is_closed());
        assert!(!new_tunnel.is_closed());
        assert!(map.get_tunnel(old_key).await.is_none());
        assert!(
            map.get_tunnel(new_key)
                .await
                .unwrap()
                .is_same_instance(&new_tunnel)
        );
        assert!(!map.is_verified_instance_indexed(&old_tunnel).await);
        assert!(map.is_verified_instance_indexed(&new_tunnel).await);
        assert_eq!(map.verified_identity_len(logical_did).await, 1);
        // The higher revision moved the name's binding to the new canonical
        // dev in the same commit sequence; the old canonical key is released.
        assert_eq!(map.bound_logical_for_dev("did:dev:rev-1").await, None);
        assert_eq!(
            map.bound_logical_for_dev("did:dev:rev-2").await,
            Some(logical_did.to_string())
        );

        assert!(
            !map.remove_if_current(old_key, &old_tunnel).await,
            "the old revision's delayed run-loop cleanup must not affect the new key"
        );
        assert!(
            map.get_tunnel(new_key)
                .await
                .unwrap()
                .is_same_instance(&new_tunnel)
        );
    }

    #[tokio::test]
    async fn older_revision_losing_cache_race_closes_itself_without_indexing() {
        let map = RTcpTunnelMap::new();
        let logical_did = "did:web:race.example";
        let new_key = "local_did:dev:race-new";
        let old_key = "local_did:dev:race-old";
        let (new_tunnel, _new_peer) = test_tunnel(42);
        let (late_old_tunnel, _old_peer) = test_tunnel(43);

        // B commits and scans first.  A reaches the cache serialization
        // point later, receives IgnoredOlder, and must self-close instead of
        // entering the index.  This is the opposite ordering from the
        // rotation test above and closes the other half of the race.
        assert!(
            map.complete_authenticated_inbound_with_outcome(
                new_key,
                new_tunnel.clone(),
                Some((
                    verified_test_identity(logical_did, 2, "rev-2"),
                    CacheWriteOutcome::Inserted,
                )),
            )
            .await
        );
        assert!(
            !map.complete_authenticated_inbound_with_outcome(
                old_key,
                late_old_tunnel.clone(),
                Some((
                    verified_test_identity(logical_did, 1, "rev-1"),
                    CacheWriteOutcome::IgnoredOlder,
                )),
            )
            .await
        );

        assert!(late_old_tunnel.is_closed());
        assert!(!new_tunnel.is_closed());
        assert!(map.get_tunnel(old_key).await.is_none());
        assert!(!map.is_verified_instance_indexed(&late_old_tunnel).await);
        assert_eq!(map.verified_identity_len(logical_did).await, 1);
    }

    #[tokio::test]
    async fn key_only_tunnel_is_not_indexed_or_kicked_by_named_revision() {
        let map = RTcpTunnelMap::new();
        let logical_did = "did:web:unverified-claim.example";
        let key_only_key = "local_did:dev:key-only";
        let named_key = "local_did:dev:verified";
        let (key_only_tunnel, _key_only_peer) = test_tunnel(44);
        let (named_tunnel, _named_peer) = test_tunnel(45);
        let (verified_key_did_tunnel, _verified_key_did_peer) = test_tunnel(54);

        assert!(
            map.complete_authenticated_inbound_with_outcome(
                key_only_key,
                key_only_tunnel.clone(),
                None
            )
            .await
        );
        assert!(
            map.complete_authenticated_inbound_with_outcome(
                "local_did:dev:verified-key-did",
                verified_key_did_tunnel.clone(),
                Some((
                    verified_test_identity("did:dev:verified-key-only", 2, "key-revision"),
                    CacheWriteOutcome::AlreadyPresent,
                )),
            )
            .await
        );
        assert!(
            map.complete_authenticated_inbound_with_outcome(
                named_key,
                named_tunnel.clone(),
                Some((
                    verified_test_identity(logical_did, 2, "rev-2"),
                    CacheWriteOutcome::Inserted,
                )),
            )
            .await
        );

        assert!(!key_only_tunnel.is_closed());
        assert!(!map.is_verified_instance_indexed(&key_only_tunnel).await);
        assert!(
            !map.is_verified_instance_indexed(&verified_key_did_tunnel)
                .await
        );
        assert!(map.is_verified_instance_indexed(&named_tunnel).await);
        assert_eq!(map.primary_len().await, 3);
    }

    #[tokio::test]
    async fn same_revision_keeps_live_slot_without_cross_key_kick() {
        let map = RTcpTunnelMap::new();
        let logical_did = "did:web:same-revision.example";
        let same_key = "local_did:dev:same-key";
        let other_key = "local_did:dev:unexpected-other-key";
        let identity = verified_test_identity(logical_did, 7, "same-document");
        let (first, _first_peer) = test_tunnel(46);
        let (same_slot_new, _same_slot_peer) = test_tunnel(47);
        let (other_slot, _other_slot_peer) = test_tunnel(48);

        assert!(
            map.complete_authenticated_inbound_with_outcome(
                same_key,
                first.clone(),
                Some((identity.clone(), CacheWriteOutcome::Inserted)),
            )
            .await
        );
        assert!(
            !map.complete_authenticated_inbound_with_outcome(
                same_key,
                same_slot_new.clone(),
                Some((identity.clone(), CacheWriteOutcome::AlreadyPresent)),
            )
            .await
        );
        assert!(!first.is_closed());
        assert!(same_slot_new.is_closed());
        assert_eq!(map.verified_identity_len(logical_did).await, 1);

        // A single document normally implies one canonical device key. If the
        // impossible-looking cross-key state is observed, log it but do not
        // invent an ordering or close either same-revision tunnel.
        assert!(
            map.complete_authenticated_inbound_with_outcome(
                other_key,
                other_slot.clone(),
                Some((identity, CacheWriteOutcome::AlreadyPresent)),
            )
            .await
        );
        assert!(!first.is_closed());
        assert!(!other_slot.is_closed());
        assert_eq!(map.verified_identity_len(logical_did).await, 2);
    }

    #[tokio::test]
    async fn verified_index_cleanup_tracks_normal_and_abnormal_exit() {
        let map = RTcpTunnelMap::new();
        let logical_did = "did:web:cleanup.example";
        let first_key = "local_did:dev:cleanup-1";
        let second_key = "local_did:dev:cleanup-2";
        let identity = verified_test_identity(logical_did, 9, "same-document");
        let (normal, _normal_peer) = test_tunnel(49);
        let (abnormal, _abnormal_peer) = test_tunnel(50);

        assert!(
            map.complete_authenticated_inbound_with_outcome(
                first_key,
                normal.clone(),
                Some((identity.clone(), CacheWriteOutcome::Inserted)),
            )
            .await
        );
        assert!(
            map.complete_authenticated_inbound_with_outcome(
                second_key,
                abnormal.clone(),
                Some((identity, CacheWriteOutcome::AlreadyPresent)),
            )
            .await
        );
        assert_eq!(map.verified_identity_len(logical_did).await, 2);

        assert!(map.remove_if_current(first_key, &normal).await);
        assert_eq!(map.verified_identity_len(logical_did).await, 1);
        abnormal.mark_closed();
        assert!(map.remove_if_current(second_key, &abnormal).await);
        assert_eq!(map.verified_identity_len(logical_did).await, 0);
        assert_eq!(map.primary_len().await, 0);
    }

    #[tokio::test]
    async fn authority_negative_closes_all_verified_instances_only() {
        let map = RTcpTunnelMap::new();
        let logical_did = "did:web:authority-negative.example";
        let identity = verified_test_identity(logical_did, 11, "same-document");
        let (first, _first_peer) = test_tunnel(51);
        let (second, _second_peer) = test_tunnel(52);
        let (key_only, _key_only_peer) = test_tunnel(53);

        assert!(
            map.complete_authenticated_inbound_with_outcome(
                "local_did:dev:authority-1",
                first.clone(),
                Some((identity.clone(), CacheWriteOutcome::Inserted)),
            )
            .await
        );
        assert!(
            map.complete_authenticated_inbound_with_outcome(
                "local_did:dev:authority-2",
                second.clone(),
                Some((identity, CacheWriteOutcome::AlreadyPresent)),
            )
            .await
        );
        assert!(
            map.complete_authenticated_inbound_with_outcome(
                "local_did:dev:authority-key-only",
                key_only.clone(),
                None,
            )
            .await
        );

        assert_eq!(
            map.close_verified_identity(logical_did, "AuthorityNotCurrent")
                .await,
            2
        );
        assert!(first.is_closed());
        assert!(second.is_closed());
        assert!(!key_only.is_closed());
        assert_eq!(map.verified_identity_len(logical_did).await, 0);
        assert_eq!(map.binding_len().await, 0);
        assert_eq!(map.primary_len().await, 1);
    }

    #[tokio::test]
    async fn authority_negative_rejects_reconnect_without_publication() {
        let map = RTcpTunnelMap::new();
        let logical_did = "did:web:authority-reconnect.example";
        let revision = DocumentRevision {
            iat: 12,
            content_hash: "rejected-document".to_string(),
        };
        let identity = verified_test_identity_bound(
            logical_did,
            revision.iat,
            &revision.content_hash,
            "did:dev:authority-reconnect",
        );
        let (initial, _initial_peer) = test_tunnel(54);
        assert!(
            map.complete_authenticated_inbound_with_outcome(
                "local_did:dev:authority-reconnect",
                initial.clone(),
                Some((identity.clone(), CacheWriteOutcome::Inserted)),
            )
            .await
        );
        assert_eq!(map.verified_identity_len(logical_did).await, 1);
        assert_eq!(
            map.force_authority_negative(
                logical_did,
                Some(revision.clone()),
                "AuthorityNotCurrent(Superseded)",
            )
            .await,
            1
        );
        assert!(initial.is_closed());

        let (candidate, _peer) = test_tunnel(56);
        assert!(
            !map.complete_authenticated_inbound_with_outcome(
                "local_did:dev:authority-reconnect",
                candidate.clone(),
                Some((identity, CacheWriteOutcome::AlreadyPresent)),
            )
            .await
        );
        assert!(candidate.is_closed());
        assert_eq!(map.primary_len().await, 0);
        assert_eq!(map.verified_identity_len(logical_did).await, 0);
        assert_eq!(map.binding_len().await, 0);
        let negative = map
            .authority_negative_snapshot(logical_did)
            .await
            .expect("Negative must remain active after rejected reconnect");
        assert_eq!(negative.rejected_revision, Some(revision));
    }

    #[tokio::test]
    async fn authority_negative_wins_race_with_inbound_commit() {
        for round in 0..32u8 {
            let map = RTcpTunnelMap::new();
            let logical_did = format!("did:web:authority-race-{}.example", round);
            let canonical_dev_did = format!("did:dev:authority-race-{}", round);
            let tunnel_key = format!("local_{}", canonical_dev_did);
            let revision = DocumentRevision {
                iat: u64::from(round) + 20,
                content_hash: format!("race-document-{}", round),
            };
            let identity = verified_test_identity_bound(
                &logical_did,
                revision.iat,
                &revision.content_hash,
                &canonical_dev_did,
            );
            let (candidate, peer) = test_tunnel(100u8.wrapping_add(round));
            let barrier = Arc::new(tokio::sync::Barrier::new(3));

            let commit_map = map.clone();
            let commit_barrier = barrier.clone();
            let commit_tunnel = candidate.clone();
            let commit_key = tunnel_key.clone();
            let commit = tokio::spawn(async move {
                commit_barrier.wait().await;
                commit_map
                    .complete_authenticated_inbound_with_outcome(
                        &commit_key,
                        commit_tunnel,
                        Some((identity, CacheWriteOutcome::Inserted)),
                    )
                    .await
            });

            let negative_map = map.clone();
            let negative_barrier = barrier.clone();
            let negative_did = logical_did.clone();
            let negative_revision = revision.clone();
            let negative = tokio::spawn(async move {
                negative_barrier.wait().await;
                negative_map
                    .force_authority_negative(
                        &negative_did,
                        Some(negative_revision),
                        "concurrent authority rejection",
                    )
                    .await
            });

            barrier.wait().await;
            let _accepted_before_negative = commit.await.unwrap();
            let _closed_by_negative = negative.await.unwrap();
            assert!(candidate.is_closed(), "round {} left candidate open", round);
            assert_eq!(map.primary_len().await, 0, "round {}", round);
            assert_eq!(
                map.verified_identity_len(&logical_did).await,
                0,
                "round {}",
                round
            );
            assert_eq!(map.binding_len().await, 0, "round {}", round);
            drop(peer);
        }
    }

    #[tokio::test]
    async fn authority_negative_clears_only_for_matching_current_generation() {
        let map = RTcpTunnelMap::new();
        let logical_did = "did:web:authority-recovery.example";
        let rejected = DocumentRevision {
            iat: 30,
            content_hash: "rejected".to_string(),
        };
        let current = DocumentRevision {
            iat: 31,
            content_hash: "current".to_string(),
        };
        map.force_authority_negative(
            logical_did,
            Some(rejected),
            "AuthorityNotCurrent(DifferentDocument)",
        )
        .await;
        let negative = map.authority_negative_snapshot(logical_did).await.unwrap();

        assert!(
            !map.clear_authority_negative_if_current(
                logical_did,
                negative.generation.wrapping_add(1),
                &current,
                40,
            )
            .await
        );
        assert!(map.authority_negative_snapshot(logical_did).await.is_some());
        assert!(
            map.clear_authority_negative_if_current(
                logical_did,
                negative.generation,
                &current,
                41,
            )
            .await
        );
        assert!(map.authority_negative_snapshot(logical_did).await.is_none());
        assert!(
            map.authority_confirmed_revision(logical_did, &current)
                .await
        );
    }

    #[tokio::test]
    async fn authority_unavailable_does_not_block_snapshot_admission() {
        let map = RTcpTunnelMap::new();
        let logical_did = "did:web:authority-unavailable.example";
        let identity = verified_test_identity(logical_did, 44, "unavailable-document");
        let ticket = map
            .begin_authority_confirmation(logical_did, &identity.document_revision, 50, Some(0))
            .await
            .unwrap();
        map.complete_authority_unavailable_if_current(logical_did, &ticket, 51)
            .await;

        let (candidate, _peer) = test_tunnel(55);
        assert!(
            map.complete_authenticated_inbound_with_outcome(
                "local_did:dev:authority-unavailable",
                candidate.clone(),
                Some((identity, CacheWriteOutcome::Inserted)),
            )
            .await
        );
        assert!(!candidate.is_closed());
        assert_eq!(map.verified_identity_len(logical_did).await, 1);
    }

    #[tokio::test]
    async fn inbound_second_logical_name_for_same_canonical_dev_is_rejected() {
        let map = RTcpTunnelMap::new();
        let shared_dev = "did:dev:shared-binding-key";
        let tunnel_key = "local_did:dev:shared-binding-key";
        let (first, _first_peer) = test_tunnel(60);
        let (second, _second_peer) = test_tunnel(61);

        assert!(
            map.complete_authenticated_inbound_with_outcome(
                tunnel_key,
                first.clone(),
                Some((
                    verified_test_identity_bound("did:web:name-a.example", 5, "doc-a", shared_dev),
                    CacheWriteOutcome::Inserted,
                )),
            )
            .await
        );
        assert_eq!(
            map.bound_logical_for_dev(shared_dev).await,
            Some("did:web:name-a.example".to_string())
        );

        // The conflicting name arrives under the SAME canonical tunnel key
        // (it proves possession of the same device key). It must be rejected
        // and must not replace the legitimate binding's tunnel.
        assert!(
            !map.complete_authenticated_inbound_with_outcome(
                tunnel_key,
                second.clone(),
                Some((
                    verified_test_identity_bound("did:web:name-b.example", 6, "doc-b", shared_dev),
                    CacheWriteOutcome::Inserted,
                )),
            )
            .await
        );

        assert!(second.is_closed());
        assert!(!first.is_closed());
        assert!(
            map.get_tunnel(tunnel_key)
                .await
                .unwrap()
                .is_same_instance(&first)
        );
        assert_eq!(
            map.bound_logical_for_dev(shared_dev).await,
            Some("did:web:name-a.example".to_string())
        );
        assert!(!map.is_verified_instance_indexed(&second).await);
        assert_eq!(map.verified_identity_len("did:web:name-b.example").await, 0);
    }

    #[tokio::test]
    async fn concurrent_conflicting_names_admit_exactly_one_binding() {
        const RACERS: usize = 8;
        let map = RTcpTunnelMap::new();
        let shared_dev = "did:dev:race-binding-key";
        let tunnel_key = "local_did:dev:race-binding-key";
        let barrier = Arc::new(tokio::sync::Barrier::new(RACERS));
        let mut tunnels = Vec::new();
        let mut peers = Vec::new();
        for i in 0..RACERS {
            let (tunnel, peer) = test_tunnel(70 + i as u8);
            tunnels.push(tunnel);
            peers.push(peer);
        }

        let mut handles = Vec::new();
        for (i, tunnel) in tunnels.iter().cloned().enumerate() {
            let map = map.clone();
            let barrier = barrier.clone();
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                map.complete_authenticated_inbound_with_outcome(
                    tunnel_key,
                    tunnel,
                    Some((
                        verified_test_identity_bound(
                            &format!("did:web:racer-{}.example", i),
                            5,
                            &format!("doc-{}", i),
                            shared_dev,
                        ),
                        CacheWriteOutcome::Inserted,
                    )),
                )
                .await
            }));
        }
        let mut accepted = 0;
        for handle in handles {
            if handle.await.unwrap() {
                accepted += 1;
            }
        }

        assert_eq!(
            accepted, 1,
            "exactly one logical name may win the canonical dev binding"
        );
        let current = map
            .get_tunnel(tunnel_key)
            .await
            .expect("winner tunnel must stay current");
        assert!(!current.is_closed());
        let mut open = 0;
        for tunnel in &tunnels {
            if !tunnel.is_closed() {
                open += 1;
                assert!(current.is_same_instance(tunnel));
            }
        }
        assert_eq!(open, 1);
        assert_eq!(map.binding_len().await, 1);
        assert!(map.bound_logical_for_dev(shared_dev).await.is_some());
    }

    #[tokio::test]
    async fn same_revision_conflicting_content_is_rejected_fail_closed() {
        let map = RTcpTunnelMap::new();
        let logical_did = "did:web:same-iat-conflict.example";
        let key_a = "local_did:dev:same-iat-a";
        let key_b = "local_did:dev:same-iat-b";
        let (first, _first_peer) = test_tunnel(80);
        let (second, _second_peer) = test_tunnel(81);

        assert!(
            map.complete_authenticated_inbound_with_outcome(
                key_a,
                first.clone(),
                Some((
                    verified_test_identity(logical_did, 7, "content-a"),
                    CacheWriteOutcome::Inserted,
                )),
            )
            .await
        );

        // name-client's CAS reports a same-iat different-content write as
        // RejectedConflict: definite rejection, current binding untouched.
        assert!(
            !map.complete_authenticated_inbound_with_outcome(
                key_b,
                second.clone(),
                Some((
                    verified_test_identity(logical_did, 7, "content-b"),
                    CacheWriteOutcome::RejectedConflict,
                )),
            )
            .await
        );
        assert!(second.is_closed());
        assert!(!first.is_closed());

        // Defense in depth: even a stored outcome cannot publish a same-iat
        // different-content revision while the current one is live -- the
        // in-map same-version gate keeps the race window fail-closed.
        let (third, _third_peer) = test_tunnel(82);
        assert!(
            !map.complete_authenticated_inbound_with_outcome(
                key_b,
                third.clone(),
                Some((
                    verified_test_identity(logical_did, 7, "content-c"),
                    CacheWriteOutcome::ReplacedOlder,
                )),
            )
            .await
        );
        assert!(third.is_closed());
        assert!(!first.is_closed());
        assert_eq!(map.verified_identity_len(logical_did).await, 1);
        assert!(
            map.get_tunnel(key_a)
                .await
                .unwrap()
                .is_same_instance(&first)
        );
    }

    #[tokio::test]
    async fn outbound_binding_arbitrates_reuse_and_cleanup() {
        let map = RTcpTunnelMap::new();
        let dev = "did:dev:outbound-bound-key";
        let key = "local_did:dev:outbound-bound-key";
        let binding_a = OutboundNameBinding {
            logical_did: "did:web:out-a.example".to_string(),
            canonical_dev_did: dev.to_string(),
        };
        let binding_b = OutboundNameBinding {
            logical_did: "did:web:out-b.example".to_string(),
            canonical_dev_did: dev.to_string(),
        };
        let (tunnel, _peer) = test_tunnel(84);

        assert!(
            map.acquire_outbound(key, Some(&binding_a))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            map.register_outbound_if_absent(key, tunnel.clone(), Some(&binding_a))
                .await
                .is_ok()
        );
        assert_eq!(
            map.bound_logical_for_dev(dev).await,
            Some(binding_a.logical_did.clone())
        );

        // Direct did:dev reuse carries no binding and shares the tunnel.
        let reused = map
            .acquire_outbound(key, None)
            .await
            .unwrap()
            .expect("direct dev addressing must reuse the bound tunnel");
        assert!(reused.is_same_instance(&tunnel));

        // The same name reuses; a second name is rejected explicitly.
        assert!(
            map.acquire_outbound(key, Some(&binding_a))
                .await
                .unwrap()
                .unwrap()
                .is_same_instance(&tunnel)
        );
        let err = match map.acquire_outbound(key, Some(&binding_b)).await {
            Err(err) => err,
            Ok(_) => panic!("second logical name must not silently reuse the bound tunnel"),
        };
        assert!(
            err.contains("out-a.example"),
            "conflict must name the bound logical: {err}"
        );
        match map
            .register_outbound_if_absent(key, tunnel.clone(), Some(&binding_b))
            .await
        {
            Err(OutboundRegisterError::BindingConflict(err)) => {
                assert!(err.contains("out-a.example"))
            }
            _ => panic!("second logical name registration must report a binding conflict"),
        }

        // run-loop exit cleanup releases both index directions.
        assert!(map.remove_if_current(key, &tunnel).await);
        assert_eq!(map.binding_len().await, 0);
        assert_eq!(map.bound_logical_for_dev(dev).await, None);
    }

    #[tokio::test]
    async fn named_reuse_of_unbound_tunnel_records_binding() {
        let map = RTcpTunnelMap::new();
        let dev = "did:dev:late-bound-key";
        let key = "local_did:dev:late-bound-key";
        let (tunnel, _peer) = test_tunnel(85);
        assert!(
            map.register_outbound_if_absent(key, tunnel.clone(), None)
                .await
                .is_ok()
        );
        assert_eq!(map.binding_len().await, 0);

        // The first named reuse claims the binding...
        let binding_a = OutboundNameBinding {
            logical_did: "did:web:late-a.example".to_string(),
            canonical_dev_did: dev.to_string(),
        };
        assert!(
            map.acquire_outbound(key, Some(&binding_a))
                .await
                .unwrap()
                .unwrap()
                .is_same_instance(&tunnel)
        );
        assert_eq!(
            map.bound_logical_for_dev(dev).await,
            Some(binding_a.logical_did.clone())
        );
        // ...so a second name can no longer share the same device silently.
        let binding_b = OutboundNameBinding {
            logical_did: "did:web:late-b.example".to_string(),
            canonical_dev_did: dev.to_string(),
        };
        assert!(map.acquire_outbound(key, Some(&binding_b)).await.is_err());
    }

    #[tokio::test]
    async fn closed_instances_do_not_defend_a_binding() {
        let map = RTcpTunnelMap::new();
        let shared_dev = "did:dev:stale-binding-key";
        let tunnel_key = "local_did:dev:stale-binding-key";
        let (first, _first_peer) = test_tunnel(86);
        let (second, _second_peer) = test_tunnel(87);

        assert!(
            map.complete_authenticated_inbound_with_outcome(
                tunnel_key,
                first.clone(),
                Some((
                    verified_test_identity_bound("did:web:stale-a.example", 3, "doc-a", shared_dev),
                    CacheWriteOutcome::Inserted,
                )),
            )
            .await
        );
        // The bound instance died (marked closed) but its run-loop cleanup
        // has not run yet. A different name may then claim the canonical
        // dev: the stale binding is pruned instead of blocking it.
        first.mark_closed();
        assert!(
            map.complete_authenticated_inbound_with_outcome(
                tunnel_key,
                second.clone(),
                Some((
                    verified_test_identity_bound("did:web:stale-b.example", 4, "doc-b", shared_dev),
                    CacheWriteOutcome::Inserted,
                )),
            )
            .await
        );
        assert_eq!(
            map.bound_logical_for_dev(shared_dev).await,
            Some("did:web:stale-b.example".to_string())
        );
        assert!(
            map.get_tunnel(tunnel_key)
                .await
                .unwrap()
                .is_same_instance(&second)
        );
        assert_eq!(map.binding_len().await, 1);
    }

    #[tokio::test]
    async fn outbound_binding_blocks_conflicting_inbound_name() {
        let map = RTcpTunnelMap::new();
        let dev = "did:dev:cross-bound-key";
        let key = "local_did:dev:cross-bound-key";
        let (outbound, _outbound_peer) = test_tunnel(88);
        let binding = OutboundNameBinding {
            logical_did: "did:web:cross-out.example".to_string(),
            canonical_dev_did: dev.to_string(),
        };
        assert!(
            map.register_outbound_if_absent(key, outbound.clone(), Some(&binding))
                .await
                .is_ok()
        );

        let (inbound, _inbound_peer) = test_tunnel(89);
        assert!(
            !map.complete_authenticated_inbound_with_outcome(
                key,
                inbound.clone(),
                Some((
                    verified_test_identity_bound("did:web:cross-in.example", 9, "doc-in", dev),
                    CacheWriteOutcome::Inserted,
                )),
            )
            .await
        );
        assert!(inbound.is_closed());
        assert!(!outbound.is_closed());
        assert!(map
            .get_tunnel(key)
            .await
            .unwrap()
            .is_same_instance(&outbound));

        // A duplicate inbound connection for the same name is also rejected;
        // the already-published outbound instance remains the shared winner.
        let (inbound_same, _inbound_same_peer) = test_tunnel(90);
        assert!(
            !map.complete_authenticated_inbound_with_outcome(
                key,
                inbound_same.clone(),
                Some((
                    verified_test_identity_bound("did:web:cross-out.example", 9, "doc-out", dev),
                    CacheWriteOutcome::Inserted,
                )),
            )
            .await
        );
        assert!(inbound_same.is_closed());
        assert!(!outbound.is_closed());
        assert!(
            map.get_tunnel(key)
                .await
                .unwrap()
                .is_same_instance(&outbound)
        );
        assert_eq!(
            map.bound_logical_for_dev(dev).await,
            Some("did:web:cross-out.example".to_string())
        );
        assert_eq!(map.binding_len().await, 1);
    }

    #[tokio::test]
    async fn authority_negative_also_closes_outbound_bound_tunnels() {
        let map = RTcpTunnelMap::new();
        let logical = "did:web:authority-outbound.example";
        let dev = "did:dev:authority-outbound-key";
        let key = "local_did:dev:authority-outbound-key";
        let (outbound, _peer) = test_tunnel(93);
        let binding = OutboundNameBinding {
            logical_did: logical.to_string(),
            canonical_dev_did: dev.to_string(),
        };
        assert!(
            map.register_outbound_if_absent(key, outbound.clone(), Some(&binding))
                .await
                .is_ok()
        );

        assert_eq!(
            map.force_authority_negative(
                logical,
                Some(DocumentRevision {
                    iat: 93,
                    content_hash: "outbound-rejected".to_string(),
                }),
                "AuthorityNotCurrent",
            )
            .await,
            1
        );
        assert!(outbound.is_closed());
        assert!(map.get_tunnel(key).await.is_none());
        assert_eq!(map.binding_len().await, 0);

        let (reconnect, _reconnect_peer) = test_tunnel(94);
        assert!(matches!(
            map.register_outbound_if_absent(key, reconnect.clone(), Some(&binding))
                .await,
            Err(OutboundRegisterError::AuthorityNegative(_))
        ));
        assert!(map.acquire_outbound(key, Some(&binding)).await.is_err());
        assert!(map.get_tunnel(key).await.is_none());
    }

    #[tokio::test]
    async fn outbound_registration_keeps_first_tunnel_and_closed_tunnel_fails_fast() {
        let map = RTcpTunnelMap::new();
        let key = "local_outbound-remote";
        let (first, _first_peer) = test_tunnel(30);
        let (extra, _extra_peer) = test_tunnel(31);

        assert!(
            map.register_outbound_if_absent(key, first.clone(), None)
                .await
                .is_ok()
        );
        let existing = match map
            .register_outbound_if_absent(key, extra, None)
            .await
            .expect_err("outbound race must preserve the first registered tunnel")
        {
            OutboundRegisterError::Existing(existing) => existing,
            OutboundRegisterError::BindingConflict(conflict) => {
                panic!("unbound outbound race must not report a binding conflict: {conflict}")
            }
            OutboundRegisterError::AuthorityNegative(reason) => {
                panic!("unbound outbound race must not report authority Negative: {reason}")
            }
        };
        assert!(existing.is_same_instance(&first));

        first.close().await;
        let ping_err = first.ping().await.unwrap_err();
        assert_eq!(ping_err.kind(), std::io::ErrorKind::BrokenPipe);
        let open_err = first
            .open_stream("closed-tunnel.test:80")
            .await
            .err()
            .expect("open on a closed tunnel must fail");
        assert_eq!(open_err.kind(), std::io::ErrorKind::BrokenPipe);
        let datagram_err = first
            .create_datagram_client("closed-tunnel.test:80")
            .await
            .err()
            .expect("datagram creation on a closed tunnel must fail");
        assert_eq!(datagram_err.kind(), std::io::ErrorKind::BrokenPipe);
    }

    // v4 regression: the nonce cache retention window must cover the
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
            DeviceDocument::new_by_jwk("client", serde_json::from_value(client_jwk).unwrap());

        let (server_signing_key, _server_pkcs8_bytes) = generate_ed25519_key();
        let server_jwk = encode_ed25519_sk_to_pk_jwk(&server_signing_key);
        let server_device_config =
            DeviceDocument::new_by_jwk("server", serde_json::from_value(server_jwk).unwrap());
        let server_id = server_device_config.id.clone();

        let mut name_info = NameInfo::new("sn.devtests.org");
        name_info.txt.push(format!("PKX={};", server_id.id));
        add_nameinfo_cache("sn.devtests.org", name_info)
            .await
            .unwrap();

        let mut client_inner = RTcpInner::new(
            client_device_config.id,
            "127.0.0.1:19083".to_string(),
            Some(client_pkcs8_bytes),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        client_inner.security.peer_identity.dns_txt_bootstrap = true;

        let state = client_inner
            .generate_tunnel_token("did:web:sn.devtests.org".to_string())
            .await
            .unwrap();
        let claims = decode_jwt_claim_without_verify(&state.token).unwrap();

        assert_eq!(
            claims.get("to").and_then(|v| v.as_str()),
            Some("did:web:sn.devtests.org")
        );
        assert_eq!(state.responder_did, "did:web:sn.devtests.org");
        assert_eq!(state.responder_canonical_did, server_id.to_string());
        assert_eq!(state.responder_trust, RtcpIdentityTrust::DnsTxtBootstrap);
        RTcpInner::validate_hello_target(
            "sn.devtests.org",
            server_id.to_string().as_str(),
            "sn.devtests.org",
            "sn.devtests.org",
            &server_id,
        )
        .unwrap();
    }

    fn ed25519_test_keys() -> (EncodingKey, DecodingKey) {
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceDocument::new_by_jwk("key-test", serde_json::from_value(jwk).unwrap());
        let default_key = device_config.get_default_key().unwrap();
        let public_key = jwk_to_ed25519_pk(&default_key).unwrap();
        (
            EncodingKey::from_ed_der(&pkcs8_bytes),
            DecodingKey::from_ed_der(&public_key),
        )
    }

    #[test]
    fn test_rtcp_verify_hello_token_rejects_from_binding_and_bad_xpub() {
        let (encoding_key, decoding_key) = ed25519_test_keys();
        let now = buckyos_get_unix_timestamp();
        let payload = TunnelTokenPayload {
            aud: RTCP_HELLO_AUD.to_string(),
            to: "did:web:responder.example.com".to_string(),
            canonical_to: DID::new("dev", "responder-key").to_string(),
            from: "did:web:initiator.example.com".to_string(),
            listen_port: 2981,
            xpub: hex::encode([1u8; 32]),
            iat: now,
            exp: now + TUNNEL_TOKEN_EXP_SECS,
            nonce: hex::encode([2u8; 16]),
        };
        let token = RTcpInner::sign_jwt(&encoding_key, &payload).unwrap();

        RTcpInner::verify_hello_token(&token, &decoding_key, Some("did:web:initiator.example.com"))
            .unwrap();

        let err = RTcpInner::verify_hello_token(
            &token,
            &decoding_key,
            Some("did:web:attacker.example.com"),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("not match expected"),
            "unexpected error: {}",
            err
        );

        let mut bad_xpub = payload.clone();
        bad_xpub.xpub = "abcd".to_string();
        let bad_xpub_token = RTcpInner::sign_jwt(&encoding_key, &bad_xpub).unwrap();
        let err = RTcpInner::verify_hello_token(
            &bad_xpub_token,
            &decoding_key,
            Some("did:web:initiator.example.com"),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("x25519 pub key"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_rtcp_v4_token_time_audience_and_listen_port_contract() {
        let (encoding_key, decoding_key) = ed25519_test_keys();
        let now = buckyos_get_unix_timestamp();
        let base = TunnelTokenPayload {
            aud: RTCP_HELLO_AUD.to_string(),
            to: "did:web:responder.example".to_string(),
            canonical_to: DID::new("dev", "responder-key").to_string(),
            from: "did:web:initiator.example".to_string(),
            listen_port: 2980,
            xpub: hex::encode([11u8; 32]),
            iat: now,
            exp: now + TUNNEL_TOKEN_EXP_SECS,
            nonce: hex::encode([12u8; 16]),
        };

        let mut old_audience = base.clone();
        old_audience.aud = "buckyos-rtcp-v2-hello".to_string();
        let token = RTcpInner::sign_jwt(&encoding_key, &old_audience).unwrap();
        assert!(
            RTcpInner::verify_hello_token(
                &token,
                &decoding_key,
                Some("did:web:initiator.example"),
            )
                .is_err()
        );

        let mut future = base.clone();
        future.iat = now + JWT_LEEWAY_SECS + 1;
        future.exp = future.iat + TUNNEL_TOKEN_EXP_SECS;
        let token = RTcpInner::sign_jwt(&encoding_key, &future).unwrap();
        assert!(
            RTcpInner::verify_hello_token(
                &token,
                &decoding_key,
                Some("did:web:initiator.example"),
            )
                .unwrap_err()
                .to_string()
                .contains("future")
        );

        let mut reversed = base.clone();
        reversed.exp = reversed.iat - 1;
        let token = RTcpInner::sign_jwt(&encoding_key, &reversed).unwrap();
        assert!(
            RTcpInner::verify_hello_token(
                &token,
                &decoding_key,
                Some("did:web:initiator.example"),
            )
                .is_err()
        );

        let mut overlong = base.clone();
        overlong.exp = overlong.iat + TUNNEL_TOKEN_EXP_SECS + 1;
        let token = RTcpInner::sign_jwt(&encoding_key, &overlong).unwrap();
        assert!(
            RTcpInner::verify_hello_token(
                &token,
                &decoding_key,
                Some("did:web:initiator.example"),
            )
                .unwrap_err()
                .to_string()
                .contains("lifetime")
        );

        let mut missing_iat = serde_json::to_value(&base).unwrap();
        missing_iat.as_object_mut().unwrap().remove("iat");
        let token = RTcpInner::sign_jwt(&encoding_key, &missing_iat).unwrap();
        assert!(
            RTcpInner::verify_hello_token(
                &token,
                &decoding_key,
                Some("did:web:initiator.example"),
            )
                .is_err()
        );

        let mut hello = RTcpHelloBody {
            from_id: "did:web:initiator.example".to_string(),
            to_id: "did:web:responder.example".to_string(),
            my_port: base.listen_port,
            tunnel_token: None,
            device_doc_jwt: None,
        };
        RTcpInner::validate_hello_signed_bindings(&base, &hello).unwrap();
        hello.my_port += 1;
        assert!(
            RTcpInner::validate_hello_signed_bindings(&base, &hello)
                .unwrap_err()
                .contains("listen_port")
        );

        let mut bns_claims = base.clone();
        bns_claims.from = "did:bns:ood1.issue39".to_string();
        let bns_hello = RTcpHelloBody {
            from_id: "did:bns:ood1.issue39".to_string(),
            to_id: "did:web:sn.devtests.org".to_string(),
            my_port: bns_claims.listen_port,
            tunnel_token: None,
            device_doc_jwt: None,
        };
        RTcpInner::validate_hello_signed_bindings(&bns_claims, &bns_hello).unwrap();

        bns_claims.from = "did:bns:ood1.other-zone".to_string();
        assert!(
            RTcpInner::validate_hello_signed_bindings(&bns_claims, &bns_hello)
                .unwrap_err()
                .contains("does not match")
        );
    }

    #[test]
    fn test_rtcp_verify_ack_token_rejects_identity_and_peer_xpub_mismatch() {
        let (encoding_key, decoding_key) = ed25519_test_keys();
        let expected_from = "did:web:responder.example.com";
        let expected_to = "did:web:initiator.example.com";
        let expected_peer_xpub = hex::encode([7u8; 32]);
        let now = buckyos_get_unix_timestamp();
        let payload = TunnelAckTokenPayload {
            aud: RTCP_HELLO_ACK_AUD.to_string(),
            to: expected_to.to_string(),
            from: expected_from.to_string(),
            xpub: hex::encode([8u8; 32]),
            peer_xpub: expected_peer_xpub.clone(),
            iat: now,
            exp: now + TUNNEL_TOKEN_EXP_SECS,
            nonce: hex::encode([9u8; 16]),
        };
        let token = RTcpInner::sign_jwt(&encoding_key, &payload).unwrap();

        RTcpInner::verify_ack_token(
            &token,
            &decoding_key,
            expected_from,
            expected_to,
            &expected_peer_xpub,
        )
        .unwrap();

        let mut wrong_from = payload.clone();
        wrong_from.from = "did:web:other-responder.example.com".to_string();
        let token = RTcpInner::sign_jwt(&encoding_key, &wrong_from).unwrap();
        assert!(
            RTcpInner::verify_ack_token(
                &token,
                &decoding_key,
                expected_from,
                expected_to,
                &expected_peer_xpub,
            )
            .unwrap_err()
            .to_string()
            .contains("from")
        );

        let mut wrong_to = payload.clone();
        wrong_to.to = "did:web:other-initiator.example.com".to_string();
        let token = RTcpInner::sign_jwt(&encoding_key, &wrong_to).unwrap();
        assert!(
            RTcpInner::verify_ack_token(
                &token,
                &decoding_key,
                expected_from,
                expected_to,
                &expected_peer_xpub,
            )
            .unwrap_err()
            .to_string()
            .contains("to")
        );

        let mut wrong_peer_xpub = payload.clone();
        wrong_peer_xpub.peer_xpub = hex::encode([10u8; 32]);
        let token = RTcpInner::sign_jwt(&encoding_key, &wrong_peer_xpub).unwrap();
        assert!(
            RTcpInner::verify_ack_token(
                &token,
                &decoding_key,
                expected_from,
                expected_to,
                &expected_peer_xpub,
            )
            .unwrap_err()
            .to_string()
            .contains("peer_xpub")
        );
    }

    #[tokio::test]
    async fn test_rtcp_validate_hello_target_rejects_wrong_canonical_target() {
        let this_host = "this.example.com";
        let this_dev_did = DID::new("dev", "hello-target-reject-dev");
        RTcpInner::validate_hello_target(
            this_host,
            this_dev_did.to_string().as_str(),
            "did:web:this.example.com",
            this_host,
            &this_dev_did,
        )
        .unwrap();

        let err = RTcpInner::validate_hello_target(
            "other.test.did",
            DID::new("dev", "different-key").to_string().as_str(),
            "did:test:other",
            this_host,
            &this_dev_did,
        )
        .unwrap_err();
        assert!(
            err.contains("not this device") || err.contains("not a valid DID"),
            "unexpected error: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_rtcp_validate_hello_target_accepts_this_dev_did_forms() {
        // token.to 固定使用 DID 的 host-name 规范形式；Hello.to_id 可保留
        // did:dev 字符串形式。
        let (device_config, _pkcs8_bytes) = test_device_config("hello-target-dev");
        let this_dev_did = device_config.id.clone();
        let this_host = "sn.devtests.org";

        RTcpInner::validate_hello_target(
            this_dev_did.to_host_name().as_str(),
            this_dev_did.to_string().as_str(),
            this_dev_did.to_string().as_str(),
            this_host,
            &this_dev_did,
        )
        .unwrap();
        // 逻辑 did 的字符串形式(this_host 的 did:web 形式)同样接受。
        RTcpInner::validate_hello_target(
            this_host,
            this_dev_did.to_string().as_str(),
            "did:web:sn.devtests.org",
            this_host,
            &this_dev_did,
        )
        .unwrap();

        // 其它设备的 did:dev 仍然拒绝。
        let (other_config, _other_pkcs8_bytes) = test_device_config("hello-target-other");
        let err = RTcpInner::validate_hello_target(
            other_config.id.to_host_name().as_str(),
            other_config.id.to_string().as_str(),
            other_config.id.to_string().as_str(),
            this_host,
            &this_dev_did,
        )
        .unwrap_err();
        assert!(err.contains("not this device"), "unexpected error: {}", err);
    }

    #[test]
    fn test_rtcp_struct_creation() {
        // 测试RTcp结构体的创建
        let did = DID::new("test", "device1");
        let listener = Arc::new(MockRTcpListener::new());

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

    fn test_device_config(name: &str) -> (DeviceDocument, [u8; 48]) {
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        (
            DeviceDocument::new_by_jwk(name, serde_json::from_value(jwk).unwrap()),
            pkcs8_bytes,
        )
    }

    fn test_named_device_identity(name: &str) -> (DID, DID, [u8; 48], String) {
        let (owner_signing_key, owner_pkcs8_bytes) = generate_ed25519_key();
        let owner_jwk = encode_ed25519_sk_to_pk_jwk(&owner_signing_key);
        let owner_config =
            DeviceDocument::new_by_jwk("owner", serde_json::from_value(owner_jwk).unwrap());
        let owner_private_key = EncodingKey::from_ed_der(&owner_pkcs8_bytes);

        let (device_signing_key, device_pkcs8_bytes) = generate_ed25519_key();
        let device_jwk = encode_ed25519_sk_to_pk_jwk(&device_signing_key);
        let mut device_config =
            DeviceDocument::new_by_jwk(name, serde_json::from_value(device_jwk).unwrap());
        let device_dev_did = device_config.id.clone();
        let logical_did = DID::new("test", name);
        device_config.id = logical_did.clone();
        device_config.owner = owner_config.id;
        let device_doc_jwt = match device_config
            .encode(Some(&owner_private_key))
            .expect("test device document signing failed")
        {
            EncodedDocument::Jwt(jwt) => jwt,
            _ => panic!("signed test device document must be JWT"),
        };

        (
            logical_did,
            device_dev_did,
            device_pkcs8_bytes,
            device_doc_jwt,
        )
    }

    async fn cache_test_device(device_config: &DeviceDocument) {
        let did_doc_value = serde_json::to_value(device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        add_observed_cache(device_config.id.clone(), None, encoded_doc, None).unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();
    }

    fn unused_tcp_port() -> u16 {
        std::net::TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    async fn wait_for_available_handshake_permits(server: &RTcp, expected: usize) {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if server.inner.pending_handshakes.available_permits() == expected {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "timed out waiting for {expected} available handshake permit(s); found {}",
                server.inner.pending_handshakes.available_permits()
            )
        });
    }

    async fn assert_connection_closed_within(stream: &mut TcpStream, duration: Duration) {
        let mut byte = [0u8; 1];
        match tokio::time::timeout(duration, stream.read(&mut byte))
            .await
            .expect("RTCP connection was not closed within the expected deadline")
        {
            Ok(0) | Err(_) => {}
            Ok(n) => panic!("server unexpectedly wrote {n} byte(s) before closing connection"),
        }
    }

    async fn wait_for_current_tunnel(
        tunnel_map: &RTcpTunnelMap,
        tunnel_key: &str,
        different_from: Option<u64>,
    ) -> RTcpTunnel {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(tunnel) = tunnel_map.get_tunnel(tunnel_key).await {
                    if different_from
                        .map(|instance_id| tunnel.instance_id() != instance_id)
                        .unwrap_or(true)
                    {
                        break tunnel;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("timed out waiting for current RTcp tunnel")
    }

    async fn add_rtcp_alias(name: &str, dev_did: &DID) {
        let mut name_info = NameInfo::from_address(name, "127.0.0.1".parse().unwrap());
        name_info.txt.push(format!("PKX={};", dev_did.id));
        add_nameinfo_cache(name, name_info).await.unwrap();
    }

    fn enable_txt_bootstrap(rtcp: &mut RTcp) {
        let mut security = RtcpSecurityConfig::default();
        security.peer_identity.dns_txt_bootstrap = true;
        rtcp.set_security_config(security).unwrap();
    }

    fn allow_named_key_fallback(rtcp: &mut RTcp) {
        let mut security = RtcpSecurityConfig::default();
        security.inbound_admission.anonymous = RtcpAnonymousAdmission::Allow;
        security.inbound_admission.named_min_relation = RtcpNamedMinRelation::Any;
        rtcp.set_security_config(security).unwrap();
    }

    #[tokio::test]
    async fn test_rtcp_bootstrap_url_requires_tunnel_manager() {
        let bootstrap_url = Url::parse("tcp://127.0.0.1:9/bootstrap").unwrap();
        let (remote_config, _) = test_device_config("bootstrap-remote");
        let remote = remote_config.id.to_string();
        let stack_id = build_rtcp_nested_remote_stack_id(&bootstrap_url, &remote, Some(2981));
        let inner = RTcpInner::new(
            DID::new("dev", "local-dev-without-sk-for-bootstrap-test"),
            "127.0.0.1:0".to_string(),
            None,
            None,
            Arc::new(MockRTcpListener::new()),
        );

        let err = match inner.create_tunnel(Some(&stack_id)).await {
            Ok(_) => panic!("bootstrap tunnel creation should fail without tunnel_manager"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("tunnel_manager is not set"),
            "unexpected error: {}",
            err
        );
        assert!(
            inner
                .tunnel_map
                .get_tunnel(
                    &inner
                        .compute_tunnel_key(&parse_rtcp_stack_id(&stack_id).unwrap())
                        .await
                        .unwrap()
                )
                .await
                .is_none(),
            "failed bootstrap setup must not register a tunnel"
        );
    }

    #[tokio::test]
    async fn test_rtcp_bootstrap_stream_open_failure_does_not_register_tunnel() {
        let create_count = Arc::new(AtomicUsize::new(0));
        let open_count = Arc::new(AtomicUsize::new(0));
        let tunnel_manager = TunnelManager::new();
        tunnel_manager.register_tunnel_builder(
            "mockfail",
            Arc::new(FailingBootstrapTunnelBuilder {
                create_count: create_count.clone(),
                open_count: open_count.clone(),
            }),
        );

        let bootstrap_url = Url::parse("mockfail://bootstrap.example/rtcp-bearing").unwrap();
        let (remote_config, _) = test_device_config("bootstrap-fail-remote");
        let remote = remote_config.id.to_string();
        let stack_id = build_rtcp_nested_remote_stack_id(&bootstrap_url, &remote, Some(2981));
        let mut inner = RTcpInner::new(
            DID::new("dev", "local-dev-without-sk-for-bootstrap-fail-test"),
            "127.0.0.1:0".to_string(),
            None,
            None,
            Arc::new(MockRTcpListener::new()),
        );
        inner.tunnel_manager = Some(tunnel_manager);

        let err = match inner.create_tunnel(Some(&stack_id)).await {
            Ok(_) => panic!("bootstrap tunnel creation should fail when bootstrap stream fails"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("open bootstrap stream"),
            "unexpected error: {}",
            err
        );
        assert_eq!(create_count.load(Ordering::SeqCst), 1);
        assert_eq!(open_count.load(Ordering::SeqCst), 1);
        assert!(
            inner
                .tunnel_map
                .get_tunnel(
                    &inner
                        .compute_tunnel_key(&parse_rtcp_stack_id(&stack_id).unwrap())
                        .await
                        .unwrap()
                )
                .await
                .is_none(),
            "failed bootstrap stream setup must not register a tunnel"
        );
    }

    #[tokio::test]
    async fn test_rtcp_tunnel_key_separates_direct_and_bootstrap_paths() {
        let (local_config, local_pkcs8_bytes) = test_device_config("key-local");
        let (remote_config, _) = test_device_config("key-remote");
        let inner = RTcpInner::new(
            local_config.id.clone(),
            "127.0.0.1:0".to_string(),
            Some(local_pkcs8_bytes),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        let remote = remote_config.id.to_string();
        let direct = parse_rtcp_stack_id(&format!("{}:2981", remote)).unwrap();
        let bootstrap_a = Url::parse("rtcp://relay-a.example.com:2993/remote:2981").unwrap();
        let bootstrap_b = Url::parse("rtcp://relay-b.example.com:2993/remote:2981").unwrap();
        let nested_a = parse_rtcp_stack_id(&build_rtcp_nested_remote_stack_id(
            &bootstrap_a,
            &remote,
            Some(2981),
        ))
        .unwrap();
        let nested_b = parse_rtcp_stack_id(&build_rtcp_nested_remote_stack_id(
            &bootstrap_b,
            &remote,
            Some(2981),
        ))
        .unwrap();

        let direct_key = inner.compute_tunnel_key(&direct).await.unwrap();
        let nested_a_key = inner.compute_tunnel_key(&nested_a).await.unwrap();
        let nested_b_key = inner.compute_tunnel_key(&nested_b).await.unwrap();

        assert_ne!(direct_key, nested_a_key);
        assert_ne!(nested_a_key, nested_b_key);
        assert_eq!(
            direct_key,
            format!(
                "{}_{}",
                local_config.id.to_string(),
                remote_config.id.to_string()
            )
        );
        assert!(!direct_key.contains("|bootstrap="));
        assert!(nested_a_key.contains("|bootstrap=rtcp://relay-a.example.com:2993/remote:2981"));
        assert!(nested_b_key.contains("|bootstrap=rtcp://relay-b.example.com:2993/remote:2981"));
    }

    #[tokio::test]
    async fn test_rtcp_tunnel_key_uses_resolved_dev_did_for_name_reset() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;

        let (local_config, local_pkcs8_bytes) = test_device_config("name-reset-local");
        let (dev_a_config, dev_a_pkcs8_bytes) = test_device_config("name-reset-a");
        let (dev_b_config, dev_b_pkcs8_bytes) = test_device_config("name-reset-b");
        let alias = "rtcp-name-reset.devtests.org";

        let (port_local, port_a, port_b) = {
            let local = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let a = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let b = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            (
                local.local_addr().unwrap().port(),
                a.local_addr().unwrap().port(),
                b.local_addr().unwrap().port(),
            )
        };

        let mut rtcp_local = RTcp::new(
            local_config.id.clone(),
            format!("127.0.0.1:{}", port_local),
            Some(local_pkcs8_bytes),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        enable_txt_bootstrap(&mut rtcp_local);
        rtcp_local.start().await.unwrap();

        let mut rtcp_a = RTcp::new(
            dev_a_config.id.clone(),
            format!("127.0.0.1:{}", port_a),
            Some(dev_a_pkcs8_bytes),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        rtcp_a.start().await.unwrap();

        add_rtcp_alias(alias, &dev_a_config.id).await;
        tokio::time::sleep(Duration::from_millis(200)).await;

        let stack_id_a = format!("{}:{}", alias, port_a);
        let tunnel_a = rtcp_local
            .create_tunnel(Some(stack_id_a.as_str()))
            .await
            .unwrap();
        tunnel_a.ping().await.unwrap();
        let key_a = rtcp_local
            .inner
            .compute_tunnel_key(&parse_rtcp_stack_id(&stack_id_a).unwrap())
            .await
            .unwrap();
        assert!(key_a.ends_with(dev_a_config.id.to_string().as_str()));

        let mut rtcp_b = RTcp::new(
            dev_b_config.id.clone(),
            format!("127.0.0.1:{}", port_b),
            Some(dev_b_pkcs8_bytes),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        rtcp_b.start().await.unwrap();
        add_rtcp_alias(alias, &dev_b_config.id).await;
        tokio::time::sleep(Duration::from_millis(200)).await;

        let stack_id_b = format!("{}:{}", alias, port_b);
        let tunnel_b = rtcp_local
            .create_tunnel(Some(stack_id_b.as_str()))
            .await
            .unwrap();
        tunnel_b.ping().await.unwrap();
        let key_b = rtcp_local
            .inner
            .compute_tunnel_key(&parse_rtcp_stack_id(&stack_id_b).unwrap())
            .await
            .unwrap();

        assert_ne!(key_a, key_b);
        assert!(key_b.ends_with(dev_b_config.id.to_string().as_str()));
        assert!(
            rtcp_local
                .inner
                .tunnel_map
                .get_tunnel(&key_a)
                .await
                .is_some()
        );
        assert!(
            rtcp_local
                .inner
                .tunnel_map
                .get_tunnel(&key_b)
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_rtcp_name_and_dev_did_share_tunnel_key_for_same_device() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (local_config, local_pkcs8_bytes) = test_device_config("name-dev-key-local");
        let (remote_config, _) = test_device_config("name-dev-key-remote");
        let alias = "rtcp-same-dev.devtests.org";
        add_rtcp_alias(alias, &remote_config.id).await;

        let mut inner = RTcpInner::new(
            local_config.id.clone(),
            "127.0.0.1:0".to_string(),
            Some(local_pkcs8_bytes),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        inner.security.peer_identity.dns_txt_bootstrap = true;
        let by_name = parse_rtcp_stack_id(&format!("{}:2981", alias)).unwrap();
        let by_dev =
            parse_rtcp_stack_id(&format!("{}:2981", remote_config.id.to_string())).unwrap();
        let by_dev_host =
            parse_rtcp_stack_id(&format!("{}:2981", remote_config.id.to_host_name())).unwrap();

        let key_by_name = inner.compute_tunnel_key(&by_name).await.unwrap();
        assert_eq!(
            key_by_name,
            inner.compute_tunnel_key(&by_dev).await.unwrap()
        );
        assert_eq!(
            key_by_name,
            inner.compute_tunnel_key(&by_dev_host).await.unwrap()
        );
    }

    #[tokio::test]
    async fn test_rtcp_second_logical_name_to_same_dev_is_rejected() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (server_config, server_key) = test_device_config("one-binding-server");
        let (client_config, client_key) = test_device_config("one-binding-client");
        cache_test_device(&server_config).await;
        cache_test_device(&client_config).await;
        let alias_a = "rtcp-one-binding-a.devtests.org";
        let alias_b = "rtcp-one-binding-b.devtests.org";
        add_rtcp_alias(alias_a, &server_config.id).await;
        add_rtcp_alias(alias_b, &server_config.id).await;

        let server_port = unused_tcp_port();
        let mut server = RTcp::new(
            server_config.id.clone(),
            format!("127.0.0.1:{}", server_port),
            Some(server_key),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        allow_named_key_fallback(&mut server);
        server.start().await.unwrap();
        let mut client = RTcp::new(
            client_config.id.clone(),
            format!("127.0.0.1:{}", unused_tcp_port()),
            Some(client_key),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        enable_txt_bootstrap(&mut client);
        client.start().await.unwrap();

        // Two logical names resolving to the same DEV DID share the canonical
        // tunnel key by construction...
        let by_alias_a = parse_rtcp_stack_id(&format!("{}:{}", alias_a, server_port)).unwrap();
        let by_alias_b = parse_rtcp_stack_id(&format!("{}:{}", alias_b, server_port)).unwrap();
        assert_eq!(
            client.inner.compute_tunnel_key(&by_alias_a).await.unwrap(),
            client.inner.compute_tunnel_key(&by_alias_b).await.unwrap()
        );

        let first_handle = client
            .create_tunnel(Some(&format!("{}:{}", alias_a, server_port)))
            .await
            .unwrap();
        first_handle.ping().await.unwrap();

        let client_tunnel_key = format!(
            "{}_{}",
            client_config.id.to_string(),
            server_config.id.to_string()
        );
        let bound_instance =
            wait_for_current_tunnel(&client.inner.tunnel_map, &client_tunnel_key, None)
                .await
                .instance_id();

        // ...but two names for one device is invalid device modeling under
        // the one-to-one binding: the second name is rejected explicitly
        // instead of silently reusing the first name's tunnel.
        let err = match client
            .create_tunnel(Some(&format!("{}:{}", alias_b, server_port)))
            .await
        {
            Ok(_) => panic!("second logical name to the same canonical dev must be rejected"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("one-to-one name binding")
                && err.to_string().contains("rtcp-one-binding-a"),
            "unexpected error: {}",
            err
        );

        // The legitimate binding's tunnel stays untouched, and direct did:dev
        // addressing is not a second logical name: it keeps sharing the
        // device tunnel.
        let dev_handle = client
            .create_tunnel(Some(&format!(
                "{}:{}",
                server_config.id.to_host_name(),
                server_port
            )))
            .await
            .unwrap();
        dev_handle.ping().await.unwrap();
        assert_eq!(
            client
                .inner
                .tunnel_map
                .get_tunnel(&client_tunnel_key)
                .await
                .unwrap()
                .instance_id(),
            bound_instance
        );
        assert_eq!(
            client
                .inner
                .tunnel_map
                .bound_logical_for_dev(&server_config.id.to_string())
                .await,
            Some(by_alias_a.did.to_string())
        );
    }

    #[tokio::test]
    async fn outbound_name_then_dev_creation_reuses_existing_tunnel() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (server_config, server_key) = test_device_config("reuse-server");
        let (client_config, client_key) = test_device_config("reuse-client");
        cache_test_device(&server_config).await;
        cache_test_device(&client_config).await;
        let alias = "rtcp-reuse-target.devtests.org";
        add_rtcp_alias(alias, &server_config.id).await;

        let server_port = unused_tcp_port();
        let mut server = RTcp::new(
            server_config.id.clone(),
            format!("127.0.0.1:{}", server_port),
            Some(server_key),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        allow_named_key_fallback(&mut server);
        server.start().await.unwrap();
        let mut client = RTcp::new(
            client_config.id.clone(),
            format!("127.0.0.1:{}", unused_tcp_port()),
            Some(client_key),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        enable_txt_bootstrap(&mut client);
        client.start().await.unwrap();

        let by_name = format!("{}:{}", alias, server_port);
        let first_handle = client.create_tunnel(Some(&by_name)).await.unwrap();
        first_handle.ping().await.unwrap();

        let client_tunnel_key = format!(
            "{}_{}",
            client_config.id.to_string(),
            server_config.id.to_string()
        );
        let server_tunnel_key = format!(
            "{}_{}",
            server_config.id.to_string(),
            client_config.id.to_string()
        );
        let client_instance =
            wait_for_current_tunnel(&client.inner.tunnel_map, &client_tunnel_key, None)
                .await
                .instance_id();
        let server_instance =
            wait_for_current_tunnel(&server.inner.tunnel_map, &server_tunnel_key, None)
                .await
                .instance_id();

        let by_dev = format!("{}:{}", server_config.id.to_host_name(), server_port);
        let second_handle = client.create_tunnel(Some(&by_dev)).await.unwrap();
        second_handle.ping().await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(
            client
                .inner
                .tunnel_map
                .get_tunnel(&client_tunnel_key)
                .await
                .unwrap()
                .instance_id(),
            client_instance
        );
        assert_eq!(
            server
                .inner
                .tunnel_map
                .get_tunnel(&server_tunnel_key)
                .await
                .unwrap()
                .instance_id(),
            server_instance,
            "name/dev reuse must not create a second inbound connection"
        );
    }

    #[tokio::test]
    async fn inbound_tunnel_outlives_handshake_deadline_and_releases_permit() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (server_config, server_key) = test_device_config("handshake-lifetime-server");
        let (client_one_config, client_one_key) =
            test_device_config("handshake-lifetime-client-one");
        let (client_two_config, client_two_key) =
            test_device_config("handshake-lifetime-client-two");
        cache_test_device(&server_config).await;
        cache_test_device(&client_one_config).await;
        cache_test_device(&client_two_config).await;

        let server_port = unused_tcp_port();
        let mut server = RTcp::new(
            server_config.id.clone(),
            format!("127.0.0.1:{}", server_port),
            Some(server_key),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        let mut server_security = RtcpSecurityConfig::default();
        server_security.inbound_admission.anonymous = RtcpAnonymousAdmission::Allow;
        server_security.inbound_admission.named_min_relation = RtcpNamedMinRelation::Any;
        server_security.limits.handshake_timeout_secs = 1;
        server_security.limits.max_pending_handshakes = 1;
        server.set_security_config(server_security).unwrap();
        server.start().await.unwrap();

        let mut client_one = RTcp::new(
            client_one_config.id.clone(),
            format!("127.0.0.1:{}", unused_tcp_port()),
            Some(client_one_key),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        client_one.start().await.unwrap();
        let mut client_two = RTcp::new(
            client_two_config.id.clone(),
            format!("127.0.0.1:{}", unused_tcp_port()),
            Some(client_two_key),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        client_two.start().await.unwrap();

        let server_stack_id = format!("{}:{}", server_config.id.to_host_name(), server_port);
        let client_one_tunnel = tokio::time::timeout(
            Duration::from_secs(5),
            client_one.create_tunnel(Some(&server_stack_id)),
        )
        .await
        .expect("first RTCP handshake timed out")
        .expect("first RTCP handshake failed");
        let server_tunnel_key_one = format!(
            "{}_{}",
            server_config.id.to_string(),
            client_one_config.id.to_string()
        );
        let server_tunnel_one =
            wait_for_current_tunnel(&server.inner.tunnel_map, &server_tunnel_key_one, None).await;

        // An established tunnel must release the pending-handshake permit
        // immediately instead of retaining it for the lifetime of run().
        tokio::time::timeout(
            Duration::from_secs(5),
            client_two.create_tunnel(Some(&server_stack_id)),
        )
        .await
        .expect("second RTCP handshake timed out while the first tunnel was established")
        .expect("established tunnel retained the only pending-handshake permit");
        let server_tunnel_key_two = format!(
            "{}_{}",
            server_config.id.to_string(),
            client_two_config.id.to_string()
        );
        wait_for_current_tunnel(&server.inner.tunnel_map, &server_tunnel_key_two, None).await;

        tokio::time::sleep(Duration::from_millis(1200)).await;
        let current = server
            .inner
            .tunnel_map
            .get_tunnel(&server_tunnel_key_one)
            .await
            .expect("established inbound tunnel disappeared after handshake deadline");
        assert!(current.is_same_instance(&server_tunnel_one));
        assert!(!current.is_closed());
        current
            .ping_rtt(Duration::from_secs(2))
            .await
            .expect("inbound control read loop stopped after handshake deadline");

        let mut stream = tokio::time::timeout(
            Duration::from_secs(5),
            client_one_tunnel.open_stream("handshake-lifetime.test:80"),
        )
        .await
        .expect("open_stream timed out after handshake deadline")
        .expect("open_stream failed after handshake deadline");
        stream.write_all(b"still-alive").await.unwrap();
        let mut response = [0u8; 11];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"still-alive");
    }

    #[tokio::test]
    async fn incomplete_first_packet_still_obeys_handshake_deadline() {
        let (server_config, server_key) = test_device_config("handshake-timeout-server");
        let server_port = unused_tcp_port();
        let mut server = RTcp::new(
            server_config.id,
            format!("127.0.0.1:{}", server_port),
            Some(server_key),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        let mut security = RtcpSecurityConfig::default();
        security.limits.handshake_timeout_secs = 1;
        server.set_security_config(security).unwrap();
        server.start().await.unwrap();

        let mut stalled = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .unwrap();
        let mut byte = [0u8; 1];
        match tokio::time::timeout(Duration::from_secs(2), stalled.read(&mut byte))
            .await
            .expect("stalled first packet was not closed by handshake deadline")
        {
            Ok(0) | Err(_) => {}
            Ok(n) => panic!("server unexpectedly wrote {n} byte(s) to stalled handshake"),
        }
    }

    #[tokio::test]
    async fn initial_packet_reads_are_bounded_and_release_handshake_permits() {
        let (server_config, server_key) = test_device_config("initial-read-limit-server");
        let server_port = unused_tcp_port();
        let mut server = RTcp::new(
            server_config.id,
            format!("127.0.0.1:{}", server_port),
            Some(server_key),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        let mut security = RtcpSecurityConfig::default();
        security.limits.max_pending_handshakes = 1;
        security.limits.handshake_timeout_secs = 2;
        server.set_security_config(security).unwrap();
        server.start().await.unwrap();

        // A connection that sends no data consumes the only permit before
        // the server starts reading its first package.
        let stalled = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .unwrap();
        wait_for_available_handshake_permits(&server, 0).await;

        // Capacity exhaustion is handled in the accept loop: the next peer is
        // closed promptly instead of receiving another long-lived read task.
        let mut rejected = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .unwrap();
        assert_connection_closed_within(&mut rejected, Duration::from_secs(1)).await;

        // EOF releases the permit.
        drop(stalled);
        wait_for_available_handshake_permits(&server, 1).await;

        // A partial length field is subject to the same bound.
        let mut partial = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .unwrap();
        partial.write_all(&[0]).await.unwrap();
        wait_for_available_handshake_permits(&server, 0).await;
        let mut rejected_after_partial = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .unwrap();
        assert_connection_closed_within(&mut rejected_after_partial, Duration::from_secs(1)).await;
        drop(partial);
        wait_for_available_handshake_permits(&server, 1).await;

        // A malformed first package releases its permit as soon as parsing
        // fails (length 1 is smaller than the RTCP control header).
        let mut malformed = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .unwrap();
        wait_for_available_handshake_permits(&server, 0).await;
        malformed.write_all(&[0, 1]).await.unwrap();
        wait_for_available_handshake_permits(&server, 1).await;
        assert_connection_closed_within(&mut malformed, Duration::from_secs(1)).await;

        // Timeout also returns the permit, even with an incomplete length
        // field still pending.
        let mut timed_out = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .unwrap();
        timed_out.write_all(&[0]).await.unwrap();
        wait_for_available_handshake_permits(&server, 0).await;
        assert_connection_closed_within(&mut timed_out, Duration::from_secs(3)).await;
        wait_for_available_handshake_permits(&server, 1).await;

        // HelloStream needs the permit only through first-packet
        // classification and releases it before stream delivery.
        let mut hello_stream = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .unwrap();
        wait_for_available_handshake_permits(&server, 0).await;
        let mut hello_stream_package = vec![0, 0];
        hello_stream_package.extend_from_slice(b"0123456789abcdef0123456789abcdef");
        hello_stream.write_all(&hello_stream_package).await.unwrap();
        wait_for_available_handshake_permits(&server, 1).await;
    }

    #[tokio::test]
    async fn authenticated_second_connection_is_rejected_while_first_is_live() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (server_config, server_key) = test_device_config("replace-server");
        let (client_logical_did, client_dev_did, client_key, client_device_doc_jwt) =
            test_named_device_identity("replace-client");
        cache_test_device(&server_config).await;

        let server_port = unused_tcp_port();
        let client_one_port = unused_tcp_port();
        let client_two_port = unused_tcp_port();

        let mut server = RTcp::new(
            server_config.id.clone(),
            format!("127.0.0.1:{}", server_port),
            Some(server_key),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        allow_named_key_fallback(&mut server);
        server.start().await.unwrap();
        let mut client_one = RTcp::new(
            client_logical_did,
            format!("127.0.0.1:{}", client_one_port),
            Some(client_key),
            Some(client_device_doc_jwt),
            Arc::new(MockRTcpListener::new()),
        );
        client_one.start().await.unwrap();
        let mut client_two = RTcp::new(
            client_dev_did.clone(),
            format!("127.0.0.1:{}", client_two_port),
            Some(client_key),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        client_two.start().await.unwrap();

        let server_stack_id = format!("{}:{}", server_config.id.to_host_name(), server_port);
        let client_one_tunnel = client_one
            .create_tunnel(Some(&server_stack_id))
            .await
            .unwrap();
        let server_tunnel_key = format!(
            "{}_{}",
            server_config.id.to_string(),
            client_dev_did.to_string()
        );
        let old_server_tunnel =
            wait_for_current_tunnel(&server.inner.tunnel_map, &server_tunnel_key, None).await;

        let second_error = match client_two.create_tunnel(Some(&server_stack_id)).await {
            Ok(_) => panic!("duplicate authenticated connection must be rejected"),
            Err(err) => err,
        };
        assert!(
            second_error
                .to_string()
                .contains("first accepted tunnel wins"),
            "unexpected duplicate error: {}",
            second_error
        );

        assert!(!old_server_tunnel.is_closed());
        old_server_tunnel
            .ping_rtt(Duration::from_secs(2))
            .await
            .expect("first accepted tunnel must remain usable");
        let mut stream = tokio::time::timeout(
            Duration::from_secs(5),
            client_one_tunnel.open_stream("first-winner-echo.test:80"),
        )
        .await
        .expect("first tunnel open timed out")
        .expect("first tunnel open failed");
        stream.write_all(b"first-winner-ok").await.unwrap();
        let mut response = [0u8; 15];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"first-winner-ok");

        // Give the rejected candidate time to execute cleanup. It must not
        // remove or close the first accepted instance.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(server
            .inner
            .tunnel_map
            .get_tunnel(&server_tunnel_key)
            .await
            .unwrap()
            .is_same_instance(&old_server_tunnel));
    }

    #[tokio::test]
    async fn concurrent_create_tunnel_calls_share_one_accepted_instance() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (server_config, server_key) = test_device_config("single-flight-server");
        let (client_config, client_key) = test_device_config("single-flight-client");
        cache_test_device(&server_config).await;
        cache_test_device(&client_config).await;

        let admissions = Arc::new(AtomicUsize::new(0));
        let server_port = unused_tcp_port();
        let mut server = RTcp::new(
            server_config.id.clone(),
            format!("127.0.0.1:{}", server_port),
            Some(server_key),
            None,
            Arc::new(MockRTcpListener::counting(
                admissions.clone(),
                Duration::from_millis(150),
            )),
        );
        server.start().await.unwrap();

        let mut client = RTcp::new(
            client_config.id.clone(),
            format!("127.0.0.1:{}", unused_tcp_port()),
            Some(client_key),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        client.start().await.unwrap();

        let stack_id = format!("{}:{}", server_config.id.to_host_name(), server_port);
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let inner = client.inner.clone();
            let stack_id = stack_id.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                let tunnel = inner
                    .create_tunnel(Some(&stack_id))
                    .await
                    .map_err(|err| err.to_string())?;
                tunnel.ping().await.map_err(|err| err.to_string())
            }));
        }
        barrier.wait().await;
        for task in tasks {
            task.await.unwrap().unwrap();
        }

        assert_eq!(
            admissions.load(Ordering::SeqCst),
            1,
            "single-flight must prevent a second RTCP handshake"
        );
        let client_key = format!(
            "{}_{}",
            client_config.id.to_string(),
            server_config.id.to_string()
        );
        let server_key = format!(
            "{}_{}",
            server_config.id.to_string(),
            client_config.id.to_string()
        );
        assert_eq!(client.inner.tunnel_map.primary_len().await, 1);
        assert_eq!(server.inner.tunnel_map.primary_len().await, 1);
        assert!(client
            .inner
            .tunnel_map
            .get_tunnel(&client_key)
            .await
            .is_some());
        assert!(server
            .inner
            .tunnel_map
            .get_tunnel(&server_key)
            .await
            .is_some());
    }

    #[tokio::test]
    async fn listener_rejection_does_not_replace_current_inbound_tunnel() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (server_config, server_key) = test_device_config("reject-replace-server");
        let (client_logical_did, client_dev_did, client_key, client_device_doc_jwt) =
            test_named_device_identity("reject-replace-client");
        cache_test_device(&server_config).await;

        let admissions = Arc::new(AtomicUsize::new(0));
        let server_port = unused_tcp_port();
        let mut server = RTcp::new(
            server_config.id.clone(),
            format!("127.0.0.1:{}", server_port),
            Some(server_key),
            None,
            Arc::new(RejectAfterFirstTunnelListener {
                admissions: admissions.clone(),
            }),
        );
        allow_named_key_fallback(&mut server);
        server.start().await.unwrap();

        let mut client_one = RTcp::new(
            client_logical_did,
            format!("127.0.0.1:{}", unused_tcp_port()),
            Some(client_key),
            Some(client_device_doc_jwt),
            Arc::new(MockRTcpListener::new()),
        );
        client_one.start().await.unwrap();
        let mut client_two = RTcp::new(
            client_dev_did.clone(),
            format!("127.0.0.1:{}", unused_tcp_port()),
            Some(client_key),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        client_two.start().await.unwrap();

        let server_stack_id = format!("{}:{}", server_config.id.to_host_name(), server_port);
        let _first_client_tunnel = client_one
            .create_tunnel(Some(&server_stack_id))
            .await
            .unwrap();
        let server_tunnel_key = format!(
            "{}_{}",
            server_config.id.to_string(),
            client_dev_did.to_string()
        );
        let original =
            wait_for_current_tunnel(&server.inner.tunnel_map, &server_tunnel_key, None).await;

        // create_tunnel must wait for the responder's final listener result,
        // not return Ok immediately after sending HelloAckConfirm.
        let rejection = match client_two.create_tunnel(Some(&server_stack_id)).await {
            Ok(_) => panic!("listener rejection must be returned to the initiator"),
            Err(err) => err,
        };
        assert!(
            rejection
                .to_string()
                .contains("test listener rejects replacement"),
            "unexpected listener rejection: {}",
            rejection
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            while admissions.load(Ordering::SeqCst) < 2 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("second listener admission was not observed");

        let current = server
            .inner
            .tunnel_map
            .get_tunnel(&server_tunnel_key)
            .await
            .unwrap();
        assert!(current.is_same_instance(&original));
        assert!(!original.is_closed());
        original
            .ping_rtt(Duration::from_secs(2))
            .await
            .expect("listener rejection must leave the old tunnel usable");
    }

    #[tokio::test]
    async fn authority_negative_reconnect_never_calls_application_listener() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (server_config, server_key) = test_device_config("negative-listener-server");
        let (client_logical_did, _client_dev_did, client_key, client_device_doc_jwt) =
            test_named_device_identity("negative-listener-client");
        cache_test_device(&server_config).await;

        let admissions = Arc::new(AtomicUsize::new(0));
        let server_port = unused_tcp_port();
        let mut server = RTcp::new(
            server_config.id.clone(),
            format!("127.0.0.1:{}", server_port),
            Some(server_key),
            None,
            Arc::new(MockRTcpListener::counting(
                admissions.clone(),
                Duration::ZERO,
            )),
        );
        // Without the RTCP Negative gate this setup deliberately permits the
        // unavailable LocalAndZone verification to fall back to KeyDid and
        // reach the listener, making the callback assertion meaningful.
        allow_named_key_fallback(&mut server);
        let rejected_revision =
            DocumentRevision::of(&EncodedDocument::Jwt(client_device_doc_jwt.clone()));
        server
            .inner
            .tunnel_map
            .force_authority_negative(
                &client_logical_did.to_string(),
                rejected_revision,
                "test authority Superseded",
            )
            .await;
        server.start().await.unwrap();

        let mut client = RTcp::new(
            client_logical_did.clone(),
            format!("127.0.0.1:{}", unused_tcp_port()),
            Some(client_key),
            Some(client_device_doc_jwt),
            Arc::new(MockRTcpListener::new()),
        );
        client.start().await.unwrap();

        let stack_id = format!("{}:{}", server_config.id.to_host_name(), server_port);
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            client.create_tunnel(Some(&stack_id)),
        )
        .await
        .expect("Negative reconnect did not fail within handshake budget");
        assert!(result.is_err(), "Negative reconnect must fail closed");
        assert_eq!(
            admissions.load(Ordering::SeqCst),
            0,
            "application listener must not observe an active Negative identity"
        );
        assert_eq!(server.inner.tunnel_map.primary_len().await, 0);
        assert_eq!(
            server
                .inner
                .tunnel_map
                .verified_identity_len(&client_logical_did.to_string())
                .await,
            0
        );
    }

    // Mock实现用于测试
    struct MockRTcpListener {
        admissions: Option<Arc<AtomicUsize>>,
        admission_delay: Duration,
    }

    impl MockRTcpListener {
        fn new() -> Self {
            MockRTcpListener {
                admissions: None,
                admission_delay: Duration::ZERO,
            }
        }

        fn counting(admissions: Arc<AtomicUsize>, admission_delay: Duration) -> Self {
            MockRTcpListener {
                admissions: Some(admissions),
                admission_delay,
            }
        }
    }

    struct RejectAfterFirstTunnelListener {
        admissions: Arc<AtomicUsize>,
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
        create_count: Option<Arc<AtomicUsize>>,
    }

    #[async_trait::async_trait]
    impl TunnelBuilder for TestRtcpTunnelBuilder {
        async fn create_tunnel(
            &self,
            tunnel_stack_id: Option<&str>,
        ) -> TunnelResult<Box<dyn TunnelBox>> {
            if let Some(create_count) = self.create_count.as_ref() {
                create_count.fetch_add(1, Ordering::SeqCst);
            }
            self.inner.create_tunnel(tunnel_stack_id).await
        }
    }

    #[derive(Clone)]
    struct FailingBootstrapTunnel {
        open_count: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl Tunnel for FailingBootstrapTunnel {
        async fn ping(&self) -> Result<(), std::io::Error> {
            Ok(())
        }

        async fn open_stream_by_dest(
            &self,
            _dest_port: u16,
            _dest_host: Option<String>,
        ) -> Result<Box<dyn AsyncStream>, std::io::Error> {
            self.open_count.fetch_add(1, Ordering::SeqCst);
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "mock bootstrap stream refused",
            ))
        }

        async fn open_stream(
            &self,
            _stream_id: &str,
        ) -> Result<Box<dyn AsyncStream>, std::io::Error> {
            self.open_count.fetch_add(1, Ordering::SeqCst);
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "mock bootstrap stream refused",
            ))
        }

        async fn create_datagram_client_by_dest(
            &self,
            _dest_port: u16,
            _dest_host: Option<String>,
        ) -> Result<Box<dyn DatagramClientBox>, std::io::Error> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "mock bootstrap datagram unsupported",
            ))
        }

        async fn create_datagram_client(
            &self,
            _session_id: &str,
        ) -> Result<Box<dyn DatagramClientBox>, std::io::Error> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "mock bootstrap datagram unsupported",
            ))
        }
    }

    struct FailingBootstrapTunnelBuilder {
        create_count: Arc<AtomicUsize>,
        open_count: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl TunnelBuilder for FailingBootstrapTunnelBuilder {
        async fn create_tunnel(
            &self,
            _tunnel_stack_id: Option<&str>,
        ) -> TunnelResult<Box<dyn TunnelBox>> {
            self.create_count.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(FailingBootstrapTunnel {
                open_count: self.open_count.clone(),
            }))
        }
    }

    #[async_trait::async_trait]
    impl RTcpListener for MockRTcpListener {
        async fn on_new_tunnel(
            &self,
            _endpoint: TunnelEndpoint,
            _source_addr: SocketAddr,
            _source_device_info: Option<RTcpSourceDeviceInfo>,
        ) -> TunnelResult<()> {
            if let Some(admissions) = self.admissions.as_ref() {
                admissions.fetch_add(1, Ordering::SeqCst);
            }
            if !self.admission_delay.is_zero() {
                tokio::time::sleep(self.admission_delay).await;
            }
            Ok(())
        }

        async fn on_new_stream(
            &self,
            mut stream: Box<dyn AsyncStream>,
            _dest_host: Option<String>,
            _dest_port: u16,
            _endpoint: TunnelEndpoint,
            _remote_addr: SocketAddr,
            _local_addr: SocketAddr,
        ) -> TunnelResult<()> {
            tokio::spawn(async move {
                loop {
                    let mut buf = [0u8; 1024];
                    match stream.read(&mut buf).await {
                        Ok(n) => {
                            if n == 0 {
                                break;
                            }
                            if let Err(e) = stream.write_all(&buf[0..n]).await {
                                error!("write error: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            error!("read error: {}", e);
                            break;
                        }
                    }
                }
            });
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
    impl RTcpListener for RejectAfterFirstTunnelListener {
        async fn on_new_tunnel(
            &self,
            _endpoint: TunnelEndpoint,
            _source_addr: SocketAddr,
            _source_device_info: Option<RTcpSourceDeviceInfo>,
        ) -> TunnelResult<()> {
            let admission = self.admissions.fetch_add(1, Ordering::SeqCst);
            if admission == 0 {
                Ok(())
            } else {
                Err(TunnelError::ReasonError(
                    "test listener rejects replacement".to_string(),
                ))
            }
        }

        async fn on_new_stream(
            &self,
            _stream: Box<dyn AsyncStream>,
            _dest_host: Option<String>,
            _dest_port: u16,
            _endpoint: TunnelEndpoint,
            _remote_addr: SocketAddr,
            _local_addr: SocketAddr,
        ) -> TunnelResult<()> {
            Err(TunnelError::ReasonError(
                "test listener does not accept streams".to_string(),
            ))
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
                "test listener does not accept datagrams".to_string(),
            ))
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
        let device_config =
            DeviceDocument::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        add_observed_cache(device_config.id.clone(), None, encoded_doc, None).unwrap();
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
        let device_config =
            DeviceDocument::new_by_jwk("test2", serde_json::from_value(jwk).unwrap());
        let id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        add_observed_cache(device_config.id.clone(), None, encoded_doc, None).unwrap();
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
        // The v4 key-confirmation handshake is synchronous -- the
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
        let device_config =
            DeviceDocument::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        add_observed_cache(device_config.id.clone(), None, encoded_doc, None).unwrap();
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
        let device_config =
            DeviceDocument::new_by_jwk("test2", serde_json::from_value(jwk).unwrap());
        let id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        add_observed_cache(device_config.id.clone(), None, encoded_doc, None).unwrap();
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
            DeviceDocument::new_by_jwk("probe1", serde_json::from_value(jwk).unwrap());
        let _id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        add_observed_cache(device_config.id.clone(), None, encoded_doc, None).unwrap();
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
            DeviceDocument::new_by_jwk("probe2", serde_json::from_value(jwk).unwrap());
        let id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        add_observed_cache(device_config.id.clone(), None, encoded_doc, None).unwrap();
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
            DeviceDocument::new_by_jwk("server", serde_json::from_value(server_jwk).unwrap());
        let server_id = server_device_config.id.clone();

        let (owner_signing_key, owner_pkcs8_bytes) = generate_ed25519_key();
        let owner_jwk = encode_ed25519_sk_to_pk_jwk(&owner_signing_key);
        let owner_config =
            DeviceDocument::new_by_jwk("owner", serde_json::from_value(owner_jwk).unwrap());
        let owner_did = owner_config.id.clone();
        let owner_private_key = EncodingKey::from_ed_der(&owner_pkcs8_bytes);

        let (client_signing_key, client_pkcs8_bytes) = generate_ed25519_key();
        let client_jwk = encode_ed25519_sk_to_pk_jwk(&client_signing_key);
        let mut client_device_config =
            DeviceDocument::new_by_jwk("client", serde_json::from_value(client_jwk).unwrap());
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
        let mut server_inner = RTcpInner::new(
            server_id,
            "127.0.0.1:19064".to_string(),
            Some(server_pkcs8_bytes),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        server_inner.security.inbound_admission.named_min_relation = RtcpNamedMinRelation::Any;

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
        let (parsed_from, candidate_key, candidate_document) =
            server_inner.parse_source_candidate(&hello_body).unwrap();
        assert_eq!(parsed_from, client_id);
        assert_eq!(
            canonical_dev_did_from_ed25519_pk(&candidate_key),
            client_id.clone()
        );
        assert_eq!(
            candidate_document.unwrap().owner,
            owner_did,
            "parse-only admission must preserve the claimed owner for later trusted verification"
        );
        // server_inner is exercised here just to make sure the test
        // device boots without the long-term X25519 key (v2 dropped it).
        assert!(server_inner.this_device_ed25519_sk.is_some());

        RTcpInner::verify_hello_token(
            &state.token,
            &DecodingKey::from_ed_der(&candidate_key),
            Some(client_id.to_string().as_str()),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn test_rtcp_logical_from_requires_and_caches_device_doc_jwt() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;

        let (owner_signing_key, owner_pkcs8_bytes) = generate_ed25519_key();
        let owner_jwk = encode_ed25519_sk_to_pk_jwk(&owner_signing_key);
        let owner_config =
            DeviceDocument::new_by_jwk("owner", serde_json::from_value(owner_jwk).unwrap());
        let owner_did = owner_config.id.clone();
        let owner_private_key = EncodingKey::from_ed_der(&owner_pkcs8_bytes);

        // 设备文档的 id 是逻辑名字(非 did:dev),default key 是设备自身的 key。
        // method 用 "test" 保证 LocalAndZone 无可信材料可用。本测试锁定 D3:
        // 缺文档直接拒绝，携带自签声明也不能进入任何 self-declared/observed fallback。
        let (client_signing_key, _client_pkcs8_bytes) = generate_ed25519_key();
        let client_jwk = encode_ed25519_sk_to_pk_jwk(&client_signing_key);
        let mut client_device_config =
            DeviceDocument::new_by_jwk("client", serde_json::from_value(client_jwk).unwrap());
        let client_dev_did = client_device_config.id.clone();
        let client_logical_did = DID::new("test", "rtcp-logical-client");
        client_device_config.id = client_logical_did.clone();
        client_device_config.owner = owner_did.clone();
        let client_device_doc_jwt = match client_device_config
            .encode(Some(&owner_private_key))
            .unwrap()
        {
            EncodedDocument::Jwt(jwt) => jwt,
            _ => panic!("device config encode should return jwt"),
        };
        let mut server_inner = RTcpInner::new(
            DID::new("dev", "logical-admission-server"),
            "127.0.0.1:19066".to_string(),
            None,
            None,
            Arc::new(MockRTcpListener::new()),
        );
        server_inner.security.inbound_admission.named_min_relation = RtcpNamedMinRelation::Any;

        // 逻辑名字不带 device_doc_jwt 必须被拒绝。
        let hello_body_without_jwt = RTcpHelloBody {
            from_id: client_logical_did.to_string(),
            to_id: "did:web:server.devtests.org".to_string(),
            my_port: 19065,
            tunnel_token: Some("unused".to_string()),
            device_doc_jwt: None,
        };
        let err = match server_inner.parse_source_candidate(&hello_body_without_jwt) {
            Ok(_) => panic!("logical from without device_doc_jwt must be rejected"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("device_doc_jwt is required"),
            "unexpected error: {}",
            err
        );

        // 带 device_doc_jwt 时只允许 parse-only 得到候选 key；固定的
        // LocalAndZone 准入验证没有可信材料，因此 fail closed，不写观察缓存。
        let hello_body = RTcpHelloBody {
            from_id: client_logical_did.to_string(),
            to_id: "did:web:server.devtests.org".to_string(),
            my_port: 19065,
            tunnel_token: Some("unused".to_string()),
            device_doc_jwt: Some(client_device_doc_jwt.clone()),
        };
        let (parsed_from, candidate_key, candidate_document) =
            server_inner.parse_source_candidate(&hello_body).unwrap();
        assert_eq!(parsed_from, client_logical_did);
        assert_eq!(
            canonical_dev_did_from_ed25519_pk(&candidate_key),
            client_dev_did
        );
        let err = match server_inner
            .resolve_source_device_info(
                &hello_body,
                &parsed_from,
                candidate_key,
                candidate_document.as_ref(),
            )
            .await
        {
            Ok(_) => panic!("self-declared document must not be accepted"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("could not be evaluated")
                || err.to_string().contains("failed"),
            "unexpected error: {}",
            err
        );

        assert!(
            resolve_did(&client_logical_did, None).await.is_err(),
            "self-declared input must not become a trusted cache entry"
        );
    }

    // 测试用权威 provider:按 (did, doc_type) 返回预注册的发布状态与文档本体;
    // offline 置位后所有查询报传输错误,模拟权威源断网。
    struct TestAuthorityProvider {
        states: Vec<PublishedState>,
        docs: Vec<(DID, String, EncodedDocument)>,
        offline: Arc<AtomicBool>,
    }

    #[async_trait]
    impl NsProvider for TestAuthorityProvider {
        fn get_id(&self) -> String {
            "rtcp-test-authority".to_string()
        }

        async fn query(
            &self,
            _name: &str,
            _record_type: Option<RecordType>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<NameInfo> {
            Err(NSError::NotFound("not implemented".to_string()))
        }

        async fn query_did(
            &self,
            did: &DID,
            doc_type: Option<DidDocType>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<EncodedDocument> {
            if self.offline.load(Ordering::SeqCst) {
                return Err(NSError::Failed("authority offline (test)".to_string()));
            }
            let wanted = doc_type.unwrap_or_default();
            self.docs
                .iter()
                .find(|(candidate, doc_type, _)| candidate == did && doc_type == wanted.as_str())
                .map(|(_, _, doc)| doc.clone())
                .ok_or_else(|| NSError::NotFound("no matching doc".to_string()))
        }

        async fn resolve_published_state(
            &self,
            did: &DID,
            doc_type: &DidDocType,
        ) -> NSResult<Option<PublishedState>> {
            if self.offline.load(Ordering::SeqCst) {
                return Err(NSError::Failed("authority offline (test)".to_string()));
            }
            Ok(self
                .states
                .iter()
                .find(|state| state.did == *did && state.doc_type == doc_type.as_str())
                .cloned())
        }
    }

    #[tokio::test]
    async fn authority_negative_recovers_only_for_exact_remote_current_document() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;

        let (owner_signing_key, owner_pkcs8_bytes) = generate_ed25519_key();
        let owner_jwk = encode_ed25519_sk_to_pk_jwk(&owner_signing_key);
        let owner_config = DeviceDocument::new_by_jwk(
            "recovery-owner",
            serde_json::from_value(owner_jwk).unwrap(),
        );
        let owner_private_key = EncodingKey::from_ed_der(&owner_pkcs8_bytes);
        let logical_did = DID::new("rtcpnegative", "recoverable-device");

        let (old_signing_key, _) = generate_ed25519_key();
        let old_jwk = encode_ed25519_sk_to_pk_jwk(&old_signing_key);
        let mut old_document =
            DeviceDocument::new_by_jwk("old-device", serde_json::from_value(old_jwk).unwrap());
        old_document.id = logical_did.clone();
        old_document.owner = owner_config.id.clone();
        let old_jwt = match old_document.encode(Some(&owner_private_key)).unwrap() {
            EncodedDocument::Jwt(jwt) => jwt,
            _ => panic!("old recovery document must be JWT"),
        };

        let (current_signing_key, _) = generate_ed25519_key();
        let current_jwk = encode_ed25519_sk_to_pk_jwk(&current_signing_key);
        let mut current_document = DeviceDocument::new_by_jwk(
            "current-device",
            serde_json::from_value(current_jwk).unwrap(),
        );
        current_document.id = logical_did.clone();
        current_document.owner = owner_config.id.clone();
        let current_jwt = match current_document.encode(Some(&owner_private_key)).unwrap() {
            EncodedDocument::Jwt(jwt) => jwt,
            _ => panic!("current recovery document must be JWT"),
        };
        let old_revision = DocumentRevision::of(&EncodedDocument::Jwt(old_jwt.clone())).unwrap();
        let current_revision =
            DocumentRevision::of(&EncodedDocument::Jwt(current_jwt.clone())).unwrap();
        assert_ne!(old_revision, current_revision);

        let mut current_state = PublishedState::active(
            logical_did.clone(),
            "device".to_string(),
            EncodedDocument::Jwt(current_jwt.clone()),
        );
        current_state.effective_owner = Some(owner_config.id);
        GLOBAL_NAME_CLIENT
            .get()
            .unwrap()
            .set_method_authority(
                "rtcpnegative",
                Box::new(TestAuthorityProvider {
                    states: vec![current_state],
                    docs: vec![(
                        logical_did.clone(),
                        "device".to_string(),
                        EncodedDocument::Jwt(current_jwt.clone()),
                    )],
                    offline: Arc::new(AtomicBool::new(false)),
                }),
            )
            .await;

        let inner = RTcpInner::new(
            DID::new("dev", "negative-recovery-test-server"),
            "127.0.0.1:0".to_string(),
            None,
            None,
            Arc::new(MockRTcpListener::new()),
        );
        inner
            .tunnel_map
            .force_authority_negative(
                &logical_did.to_string(),
                Some(old_revision),
                "authority reported DifferentDocument",
            )
            .await;

        let err = inner
            .recover_negative_authority_candidate(&logical_did, &old_jwt)
            .await
            .expect_err("old snapshot must not clear authority Negative");
        assert!(
            err.to_string().contains("Current revision"),
            "unexpected recovery error: {}",
            err
        );
        assert!(
            inner
                .tunnel_map
                .authority_negative_snapshot(&logical_did.to_string())
                .await
                .is_some()
        );

        inner
            .recover_negative_authority_candidate(&logical_did, &current_jwt)
            .await
            .expect("exact RemoteAuthority Current document must recover identity");
        assert!(
            inner
                .tunnel_map
                .authority_negative_snapshot(&logical_did.to_string())
                .await
                .is_none()
        );
        assert!(
            inner
                .tunnel_map
                .authority_confirmed_revision(&logical_did.to_string(), &current_revision)
                .await
        );
    }

    // 权威锚定成功路径(doc/verify-did-document-jwt.md"RTCP 迁移示例"):
    // 权威源给出 owner 绑定与当前发布集合证明时,resolve_source_device_info 走
    // name-client 的 resolve_and_verify_device_document_jwt,source owner 取
    // authz_owner(权威绑定,不是 payload 自声明)。纯 verify 不写 cache;
    // 模拟持钥证明与授权完成后显式提交 Verified cache,之后即使权威源断网,
    // strict resolve_did 也能命中,不再需要宽松策略。
    #[tokio::test]
    async fn test_rtcp_authority_anchored_known_owner_hits_trusted_cache() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;

        let (owner_signing_key, owner_pkcs8_bytes) = generate_ed25519_key();
        let owner_jwk = encode_ed25519_sk_to_pk_jwk(&owner_signing_key);
        let owner_did = DID::new("rtcpauth", "owner1");
        let owner_private_key = EncodingKey::from_ed_der(&owner_pkcs8_bytes);
        let owner_doc = OwnerDocument::new(
            owner_did.clone(),
            "owner1".to_string(),
            "owner1@rtcpauth".to_string(),
            serde_json::from_value(owner_jwk).unwrap(),
        );
        let owner_doc_encoded = owner_doc.encode(Some(&owner_private_key)).unwrap();

        let (device_signing_key, _device_pkcs8_bytes) = generate_ed25519_key();
        let device_jwk = encode_ed25519_sk_to_pk_jwk(&device_signing_key);
        let mut device_config =
            DeviceDocument::new_by_jwk("dev1", serde_json::from_value(device_jwk).unwrap());
        let device_dev_did = device_config.id.clone();
        let device_did = DID::new("rtcpauth", "dev1");
        device_config.id = device_did.clone();
        device_config.owner = owner_did.clone();
        let device_doc_jwt = match device_config.encode(Some(&owner_private_key)).unwrap() {
            EncodedDocument::Jwt(jwt) => jwt,
            _ => panic!("device config encode should return jwt"),
        };

        // A cryptographically valid candidate for the same DID that is not
        // the authority's current body.  The new API reports this as
        // AuthorityFreshness::NotCurrent instead of folding it into verify.
        let mut superseded_device_config = device_config.clone();
        superseded_device_config.name = "superseded-dev1".to_string();
        let superseded_device_doc_jwt = match superseded_device_config
            .encode(Some(&owner_private_key))
            .unwrap()
        {
            EncodedDocument::Jwt(jwt) => jwt,
            _ => panic!("device config encode should return jwt"),
        };

        let revoked_device_did = DID::new("rtcpauth", "revoked1");
        let mut revoked_device_config = device_config.clone();
        revoked_device_config.id = revoked_device_did.clone();
        revoked_device_config.name = "revoked1".to_string();
        let revoked_device_doc_jwt = match revoked_device_config
            .encode(Some(&owner_private_key))
            .unwrap()
        {
            EncodedDocument::Jwt(jwt) => jwt,
            _ => panic!("device config encode should return jwt"),
        };

        // 越权候选:权威 owner 绑定是 owner1,文档却自声明一个 did:dev owner
        // 并用它的 key 签名。旧的自声明验证会放行("JWT 能被它自己声明的 owner
        // 验过"),权威锚定验证必须以 DeclaredOwnerMismatch 拒绝且不回落。
        let (rogue_owner_signing_key, rogue_owner_pkcs8_bytes) = generate_ed25519_key();
        let rogue_owner_jwk = encode_ed25519_sk_to_pk_jwk(&rogue_owner_signing_key);
        let rogue_owner_config = DeviceDocument::new_by_jwk(
            "rogue-owner",
            serde_json::from_value(rogue_owner_jwk).unwrap(),
        );
        let rogue_owner_private_key = EncodingKey::from_ed_der(&rogue_owner_pkcs8_bytes);
        let (rogue_device_signing_key, _) = generate_ed25519_key();
        let rogue_device_jwk = encode_ed25519_sk_to_pk_jwk(&rogue_device_signing_key);
        let mut rogue_device_config =
            DeviceDocument::new_by_jwk("dev2", serde_json::from_value(rogue_device_jwk).unwrap());
        let rogue_device_did = DID::new("rtcpauth", "dev2");
        rogue_device_config.id = rogue_device_did.clone();
        rogue_device_config.owner = rogue_owner_config.id.clone();
        let rogue_device_doc_jwt = match rogue_device_config
            .encode(Some(&rogue_owner_private_key))
            .unwrap()
        {
            EncodedDocument::Jwt(jwt) => jwt,
            _ => panic!("device config encode should return jwt"),
        };

        // 权威源:owner 文档锚定发布;device 文档 Active + effective_owner 绑定
        // + 内联 body(外部候选与当前发布集合一致 → membership 成立 → Published)。
        let mut device_state = PublishedState::active(
            device_did.clone(),
            "device".to_string(),
            EncodedDocument::Jwt(device_doc_jwt.clone()),
        );
        device_state.effective_owner = Some(owner_did.clone());
        let mut rogue_device_state = PublishedState::active(
            rogue_device_did.clone(),
            "device".to_string(),
            EncodedDocument::Jwt(rogue_device_doc_jwt.clone()),
        );
        rogue_device_state.effective_owner = Some(owner_did.clone());
        let mut revoked_device_state =
            PublishedState::missing(revoked_device_did.clone(), "device".to_string());
        revoked_device_state.document_status = DocumentStatus::Revoked;
        revoked_device_state.effective_owner = Some(owner_did.clone());
        let provider = TestAuthorityProvider {
            states: vec![
                PublishedState::active(
                    owner_did.clone(),
                    "owner".to_string(),
                    owner_doc_encoded.clone(),
                ),
                device_state,
                rogue_device_state,
                revoked_device_state,
            ],
            docs: vec![
                (
                    owner_did.clone(),
                    "owner".to_string(),
                    owner_doc_encoded.clone(),
                ),
                (
                    device_did.clone(),
                    "device".to_string(),
                    EncodedDocument::Jwt(device_doc_jwt.clone()),
                ),
            ],
            offline: Arc::new(AtomicBool::new(false)),
        };
        let offline = provider.offline.clone();
        GLOBAL_NAME_CLIENT
            .get()
            .unwrap()
            .set_method_authority("rtcpauth", Box::new(provider))
            .await;
        let mut authority_policy = ResolvePolicy::default();
        authority_policy.source = ResolveSourcePolicy::RemoteAuthority;
        authority_policy.allow_stale_cache = false;
        let resolved_owner = resolve_did_ex(
            &owner_did,
            Some(DidDocType::Owner),
            authority_policy.clone(),
        )
        .await
        .unwrap();
        GLOBAL_NAME_CLIENT
            .get()
            .unwrap()
            .add_verified_cache(
                owner_did.clone(),
                Some(DidDocType::Owner),
                resolved_owner.document,
            )
            .unwrap();
        let authority_options = ResolveVerifyOptions {
            purpose: VerifyPurpose::AuthSubject,
            policy: authority_policy,
        };
        let (_, authority_verified) = resolve_and_verify_device_document_jwt(
            &device_did,
            &device_doc_jwt,
            &authority_options,
        )
        .await
        .unwrap();
        GLOBAL_NAME_CLIENT
            .get()
            .unwrap()
            .add_verified_cache(
                device_did.clone(),
                Some(DidDocType::Device),
                authority_verified.document.clone(),
            )
            .unwrap();
        let (device_doc, verified) = resolve_and_verify_device_document_jwt(
            &device_did,
            &device_doc_jwt,
            &authority_options,
        )
        .await
        .unwrap();
        assert_eq!(verified.subject_did, device_did);
        assert_eq!(verified.authz_owner, Some(owner_did.clone()));
        assert!(
            verified.validity.owner_document_source.is_some(),
            "known_owner requires trusted OwnerDocument evidence"
        );
        let mut known_owner_inner = RTcpInner::new(
            DID::new("dev", "known-owner-admission-server"),
            "127.0.0.1:0".to_string(),
            None,
            None,
            Arc::new(MockRTcpListener::new()),
        );
        known_owner_inner
            .security
            .inbound_admission
            .named_min_relation = RtcpNamedMinRelation::KnownOwner;
        known_owner_inner
            .validate_named_relation(&device_doc, &verified)
            .expect("owner-backed AuthSubject must pass known_owner admission");

        let mut ownerless_verified = verified.clone();
        ownerless_verified.authz_owner = None;
        ownerless_verified.usable_as_authz_subject = false;
        ownerless_verified.validity.owner_document_source = None;
        let err = known_owner_inner
            .validate_named_relation(&device_doc, &ownerless_verified)
            .expect_err("identity without trusted owner evidence must fail known_owner admission");
        assert!(
            err.to_string().contains("no trusted owner evidence"),
            "unexpected error: {}",
            err
        );
        let verified_key = jwk_to_ed25519_pk(&device_doc.get_default_key().unwrap()).unwrap();
        assert_eq!(
            canonical_dev_did_from_ed25519_pk(&verified_key),
            device_dev_did
        );
        let verified_cache_entry = Some(PendingVerifiedCacheEntry {
            did: verified.subject_did.clone(),
            document: verified.document.clone(),
            identity: VerifiedTunnelIdentity {
                logical_did: verified.subject_did.to_string(),
                canonical_dev_did: canonical_dev_did_from_ed25519_pk(&verified_key).to_string(),
                document_revision: verified.revision.clone(),
            },
        });

        // Validity and freshness are separate: this candidate has the right
        // owner signature but the fresh authority receipt binds another body.
        // RTCP's policy must reject it before the self-declared fallback.
        let superseded_hello_body = RTcpHelloBody {
            from_id: device_did.to_string(),
            to_id: "did:web:server.devtests.org".to_string(),
            my_port: 19067,
            tunnel_token: Some("unused".to_string()),
            device_doc_jwt: Some(superseded_device_doc_jwt),
        };
        let (_, superseded_verified) = resolve_and_verify_device_document_jwt(
            &device_did,
            superseded_hello_body.device_doc_jwt.as_deref().unwrap(),
            &authority_options,
        )
        .await
        .unwrap();
        let err = RTcpInner::freshness_rejection(&superseded_verified)
            .expect("authority-current body mismatch must be rejected");
        assert!(
            err.contains("authority rejected candidate") || err.contains("conflicts with"),
            "unexpected error: {}",
            err
        );

        // Revoked/Tombstoned are typed terminal VerifyError values.  They are
        // definite rejection and may never enter self-declared verification.
        let revoked_hello_body = RTcpHelloBody {
            from_id: revoked_device_did.to_string(),
            to_id: "did:web:server.devtests.org".to_string(),
            my_port: 19067,
            tunnel_token: Some("unused".to_string()),
            device_doc_jwt: Some(revoked_device_doc_jwt),
        };
        let err = match resolve_and_verify_device_document_jwt(
            &revoked_device_did,
            revoked_hello_body.device_doc_jwt.as_deref().unwrap(),
            &authority_options,
        )
        .await
        {
            Ok(_) => panic!("terminal authority state must be rejected"),
            Err(e) => e,
        };
        assert!(
            RTcpInner::is_definite_verify_rejection(&err),
            "unexpected error: {}",
            err
        );

        // 越权候选被 Definite 拒绝,不回落:若错误来自回落路径,消息会是
        // "resolve owner auth key ... failed"(甚至因 did:dev owner 可本地验签
        // 而放行),而不是带稳定错误码的 rejected。
        let rogue_hello_body = RTcpHelloBody {
            from_id: rogue_device_did.to_string(),
            to_id: "did:web:server.devtests.org".to_string(),
            my_port: 19067,
            tunnel_token: Some("unused".to_string()),
            device_doc_jwt: Some(rogue_device_doc_jwt),
        };
        let err = match resolve_and_verify_device_document_jwt(
            &rogue_device_did,
            rogue_hello_body.device_doc_jwt.as_deref().unwrap(),
            &authority_options,
        )
        .await
        {
            Ok(_) => panic!("declared owner mismatching authority binding must be rejected"),
            Err(e) => e,
        };
        assert!(
            RTcpInner::is_definite_verify_rejection(&err)
                && err.to_string().contains("does not match expected owner"),
            "unexpected error: {}",
            err
        );

        // resolve/verify 到这里都没有隐式写入。模拟完整握手已完成持钥证明与
        // listener 授权,显式提交 verified cache;结构化 outcome 同时充当
        // high-water 的并发合并结果。
        let (_, cache_outcome) = RTcpInner::commit_verified_cache_entry(verified_cache_entry)
            .unwrap()
            .expect("authoritatively verified document should be staged for cache");
        assert!(cache_outcome.stored());

        // 受控缓存写入在权威源断网后仍可被 strict resolve_did 命中,与上一个
        // 测试的 Observed/Unverified(strict 下等同 miss)形成对照。
        offline.store(true, Ordering::SeqCst);
        let resolved = resolve_did(&device_did, Some(DidDocType::Device))
            .await
            .expect("strict resolve_did must hit the controlled cache entry");
        assert_eq!(resolved, EncodedDocument::Jwt(device_doc_jwt));
    }

    #[tokio::test]
    async fn test_rtcp_stream() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let port1 = unused_tcp_port();
        let port2 = unused_tcp_port();
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceDocument::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        add_observed_cache(device_config.id.clone(), None, encoded_doc, None).unwrap();
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
            format!("127.0.0.1:{port1}"),
            Some(pkcs8_bytes),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        rtcp1.start().await.unwrap();

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceDocument::new_by_jwk("test2", serde_json::from_value(jwk).unwrap());
        let id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        add_observed_cache(device_config.id.clone(), None, encoded_doc, None).unwrap();
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
            format!("127.0.0.1:{port2}"),
            Some(pkcs8_bytes),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        rtcp2.start().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;

        {
            let tunnel = rtcp1
                .create_tunnel(Some(format!("{}:{port2}", id2.to_host_name()).as_str()))
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
                .create_tunnel(Some(format!("{}:{port1}", id1.to_host_name()).as_str()))
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

    struct NestedRtcpRelayFixture {
        rtcp_a: RTcp,
        _rtcp_b: RTcp,
        _rtcp_c: RTcp,
        id_a: DID,
        id_b: DID,
        id_c: DID,
        nested_url: Url,
        tunnel: Box<dyn TunnelBox>,
        reverse_tunnel: Box<dyn TunnelBox>,
        bootstrap_create_count: Arc<AtomicUsize>,
    }

    fn configure_nested_stress_limits(rtcp: &mut RTcp) {
        let mut security = RtcpSecurityConfig::default();
        security.limits.max_pending_stream_builds_per_tunnel = 2048;
        security.limits.stream_requests_per_second = 100_000;
        security.limits.stream_request_burst = 4096;
        rtcp.set_security_config(security).unwrap();
    }

    async fn setup_nested_rtcp_relay_fixture(test_name: &str) -> NestedRtcpRelayFixture {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (port_a, port_b, port_c) = {
            let listener_a = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let listener_b = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let listener_c = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            (
                listener_a.local_addr().unwrap().port(),
                listener_b.local_addr().unwrap().port(),
                listener_c.local_addr().unwrap().port(),
            )
        };

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceDocument::new_by_jwk(
            format!("{}-a", test_name).as_str(),
            serde_json::from_value(jwk).unwrap(),
        );
        let id_a = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        add_observed_cache(device_config.id.clone(), None, encoded_doc, None).unwrap();
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
            format!("127.0.0.1:{}", port_a),
            Some(pkcs8_bytes),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        configure_nested_stress_limits(&mut rtcp_a);
        let tunnel_manager = TunnelManager::new();
        rtcp_a.set_tunnel_manager(tunnel_manager.clone());
        let bootstrap_create_count = Arc::new(AtomicUsize::new(0));
        tunnel_manager.register_tunnel_builder(
            "rtcp",
            Arc::new(TestRtcpTunnelBuilder {
                inner: rtcp_a.inner.clone(),
                create_count: Some(bootstrap_create_count.clone()),
            }),
        );
        rtcp_a.start().await.unwrap();

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceDocument::new_by_jwk(
            format!("{}-b", test_name).as_str(),
            serde_json::from_value(jwk).unwrap(),
        );
        let id_b = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        add_observed_cache(device_config.id.clone(), None, encoded_doc, None).unwrap();
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
            format!("127.0.0.1:{}", port_b),
            Some(pkcs8_bytes),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        configure_nested_stress_limits(&mut rtcp_b);
        rtcp_b.start().await.unwrap();

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceDocument::new_by_jwk(
            format!("{}-c", test_name).as_str(),
            serde_json::from_value(jwk).unwrap(),
        );
        let id_c = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        add_observed_cache(device_config.id.clone(), None, encoded_doc, None).unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let relay_routes = HashMap::from([(
            id_b.to_host_name(),
            format!("127.0.0.1:{}", port_b).parse().unwrap(),
        )]);
        let mut rtcp_c = RTcp::new(
            device_config.id,
            format!("127.0.0.1:{}", port_c),
            Some(pkcs8_bytes),
            None,
            Arc::new(RelayRTcpListener::new(relay_routes)),
        );
        configure_nested_stress_limits(&mut rtcp_c);
        rtcp_c.start().await.unwrap();

        tokio::time::sleep(Duration::from_secs(1)).await;

        let bootstrap_url = Url::parse(
            format!(
                "rtcp://{}:{}/{}:{}",
                id_c.to_host_name(),
                port_c,
                id_b.to_host_name(),
                port_b
            )
            .as_str(),
        )
        .unwrap();
        let nested_remote_stack_id =
            build_rtcp_nested_remote_stack_id(&bootstrap_url, &id_b.to_host_name(), Some(port_b));

        let before_outer_tunnel = bootstrap_create_count.load(Ordering::SeqCst);
        let tunnel = tokio::time::timeout(
            Duration::from_secs(10),
            rtcp_a.create_tunnel(Some(nested_remote_stack_id.as_str())),
        )
        .await
        .expect("nested remote tunnel creation timed out")
        .expect("A should build the outer tunnel to B through C");
        assert!(
            bootstrap_create_count.load(Ordering::SeqCst) > before_outer_tunnel,
            "nested outer tunnel creation must obtain its bearing stream through bootstrap"
        );

        tokio::time::timeout(Duration::from_secs(10), tunnel.ping())
            .await
            .expect("nested remote tunnel ping timed out")
            .expect("nested remote tunnel ping failed");

        let nested_url = Url::parse(format!("rtcp://{}", nested_remote_stack_id).as_str()).unwrap();

        let reverse_tunnel_key = format!("{}_{}", id_b.to_string(), id_a.to_string());
        let reverse_tunnel = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(tunnel) = rtcp_b
                    .inner
                    .tunnel_map
                    .get_tunnel(&reverse_tunnel_key)
                    .await
                {
                    break tunnel;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("B-side nested tunnel registration timed out");

        NestedRtcpRelayFixture {
            rtcp_a,
            _rtcp_b: rtcp_b,
            _rtcp_c: rtcp_c,
            id_a,
            id_b,
            id_c,
            nested_url,
            tunnel,
            reverse_tunnel: Box::new(reverse_tunnel),
            bootstrap_create_count,
        }
    }

    async fn open_echo_stream(
        tunnel: &dyn TunnelBox,
        stream_id: &str,
        payload: &[u8],
        context: &str,
    ) -> Box<dyn AsyncStream> {
        open_echo_stream_with_open_retries(tunnel, stream_id, payload, context, 1).await
    }

    async fn open_echo_stream_with_open_retries(
        tunnel: &dyn TunnelBox,
        stream_id: &str,
        payload: &[u8],
        context: &str,
        open_attempts: usize,
    ) -> Box<dyn AsyncStream> {
        let stream =
            open_stream_with_quota_retries(tunnel, stream_id, context, open_attempts).await;
        echo_stream(stream, payload, context).await
    }

    async fn echo_stream(
        mut stream: Box<dyn AsyncStream>,
        payload: &[u8],
        context: &str,
    ) -> Box<dyn AsyncStream> {
        match tokio::time::timeout(Duration::from_secs(60), stream.write_all(payload)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => panic!("{} stream write failed: {}", context, e),
            Err(_) => panic!("{} stream write timed out", context),
        }

        let mut buf = vec![0u8; payload.len()];
        match tokio::time::timeout(Duration::from_secs(60), stream.read_exact(&mut buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => panic!("{} stream read failed: {}", context, e),
            Err(_) => panic!("{} stream read timed out", context),
        }
        assert_eq!(buf, payload, "{} stream echo payload mismatch", context);

        stream
    }

    async fn open_stream_with_quota_retries(
        tunnel: &dyn TunnelBox,
        stream_id: &str,
        context: &str,
        open_attempts: usize,
    ) -> Box<dyn AsyncStream> {
        let open_attempts = open_attempts.max(1);
        for attempt in 1..=open_attempts {
            match tokio::time::timeout(Duration::from_secs(30), tunnel.open_stream(stream_id)).await
            {
                Ok(Ok(stream)) => return stream,
                Ok(Err(e)) => {
                    let error_message = e.to_string();
                    let is_transient_rejection = error_message.contains("result=1")
                        || error_message.contains("result=2")
                        || error_message.contains("result=8");
                    if is_transient_rejection && attempt < open_attempts {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                    panic!("{} stream open failed: {}", context, e);
                }
                Err(_) => panic!("{} stream open timed out", context),
            }
        }
        unreachable!("open_attempts is clamped to at least one");
    }

    async fn assert_concurrent_stream_opens(
        tunnel: Box<dyn TunnelBox>,
        stream_id_prefix: &'static str,
        count: usize,
    ) {
        let mut streams = FuturesUnordered::new();
        for i in 0..count {
            let tunnel = tunnel.clone();
            streams.push(async move {
                let stream_id = format!("{}{}.test:80", stream_id_prefix, i);
                let stream = open_stream_with_quota_retries(
                    tunnel.as_ref(),
                    &stream_id,
                    stream_id_prefix,
                    500,
                )
                .await;
                drop(stream);
            });
        }

        let mut completed = 0usize;
        while streams.next().await.is_some() {
            completed += 1;
        }
        assert_eq!(completed, count, "{} streams opened", stream_id_prefix);
    }

    #[tokio::test]
    async fn test_rtcp_nested_remote_rebinds_transport_via_rtcp_relay() {
        let fixture = setup_nested_rtcp_relay_fixture("nested-flow").await;

        let nested_status = tokio::time::timeout(
            Duration::from_secs(10),
            fixture
                .rtcp_a
                .probe_url(&fixture.nested_url, &TunnelProbeOptions::default()),
        )
        .await
        .expect("nested remote probe timed out")
        .expect("nested remote probe failed");
        assert_eq!(
            nested_status.state,
            crate::tunnel_url_status::TunnelUrlState::Reachable
        );
        assert_eq!(
            nested_status.source,
            crate::tunnel_url_status::TunnelUrlStatusSource::ExistingTunnel
        );
        assert!(
            nested_status
                .runtime_tunnel_key
                .as_deref()
                .unwrap_or_default()
                .contains("|bootstrap=rtcp://"),
            "nested probe must report a bootstrap-qualified tunnel key: {:?}",
            nested_status.runtime_tunnel_key
        );

        let before_business_stream = fixture.bootstrap_create_count.load(Ordering::SeqCst);
        let stream = open_echo_stream(
            fixture.tunnel.as_ref(),
            "test:80",
            b"test",
            "nested remote forward",
        )
        .await;
        assert!(
            fixture.bootstrap_create_count.load(Ordering::SeqCst) > before_business_stream,
            "nested business stream open must replay the bootstrap transport"
        );

        let before_reverse_stream = fixture.bootstrap_create_count.load(Ordering::SeqCst);
        let reverse_stream = open_echo_stream(
            fixture.reverse_tunnel.as_ref(),
            "reverse.test:80",
            b"back",
            "nested remote reverse",
        )
        .await;
        assert!(
            fixture.bootstrap_create_count.load(Ordering::SeqCst) > before_reverse_stream,
            "B-side reverse open should make A replay the bootstrap transport"
        );
        drop(stream);

        let control_status_while_reverse_stream_open = tokio::time::timeout(
            Duration::from_secs(10),
            fixture
                .rtcp_a
                .probe_url(&fixture.nested_url, &TunnelProbeOptions::default()),
        )
        .await
        .expect("nested remote control probe timed out while reverse stream is open")
        .expect("nested remote control probe failed while reverse stream is open");
        assert_eq!(
            control_status_while_reverse_stream_open.state,
            crate::tunnel_url_status::TunnelUrlState::Reachable
        );
        assert_eq!(
            control_status_while_reverse_stream_open.source,
            crate::tunnel_url_status::TunnelUrlStatusSource::ExistingTunnel
        );
        drop(reverse_stream);

        assert_ne!(fixture.id_a, fixture.id_b);
        assert_ne!(fixture.id_b, fixture.id_c);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_rtcp_nested_remote_concurrent_streams_via_rtcp_relay() {
        let fixture = setup_nested_rtcp_relay_fixture("nested-concurrent").await;
        let concurrent_stream_count = 1000usize;

        let before_concurrent_streams = fixture.bootstrap_create_count.load(Ordering::SeqCst);
        tokio::join!(
            assert_concurrent_stream_opens(
                fixture.tunnel.clone(),
                "forward",
                concurrent_stream_count,
            ),
            assert_concurrent_stream_opens(
                fixture.reverse_tunnel.clone(),
                "reverse",
                concurrent_stream_count,
            ),
        );
        assert!(
            fixture.bootstrap_create_count.load(Ordering::SeqCst)
                >= before_concurrent_streams + (concurrent_stream_count * 2),
            "each concurrent forward and reverse stream should replay the bootstrap transport"
        );

        let _forward_after_stress = open_echo_stream(
            fixture.tunnel.as_ref(),
            "forward-after-stress.test:80",
            b"forward-after-stress",
            "forward after concurrent open stress",
        )
        .await;

        let _reverse_after_stress = open_echo_stream(
            fixture.reverse_tunnel.as_ref(),
            "reverse-after-stress.test:80",
            b"reverse-after-stress",
            "reverse after concurrent open stress",
        )
        .await;
    }

    #[tokio::test]
    async fn test_rtcp_datagram() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let port1 = unused_tcp_port();
        let port2 = unused_tcp_port();
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceDocument::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        add_observed_cache(device_config.id.clone(), None, encoded_doc, None).unwrap();
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
            format!("127.0.0.1:{port1}"),
            Some(pkcs8_bytes),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        rtcp1.start().await.unwrap();

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceDocument::new_by_jwk("test2", serde_json::from_value(jwk).unwrap());
        let id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        add_observed_cache(device_config.id.clone(), None, encoded_doc, None).unwrap();
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
            format!("127.0.0.1:{port2}"),
            Some(pkcs8_bytes),
            None,
            Arc::new(MockRTcpListener::new()),
        );
        rtcp2.start().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;

        {
            let tunnel = rtcp1
                .create_tunnel(Some(format!("{}:{port2}", id2.to_host_name()).as_str()))
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
                .create_tunnel(Some(format!("{}:{port1}", id1.to_host_name()).as_str()))
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
