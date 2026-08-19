use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fmt::Debug;
use std::io::ErrorKind;
use std::pin::Pin;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CmdType {
    UnknownProtocol = 0,
    Hello = 1,
    HelloAck = 2,
    Ping = 3,
    Pong = 4,
    ROpen = 5,
    ROpenResp = 6,
    Open = 7,
    OpenResp = 8,
    HelloAckConfirm = 9,
    TunnelResult = 10,
}

impl From<u8> for CmdType {
    fn from(value: u8) -> Self {
        match value {
            1 => CmdType::Hello,
            2 => CmdType::HelloAck,
            3 => CmdType::Ping,
            4 => CmdType::Pong,
            5 => CmdType::ROpen,
            6 => CmdType::ROpenResp,
            7 => CmdType::Open,
            8 => CmdType::OpenResp,
            9 => CmdType::HelloAckConfirm,
            10 => CmdType::TunnelResult,
            _ => CmdType::UnknownProtocol,
        }
    }
}

impl Into<u8> for CmdType {
    fn into(self) -> u8 {
        self as u8
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct RTcpTunnelPackageImpl<T>
where
    T: Serialize + Debug,
{
    pub len: u16,
    pub json_pos: u8,
    pub cmd: u8,
    pub seq: u32,
    pub body: T,
}

// JWT audience tag for the initiator's Hello token. Decode rejects any
// token whose `aud` is missing or not exactly this string. Bumping the
// suffix is how RTCP signals an incompatible handshake protocol revision
// without relying on an out-of-band version negotiation.
pub(crate) const RTCP_PROTOCOL_VERSION: u8 = 4;
pub(crate) const RTCP_HELLO_AUD: &str = "buckyos-rtcp-v4-hello";

// JWT audience tag for the responder's HelloAck token. Distinct from the
// Hello tag so that a captured Hello cannot be re-purposed as an ack and
// vice-versa (a confused-deputy mitigation in the RTCP v4 handshake).
pub(crate) const RTCP_HELLO_ACK_AUD: &str = "buckyos-rtcp-v4-ack";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct TunnelTokenPayload {
    // Audience binding (RFC 7519 §4.1.3). Pinned to RTCP_HELLO_AUD; any
    // other value is rejected at decode time. Locks this token to the
    // RTCP Hello flow and a specific protocol version, so it cannot be
    // replayed against a future BuckyOS protocol that happens to share
    // the same Ed25519 signing key.
    pub aud: String,
    // Semantic identity requested by the caller (for example a did:web
    // alias). It is retained in the HKDF context and echoed by HelloAck.
    pub to: String,
    // Canonical did:dev derived from the responder key selected by the
    // resolver. This lets the receiver prove that a semantic alias was
    // actually resolved to its own long-term key.
    pub canonical_to: String,
    pub from: String,
    // Signed copy of Hello.my_port. Receivers reject a mismatch before using
    // the plaintext field as a reconnect target.
    pub listen_port: u16,
    // Hex-encoded ephemeral X25519 public key. v4 always uses a freshly-
    // generated ephemeral key here; the key is no longer derived from
    // the device's long-term Ed25519 identity.
    pub xpub: String,
    pub iat: u64,
    pub exp: u64,
    // Hex-encoded random nonce (16 random bytes -> 32 hex chars).
    //
    // Responder keeps a short-lived per-(from_id, nonce) cache and rejects
    // any repeat while the token is still within its validity window. This
    // closes the replay gap in the v4 handshake: without the
    // nonce, a captured Hello could be replayed verbatim until the 60s
    // token expiry plus clock leeway elapsed.
    pub nonce: String,
}

// Responder's signed JWT carried inside HelloAck. Binds the responder's
// fresh ephemeral X25519 public key to its long-term Ed25519 identity,
// and to the *specific* Hello it is acking via `peer_xpub`.
//
// Without `peer_xpub` an attacker could splice an ack from a different
// session onto a Hello they captured -- both would type-check as valid
// JWTs from the responder. Embedding the initiator's ephemeral pin closes
// that splicing window.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct TunnelAckTokenPayload {
    pub aud: String,
    pub to: String,
    pub from: String,
    // Hex-encoded ephemeral X25519 public key for this side (responder).
    pub xpub: String,
    // Hex-encoded ephemeral X25519 public key from the initiator's Hello
    // that this ack is responding to. Binds the ack to one specific
    // handshake: a captured ack cannot be re-served against a different
    // initiator session, even by the same device.
    pub peer_xpub: String,
    pub iat: u64,
    pub exp: u64,
    pub nonce: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct RTcpHelloBody {
    pub from_id: String,
    pub to_id: String,
    pub my_port: u16,
    pub tunnel_token: Option<String>, //jwt token ,payload is TunnelTokenPayload
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_doc_jwt: Option<String>,
}

pub(crate) type RTcpHelloPackage = RTcpTunnelPackageImpl<RTcpHelloBody>;
impl RTcpHelloPackage {
    pub fn new(
        seq: u32,
        from_id: String,
        to_id: String,
        my_port: u16,
        tunnel_token: Option<String>,
        device_doc_jwt: Option<String>,
    ) -> Self {
        RTcpHelloPackage {
            len: 0,
            json_pos: 0,
            cmd: CmdType::Hello.into(),
            seq: seq,
            body: RTcpHelloBody {
                from_id,
                to_id,
                my_port,
                tunnel_token,
                device_doc_jwt,
            },
        }
    }

    pub fn from_json(seq: u32, json_value: serde_json::Value) -> Result<Self, std::io::Error> {
        let body = serde_json::from_value::<RTcpHelloBody>(json_value);
        if body.is_err() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "parse package error",
            ));
        }
        let pakcage = RTcpHelloPackage {
            len: 0,
            json_pos: 0,
            cmd: CmdType::Hello.into(),
            seq: seq,
            body: body.unwrap(),
        };
        Ok(pakcage)
    }
}

// HelloAck is the responder's plaintext reply in the v4 handshake. It
// publishes the responder's fresh ephemeral X25519 public key (carried
// inside `ack_token`, signed by the responder's long-term Ed25519 key)
// plus a fresh challenge. Both sides then derive the session key from
// ECDH(initiator_eph, responder_eph) -- a pure ephemeral exchange, so
// compromise of the long-term Ed25519 keys later does not unlock past
// sessions (forward secrecy).
//
// The challenge is sent in the clear here: HelloAckConfirm flows over
// the AEAD record layer, and an attacker without the derived AES key
// cannot produce a valid encrypted echo. The ack_token's signature
// (verified against the responder's published Ed25519 key) is what
// authenticates the responder's ephemeral key.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct RTcpHelloAckBody {
    // JWT signed by responder's Ed25519 long-term key, payload is
    // TunnelAckTokenPayload. Carries the responder's ephemeral X25519
    // public key bound to the initiator's `xpub` from the Hello.
    pub ack_token: String,
    // Hex-encoded 16 random bytes. Initiator echoes this back inside an
    // AEAD record (HelloAckConfirm) to prove it derived the same session
    // key.
    pub challenge: String,
    // Responder's DID hostname. Initiator cross-checks against the `to`
    // it signed into the original Hello.
    pub responder_id: String,
}
pub(crate) type RTcpHelloAckPackage = RTcpTunnelPackageImpl<RTcpHelloAckBody>;

impl RTcpHelloAckPackage {
    pub fn new(seq: u32, ack_token: String, challenge: String, responder_id: String) -> Self {
        RTcpHelloAckPackage {
            len: 0,
            json_pos: 0,
            cmd: CmdType::HelloAck.into(),
            seq: seq,
            body: RTcpHelloAckBody {
                ack_token,
                challenge,
                responder_id,
            },
        }
    }

    pub fn from_json(seq: u32, json_value: serde_json::Value) -> Result<Self, std::io::Error> {
        let body = serde_json::from_value::<RTcpHelloAckBody>(json_value);
        if body.is_err() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "parse package error",
            ));
        }
        let package = RTcpHelloAckPackage {
            len: 0,
            json_pos: 0,
            cmd: CmdType::HelloAck.into(),
            seq: seq,
            body: body.unwrap(),
        };
        Ok(package)
    }
}

// HelloAckConfirm proves initiator key possession in the v4 handshake by
// echoing the responder's challenge with the AEAD key. The responder's
// subsequent TunnelResult closes the handshake after admission.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct RTcpHelloAckConfirmBody {
    pub challenge_echo: String,
}
pub(crate) type RTcpHelloAckConfirmPackage = RTcpTunnelPackageImpl<RTcpHelloAckConfirmBody>;

impl RTcpHelloAckConfirmPackage {
    pub fn new(seq: u32, challenge_echo: String) -> Self {
        RTcpHelloAckConfirmPackage {
            len: 0,
            json_pos: 0,
            cmd: CmdType::HelloAckConfirm.into(),
            seq: seq,
            body: RTcpHelloAckConfirmBody { challenge_echo },
        }
    }

    pub fn from_json(seq: u32, json_value: serde_json::Value) -> Result<Self, std::io::Error> {
        let body = serde_json::from_value::<RTcpHelloAckConfirmBody>(json_value);
        if body.is_err() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "parse package error",
            ));
        }
        let package = RTcpHelloAckConfirmPackage {
            len: 0,
            json_pos: 0,
            cmd: CmdType::HelloAckConfirm.into(),
            seq: seq,
            body: body.unwrap(),
        };
        Ok(package)
    }
}

// The responder sends TunnelResult only after listener authorization and
// authoritative tunnel-map arbitration have completed. The initiator must not
// publish or return a tunnel before it receives an accepted result.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct RTcpTunnelResultBody {
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}
pub(crate) type RTcpTunnelResultPackage = RTcpTunnelPackageImpl<RTcpTunnelResultBody>;

impl RTcpTunnelResultPackage {
    pub fn accepted(seq: u32) -> Self {
        Self::new(seq, true, String::new())
    }

    pub fn rejected(seq: u32, reason: impl Into<String>) -> Self {
        Self::new(seq, false, reason.into())
    }

    fn new(seq: u32, accepted: bool, reason: String) -> Self {
        RTcpTunnelResultPackage {
            len: 0,
            json_pos: 0,
            cmd: CmdType::TunnelResult.into(),
            seq,
            body: RTcpTunnelResultBody { accepted, reason },
        }
    }

    pub fn from_json(seq: u32, json_value: serde_json::Value) -> Result<Self, std::io::Error> {
        let body = serde_json::from_value::<RTcpTunnelResultBody>(json_value).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "parse package error")
        })?;
        Ok(RTcpTunnelResultPackage {
            len: 0,
            json_pos: 0,
            cmd: CmdType::TunnelResult.into(),
            seq,
            body,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct RTcpPingBody {
    timestamp: u64,
}
pub(crate) type RTcpPingPackage = RTcpTunnelPackageImpl<RTcpPingBody>;

impl RTcpPingPackage {
    pub fn new(seq: u32, timestamp: u64) -> Self {
        RTcpPingPackage {
            len: 0,
            json_pos: 0,
            cmd: CmdType::Ping.into(),
            seq: seq,
            body: RTcpPingBody { timestamp },
        }
    }

    pub fn from_json(seq: u32, json_value: serde_json::Value) -> Result<Self, std::io::Error> {
        let body = serde_json::from_value::<RTcpPingBody>(json_value);
        if body.is_err() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "parse package error",
            ));
        }
        let package = RTcpPingPackage {
            len: 0,
            json_pos: 0,
            cmd: CmdType::Ping.into(),
            seq: seq,
            body: body.unwrap(),
        };
        Ok(package)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct RTcpPongBody {
    timestamp: u64,
}
pub(crate) type RTcpPongPackage = RTcpTunnelPackageImpl<RTcpPongBody>;

impl RTcpPongPackage {
    pub fn new(seq: u32, timestamp: u64) -> Self {
        RTcpPongPackage {
            len: 0,
            json_pos: 0,
            cmd: CmdType::Pong.into(),
            seq: seq,
            body: RTcpPongBody { timestamp },
        }
    }

    pub fn from_json(seq: u32, json_value: serde_json::Value) -> Result<Self, std::io::Error> {
        let body = serde_json::from_value::<RTcpPongBody>(json_value);
        if body.is_err() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "parse package error",
            ));
        }

        let package = RTcpPongPackage {
            len: 0,
            json_pos: 0,
            cmd: CmdType::Pong.into(),
            seq: seq,
            body: body.unwrap(),
        };

        Ok(package)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamPurpose {
    Stream = 0,
    Datagram = 1,
}

impl Default for StreamPurpose {
    fn default() -> Self {
        StreamPurpose::Stream
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct RTcpROpenBody {
    #[serde(rename = "streamid", alias = "stream_id")]
    pub stream_id: String,

    // Stream purpose, None is default as Stream
    pub purpose: Option<StreamPurpose>,

    pub dest_port: u16,

    // Dest host in ip or domain format, if none, then use default local ip
    pub dest_host: Option<String>,
}

pub(crate) type RTcpROpenPackage = RTcpTunnelPackageImpl<RTcpROpenBody>;

impl RTcpROpenPackage {
    pub fn new(
        seq: u32,
        session_key: String,
        purpose: Option<StreamPurpose>,
        dest_port: u16,
        dest_host: Option<String>,
    ) -> Self {
        RTcpROpenPackage {
            len: 0,
            json_pos: 0,
            cmd: CmdType::ROpen.into(),
            seq: seq,
            body: RTcpROpenBody {
                stream_id: session_key,
                purpose,
                dest_port,
                dest_host,
            },
        }
    }

    pub fn from_json(seq: u32, json_value: serde_json::Value) -> Result<Self, std::io::Error> {
        let body = serde_json::from_value::<RTcpROpenBody>(json_value);
        if body.is_err() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "parse package error",
            ));
        }

        let package = RTcpROpenPackage {
            len: 0,
            json_pos: 0,
            cmd: CmdType::ROpen.into(),
            seq: seq,
            body: body.unwrap(),
        };
        Ok(package)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct RTcpROpenRespBody {
    pub(crate) result: u32,
}
pub(crate) type RTcpROpenRespPackage = RTcpTunnelPackageImpl<RTcpROpenRespBody>;

impl RTcpROpenRespPackage {
    pub fn new(seq: u32, result: u32) -> Self {
        RTcpROpenRespPackage {
            len: 0,
            json_pos: 0,
            cmd: CmdType::ROpenResp.into(),
            seq: seq,
            body: RTcpROpenRespBody { result },
        }
    }

    pub fn from_json(seq: u32, json_value: serde_json::Value) -> Result<Self, std::io::Error> {
        let body = serde_json::from_value::<RTcpROpenRespBody>(json_value);
        if body.is_err() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "parse package error",
            ));
        }

        let package = RTcpROpenRespPackage {
            len: 0,
            json_pos: 0,
            cmd: CmdType::ROpenResp.into(),
            seq: seq,
            body: body.unwrap(),
        };
        Ok(package)
    }
}

// Same as RTcpROpenBody
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct RTcpOpenBody {
    #[serde(rename = "streamid", alias = "stream_id")]
    pub stream_id: String,

    // Stream purpose, None is default as Stream
    pub purpose: Option<StreamPurpose>,

    pub dest_port: u16,

    // Dest host in ip or domain format, if none, then use default local ip
    pub dest_host: Option<String>,
}

pub(crate) type RTcpOpenPackage = RTcpTunnelPackageImpl<RTcpOpenBody>;

impl RTcpOpenPackage {
    pub fn new(
        seq: u32,
        session_key: String,
        purpose: Option<StreamPurpose>,
        dest_port: u16,
        dest_host: Option<String>,
    ) -> Self {
        Self {
            len: 0,
            json_pos: 0,
            cmd: CmdType::Open.into(),
            seq: seq,
            body: RTcpOpenBody {
                stream_id: session_key,
                purpose,
                dest_port,
                dest_host,
            },
        }
    }

    pub fn from_json(seq: u32, json_value: serde_json::Value) -> Result<Self, std::io::Error> {
        let body = serde_json::from_value::<RTcpOpenBody>(json_value);
        if body.is_err() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "parse package error",
            ));
        }

        let package = Self {
            len: 0,
            json_pos: 0,
            cmd: CmdType::Open.into(),
            seq: seq,
            body: body.unwrap(),
        };
        Ok(package)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct RTcpOpenRespBody {
    pub(crate) result: u32,
}
pub(crate) type RTcpOpenRespPackage = RTcpTunnelPackageImpl<RTcpOpenRespBody>;

impl RTcpOpenRespPackage {
    pub fn new(seq: u32, result: u32) -> Self {
        Self {
            len: 0,
            json_pos: 0,
            cmd: CmdType::OpenResp.into(),
            seq: seq,
            body: RTcpOpenRespBody { result },
        }
    }

    pub fn from_json(seq: u32, json_value: serde_json::Value) -> Result<Self, std::io::Error> {
        let body = serde_json::from_value::<RTcpOpenRespBody>(json_value);
        if body.is_err() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "parse package error",
            ));
        }

        let package = Self {
            len: 0,
            json_pos: 0,
            cmd: CmdType::OpenResp.into(),
            seq: seq,
            body: body.unwrap(),
        };
        Ok(package)
    }
}

#[derive(Clone, Debug)]
pub(crate) enum RTcpTunnelPackage {
    HelloStream(String),
    Hello(RTcpHelloPackage),
    HelloAck(RTcpHelloAckPackage),
    HelloAckConfirm(RTcpHelloAckConfirmPackage),
    TunnelResult(RTcpTunnelResultPackage),
    Ping(RTcpPingPackage),
    Pong(RTcpPongPackage),
    ROpen(RTcpROpenPackage),
    ROpenResp(RTcpROpenRespPackage),
    Open(RTcpOpenPackage),
    OpenResp(RTcpOpenRespPackage),
}

const TUNNEL_KEY_DEFAULT: [u8; 32] = [6; 32];

impl RTcpTunnelPackage {
    pub async fn read_package<'a, S>(
        mut stream: Pin<&'a mut S>,
        is_first_package: bool,
        source_info: &str,
    ) -> Result<RTcpTunnelPackage, std::io::Error>
    where
        S: AsyncReadExt + 'a,
    {
        let mut buf = [0; 2];
        //info!("try read 2 bytes package len");
        stream.read_exact(&mut buf).await.map_err(|e| {
            if e.kind() == ErrorKind::UnexpectedEof {
                warn!("Read tunnel package len eof: {}, {}", source_info, e);
            } else {
                error!("Read tunnel package len error: {}, {}", source_info, e);
            }
            e
        })?;

        let len = u16::from_be_bytes(buf);
        debug!("{} ==> rtcp package, len: {}", source_info, len);
        if len == 0 {
            if !is_first_package {
                error!("HelloStream MUST be first package.");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "first package is not HelloStream",
                ));
            }

            let mut buf = [0; 32];
            stream.read_exact(&mut buf).await.map_err(|e| {
                error!("Read HelloStream error: {}, {}", source_info, e);
                e
            })?;

            let session_key = std::str::from_utf8(&buf).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "HelloStream stream id is not UTF-8",
                )
            })?;
            if !session_key.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "HelloStream stream id must be 32 hexadecimal ASCII bytes",
                ));
            }
            return Ok(RTcpTunnelPackage::HelloStream(session_key.to_string()));
        } else {
            const HEADER_LEN: usize = 8;
            if usize::from(len) < HEADER_LEN {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("rtcp control package length {} is smaller than 8", len),
                ));
            }
            let body_len = usize::from(len).checked_sub(2).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "rtcp package length underflow",
                )
            })?;
            let mut buf = vec![0; body_len];
            //info!("read package data len:{}",_len);
            stream.read_exact(&mut buf).await.map_err(|e| {
                error!("Read package data error: {}, {}", source_info, e);
                e
            })?;

            let json_pos = *buf.first().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "missing json_pos")
            })?;
            if usize::from(json_pos) != HEADER_LEN {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "rtcp v{} requires json_pos=8, got {}",
                        RTCP_PROTOCOL_VERSION, json_pos
                    ),
                ));
            }
            if usize::from(json_pos) > usize::from(len) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "json_pos is beyond package length",
                ));
            }
            let cmd_type = *buf.get(1).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "missing command")
            })?;
            let seq_bytes: [u8; 4] = buf
                .get(2..6)
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "missing sequence")
                })?
                .try_into()
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid sequence")
                })?;
            let seq = u32::from_be_bytes(seq_bytes);

            //start read json
            let json_index = usize::from(json_pos).checked_sub(2).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "json_pos is before length field",
                )
            })?;
            let read_buf = buf.get(json_index..).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "JSON offset is beyond package body",
                )
            })?;
            if read_buf.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "rtcp control package has empty JSON body",
                ));
            }
            let json_str = std::str::from_utf8(read_buf).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "rtcp JSON body is not UTF-8",
                )
            })?;

            //info!("read json:{}",json_str);
            let package_value = serde_json::from_str(json_str);
            if package_value.is_err() {
                let msg = format!(
                    "Parse rtcp package JSON error: {}",
                    package_value.err().unwrap()
                );
                error!("{}", msg);
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, msg));
            }
            let package_value = package_value.unwrap();

            let cmd = CmdType::from(cmd_type);
            match cmd {
                CmdType::Hello => {
                    let result_package = RTcpHelloPackage::from_json(seq, package_value)?;
                    return Ok(RTcpTunnelPackage::Hello(result_package));
                }
                CmdType::HelloAck => {
                    let result_package = RTcpHelloAckPackage::from_json(seq, package_value)?;
                    return Ok(RTcpTunnelPackage::HelloAck(result_package));
                }
                CmdType::HelloAckConfirm => {
                    let result_package = RTcpHelloAckConfirmPackage::from_json(seq, package_value)?;
                    return Ok(RTcpTunnelPackage::HelloAckConfirm(result_package));
                }
                CmdType::TunnelResult => {
                    let result_package = RTcpTunnelResultPackage::from_json(seq, package_value)?;
                    return Ok(RTcpTunnelPackage::TunnelResult(result_package));
                }
                CmdType::Ping => {
                    let result_package: RTcpTunnelPackageImpl<RTcpPingBody> =
                        RTcpPingPackage::from_json(seq, package_value)?;
                    return Ok(RTcpTunnelPackage::Ping(result_package));
                }
                CmdType::Pong => {
                    let result_package = RTcpPongPackage::from_json(seq, package_value)?;
                    return Ok(RTcpTunnelPackage::Pong(result_package));
                }
                CmdType::ROpen => {
                    let result_package = RTcpROpenPackage::from_json(seq, package_value)?;
                    return Ok(RTcpTunnelPackage::ROpen(result_package));
                }
                CmdType::ROpenResp => {
                    let result_package = RTcpROpenRespPackage::from_json(seq, package_value)?;
                    return Ok(RTcpTunnelPackage::ROpenResp(result_package));
                }
                CmdType::Open => {
                    let result_package = RTcpOpenPackage::from_json(seq, package_value)?;
                    return Ok(RTcpTunnelPackage::Open(result_package));
                }
                CmdType::OpenResp => {
                    let result_package = RTcpOpenRespPackage::from_json(seq, package_value)?;
                    return Ok(RTcpTunnelPackage::OpenResp(result_package));
                }
                v @ _ => {
                    let msg = format!("Unsupported package type {:?}", v);
                    error!("{}", msg);
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, msg));
                }
            }
        }
    }

    pub async fn send_package<S, T>(
        mut stream: Pin<&mut S>,
        pkg: RTcpTunnelPackageImpl<T>,
    ) -> Result<()>
    where
        T: Serialize + Debug,
        S: AsyncWriteExt,
    {
        //encode package to json
        let json_body = serde_json::to_string(&pkg.body).unwrap();
        let body_bytes = json_body.as_bytes();

        //let base64_str = URL_SAFE_NO_PAD.encode(json_str.as_bytes());
        let json_pos: u8 = 2 + 1 + 1 + 4;
        let total_len = 2 + 1 + 1 + 4 + body_bytes.len();
        if total_len > 0xffff {
            let msg = format!("package too long: {}", total_len);
            error!("{}", msg);
            return Err(anyhow::anyhow!(msg).into());
        }

        let mut write_buf: Vec<u8> = Vec::new();
        let bytes = u16::to_be_bytes(total_len as u16);
        write_buf.extend_from_slice(&bytes);
        write_buf.extend(std::iter::once(json_pos));
        write_buf.extend(std::iter::once(pkg.cmd as u8));
        let bytes = u32::to_be_bytes(pkg.seq);
        write_buf.extend_from_slice(&bytes);
        write_buf.extend_from_slice(body_bytes);

        debug!(
            "Send package cmd:{} len:{} buf_len:{}",
            pkg.cmd,
            total_len,
            write_buf.len()
        );

        stream.write_all(&write_buf).await.map_err(|e| {
            error!("Send package error: {}", e);
            e
        })?;

        Ok(())
    }

    pub async fn send_hello_stream<S>(
        stream: &mut S,
        session_key: &str,
    ) -> Result<(), anyhow::Error>
    where
        S: tokio::io::AsyncWrite + Unpin + ?Sized,
    {
        if session_key.len() != 32 || !session_key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "HelloStream stream id must be exactly 32 hexadecimal ASCII bytes",
            )
            .into());
        }
        // First hello package len is 0
        let total_len = 0;
        let mut write_buf: Vec<u8> = Vec::new();
        let bytes = u16::to_be_bytes(total_len);
        write_buf.extend_from_slice(&bytes);
        write_buf.extend_from_slice(session_key.as_bytes());
        stream.write_all(&write_buf).await.map_err(|e| {
            error!("Send HelloStream error: {}", e);
            e
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{Duration, timeout};

    async fn parse_bytes(bytes: Vec<u8>, first: bool) -> std::io::Result<RTcpTunnelPackage> {
        let (mut tx, mut rx) = tokio::io::duplex(128 * 1024);
        let writer = tokio::spawn(async move {
            tx.write_all(&bytes).await.unwrap();
            tx.shutdown().await.unwrap();
        });
        let result = timeout(
            Duration::from_millis(250),
            RTcpTunnelPackage::read_package(Pin::new(&mut rx), first, "parser-test"),
        )
        .await
        .expect("parser must never wait indefinitely");
        writer.await.unwrap();
        result
    }

    #[tokio::test]
    async fn malformed_lengths_offsets_and_json_never_panic() {
        for len in 0u16..=9 {
            let mut bytes = len.to_be_bytes().to_vec();
            if len == 0 {
                bytes.extend_from_slice(&[b'g'; 32]);
            } else {
                bytes.resize(usize::from(len), 0);
            }
            let err = parse_bytes(bytes, true).await.unwrap_err();
            assert!(
                matches!(
                    err.kind(),
                    ErrorKind::InvalidData | ErrorKind::UnexpectedEof
                ),
                "len={len}, error={err}"
            );
        }

        for json_pos in [0u8, 7, 9, u8::MAX] {
            let mut bytes = 9u16.to_be_bytes().to_vec();
            bytes.extend_from_slice(&[json_pos, CmdType::Ping as u8, 0, 0, 0, 1, b'{']);
            assert_eq!(
                parse_bytes(bytes, false).await.unwrap_err().kind(),
                ErrorKind::InvalidData
            );
        }

        let mut invalid_utf8 = 9u16.to_be_bytes().to_vec();
        invalid_utf8.extend_from_slice(&[8, CmdType::Ping as u8, 0, 0, 0, 1, 0xff]);
        assert_eq!(
            parse_bytes(invalid_utf8, false).await.unwrap_err().kind(),
            ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn arbitrary_short_inputs_return_without_panic_or_unbounded_wait() {
        for seed in 0u8..=255 {
            let len = usize::from(seed % 48);
            let bytes: Vec<u8> = (0..len)
                .map(|index| seed.wrapping_mul(31).wrapping_add(index as u8))
                .collect();
            let _ = parse_bytes(bytes, true).await;
        }
    }

    #[tokio::test]
    async fn hello_stream_requires_canonical_stream_id() {
        let valid = format!("{:032x}", 7);
        let mut bytes = 0u16.to_be_bytes().to_vec();
        bytes.extend_from_slice(valid.as_bytes());
        match parse_bytes(bytes, true).await.unwrap() {
            RTcpTunnelPackage::HelloStream(id) => assert_eq!(id, valid),
            other => panic!("unexpected package: {:?}", other),
        }

        let (mut tx, _rx) = tokio::io::duplex(128);
        let err = RTcpTunnelPackage::send_hello_stream(&mut tx, "short")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("exactly 32"));
    }

    #[tokio::test]
    async fn open_wire_format_keeps_string_purpose_and_header_v4_contract() {
        let package = RTcpOpenPackage::new(
            0x01020304,
            "00112233445566778899aabbccddeeff".to_string(),
            Some(StreamPurpose::Datagram),
            53,
            Some("dns.example".to_string()),
        );
        let (mut tx, mut rx) = tokio::io::duplex(4096);
        RTcpTunnelPackage::send_package(Pin::new(&mut tx), package)
            .await
            .unwrap();
        tx.shutdown().await.unwrap();
        let mut wire = Vec::new();
        rx.read_to_end(&mut wire).await.unwrap();

        let json = br#"{"streamid":"00112233445566778899aabbccddeeff","purpose":"Datagram","dest_port":53,"dest_host":"dns.example"}"#;
        let total_len = 8 + json.len();
        let mut expected = (total_len as u16).to_be_bytes().to_vec();
        expected.extend_from_slice(&[8, CmdType::Open as u8, 1, 2, 3, 4]);
        expected.extend_from_slice(json);
        assert_eq!(wire, expected);
    }
}
