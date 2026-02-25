use std::collections::HashMap;
use super::package::*;
use super::protocol::*;
use super::stream_helper::RTcpStreamBuildHelper;

use crate::tunnel::{TunnelBox};
use crate::{get_dest_info_from_url_path, has_scheme, DatagramClientBox, EncryptedStream, Tunnel, TunnelEndpoint, TunnelError, TunnelResult};
use anyhow::Result;
use async_trait::async_trait;
use buckyos_kit::{buckyos_get_unix_timestamp, AsyncStream};
use hex::ToHex;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use log::*;
use name_client::*;
use name_lib::*;
use percent_encoding::percent_decode_str;
use sha2::{Digest, Sha256};
use url::Url;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::time::Duration;
use rand::Rng;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Notify};
use tokio::task;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use crate::rtcp::datagram::RTcpTunnelDatagramClient;

pub struct RTcp {
    inner: Arc<RTcpInner>,
    handle: Option<JoinHandle<()>>,
}

impl Drop for RTcp {
    fn drop(&mut self) {
        log::info!("RTcp {} drop", self.inner.this_device_did.to_string());
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
        listener: RTcpListenerRef,
    ) -> RTcp {
        RTcp {
            inner: Arc::new(RTcpInner::new(
                this_device_did,
                bind_addr,
                private_key_pkcs8_bytes,
                listener,
            )),
            handle: None,
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
}

struct RTcpInner {
    tunnel_map: RTcpTunnelMap,
    stream_helper: RTcpStreamBuildHelper,
    listener: RTcpListenerRef,

    bind_addr: String,
    this_device_did: DID, //name or did
    this_device_ed25519_sk: Option<EncodingKey>,
    this_device_x25519_sk: Option<StaticSecret>,
}

impl Drop for RTcpInner {
    fn drop(&mut self) {
        log::info!("RTcpInner {} drop", self.this_device_did.to_string());
    }
}

impl RTcpInner {
    pub fn new(
        this_device_did: DID,
        bind_addr: String,
        private_key_pkcs8_bytes: Option<[u8; 48]>,
        listener: RTcpListenerRef,
    ) -> RTcpInner {
        let mut this_device_x25519_sk = None;
        let mut this_device_ed25519_sk = None;
        if private_key_pkcs8_bytes.is_some() {
            let private_key_pkcs8_bytes = private_key_pkcs8_bytes.unwrap();
            //info!("rtcp stack ed25519 private_key pkcs8 bytes: {:?}",private_key_pkcs8_bytes);
            let encoding_key = EncodingKey::from_ed_der(&private_key_pkcs8_bytes);
            this_device_ed25519_sk = Some(encoding_key);

            let private_key_bytes = from_pkcs8(&private_key_pkcs8_bytes).unwrap();
            //info!("rtcp stack ed25519 private_key  bytes: {:?}",private_key_bytes);

            let x25519_private_key =
                ed25519_to_curve25519::ed25519_sk_to_curve25519(private_key_bytes);
            //info!("rtcp stack x25519 private_key_bytes: {:?}",x25519_private_key);
            this_device_x25519_sk = Some(x25519_dalek::StaticSecret::from(x25519_private_key));
        }

        let result = RTcpInner {
            tunnel_map: RTcpTunnelMap::new(),
            stream_helper: RTcpStreamBuildHelper::new(),

            listener,
            bind_addr,
            this_device_did,
            this_device_ed25519_sk: this_device_ed25519_sk, //for sign tunnel token
            this_device_x25519_sk: this_device_x25519_sk,   //for decode tunnel token from remote
        };
        return result;
    }

    // return (tunnel_token,aes_key,my_public_bytes)
    async fn generate_tunnel_token(
        &self,
        target_hostname: String,
    ) -> Result<(String, [u8; 32], [u8; 32]), TunnelError> {
        if self.this_device_ed25519_sk.is_none() {
            return Err(TunnelError::DocumentError(
                "this device ed25519 sk is none".to_string(),
            ));
        }
        let remote_did = DID::from_str(target_hostname.as_str()).map_err(|op| {
            TunnelError::DocumentError(format!("invalid target device is not did: {}",op))
        })?;

        let exchange_key = resolve_ed25519_exchange_key(&remote_did)
            .await
            .map_err(|op| {
                let msg = format!(
                    "cann't resolve target device {} ed25519 exchange key: {}",
                    target_hostname.as_str(),
                    op
                );
                error!("{}", msg);
                TunnelError::DocumentError(msg)
            })?;

        //info!("remote ed25519 auth_key: {:?}",auth_key);
        let remote_x25519_pk = ed25519_to_curve25519::ed25519_pk_to_curve25519(exchange_key);
        //info!("remote x25519 pk: {:?}",remote_x25519_pk);

        let my_secret = EphemeralSecret::random();
        let my_public = PublicKey::from(&my_secret);
        let my_public_bytes = my_public.to_bytes();
        let my_public_hex = my_public.encode_hex();
        //info!("my_public_hex: {:?}",my_public_hex);
        let aes_key = RTcpInner::generate_aes256_key(my_secret, remote_x25519_pk);
        //info!("aes_key: {:?}",aes_key);
        //create jwt by tunnel token payload
        let tunnel_token_payload = TunnelTokenPayload {
            to: remote_did.to_host_name(),
            from: self.this_device_did.to_host_name(),
            xpub: my_public_hex,
            exp: buckyos_get_unix_timestamp() + 3600 * 2,
        };
        info!("send tunnel_token_payload: {:?}", tunnel_token_payload);
        let payload = serde_json::to_value(&tunnel_token_payload).map_err(|op| {
            TunnelError::ReasonError(format!("encode tunnel token payload error:{}", op))
        })?;

        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = None;
        header.typ = None;
        let tunnel_token = encode(
            &header,
            &payload,
            &self.this_device_ed25519_sk.as_ref().unwrap(),
        );
        if tunnel_token.is_err() {
            let err_str = tunnel_token.err().unwrap().to_string();
            return Err(TunnelError::ReasonError(err_str));
        }
        let tunnel_token = tunnel_token.unwrap();

        Ok((tunnel_token, aes_key, my_public_bytes))
    }

    fn generate_aes256_key(
        this_private_key: EphemeralSecret,
        x25519_public_key: [u8; 32],
    ) -> [u8; 32] {
        //info!("will create share sec with remote x25519 pk: {:?}",x25519_public_key);
        let x25519_public_key = x25519_dalek::PublicKey::from(x25519_public_key);
        let shared_secret = this_private_key.diffie_hellman(&x25519_public_key);

        let mut hasher = Sha256::new();
        hasher.update(shared_secret.as_bytes());
        let key_bytes = hasher.finalize();
        return key_bytes.try_into().unwrap();
        //return shared_secret.as_bytes().clone();
    }

    pub async fn decode_tunnel_token(
        this_private_key: &StaticSecret,
        token: String,
        from_hostname: String,
    ) -> Result<([u8; 32], [u8; 32]), TunnelError> {
        let from_did = DID::from_str(from_hostname.as_str());
        if from_did.is_err() {
            return Err(TunnelError::DocumentError(
                "invalid from device is not did".to_string(),
            ));
        }
        let from_did = from_did.unwrap();
        let ed25519_pk = resolve_ed25519_exchange_key(&from_did)
            .await
            .map_err(|op| {
                TunnelError::DocumentError(format!(
                    "cann't resolve from device {} auth key:{}",
                    from_hostname.as_str(),
                    op
                ))
            })?;

        let from_public_key = DecodingKey::from_ed_der(&ed25519_pk);

        let tunnel_token_payload = decode::<TunnelTokenPayload>(
            token.as_str(),
            &from_public_key,
            &Validation::new(Algorithm::EdDSA),
        );
        if tunnel_token_payload.is_err() {
            return Err(TunnelError::DocumentError(
                "decode tunnel token error".to_string(),
            ));
        }
        let tunnel_token_payload = tunnel_token_payload.unwrap();
        let tunnel_token_payload = tunnel_token_payload.claims;
        //info!("tunnel_token_payload: {:?}",tunnel_token_payload);
        let remomte_x25519_pk = hex::decode(tunnel_token_payload.xpub).unwrap();

        let remomte_x25519_pk: [u8; 32] = remomte_x25519_pk.try_into().map_err(|_op| {
            let msg = format!("decode remote x25519 hex error");
            error!("{}", msg);
            TunnelError::ReasonError(msg)
        })?;

        //info!("remomte_x25519_pk: {:?}",remomte_x25519_pk);
        let aes_key = RTcpInner::get_aes256_key(this_private_key, remomte_x25519_pk.clone());
        //info!("aes_key: {:?}",aes_key);
        Ok((aes_key, remomte_x25519_pk))
    }

    fn get_aes256_key(
        this_private_key: &StaticSecret,
        remote_x25519_auth_key: [u8; 32],
    ) -> [u8; 32] {
        //info!("will get share sec with remote x25519 temp pk: {:?}",remote_x25519_auth_key);
        let x25519_public_key = x25519_dalek::PublicKey::from(remote_x25519_auth_key);
        let shared_secret = this_private_key.diffie_hellman(&x25519_public_key);

        let mut hasher = Sha256::new();
        hasher.update(shared_secret.as_bytes());
        let key_bytes = hasher.finalize();
        return key_bytes.try_into().unwrap();
    }

    pub async fn start(self: &Arc<Self>) -> TunnelResult<JoinHandle<()>> {
        let rtcp_listener = TcpListener::bind(&self.bind_addr).await.map_err(|e| {
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
                info!(
                    "RTcp stack {} accept new stream: {}, {}",
                    self.this_device_did.to_string(),
                    addr,
                    session_key
                );
                self.on_new_stream(stream, session_key).await;
            }
            RTcpTunnelPackage::Hello(hello_package) => {
                info!(
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
        // decode hello.body.tunnel_token
        if hello_package.body.tunnel_token.is_none() {
            error!("hello.body.tunnel_token is none");
            return;
        }
        let token = hello_package.body.tunnel_token.as_ref().unwrap().clone();
        let aes_key = RTcpInner::decode_tunnel_token(
            &self.this_device_x25519_sk.as_ref().unwrap(),
            token,
            hello_package.body.from_id.clone(),
        )
            .await;
        if aes_key.is_err() {
            error!("decode tunnel token error:{}", aes_key.err().unwrap());
            return;
        }

        let (aes_key, random_pk) = aes_key.unwrap();
        let from_did = DID::from_str(hello_package.body.from_id.as_str());
        if from_did.is_err() {
            error!("parser remote did error:{}", from_did.err().unwrap());
            return;
        }
        let from_did = from_did.unwrap();
        let target = RTcpTargetStackEP::new(
            from_did,
            hello_package.body.my_port,
        );
        if target.is_err() {
            error!("parser remote did error:{}", target.err().unwrap());
            return;
        }
        let target = target.unwrap();
        let tunnel = RTcpTunnel::new(
            self.stream_helper.clone(),
            self.this_device_did.clone(),
            &target,
            false,
            stream,
            aes_key,
            random_pk,
            self.listener.clone(),
        );

        let tunnel_key = format!(
            "{}_{}",
            self.this_device_did.to_string(),
            hello_package.body.from_id.as_str()
        );
        {
            //info!("accept tunnel from {} try get lock",hello_package.body.from_id.as_str());
            self.tunnel_map
                .on_new_tunnel(&tunnel_key, tunnel.clone())
                .await;
            // info!("Accept tunnel from {}", hello_package.body.from_id.as_str());
        }

        info!(
            "Tunnel {} accept from {} OK,start running",
            hello_package.body.from_id.as_str(),
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
                "rtcp target stack id is none".to_string(),
            ));
        }
        let tunnel_stack_id = tunnel_stack_id.unwrap();
        let target = parse_rtcp_stack_id(tunnel_stack_id);
        if target.is_none() {
            return Err(TunnelError::ConnectError(format!(
                "invalid target url:{:?}",
                target
            )));
        }
        let target: RTcpTargetStackEP = target.unwrap();
        let target_id_str = target.did.to_string();

        let tunnel_key = format!(
            "{}_{}",
            self.this_device_did.to_string(),
            target_id_str.as_str()
        );
        debug!(
            "will create tunnel to {} ,tunnel key is {},try reuse",
            target_id_str.as_str(),
            tunnel_key.as_str()
        );

        // First check if the tunnel already exists, then we can reuse it
        let tunnels = self.tunnel_map.tunnel_map().clone();
        let mut all_tunnel = tunnels.lock().await;
        let tunnel = all_tunnel.get(tunnel_key.as_str());
        if tunnel.is_some() {
            debug!("Reuse tunnel {}", tunnel_key.as_str());
            return Ok(Box::new(tunnel.unwrap().clone()));
        }

        // 1） resolve target auth-key and ip (rtcp base on tcp,so need ip)

        let device_ip = resolve_ip(target_id_str.as_str()).await.map_err(|_err| {
            let msg = format!("cann't resolve target device {} ip", target_id_str);
            error!("{}", msg);
            TunnelError::DocumentError(msg)
        })?;
        let port = target.stack_port;
        let remote_addr = format!("{}:{}", device_ip, port);

        info!(
            "Will open tunnel to {}, target addr is {}",
            target_id_str.as_str(),
            remote_addr.as_str()
        );

        // connect to target
        let tunnel_stream = tokio::net::TcpStream::connect(remote_addr.clone()).await;
        if tunnel_stream.is_err() {
            warn!(
                "connect to {} error:{}",
                remote_addr,
                tunnel_stream.err().unwrap()
            );
            return Err(TunnelError::ConnectError(format!(
                "connect to {} error.",
                remote_addr
            )));
        }
        // create tunnel token
        let (tunnel_token, aes_key, random_pk) = self
            .generate_tunnel_token(target_id_str.clone())
            .await
            .map_err(|e| {
                let msg = format!("generate tunnel token error: {}, {}", target_id_str, e);
                error!("{}", msg);
                e
            })?;

        let addr: SocketAddr = self.bind_addr.parse().unwrap();
        // send hello to target
        let mut tunnel_stream = tunnel_stream.unwrap();
        let hello_package = RTcpHelloPackage::new(
            0,
            self.this_device_did.to_string(),
            target_id_str.clone(),
            addr.port(),
            Some(tunnel_token),
        );
        let send_result =
            RTcpTunnelPackage::send_package(Pin::new(&mut tunnel_stream), hello_package).await;
        if send_result.is_err() {
            warn!(
                "send hello package to {} error:{}",
                remote_addr,
                send_result.err().unwrap()
            );
            return Err(TunnelError::ConnectError(format!(
                "send hello package to {} error.",
                remote_addr
            )));
        }

        // create tunnel and add to map
        let tunnel = RTcpTunnel::new(
            self.stream_helper.clone(),
            self.this_device_did.clone(),
            &target,
            true,
            tunnel_stream,
            aes_key,
            random_pk,
            self.listener.clone(),
        );
        all_tunnel.insert(tunnel_key.clone(), tunnel.clone());
        info!(
            "create tunnel {} ok, remote addr is {}",
            tunnel_key.as_str(),
            remote_addr.as_str()
        );
        drop(all_tunnel);

        let result: TunnelResult<Box<dyn TunnelBox>> = Ok(Box::new(tunnel.clone()));
        let tunnel_map = self.tunnel_map.clone();
        task::spawn(async move {
            info!(
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
}

#[derive(Clone)]
struct RTcpTunnel {
    build_helper: RTcpStreamBuildHelper,
    target: RTcpTargetStackEP,
    can_direct: bool,
    peer_addr: SocketAddr,
    this_device: DID,
    aes_key: [u8; 32],
    write_stream: Arc<Mutex<WriteHalf<EncryptedStream<TcpStream>>>>,
    read_stream: Arc<Mutex<ReadHalf<EncryptedStream<TcpStream>>>>,

    next_seq: Arc<AtomicU32>,
    listener: RTcpListenerRef,

    // Use to notify the open stream waiter
    open_resp_notify: Arc<Mutex<HashMap<u32, Arc<Notify>>>>,
}

impl RTcpTunnel {
    pub fn new(
        build_helper: RTcpStreamBuildHelper,
        this_device: DID,
        target: &RTcpTargetStackEP,
        can_direct: bool,
        stream: TcpStream,
        aes_key: [u8; 32],
        random_pk: [u8; 32],
        listener: RTcpListenerRef,
    ) -> Self {
        let peer_addr = stream.peer_addr().unwrap();
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&random_pk[..16]);
        let encrypted_stream = EncryptedStream::new(stream, &aes_key, &iv);
        let (read_stream, write_stream) = tokio::io::split(encrypted_stream);
        //let (read_stream,write_stream) =  tokio::io::split(stream);
        let this_target = target.clone();

        //this_target.target_port = 0;
        Self {
            build_helper,
            target: this_target,
            can_direct, //Considering the limit of port mapping, the default configuration is configured as "NoDirect" mode
            peer_addr: peer_addr,
            this_device: this_device,
            aes_key: aes_key,
            read_stream: Arc::new(Mutex::new(read_stream)),
            write_stream: Arc::new(Mutex::new(write_stream)),

            next_seq: Arc::new(AtomicU32::new(0)),
            listener,
            open_resp_notify: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn close(&self) {
        //let mut read_stream = self.read_stream.lock().await;
        //let mut read_stream:OwnedReadHalf = (*read_stream);
        //read_stream.shutdown().await;
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
            RTcpTunnelPackage::ROpen(ropen_package) =>
                self.on_ropen(ropen_package).await,
            RTcpTunnelPackage::ROpenResp(_ropen_resp_package) => {
                //check result
                Ok(())
            }
            RTcpTunnelPackage::Open(open_package) =>
                self.on_open(open_package).await,
            RTcpTunnelPackage::OpenResp(open_resp_package) => {
                // Notify the open_stream waiter with the seq
                let notify = self
                    .open_resp_notify
                    .lock()
                    .await
                    .remove(&open_resp_package.seq);
                if notify.is_some() {
                    notify.unwrap().notify_one();
                } else {
                    warn!(
                        "Tunnel open stream notify not found: seq={}",
                        open_resp_package.seq
                    );
                }

                Ok(())
            }
            RTcpTunnelPackage::Pong(_pong_package) => Ok(()),
            pkg_type @ _ => {
                error!("Unsupport tunnel package type: {:?}", pkg_type);
                Ok(())
            }
        }
    }

    async fn on_ropen(&self, ropen_package: RTcpROpenPackage) -> Result<(), anyhow::Error> {
        info!(
            "RTcp tunnel ropen request: {:?}:{}, {:?}",
            ropen_package.body.dest_host, ropen_package.body.dest_port, ropen_package.body.purpose
        );


        // 1. open stream to remote and send hello stream
        let mut target_addr = self.peer_addr.clone();
        target_addr.set_port(self.target.stack_port);
        let rtcp_stream = tokio::net::TcpStream::connect(target_addr).await;
        if rtcp_stream.is_err() {
            error!(
                "open rtcp stream to remote {} error:{}",
                target_addr,
                rtcp_stream.err().unwrap()
            );
            let ropen_resp_package = RTcpROpenRespPackage::new(ropen_package.seq, 2);
            let mut write_stream = self.write_stream.lock().await;
            let write_stream = Pin::new(&mut *write_stream);
            RTcpTunnelPackage::send_package(write_stream, ropen_resp_package).await?;

            return Ok(());
        }

        // 2. send ropen_resp
        {
            let mut write_stream = self.write_stream.lock().await;
            let write_stream = Pin::new(&mut *write_stream);
            let ropen_resp_package = RTcpROpenRespPackage::new(ropen_package.seq, 0);
            RTcpTunnelPackage::send_package(write_stream, ropen_resp_package).await?;
        }

        let mut rtcp_stream = rtcp_stream.unwrap();

        // 3. send hello stream
        RTcpTunnelPackage::send_hello_stream(
            &mut rtcp_stream,
            ropen_package.body.stream_id.as_str(),
        )
            .await?;

        let remote_addr = rtcp_stream
            .peer_addr()
            .map_err(|e| anyhow::format_err!("get peer_addr error: {}", e))?;
        let local_addr = rtcp_stream
            .local_addr()
            .map_err(|e| anyhow::format_err!("get local_addr error: {}", e))?;

        let nonce_bytes: [u8; 16] = hex::decode(ropen_package.body.stream_id.as_str())
            .map_err(|op| anyhow::format_err!("decode stream_id error:{}", op))?
            .try_into()
            .map_err(|_op| anyhow::format_err!("decode stream_id error"))?;
        let aes_key = self.get_key().clone();
        let aes_stream = EncryptedStream::new(rtcp_stream, &aes_key, &nonce_bytes);

        info!(
            "RTcp stream encrypted with aes_key:{}, nonce_bytes:{}",
            hex::encode(aes_key),
            hex::encode(nonce_bytes)
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
            device_id: self.target.did.to_string(),
            port: self.target.stack_port,
        };
        self.listener
            .on_new_stream(stream, dest_host, dest_port, end_point, remote_addr, local_addr)
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
            device_id: self.target.did.to_string(),
            port: self.target.stack_port,
        };
        self.listener
            .on_new_datagram(stream, dest_host, dest_port, end_point, remote_addr, local_addr)
            .await?;
        Ok(())
    }

    async fn on_open(&self, open_package: RTcpOpenPackage) -> Result<(), anyhow::Error> {
        info!(
            "RTcp tunnel open request: {:?}:{}, {:?}",
            open_package.body.dest_host, open_package.body.dest_port, open_package.body.purpose
        );

        // 1. Prepare wait for the new stream before send open_resp
        let real_key = format!(
            "{}_{}",
            self.this_device.to_string(),
            open_package.body.stream_id
        );
        self.build_helper.new_wait_stream(&real_key).await;

        // 2. send open_resp with success
        {
            let mut write_stream = self.write_stream.lock().await;
            let write_stream = Pin::new(&mut *write_stream);
            let open_resp_package = RTcpOpenRespPackage::new(open_package.seq, 0);
            RTcpTunnelPackage::send_package(write_stream, open_resp_package).await?;
        }

        // 3. Wait for the new stream
        let stream = self.wait_ropen_stream(&open_package.body.stream_id).await?;

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
        let aes_stream = EncryptedStream::new(stream, &aes_key, &nonce_bytes);

        info!(
            "RTcp stream encrypted with aes_key:{}, nonce_bytes:{}",
            hex::encode(aes_key),
            hex::encode(nonce_bytes)
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
        let source_info = self.target.did.to_string();
        let mut read_stream = self.read_stream.lock().await;
        //let read_stream = self.read_stream.clone();
        loop {
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
        // First generate 32byte session_key
        let random_bytes: [u8; 16] = rand::rng().random();
        let session_key = hex::encode(random_bytes);
        let real_key = format!("{}_{}", self.this_device.to_string(), session_key);
        let seq = self.next_seq();

        info!(
            "RTcp tunnel open stream to {}:{}, can_direct:{}",
            dest_host.clone().unwrap_or("127.0.0.1".to_string()),
            dest_port,
            self.can_direct
        );

        if self.can_direct {
            let notify = Arc::new(Notify::new());
            self.open_resp_notify
                .lock()
                .await
                .insert(seq, notify.clone());

            // Send open to target to build a direct stream
            self.post_open(seq, purpose, dest_port, dest_host, session_key.as_str())
                .await?;

            // Must wait openresp package then we can build a direct stream
            let wait_result = timeout(Duration::from_secs(60), notify.notified()).await;
            if wait_result.is_err() {
                self.open_resp_notify.lock().await.remove(&seq); // Remove the notify if timeout
                error!(
                    "Timeout: open stream {} was not found within the time limit.",
                    real_key.as_str()
                );
                return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "Timeout"));
            }

            // Build a direct stream to target
            let mut target_addr = self.peer_addr.clone();
            target_addr.set_port(self.target.stack_port);
            let ret = tokio::net::TcpStream::connect(target_addr).await;
            if ret.is_err() {
                let e = ret.err().unwrap();
                error!(
                    "RTcp tunnel open direct stream to {}, {} error: {}",
                    target_addr,
                    self.target.did.to_string(),
                    e
                );
                return Err(e);
            }
            let mut stream = ret.unwrap();

            // Send hello stream
            RTcpTunnelPackage::send_hello_stream(&mut stream, session_key.as_str())
                .await
                .map_err(|e| {
                    let msg = format!("send hello stream error: {}, {}", target_addr, e);
                    error!("{}", msg);
                    std::io::Error::new(std::io::ErrorKind::Other, msg)
                })?;

            let aes_stream: EncryptedStream<TcpStream> =
                EncryptedStream::new(stream, &self.get_key(), &random_bytes);

            info!(
                "RTcp tunnel open direct stream to {}, {}",
                target_addr,
                self.target.did.to_string()
            );

            Ok(Box::new(aes_stream))
        } else {
            //send ropen to target

            self.build_helper.new_wait_stream(&real_key).await;

            //info!("insert session_key {} to wait ropen stream map",real_key.as_str());
            self.post_ropen(seq, purpose, dest_port, dest_host, session_key.as_str())
                .await?;

            // wait new stream with session_key from target
            let stream = self.wait_ropen_stream(&session_key.as_str()).await?;
            let aes_stream: EncryptedStream<TcpStream> =
                EncryptedStream::new(stream, &self.get_key(), &random_bytes);
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
                    return self.open_stream_by_dest(0, Some(real_stream_id.to_string())).await;
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
                    return self.create_datagram_client_by_dest(0, Some(real_stream_id.to_string())).await;
                }
            }
        }
        let (dest_host, dest_port) = get_dest_info_from_url_path(session_id)?;
        self.create_datagram_client_by_dest(dest_port, dest_host)
            .await
    }
}

#[async_trait::async_trait]
pub trait RTcpListener: 'static + Send + Sync {
    async fn on_new_stream(&self,
                           stream: Box<dyn AsyncStream>,
                           dest_host: Option<String>,
                           dest_port: u16,
                           endpoint: TunnelEndpoint,
                           remote_addr: SocketAddr,
                           local_addr: SocketAddr,) -> TunnelResult<()>;
    async fn on_new_datagram(&self,
                             stream: Box<dyn AsyncStream>,
                             dest_host: Option<String>,
                             dest_port: u16,
                             endpoint: TunnelEndpoint,
                             remote_addr: SocketAddr,
                             local_addr: SocketAddr,) -> TunnelResult<()>;
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

    pub async fn on_new_tunnel(&self, tunnel_key: &str, tunnel: RTcpTunnel) {
        let mut all_tunnel = self.tunnel_map.lock().await;
        let mut_old_tunnel = all_tunnel.get(tunnel_key);
        if mut_old_tunnel.is_some() {
            warn!("tunnel {} already exist", tunnel_key);
            mut_old_tunnel.unwrap().close().await;
        }

        all_tunnel.insert(tunnel_key.to_owned(), tunnel);
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
    use crate::rtcp::rtcp::RTcp;
    use crate::{TunnelEndpoint, TunnelResult};
    use buckyos_kit::{AsyncStream};
    use name_lib::DID;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use crate::rtcp::AsyncStreamWithDatagram;

    #[test]
    fn test_rtcp_struct_creation() {
        // 测试RTcp结构体的创建
        let did = DID::new("test", "device1");
        let listener = Arc::new(MockRTcpListener {});

        let _rtcp = RTcp::new(did.clone(), "127.0.0.1:8000".to_string(), None, listener);

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

    #[tokio::test]
    async fn test_rtcp_err() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let mut rtcp1 = RTcp::new(device_config.id, "127.0.0.1:19023".to_string(), Some(pkcs8_bytes), Arc::new(MockRTcpListener::new()));
        rtcp1.start().await.unwrap();


        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test2", serde_json::from_value(jwk).unwrap());
        let id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let mut rtcp2 = RTcp::new(device_config.id, "127.0.0.1:19024".to_string(), Some(pkcs8_bytes), Arc::new(MockRTcpListener::new()));
        rtcp2.start().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;

        {
            let _tunnel = rtcp1.create_tunnel(Some(format!("{}:19024", id2.to_host_name()).as_str())).await.unwrap();
        }
        drop(rtcp2);
        tokio::time::sleep(Duration::from_secs(2)).await;
        {
            let ret = rtcp1.create_tunnel(Some(format!("{}:19024", id2.to_host_name()).as_str())).await;
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
        update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
        add_nameinfo_cache(device_config.id.to_string().as_str(), NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap())).await.unwrap();

        let mut rtcp1 = RTcp::new(device_config.id, "127.0.0.1:19033".to_string(), Some(pkcs8_bytes), Arc::new(MockRTcpListener::new()));
        rtcp1.start().await.unwrap();


        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test2", serde_json::from_value(jwk).unwrap());
        let id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let mut rtcp2 = RTcp::new(device_config.id, "127.0.0.1:19034".to_string(), Some(pkcs8_bytes), Arc::new(MockRTcpListener::new()));
        rtcp2.start().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;

        for _ in 0..10 {
            let tunnel = rtcp1.create_tunnel(Some(format!("{}:19034", id2.to_host_name()).as_str())).await.unwrap();
            let ret = tunnel.ping().await;
            assert!(ret.is_ok());
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
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
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let mut rtcp1 = RTcp::new(device_config.id, "127.0.0.1:19053".to_string(), Some(pkcs8_bytes), Arc::new(MockRTcpListener::new()));
        rtcp1.start().await.unwrap();


        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test2", serde_json::from_value(jwk).unwrap());
        let id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let mut rtcp2 = RTcp::new(device_config.id, "127.0.0.1:19054".to_string(), Some(pkcs8_bytes), Arc::new(MockRTcpListener::new()));
        rtcp2.start().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;

        {
            let tunnel = rtcp1.create_tunnel(Some(format!("{}:19054", id2.to_host_name()).as_str())).await.unwrap();
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
            let tunnel = rtcp2.create_tunnel(Some(format!("{}:19053", id1.to_host_name()).as_str())).await.unwrap();
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
    async fn test_rtcp_datagram() {
        let _ = init_name_lib_for_test(&HashMap::new()).await.unwrap();
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let mut rtcp1 = RTcp::new(device_config.id, "127.0.0.1:19043".to_string(), Some(pkcs8_bytes), Arc::new(MockRTcpListener::new()));
        rtcp1.start().await.unwrap();


        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test2", serde_json::from_value(jwk).unwrap());
        let id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let mut rtcp2 = RTcp::new(device_config.id, "127.0.0.1:19044".to_string(), Some(pkcs8_bytes), Arc::new(MockRTcpListener::new()));
        rtcp2.start().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;

        {
            let tunnel = rtcp1.create_tunnel(Some(format!("{}:19044", id2.to_host_name()).as_str())).await.unwrap();
            let stream = tunnel.create_datagram_client("www.baidu.com:80").await.unwrap();
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
            let tunnel = rtcp2.create_tunnel(Some(format!("{}:19043", id1.to_host_name()).as_str())).await.unwrap();
            let stream = tunnel.create_datagram_client("www.baidu.com:80").await.unwrap();
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
