use std::fmt::Debug;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use crate::{config_err, into_config_err, ConfigErrorCode, ConfigResult, PrivateKeyDer, PrivatePkcs8KeyDer};


pub struct SelfCertConfig {
    pub ca_path: Option<String>,
    pub key_path: Option<String>,
    pub store_path: String,
}

impl Default for SelfCertConfig {
    fn default() -> SelfCertConfig {
        SelfCertConfig {
            ca_path: None,
            key_path: None,
            store_path: "".to_string(),
        }
    }
}

pub struct SelfCertMgr {
    issuer: RwLock<Option<(Arc<Issuer<'static, KeyPair>>, String)>>,
    store_path: PathBuf,
    cert_cache: mini_moka::sync::Cache<String, Arc<CertifiedKey>>,
}

pub struct SelfCertMgrHolder {
    mgr: RwLock<Arc<SelfCertMgr>>,
}

impl Debug for SelfCertMgrHolder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelfCertConfig")
            .finish()
    }
}

impl SelfCertMgrHolder {
    pub fn new(mgr: SelfCertMgr) -> SelfCertMgrHolder {
        SelfCertMgrHolder {
            mgr: RwLock::new(Arc::new(mgr)),
        }
    }

    pub async fn update(&self, config: SelfCertConfig) -> ConfigResult<()> {
        let mgr = SelfCertMgr::create(config).await?;
        *self.mgr.write().unwrap() = mgr.get();
        Ok(())
    }

    pub fn get(&self) -> Arc<SelfCertMgr> {
        self.mgr.read().unwrap().clone()
    }
}

impl ResolvesServerCert for SelfCertMgrHolder {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.get().resolve(client_hello)
    }
}

// 添加从证书中获取证书指纹的代码
fn get_cert_fingerprint(pem: &str) -> Option<String> {
    for cert_der in rustls_pemfile::certs(&mut Cursor::new(pem.as_bytes())) {
        if cert_der.is_err() {
            continue;
        }
        let cert_der = cert_der.unwrap();
        use ring::digest;
        let digest = digest::digest(&digest::SHA256, cert_der.as_ref());
        let hex_bytes = digest.as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join("");
        return Some(hex_bytes);
    }
    None
}

pub type SelfCertMgrRef = Arc<SelfCertMgrHolder>;

impl Debug for SelfCertMgr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelfCertConfig")
            .finish()
    }
}

impl SelfCertMgr {
    pub async fn create(config: SelfCertConfig) -> ConfigResult<SelfCertMgrRef> {
        let store_path = Path::new(config.store_path.as_str());
        if !store_path.exists() {
            tokio::fs::create_dir_all(store_path).await
                .map_err(into_config_err!(ConfigErrorCode::InvalidConfig, "create path {:?}", store_path))?;
        }
        let issuer = if config.ca_path.is_some() && config.key_path.is_some() {
            let ca = tokio::fs::read_to_string(config.ca_path.as_ref().unwrap()).await
                .map_err(into_config_err!(ConfigErrorCode::InvalidConfig, "load ca {}", config.ca_path.as_ref().unwrap()))?;
            let key = tokio::fs::read_to_string(config.key_path.as_ref().unwrap()).await
                .map_err(into_config_err!(ConfigErrorCode::InvalidConfig, "load key {}", config.key_path.as_ref().unwrap()))?;
            let key_pair = KeyPair::from_pem(key.as_str())
                .map_err(into_config_err!(ConfigErrorCode::InvalidConfig, "parse key {}", config.key_path.as_ref().unwrap()))?;
            let issuer = Issuer::from_ca_cert_pem(ca.as_str(), key_pair)
                .map_err(into_config_err!(ConfigErrorCode::InvalidConfig, "parse ca {}", config.key_path.as_ref().unwrap()))?;
            let cert_fingerprint = get_cert_fingerprint(ca.as_str());
            if cert_fingerprint.is_none() {
                None
            } else {
                Some((Arc::new(issuer), cert_fingerprint.unwrap()))
            }
        } else {
            let cert_path = store_path.join("ca.crt");
            let key_path = store_path.join("ca.key");
            if !cert_path.exists() || !key_path.exists() {
                None
            } else {
                let ca = tokio::fs::read_to_string(cert_path.to_string_lossy().to_string().as_str()).await
                    .map_err(into_config_err!(ConfigErrorCode::InvalidConfig, "load ca {:?}", cert_path))?;
                let key = tokio::fs::read_to_string(key_path.to_string_lossy().to_string().as_str()).await
                    .map_err(into_config_err!(ConfigErrorCode::InvalidConfig, "load key {:?}", key_path))?;
                let key_pair = KeyPair::from_pem(key.as_str())
                    .map_err(into_config_err!(ConfigErrorCode::InvalidConfig, "parse key {:?}", cert_path))?;
                let issuer = Issuer::from_ca_cert_pem(ca.as_str(), key_pair)
                    .map_err(into_config_err!(ConfigErrorCode::InvalidConfig, "parse ca {:?}", key_path))?;
                let cert_fingerprint = get_cert_fingerprint(ca.as_str());
                if cert_fingerprint.is_none() {
                    None
                } else {
                    Some((Arc::new(issuer), cert_fingerprint.unwrap()))
                }
            }
        };

        Ok(Arc::new(SelfCertMgrHolder::new(SelfCertMgr {
            issuer: RwLock::new(issuer),
            store_path: store_path.to_path_buf(),
            cert_cache: mini_moka::sync::CacheBuilder::new(1024)
                .time_to_idle(Duration::from_secs(600)).build(),
        })))
    }

    fn gen_ca(cert_path: &Path, key_path: &Path) -> ConfigResult<(Issuer<'static, KeyPair>, String)> {
        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.distinguished_name.push(rcgen::DnType::CommonName, "Buckyos CA");
        params.distinguished_name.push(rcgen::DnType::OrganizationName, "Buckyos");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature,
                                 rcgen::KeyUsagePurpose::KeyCertSign,
                                 rcgen::KeyUsagePurpose::CrlSign];
        // 3. 生成证书（自签名）
        let cert = params.self_signed(&key_pair)
            .map_err(into_config_err!(ConfigErrorCode::InvalidConfig, "gen ca"))?;
        // 4. 获取 PEM 格式的证书和私钥
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();
        // 5. 保存到文件（可选）
        std::fs::write(cert_path, &cert_pem)
            .map_err(into_config_err!(ConfigErrorCode::InvalidConfig, "write cert {:?}", cert_path))?;
        std::fs::write(key_path, &key_pem)
            .map_err(into_config_err!(ConfigErrorCode::InvalidConfig, "write key {:?}", key_path))?;
        let issuer = Issuer::from_ca_cert_pem(cert_pem.as_str(), key_pair)
            .map_err(into_config_err!(ConfigErrorCode::InvalidConfig, "load ca"))?;
        let cert_fingerprint = get_cert_fingerprint(cert_pem.as_str()).unwrap();
        Ok((issuer, cert_fingerprint))
    }

    fn get_issuer(&self) -> ConfigResult<(Arc<Issuer<'static, KeyPair>>, String)> {
        {
            let issuer = self.issuer.read().unwrap();
            if issuer.is_some() {
                return Ok(issuer.clone().unwrap());
            }
        }
        let (issuer, fingerprint) = Self::gen_ca(self.store_path.join("ca.crt").as_path(), self.store_path.join("ca.key").as_path())?;
        let issuer = Arc::new(issuer);
        *self.issuer.write().unwrap() = Some((issuer.clone(), fingerprint.clone()));
        Ok((issuer, fingerprint))
    }

    fn gen_file_name(domain_name: &str) -> &str {
        if domain_name.starts_with("*.") {
            &domain_name[1..]
        } else {
            domain_name
        }
    }
    fn gen_cert(&self, domain_name: &str) -> ConfigResult<Arc<CertifiedKey>> {
        let key_pair = KeyPair::generate().unwrap();

        let mut params = CertificateParams::default();
        params.distinguished_name.push(rcgen::DnType::CommonName, domain_name);

        params.subject_alt_names = vec![rcgen::SanType::DnsName(domain_name.try_into().map_err(into_config_err!(ConfigErrorCode::InvalidConfig, "invalid domain name: {}", domain_name))?)];

        let (issuer, fingerprint) = self.get_issuer()?;
        let cert = params.signed_by(&key_pair, issuer.as_ref())
            .map_err(into_config_err!(ConfigErrorCode::InvalidConfig, "sign cert"))?;

        // 获取PEM格式的证书和私钥
        let cert_pem = cert.pem().as_bytes().to_vec();
        let key_pem = key_pair.serialize_pem().as_bytes().to_vec();

        let store_path = self.store_path.join(fingerprint.as_str());
        if !store_path.exists() {
            std::fs::create_dir_all(store_path.as_path())
                .map_err(into_config_err!(ConfigErrorCode::InvalidConfig, "create dir {:?}", store_path))?;
        }
        let cert_path = store_path.join(format!("{}.crt", Self::gen_file_name(domain_name)));
        let key_path = store_path.join(format!("{}.key", Self::gen_file_name(domain_name)));

        std::fs::write(cert_path.as_path(), &cert_pem)
            .map_err(into_config_err!(ConfigErrorCode::InvalidConfig, "write cert {:?}", cert_path))?;
        std::fs::write(key_path.as_path(), &key_pem)
            .map_err(into_config_err!(ConfigErrorCode::InvalidConfig, "write key {:?}", key_path))?;

        let mut certs = Vec::new();
        for cert in rustls_pemfile::certs(&mut Cursor::new(cert_pem)) {
            certs.push(cert.map_err(into_config_err!(ConfigErrorCode::InvalidConfig, "load cert {:?}", cert_path))?);
        }

        let mut keys = Vec::new();
        for key in rustls_pemfile::pkcs8_private_keys(&mut Cursor::new(key_pem)) {
            keys.push(key.map_err(into_config_err!(ConfigErrorCode::InvalidConfig, "load key {:?}", key_path))?);
        }

        if keys.is_empty() {
            return Err(config_err!(ConfigErrorCode::InvalidConfig, "no key found in {:?}", key_path));
        }

        let crypto_provider = rustls::crypto::ring::default_provider();
        let key = Arc::new(CertifiedKey::from_der(certs, PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            keys.into_iter().next().unwrap(),
        )), &crypto_provider).map_err(into_config_err!(ConfigErrorCode::InvalidConfig, "create certified key"))?);
        self.cert_cache.insert(domain_name.to_string(), key.clone());
        Ok(key)
    }

    fn get_or_create_cert(&self, domain_name: String) -> ConfigResult<Arc<CertifiedKey>> {
        if let Some(cert) = self.cert_cache.get(&domain_name) {
            return Ok(cert);
        }

        let (_, fingerprint) = self.get_issuer()?;
        let store_path = self.store_path.join(fingerprint.as_str());
        let cert_path = store_path.join(format!("{}.crt", Self::gen_file_name(domain_name.as_str())));
        let key_path = store_path.join(format!("{}.key", Self::gen_file_name(domain_name.as_str())));

        if cert_path.exists() && key_path.exists() {
            let cert = std::fs::read(cert_path.to_string_lossy().to_string().as_str())
                .map_err(into_config_err!(ConfigErrorCode::InvalidConfig, "load cert {:?}", cert_path))?;
            let key = std::fs::read(key_path.to_string_lossy().to_string().as_str())
                .map_err(into_config_err!(ConfigErrorCode::InvalidConfig, "load key {:?}", key_path))?;

            let mut certs = Vec::new();
            for cert in rustls_pemfile::certs(&mut Cursor::new(cert)) {
                certs.push(cert.map_err(into_config_err!(ConfigErrorCode::InvalidConfig, "load cert {:?}", cert_path))?);
            }

            let mut keys = Vec::new();
            for key in rustls_pemfile::pkcs8_private_keys(&mut Cursor::new(key)) {
                keys.push(key.map_err(into_config_err!(ConfigErrorCode::InvalidConfig, "load key {:?}", key_path))?);
            }

            if keys.is_empty() {
                return Err(config_err!(ConfigErrorCode::InvalidConfig, "no key found in {:?}", key_path));
            }

            let crypto_provider = rustls::crypto::ring::default_provider();
            let key = Arc::new(CertifiedKey::from_der(certs, PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                keys.into_iter().next().unwrap()
            )), &crypto_provider).map_err(into_config_err!(ConfigErrorCode::InvalidConfig, "create certified key"))?);
            self.cert_cache.insert(domain_name, key.clone());
            Ok(key)
        } else {
            self.gen_cert(domain_name.as_str())
        }
    }

    pub fn get_cert(&self, server_name: &str) -> Option<Arc<CertifiedKey>> {
        let parts: Vec<&str> = server_name.split('.').collect();
        let parts_len = parts.len();
        let domain = if parts_len >= 3 {
            let wildcard_domain = format!("*.{}", parts[parts_len - 2..].join("."));
            wildcard_domain
        } else {
            server_name.to_string()
        };

        match self.get_or_create_cert(domain) {
            Ok(cert) => {
                Some(cert)
            },
            Err(e) => {
                log::error!("resolve self cert {} failed {}", server_name, e);
                None
            }
        }
    }
}

impl ResolvesServerCert for SelfCertMgr {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let server_name = client_hello.server_name().unwrap_or("").to_string();
        self.get_cert(server_name.as_str())
    }
}