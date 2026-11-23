use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::{Result, anyhow};
use cyfs_acme::{AcmeCertManager, AcmeCertState, ChallengeType};
use cyfs_gateway_app_lib::{
    GatewayConfig, GatewayRuntimeServiceContext, GatewayRuntimeServiceHandle,
};
use cyfs_gateway_lib::{StackManager, TlsHostCertificate};
use cyfs_sn::OODInfo;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::task::JoinHandle;

use crate::acme_sn_provider::AcmdSnProviderConfig;
use crate::sn_device::SnDeviceClient;

const SN_DNS_PROVIDER: &str = "sn-dns";
const STATE_FILE: &str = "self_cert_state.json";
const FIRST_CHECK_DELAY: Duration = Duration::from_secs(30);
const CHECK_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
struct CertStateItem {
    did: String,
    domain: String,
    state: bool,
}

/// Host -> fingerprint of the certificates in use and valid now.
type LoadedCerts = Box<dyn Fn() -> HashMap<String, String> + Send + Sync>;

#[derive(Clone, Debug, PartialEq)]
struct ReportConfig {
    sn: String,
    key_path: String,
    device_config_path: String,
    access_token: Option<String>,
    hosts: Vec<String>,
    /// Report only when every host has its certificate.
    all_hosts: bool,
}

/// `self_cert_report`, or what the `sn-dns` ACME provider implies without it.
fn report_config(config: &GatewayConfig) -> Option<ReportConfig> {
    if let Some(report) = config.self_cert_report.as_ref() {
        return Some(ReportConfig {
            sn: report.sn.clone(),
            key_path: report.key_path.clone(),
            device_config_path: report.device_config_path.clone(),
            access_token: None,
            hosts: report
                .hosts
                .iter()
                .map(|host| host.trim().to_lowercase())
                .collect(),
            all_hosts: true,
        });
    }
    let acme = config.acme_config.as_ref()?;
    let params = acme.dns_providers.as_ref()?.get(SN_DNS_PROVIDER)?;
    let provider: AcmdSnProviderConfig = serde_json::from_value(params.clone()).ok()?;
    let mut hosts = Vec::new();
    for host in &acme.hosts {
        if host.challenge_type != Some(ChallengeType::Dns01)
            || host.dns_provider.as_deref() != Some(SN_DNS_PROVIDER)
        {
            continue;
        }
        let name = host.host.trim();
        let wildcard = format!("*.{}", name.strip_prefix("*.").unwrap_or(name));
        if !hosts.contains(&wildcard) {
            hosts.push(wildcard);
        }
    }
    (!hosts.is_empty()).then_some(ReportConfig {
        sn: provider.sn,
        key_path: provider.key_path,
        device_config_path: provider.device_config_path?,
        access_token: provider.access_token,
        hosts,
        all_hosts: false,
    })
}

fn valid_fingerprints(certificates: Vec<TlsHostCertificate>, now: u64) -> HashMap<String, String> {
    certificates
        .into_iter()
        .filter_map(|certificate| {
            let loaded = certificate.loaded?;
            (loaded.not_before <= now && now < loaded.not_after)
                .then_some((certificate.host, loaded.fingerprint))
        })
        .collect()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn tls_stack_certs(stack_manager: Weak<StackManager>) -> LoadedCerts {
    Box::new(move || {
        stack_manager
            .upgrade()
            .map(|manager| valid_fingerprints(manager.tls_host_certificates(), unix_now()))
            .unwrap_or_default()
    })
}

fn acme_certs(acme_manager: Weak<AcmeCertManager>) -> LoadedCerts {
    Box::new(move || {
        let now = unix_now();
        acme_manager
            .upgrade()
            .map(|manager| manager.cert_statuses())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|status| {
                let usable = matches!(
                    status.state,
                    AcmeCertState::Ready | AcmeCertState::Renewing | AcmeCertState::Manual
                );
                let cert = status
                    .installed
                    .filter(|cert| usable && cert.not_before <= now && now < cert.not_after)?;
                Some((status.host, cert.fingerprint))
            })
            .collect()
    })
}

/// Starts the report of this configuration, if there is one to make.
pub(crate) fn start_self_cert_report(
    context: &GatewayRuntimeServiceContext<'_>,
    data_path: PathBuf,
) -> Option<GatewayRuntimeServiceHandle> {
    let config = report_config(context.config)?;
    let loaded = if config.all_hosts {
        tls_stack_certs(Arc::downgrade(context.stack_manager))
    } else {
        acme_certs(Arc::downgrade(context.acme_manager))
    };
    let handle = tokio::spawn(run_report(config, data_path, loaded));
    Some(Box::new(AbortOnDrop(handle)))
}

struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn run_report(config: ReportConfig, data_path: PathBuf, loaded: LoadedCerts) {
    tokio::time::sleep(FIRST_CHECK_DELAY).await;
    let mut reporter = None;
    loop {
        let result = check_once(&config, &data_path, &loaded, &mut reporter).await;
        if let Err(e) = result {
            log::error!("report self_cert failed: {:#}", e);
        }
        tokio::time::sleep(CHECK_INTERVAL).await;
    }
}

async fn check_once(
    config: &ReportConfig,
    data_path: &std::path::Path,
    loaded: &LoadedCerts,
    reporter: &mut Option<Reporter<SnDeviceClient>>,
) -> Result<()> {
    let reporter = match reporter {
        Some(reporter) => reporter,
        None => {
            let client = SnDeviceClient::load(
                &config.sn,
                &config.key_path,
                &config.device_config_path,
                config.access_token.clone(),
            )
            .await?;
            let did = client.did();
            let state = ReportState::load(data_path.to_path_buf(), did, &config.hosts).await?;
            reporter.insert(Reporter {
                sn: client,
                state,
                hosts: config.hosts.clone(),
                all_hosts: config.all_hosts,
                reported: HashMap::new(),
            })
        }
    };
    reporter.check(loaded()).await
}

#[async_trait::async_trait]
trait SelfCertTarget: Send + Sync {
    async fn set_self_cert(&self) -> Result<()>;
}

#[async_trait::async_trait]
impl SelfCertTarget for SnDeviceClient {
    async fn set_self_cert(&self) -> Result<()> {
        let deviceinfo_krpc = self.krpc_for_route("/kapi/sn/deviceinfo")?;
        let result = deviceinfo_krpc
            .call(
                "deviceinfo.resolve_ood_by_did",
                json!({
                    "source_device_id": self.did()
                }),
            )
            .await
            .map_err(|e| anyhow!("resolve_ood_by_did failed.{:?}", e))?;
        let _ood_info = serde_json::from_value::<OODInfo>(result)
            .map_err(|_| anyhow!("parse resolve_ood_by_did result failed"))?;

        let auth_krpc = self.krpc_for_route("/kapi/sn/auth")?;
        auth_krpc
            .call(
                "user.set_self_cert",
                json!({
                    "self_cert": true,
                    "device_did": self.did()
                }),
            )
            .await
            .map_err(|e| anyhow!("set_user_self_cert failed.{:?}", e))?;
        Ok(())
    }
}

struct Reporter<T> {
    sn: T,
    state: ReportState,
    hosts: Vec<String>,
    all_hosts: bool,
    /// Host -> fingerprint the SN knows about, as far as this process has seen.
    reported: HashMap<String, String>,
}

impl<T: SelfCertTarget> Reporter<T> {
    async fn check(&mut self, loaded: HashMap<String, String>) -> Result<()> {
        let ready = self
            .hosts
            .iter()
            .filter_map(|host| Some((host.clone(), loaded.get(host)?.clone())))
            .collect::<HashMap<_, _>>();
        if ready.is_empty() || (self.all_hosts && ready.len() < self.hosts.len()) {
            return Ok(());
        }
        let pending = ready.keys().any(|host| !self.state.is_set(host));
        let renewed = ready.iter().any(|(host, fingerprint)| {
            self.reported
                .get(host)
                .is_some_and(|known| known != fingerprint)
        });
        if pending || renewed {
            self.sn.set_self_cert().await?;
            self.state.set_all().await?;
        }
        self.reported = ready;
        Ok(())
    }
}

/// `self_cert_state.json`, shown by the control panel.
struct ReportState {
    data_path: PathBuf,
    did: String,
    items: Vec<CertStateItem>,
}

impl ReportState {
    async fn load(data_path: PathBuf, did: String, hosts: &[String]) -> Result<Self> {
        let path = data_path.join(STATE_FILE);
        let stored: Vec<CertStateItem> = match tokio::fs::read_to_string(&path).await {
            Ok(content) => serde_json::from_str(&content).unwrap_or_else(|e| {
                log::warn!("parse {} failed, start over: {}", path.display(), e);
                Vec::new()
            }),
            Err(_) => Vec::new(),
        };

        let mut items: Vec<CertStateItem> = Vec::new();
        for item in &stored {
            // Another device had this host before.
            if item.did != did && hosts.contains(&item.domain) {
                continue;
            }
            match items
                .iter_mut()
                .find(|known| known.did == item.did && known.domain == item.domain)
            {
                Some(known) => known.state |= item.state,
                None => items.push(item.clone()),
            }
        }
        let known = items
            .iter()
            .filter(|item| item.did == did)
            .map(|item| item.domain.clone())
            .collect::<HashSet<_>>();
        for host in hosts {
            if !known.contains(host) {
                items.push(CertStateItem {
                    did: did.clone(),
                    domain: host.clone(),
                    state: false,
                });
            }
        }
        let state = Self {
            data_path,
            did,
            items,
        };
        if state.items != stored {
            state.save().await?;
        }
        Ok(state)
    }

    fn is_set(&self, host: &str) -> bool {
        self.items
            .iter()
            .any(|item| item.did == self.did && item.domain == host && item.state)
    }

    async fn set_all(&mut self) -> Result<()> {
        for item in self.items.iter_mut() {
            if item.did == self.did {
                item.state = true;
            }
        }
        self.save().await
    }

    async fn save(&self) -> Result<()> {
        let path = self.data_path.join(STATE_FILE);
        tokio::fs::create_dir_all(&self.data_path)
            .await
            .map_err(|e| anyhow!("create {} failed: {}", self.data_path.display(), e))?;
        tokio::fs::write(&path, serde_json::to_string(&self.items)?)
            .await
            .map_err(|e| anyhow!("save {} failed: {}", path.display(), e))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cyfs_gateway_app_lib::{
        CoreGatewayModule, GatewayAppProfile, GatewayCompositionBuilder, GatewayConfigParser,
    };
    use cyfs_identity_cert::CertificateSummary;
    use name_lib::{DID, DeviceDocument, generate_ed25519_key_pair};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    const DID_A: &str = "did:dev:a";

    #[derive(Default)]
    struct FakeSn {
        calls: AtomicUsize,
        refuse: AtomicBool,
    }

    #[async_trait::async_trait]
    impl SelfCertTarget for Arc<FakeSn> {
        async fn set_self_cert(&self) -> Result<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.refuse.load(Ordering::SeqCst) {
                return Err(anyhow!("device is not registered"));
            }
            Ok(())
        }
    }

    fn hosts(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    fn certs(entries: &[(&str, &str)]) -> HashMap<String, String> {
        entries
            .iter()
            .map(|(host, fingerprint)| (host.to_string(), fingerprint.to_string()))
            .collect()
    }

    async fn reporter(
        dir: &std::path::Path,
        names: &[&str],
        all_hosts: bool,
    ) -> (Reporter<Arc<FakeSn>>, Arc<FakeSn>) {
        let sn = Arc::new(FakeSn::default());
        let reporter = Reporter {
            sn: sn.clone(),
            state: ReportState::load(dir.to_path_buf(), DID_A.to_string(), &hosts(names))
                .await
                .unwrap(),
            hosts: hosts(names),
            all_hosts,
            reported: HashMap::new(),
        };
        (reporter, sn)
    }

    fn stored(dir: &std::path::Path) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(dir.join(STATE_FILE)).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn reports_once_when_every_host_is_loaded() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("sn_dns");
        let (mut report, sn) = reporter(&dir, &["*.d.example", "d.example"], true).await;
        assert_eq!(
            stored(&dir),
            json!([
                { "did": DID_A, "domain": "*.d.example", "state": false },
                { "did": DID_A, "domain": "d.example", "state": false }
            ])
        );

        report.check(certs(&[])).await.unwrap();
        report.check(certs(&[("*.d.example", "1")])).await.unwrap();
        report
            .check(certs(&[("*.d.example", "1"), ("other.example", "1")]))
            .await
            .unwrap();
        assert_eq!(sn.calls.load(Ordering::SeqCst), 0);

        let both = certs(&[("*.d.example", "1"), ("d.example", "2")]);
        report.check(both.clone()).await.unwrap();
        report.check(both.clone()).await.unwrap();
        assert_eq!(sn.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            stored(&dir),
            json!([
                { "did": DID_A, "domain": "*.d.example", "state": true },
                { "did": DID_A, "domain": "d.example", "state": true }
            ])
        );

        // After a restart nothing is repeated, a renewed certificate is.
        let (mut report, sn) = reporter(&dir, &["*.d.example", "d.example"], true).await;
        report.check(both).await.unwrap();
        assert_eq!(sn.calls.load(Ordering::SeqCst), 0);
        let renewed = certs(&[("*.d.example", "3"), ("d.example", "2")]);
        report.check(renewed.clone()).await.unwrap();
        report.check(renewed).await.unwrap();
        assert_eq!(sn.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_refused_report_is_repeated() {
        let temp = tempfile::tempdir().unwrap();
        let (mut report, sn) = reporter(temp.path(), &["d.example"], true).await;
        sn.refuse.store(true, Ordering::SeqCst);
        let loaded = certs(&[("d.example", "1")]);
        assert!(report.check(loaded.clone()).await.is_err());
        assert_eq!(stored(temp.path())[0]["state"], false);
        sn.refuse.store(false, Ordering::SeqCst);
        report.check(loaded).await.unwrap();
        assert_eq!(sn.calls.load(Ordering::SeqCst), 2);
        assert_eq!(stored(temp.path())[0]["state"], true);
    }

    #[tokio::test]
    async fn without_a_report_section_one_host_is_enough() {
        let temp = tempfile::tempdir().unwrap();
        let (mut report, sn) = reporter(temp.path(), &["*.a.example", "*.b.example"], false).await;
        report.check(certs(&[("*.b.example", "1")])).await.unwrap();
        assert_eq!(sn.calls.load(Ordering::SeqCst), 1);
        report
            .check(certs(&[("*.a.example", "2"), ("*.b.example", "1")]))
            .await
            .unwrap();
        assert_eq!(sn.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn former_state_is_cleaned_up() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join(STATE_FILE),
            json!([
                { "did": "did:dev:old", "domain": "*.d.example", "state": true },
                { "did": "did:dev:old", "domain": "*.else.example", "state": true },
                { "did": DID_A, "domain": "*.d.example", "state": true },
                { "did": DID_A, "domain": "*.d.example", "state": false }
            ])
            .to_string(),
        )
        .unwrap();
        let (report, _) = reporter(temp.path(), &["*.d.example", "d.example"], true).await;
        assert!(report.state.is_set("*.d.example"));
        assert!(!report.state.is_set("d.example"));
        assert_eq!(
            stored(temp.path()),
            json!([
                { "did": "did:dev:old", "domain": "*.else.example", "state": true },
                { "did": DID_A, "domain": "*.d.example", "state": true },
                { "did": DID_A, "domain": "d.example", "state": false }
            ])
        );
        std::fs::write(temp.path().join(STATE_FILE), "broken").unwrap();
        let (report, _) = reporter(temp.path(), &["d.example"], true).await;
        assert_eq!(report.state.items.len(), 1);
    }

    #[test]
    fn expired_and_missing_certificates_do_not_count() {
        let certificate = |host: &str, not_before, not_after| TlsHostCertificate {
            host: host.to_string(),
            loaded: Some(CertificateSummary {
                not_before,
                not_after,
                issuer: String::new(),
                dns_names: vec![],
                fingerprint: "sha256:1".to_string(),
            }),
            manager: None,
        };
        let loaded = valid_fingerprints(
            vec![
                certificate("valid.example", 10, 30),
                certificate("expired.example", 10, 20),
                certificate("future.example", 21, 30),
                TlsHostCertificate {
                    host: "missing.example".to_string(),
                    loaded: None,
                    manager: None,
                },
            ],
            20,
        );
        assert_eq!(loaded, certs(&[("valid.example", "sha256:1")]));
    }

    fn parse(config: serde_json::Value) -> GatewayConfig {
        let mut builder = GatewayCompositionBuilder::new(GatewayAppProfile::cyfs_gateway());
        builder.install(CoreGatewayModule::new()).unwrap();
        GatewayConfigParser::new(Arc::new(builder.build().unwrap()))
            .parse(config)
            .unwrap()
    }

    #[test]
    fn config_comes_from_the_section_or_from_sn_dns() {
        let acme = json!({
            "dns_providers": { "sn-dns": {
                "sn": "https://sn.example/kapi/sn", "key_path": "key",
                "device_config_path": "did.json", "access_token": "token"
            }},
            "hosts": [
                { "host": "*.d.example", "challenge_type": "dns-01", "dns_provider": "sn-dns" },
                { "host": "d.example", "challenge_type": "dns-01", "dns_provider": "sn-dns" },
                { "host": "e.example", "challenge_type": "dns-01", "dns_provider": "sn-dns" },
                { "host": "f.example", "challenge_type": "dns-01", "dns_provider": "local" },
                { "host": "g.example", "challenge_type": "http-01" }
            ]
        });
        assert_eq!(
            report_config(&parse(json!({ "acme": acme }))),
            Some(ReportConfig {
                sn: "https://sn.example/kapi/sn".to_string(),
                key_path: "key".to_string(),
                device_config_path: "did.json".to_string(),
                access_token: Some("token".to_string()),
                hosts: hosts(&["*.d.example", "*.e.example"]),
                all_hosts: false,
            })
        );
        let section = json!({
            "sn": "https://sn2.example/kapi/sn", "key_path": "key2",
            "device_config_path": "did2.json", "hosts": ["*.d.example", "d.example"]
        });
        let expected = Some(ReportConfig {
            sn: "https://sn2.example/kapi/sn".to_string(),
            key_path: "key2".to_string(),
            device_config_path: "did2.json".to_string(),
            access_token: None,
            hosts: hosts(&["*.d.example", "d.example"]),
            all_hosts: true,
        });
        assert_eq!(
            report_config(&parse(json!({ "acme": acme, "self_cert_report": section }))),
            expected
        );
        assert_eq!(
            report_config(&parse(json!({ "self_cert_report": section }))),
            expected
        );
        assert_eq!(report_config(&parse(json!({}))), None);
        assert_eq!(
            report_config(&parse(json!({ "acme": { "hosts": [] } }))),
            None
        );
    }

    /// Answers the two kRPC calls and records them.
    async fn mock_sn(log: Arc<Mutex<Vec<(String, serde_json::Value)>>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                let path = line.split_whitespace().nth(1).unwrap().to_string();
                let mut length = 0;
                loop {
                    line.clear();
                    stream.read_line(&mut line).await.unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            length = value.trim().parse().unwrap();
                        }
                    }
                }
                let mut body = vec![0; length];
                stream.read_exact(&mut body).await.unwrap();
                let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
                let result = if request["method"] == "deviceinfo.resolve_ood_by_did" {
                    json!({
                        "did_hostname": "ood1.d.example", "owner_id": "alice",
                        "self_cert": false, "state": "active"
                    })
                } else {
                    json!({ "code": 0 })
                };
                let body = json!({ "result": result, "sys": [request["sys"][0]] }).to_string();
                log.lock().unwrap().push((path, request));
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream
                    .get_mut()
                    .write_all(response.as_bytes())
                    .await
                    .unwrap();
            }
        });
        url
    }

    #[tokio::test]
    async fn the_sn_is_told_with_the_existing_calls() {
        let temp = tempfile::tempdir().unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let url = mock_sn(log.clone()).await;
        let (private_key, public_jwk) = generate_ed25519_key_pair();
        let key_path = temp.path().join("key.pem");
        let device_path = temp.path().join("did.json");
        std::fs::write(&key_path, private_key).unwrap();
        let mut device =
            DeviceDocument::new_by_jwk("ood1", serde_json::from_value(public_jwk).unwrap());
        device.id = DID::new("web", "ood1.d.example");
        std::fs::write(&device_path, serde_json::to_vec(&device).unwrap()).unwrap();
        let mut config = ReportConfig {
            sn: format!("{url}/kapi/sn"),
            key_path: key_path.to_string_lossy().to_string(),
            device_config_path: "missing".to_string(),
            access_token: None,
            hosts: hosts(&["d.example"]),
            all_hosts: true,
        };
        let loaded: LoadedCerts = Box::new(|| certs(&[("d.example", "1")]));
        let data_path = temp.path().join("sn_dns");
        let mut reporter = None;
        assert!(
            check_once(&config, &data_path, &loaded, &mut reporter)
                .await
                .is_err()
        );
        config.device_config_path = device_path.to_string_lossy().to_string();
        for _ in 0..2 {
            check_once(&config, &data_path, &loaded, &mut reporter)
                .await
                .unwrap();
        }

        let log = log.lock().unwrap();
        let did = reporter.unwrap().state.did;
        assert_eq!(
            log.iter()
                .map(|(path, request)| (
                    path.as_str(),
                    request["method"].as_str().unwrap(),
                    request["params"].clone()
                ))
                .collect::<Vec<_>>(),
            vec![
                (
                    "/kapi/sn/deviceinfo",
                    "deviceinfo.resolve_ood_by_did",
                    json!({ "source_device_id": did })
                ),
                (
                    "/kapi/sn/auth",
                    "user.set_self_cert",
                    json!({ "self_cert": true, "device_did": did })
                ),
            ]
        );
    }
}
