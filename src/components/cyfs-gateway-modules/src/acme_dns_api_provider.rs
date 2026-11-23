use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use anyhow::{Result, anyhow};
use cyfs_acme::{AcmeCertManager, DnsProvider, DnsProviderFactory, DnsProviderRef};
use cyfs_dns_provider::{
    DnsCredential, DnsLookupResult, DnsProviderResult, DnsRecordProviderRef, RecordType,
    SystemDnsLookup, ZoneApex, create_provider, find_zone_apex, load_credential, provider_info,
    wait_txt_visible,
};
use serde::Deserialize;

const CHALLENGE_TTL_SECS: u32 = 60;
const PROPAGATION_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// The parts of cyfs-dns-provider used here.
#[async_trait::async_trait]
trait DnsApi: Send + Sync + 'static {
    /// Unknown ones count as secret.
    fn is_secret(&self, provider: &str, field: &str) -> bool;
    fn load_credential(&self, path: &Path) -> DnsProviderResult<DnsCredential>;
    fn create_provider(
        &self,
        credential: &DnsCredential,
        origin: &str,
    ) -> DnsProviderResult<DnsRecordProviderRef>;
    async fn find_zone_apex(&self, name: &str) -> DnsLookupResult<ZoneApex>;
    async fn wait_txt_visible(
        &self,
        name: &str,
        value: &str,
        timeout: Duration,
    ) -> DnsLookupResult<bool>;
}

struct SystemDnsApi;

#[async_trait::async_trait]
impl DnsApi for SystemDnsApi {
    fn is_secret(&self, provider: &str, field: &str) -> bool {
        provider_info(provider)
            .and_then(|info| info.fields.iter().find(|known| known.id == field))
            .is_none_or(|known| known.secret)
    }

    fn load_credential(&self, path: &Path) -> DnsProviderResult<DnsCredential> {
        load_credential(path)
    }

    fn create_provider(
        &self,
        credential: &DnsCredential,
        origin: &str,
    ) -> DnsProviderResult<DnsRecordProviderRef> {
        create_provider(credential, origin)
    }

    async fn find_zone_apex(&self, name: &str) -> DnsLookupResult<ZoneApex> {
        find_zone_apex(SystemDnsLookup::new().as_ref(), name).await
    }

    async fn wait_txt_visible(
        &self,
        name: &str,
        value: &str,
        timeout: Duration,
    ) -> DnsLookupResult<bool> {
        wait_txt_visible(SystemDnsLookup::new().as_ref(), name, value, timeout).await
    }
}

/// ACME DNS-01 through the DNS service the user's credential is for.
pub struct AcmeDnsApiProviderFactory {
    api: Arc<dyn DnsApi>,
    propagation_timeout: Duration,
    // Some services are read, changed and written back as a whole: two challenges
    // under one name must not be written at the same time.
    write_lock: Arc<tokio::sync::Mutex<()>>,
}

impl AcmeDnsApiProviderFactory {
    pub fn new() -> Arc<Self> {
        Self::with_api(Arc::new(SystemDnsApi), PROPAGATION_TIMEOUT)
    }

    fn with_api(api: Arc<dyn DnsApi>, propagation_timeout: Duration) -> Arc<Self> {
        Arc::new(Self {
            api,
            propagation_timeout,
            write_lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcmeDnsApiProviderConfig {
    credential_path: PathBuf,
}

#[async_trait::async_trait]
impl DnsProviderFactory for AcmeDnsApiProviderFactory {
    async fn create(
        &self,
        _acme_mgr: Weak<AcmeCertManager>,
        params: serde_json::Value,
    ) -> Result<DnsProviderRef> {
        let config: AcmeDnsApiProviderConfig = serde_json::from_value(params)
            .map_err(|e| anyhow!("invalid dns-api provider config: {}", e))?;
        Ok(Arc::new(AcmeDnsApiProvider {
            api: self.api.clone(),
            credential_path: config.credential_path,
            write_lock: self.write_lock.clone(),
            pending: Mutex::new(Vec::new()),
        }))
    }

    async fn wait_propagation(&self, domain: &str, key_hash: &str) -> Result<()> {
        let visible = self
            .api
            .wait_txt_visible(domain, key_hash, self.propagation_timeout)
            .await
            .map_err(|e| anyhow!("check challenge record {} failed: {}", domain, e))?;
        if !visible {
            return Err(anyhow!(
                "challenge record {} is not visible on its name servers after {:?}",
                domain,
                self.propagation_timeout
            ));
        }
        Ok(())
    }
}

struct AcmeDnsApiProvider {
    api: Arc<dyn DnsApi>,
    credential_path: PathBuf,
    write_lock: Arc<tokio::sync::Mutex<()>>,
    /// Challenges written and not taken away yet: (name, value).
    pending: Mutex<Vec<(String, String)>>,
}

/// A reload drops the orders in progress without reverting their challenges.
impl Drop for AcmeDnsApiProvider {
    fn drop(&mut self) {
        let pending = std::mem::take(&mut *self.pending.lock().unwrap());
        if pending.is_empty() {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let provider = AcmeDnsApiProvider {
            api: self.api.clone(),
            credential_path: self.credential_path.clone(),
            write_lock: self.write_lock.clone(),
            pending: Mutex::new(Vec::new()),
        };
        runtime.spawn(async move {
            for (domain, key_hash) in pending {
                if let Err(e) = provider
                    .call("del_challenge".to_string(), domain, key_hash)
                    .await
                {
                    log::warn!("remove abandoned challenge failed: {}", e);
                }
            }
        });
    }
}

#[async_trait::async_trait]
impl DnsProvider for AcmeDnsApiProvider {
    async fn call(&self, op: String, domain: String, key_hash: String) -> Result<()> {
        // Read every time: the user may have replaced the token.
        let credential = self
            .api
            .load_credential(&self.credential_path)
            .map_err(|e| anyhow!("load dns credential failed: {}", e))?;
        self.change_record(&credential, &op, &domain, key_hash)
            .await
            .map_err(|e| {
                anyhow!(
                    "{}",
                    redact(self.api.as_ref(), format!("{e:#}"), &credential)
                )
            })
    }
}

impl AcmeDnsApiProvider {
    async fn change_record(
        &self,
        credential: &DnsCredential,
        op: &str,
        domain: &str,
        key_hash: String,
    ) -> Result<()> {
        let zone = self
            .api
            .find_zone_apex(domain)
            .await
            .map_err(|e| anyhow!("find the zone of {} failed: {}", domain, e))?;
        let provider = self
            .api
            .create_provider(credential, &zone.apex)
            .map_err(|e| anyhow!("{}: {}", credential.provider, e))?;
        let _write = self.write_lock.lock().await;
        let challenge = (domain.to_string(), key_hash.clone());
        match op {
            "add_challenge" => {
                self.pending.lock().unwrap().push(challenge);
                provider
                    .add_values(domain, RecordType::TXT, CHALLENGE_TTL_SECS, vec![key_hash])
                    .await
                    .map_err(|e| {
                        anyhow!("{}: add {} TXT failed: {}", credential.provider, domain, e)
                    })
            }
            "del_challenge" => {
                provider
                    .remove_values(domain, RecordType::TXT, vec![key_hash])
                    .await
                    .map_err(|e| {
                        anyhow!(
                            "{}: remove {} TXT failed: {}",
                            credential.provider,
                            domain,
                            e
                        )
                    })?;
                self.pending
                    .lock()
                    .unwrap()
                    .retain(|known| *known != challenge);
                Ok(())
            }
            _ => Err(anyhow!("unsupported dns-api operation: {}", op)),
        }
    }
}

/// Services may repeat what they were sent in their error text.
fn redact(api: &dyn DnsApi, mut text: String, credential: &DnsCredential) -> String {
    for (field, value) in &credential.fields {
        if !value.is_empty() && api.is_secret(&credential.provider, field) {
            text = text.replace(value.as_str(), "***");
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use cyfs_dns_provider::{DnsLookupError, DnsProviderError, DnsRecordProvider};
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// A service that only replaces whole RRsets, as the worst of them do.
    #[derive(Default)]
    struct FakeService {
        records: Mutex<BTreeMap<String, Vec<String>>>,
        tokens: Mutex<Vec<String>>,
        origins: Mutex<Vec<String>>,
        refuse: AtomicBool,
        visible_after: AtomicUsize,
        checks: AtomicUsize,
    }

    struct FakeProvider(Arc<FakeService>, String);

    impl FakeProvider {
        async fn change(
            &self,
            name: &str,
            change: impl FnOnce(&mut Vec<String>) + Send,
        ) -> DnsProviderResult<()> {
            if self.0.refuse.load(Ordering::SeqCst) {
                return Err(DnsProviderError::Unauthorized(format!(
                    "token {} was refused",
                    self.1
                )));
            }
            let mut values = self
                .0
                .records
                .lock()
                .unwrap()
                .get(name)
                .cloned()
                .unwrap_or_default();
            change(&mut values);
            tokio::time::sleep(Duration::from_millis(20)).await;
            self.0
                .records
                .lock()
                .unwrap()
                .insert(name.to_string(), values);
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl DnsRecordProvider for FakeProvider {
        async fn set_rrset(
            &self,
            _name: &str,
            _ty: RecordType,
            _ttl: u32,
            _values: Vec<String>,
        ) -> DnsProviderResult<()> {
            panic!("the whole record set must not be replaced")
        }

        async fn add_values(
            &self,
            name: &str,
            ty: RecordType,
            _ttl: u32,
            values: Vec<String>,
        ) -> DnsProviderResult<()> {
            assert_eq!(ty, RecordType::TXT);
            self.change(name, |known| known.extend(values)).await
        }

        async fn remove_values(
            &self,
            name: &str,
            ty: RecordType,
            values: Vec<String>,
        ) -> DnsProviderResult<()> {
            assert_eq!(ty, RecordType::TXT);
            self.change(name, |known| known.retain(|value| !values.contains(value)))
                .await
        }
    }

    struct FakeApi(Arc<FakeService>);

    #[async_trait::async_trait]
    impl DnsApi for FakeApi {
        fn is_secret(&self, _provider: &str, field: &str) -> bool {
            field != "region"
        }

        fn load_credential(&self, path: &Path) -> DnsProviderResult<DnsCredential> {
            let content = std::fs::read(path)
                .map_err(|e| DnsProviderError::InvalidCredential(e.to_string()))?;
            serde_json::from_slice(&content)
                .map_err(|e| DnsProviderError::InvalidCredential(e.to_string()))
        }

        fn create_provider(
            &self,
            credential: &DnsCredential,
            origin: &str,
        ) -> DnsProviderResult<DnsRecordProviderRef> {
            let token = credential.fields["api_token"].clone();
            self.0.tokens.lock().unwrap().push(token.clone());
            self.0.origins.lock().unwrap().push(origin.to_string());
            Ok(Arc::new(FakeProvider(self.0.clone(), token)))
        }

        async fn find_zone_apex(&self, name: &str) -> DnsLookupResult<ZoneApex> {
            if !name.ends_with(".example.co.uk") {
                return Err(DnsLookupError::Failed(format!("no SOA above {name}")));
            }
            Ok(ZoneApex {
                apex: "example.co.uk".to_string(),
                ns: vec![],
            })
        }

        async fn wait_txt_visible(
            &self,
            name: &str,
            value: &str,
            timeout: Duration,
        ) -> DnsLookupResult<bool> {
            let wait = async {
                loop {
                    let checks = self.0.checks.fetch_add(1, Ordering::SeqCst);
                    let written = self
                        .0
                        .records
                        .lock()
                        .unwrap()
                        .get(name)
                        .is_some_and(|values| values.iter().any(|known| known == value));
                    if written && checks >= self.0.visible_after.load(Ordering::SeqCst) {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            };
            Ok(tokio::time::timeout(timeout, wait).await.is_ok())
        }
    }

    const NAME: &str = "_acme-challenge.home.example.co.uk";

    struct Fixture {
        service: Arc<FakeService>,
        factory: Arc<AcmeDnsApiProviderFactory>,
        credential: PathBuf,
        _temp: tempfile::TempDir,
    }

    impl Fixture {
        fn new(timeout: Duration) -> Self {
            let temp = tempfile::tempdir().unwrap();
            let service = Arc::new(FakeService::default());
            let fixture = Self {
                factory: AcmeDnsApiProviderFactory::with_api(
                    Arc::new(FakeApi(service.clone())),
                    timeout,
                ),
                service,
                credential: temp.path().join("credential.json"),
                _temp: temp,
            };
            fixture.write_token("first-token");
            fixture
        }

        fn write_token(&self, token: &str) {
            std::fs::write(
                &self.credential,
                json!({
                    "provider": "test", "fields": { "api_token": token, "region": "was" }
                })
                .to_string(),
            )
            .unwrap();
        }

        async fn provider(&self) -> DnsProviderRef {
            self.factory
                .create(Weak::new(), json!({ "credential_path": self.credential }))
                .await
                .unwrap()
        }

        fn values(&self) -> Vec<String> {
            self.service
                .records
                .lock()
                .unwrap()
                .get(NAME)
                .cloned()
                .unwrap_or_default()
        }
    }

    async fn call(provider: &DnsProviderRef, op: &str, value: &str) -> Result<()> {
        provider
            .call(op.to_string(), NAME.to_string(), value.to_string())
            .await
    }

    #[tokio::test]
    async fn challenges_are_added_and_removed_by_value() {
        let fixture = Fixture::new(PROPAGATION_TIMEOUT);
        fixture
            .service
            .records
            .lock()
            .unwrap()
            .insert(NAME.to_string(), vec!["kept".to_string()]);
        // Two generations of the configuration, writing at the same time.
        let (first, second) = (fixture.provider().await, fixture.provider().await);
        let (a, b) = tokio::join!(
            call(&first, "add_challenge", "one"),
            call(&second, "add_challenge", "two")
        );
        a.unwrap();
        b.unwrap();
        let mut values = fixture.values();
        values.sort();
        assert_eq!(values, vec!["kept", "one", "two"]);

        let (a, b) = tokio::join!(
            call(&first, "del_challenge", "one"),
            call(&second, "add_challenge", "three")
        );
        a.unwrap();
        b.unwrap();
        let mut values = fixture.values();
        values.sort();
        assert_eq!(values, vec!["kept", "three", "two"]);
        assert!(
            fixture
                .service
                .origins
                .lock()
                .unwrap()
                .iter()
                .all(|origin| origin == "example.co.uk")
        );
        assert!(call(&first, "other", "one").await.is_err());
    }

    #[tokio::test]
    async fn a_replaced_token_is_used_at_once() {
        let fixture = Fixture::new(PROPAGATION_TIMEOUT);
        let provider = fixture.provider().await;
        call(&provider, "add_challenge", "one").await.unwrap();
        fixture.write_token("second-token");
        call(&provider, "del_challenge", "one").await.unwrap();
        assert_eq!(
            *fixture.service.tokens.lock().unwrap(),
            vec!["first-token", "second-token"]
        );
        // The file may be missing when the gateway starts.
        std::fs::remove_file(&fixture.credential).unwrap();
        let provider = fixture.provider().await;
        assert!(call(&provider, "add_challenge", "two").await.is_err());
        fixture.write_token("third-token");
        call(&provider, "add_challenge", "two").await.unwrap();
    }

    #[tokio::test]
    async fn challenges_of_dropped_orders_are_taken_away() {
        let fixture = Fixture::new(PROPAGATION_TIMEOUT);
        let provider = fixture.provider().await;
        call(&provider, "add_challenge", "one").await.unwrap();
        call(&provider, "add_challenge", "two").await.unwrap();
        call(&provider, "del_challenge", "two").await.unwrap();
        let next = fixture.provider().await;
        call(&next, "add_challenge", "three").await.unwrap();
        drop(provider);
        tokio::time::timeout(Duration::from_secs(5), async {
            while fixture.values() != vec!["three"] {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn errors_do_not_show_the_token() {
        let fixture = Fixture::new(PROPAGATION_TIMEOUT);
        fixture.service.refuse.store(true, Ordering::SeqCst);
        let error = call(&fixture.provider().await, "add_challenge", "one")
            .await
            .unwrap_err();
        let text = format!("{error:?} {error:#}");
        assert!(!text.contains("first-token"), "{text}");
        assert!(text.contains("token *** was refused"), "{text}");

        let error = fixture
            .factory
            .create(
                Weak::new(),
                json!({ "credential_path": "x", "api_token": "first-token" }),
            )
            .await
            .err()
            .unwrap();
        assert!(!format!("{error:?}").contains("first-token"));
    }

    #[tokio::test]
    async fn propagation_is_checked_and_times_out() {
        let fixture = Fixture::new(Duration::from_millis(200));
        call(&fixture.provider().await, "add_challenge", "one")
            .await
            .unwrap();
        fixture.service.visible_after.store(3, Ordering::SeqCst);
        fixture.factory.wait_propagation(NAME, "one").await.unwrap();
        assert!(fixture.service.checks.load(Ordering::SeqCst) > 3);
        let error = fixture
            .factory
            .wait_propagation(NAME, "never written")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("not visible"), "{error}");
    }
}
