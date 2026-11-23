//! The three operations on top of "list one RRset" and "change one RRset", so
//! every service gets the same rules: values are compared in one form, only the
//! given name and type are touched, one change at a time per zone, rate limits
//! are waited out and no error carries a secret.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use serde_json::Value;

use crate::provider::{DnsProviderError, DnsProviderResult, DnsRecordProvider, RecordType};
use crate::values::{host, input_value, is_under, type_name};

const MAX_ATTEMPTS: u32 = 4;
const MAX_WAIT: Duration = Duration::from_secs(30);

/// Runs `step` again while the service asks to wait, within bounds.
async fn patiently<T, F, R>(mut step: F) -> DnsProviderResult<T>
where
    F: FnMut() -> R,
    R: Future<Output = DnsProviderResult<T>>,
{
    let mut attempt = 0;
    loop {
        let result = step().await;
        let Err(DnsProviderError::RateLimited { retry_after, .. }) = &result else {
            return result;
        };
        let wait = retry_after.unwrap_or(Duration::from_secs(1 << attempt));
        attempt += 1;
        if attempt == MAX_ATTEMPTS || wait > MAX_WAIT {
            return result;
        }
        tokio::time::sleep(wait).await;
    }
}

/// One value of an RRset as the service holds it.
#[derive(Clone, Debug, Default)]
pub(crate) struct Stored {
    /// The service's record id; empty when it only knows RRsets.
    pub id: String,
    pub value: String,
    pub ttl: u32,
    /// As the service returned it, written back unchanged when the value stays.
    pub raw: Value,
    /// The value is right but the record has to be rewritten.
    pub stale: bool,
}

pub(crate) struct Change {
    pub keep: Vec<Stored>,
    /// When a value replaces another, they are at the same position.
    pub remove: Vec<Stored>,
    pub add: Vec<String>,
    pub ttl: u32,
}

#[async_trait::async_trait]
pub(crate) trait Backend: Send + Sync {
    fn ttl_range(&self) -> (u32, u32) {
        (60, 86400)
    }

    async fn list(&self, name: &str, ty: RecordType) -> DnsProviderResult<Vec<Stored>>;

    async fn apply(&self, name: &str, ty: RecordType, change: Change) -> DnsProviderResult<()>;
}

/// A service whose records have ids of their own.
#[async_trait::async_trait]
pub(crate) trait RecordApi: Send + Sync {
    /// Whether [`RecordApi::update`] can change a record in place.
    const UPDATES: bool = false;

    fn ttl_range(&self) -> (u32, u32) {
        (60, 86400)
    }

    async fn list(&self, name: &str, ty: RecordType) -> DnsProviderResult<Vec<Stored>>;

    /// `Ok` when the same record is already there.
    async fn create(
        &self,
        name: &str,
        ty: RecordType,
        ttl: u32,
        value: &str,
    ) -> DnsProviderResult<()>;

    async fn update(
        &self,
        _name: &str,
        _ty: RecordType,
        _ttl: u32,
        _record: &Stored,
        _value: &str,
    ) -> DnsProviderResult<()> {
        Err(DnsProviderError::Unsupported("update".to_string()))
    }

    /// `Ok` when the record is already gone.
    async fn delete(&self, name: &str, ty: RecordType, record: &Stored) -> DnsProviderResult<()>;

    /// Runs after the changes of one RRset, successful or not.
    async fn commit(&self) -> DnsProviderResult<()> {
        Ok(())
    }
}

pub(crate) struct PerRecord<A>(pub A);

impl<A: RecordApi> PerRecord<A> {
    async fn change(&self, name: &str, ty: RecordType, change: Change) -> DnsProviderResult<()> {
        let api = &self.0;
        let ttl = change.ttl;
        let mut remove = change.remove;
        let mut add = change.add;
        if A::UPDATES {
            let pairs = remove.len().min(add.len());
            for (record, value) in remove.drain(..pairs).zip(add.drain(..pairs)) {
                patiently(|| api.update(name, ty, ttl, &record, &value)).await?;
            }
        }
        // A name can hold only one CNAME, everything else overlaps without a gap.
        if ty == RecordType::CNAME {
            for record in &remove {
                patiently(|| api.delete(name, ty, record)).await?;
            }
            for value in &add {
                if let Err(error) = patiently(|| api.create(name, ty, ttl, value)).await {
                    for old in &remove {
                        let ttl = old.ttl.max(ttl);
                        let _ = patiently(|| api.create(name, ty, ttl, &old.value)).await;
                    }
                    return Err(error);
                }
            }
        } else {
            for value in &add {
                patiently(|| api.create(name, ty, ttl, value)).await?;
            }
            for record in &remove {
                patiently(|| api.delete(name, ty, record)).await?;
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl<A: RecordApi> Backend for PerRecord<A> {
    fn ttl_range(&self) -> (u32, u32) {
        self.0.ttl_range()
    }

    async fn list(&self, name: &str, ty: RecordType) -> DnsProviderResult<Vec<Stored>> {
        self.0.list(name, ty).await
    }

    async fn apply(&self, name: &str, ty: RecordType, change: Change) -> DnsProviderResult<()> {
        let changed = self.change(name, ty, change).await;
        let committed = self.0.commit().await;
        changed.and(committed)
    }
}

enum Op {
    Set,
    Add,
    Remove,
}

fn plan(op: &Op, existing: Vec<Stored>, values: &[String], ttl: u32) -> Option<Change> {
    let mut keep = Vec::new();
    let mut remove = Vec::new();
    let mut add = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for record in existing {
        let wanted = values.contains(&record.value);
        match op {
            Op::Remove if wanted => remove.push(record),
            Op::Remove => keep.push(record),
            Op::Set if !wanted || seen.contains(&record.value) => remove.push(record),
            _ if wanted && record.stale => {
                // First in both lists, so it is rewritten in place.
                seen.push(record.value.clone());
                add.insert(0, record.value.clone());
                remove.insert(0, record);
            }
            _ => {
                seen.push(record.value.clone());
                keep.push(record);
            }
        }
    }
    if !matches!(op, Op::Remove) {
        for value in values {
            if !seen.contains(value) {
                seen.push(value.clone());
                add.push(value.clone());
            }
        }
    }
    if add.is_empty() && remove.is_empty() {
        return None;
    }
    let ttl = keep
        .first()
        .map(|record| record.ttl)
        .filter(|ttl| *ttl > 0)
        .unwrap_or(ttl);
    Some(Change {
        keep,
        remove,
        add,
        ttl,
    })
}

type ZoneLock = Arc<tokio::sync::Mutex<()>>;

static ZONE_LOCKS: LazyLock<Mutex<HashMap<(String, String), ZoneLock>>> =
    LazyLock::new(Default::default);

pub(crate) struct Engine {
    origin: String,
    backend: Box<dyn Backend>,
    secrets: Vec<String>,
    lock: ZoneLock,
}

impl Engine {
    pub(crate) fn new(
        provider: &str,
        origin: &str,
        backend: Box<dyn Backend>,
        secrets: Vec<String>,
    ) -> Self {
        let lock = ZONE_LOCKS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry((provider.to_string(), origin.to_string()))
            .or_default()
            .clone();
        Self {
            origin: origin.to_string(),
            backend,
            secrets,
            lock,
        }
    }

    fn redact(&self, error: DnsProviderError) -> DnsProviderError {
        let clean = |text: String| {
            self.secrets
                .iter()
                .fold(text, |text, secret| text.replace(secret, "***"))
        };
        match error {
            DnsProviderError::Unauthorized(text) => DnsProviderError::Unauthorized(clean(text)),
            DnsProviderError::ZoneNotFound(text) => DnsProviderError::ZoneNotFound(clean(text)),
            DnsProviderError::RateLimited {
                message,
                retry_after,
            } => DnsProviderError::RateLimited {
                message: clean(message),
                retry_after,
            },
            DnsProviderError::InvalidCredential(text) => {
                DnsProviderError::InvalidCredential(clean(text))
            }
            DnsProviderError::Unsupported(text) => DnsProviderError::Unsupported(clean(text)),
            DnsProviderError::Network(text) => DnsProviderError::Network(clean(text)),
            DnsProviderError::Api(text) => DnsProviderError::Api(clean(text)),
        }
    }

    async fn once(
        &self,
        op: &Op,
        name: &str,
        ty: RecordType,
        ttl: u32,
        values: &[String],
    ) -> DnsProviderResult<()> {
        let existing = self.backend.list(name, ty).await?;
        match plan(op, existing, values, ttl) {
            Some(change) => self.backend.apply(name, ty, change).await,
            None => Ok(()),
        }
    }

    async fn run(
        &self,
        op: Op,
        name: &str,
        ty: RecordType,
        ttl: u32,
        values: Vec<String>,
    ) -> DnsProviderResult<()> {
        let name = host(name);
        if !is_under(&name, &self.origin) {
            return Err(DnsProviderError::ZoneNotFound(format!(
                "{name} is not in {}",
                self.origin
            )));
        }
        if matches!(ty, RecordType::SOA | RecordType::CAA)
            || (ty == RecordType::NS && name == self.origin)
        {
            return Err(DnsProviderError::Unsupported(format!(
                "{} records of {name} are not written",
                type_name(ty)
            )));
        }
        let values = values
            .iter()
            .map(|value| input_value(ty, value))
            .collect::<DnsProviderResult<Vec<_>>>()?;
        let (min, max) = self.backend.ttl_range();
        let ttl = ttl.clamp(min, max);

        let _zone = self.lock.lock().await;
        patiently(|| self.once(&op, &name, ty, ttl, &values))
            .await
            .map_err(|error| self.redact(error))
    }
}

#[async_trait::async_trait]
impl DnsRecordProvider for Engine {
    async fn set_rrset(
        &self,
        name: &str,
        ty: RecordType,
        ttl: u32,
        values: Vec<String>,
    ) -> DnsProviderResult<()> {
        self.run(Op::Set, name, ty, ttl, values).await
    }

    async fn add_values(
        &self,
        name: &str,
        ty: RecordType,
        ttl: u32,
        values: Vec<String>,
    ) -> DnsProviderResult<()> {
        self.run(Op::Add, name, ty, ttl, values).await
    }

    async fn remove_values(
        &self,
        name: &str,
        ty: RecordType,
        values: Vec<String>,
    ) -> DnsProviderResult<()> {
        self.run(Op::Remove, name, ty, 0, values).await
    }

    async fn list_values(&self, name: &str, ty: RecordType) -> DnsProviderResult<Vec<String>> {
        let name = host(name);
        let records = patiently(|| self.backend.list(&name, ty))
            .await
            .map_err(|error| self.redact(error))?;
        Ok(records.into_iter().map(|record| record.value).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Memory {
        records: Mutex<Vec<(String, RecordType, Stored)>>,
        failures: Mutex<Vec<DnsProviderError>>,
        writes: Mutex<u32>,
        fail_create: Mutex<bool>,
    }

    #[async_trait::async_trait]
    impl RecordApi for Arc<Memory> {
        async fn list(&self, name: &str, ty: RecordType) -> DnsProviderResult<Vec<Stored>> {
            if let Some(error) = self.failures.lock().unwrap().pop() {
                return Err(error);
            }
            Ok(self
                .records
                .lock()
                .unwrap()
                .iter()
                .filter(|(n, t, _)| n == name && *t == ty)
                .map(|(_, _, record)| record.clone())
                .collect())
        }

        async fn create(
            &self,
            name: &str,
            ty: RecordType,
            ttl: u32,
            value: &str,
        ) -> DnsProviderResult<()> {
            if std::mem::take(&mut *self.fail_create.lock().unwrap()) {
                return Err(DnsProviderError::Api("refused secret-value".to_string()));
            }
            *self.writes.lock().unwrap() += 1;
            self.records.lock().unwrap().push((
                name.to_string(),
                ty,
                Stored {
                    id: value.to_string(),
                    value: value.to_string(),
                    ttl,
                    ..Default::default()
                },
            ));
            Ok(())
        }

        async fn delete(
            &self,
            name: &str,
            ty: RecordType,
            record: &Stored,
        ) -> DnsProviderResult<()> {
            *self.writes.lock().unwrap() += 1;
            self.records
                .lock()
                .unwrap()
                .retain(|(n, t, r)| !(n == name && *t == ty && r.id == record.id));
            Ok(())
        }
    }

    fn engine(memory: &Arc<Memory>, origin: &str) -> Engine {
        Engine::new(
            "memory",
            origin,
            Box::new(PerRecord(memory.clone())),
            vec!["secret-value".to_string()],
        )
    }

    fn values(memory: &Memory, name: &str) -> Vec<String> {
        memory
            .records
            .lock()
            .unwrap()
            .iter()
            .filter(|(n, _, _)| n == name)
            .map(|(_, _, record)| record.value.clone())
            .collect()
    }

    #[tokio::test]
    async fn failed_cname_replacement_is_put_back() {
        let memory = Arc::new(Memory::default());
        let engine = engine(&memory, "rollback.test");
        engine
            .set_rrset(
                "a.rollback.test",
                RecordType::CNAME,
                300,
                vec!["old.test".into()],
            )
            .await
            .unwrap();
        *memory.fail_create.lock().unwrap() = true;
        let error = engine
            .set_rrset(
                "a.rollback.test",
                RecordType::CNAME,
                300,
                vec!["new.test".into()],
            )
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "refused ***");
        assert_eq!(values(&memory, "a.rollback.test"), ["old.test"]);
    }

    #[tokio::test]
    async fn refuses_foreign_names_and_the_zone_ns() {
        let memory = Arc::new(Memory::default());
        let engine = engine(&memory, "guard.test");
        assert!(matches!(
            engine
                .set_rrset("badguard.test", RecordType::A, 60, vec!["192.0.2.1".into()])
                .await,
            Err(DnsProviderError::ZoneNotFound(_))
        ));
        assert!(matches!(
            engine
                .set_rrset("guard.test", RecordType::NS, 60, vec!["ns.example".into()])
                .await,
            Err(DnsProviderError::Unsupported(_))
        ));
        assert_eq!(*memory.writes.lock().unwrap(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn rate_limits_are_waited_out_within_bounds() {
        let limited = |seconds| DnsProviderError::RateLimited {
            message: "slow down".to_string(),
            retry_after: seconds,
        };
        let memory = Arc::new(Memory::default());
        let engine = engine(&memory, "limits.test");
        let add = || engine.add_values("t.limits.test", RecordType::TXT, 60, vec!["v".into()]);

        *memory.failures.lock().unwrap() =
            vec![limited(None), limited(Some(Duration::from_secs(7)))];
        let started = tokio::time::Instant::now();
        add().await.unwrap();
        assert_eq!(started.elapsed().as_secs(), 7 + 2);

        *memory.failures.lock().unwrap() = vec![limited(Some(Duration::from_secs(3600)))];
        let started = tokio::time::Instant::now();
        assert!(matches!(
            add().await,
            Err(DnsProviderError::RateLimited { .. })
        ));
        assert_eq!(started.elapsed().as_secs(), 0);

        *memory.failures.lock().unwrap() = (0..10).map(|_| limited(None)).collect();
        assert!(matches!(
            add().await,
            Err(DnsProviderError::RateLimited { .. })
        ));
        assert_eq!(
            memory.failures.lock().unwrap().len(),
            10 - MAX_ATTEMPTS as usize
        );
    }

    #[tokio::test]
    async fn concurrent_adds_keep_both_values() {
        let memory = Arc::new(Memory::default());
        let first = engine(&memory, "parallel.test");
        let second = engine(&memory, "parallel.test");
        let name = "_acme-challenge.parallel.test";
        let (a, b) = tokio::join!(
            first.add_values(name, RecordType::TXT, 60, vec!["one".into()]),
            second.add_values(name, RecordType::TXT, 60, vec!["two".into()]),
        );
        a.unwrap();
        b.unwrap();
        assert_eq!(values(&memory, name), ["one", "two"]);
    }
}
