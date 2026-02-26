use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use chrono::{Datelike, Local, TimeZone};
use sfo_sql::Row;
use sfo_sql::sqlite::sql_query;
use tokio::task::JoinHandle;

#[derive(Clone)]
pub struct DeviceInfo {
    ip: IpAddr,
    mac: Option<String>,
    hostname: Option<String>,
    active_connections: u32,
    last_connected_at: u64,
    last_disconnected_at: Option<u64>,
    today_online_seconds: u64,
    current_session_online_seconds: u64,
}

impl DeviceInfo {
    pub fn ip(&self) -> IpAddr {
        self.ip
    }

    pub fn mac(&self) -> Option<&str> {
        self.mac.as_deref()
    }

    pub fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }

    pub fn active_connections(&self) -> u32 {
        self.active_connections
    }

    pub fn last_connected_at(&self) -> u64 {
        self.last_connected_at
    }

    pub fn last_disconnected_at(&self) -> Option<u64> {
        self.last_disconnected_at
    }

    pub fn today_online_seconds(&self) -> u64 {
        self.today_online_seconds
    }

    pub fn current_session_online_seconds(&self) -> u64 {
        self.current_session_online_seconds
    }
}

#[derive(Clone)]
pub struct PersistedDeviceState {
    pub ip: IpAddr,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub last_connected_at: u64,
    pub last_disconnected_at: Option<u64>,
    pub day_key: i32,
    pub today_online_seconds: u64,
}

#[async_trait]
pub trait DeviceOnlineStore: Send + Sync {
    async fn load_device(&self, ip: IpAddr) -> Result<Option<PersistedDeviceState>, String>;
    async fn upsert_devices(&self, states: Vec<PersistedDeviceState>) -> Result<(), String>;
    async fn cleanup_daily_before(&self, min_day_key: i32) -> Result<u64, String>;
}

pub type DeviceOnlineStoreRef = Arc<dyn DeviceOnlineStore + Send + Sync>;

pub struct SqliteDeviceOnlineStore {
    pool: sfo_sql::sqlite::SqlPool,
}

impl SqliteDeviceOnlineStore {
    pub async fn new(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        if let Some(parent) = path.parent()
            && let Err(e) = tokio::fs::create_dir_all(parent).await
        {
            return Err(format!("create sqlite dir failed: {:?}", e));
        }

        let dsn = if path.to_string_lossy().starts_with("sqlite://") {
            path.to_string_lossy().to_string()
        } else {
            format!("sqlite://{}", path.to_string_lossy())
        };

        let pool = sfo_sql::sqlite::SqlPool::open(dsn.as_str(), 5, None)
            .await
            .map_err(|e| e.to_string())?;

        let mut conn = pool.get_conn().await.map_err(|e| e.to_string())?;
        conn.execute_sql(sql_query(
            "CREATE TABLE IF NOT EXISTS device_daily_online (ip TEXT NOT NULL, day_key INTEGER NOT NULL, online_seconds INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY(ip, day_key));",
        ))
        .await
        .map_err(|e| e.to_string())?;
        conn.execute_sql(sql_query(
            "CREATE INDEX IF NOT EXISTS idx_device_daily_online_day_key ON device_daily_online(day_key);",
        ))
        .await
        .map_err(|e| e.to_string())?;
        conn.execute_sql(sql_query(
            "CREATE TABLE IF NOT EXISTS device_runtime_state (ip TEXT PRIMARY KEY, mac TEXT, hostname TEXT, last_connected_at INTEGER NOT NULL, last_disconnected_at INTEGER, day_key INTEGER NOT NULL, today_online_seconds INTEGER NOT NULL, updated_at INTEGER NOT NULL);",
        ))
        .await
        .map_err(|e| e.to_string())?;

        Ok(Self { pool })
    }
}

#[async_trait]
impl DeviceOnlineStore for SqliteDeviceOnlineStore {
    async fn load_device(&self, ip: IpAddr) -> Result<Option<PersistedDeviceState>, String> {
        let mut conn = self.pool.get_conn().await.map_err(|e| e.to_string())?;
        let row = match conn
            .query_one(
                sql_query(
                    "SELECT ip, mac, hostname, last_connected_at, last_disconnected_at, day_key, today_online_seconds FROM device_runtime_state WHERE ip = ?;",
                )
                .bind(ip.to_string()),
            )
            .await
        {
            Ok(row) => row,
            Err(e) => {
                if e.code() == sfo_sql::errors::SqlErrorCode::NotFound {
                    return Ok(None);
                }
                return Err(e.to_string());
            }
        };

        let ip_text: String = row.get("ip");
        let ip = ip_text.parse::<IpAddr>().map_err(|e| e.to_string())?;
        let last_disconnected: Option<i64> = row.get("last_disconnected_at");

        Ok(Some(PersistedDeviceState {
            ip,
            mac: row.get("mac"),
            hostname: row.get("hostname"),
            last_connected_at: row.get::<i64, _>("last_connected_at") as u64,
            last_disconnected_at: last_disconnected.map(|v| v as u64),
            day_key: row.get::<i64, _>("day_key") as i32,
            today_online_seconds: row.get::<i64, _>("today_online_seconds") as u64,
        }))
    }

    async fn upsert_devices(&self, states: Vec<PersistedDeviceState>) -> Result<(), String> {
        if states.is_empty() {
            return Ok(());
        }

        let mut conn = self.pool.get_conn().await.map_err(|e| e.to_string())?;
        for state in states {
            let updated_at = now_seconds() as i64;
            conn.execute_sql(
                sql_query(
                    "INSERT INTO device_daily_online (ip, day_key, online_seconds, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(ip, day_key) DO UPDATE SET online_seconds = excluded.online_seconds, updated_at = excluded.updated_at;",
                )
                .bind(state.ip.to_string())
                .bind(state.day_key as i64)
                .bind(state.today_online_seconds as i64)
                .bind(updated_at),
            )
            .await
            .map_err(|e| e.to_string())?;

            conn.execute_sql(
                sql_query(
                    "INSERT INTO device_runtime_state (ip, mac, hostname, last_connected_at, last_disconnected_at, day_key, today_online_seconds, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(ip) DO UPDATE SET mac = excluded.mac, hostname = excluded.hostname, last_connected_at = excluded.last_connected_at, last_disconnected_at = excluded.last_disconnected_at, day_key = excluded.day_key, today_online_seconds = excluded.today_online_seconds, updated_at = excluded.updated_at;",
                )
                .bind(state.ip.to_string())
                .bind(state.mac)
                .bind(state.hostname)
                .bind(state.last_connected_at as i64)
                .bind(state.last_disconnected_at.map(|v| v as i64))
                .bind(state.day_key as i64)
                .bind(state.today_online_seconds as i64)
                .bind(updated_at),
            )
            .await
            .map_err(|e| e.to_string())?;
        }

        Ok(())
    }

    async fn cleanup_daily_before(&self, min_day_key: i32) -> Result<u64, String> {
        let mut conn = self.pool.get_conn().await.map_err(|e| e.to_string())?;
        let result = conn
            .execute_sql(
                sql_query("DELETE FROM device_daily_online WHERE day_key < ?;")
                    .bind(min_day_key as i64),
            )
            .await
            .map_err(|e| e.to_string())?;

        Ok(result.rows_affected() as u64)
    }
}

struct DeviceState {
    ip: IpAddr,
    mac: Option<String>,
    hostname: Option<String>,
    active_connections: u32,
    last_connected_at: u64,
    last_disconnected_at: Option<u64>,
    today_day_key: i32,
    today_online_seconds: u64,
    current_session_started_at: Option<u64>,
    current_day_session_started_at: Option<u64>,
    last_persisted_at: u64,
    persisted_loaded: bool,
    loading_from_store: bool,
    last_probe_at: Option<u64>,
    probe_fail_day_key: i32,
    probe_fail_count: u8,
    probing: bool,
}

impl DeviceState {
    fn to_info(&self, now: u64) -> DeviceInfo {
        let current_session_online_seconds = self
            .current_session_started_at
            .map(|started_at| now.saturating_sub(started_at))
            .unwrap_or(0);
        let current_day_online_seconds = self
            .current_day_session_started_at
            .map(|started_at| now.saturating_sub(started_at))
            .unwrap_or(0);

        DeviceInfo {
            ip: self.ip,
            mac: self.mac.clone(),
            hostname: self.hostname.clone(),
            active_connections: self.active_connections,
            last_connected_at: self.last_connected_at,
            last_disconnected_at: self.last_disconnected_at,
            today_online_seconds: self
                .today_online_seconds
                .saturating_add(current_day_online_seconds),
            current_session_online_seconds,
        }
    }

    fn to_persisted(&self, now: u64) -> PersistedDeviceState {
        let current_day_online_seconds = self
            .current_day_session_started_at
            .map(|started_at| now.saturating_sub(started_at))
            .unwrap_or(0);

        PersistedDeviceState {
            ip: self.ip,
            mac: self.mac.clone(),
            hostname: self.hostname.clone(),
            last_connected_at: self.last_connected_at,
            last_disconnected_at: self.last_disconnected_at,
            day_key: self.today_day_key,
            today_online_seconds: self
                .today_online_seconds
                .saturating_add(current_day_online_seconds),
        }
    }
}

pub struct DeviceManager {
    devices: Mutex<HashMap<IpAddr, DeviceState>>,
    store: DeviceOnlineStoreRef,
    offline_timeout: Duration,
    cleanup_interval: Duration,
    cleanup_handle: Mutex<Option<JoinHandle<()>>>,
    last_retention_cleanup_at: Mutex<u64>,
}

pub type DeviceManagerRef = Arc<DeviceManager>;

impl DeviceManager {
    pub async fn new(
        store: DeviceOnlineStoreRef,
        offline_timeout: Duration,
        cleanup_interval: Duration,
    ) -> DeviceManagerRef {
        let manager = Arc::new(Self {
            devices: Mutex::new(HashMap::new()),
            store,
            offline_timeout,
            cleanup_interval,
            cleanup_handle: Mutex::new(None),
            last_retention_cleanup_at: Mutex::new(0),
        });
        manager.start_cleanup_task();
        manager
    }

    pub fn on_connection_open(self: &Arc<Self>, ip: IpAddr) {
        let now = now_seconds();
        let mut persist_list = Vec::new();
        let mut need_load_from_store = false;
        let need_probe = {
            let mut devices = self.devices.lock().unwrap();
            let state = devices.entry(ip).or_insert_with(|| DeviceState {
                ip,
                mac: None,
                hostname: None,
                active_connections: 0,
                last_connected_at: now,
                last_disconnected_at: None,
                today_day_key: day_key_local(now),
                today_online_seconds: 0,
                current_session_started_at: None,
                current_day_session_started_at: None,
                last_persisted_at: 0,
                persisted_loaded: false,
                loading_from_store: false,
                last_probe_at: None,
                probe_fail_day_key: day_key_local(now),
                probe_fail_count: 0,
                probing: false,
            });

            if !state.persisted_loaded && !state.loading_from_store {
                state.loading_from_store = true;
                need_load_from_store = true;
            }

            if let Some(snapshot) = Self::align_state_to_today(state, now) {
                persist_list.push(snapshot);
            }

            state.active_connections = state.active_connections.saturating_add(1);
            state.last_connected_at = now;
            state.last_disconnected_at = None;
            if state.active_connections == 1 {
                state.current_session_started_at = Some(now);
                state.current_day_session_started_at = Some(now);
            }

            Self::should_schedule_probe(state, now, false)
        };

        if !persist_list.is_empty() {
            self.spawn_persist(persist_list, false, now);
        }

        if need_load_from_store {
            let store = self.store.clone();
            let this = self.clone();
            tokio::spawn(async move {
                let persisted = store.load_device(ip).await;
                let now = now_seconds();
                let today = day_key_local(now);
                let mut devices = this.devices.lock().unwrap();
                let Some(state) = devices.get_mut(&ip) else {
                    return;
                };

                state.loading_from_store = false;
                state.persisted_loaded = true;

                let persisted = match persisted {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("load device online state failed for {}: {}", ip, e);
                        return;
                    }
                };

                let Some(item) = persisted else {
                    return;
                };

                if state.mac.is_none() {
                    state.mac = item.mac;
                }
                if state.hostname.is_none() {
                    state.hostname = item.hostname;
                }
                state.last_connected_at = state.last_connected_at.max(item.last_connected_at);
                if state.last_disconnected_at.is_none() {
                    state.last_disconnected_at = item.last_disconnected_at;
                }

                if item.day_key == today {
                    state.today_online_seconds = state
                        .today_online_seconds
                        .saturating_add(item.today_online_seconds);
                }

                let need_probe_after_load = Self::should_schedule_probe(state, now, true);
                drop(devices);

                if need_probe_after_load {
                    this.spawn_probe_task(ip);
                }
            });
        }

        if need_probe && !need_load_from_store {
            self.spawn_probe_task(ip);
        }
    }

    pub fn on_connection_close(&self, ip: IpAddr) {
        let now = now_seconds();
        let mut persist_list = Vec::new();
        let mut devices = self.devices.lock().unwrap();

        if let Some(state) = devices.get_mut(&ip) {
            if let Some(snapshot) = Self::align_state_to_today(state, now) {
                persist_list.push(snapshot);
            }

            if state.active_connections > 0 {
                state.active_connections -= 1;
            }

            if state.active_connections == 0 {
                if let Some(started_at) = state.current_day_session_started_at.take() {
                    state.today_online_seconds = state
                        .today_online_seconds
                        .saturating_add(now.saturating_sub(started_at));
                }
                state.last_disconnected_at = Some(now);
                state.current_session_started_at = None;
                state.last_persisted_at = now;
                persist_list.push(state.to_persisted(now));
            }
        }

        drop(devices);
        if !persist_list.is_empty() {
            self.spawn_persist(persist_list, false, now);
        }
    }

    pub fn get_all_devices(&self) -> Vec<DeviceInfo> {
        let now = now_seconds();
        let mut persist_list = Vec::new();
        let mut devices = self.devices.lock().unwrap();

        let infos = devices
            .values_mut()
            .map(|state| {
                if let Some(snapshot) = Self::align_state_to_today(state, now) {
                    persist_list.push(snapshot);
                }
                state.to_info(now)
            })
            .collect::<Vec<_>>();

        drop(devices);
        if !persist_list.is_empty() {
            self.spawn_persist(persist_list, false, now);
        }
        infos
    }

    pub fn get_device(&self, ip: IpAddr) -> Option<DeviceInfo> {
        let now = now_seconds();
        let mut persist_list = Vec::new();
        let mut devices = self.devices.lock().unwrap();

        let info = devices.get_mut(&ip).map(|state| {
            if let Some(snapshot) = Self::align_state_to_today(state, now) {
                persist_list.push(snapshot);
            }
            state.to_info(now)
        });

        drop(devices);
        if !persist_list.is_empty() {
            self.spawn_persist(persist_list, false, now);
        }
        info
    }

    pub fn restore_from_snapshot(&self, snapshot: Vec<DeviceInfo>) {
        let mut restored = HashMap::new();
        let now = now_seconds();
        let today = day_key_local(now);

        for info in snapshot {
            let ip = info.ip();
            restored.insert(
                ip,
                DeviceState {
                    ip,
                    mac: info.mac().map(|v| v.to_string()),
                    hostname: info.hostname().map(|v| v.to_string()),
                    active_connections: info.active_connections(),
                    last_connected_at: info.last_connected_at(),
                    last_disconnected_at: info.last_disconnected_at(),
                    today_day_key: today,
                    today_online_seconds: info.today_online_seconds(),
                    current_session_started_at: if info.active_connections() > 0 {
                        Some(info.last_connected_at())
                    } else {
                        None
                    },
                    current_day_session_started_at: if info.active_connections() > 0 {
                        Some(info.last_connected_at())
                    } else {
                        None
                    },
                    last_persisted_at: now,
                    persisted_loaded: true,
                    loading_from_store: false,
                    last_probe_at: None,
                    probe_fail_day_key: today,
                    probe_fail_count: 0,
                    probing: false,
                },
            );
        }

        *self.devices.lock().unwrap() = restored;
    }

    fn start_cleanup_task(self: &Arc<Self>) {
        let this = self.clone();
        *self.cleanup_handle.lock().unwrap() = Some(tokio::spawn(async move {
            loop {
                tokio::time::sleep(this.cleanup_interval).await;
                this.cleanup_expired_devices();
                this.persist_due_devices();
            }
        }));
    }

    fn cleanup_expired_devices(&self) {
        let now = now_seconds();
        let timeout = self.offline_timeout.as_secs();
        let mut devices = self.devices.lock().unwrap();
        devices.retain(|_, state| {
            if state.active_connections > 0 {
                return true;
            }
            let Some(last_disconnected_at) = state.last_disconnected_at else {
                return false;
            };
            now.saturating_sub(last_disconnected_at) <= timeout
        });
    }

    fn persist_due_devices(&self) {
        let now = now_seconds();
        let mut rollover_persist = Vec::new();
        let mut due_persist = Vec::new();

        {
            let mut devices = self.devices.lock().unwrap();
            for state in devices.values_mut() {
                if let Some(snapshot) = Self::align_state_to_today(state, now) {
                    rollover_persist.push(snapshot);
                }

                if now.saturating_sub(state.last_persisted_at) >= 600 {
                    due_persist.push(state.to_persisted(now));
                    state.last_persisted_at = now;
                }
            }
        }

        if !rollover_persist.is_empty() {
            self.spawn_persist(rollover_persist, false, now);
        }
        if !due_persist.is_empty() {
            self.spawn_persist(due_persist, true, now);
        }
    }

    fn align_state_to_today(state: &mut DeviceState, now: u64) -> Option<PersistedDeviceState> {
        let current_day = day_key_local(now);
        if state.today_day_key == current_day {
            return None;
        }

        if let Some(started_at) = state.current_day_session_started_at {
            let current_day_start = day_start_timestamp_local(current_day);
            let end = current_day_start.min(now);
            state.today_online_seconds = state
                .today_online_seconds
                .saturating_add(end.saturating_sub(started_at));
        }

        let old_snapshot = state.to_persisted(now);
        state.today_day_key = current_day;
        state.today_online_seconds = 0;
        state.current_day_session_started_at = if state.active_connections > 0 {
            Some(day_start_timestamp_local(current_day))
        } else {
            None
        };
        state.probe_fail_day_key = current_day;
        state.probe_fail_count = 0;

        Some(old_snapshot)
    }

    fn should_schedule_probe(state: &mut DeviceState, now: u64, force_after_load: bool) -> bool {
        let today = day_key_local(now);
        if state.probe_fail_day_key != today {
            state.probe_fail_day_key = today;
            state.probe_fail_count = 0;
        }

        if state.probing {
            return false;
        }

        if state.probe_fail_count >= 3 {
            return false;
        }

        let missing_info = state.mac.is_none() || state.hostname.is_none();
        let stale_info = state
            .last_probe_at
            .map(|last| now.saturating_sub(last) >= 24 * 3600)
            .unwrap_or(false);

        if force_after_load || missing_info || stale_info {
            state.probing = true;
            return true;
        }

        false
    }

    fn apply_probe_result(
        state: &mut DeviceState,
        now: u64,
        mac: Option<String>,
        hostname: Option<String>,
        mac_ok: bool,
        hostname_ok: bool,
    ) {
        if let Some(mac) = mac {
            state.mac = Some(mac);
        }
        if let Some(hostname) = hostname {
            state.hostname = Some(hostname);
        }

        let today = day_key_local(now);
        if state.probe_fail_day_key != today {
            state.probe_fail_day_key = today;
            state.probe_fail_count = 0;
        }

        if !mac_ok || !hostname_ok {
            state.probe_fail_count = state.probe_fail_count.saturating_add(1);
        } else {
            state.probe_fail_count = 0;
        }

        state.last_probe_at = Some(now);
        state.probing = false;
    }

    fn spawn_probe_task(self: &Arc<Self>, ip: IpAddr) {
        let this = self.clone();
        tokio::spawn(async move {
            let mac = cyfs_lookup::lookup_mac(ip).await.ok().flatten();
            let hostname = cyfs_lookup::lookup_hostname(ip).await.ok().flatten();
            let mac_ok = mac.is_some();
            let hostname_ok = hostname.is_some();
            let now = now_seconds();

            let mut devices = this.devices.lock().unwrap();
            if let Some(state) = devices.get_mut(&ip) {
                Self::apply_probe_result(state, now, mac, hostname, mac_ok, hostname_ok);
            }
        });
    }

    fn spawn_persist(
        &self,
        states: Vec<PersistedDeviceState>,
        run_retention_cleanup: bool,
        now: u64,
    ) {
        if states.is_empty() {
            return;
        }

        let mut dedup = HashMap::new();
        for state in states {
            dedup.insert((state.ip, state.day_key), state);
        }

        let merged_states = dedup.into_values().collect::<Vec<_>>();
        let store = self.store.clone();
        let should_cleanup = if run_retention_cleanup {
            let mut last_cleanup = self.last_retention_cleanup_at.lock().unwrap();
            if now.saturating_sub(*last_cleanup) >= 3600 {
                *last_cleanup = now;
                true
            } else {
                false
            }
        } else {
            false
        };

        tokio::spawn(async move {
            if let Err(e) = store.upsert_devices(merged_states).await {
                warn!("persist device online states failed: {}", e);
            }

            if should_cleanup {
                let min_day_key = day_key_local(now.saturating_sub(90 * 24 * 3600));
                if let Err(e) = store.cleanup_daily_before(min_day_key).await {
                    warn!("cleanup device daily online data failed: {}", e);
                }
            }
        });
    }
}

impl Drop for DeviceManager {
    fn drop(&mut self) {
        if let Some(handle) = self.cleanup_handle.lock().unwrap().take() {
            handle.abort();
        }
    }
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .unwrap_or(0)
}

fn day_key_local(ts: u64) -> i32 {
    let dt = Local
        .timestamp_opt(ts as i64, 0)
        .single()
        .unwrap_or_else(Local::now);
    dt.year() * 10_000 + dt.month() as i32 * 100 + dt.day() as i32
}

fn day_start_timestamp_local(day_key: i32) -> u64 {
    let year = day_key / 10_000;
    let month = ((day_key / 100) % 100) as u32;
    let day = (day_key % 100) as u32;

    Local
        .with_ymd_and_hms(year, month, day, 0, 0, 0)
        .earliest()
        .map(|v| v.timestamp() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::Duration;

    use super::{DeviceManager, DeviceOnlineStoreRef, SqliteDeviceOnlineStore};

    async fn new_test_store() -> DeviceOnlineStoreRef {
        let db_path = std::env::temp_dir().join(format!(
            "cyfs_gateway_device_online_{}_{}.db",
            std::process::id(),
            super::now_seconds()
        ));
        let store = SqliteDeviceOnlineStore::new(db_path).await.unwrap();
        Arc::new(store)
    }

    #[tokio::test]
    async fn offline_timeout_starts_after_last_connection_closed() {
        let manager = DeviceManager::new(
            new_test_store().await,
            Duration::from_secs(1),
            Duration::from_millis(200),
        )
        .await;
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

        manager.on_connection_open(ip);
        manager.on_connection_open(ip);
        manager.on_connection_close(ip);

        tokio::time::sleep(Duration::from_millis(1200)).await;
        let all = manager.get_all_devices();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].active_connections(), 1);

        manager.on_connection_close(ip);
        tokio::time::sleep(Duration::from_millis(2200)).await;
        assert!(manager.get_all_devices().is_empty());
    }

    #[tokio::test]
    async fn current_session_duration_is_zero_when_offline() {
        let manager = DeviceManager::new(
            new_test_store().await,
            Duration::from_secs(10),
            Duration::from_millis(200),
        )
        .await;
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 11));

        manager.on_connection_open(ip);
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let online_info = manager.get_device(ip).unwrap();
        assert!(online_info.current_session_online_seconds() >= 1);

        manager.on_connection_close(ip);
        let offline_info = manager.get_device(ip).unwrap();
        assert_eq!(offline_info.current_session_online_seconds(), 0);
    }
}
