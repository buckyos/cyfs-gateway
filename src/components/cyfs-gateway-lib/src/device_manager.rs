use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::task::JoinHandle;

#[derive(Clone)]
pub struct DeviceInfo {
    ip: IpAddr,
    mac: Option<String>,
    hostname: Option<String>,
    active_connections: u32,
    last_connected_at: u64,
    last_disconnected_at: Option<u64>,
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
}

struct DeviceState {
    ip: IpAddr,
    mac: Option<String>,
    hostname: Option<String>,
    active_connections: u32,
    last_connected_at: u64,
    last_disconnected_at: Option<u64>,
    probing: bool,
}

impl DeviceState {
    fn to_info(&self) -> DeviceInfo {
        DeviceInfo {
            ip: self.ip,
            mac: self.mac.clone(),
            hostname: self.hostname.clone(),
            active_connections: self.active_connections,
            last_connected_at: self.last_connected_at,
            last_disconnected_at: self.last_disconnected_at,
        }
    }
}

pub struct DeviceManager {
    devices: Mutex<HashMap<IpAddr, DeviceState>>,
    offline_timeout: Duration,
    cleanup_interval: Duration,
    cleanup_handle: Mutex<Option<JoinHandle<()>>>,
}

pub type DeviceManagerRef = Arc<DeviceManager>;

impl DeviceManager {
    pub fn new(offline_timeout: Duration, cleanup_interval: Duration) -> DeviceManagerRef {
        let manager = Arc::new(Self {
            devices: Mutex::new(HashMap::new()),
            offline_timeout,
            cleanup_interval,
            cleanup_handle: Mutex::new(None),
        });
        manager.start_cleanup_task();
        manager
    }

    pub fn on_connection_open(self: &Arc<Self>, ip: IpAddr) {
        let now = now_seconds();
        let need_probe = {
            let mut devices = self.devices.lock().unwrap();
            let state = devices.entry(ip).or_insert_with(|| DeviceState {
                ip,
                mac: None,
                hostname: None,
                active_connections: 0,
                last_connected_at: now,
                last_disconnected_at: None,
                probing: false,
            });
            state.active_connections = state.active_connections.saturating_add(1);
            state.last_connected_at = now;
            state.last_disconnected_at = None;

            let missing_info = state.mac.is_none() || state.hostname.is_none();
            if missing_info && !state.probing {
                state.probing = true;
                true
            } else {
                false
            }
        };

        if need_probe {
            let this = self.clone();
            tokio::spawn(async move {
                let mac = cyfs_lookup::lookup_mac(ip).await.ok().flatten();
                let hostname = cyfs_lookup::lookup_hostname(ip).await.ok().flatten();
                let mut devices = this.devices.lock().unwrap();
                if let Some(state) = devices.get_mut(&ip) {
                    if mac.is_some() {
                        state.mac = mac;
                    }
                    if hostname.is_some() {
                        state.hostname = hostname;
                    }
                    state.probing = false;
                }
            });
        }
    }

    pub fn on_connection_close(&self, ip: IpAddr) {
        let now = now_seconds();
        let mut devices = self.devices.lock().unwrap();
        if let Some(state) = devices.get_mut(&ip) {
            if state.active_connections > 0 {
                state.active_connections -= 1;
            }
            if state.active_connections == 0 {
                state.last_disconnected_at = Some(now);
            }
        }
    }

    pub fn get_all_devices(&self) -> Vec<DeviceInfo> {
        self.devices
            .lock()
            .unwrap()
            .values()
            .map(DeviceState::to_info)
            .collect()
    }

    pub fn get_device(&self, ip: IpAddr) -> Option<DeviceInfo> {
        self.devices
            .lock()
            .unwrap()
            .get(&ip)
            .map(DeviceState::to_info)
    }

    pub fn restore_from_snapshot(&self, snapshot: Vec<DeviceInfo>) {
        let mut restored = HashMap::new();

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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use super::DeviceManager;

    #[tokio::test]
    async fn offline_timeout_starts_after_last_connection_closed() {
        let manager = DeviceManager::new(Duration::from_secs(1), Duration::from_millis(200));
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
}
