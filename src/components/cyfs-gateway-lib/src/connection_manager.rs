use crate::{DeviceInfo, DeviceManagerRef, StackErrorCode, StackProtocol, StackResult, stack_err};
use cyfs_process_chain::*;
use sfo_io::{SfoSpeedStat, SpeedStat, SpeedTracker};
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, RwLock};
use tokio::task::{AbortHandle, JoinHandle};

pub type SpeedStatRef = Arc<dyn SpeedStat>;
pub type SpeedTrackerRef = Arc<dyn SpeedTracker>;

pub struct NoSpeedStat {
    write_stat: AtomicU64,
    read_stat: AtomicU64,
}

impl NoSpeedStat {
    pub fn new() -> Self {
        Self {
            write_stat: AtomicU64::new(0),
            read_stat: AtomicU64::new(0),
        }
    }
}

impl sfo_io::SpeedStat for NoSpeedStat {
    fn get_write_speed(&self) -> u64 {
        0
    }

    fn get_write_sum_size(&self) -> u64 {
        self.write_stat.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn get_read_speed(&self) -> u64 {
        0
    }

    fn get_read_sum_size(&self) -> u64 {
        self.read_stat.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl sfo_io::SpeedTracker for NoSpeedStat {
    fn add_write_data_size(&self, size: u64) {
        self.write_stat
            .fetch_add(size, std::sync::atomic::Ordering::Relaxed);
    }

    fn add_read_data_size(&self, size: u64) {
        self.read_stat
            .fetch_add(size, std::sync::atomic::Ordering::Relaxed);
    }
}

pub struct StatManager {
    speed_stats: RwLock<HashMap<String, SpeedTrackerRef>>,
}
pub type StatManagerRef = Arc<StatManager>;

impl StatManager {
    pub fn new() -> StatManagerRef {
        Arc::new(Self {
            speed_stats: RwLock::new(HashMap::new()),
        })
    }

    pub fn get_speed_stat(&self, id: &str) -> Option<SpeedTrackerRef> {
        self.speed_stats.read().unwrap().get(id).cloned()
    }

    fn get_or_create_speed_stat(&self, id: &str) -> SpeedTrackerRef {
        if let Some(stat_ref) = self.get_speed_stat(id) {
            stat_ref
        } else {
            let stat = Arc::new(NoSpeedStat::new());
            self.new_speed_stat(id, stat.clone());
            stat
        }
    }

    pub fn get_speed_stats(&self, ids: &[String]) -> Vec<SpeedTrackerRef> {
        let mut stats = Vec::with_capacity(ids.len());
        for id in ids.iter() {
            stats.push(self.get_or_create_speed_stat(id));
        }
        stats
    }

    pub fn new_speed_stat(&self, id: &str, speed_stat: SpeedTrackerRef) {
        self.speed_stats
            .write()
            .unwrap()
            .insert(id.to_string(), speed_stat);
    }
}

pub struct MutComposedSpeedStat {
    local_stat: Arc<SfoSpeedStat>,
    stats: RwLock<Vec<SpeedTrackerRef>>,
}
pub type MutComposedSpeedStatRef = Arc<MutComposedSpeedStat>;

impl MutComposedSpeedStat {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            local_stat: Arc::new(SfoSpeedStat::new()),
            stats: RwLock::new(Vec::new()),
        })
    }

    pub fn set_external_stats(&self, stats: Vec<SpeedTrackerRef>) {
        for stat in stats.iter() {
            stat.add_write_data_size(self.local_stat.get_write_sum_size());
            stat.add_read_data_size(self.local_stat.get_read_sum_size());
        }
        *self.stats.write().unwrap() = stats;
    }
}

impl sfo_io::SpeedStat for MutComposedSpeedStat {
    fn get_write_speed(&self) -> u64 {
        self.local_stat.get_write_speed()
    }

    fn get_write_sum_size(&self) -> u64 {
        self.local_stat.get_write_sum_size()
    }

    fn get_read_speed(&self) -> u64 {
        self.local_stat.get_read_speed()
    }

    fn get_read_sum_size(&self) -> u64 {
        self.local_stat.get_read_sum_size()
    }
}

impl sfo_io::SpeedTracker for MutComposedSpeedStat {
    fn add_write_data_size(&self, size: u64) {
        self.local_stat.add_write_data_size(size);
        for stat in self.stats.read().unwrap().iter() {
            stat.add_write_data_size(size);
        }
    }

    fn add_read_data_size(&self, size: u64) {
        self.local_stat.add_read_data_size(size);
        for stat in self.stats.read().unwrap().iter() {
            stat.add_read_data_size(size);
        }
    }
}

pub struct ComposedSpeedStat {
    local_stat: Arc<SfoSpeedStat>,
    stats: Vec<SpeedTrackerRef>,
}
pub type ComposedSpeedStatRef = Arc<ComposedSpeedStat>;

impl ComposedSpeedStat {
    pub fn new(stats: Vec<SpeedTrackerRef>) -> Arc<Self> {
        Arc::new(Self {
            local_stat: Arc::new(SfoSpeedStat::new()),
            stats,
        })
    }
}

impl sfo_io::SpeedStat for ComposedSpeedStat {
    fn get_write_speed(&self) -> u64 {
        self.local_stat.get_write_speed()
    }

    fn get_write_sum_size(&self) -> u64 {
        self.local_stat.get_write_sum_size()
    }

    fn get_read_speed(&self) -> u64 {
        self.local_stat.get_read_speed()
    }

    fn get_read_sum_size(&self) -> u64 {
        self.local_stat.get_read_sum_size()
    }
}

impl sfo_io::SpeedTracker for ComposedSpeedStat {
    fn add_write_data_size(&self, size: u64) {
        self.local_stat.add_write_data_size(size);
        for stat in self.stats.iter() {
            stat.add_write_data_size(size);
        }
    }

    fn add_read_data_size(&self, size: u64) {
        self.local_stat.add_read_data_size(size);
        for stat in self.stats.iter() {
            stat.add_read_data_size(size);
        }
    }
}

pub async fn get_stat_info(chain_env: EnvRef) -> StackResult<Vec<String>> {
    let stat = chain_env
        .get("STAT")
        .await
        .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;

    match stat {
        Some(CollectionValue::Set(set)) => {
            let stat_ids = set
                .get_all()
                .await
                .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
            Ok(stat_ids)
        }
        _ => Ok(vec![]),
    }
}

#[async_trait::async_trait]
pub trait ConnectionController: 'static + Send + Sync {
    fn stop_connection(&self);
    async fn wait_stop(&self);
    fn is_stopped(&self) -> bool;
}

pub type ConnectionControllerRef = Arc<dyn ConnectionController>;

pub struct HandleConnectionController {
    handle: Mutex<Option<JoinHandle<()>>>,
    abort_handle: AbortHandle,
}

impl HandleConnectionController {
    pub fn new(handle: JoinHandle<()>) -> Arc<Self> {
        let abort_handle = handle.abort_handle();
        Arc::new(Self {
            handle: Mutex::new(Some(handle)),
            abort_handle,
        })
    }
}

#[async_trait::async_trait]
impl ConnectionController for HandleConnectionController {
    fn stop_connection(&self) {
        self.abort_handle.abort();
    }

    async fn wait_stop(&self) {
        let handle = {
            let mut handle = self.handle.lock().unwrap();
            handle.take().unwrap()
        };
        let _ = handle.await;
    }

    fn is_stopped(&self) -> bool {
        self.abort_handle.is_finished()
    }
}

pub struct ConnectionInfo {
    source: String,
    destination: String,
    protocol: StackProtocol,
    speed_stat: SpeedStatRef,
    connection_controller: ConnectionControllerRef,
}

impl Drop for ConnectionInfo {
    fn drop(&mut self) {
        log::debug!("{} dropped", self.connection_id());
    }
}

impl ConnectionInfo {
    pub fn new(
        source: String,
        destination: String,
        protocol: StackProtocol,
        speed: SpeedStatRef,
        connection_controller: ConnectionControllerRef,
    ) -> Self {
        Self {
            source,
            destination,
            protocol,
            speed_stat: speed,
            connection_controller,
        }
    }

    pub fn source(&self) -> &str {
        self.source.as_str()
    }

    pub fn destination(&self) -> &str {
        self.destination.as_str()
    }

    pub fn protocol(&self) -> StackProtocol {
        self.protocol.clone()
    }

    pub fn get_upload_speed(&self) -> u64 {
        self.speed_stat.get_write_speed()
    }

    pub fn get_download_speed(&self) -> u64 {
        self.speed_stat.get_read_speed()
    }

    pub fn connection_id(&self) -> String {
        format!("{} -> {}", self.source, self.destination)
    }

    pub fn stop_connection(&self) {
        self.connection_controller.stop_connection();
    }

    pub fn is_aborted(&self) -> bool {
        self.connection_controller.is_stopped()
    }

    pub async fn wait(&self) {
        self.connection_controller.wait_stop().await
    }
}

pub struct ConnectionManager {
    connections: Mutex<BTreeMap<String, Arc<ConnectionInfo>>>,
    device_manager: RwLock<Option<DeviceManagerRef>>,
}
pub type ConnectionManagerRef = Arc<ConnectionManager>;

impl ConnectionManager {
    pub fn new() -> ConnectionManagerRef {
        Arc::new(Self {
            connections: Mutex::new(BTreeMap::new()),
            device_manager: RwLock::new(None),
        })
    }

    pub fn set_device_manager(&self, device_manager: DeviceManagerRef) {
        let snapshot = self
            .device_manager
            .read()
            .unwrap()
            .as_ref()
            .map(|manager| manager.get_all_devices())
            .unwrap_or_default();

        device_manager.restore_from_snapshot(snapshot);
        *self.device_manager.write().unwrap() = Some(device_manager);
    }

    pub fn remove_device_manager(&self) {
        *self.device_manager.write().unwrap() = None;
    }

    pub fn add_connection(self: &Arc<Self>, info: ConnectionInfo) {
        let info = Arc::new(info);
        let connection_id = info.connection_id();
        let source_ip = parse_source_ip(info.source());
        if let Some(ip) = source_ip
            && let Some(device_manager) = self.device_manager.read().unwrap().clone()
        {
            device_manager.on_connection_open(ip);
        }

        let replaced_ip = {
            let mut connections = self.connections.lock().unwrap();
            let replaced = connections.insert(connection_id.clone(), info.clone());
            replaced.and_then(|old| parse_source_ip(old.source()))
        };
        if let Some(ip) = replaced_ip
            && let Some(device_manager) = self.device_manager.read().unwrap().clone()
        {
            device_manager.on_connection_close(ip);
        }

        let this = self.clone();
        tokio::spawn(async move {
            info.wait().await;
            let removed_ip = {
                let mut connections = this.connections.lock().unwrap();
                match connections.get(&connection_id) {
                    Some(current) if Arc::ptr_eq(current, &info) => connections
                        .remove(&connection_id)
                        .and_then(|old| parse_source_ip(old.source())),
                    _ => None,
                }
            };
            if let Some(ip) = removed_ip
                && let Some(device_manager) = this.device_manager.read().unwrap().clone()
            {
                device_manager.on_connection_close(ip);
            }
        });
    }

    pub fn stop_all_connections(self: &Arc<Self>) {
        for info in self.connections.lock().unwrap().values() {
            info.stop_connection();
        }
    }

    pub fn get_connection_info(&self, id: &str) -> Option<Arc<ConnectionInfo>> {
        self.connections.lock().unwrap().get(id).cloned()
    }

    pub fn get_all_connection_info(&self) -> Vec<Arc<ConnectionInfo>> {
        self.connections.lock().unwrap().values().cloned().collect()
    }

    pub fn get_all_connection_device_info(&self) -> Vec<DeviceInfo> {
        let device_manager = self.device_manager.read().unwrap().clone();
        if let Some(device_manager) = device_manager {
            device_manager.get_all_devices()
        } else {
            Vec::new()
        }
    }

    pub fn get_device_info_by_source(&self, source: IpAddr) -> Option<DeviceInfo> {
        let device_manager = self.device_manager.read().unwrap().clone()?;
        device_manager.get_device(source)
    }
}

fn parse_source_ip(source: &str) -> Option<IpAddr> {
    if let Ok(addr) = source.parse::<SocketAddr>() {
        return Some(addr.ip());
    }
    source.parse::<IpAddr>().ok()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{DeviceManager, DeviceOnlineStoreRef, SqliteDeviceOnlineStore};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio;

    async fn new_test_store() -> DeviceOnlineStoreRef {
        let db_path = std::env::temp_dir().join(format!(
            "cyfs_gateway_device_online_conn_{}_{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|v| v.as_nanos())
                .unwrap_or(0)
        ));
        let store = SqliteDeviceOnlineStore::new(db_path).await.unwrap();
        Arc::new(store)
    }

    pub struct MockSpeedStat {
        write_speed: AtomicU64,
        read_speed: AtomicU64,
    }

    impl MockSpeedStat {
        fn new() -> Self {
            Self {
                write_speed: AtomicU64::new(0),
                read_speed: AtomicU64::new(0),
            }
        }

        fn add_read_speed(&self, speed: u64) {
            self.read_speed.store(speed, Ordering::Relaxed);
        }

        fn add_write_speed(&self, speed: u64) {
            self.write_speed.store(speed, Ordering::Relaxed);
        }
    }
    impl SpeedStat for MockSpeedStat {
        fn get_write_speed(&self) -> u64 {
            self.write_speed.load(Ordering::Relaxed)
        }

        fn get_write_sum_size(&self) -> u64 {
            0
        }

        fn get_read_speed(&self) -> u64 {
            self.read_speed.load(Ordering::Relaxed)
        }

        fn get_read_sum_size(&self) -> u64 {
            0
        }
    }

    #[tokio::test]
    async fn test_connection_info_creation() {
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9090);
        let protocol = StackProtocol::Tcp;
        let speed = Arc::new(MockSpeedStat::new());
        speed.add_write_speed(100);
        speed.add_read_speed(200);
        let handle = tokio::spawn(async {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        });

        let controller = HandleConnectionController::new(handle);
        let connection_info = ConnectionInfo::new(
            source.to_string(),
            destination.to_string(),
            protocol,
            speed,
            controller,
        );

        assert_eq!(connection_info.source(), source.to_string());
        assert_eq!(connection_info.destination(), destination.to_string());
        assert_eq!(connection_info.protocol(), StackProtocol::Tcp);
        assert_eq!(connection_info.get_upload_speed(), 100);
        assert_eq!(connection_info.get_download_speed(), 200);
        assert_eq!(
            connection_info.connection_id(),
            "127.0.0.1:8080 -> 127.0.0.1:9090"
        );
    }

    #[tokio::test]
    async fn test_connection_manager_add_and_get_connection() {
        let manager = ConnectionManager::new();
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9090);
        let protocol = StackProtocol::Tcp;
        let speed = Arc::new(MockSpeedStat::new());
        let handle = tokio::spawn(async {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        });

        let controller = HandleConnectionController::new(handle);
        let connection_info = ConnectionInfo::new(
            source.to_string(),
            destination.to_string(),
            protocol,
            speed,
            controller,
        );
        let connection_id = connection_info.connection_id();

        manager.add_connection(connection_info);

        let retrieved_info = manager.get_connection_info(&connection_id);
        assert!(retrieved_info.is_some());
        assert_eq!(retrieved_info.unwrap().connection_id(), connection_id);
    }

    #[tokio::test]
    async fn test_connection_manager_get_all_connections() {
        let manager = ConnectionManager::new();
        let source1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let destination1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9090);
        let protocol1 = StackProtocol::Tcp;
        let speed1 = Arc::new(MockSpeedStat::new());
        let handle1 = tokio::spawn(async {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        });

        let source2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);
        let destination2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9091);
        let protocol2 = StackProtocol::Udp;
        let speed2 = Arc::new(MockSpeedStat::new());
        let handle2 = tokio::spawn(async {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        });

        let controller1 = HandleConnectionController::new(handle1);
        let controller2 = HandleConnectionController::new(handle2);
        let connection_info1 = ConnectionInfo::new(
            source1.to_string(),
            destination1.to_string(),
            protocol1,
            speed1,
            controller1,
        );
        let connection_info2 = ConnectionInfo::new(
            source2.to_string(),
            destination2.to_string(),
            protocol2,
            speed2,
            controller2,
        );

        manager.add_connection(connection_info1);
        manager.add_connection(connection_info2);

        let all_connections = manager.get_all_connection_info();
        assert_eq!(all_connections.len(), 2);
    }

    #[tokio::test]
    async fn test_connection_stop() {
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9090);
        let protocol = StackProtocol::Tcp;
        let speed = Arc::new(MockSpeedStat::new());

        let handle = tokio::spawn(async {
            // 一个长时间运行的任务
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
        });

        let controller = HandleConnectionController::new(handle);
        let connection_info = ConnectionInfo::new(
            source.to_string(),
            destination.to_string(),
            protocol,
            speed,
            controller,
        );
        assert!(!connection_info.is_aborted());

        connection_info.stop_connection();
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        assert!(connection_info.is_aborted());
    }

    #[tokio::test]
    async fn test_connection_manager_stop_all() {
        let manager = ConnectionManager::new();
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9090);
        let protocol = StackProtocol::Tcp;
        let speed = Arc::new(MockSpeedStat::new());

        let handle = tokio::spawn(async {
            // 一个长时间运行的任务
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
        });

        let controller = HandleConnectionController::new(handle);
        let connection_info = ConnectionInfo::new(
            source.to_string(),
            destination.to_string(),
            protocol,
            speed,
            controller,
        );
        let connection_id = connection_info.connection_id();

        manager.add_connection(connection_info);

        // 确保连接已添加
        assert!(manager.get_connection_info(&connection_id).is_some());

        manager.stop_all_connections();

        // 给一些时间让任务停止并被移除
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        assert!(manager.get_connection_info(&connection_id).is_none());
    }

    #[tokio::test]
    async fn test_set_device_manager_keeps_current_devices() {
        let manager = ConnectionManager::new();
        let first_device_manager = DeviceManager::new(
            new_test_store().await,
            tokio::time::Duration::from_secs(60),
            tokio::time::Duration::from_secs(60),
        )
        .await;
        manager.set_device_manager(first_device_manager);

        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)), 8080);
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9090);
        let protocol = StackProtocol::Tcp;
        let speed = Arc::new(MockSpeedStat::new());
        let handle = tokio::spawn(async {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        });
        let controller = HandleConnectionController::new(handle);
        manager.add_connection(ConnectionInfo::new(
            source.to_string(),
            destination.to_string(),
            protocol,
            speed,
            controller,
        ));

        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
        assert_eq!(manager.get_all_connection_device_info().len(), 1);

        let second_device_manager = DeviceManager::new(
            new_test_store().await,
            tokio::time::Duration::from_secs(60),
            tokio::time::Duration::from_secs(60),
        )
        .await;
        manager.set_device_manager(second_device_manager);

        let devices = manager.get_all_connection_device_info();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].ip(), source.ip());
        assert_eq!(devices[0].active_connections(), 1);

        manager.stop_all_connections();
    }
}
