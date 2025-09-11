#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use std::collections::{BTreeMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use sfo_io::SpeedStat;
use tokio::task::{AbortHandle, JoinHandle};
use crate::StackProtocol;

pub type SpeedStatRef = Arc<dyn SpeedStat>;

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
        self.protocol
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
}
pub type ConnectionManagerRef = Arc<ConnectionManager>;

impl ConnectionManager {
    pub fn new() -> ConnectionManagerRef {
        Arc::new(Self {
            connections: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn add_connection(self: &Arc<Self>, info: ConnectionInfo) {
        let info = Arc::new(info);
        self.connections.lock().unwrap().insert(info.connection_id(), info.clone());
        let this = self.clone();
        tokio::spawn(async move {
            info.wait().await;
            this.connections.lock().unwrap().remove(&info.connection_id());
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
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio;

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
        let connection_info = ConnectionInfo::new(source.to_string(), destination.to_string(), protocol, speed, controller);

        assert_eq!(connection_info.source(), source.to_string());
        assert_eq!(connection_info.destination(), destination.to_string());
        assert_eq!(connection_info.protocol(), StackProtocol::Tcp);
        assert_eq!(connection_info.get_upload_speed(), 100);
        assert_eq!(connection_info.get_download_speed(), 200);
        assert_eq!(connection_info.connection_id(), "127.0.0.1:8080 -> 127.0.0.1:9090");
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
        let connection_info = ConnectionInfo::new(source.to_string(), destination.to_string(), protocol, speed, controller);
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
        let connection_info1 = ConnectionInfo::new(source1.to_string(), destination1.to_string(), protocol1, speed1, controller1);
        let connection_info2 = ConnectionInfo::new(source2.to_string(), destination2.to_string(), protocol2, speed2, controller2);

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
        let connection_info = ConnectionInfo::new(source.to_string(), destination.to_string(), protocol, speed, controller);
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
        let connection_info = ConnectionInfo::new(source.to_string(), destination.to_string(), protocol, speed, controller);
        let connection_id = connection_info.connection_id();

        manager.add_connection(connection_info);

        // 确保连接已添加
        assert!(manager.get_connection_info(&connection_id).is_some());

        manager.stop_all_connections();

        // 给一些时间让任务停止并被移除
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        assert!(manager.get_connection_info(&connection_id).is_none());
    }
}
