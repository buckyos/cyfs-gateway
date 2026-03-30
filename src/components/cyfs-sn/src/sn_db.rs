// 0. 基于sqlite3作为数据库
// 1.批量产生未使用的激活码，激活码是32byte的随机字符串
// 2.提供注册接口，输入激活码，用户名，和一个用户提供的公钥。注册成功激活码会使用
//    用户名必须是全站唯一的，如果用户名被使用则返回注册失败。
// 3.提供用户设备信息的注册/更新/查询接口，设备信息包括设备的owner用户名,设备名，设备的did,设备的最新ip,以及字符串描述的设备信息，并保存有设备的创建时间和设备信息最后更新时间
use crate::SnResult;

#[derive(Debug, Clone)]
pub enum UserState {
    Active,
    Suspended,
    Deleted,
    Banned,
}

impl ToString for UserState {
    fn to_string(&self) -> String {
        match self {
            UserState::Active => "active".to_string(),
            UserState::Suspended => "suspended".to_string(),
            UserState::Deleted => "deleted".to_string(),
            UserState::Banned => "banned".to_string(),
        }
    }
}

impl UserState {
    pub fn from_str(s: Option<&str>) -> Self {
        match s {
            Some("suspended") => UserState::Suspended,
            Some("deleted") => UserState::Deleted,
            Some("banned") => UserState::Banned,
            _ => UserState::Active, // 默认为 Active
        }
    }
}

#[derive(Debug, Clone)]
pub struct SNUserInfo {
    pub username: Option<String>,
    pub state: UserState,
    pub public_key: String,
    pub zone_config: String,
    pub self_cert: bool,
    pub user_domain: Option<String>,
    pub sn_ips: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SNDeviceInfo {
    pub owner: String,
    pub device_name: String,
    pub mini_config_jwt: String,
    pub did: String,
    pub ip: String,
    pub description: String,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone)]
pub struct SnClearStateResult {
    pub deleted_users: u64,
    pub deleted_devices: u64,
    pub deleted_domain_records: u64,
    pub deleted_did_documents: u64,
    pub activation_code_reset: bool,
}

#[derive(Debug, Clone)]
pub struct SnV2AuthInfo {
    pub username: String,
    pub password_hash: String,
    pub password_salt: String,
    pub password_algo: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub last_login_at: Option<u64>,
}

#[async_trait::async_trait]
pub trait SnDB: Send + Sync + 'static {
    async fn get_activation_codes(&self) -> SnResult<Vec<String>>;
    async fn insert_activation_code(&self, code: &str) -> SnResult<()>;
    async fn generate_activation_codes(&self, count: usize) -> SnResult<Vec<String>>;
    async fn check_active_code(&self, active_code: &str) -> SnResult<bool>;
    async fn clear_state_by_active_code(&self, active_code: &str) -> SnResult<SnClearStateResult>;
    async fn register_user(
        &self,
        active_code: &str,
        username: &str,
        public_key: &str,
        zone_config: &str,
        user_domain: Option<String>,
    ) -> SnResult<bool>;
    async fn register_user_with_sn_ips(
        &self,
        active_code: &str,
        username: &str,
        public_key: &str,
        zone_config: &str,
        user_domain: Option<String>,
        sn_ips: Option<String>,
    ) -> SnResult<bool>;
    async fn get_user_by_public_key(
        &self,
        public_key: &str,
    ) -> SnResult<Option<(String, String, Option<String>)>>;
    async fn register_user_directly(
        &self,
        username: &str,
        public_key: &str,
        zone_config: &str,
        user_domain: Option<String>,
    ) -> SnResult<bool>;
    async fn register_user_v2(
        &self,
        active_code: &str,
        username: &str,
        password_hash: &str,
        password_salt: &str,
        password_algo: &str,
    ) -> SnResult<bool>;
    async fn is_user_exist(&self, username: &str) -> SnResult<bool>;
    async fn update_user_public_key(&self, username: &str, public_key: &str) -> SnResult<()>;
    async fn update_user_zone_config(&self, username: &str, zone_config: &str) -> SnResult<()>;
    async fn update_user_sn_ips(&self, username: &str, sn_ips: &str) -> SnResult<()>;
    async fn update_user_self_cert(&self, username: &str, self_cert: bool) -> SnResult<()>;
    async fn update_user_domain(&self, username: &str, user_domain: Option<String>)
        -> SnResult<()>;
    async fn get_user_sn_ips(&self, username: &str) -> SnResult<Option<String>>;
    async fn get_user_sn_ips_as_vec(&self, username: &str) -> SnResult<Option<Vec<String>>>;
    async fn set_user_sn_ips_from_vec(&self, username: &str, ips: &[String]) -> SnResult<()>;
    async fn add_user_sn_ip(&self, username: &str, ip: &str) -> SnResult<()>;
    async fn remove_user_sn_ip(&self, username: &str, ip: &str) -> SnResult<()>;
    async fn get_user_info(&self, username: &str) -> SnResult<Option<SNUserInfo>>;
    async fn register_device(
        &self,
        username: &str,
        device_name: &str,
        did: &str,
        mini_config_jwt: &str,
        ip: &str,
        description: &str,
    ) -> SnResult<()>;
    async fn update_device_by_did(&self, did: &str, ip: &str, description: &str) -> SnResult<()>;
    async fn update_device_by_name(
        &self,
        username: &str,
        device_name: &str,
        did: &str,
        mini_config_jwt: &str,
        ip: &str,
        description: &str,
    ) -> SnResult<()>;
    async fn update_device_info_by_name(
        &self,
        username: &str,
        device_name: &str,
        ip: &str,
        description: &str,
    ) -> SnResult<()>;
    async fn query_device_by_name(
        &self,
        username: &str,
        device_name: &str,
    ) -> SnResult<Option<SNDeviceInfo>>;
    async fn list_user_devices(&self, username: &str) -> SnResult<Vec<SNDeviceInfo>>;
    async fn query_device_by_did(&self, did: &str) -> SnResult<Option<SNDeviceInfo>>;
    async fn get_user_info_by_domain(&self, domain: &str) -> SnResult<Option<SNUserInfo>>;
    async fn query_device(&self, did: &str) -> SnResult<Option<SNDeviceInfo>>;
    async fn add_user_domain(
        &self,
        username: &str,
        domain: &str,
        record_type: &str,
        record: &str,
        ttl: u32,
    ) -> SnResult<()>;
    async fn remove_user_domain(
        &self,
        username: &str,
        domain: &str,
        record_type: &str,
    ) -> SnResult<()>;
    async fn query_domain_record(
        &self,
        domain: &str,
        record_type: &str,
    ) -> SnResult<Option<(String, u32)>>;
    async fn query_domain_records(&self, domain: &str) -> SnResult<Vec<(String, String, u32)>>;
    async fn query_user_domain_records(
        &self,
        username: &str,
    ) -> SnResult<Vec<(String, String, String, u32)>>;
    async fn insert_user_did_document(
        &self,
        obj_id: &str,
        owner_user: &str,
        obj_name: &str,
        did_document: &str,
        doc_type: Option<&str>,
    ) -> SnResult<()>;
    async fn query_user_did_document(
        &self,
        owner_user: &str,
        obj_name: &str,
        doc_type: Option<&str>,
    ) -> SnResult<Option<(String, String, Option<String>)>>;
    async fn get_v2_auth(&self, username: &str) -> SnResult<Option<SnV2AuthInfo>>;
    async fn update_v2_last_login(&self, username: &str, last_login_at: u64) -> SnResult<()>;
}
pub type SnDBRef = std::sync::Arc<dyn SnDB>;
