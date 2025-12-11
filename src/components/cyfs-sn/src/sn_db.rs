// 0. 基于sqlite3作为数据库
// 1.批量产生未使用的激活码，激活码是32byte的随机字符串
// 2.提供注册接口，输入激活码，用户名，和一个用户提供的公钥。注册成功激活码会使用
//    用户名必须是全站唯一的，如果用户名被使用则返回注册失败。
// 3.提供用户设备信息的注册/更新/查询接口，设备信息包括设备的owner用户名,设备名，设备的did,设备的最新ip,以及字符串描述的设备信息，并保存有设备的创建时间和设备信息最后更新时间
#[allow(dead_code)]
use rusqlite::{params, Connection, OptionalExtension, Result};
use rand::Rng;
use std::{path::PathBuf, time::{SystemTime, UNIX_EPOCH}};
use log::*;
use serde_json;

use tokio::sync::Mutex;
use std::sync::Arc;
use lazy_static::lazy_static;

// global
lazy_static! {
    pub static ref GLOBAL_SN_DB: Arc<Mutex<SnDB>> = Arc::new(Mutex::new(
        SnDB::new().unwrap()));
}

pub struct SnDB {
    pub conn: Connection,
}

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

impl SnDB {
    pub fn new() -> Result<SnDB> {
        //获得当前可执行文件所在的目录
        let base_dir = PathBuf::from(std::env::current_exe().unwrap().parent().unwrap());
        let db_path = base_dir.join("sn_db.sqlite3");
        let conn = Connection::open(db_path);
        if conn.is_err() {
            let err = conn.err().unwrap();
            error!("Failed to open sn_db.sqlite3 {}", err.to_string());
            return Err(err);
        }
        let conn = conn.unwrap();
        Ok(SnDB {
            conn,
        })
    }

    pub fn new_by_path(path: &str) -> Result<SnDB> {
        let conn = Connection::open(path);
        if conn.is_err() {
            let err = conn.err().unwrap();
            error!("Failed to open sn_db.sqlite3 {}", err.to_string());
            return Err(err);
        }
        let conn = conn.unwrap();
        Ok(SnDB {
            conn,
        })
    }

    pub fn get_activation_codes(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare("SELECT code FROM activation_codes WHERE used = 0")?;
        let codes: Vec<String> = stmt.query_map([], |row| {
            row.get(0)
        })?
        .filter_map(|result| result.ok())
        .collect();
        Ok(codes)
    }
    
    pub fn insert_activation_code(&self, code: &str) -> Result<()> {
        let mut stmt = self.conn.prepare("INSERT INTO activation_codes (code, used) VALUES (?1, 0)")?;
        stmt.execute(params![code])?;
        Ok(()) 
    }

    pub fn generate_activation_codes(&self, count: usize) -> Result<Vec<String>> {
        let mut codes: Vec<String> = Vec::new();
        let mut stmt = self.conn.prepare("INSERT INTO activation_codes (code, used) VALUES (?1, 0)")?;
        for _ in 0..count {
            let code: String = rand::rng().random_range(0..1000000).to_string();
            codes.push(code.clone());
            stmt.execute(params![code])?;
        }
        Ok(codes)
    }

    pub fn check_active_code(&self, active_code: &str) -> Result<bool> {
        let mut stmt = self.conn.prepare("SELECT used FROM activation_codes WHERE code =?1")?;
        let used : Result<Option<i32>, rusqlite::Error> = stmt.query_row(params![active_code], |row| row.get(0));
        if used.is_err() {
            return Ok(false);
        }
        let used = used.unwrap();
        Ok(used.unwrap() == 0)
    }

    pub fn register_user(&self, active_code: &str, username: &str, public_key: &str, zone_config: &str, user_domain: Option<String>) -> Result<bool> {
        self.register_user_with_sn_ips(active_code, username, public_key, zone_config, user_domain, None)
    }
    
    pub fn register_user_with_sn_ips(&self, active_code: &str, username: &str, public_key: &str, zone_config: &str, user_domain: Option<String>, sn_ips: Option<String>) -> Result<bool> {
        let mut stmt = self.conn.prepare("SELECT used FROM activation_codes WHERE code =?1")?;
        let used: Option<i32> = stmt.query_row(params![active_code], |row| row.get(0))?;
        if let Some(0) = used {
            let mut stmt = self.conn.prepare("INSERT INTO users (username, state, public_key, activation_code, zone_config, user_domain, sn_ips) VALUES (?1,?2,?3,?4,?5,?6,?7)")?;   
            stmt.execute(params![username, UserState::Active.to_string(), public_key, active_code, zone_config, user_domain, sn_ips])?;    
            let mut stmt = self.conn.prepare("UPDATE activation_codes SET used = 1 WHERE code =?1")?;   
            stmt.execute(params![active_code])?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    pub fn is_user_exist(&self, username: &str) -> Result<bool> {
        let mut stmt = self.conn.prepare("SELECT COUNT(*) FROM users WHERE username =?1")?;
        let count: Option<i32> = stmt.query_row(params![username], |row| row.get(0))?;
        Ok(count.unwrap_or(0) > 0)
    }
    pub fn update_user_zone_config(&self, username: &str, zone_config: &str) -> Result<()> {
        let mut stmt = self.conn.prepare("UPDATE users SET zone_config =?1 WHERE username =?2")?;
        stmt.execute(params![zone_config, username])?;
        Ok(())
    }
    
    pub fn update_user_sn_ips(&self, username: &str, sn_ips: &str) -> Result<()> {
        let mut stmt = self.conn.prepare("UPDATE users SET sn_ips =?1 WHERE username =?2")?;
        stmt.execute(params![sn_ips, username])?;
        Ok(())
    }

    pub fn update_user_self_cert(&self, username: &str, self_cert: bool) -> Result<()> {
        let mut stmt = self.conn.prepare("UPDATE users SET self_cert =?1 WHERE username =?2")?;
        stmt.execute(params![self_cert, username])?;
        Ok(())
    }
    
    pub fn get_user_sn_ips(&self, username: &str) -> Result<Option<String>> {
        let mut stmt = self.conn.prepare("SELECT sn_ips FROM users WHERE username =?1")?;
        let sn_ips = stmt.query_row(params![username], |row| row.get(0)).optional()?;
        Ok(sn_ips)
    }
    
    pub fn get_user_sn_ips_as_vec(&self, username: &str) -> Result<Option<Vec<String>>> {
        if let Some(sn_ips_str) = self.get_user_sn_ips(username)? {
            if sn_ips_str.is_empty() {
                return Ok(Some(Vec::new()));
            }
            match serde_json::from_str::<Vec<String>>(&sn_ips_str) {
                Ok(ips) => Ok(Some(ips)),
                Err(_) => {
                    // 如果 JSON 解析失败，尝试作为逗号分隔的字符串解析
                    let ips: Vec<String> = sn_ips_str.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    Ok(Some(ips))
                }
            }
        } else {
            Ok(None)
        }
    }
    
    pub fn set_user_sn_ips_from_vec(&self, username: &str, ips: &[String]) -> Result<()> {
        let sn_ips_json = serde_json::to_string(ips).map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))?;
        self.update_user_sn_ips(username, &sn_ips_json)
    }
    
    pub fn add_user_sn_ip(&self, username: &str, ip: &str) -> Result<()> {
        let mut current_ips = self.get_user_sn_ips_as_vec(username)?.unwrap_or_default();
        if !current_ips.contains(&ip.to_string()) {
            current_ips.push(ip.to_string());
            self.set_user_sn_ips_from_vec(username, &current_ips)?;
        }
        Ok(())
    }
    
    pub fn remove_user_sn_ip(&self, username: &str, ip: &str) -> Result<()> {
        let mut current_ips = self.get_user_sn_ips_as_vec(username)?.unwrap_or_default();
        current_ips.retain(|x| x != ip);
        self.set_user_sn_ips_from_vec(username, &current_ips)
    }

    pub fn get_user_info(&self, username: &str) -> Result<Option<SNUserInfo>> {
        let mut stmt = self.conn.prepare("SELECT state, public_key, zone_config, self_cert, user_domain, sn_ips FROM users WHERE username =?1")?;
        let user_info = stmt.query_row(params![username], |row| {
            let state_str: Option<String> = row.get(0)?;
            let self_cert: Option<i32> = row.get(3)?;
            Ok(SNUserInfo {
                username: None,
                state: UserState::from_str(state_str.as_deref()),
                public_key: row.get(1)?,
                zone_config: row.get(2)?,
                self_cert: self_cert.unwrap_or(0) != 0,
                user_domain: row.get(4)?,
                sn_ips: row.get(5)?,
            })
        }) 
        .optional()?;
        Ok(user_info)
    }

    pub fn register_device(&self, username: &str, device_name: &str, did: &str, mini_config_jwt: &str, ip: &str, description: &str) -> Result<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut stmt = self.conn.prepare("INSERT INTO devices (owner, device_name, did, ip, description, mini_config_jwt, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)")?;
        stmt.execute(params![username, device_name, did, ip, description, mini_config_jwt, now, now])?;
        Ok(())  
    }
    pub fn update_device_by_did(&self, did: &str, ip: &str, description: &str) -> Result<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut stmt = self.conn.prepare("UPDATE devices SET ip =?1, description =?2, updated_at =?3 WHERE did =?4")?;
        stmt.execute(params![ip, description, now, did])?;
        Ok(())  
    }
    pub fn update_device_by_name(&self, username: &str, device_name: &str, did: &str, mini_config_jwt: &str,ip: &str, description: &str) -> Result<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();  
        let mut stmt = self.conn.prepare("UPDATE devices SET did =?1, mini_config_jwt =?2, ip =?3, description =?4, updated_at =?5 WHERE device_name =?6 AND owner =?7")?;    
        stmt.execute(params![did, mini_config_jwt, ip, description, now, device_name, username])?;
        Ok(())
    }
    pub fn update_device_info_by_name(&self, username: &str, device_name: &str,ip: &str, description: &str) -> Result<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();  
        let mut stmt = self.conn.prepare("UPDATE devices SET ip =?1, description =?2, updated_at =?3 WHERE device_name =?4 AND owner =?5")?;    
        stmt.execute(params![ip, description, now, device_name, username])?;
        Ok(())
    }
    pub fn query_device_by_name(&self, username: &str, device_name: &str) -> Result<Option<SNDeviceInfo>> {
        let mut stmt = self.conn.prepare("SELECT owner, device_name, mini_config_jwt, did, ip, description, created_at, updated_at FROM devices WHERE device_name =?1 AND owner =?2")?;
        let device_info = stmt.query_row(params![device_name, username], |row| {
            Ok(SNDeviceInfo {
                owner: row.get(0)?,
                device_name: row.get(1)?,
                mini_config_jwt: row.get(2)?,
                did: row.get(3)?,
                ip: row.get(4)?,
                description: row.get(5)?,
                created_at: row.get(6)?,
                updated_at: row.get(7)?,
            })
        })
        .optional()?;
        Ok(device_info)
    }
    pub fn query_device_by_did(&self, did: &str) -> Result<Option<SNDeviceInfo>> {
        let mut stmt = self.conn.prepare("SELECT owner, device_name, mini_config_jwt, did, ip, description, created_at, updated_at FROM devices WHERE did =?1")?;
        let device_info = stmt.query_row(params![did], |row| {
            Ok(SNDeviceInfo {
                owner: row.get(0)?,
                device_name: row.get(1)?,
                mini_config_jwt: row.get(2)?,
                did: row.get(3)?,
                ip: row.get(4)?,
                description: row.get(5)?,
                created_at: row.get(6)?,
                updated_at: row.get(7)?,
            })
        })
       .optional()?;
        Ok(device_info)
    }

    pub fn initialize_database(&self) -> Result<()> {
        let mut stmt = self.conn.prepare("CREATE TABLE IF NOT EXISTS activation_codes (code TEXT PRIMARY KEY, used INTEGER)")?;
        stmt.execute([])?;
        let mut stmt = self.conn.prepare("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, state TEXT, public_key TEXT, activation_code TEXT, zone_config TEXT, self_cert boolean, user_domain TEXT, sn_ips TEXT)")?;   
        stmt.execute([])?; 
        let mut stmt = self.conn.prepare("CREATE TABLE IF NOT EXISTS devices (owner TEXT, device_name TEXT, did TEXT PRIMARY KEY, ip TEXT, description TEXT, mini_config_jwt TEXT, created_at INTEGER, updated_at INTEGER)")?;
        stmt.execute([])?;
        Ok(())
    }
    pub fn get_user_info_by_domain(&self, domain: &str) -> Result<Option<SNUserInfo>> {
        let mut stmt = self.conn.prepare("SELECT username, state, public_key, zone_config, self_cert, user_domain, sn_ips FROM users WHERE ? = user_domain OR ? LIKE '%.' || user_domain")?;
        let user_info = stmt.query_row(params![domain, domain], |row| {
            let state_str: Option<String> = row.get(1)?;
            let self_cert: Option<i32> = row.get(4)?;
            Ok(SNUserInfo {
                username: Some(row.get(0)?),
                state: UserState::from_str(state_str.as_deref()),
                public_key: row.get(2)?,
                zone_config: row.get(3)?,
                self_cert: self_cert.unwrap_or(0) != 0,
                user_domain: row.get(5)?,
                sn_ips: row.get(6)?,
            })
        }).optional()?;
        Ok(user_info)
    }

    pub fn query_device(&self, did: &str) -> Result<Option<SNDeviceInfo>> {
        let mut stmt = self.conn.prepare("SELECT owner, device_name, mini_config_jwt, did, ip, description, created_at, updated_at FROM devices WHERE did = ?1")?;
        let device_info = stmt.query_row(params![did], |row| {
            Ok(SNDeviceInfo {
                owner: row.get(0)?,
                device_name: row.get(1)?,
                mini_config_jwt: row.get(2)?,
                did: row.get(3)?,
                ip: row.get(4)?,
                description: row.get(5)?,
                created_at: row.get(6)?,
                updated_at: row.get(7)?,
            })
        }).optional()?;
        Ok(device_info)
    }

}


#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_main() -> Result<()> {
        //let tmp_dir = std::env::temp_dir();
        let base_dir = std::env::temp_dir();
        let db_path = base_dir.join("sn_db.sqlite3");
        let _ = std::fs::remove_file(db_path.clone());
        println!("db_path: {}",db_path.to_str().unwrap());
        //remove db file
        let db_path_str = db_path.to_str().unwrap();


        let db = SnDB::new_by_path(db_path_str)?;
        db.initialize_database()?;
        let codes = db.generate_activation_codes(100)?;
        println!("codes: {:?}", codes);
        // Example usage
        println!("codes: {:?}", codes);
        let first_code = codes.first().unwrap();

        
        let registration_success = db.register_user(first_code.as_str(), 
            "lzc", "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8", 
            "eyJhbGciOiJFZERTQSJ9.eyJkaWQiOiJkaWQ6ZW5zOmx6YyIsIm9vZHMiOlsib29kMSJdLCJzbiI6IndlYjMuYnVja3lvcy5pbyIsImV4cCI6MjA0NDgyMzMzNn0.Xqd-4FsDbqZt1YZOIfduzsJik5UZmuylknMiAxLToB2jBBzHHccn1KQptLhhyEL5_Y-89YihO9BX6wO7RoqABw", Some("www.zhicong.me".to_string()))?;
        if registration_success {
            println!("User registered successfully.");
            
            // 设置初始的 sn_ips
            db.set_user_sn_ips_from_vec("lzc", &vec!["70.221.32.12".to_string()])?;
            println!("Set initial sn_ips for user");
        } else {
            println!("Registration failed.");
        }
        
        // 测试 sn_ips 功能
        if let Some(sn_ips) = db.get_user_sn_ips("lzc")? {
            println!("User sn_ips: {}", sn_ips);
        }
        
        if let Some(ips_vec) = db.get_user_sn_ips_as_vec("lzc")? {
            println!("User sn_ips as vec: {:?}", ips_vec);
        }
        
        // 添加新的 IP
        db.add_user_sn_ip("lzc", "192.168.1.100")?;
        println!("Added new IP to user");
        
        if let Some(ips_vec) = db.get_user_sn_ips_as_vec("lzc")? {
            println!("User sn_ips after adding: {:?}", ips_vec);
        }
        
        // 移除 IP
        db.remove_user_sn_ip("lzc", "70.221.32.12")?;
        println!("Removed IP from user");
        
        if let Some(ips_vec) = db.get_user_sn_ips_as_vec("lzc")? {
            println!("User sn_ips after removing: {:?}", ips_vec);
        }
        
        // 测试更新用户 self_cert 字段
        println!("\n=== Test update_user_self_cert ===");
        db.update_user_self_cert("lzc", true)?;
        println!("Updated user self_cert to true");
        
        if let Some(user_info) = db.get_user_info("lzc")? {
            println!("Self cert after update: {}", user_info.self_cert);
            assert_eq!(user_info.self_cert, true, "self_cert should be true");
        }
        
        // 测试设备注册和查询
        let device_info_str =r#"{"hostname":"ood1","device_type":"ood","did":"did:dev:gubVIszw-u_d5PVTh-oc8CKAhM9C-ne5G_yUK5BDaXc","ip":"192.168.1.86","sys_hostname":"LZC-USWORK","base_os_info":"Ubuntu 22.04 5.15.153.1-microsoft-standard-WSL2","cpu_info":"AMD Ryzen 7 5800X 8-Core Processor @ 3800 MHz","cpu_usage":0.0,"total_mem":67392299008,"mem_usage":5.7286677}"#;
        println!("\ndevice_info_str: {}",device_info_str);
        let mini_config_jwt = "eyJhbGciOiJFZERTQSJ9.eyJkaWQiOiJkaWQ6ZGV2Om9vZDEiLCJvd25lciI6ImRpZDplbnM6bHpjIiwiZXhwIjoyMDQ0ODIzMzM2fQ.test_signature";
        db.register_device( "lzc", "ood1", "did:dev:gubVIszw-u_d5PVTh-oc8CKAhM9C-ne5G_yUK5BDaXc", mini_config_jwt, "192.168.1.188", device_info_str)?;
        
        // 测试使用 SNDeviceInfo 结构体
        if let Some(device_info) = db.query_device("did:dev:gubVIszw-u_d5PVTh-oc8CKAhM9C-ne5G_yUK5BDaXc")? {
            println!("\n=== Device Info (by DID) ===");
            println!("Device info: {:?}", device_info);
            println!("Device owner: {}", device_info.owner);
            println!("Device name: {}", device_info.device_name);
            println!("Device DID: {}", device_info.did);
            println!("Device mini_config_jwt: {}", device_info.mini_config_jwt);
            println!("Device IP: {}", device_info.ip);
            println!("Device created_at: {}", device_info.created_at);
            println!("Device updated_at: {}", device_info.updated_at);
        } else {
            println!("Device not found.");
        }
        
        // 测试通过设备名查询
        if let Some(device_info) = db.query_device_by_name("lzc", "ood1")? {
            println!("\n=== Device Info (by name) ===");
            println!("Query device by name - owner: {}, did: {}", device_info.owner, device_info.did);
            println!("Mini config JWT: {}", device_info.mini_config_jwt);
        }
        
        // 测试更新设备信息（包括 did 和 mini_config_jwt）
        println!("\n=== Test update_device_by_name ===");
        let updated_device_info_str =r#"{"hostname":"ood1","device_type":"ood","did":"did:dev:gubVIszw-u_d5PVTh-oc8CKAhM9C-ne5G_yUK5BDaXc","ip":"192.168.1.100","sys_hostname":"LZC-USWORK-UPDATED","base_os_info":"Ubuntu 22.04","cpu_info":"AMD Ryzen 7 5800X","cpu_usage":1.5,"total_mem":67392299008,"mem_usage":6.0}"#;
        let updated_did = "did:dev:gubVIszw-u_d5PVTh-oc8CKAhM9C-ne5G_yUK5BDaXc-updated";
        let updated_mini_config_jwt = "eyJhbGciOiJFZERTQSJ9.eyJkaWQiOiJkaWQ6ZGV2Om9vZDEiLCJvd25lciI6ImRpZDplbnM6bHpjIiwiZXhwIjoyMDQ0ODIzMzM2fQ.updated_signature";
        db.update_device_by_name("lzc", "ood1", updated_did, updated_mini_config_jwt, "192.168.1.200", updated_device_info_str)?;
        println!("Updated device by name with new DID, mini_config_jwt, IP and description");
        
        if let Some(device_info) = db.query_device_by_name("lzc", "ood1")? {
            println!("Updated device DID: {}", device_info.did);
            println!("Updated device IP: {}", device_info.ip);
            println!("Updated mini_config_jwt: {}", device_info.mini_config_jwt);
            assert_eq!(device_info.did, updated_did, "DID should be updated");
            assert_eq!(device_info.ip, "192.168.1.200", "IP should be updated");
            assert_eq!(device_info.mini_config_jwt, updated_mini_config_jwt, "mini_config_jwt should be updated");
        }
        
        // 测试使用 SNUserInfo 结构体 - 验证所有字段都被正确填充
        if let Some(user_info) = db.get_user_info("lzc")? {
            println!("\n=== User Info (by username) - Final State ===");
            println!("User info: {:?}", user_info);
            println!("State: {:?}", user_info.state);
            println!("Public key: {}", user_info.public_key);
            println!("Zone config: {}", user_info.zone_config);
            println!("Self cert: {} (should be true after update)", user_info.self_cert);
            assert_eq!(user_info.self_cert, true, "self_cert should be true after update");
            if let Some(domain) = &user_info.user_domain {
                println!("User domain: {}", domain);
            }
            if let Some(sn_ips) = &user_info.sn_ips {
                println!("SN IPs: {}", sn_ips);
            }
        }
        
        // 测试通过域名查询用户信息 - 验证所有字段都被正确填充
        if let Some(user_info) = db.get_user_info_by_domain("app1.www.zhicong.me")? {
            println!("\n=== User Info (by domain) ===");
            println!("User info by domain: {:?}", user_info);
            if let Some(username) = &user_info.username {
                println!("Username from domain query: {}", username);
            }
            println!("State: {:?}", user_info.state);
            println!("Public key from domain query: {}", user_info.public_key);
            println!("Zone config: {}", user_info.zone_config);
            println!("Self cert: {} (should be true)", user_info.self_cert);
            assert_eq!(user_info.self_cert, true, "self_cert should be true in domain query");
            if let Some(domain) = &user_info.user_domain {
                println!("User domain from query: {}", domain);
            }
            if let Some(sn_ips) = &user_info.sn_ips {
                println!("SN IPs from domain query: {}", sn_ips);
            }
        }

        Ok(())
    }
}
