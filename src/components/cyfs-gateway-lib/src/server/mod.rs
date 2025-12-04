mod http_server;
mod dns_server;
mod socks5_server;
mod server;
mod qa_server;
mod dir_server;
mod ndn_server;
mod acme_http_challenge_server;

use std::path::PathBuf;

pub use http_server::*;
pub use socks5_server::*;
pub use server::*;
pub use qa_server::*;
pub use dns_server::*;
pub use dir_server::*;
pub use ndn_server::*;
pub use acme_http_challenge_server::*;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ServerErrorCode {
    BindFailed,
    NotFound,
    InvalidConfig,
    InvalidParam,
    ProcessChainError,
    StreamError,
    TunnelError,
    InvalidTlsKey,
    InvalidTlsCert,
    InvalidData,
    IOError,
    BadRequest,
    UnknownServerType,
    EncodeError,
    DnsQueryError,
    InvalidDnsOpType,
    InvalidDnsMessageType,
    InvalidDnsRecordType,
    Rejected,
    AlreadyExists
}
pub type ServerResult<T> = sfo_result::Result<T, ServerErrorCode>;
pub type ServerError = sfo_result::Error<ServerErrorCode>;
pub use sfo_result::err as server_err;
pub use sfo_result::into_err as into_server_err;

pub fn get_gateway_main_config_dir() -> PathBuf {
    //get env CYFS_GATEWAY_CONFIG_PATH
    let config_path_str = std::env::var("CYFS_GATEWAY_CONFIG_PATH");
    if config_path_str.is_ok() {
        return PathBuf::from(config_path_str.unwrap());
    } else  {
        return buckyos_kit::get_buckyos_system_etc_dir();
    }
}

pub fn set_gateway_main_config_dir(path: &PathBuf) {
    // SAFETY: This function is typically called during application initialization
    // before any threads are spawned that might read this environment variable.
    unsafe {
        let mut real_path = path.to_string_lossy().to_string();
        if path.is_file() {
            real_path = path.parent().unwrap().to_string_lossy().to_string();
        }
        std::env::set_var("CYFS_GATEWAY_CONFIG_PATH", real_path);
    }
}

//will move to buckyos_kit
pub fn normalize_config_file_path(path: PathBuf,base_dir:&PathBuf) -> PathBuf {
    if path.is_relative() {
        let result_path = base_dir.join(path.clone());
        debug!("{:?} -> {:?}", path, result_path);
        return result_path;
    }
    debug!("{:?} -> {:?}", path, path);
    path
}

//will move to buckyos_kit
pub fn normalize_all_path_value_config(config:&mut serde_json::Value,base_dir:&PathBuf)  {
    if config.is_object() {
        for (key, value) in config.as_object_mut().unwrap() {
            if value.is_string() {
                if key.ends_with("path") {
                    //debug!("normalize_all_path_value_config: {:?} : {:?}", key, value);
                    let value_str = value.as_str().unwrap();
                    let value_path = normalize_config_file_path(PathBuf::from(value_str),base_dir);
                    *value = serde_json::Value::String(value_path.to_string_lossy().to_string());
                }
            } else {
                normalize_all_path_value_config(value,base_dir);
            }

        }
    }

    if config.is_array() {
        for value in config.as_array_mut().unwrap() {
            normalize_all_path_value_config(value,base_dir);
        }
    }

}


// normalize_all_path_value_config test case
mod test {
    use super::*;
    use buckyos_kit::init_logging;
    #[test]
    fn test_normalize_all_path_value_config() {
        unsafe {
            std::env::set_var("BUCKY_LOG", "debug");
        }
        init_logging("test_normalize_all_path_value_config",false);
        let config_str = r#"
        {
            "servers":[
                {
                    "type":"cyfs-warp",
                    "bind":"0.0.0.0",
                    "http_port":80,
                    "https_port":443,
                    "tls_only":1,
                    "tls": {
                        "cert_path": "cert.pem"
                    }
                }
            ],
            "path": "test.txt"
        }
        "#;
        let mut config: serde_json::Value = serde_json::from_str(config_str).unwrap();
        let base_dir = PathBuf::from("/opt/buckyos/etc");
        normalize_all_path_value_config(&mut config,&base_dir);
        assert_eq!(config.get("path").unwrap().as_str().unwrap().replace("\\","/"), "/opt/buckyos/etc/test.txt");
        assert_eq!(config.get("servers").unwrap().as_array().unwrap().get(0).unwrap().as_object().unwrap().get("tls").unwrap().as_object().unwrap().get("cert_path").unwrap().as_str().unwrap().replace("\\","/"), "/opt/buckyos/etc/cert.pem");
    }
}
