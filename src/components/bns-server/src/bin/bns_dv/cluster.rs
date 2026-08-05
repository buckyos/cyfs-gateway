use std::collections::HashMap;
use std::path::Path;

use serde_json::{Map, Value};

type DynError = Box<dyn std::error::Error + Send + Sync>;

const CLUSTER_CONFIG_PATH: &str = "/etc/cluster_config/cluster_config.json";
const SECURITY_CONFIG_PATH: &str = "/etc/security/security_config.json";
const APP_ID: &str = "bns_dv";
const DATABASE_ROOT: &str = "/var/lib/bns-backend";
const JSON_SAFE_INTEGER_MAX: u64 = 9_007_199_254_740_991;
const SETTINGS_KEYS: [&str; 8] = [
    "contract",
    "chain_id",
    "db",
    "listen",
    "start_block",
    "confirmations",
    "interval_ms",
    "max_block_span",
];
const REQUIRED_SETTINGS_KEYS: [&str; 7] = [
    "contract",
    "chain_id",
    "db",
    "listen",
    "start_block",
    "confirmations",
    "interval_ms",
];

pub fn merge_cluster_serve_flags(
    command_line_flags: HashMap<String, String>,
) -> Result<HashMap<String, String>, DynError> {
    let cluster_config = read_json_config(CLUSTER_CONFIG_PATH, "Cluster Config")?;
    let security_config = read_json_config(SECURITY_CONFIG_PATH, "Security Config")?;
    let mut flags = cluster_serve_flags(&cluster_config, &security_config)?;
    flags.extend(command_line_flags);
    Ok(flags)
}

pub fn create_database_parent(db: &str) -> Result<(), DynError> {
    let path = Path::new(db);
    let Some(parent) = path.parent() else {
        return Err(format!("cannot determine parent directory for {db}").into());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(parent).map_err(|err| {
        format!(
            "failed to create database directory {}: {err}",
            parent.display()
        )
        .into()
    })
}

fn read_json_config(path: &str, label: &str) -> Result<Value, DynError> {
    let source = std::fs::read_to_string(path)
        .map_err(|err| format!("cannot read {label} at {path}: {err}"))?;
    serde_json::from_str(&source)
        .map_err(|err| format!("cannot parse {label} at {path}: {err}").into())
}

fn cluster_serve_flags(
    cluster_config: &Value,
    security_config: &Value,
) -> Result<HashMap<String, String>, DynError> {
    let cluster = json_object(cluster_config, "cluster config")?;
    let apps = json_member_object(cluster, "apps", "apps")?;
    let app_path = format!("apps.{APP_ID}");
    let app = json_member_object(apps, APP_ID, &app_path)?;
    let settings_path = format!("{app_path}.settings");
    let settings = json_member_object(app, "settings", &settings_path)?;

    let mut unknown_keys = settings
        .keys()
        .filter(|key| !SETTINGS_KEYS.contains(&key.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    unknown_keys.sort();
    if !unknown_keys.is_empty() {
        return invalid(format!(
            "{settings_path} contains unknown keys: {}",
            unknown_keys.join(", ")
        ));
    }
    for key in REQUIRED_SETTINGS_KEYS {
        if !settings.contains_key(key) {
            return invalid(format!("{settings_path}.{key} is missing"));
        }
    }

    let security = json_object(security_config, "security config")?;
    let rpc = rpc_url(json_member(
        security,
        "chain_rpc_url",
        "security.chain_rpc_url",
    )?)?;
    let contract = contract_address(setting(settings, &settings_path, "contract")?)?;
    let chain_id = setting_integer(settings, &settings_path, "chain_id", 1)?;
    let db = database_path(setting(settings, &settings_path, "db")?)?;
    let listen = listen_address(setting(settings, &settings_path, "listen")?)?;
    let start_block = setting_integer(settings, &settings_path, "start_block", 0)?;
    let confirmations = setting_integer(settings, &settings_path, "confirmations", 0)?;
    let interval_ms = setting_integer(settings, &settings_path, "interval_ms", 1)?;
    let max_block_span = match settings.get("max_block_span") {
        None | Some(Value::Null) => 500,
        Some(value) => integer(value, &format!("{settings_path}.max_block_span"), 1)?,
    };

    Ok(HashMap::from([
        ("rpc".to_string(), rpc),
        ("contract".to_string(), contract),
        ("chain-id".to_string(), chain_id.to_string()),
        ("db".to_string(), db),
        ("listen".to_string(), listen),
        ("start-block".to_string(), start_block.to_string()),
        ("confirmations".to_string(), confirmations.to_string()),
        ("interval-ms".to_string(), interval_ms.to_string()),
        ("max-block-span".to_string(), max_block_span.to_string()),
    ]))
}

fn json_object<'a>(value: &'a Value, path: &str) -> Result<&'a Map<String, Value>, DynError> {
    value
        .as_object()
        .ok_or_else(|| format!("invalid bns_dv configuration: {path} must be an object").into())
}

fn json_member<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<&'a Value, DynError> {
    object
        .get(key)
        .ok_or_else(|| format!("invalid bns_dv configuration: {path} is missing").into())
}

fn json_member_object<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<&'a Map<String, Value>, DynError> {
    json_object(json_member(object, key, path)?, path)
}

fn setting<'a>(
    settings: &'a Map<String, Value>,
    settings_path: &str,
    key: &str,
) -> Result<&'a Value, DynError> {
    json_member(settings, key, &format!("{settings_path}.{key}"))
}

fn setting_integer(
    settings: &Map<String, Value>,
    settings_path: &str,
    key: &str,
    minimum: u64,
) -> Result<u64, DynError> {
    integer(
        setting(settings, settings_path, key)?,
        &format!("{settings_path}.{key}"),
        minimum,
    )
}

fn invalid<T>(message: impl Into<String>) -> Result<T, DynError> {
    Err(format!("invalid bns_dv configuration: {}", message.into()).into())
}

fn non_empty_string(value: &Value, path: &str) -> Result<String, DynError> {
    let Some(value) = value.as_str() else {
        return invalid(format!("{path} must be a non-empty single-line string"));
    };
    if value.is_empty()
        || value.trim() != value
        || value
            .chars()
            .any(|character| matches!(character, '\0' | '\n' | '\r'))
    {
        return invalid(format!("{path} must be a non-empty single-line string"));
    }
    Ok(value.to_string())
}

fn integer(value: &Value, path: &str, minimum: u64) -> Result<u64, DynError> {
    let Some(value) = value.as_u64() else {
        return invalid(format!(
            "{path} must be a safe integer greater than or equal to {minimum}"
        ));
    };
    if value < minimum || value > JSON_SAFE_INTEGER_MAX {
        return invalid(format!(
            "{path} must be a safe integer greater than or equal to {minimum}"
        ));
    }
    Ok(value)
}

fn contract_address(value: &Value) -> Result<String, DynError> {
    let path = format!("apps.{APP_ID}.settings.contract");
    let address = non_empty_string(value, &path)?;
    let valid = address
        .strip_prefix("0x")
        .is_some_and(|hex| hex.len() == 40 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()));
    if !valid {
        return invalid(format!("{path} must be a 20-byte hex address"));
    }
    Ok(address)
}

fn database_path(value: &Value) -> Result<String, DynError> {
    let path_name = format!("apps.{APP_ID}.settings.db");
    let path = non_empty_string(value, &path_name)?;
    let Some(relative) = path.strip_prefix(&format!("{DATABASE_ROOT}/")) else {
        return invalid(format!("{path_name} must be below {DATABASE_ROOT}"));
    };
    if relative
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return invalid(format!("{path_name} must be a normalized file path"));
    }
    Ok(path)
}

fn listen_address(value: &Value) -> Result<String, DynError> {
    let path = format!("apps.{APP_ID}.settings.listen");
    let listen = non_empty_string(value, &path)?;
    let valid = listen
        .strip_prefix("127.0.0.1:")
        .and_then(|port| port.parse::<u16>().ok())
        .is_some_and(|port| port != 0);
    if !valid {
        return invalid(format!("{path} must be a valid IPv4 loopback address"));
    }
    Ok(listen)
}

fn rpc_url(value: &Value) -> Result<String, DynError> {
    let path = "security.chain_rpc_url";
    let rpc = non_empty_string(value, path)?;
    let valid = rpc.parse::<http::Uri>().ok().is_some_and(|uri| {
        matches!(uri.scheme_str(), Some("http" | "https")) && uri.authority().is_some()
    });
    if !valid {
        return invalid(format!("{path} must use http or https"));
    }
    Ok(rpc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_cluster_config() -> Value {
        json!({
            "apps": {
                "bns_dv": {
                    "settings": {
                        "contract": "0x2222222222222222222222222222222222222222",
                        "chain_id": 31337,
                        "db": "/var/lib/bns-backend/bns/bns.sqlite",
                        "listen": "127.0.0.1:1318",
                        "start_block": 10,
                        "confirmations": 2,
                        "interval_ms": 15000
                    }
                }
            }
        })
    }

    #[test]
    fn maps_cluster_config_to_existing_flags_with_defaults() {
        let mapped = cluster_serve_flags(
            &sample_cluster_config(),
            &json!({"chain_rpc_url": "https://rpc.example.test"}),
        )
        .unwrap();
        assert_eq!(mapped.get("rpc").unwrap(), "https://rpc.example.test");
        assert_eq!(mapped.get("chain-id").unwrap(), "31337");
        assert_eq!(
            mapped.get("db").unwrap(),
            "/var/lib/bns-backend/bns/bns.sqlite"
        );
        assert_eq!(mapped.get("max-block-span").unwrap(), "500");
    }

    #[test]
    fn command_line_flags_override_every_cluster_value() {
        let mut cluster = cluster_serve_flags(
            &sample_cluster_config(),
            &json!({"chain_rpc_url": "https://rpc.example.test"}),
        )
        .unwrap();
        let overrides = HashMap::from([
            ("rpc".to_string(), "http://override:8545".to_string()),
            (
                "contract".to_string(),
                "0x3333333333333333333333333333333333333333".to_string(),
            ),
            ("chain-id".to_string(), "1".to_string()),
            ("db".to_string(), "/tmp/override.sqlite".to_string()),
            ("listen".to_string(), "0.0.0.0:8080".to_string()),
            ("start-block".to_string(), "20".to_string()),
            ("confirmations".to_string(), "3".to_string()),
            ("interval-ms".to_string(), "30000".to_string()),
            ("max-block-span".to_string(), "750".to_string()),
        ]);
        cluster.extend(overrides.clone());
        for (key, expected) in overrides {
            assert_eq!(cluster.get(&key), Some(&expected), "override for --{key}");
        }
    }

    #[test]
    fn rejects_unknown_settings() {
        let mut cluster = sample_cluster_config();
        cluster["apps"]["bns_dv"]["settings"]["seed_config"] = json!("forbidden.yaml");
        let error = cluster_serve_flags(
            &cluster,
            &json!({"chain_rpc_url": "https://rpc.example.test"}),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("unknown keys: seed_config"), "{error}");
    }
}
