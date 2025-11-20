use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::{Arc, RwLock};
use clap::{Arg, Command};
use sfo_io::{SpeedLimitSession, SpeedLimiter, SpeedLimiterRef};
use cyfs_process_chain::{command_help, CollectionValue, CommandArgs, CommandHelpType, CommandResult, Context, EnvLevel, EnvRef, ExternalCommand, MemoryMapCollection};
use crate::{stack_err, StackErrorCode, StackResult};

#[derive(Clone)]
pub struct Limiter {
    read_limiter: SpeedLimiterRef,
    write_limiter: SpeedLimiterRef
}

impl Limiter {
    pub fn new(upper: Option<Limiter>, concurrent: Option<u32>, read_speed: Option<u32>, write_speed: Option<u32>) -> Self {
        let (read_rate, read_weight) = Self::get_limit_info(concurrent, read_speed);
        let (write_rate, write_weight) = Self::get_limit_info(concurrent, write_speed);
        let (upper_read_limiter, upper_write_limiter) = match upper {
            Some(upper) => (Some(upper.read_limiter.clone()), Some(upper.write_limiter.clone())),
            None => (None, None),
        };

        Limiter {
            read_limiter: SpeedLimiter::new(upper_read_limiter, read_rate, read_weight),
            write_limiter: SpeedLimiter::new(upper_write_limiter, write_rate, write_weight),
        }
    }

    fn get_limit_info(concurrent: Option<u32>, speed: Option<u32>) -> (Option<NonZeroU32>, Option<NonZeroU32>) {
        match speed {
            Some(speed) => {
                let concurrent = concurrent.unwrap_or(1);
                let rate = concurrent * 100;
                if rate > speed {
                    (Some(NonZeroU32::new(speed).unwrap()), Some(NonZeroU32::new(1).unwrap()))
                } else {
                    if speed % rate > ((rate as f64) * 0.4f64) as u32 {
                        (Some(NonZeroU32::new(rate).unwrap()), Some(NonZeroU32::new(speed / rate + 1).unwrap()))
                    } else {
                        (Some(NonZeroU32::new(rate).unwrap()), Some(NonZeroU32::new(speed / rate).unwrap()))
                    }
                }
            },
            None => (None, None),
        }
    }
    pub fn set_speed(&self, concurrent: Option<u32>, read_speed: Option<u32>, write_speed: Option<u32>) {
        let (read_rate, read_weight) = Self::get_limit_info(concurrent, read_speed);
        let (write_rate, write_weight) = Self::get_limit_info(concurrent, write_speed);
        self.read_limiter.set_limit(read_rate, read_weight);
        self.write_limiter.set_limit(write_rate, write_weight);
    }

    pub fn new_limit_session(&self) -> (SpeedLimitSession, SpeedLimitSession) {
        (self.read_limiter.new_limit_session(), self.write_limiter.new_limit_session())
    }
}

pub const GLOBAL: &str = "global";

pub struct LimiterManager {
    limiters: RwLock<HashMap<String, Limiter>>,
}
pub type LimiterManagerRef = Arc<LimiterManager>;

impl LimiterManager {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            limiters: RwLock::new(HashMap::new()),
        })
    }

    pub fn get_limiter(&self, id: impl Into<String>) -> Option<Limiter> {
        self.limiters.read().unwrap().get(&id.into()).cloned()
    }

    pub fn new_limiter(&self,
                       id: impl Into<String>,
                       upper: Option<impl Into<String>>,
                       concurrent: Option<u32>,
                       read_speed: Option<u32>,
                       write_speed: Option<u32>) -> Limiter {
        let upper = match upper {
            Some(id) => self.get_limiter(id),
            None => None,
        };

        let limiter = Limiter::new(upper, concurrent, read_speed, write_speed);
        let mut limiters = self.limiters.write().unwrap();
        limiters.insert(id.into(), limiter.clone());
        limiter
    }
}

pub struct LimitCmd {
    name: String,
    cmd: Command,
}

impl LimitCmd {
    pub fn new() -> Self {
        let cmd = Command::new("set_limit")
            .about("Set a speed limit for the connection")
            .after_help(
                r#"
Examples:
    set_limit global
    set_limit 100KB/s 100KB/s
    set_limit global 100KB/s 100KB/s
                "#
            )
            .arg(
                Arg::new("limiter_id")
                    .help("Predefined speed limiter id")
                    .index(1)
                    .required(false)
            )
            .arg(
                Arg::new("down_speed")
                    .help("Download speed limit.Supports units: B/s, KB/s, MB/s, GB/s")
                    .index(2)
                    .required(false)
            )
            .arg(
                Arg::new("upload_speed")
                    .help("Upload speed limit.Supports units: B/s, KB/s, MB/s, GB/s")
                    .index(3)
                    .required(false)
            );
        LimitCmd {
            name: "set_limit".to_string(),
            cmd,
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }
}

#[async_trait::async_trait]
impl ExternalCommand for LimitCmd {
    fn help(&self, name: &str, help_type: CommandHelpType) -> String {
        assert_eq!(self.cmd.get_name(), name);
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        let matches = self.cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid resolve command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;
        let count = matches.ids().count();
        let _limiter_id = matches.get_one::<String>("limiter_id").map(|s| s.to_string());
        let down_speed = matches.get_one::<String>("down_speed").map(|s| s.to_string());
        let upload_speed = matches.get_one::<String>("upload_speed").map(|s| s.to_string());
        match count {
            3 => {
                // 检测down_speed和upload_speed是否满足格式：100.1KB/s,Supports units: B/s, KB/s, MB/s, GB/s
                if let Some(down_speed_str) = &down_speed {
                    if !is_valid_speed(down_speed_str) {
                        return Err(format!("Invalid download speed format: {}. Expected format: 100.1KB/s. Supports units: B/s, KB/s, MB/s, GB/s", down_speed_str));
                    }
                }
                if let Some(upload_speed_str) = &upload_speed {
                    if !is_valid_speed(upload_speed_str) {
                        return Err(format!("Invalid upload speed format: {}. Expected format: 100.1KB/s. Supports units: B/s, KB/s, MB/s, GB/s", upload_speed_str));
                    }
                }
            }
            2 => {
                if let Some(down_speed_str) = &down_speed {
                    if !is_valid_speed(down_speed_str) {
                        return Err(format!("Invalid download speed format: {}. Expected format: 100.1KB/s. Supports units: B/s, KB/s, MB/s, GB/s", down_speed_str));
                    }
                }
                if let Some(upload_speed_str) = &upload_speed {
                    if !is_valid_speed(upload_speed_str) {
                        return Err(format!("Invalid upload speed format: {}. Expected format: 100.1KB/s. Supports units: B/s, KB/s, MB/s, GB/s", upload_speed_str));
                    }
                }
            }
            1 => {}
            _ => {
                return Err("Invalid command arguments".to_string());
            }
        }
        Ok(())
    }

    async fn exec(&self, context: &Context, args: &[CollectionValue], _origin_args: &CommandArgs) -> Result<CommandResult, String> {
        let mut str_args = Vec::with_capacity(args.len());
        for arg in args.iter() {
            if !arg.is_string() {
                let msg = format!("Invalid argument type: expected string, got {:?}", arg);
                error!("{}", msg);
                return Err(msg);
            }
            str_args.push(arg.as_str().unwrap());
        }

        let matches = self.cmd
            .clone()
            .try_get_matches_from(&str_args)
            .map_err(|e| {
                let msg = format!("Invalid resolve command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        let count = matches.ids().count();
        let limiter_id = matches.get_one::<String>("limiter_id").map(|s| s.to_string());
        let down_speed = matches.get_one::<String>("down_speed").map(|s| s.to_string());
        let upload_speed = matches.get_one::<String>("upload_speed").map(|s| s.to_string());

        let map = MemoryMapCollection::new_ref();
        match count {
            3 => {
                if limiter_id.is_none() {
                    return Err("Invalid set_limit command: missing limiter_id".to_string());
                }
                let limiter_id = limiter_id.unwrap();
                map.insert("limiter_id", CollectionValue::String(limiter_id)).await?;
                if down_speed.is_none() {
                    return Err("Invalid set_limit command: missing down_speed".to_string());
                }
                let down_speed = parse_speed(down_speed.unwrap().as_str())?;
                map.insert("down_speed", CollectionValue::String(format!("{}", down_speed))).await?;
                if upload_speed.is_none() {
                    return Err("Invalid set_limit command: missing upload_speed".to_string());
                }
                let upload_speed = parse_speed(upload_speed.unwrap().as_str())?;
                map.insert("upload_speed", CollectionValue::String(format!("{}", upload_speed))).await?;
            }
            2 => {
                if down_speed.is_none() {
                    return Err("Invalid set_limit command: missing down_speed".to_string());
                }
                let down_speed = parse_speed(down_speed.unwrap().as_str())?;
                map.insert("down_speed", CollectionValue::String(format!("{}", down_speed))).await?;
                if upload_speed.is_none() {
                    return Err("Invalid set_limit command: missing upload_speed".to_string());
                }
                let upload_speed = parse_speed(upload_speed.unwrap().as_str())?;
                map.insert("upload_speed", CollectionValue::String(format!("{}", upload_speed))).await?;
            }
            1 => {
                if limiter_id.is_none() {
                    return Err("Invalid set_limit command: missing limiter_id".to_string());
                }
                let limiter_id = limiter_id.unwrap();
                map.insert("limiter_id", CollectionValue::String(limiter_id)).await?;
            }
            _ => {
                return Err("Invalid set_limit command".to_string());
            }
        }
        context.env().create("LIMIT", CollectionValue::Map(map), EnvLevel::Chain).await?;
        Ok(CommandResult::Success("RESP".to_string()))
    }
}

fn is_valid_speed(speed: &str) -> bool {
    // Define regex pattern for validating speed format
    // Supports formats like: 100B/s, 100.5KB/s, 1.5MB/s, 0.5GB/s
    let re = regex::Regex::new(r"^(\d+(\.\d+)?)\s*(B|KB|MB|GB)/s$").unwrap();
    re.is_match(speed)
}

fn parse_speed(speed: &str) -> Result<u64, String> {
    let re = regex::Regex::new(r"^(\d+(\.\d+)?)\s*(B|KB|MB|GB)/s$").unwrap();
    if let Some(captures) = re.captures(speed) {
        let num = captures.get(1).ok_or_else(|| {
            let msg = format!("Invalid speed number: {}", speed);
            error!("{}", msg);
            msg
        })?.as_str().parse::<f64>().map_err(|e| {
            let msg = format!("Invalid speed number: {}. Error: {}", speed, e);
            error!("{}", msg);
            msg
        })?;
        let unit = captures.get(3).unwrap().as_str();
        match unit {
            "B" => Ok(num as u64),
            "KB" => Ok((num * 1024.0) as u64),
            "MB" => Ok((num * 1024.0 * 1024.0) as u64),
            "GB" => Ok((num * 1024.0 * 1024.0 * 1024.0) as u64),
            _ => Err("Invalid speed unit".to_string()),
        }
    } else {
        Err("Invalid speed format".to_string())
    }
}

pub async fn get_limit_info(chain_env: EnvRef) -> StackResult<(Option<String>, Option<u64>, Option<u64>)> {
    let limit_info = chain_env.get("LIMIT").await.map_err(
        |e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;

    let mut limiter_id = None;
    let mut down_speed = None;
    let mut upload_speed = None;
    if let Some(limit_info) = limit_info {
        if let CollectionValue::Map(map) = limit_info {
            limiter_id = if let Ok(Some(CollectionValue::String(limiter_id))) = map.get("limiter_id").await {
                Some(limiter_id)
            } else {
                None
            };

            down_speed = if let Ok(Some(CollectionValue::String(down_speed))) = map.get("down_speed").await {
                down_speed.parse::<u64>().ok()
            } else {
                None
            };

            upload_speed = if let Ok(Some(CollectionValue::String(upload_speed))) = map.get("upload_speed").await {
                upload_speed.parse::<u64>().ok()
            } else {
                None
            };
        }
    }

    Ok((limiter_id, down_speed, upload_speed))
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_speed() {
        // Valid speeds
        assert!(is_valid_speed("100B/s"));
        assert!(is_valid_speed("100.5KB/s"));
        assert!(is_valid_speed("1.5MB/s"));
        assert!(is_valid_speed("0.5GB/s"));
        assert!(is_valid_speed("100KB/s"));
        assert!(is_valid_speed("1000MB/s"));
        assert!(is_valid_speed("1.0GB/s"));
        assert!(is_valid_speed("0B/s"));

        // Invalid speeds
        assert!(!is_valid_speed("100"));
        assert!(!is_valid_speed("100KB"));
        assert!(!is_valid_speed("KB/s"));
        assert!(!is_valid_speed("100.5.5KB/s"));
        assert!(!is_valid_speed("100.5 KBS"));
        assert!(!is_valid_speed(""));
        assert!(!is_valid_speed("ABC KB/s"));
    }

    #[test]
    fn test_parse_speed() {
        // Valid parsing
        assert_eq!(parse_speed("100B/s").unwrap(), 100);
        assert_eq!(parse_speed("1KB/s").unwrap(), 1024);
        assert_eq!(parse_speed("1.5KB/s").unwrap(), 1536); // 1.5 * 1024
        assert_eq!(parse_speed("1MB/s").unwrap(), 1024 * 1024);
        assert_eq!(parse_speed("1GB/s").unwrap(), 1024 * 1024 * 1024);

        // Invalid formats
        assert!(parse_speed("100").is_err());
        assert!(parse_speed("100KB").is_err());
        assert!(parse_speed("invalid").is_err());
    }
}
