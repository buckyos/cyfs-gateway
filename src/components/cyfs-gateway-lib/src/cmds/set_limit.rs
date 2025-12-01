use clap::{Arg, Command};
use cyfs_process_chain::{command_help, CollectionValue, CommandArgs, CommandHelpType, CommandResult, Context, EnvLevel, ExternalCommand, MemoryMapCollection};
use crate::parse_speed;
use crate::stack::is_valid_speed;

pub struct SetLimit {
    name: String,
    cmd: Command,
}

impl SetLimit {
    pub fn new() -> Self {
        let cmd = Command::new("set-limit")
            .about("Set a speed limit for the connection")
            .after_help(
                r#"
Examples:
    set-limit global
    set-limit 100KB/s 100KB/s
    set-limit global 100KB/s 100KB/s
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
        SetLimit {
            name: "set-limit".to_string(),
            cmd,
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }
}

#[async_trait::async_trait]
impl ExternalCommand for SetLimit {
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

        let map = MemoryMapCollection::new_ref();
        match count {
            3 => {
                let limiter_id = matches.get_one::<String>("limiter_id").map(|s| s.to_string());
                let down_speed = matches.get_one::<String>("down_speed").map(|s| s.to_string());
                let upload_speed = matches.get_one::<String>("upload_speed").map(|s| s.to_string());
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
                let down_speed = matches.get_one::<String>("limiter_id").map(|s| s.to_string());
                let upload_speed = matches.get_one::<String>("down_speed").map(|s| s.to_string());
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
                let limiter_id = matches.get_one::<String>("limiter_id").map(|s| s.to_string());
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
        Ok(CommandResult::Success("LIMIT".to_string()))
    }
}
