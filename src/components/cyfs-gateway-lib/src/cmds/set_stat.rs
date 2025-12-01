use clap::{Arg, Command};
use cyfs_process_chain::{command_help, CollectionValue, CommandArgs, CommandHelpType, CommandResult, Context, EnvLevel, ExternalCommand, MemorySetCollection};

pub struct SetStat {
    name: String,
    cmd: Command,
}

impl SetStat {
    pub fn new() -> Self {
        let cmd = Command::new("set-stat")
            .about("Set the statistical group IDs for which this connection needs to be counted.")
            .after_help(
                r#"
Examples:
    set-stat group1
    set-stat group1 group2
                "#
            )
            .arg(
                Arg::new("group_id")
                    .num_args(0..)
                    .help("Statistical group ID")
                    .required(true)
            );
        Self {
            name: "set-stat".to_string(),
            cmd,
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }
}

#[async_trait::async_trait]
impl ExternalCommand for SetStat {
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

        let group_ids = matches.get_many::<String>("group_id");
        if group_ids.is_none() {
            return Err("group_id is required".to_string());
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

        let group_ids = matches.get_many::<String>("group_id");
        if group_ids.is_none() {
            return Err("group_id is required".to_string());
        }

        let group_ids = group_ids.unwrap();
        let set = MemorySetCollection::new_ref();
        for group_id in group_ids {
            set.insert(group_id.as_str()).await?;
        }

        context.env().create("STAT", CollectionValue::Set(set), EnvLevel::Chain).await?;
        Ok(CommandResult::Success("STAT".to_string()))
    }
}
