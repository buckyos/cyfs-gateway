use clap::{Arg, Command};
use cyfs_process_chain::{
    CollectionValue, CommandArgs, CommandHelpType, CommandResult, Context, ExternalCommand,
    MemoryMapCollection, command_help,
};

pub struct ParseCookie {
    name: String,
    cmd: Command,
}

impl ParseCookie {
    pub fn new() -> Self {
        let cmd = Command::new("parse-cookie")
            .about("Parse a Cookie header string into a field->value map")
            .after_help(
                r#"
Examples:
    parse-cookie "sid=abc; theme=dark"
    parse-cookie $REQ.headers.cookie
                "#,
            )
            .arg(
                Arg::new("cookie")
                    .help("Cookie header string")
                    .index(1)
                    .required(true),
            );

        Self {
            name: "parse-cookie".to_string(),
            cmd,
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }
}

#[async_trait::async_trait]
impl ExternalCommand for ParseCookie {
    fn help(&self, name: &str, help_type: CommandHelpType) -> String {
        assert_eq!(self.cmd.get_name(), name);
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        self.cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid parse-cookie command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;
        Ok(())
    }

    async fn exec(
        &self,
        _context: &Context,
        args: &[CollectionValue],
        _origin_args: &CommandArgs,
    ) -> Result<CommandResult, String> {
        if args.len() != 2 {
            let msg = format!(
                "Invalid parse-cookie command args length: expected 2, got {}",
                args.len()
            );
            error!("{}", msg);
            return Err(msg);
        }

        let cookie = args[1].try_as_str()?;
        let result = MemoryMapCollection::new_ref();

        for raw_field in cookie.split(';') {
            let field = raw_field.trim();
            if field.is_empty() {
                continue;
            }

            let (name, value) = field.split_once('=').ok_or_else(|| {
                format!(
                    "invalid cookie field '{}': expected key=value entries separated by ';'",
                    field
                )
            })?;
            let name = name.trim();
            if name.is_empty() {
                return Err(format!("invalid cookie field '{}': empty name", field));
            }

            result
                .insert(name, CollectionValue::String(value.trim().to_string()))
                .await?;
        }

        Ok(CommandResult::success_with_value(CollectionValue::Map(
            result,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cyfs_process_chain::{CollectionValue, HookPoint, HookPointEnv};
    use std::sync::Arc;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_parse_cookie_returns_field_map() {
        let process_chain = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            local cookie = $(parse-cookie $COOKIE);
            eq $cookie.sid "abc" && eq $cookie.theme "dark" && eq $cookie.lang "zh-CN" && return --from lib "ok";
            return --from lib "bad";
        ]]>
    </block>
</process_chain>
</root>
"#;

        let hook_point = HookPoint::new("test-parse-cookie");
        hook_point
            .load_process_chain_lib("parse_cookie_lib", 0, process_chain)
            .await
            .unwrap();
        let data_dir = TempDir::new().unwrap();
        let hook_point_env = HookPointEnv::new("test-parse-cookie", data_dir.path().to_path_buf());
        hook_point_env
            .register_external_command("parse-cookie", Arc::new(Box::new(ParseCookie::new())))
            .unwrap();
        hook_point_env
            .hook_point_env()
            .create(
                "COOKIE",
                CollectionValue::String("sid=abc; theme=dark; lang=zh-CN".to_string()),
            )
            .await
            .unwrap();
        let exec = hook_point_env.link_hook_point(&hook_point).await.unwrap();
        let result = exec.execute_lib("parse_cookie_lib").await.unwrap();

        assert_eq!(result.value(), "ok");
    }

    #[tokio::test]
    async fn test_parse_cookie_last_value_wins_for_duplicate_fields() {
        let process_chain = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            local cookie = $(parse-cookie $COOKIE);
            eq $cookie.sid "second" && return --from lib "ok";
            return --from lib "bad";
        ]]>
    </block>
</process_chain>
</root>
"#;

        let hook_point = HookPoint::new("test-parse-cookie-dup");
        hook_point
            .load_process_chain_lib("parse_cookie_dup_lib", 0, process_chain)
            .await
            .unwrap();
        let data_dir = TempDir::new().unwrap();
        let hook_point_env =
            HookPointEnv::new("test-parse-cookie-dup", data_dir.path().to_path_buf());
        hook_point_env
            .register_external_command("parse-cookie", Arc::new(Box::new(ParseCookie::new())))
            .unwrap();
        hook_point_env
            .hook_point_env()
            .create(
                "COOKIE",
                CollectionValue::String("sid=first; sid=second".to_string()),
            )
            .await
            .unwrap();
        let exec = hook_point_env.link_hook_point(&hook_point).await.unwrap();
        let result = exec.execute_lib("parse_cookie_dup_lib").await.unwrap();

        assert_eq!(result.value(), "ok");
    }
}
