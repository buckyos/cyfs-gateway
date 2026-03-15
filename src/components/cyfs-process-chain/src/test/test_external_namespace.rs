use super::external::AddCommand;
use crate::*;
use simplelog::*;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Once;
use std::time::{SystemTime, UNIX_EPOCH};

static LOGGER_INIT: Once = Once::new();

fn init_test_logger() {
    LOGGER_INIT.call_once(|| {
        TermLogger::init(
            LevelFilter::Info,
            Config::default(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        )
        .unwrap_or_else(|_| {
            let _ = SimpleLogger::init(LevelFilter::Info, Config::default());
        });
    });
}

fn new_test_data_dir(scope: &str) -> Result<PathBuf, String> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system time error: {}", e))?
        .as_nanos();
    let pid = std::process::id();
    let data_dir =
        std::env::temp_dir().join(format!("cyfs-process-chain-{}-{}-{}", scope, pid, ts));
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| format!("create test data dir {:?} failed: {}", data_dir, e))?;
    Ok(data_dir)
}

fn unique_name(prefix: &str) -> Result<String, String> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system time error: {}", e))?
        .as_nanos();
    Ok(format!("{}_{}_{}", prefix, std::process::id(), ts))
}

#[tokio::test]
async fn test_call_external_namespace_success() -> Result<(), String> {
    init_test_logger();

    let global_cmd = unique_name("ns_global_add")?;
    let local_cmd = unique_name("ns_local_add")?;

    EXTERNAL_COMMAND_FACTORY.register(&global_cmd, Arc::new(Box::new(AddCommand::new())))?;

    let process_chain = format!(
        r#"
<root>
<process_chain id="route">
    <block id="entry">
        <![CDATA[
            local global_sum = $(call global::{global_cmd} 1 2);
            local local_sum = $(call local::{local_cmd} 2 3);
            eq $global_sum 3 && eq $local_sum 5 && return --from lib "ok";
            return --from lib "bad";
        ]]>
    </block>
</process_chain>
</root>
"#
    );

    let hook_point = HookPoint::new("test_external_namespace_success");
    hook_point
        .load_process_chain_lib("ns_success_lib", 0, process_chain.as_str())
        .await?;

    let data_dir = new_test_data_dir("test-external-namespace-success")?;
    let hook_point_env = HookPointEnv::new("test-external-namespace-success", data_dir);
    hook_point_env.register_external_command(&local_cmd, Arc::new(Box::new(AddCommand::new())))?;

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("ns_success_lib").await?;
    assert_eq!(ret.value(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_call_external_namespace_scope_mismatch() -> Result<(), String> {
    init_test_logger();

    let global_cmd = unique_name("ns_scope_mismatch_add")?;
    EXTERNAL_COMMAND_FACTORY.register(&global_cmd, Arc::new(Box::new(AddCommand::new())))?;

    let process_chain = format!(
        r#"
<root>
<process_chain id="route">
    <block id="entry">
        <![CDATA[
            call local::{global_cmd} 1 2;
        ]]>
    </block>
</process_chain>
</root>
"#
    );

    let hook_point = HookPoint::new("test_external_namespace_scope_mismatch");
    hook_point
        .load_process_chain_lib("ns_scope_mismatch_lib", 0, process_chain.as_str())
        .await?;

    let data_dir = new_test_data_dir("test-external-namespace-scope-mismatch")?;
    let hook_point_env = HookPointEnv::new("test-external-namespace-scope-mismatch", data_dir);
    let err = match hook_point_env.link_hook_point(&hook_point).await {
        Ok(_) => {
            return Err(
                "link_hook_point should fail when local:: command does not exist".to_string(),
            );
        }
        Err(err) => err,
    };
    assert!(
        err.contains("External command 'local::"),
        "unexpected error: {}",
        err
    );

    Ok(())
}
