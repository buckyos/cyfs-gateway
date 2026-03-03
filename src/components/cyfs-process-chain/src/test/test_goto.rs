use crate::*;
use simplelog::*;
use std::path::PathBuf;
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

const CALLEE_LIB: &str = r#"
<root>
<process_chain id="callee" priority="100">
    <block id="entry">
        <![CDATA[
            return --from chain "callee_ok";
        ]]>
    </block>
</process_chain>
</root>
"#;

const CALLER_LIB_FROM_LIB: &str = r#"
<root>
<process_chain id="main" priority="100">
    <block id="entry">
        <![CDATA[
            goto --chain callee_lib:callee --from lib;
            return --from lib "main_after";
        ]]>
    </block>
</process_chain>
<process_chain id="tail" priority="200">
    <block id="entry">
        <![CDATA[
            return --from lib "tail_should_not_run";
        ]]>
    </block>
</process_chain>
</root>
"#;

const CALLER_LIB_DEFAULT_FROM_CHAIN: &str = r#"
<root>
<process_chain id="main" priority="100">
    <block id="entry">
        <![CDATA[
            goto --chain callee_lib:callee;
            return --from lib "main_after";
        ]]>
    </block>
</process_chain>
<process_chain id="tail" priority="200">
    <block id="entry">
        <![CDATA[
            return --from lib "tail_ran";
        ]]>
    </block>
</process_chain>
</root>
"#;

#[tokio::test]
async fn test_goto_chain_with_from_lib_exits_lib() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_goto_chain_with_from_lib");
    hook_point
        .load_process_chain_lib("callee_lib", 0, CALLEE_LIB)
        .await?;
    hook_point
        .load_process_chain_lib("caller_from_lib", 1, CALLER_LIB_FROM_LIB)
        .await?;

    let data_dir = new_test_data_dir("test-goto-chain-from-lib")?;
    let hook_point_env = HookPointEnv::new("test-goto-chain-from-lib", data_dir);
    let exec = hook_point_env.link_hook_point(&hook_point).await?;

    let ret = exec.execute_lib("caller_from_lib").await?;
    assert_eq!(ret.value(), "callee_ok");

    Ok(())
}

#[tokio::test]
async fn test_goto_chain_default_from_chain_continues_lib() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_goto_chain_default_from_chain");
    hook_point
        .load_process_chain_lib("callee_lib", 0, CALLEE_LIB)
        .await?;
    hook_point
        .load_process_chain_lib(
            "caller_default_chain",
            1,
            CALLER_LIB_DEFAULT_FROM_CHAIN,
        )
        .await?;

    let data_dir = new_test_data_dir("test-goto-chain-default-from-chain")?;
    let hook_point_env = HookPointEnv::new("test-goto-chain-default-from-chain", data_dir);
    let exec = hook_point_env.link_hook_point(&hook_point).await?;

    let ret = exec.execute_lib("caller_default_chain").await?;
    assert_eq!(ret.value(), "tail_ran");

    Ok(())
}

