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

const CALLEE_LIB_ERROR: &str = r#"
<root>
<process_chain id="callee_err" priority="100">
    <block id="entry">
        <![CDATA[
            error --from chain "callee_err";
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

const CALLER_LIB_OK_FROM_LIB: &str = r#"
<root>
<process_chain id="main" priority="100">
    <block id="entry">
        <![CDATA[
            goto --chain callee_lib:callee --ok-from lib --err-from chain;
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

const CALLER_LIB_ERR_FROM_OVERRIDE: &str = r#"
<root>
<process_chain id="main" priority="100">
    <block id="entry">
        <![CDATA[
            goto --chain callee_err_lib:callee_err --from chain --err-from lib;
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

const CALLER_LIB_DEFAULT_FROM_BLOCK: &str = r#"
<root>
<process_chain id="main" priority="100">
    <block id="entry_first">
        <![CDATA[
            goto --chain callee_lib:callee;
            return --from lib "entry_should_not_continue";
        ]]>
    </block>
    <block id="entry_after">
        <![CDATA[
            return --from lib "after_block_ran";
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
async fn test_goto_chain_default_from_block_matches_return_default() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_goto_chain_default_from_block");
    hook_point
        .load_process_chain_lib("callee_lib", 0, CALLEE_LIB)
        .await?;
    hook_point
        .load_process_chain_lib("caller_default_block", 1, CALLER_LIB_DEFAULT_FROM_BLOCK)
        .await?;

    let data_dir = new_test_data_dir("test-goto-chain-default-from-block")?;
    let hook_point_env = HookPointEnv::new("test-goto-chain-default-from-block", data_dir);
    let exec = hook_point_env.link_hook_point(&hook_point).await?;

    let ret = exec.execute_lib("caller_default_block").await?;
    assert_eq!(ret.value(), "after_block_ran");

    Ok(())
}

#[tokio::test]
async fn test_goto_chain_ok_from_lib_exits_lib() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_goto_chain_ok_from_lib");
    hook_point
        .load_process_chain_lib("callee_lib", 0, CALLEE_LIB)
        .await?;
    hook_point
        .load_process_chain_lib("caller_ok_from_lib", 1, CALLER_LIB_OK_FROM_LIB)
        .await?;

    let data_dir = new_test_data_dir("test-goto-chain-ok-from-lib")?;
    let hook_point_env = HookPointEnv::new("test-goto-chain-ok-from-lib", data_dir);
    let exec = hook_point_env.link_hook_point(&hook_point).await?;

    let ret = exec.execute_lib("caller_ok_from_lib").await?;
    assert_eq!(ret.value(), "callee_ok");

    Ok(())
}

#[tokio::test]
async fn test_goto_chain_err_from_overrides_from_on_error() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_goto_chain_err_from_override");
    hook_point
        .load_process_chain_lib("callee_err_lib", 0, CALLEE_LIB_ERROR)
        .await?;
    hook_point
        .load_process_chain_lib("caller_err_from_override", 1, CALLER_LIB_ERR_FROM_OVERRIDE)
        .await?;

    let data_dir = new_test_data_dir("test-goto-chain-err-from-override")?;
    let hook_point_env = HookPointEnv::new("test-goto-chain-err-from-override", data_dir);
    let exec = hook_point_env.link_hook_point(&hook_point).await?;

    let ret = exec.execute_lib("caller_err_from_override").await?;
    let control = ret
        .as_control()
        .ok_or_else(|| format!("expected control error result, got {:?}", ret))?;
    match control {
        CommandControl::Error(value) => {
            assert_eq!(value.level, CommandControlLevel::Lib);
            assert_eq!(value.value.as_str(), Some("callee_err"));
        }
        _ => {
            return Err(format!(
                "expected lib-level error control, got {:?}",
                control
            ));
        }
    }

    Ok(())
}
