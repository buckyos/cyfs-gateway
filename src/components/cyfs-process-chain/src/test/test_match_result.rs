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

async fn execute_lib(script: &str, scope: &str) -> Result<CommandResult, String> {
    let hook_point = HookPoint::new(scope);
    hook_point
        .load_process_chain_lib("test_match_result_lib", 0, script)
        .await?;

    let data_dir = new_test_data_dir(scope)?;
    let hook_point_env = HookPointEnv::new(scope, data_dir);
    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    exec.execute_lib("test_match_result_lib").await
}

#[tokio::test]
async fn test_match_result_success_branch_and_scope_restore() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            local outer="outer";
            local calls="";

            match-result $(capture --value calls $(append $calls "1"))
            ok(outer)
                eq $outer "1" || return --from lib "bad_match_value";
                eq $calls "1" || return --from lib "bad_calls_inside";
            err(err_value)
                return --from lib $(append "unexpected_err:" $err_value);
            end

            eq $calls "1" || return --from lib "bad_calls_after";
            eq $outer "outer" || return --from lib "bad_shadow_restore";
            return --from lib "ok";
        ]]>
    </block>
</process_chain>
</root>
"#;

    let ret = execute_lib(script, "test-match-result-success").await?;
    assert_eq!(ret.value(), "ok");
    Ok(())
}

#[tokio::test]
async fn test_match_result_ok_only_branch() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            match-result $(append "hello" "_ok")
            ok(value)
                eq $value "hello_ok" || return --from lib "bad_ok_value";
                return --from lib $(append "handled:" $value);
            end
        ]]>
    </block>
</process_chain>
</root>
"#;

    let ret = execute_lib(script, "test-match-result-ok-only").await?;
    assert_eq!(ret.value(), "handled:hello_ok");
    Ok(())
}

#[tokio::test]
async fn test_match_result_error_branch() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            match-result $(match "abc" "z*")
            ok(value)
                return --from lib $(append "unexpected_ok:" $value);
            err(err_value)
                eq $err_value false || return --from lib "bad_err_value";
                return --from lib "handled_error";
            end
        ]]>
    </block>
</process_chain>
</root>
"#;

    let ret = execute_lib(script, "test-match-result-error").await?;
    assert_eq!(ret.value(), "handled_error");
    Ok(())
}

#[tokio::test]
async fn test_match_result_err_only_branch() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            match-result $(match "abc" "z*")
            err(err_value)
                eq $err_value false || return --from lib "bad_err_value";
                return --from lib "handled_err_only";
            end
        ]]>
    </block>
</process_chain>
</root>
"#;

    let ret = execute_lib(script, "test-match-result-err-only").await?;
    assert_eq!(ret.value(), "handled_err_only");
    Ok(())
}

#[tokio::test]
async fn test_match_result_control_branch() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            match-result $(return --from chain "chain_value")
            ok(value)
                return --from lib $(append "unexpected_ok:" $value);
            err(err_value)
                return --from lib $(append "unexpected_err:" $err_value);
            control(action, from, value)
                eq $action "return" || return --from lib "bad_action";
                eq $from "chain" || return --from lib "bad_from";
                eq $value "chain_value" || return --from lib "bad_control_value";
                return --from lib "handled_control";
            end
        ]]>
    </block>
</process_chain>
</root>
"#;

    let ret = execute_lib(script, "test-match-result-control").await?;
    assert_eq!(ret.value(), "handled_control");
    Ok(())
}

#[tokio::test]
async fn test_match_result_control_only_branch() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            match-result $(return --from chain "chain_value")
            control(action, from, value)
                eq $action "return" || return --from lib "bad_action";
                eq $from "chain" || return --from lib "bad_from";
                eq $value "chain_value" || return --from lib "bad_control_value";
                return --from lib "handled_control_only";
            end
        ]]>
    </block>
</process_chain>
</root>
"#;

    let ret = execute_lib(script, "test-match-result-control-only").await?;
    assert_eq!(ret.value(), "handled_control_only");
    Ok(())
}

#[tokio::test]
async fn test_match_result_propagates_unhandled_control() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            match-result $(return --from lib "propagated")
            ok(value)
                return --from lib $(append "unexpected_ok:" $value);
            err(err_value)
                return --from lib $(append "unexpected_err:" $err_value);
            end

            return --from lib "after_match_result";
        ]]>
    </block>
</process_chain>
</root>
"#;

    let ret = execute_lib(script, "test-match-result-propagate").await?;
    assert_eq!(ret.value(), "propagated");
    Ok(())
}
