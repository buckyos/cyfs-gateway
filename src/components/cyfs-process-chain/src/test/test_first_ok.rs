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
        .load_process_chain_lib("test_first_ok_lib", 0, script)
        .await?;

    let data_dir = new_test_data_dir(scope)?;
    let hook_point_env = HookPointEnv::new(scope, data_dir);
    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    exec.execute_lib("test_first_ok_lib").await
}

#[tokio::test]
async fn test_first_ok_returns_first_success_value() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="candidate1">
        <![CDATA[
            global calls=$(append $calls "1");
            strip-prefix "/public/api/v1" "/internal";
        ]]>
    </block>
    <block id="candidate2">
        <![CDATA[
            global calls=$(append $calls "2");
            strip-prefix "/public/api/v1" "/public";
        ]]>
    </block>
    <block id="candidate3">
        <![CDATA[
            global calls=$(append $calls "3");
            strip-prefix "/public/api/v1" "/api";
        ]]>
    </block>
    <block id="entry">
        <![CDATA[
            global calls="";
            local tail=$(first-ok
              $(exec --block candidate1)
              $(exec --block candidate2)
              $(exec --block candidate3)
            );

            eq $tail "/api/v1" || return --from lib "bad_tail";
            eq $calls "12" || return --from lib "bad_call_order";
            return --from lib "ok";
        ]]>
    </block>
</process_chain>
</root>
"#;

    let ret = execute_lib(script, "test-first-ok-success").await?;
    assert_eq!(ret.value(), "ok");
    Ok(())
}

#[tokio::test]
async fn test_first_ok_returns_last_error_when_all_candidates_fail() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            match-result $(first-ok
              $(strip-prefix "/public/api/v1" "/internal")
              $(strip-prefix "/public/api/v1" "/api")
            )
            ok(value)
                return --from lib $(append "unexpected_ok:" $value);
            err(err_value)
                eq $err_value "" || return --from lib "bad_last_error_value";
                return --from lib "handled_error";
            end
        ]]>
    </block>
</process_chain>
</root>
"#;

    let ret = execute_lib(script, "test-first-ok-error").await?;
    assert_eq!(ret.value(), "handled_error");
    Ok(())
}

#[tokio::test]
async fn test_first_ok_propagates_control_without_swallowing() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            first-ok $(return --from lib "propagated") $(append "unexpected" "_fallback");

            return --from lib "after_first_ok";
        ]]>
    </block>
</process_chain>
</root>
"#;

    let ret = execute_lib(script, "test-first-ok-control").await?;
    assert_eq!(ret.value(), "propagated");
    Ok(())
}

#[tokio::test]
async fn test_first_ok_rejects_non_command_substitution_arguments() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            first-ok "literal" $(append "ok" "");
            return --from lib "unexpected";
        ]]>
    </block>
</process_chain>
</root>
"#;

    let hook_point = HookPoint::new("test-first-ok-parse-error");
    hook_point
        .load_process_chain_lib("test_first_ok_lib", 0, script)
        .await?;

    let data_dir = new_test_data_dir("test-first-ok-parse-error")?;
    let hook_point_env = HookPointEnv::new("test-first-ok-parse-error", data_dir);

    let err = hook_point_env
        .link_hook_point(&hook_point)
        .await
        .err()
        .ok_or_else(|| "link should fail for non-command-substitution first-ok arg".to_string())?;
    assert!(
        err.contains("first-ok expects command substitution arguments"),
        "unexpected link error: {}",
        err
    );

    Ok(())
}
