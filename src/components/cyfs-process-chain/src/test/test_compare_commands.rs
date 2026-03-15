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

async fn execute_lib(script: &str, lib_id: &str, scope: &str) -> Result<String, String> {
    let hook_point = HookPoint::new(scope);
    hook_point.load_process_chain_lib(lib_id, 0, script).await?;

    let data_dir = new_test_data_dir(scope)?;
    let hook_point_env = HookPointEnv::new(scope, data_dir);
    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib(lib_id).await?;
    Ok(ret.value().to_string())
}

const PROCESS_CHAIN_NUMBER_COMPARE: &str = r#"
<process_chain_lib id="number_compare_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                gt 10 9 || return --from lib "gt_basic_fail";
                ge 10 10 || return --from lib "ge_basic_fail";
                lt 1 2 || return --from lib "lt_basic_fail";
                le 2 2 || return --from lib "le_basic_fail";

                gt 2 3 && return --from lib "gt_false_should_not_pass";
                ge 2 3 && return --from lib "ge_false_should_not_pass";
                lt 3 2 && return --from lib "lt_false_should_not_pass";
                le 3 2 && return --from lib "le_false_should_not_pass";

                gt "12" 2 && return --from lib "gt_strict_string_should_fail";
                gt --loose "12" 2 || return --from lib "gt_loose_string_number_fail";
                lt --loose "1.5" 2 || return --from lib "lt_loose_float_string_fail";
                ge --loose 2 "2" || return --from lib "ge_loose_mixed_fail";
                le --loose "2.0" 2 || return --from lib "le_loose_mixed_fail";

                gt --loose true 0 && return --from lib "gt_loose_bool_should_fail";
                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_NE_COMPARE: &str = r#"
<process_chain_lib id="ne_compare_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                ne 1 "1" || return --from lib "ne_strict_cross_type_should_true";
                ne --loose 1 "1" && return --from lib "ne_loose_num_string_should_false";

                ne --ignore-case "Host" "HOST" && return --from lib "ne_ignore_case_should_false";
                ne --ignore-case "Host" "Other" || return --from lib "ne_ignore_case_should_true";

                ne true false || return --from lib "ne_bool_basic_fail";
                ne true true && return --from lib "ne_bool_equal_should_false";
                ne --loose true "true" || return --from lib "ne_loose_bool_string_should_true";

                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

#[tokio::test]
async fn test_number_compare_commands() -> Result<(), String> {
    init_test_logger();
    let ret = execute_lib(
        PROCESS_CHAIN_NUMBER_COMPARE,
        "number_compare_lib",
        "test-number-compare",
    )
    .await?;
    assert_eq!(ret, "ok");
    Ok(())
}

#[tokio::test]
async fn test_ne_command() -> Result<(), String> {
    init_test_logger();
    let ret = execute_lib(
        PROCESS_CHAIN_NE_COMPARE,
        "ne_compare_lib",
        "test-ne-compare",
    )
    .await?;
    assert_eq!(ret, "ok");
    Ok(())
}
