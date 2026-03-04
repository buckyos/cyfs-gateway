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

const PROCESS_CHAIN_EQ_STRICT: &str = r#"
<process_chain_lib id="eq_strict_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                local i=1;
                local f=1.0;
                local b=true;
                local z=null;

                eq $i 1 || return --from lib "strict_int_fail";
                eq $i "1" && return --from lib "strict_cross_type_should_fail";
                eq $i $f && return --from lib "strict_number_variant_should_fail";

                eq $b true || return --from lib "strict_bool_fail";
                eq $b "true" && return --from lib "strict_bool_string_should_fail";

                eq $z null || return --from lib "strict_null_fail";
                eq $z "null" && return --from lib "strict_null_string_should_fail";

                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_EQ_IGNORE_CASE_STRICT: &str = r#"
<process_chain_lib id="eq_ignore_case_strict_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                eq --ignore-case "Host" "HOST" || return --from lib "ignore_case_string_fail";
                eq --ignore-case true "TRUE" && return --from lib "ignore_case_cross_type_should_fail";
                eq --ignore-case "abc" "abD" && return --from lib "ignore_case_mismatch_should_fail";
                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_EQ_LOOSE: &str = r#"
<process_chain_lib id="eq_loose_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                eq --loose 1 "1" || return --from lib "loose_num_string_fail";
                eq --loose "1.5" 1.5 || return --from lib "loose_float_string_fail";
                eq --loose 1 1.0 || return --from lib "loose_int_float_fail";
                eq --loose true true || return --from lib "loose_bool_same_type_fail";
                eq --loose true "TRUE" && return --from lib "loose_bool_string_should_fail";
                eq --loose false 0 && return --from lib "loose_bool_num_should_fail";
                eq --loose "false" 0 && return --from lib "loose_string_num_bool_should_fail";
                eq --loose --ignore-case "Host" "HOST" || return --from lib "loose_ignore_case_fail";

                eq --loose null "null" && return --from lib "loose_null_string_should_fail";
                eq --loose "abc" true && return --from lib "loose_invalid_cast_should_fail";
                eq --loose "yes" true && return --from lib "loose_yes_should_fail";
                eq --loose "on" true && return --from lib "loose_on_should_fail";
                eq --loose "no" false && return --from lib "loose_no_should_fail";

                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

#[tokio::test]
async fn test_eq_strict_typed_comparison() -> Result<(), String> {
    init_test_logger();
    let ret = execute_lib(PROCESS_CHAIN_EQ_STRICT, "eq_strict_lib", "test-eq-strict").await?;
    assert_eq!(ret, "ok");
    Ok(())
}

#[tokio::test]
async fn test_eq_ignore_case_only_applies_to_strings() -> Result<(), String> {
    init_test_logger();
    let ret = execute_lib(
        PROCESS_CHAIN_EQ_IGNORE_CASE_STRICT,
        "eq_ignore_case_strict_lib",
        "test-eq-ignore-case-strict",
    )
    .await?;
    assert_eq!(ret, "ok");
    Ok(())
}

#[tokio::test]
async fn test_eq_loose_comparison() -> Result<(), String> {
    init_test_logger();
    let ret = execute_lib(PROCESS_CHAIN_EQ_LOOSE, "eq_loose_lib", "test-eq-loose").await?;
    assert_eq!(ret, "ok");
    Ok(())
}
