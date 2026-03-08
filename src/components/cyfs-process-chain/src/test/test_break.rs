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

const PROCESS_CHAIN_BREAK_OUTSIDE_MAP: &str = r#"
<process_chain_lib id="break_outside_map_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                break "stop";
                return --from lib "unexpected";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_BREAK_IN_MAP_REDUCE_VALID: &str = r#"
<process_chain_lib id="break_in_map_reduce_valid_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                set-create --block stop_set;
                set-add stop_set "a" "b" "c";
                map $stop_set $(break "stop") reduce $(echo "done");

                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

#[tokio::test]
async fn test_break_outside_map_returns_error() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_break_outside_map");
    hook_point
        .load_process_chain_lib("break_outside_map_lib", 0, PROCESS_CHAIN_BREAK_OUTSIDE_MAP)
        .await?;

    let data_dir = new_test_data_dir("test-break-outside-map")?;
    let hook_point_env = HookPointEnv::new("test-break-outside-map", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let err = exec
        .execute_lib("break_outside_map_lib")
        .await
        .err()
        .ok_or_else(|| "break outside map should fail".to_string())?;

    assert!(
        err.contains("break action only valid in map-reduce loop"),
        "unexpected error: {}",
        err
    );

    Ok(())
}

#[tokio::test]
async fn test_break_inside_map_with_reduce_is_valid() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_break_in_map_reduce_valid");
    hook_point
        .load_process_chain_lib(
            "break_in_map_reduce_valid_lib",
            0,
            PROCESS_CHAIN_BREAK_IN_MAP_REDUCE_VALID,
        )
        .await?;

    let data_dir = new_test_data_dir("test-break-in-map-reduce-valid")?;
    let hook_point_env = HookPointEnv::new("test-break-in-map-reduce-valid", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("break_in_map_reduce_valid_lib").await?;
    assert_eq!(ret.value(), "ok");

    Ok(())
}
