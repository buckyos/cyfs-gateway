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

const PROCESS_CHAIN_LIST_BASIC: &str = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            list-create --global test_list;
            list-push test_list "a" "b";
            list-insert test_list 1 "x";
            match-include test_list "a" "x" "b" || error --from lib "missing_after_insert";

            list-set test_list 0 "a0";
            !match-include test_list "a" || error --from lib "old_value_still_exists";
            match-include test_list "a0" "x" "b" || error --from lib "set_failed";

            list-remove test_list 1;
            !match-include test_list "x" || error --from lib "remove_failed";

            list-pop test_list;
            !match-include test_list "b" || error --from lib "pop_failed";

            list-clear test_list;
            match-include test_list "a0" && error --from lib "clear_failed";

            return --from lib "ok";
        ]]>
    </block>
</process_chain>
</root>
"#;

const PROCESS_CHAIN_LIST_REFERENCE: &str = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            list-create --global records;
            map-create --global payload;
            map-add payload key origin;
            list-push records $payload;
            map-add payload key updated;
            return --from lib "ok";
        ]]>
    </block>
</process_chain>
</root>
"#;

const PROCESS_CHAIN_LIST_INVALID_INDEX: &str = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            list-create --global test_list;
            list-push test_list "a";
            list-insert test_list abc "x";
            return --from lib "bad";
        ]]>
    </block>
</process_chain>
</root>
"#;

#[tokio::test]
async fn test_list_commands_basic_flow() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_list_basic");
    hook_point
        .load_process_chain_lib("test_list_basic_lib", 0, PROCESS_CHAIN_LIST_BASIC)
        .await?;

    let data_dir = new_test_data_dir("test-list-basic")?;
    let hook_point_env = HookPointEnv::new("test-list-basic", data_dir);
    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("test_list_basic_lib").await?;
    assert_eq!(ret.value(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_list_push_keeps_collection_reference_semantics() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_list_reference");
    hook_point
        .load_process_chain_lib("test_list_reference_lib", 0, PROCESS_CHAIN_LIST_REFERENCE)
        .await?;

    let data_dir = new_test_data_dir("test-list-reference")?;
    let hook_point_env = HookPointEnv::new("test-list-reference", data_dir);
    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let lib_exec = exec.prepare_exec_lib("test_list_reference_lib")?;
    let global_env = lib_exec.global_env().clone();
    let ret = lib_exec.execute_lib().await?;
    assert_eq!(ret.value(), "ok");

    let records = global_env
        .get("records")
        .await?
        .ok_or_else(|| "records missing".to_string())?;
    let records = match records {
        CollectionValue::List(list) => list,
        other => return Err(format!("records is not list, got {}", other.get_type())),
    };

    let first = records
        .get(0)
        .await?
        .ok_or_else(|| "records[0] missing".to_string())?;
    let payload = match first {
        CollectionValue::Map(map) => map,
        other => return Err(format!("records[0] is not map, got {}", other.get_type())),
    };

    let key = payload
        .get("key")
        .await?
        .ok_or_else(|| "payload.key missing".to_string())?;
    assert_eq!(key.as_str(), Some("updated"));

    Ok(())
}

#[tokio::test]
async fn test_list_insert_rejects_invalid_index() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_list_invalid_index");
    hook_point
        .load_process_chain_lib(
            "test_list_invalid_index_lib",
            0,
            PROCESS_CHAIN_LIST_INVALID_INDEX,
        )
        .await?;

    let data_dir = new_test_data_dir("test-list-invalid-index")?;
    let hook_point_env = HookPointEnv::new("test-list-invalid-index", data_dir);
    let exec = hook_point_env.link_hook_point(&hook_point).await?;

    let err = match exec.execute_lib("test_list_invalid_index_lib").await {
        Ok(ret) => return Err(format!("execute should fail, got: {:?}", ret)),
        Err(err) => err,
    };
    assert!(err.contains("Invalid index"), "unexpected error: {}", err);

    Ok(())
}
