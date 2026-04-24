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

const PROCESS_CHAIN_COLLECTION_BASIC: &str = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            list-create --global nums;
            list-push nums "n1" "n2" "n3";
            list-set nums 1 "n2x";
            local list_order="";
            for idx, item in $nums then
                is-number $idx || error --from lib "list_idx_not_number";
                local list_order=$(append $list_order $item "|");
            end
            eq $list_order "n1|n2x|n3|" || error --from lib "list_order_bad";

            set-create --global tags;
            set-add tags "b" "a" "c" "a";
            local set_order="";
            for item in $tags then
                local set_order=$(append $set_order $item "|");
            end
            eq $set_order "b|a|c|" || error --from lib "set_order_bad";
            set-remove tags "a";
            set-add tags "d";
            local set_order_after="";
            for item in $tags then
                local set_order_after=$(append $set_order_after $item "|");
            end
            eq $set_order_after "b|c|d|" || error --from lib "set_remove_insert_order_bad";

            map-create --global routes;
            map-add routes "k2" "v2";
            map-add routes "k1" "v1";
            map-add routes "k3" "v3";
            local map_order="";
            for key, value in $routes then
                local map_order=$(append $map_order $key ":" $value "|");
            end
            eq $map_order "k2:v2|k1:v1|k3:v3|" || error --from lib "map_order_bad";
            map-add routes "k1" "v1b";
            map-remove routes "k2";
            map-add routes "k4" "v4";
            local map_order_after="";
            for key, value in $routes then
                local map_order_after=$(append $map_order_after $key ":" $value "|");
            end
            eq $map_order_after "k1:v1b|k3:v3|k4:v4|" || error --from lib "map_update_order_bad";

            map-create --multi --global mhosts;
            map-add mhosts "svc2" "b" "a";
            map-add mhosts "svc1" "x";
            map-add mhosts "svc2" "c" "a";
            local mm_order="";
            for key, values in $mhosts then
                local mm_order=$(append $mm_order $key ":");
                for item in $values then
                    local mm_order=$(append $mm_order $item ",");
                end
                local mm_order=$(append $mm_order "|");
            end
            eq $mm_order "svc2:b,a,c,|svc1:x,|" || error --from lib "multimap_order_bad";
            map-remove mhosts "svc2" "a";
            local mm_order_after="";
            for key, values in $mhosts then
                local mm_order_after=$(append $mm_order_after $key ":");
                for item in $values then
                    local mm_order_after=$(append $mm_order_after $item ",");
                end
                local mm_order_after=$(append $mm_order_after "|");
            end
            eq $mm_order_after "svc2:b,c,|svc1:x,|" || error --from lib "multimap_remove_order_bad";

            return --from lib "ok";
        ]]>
    </block>
</process_chain>
</root>
"#;

const PROCESS_CHAIN_COLLECTION_PERSIST_WRITE: &str = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            list-push p_list "a" "b" "c";
            list-set p_list 1 "x";

            set-add p_set "b" "a" "c";

            map-add p_map "k2" "v2";
            map-add p_map "k1" "v1";

            map-add p_mm "svc2" "b" "a";
            map-add p_mm "svc1" "x";

            return --from lib "write_ok";
        ]]>
    </block>
</process_chain>
</root>
"#;

const PROCESS_CHAIN_COLLECTION_PERSIST_READ: &str = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            local list_order="";
            for idx, item in $p_list then
                is-number $idx || error --from lib "persist_list_idx_not_number";
                local list_order=$(append $list_order $item "|");
            end
            eq $list_order "a|x|c|" || error --from lib "persist_list_order_bad";

            local set_order="";
            for item in $p_set then
                local set_order=$(append $set_order $item "|");
            end
            eq $set_order "b|a|c|" || error --from lib "persist_set_order_bad";

            local map_order="";
            for key, value in $p_map then
                local map_order=$(append $map_order $key ":" $value "|");
            end
            eq $map_order "k2:v2|k1:v1|" || error --from lib "persist_map_order_bad";

            local mm_order="";
            for key, values in $p_mm then
                local mm_order=$(append $mm_order $key ":");
                for item in $values then
                    local mm_order=$(append $mm_order $item ",");
                end
                local mm_order=$(append $mm_order "|");
            end
            eq $mm_order "svc2:b,a,|svc1:x,|" || error --from lib "persist_multimap_order_bad";

            return --from lib "ok";
        ]]>
    </block>
</process_chain>
</root>
"#;

const PROCESS_CHAIN_MAP_REDUCE_EXTERNAL_SCOPE: &str = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            map-create --block routes;
            map-add routes "k1" "v1";
            map-add routes "k2" "v2";

            capture --value last $(map $routes $(append $__key ":" $__value ":" $__key ":" $__value));
            eq $last "k2:v2:k2:v2" || error --from lib "map_result_bad";

            local seen="";
            map $routes $(capture --value seen $(append $seen $__key ":" $__value "|"));
            eq $seen "k1:v1|k2:v2|" || error --from lib "map_external_vars_bad";

            capture --value assigned $(map $routes $(capture --value __value $(append $__value "set")));
            eq $assigned "v2set" || error --from lib "map_external_set_bad";

            capture --value removed $(map $routes $(delete __value));
            eq $removed "v2" || error --from lib "map_external_remove_bad";

            eq $__key "" || error --from lib "map_key_leaked";
            eq $__value "" || error --from lib "map_value_leaked";

            return --from lib "ok";
        ]]>
    </block>
</process_chain>
</root>
"#;

#[tokio::test]
async fn test_collection_basic_semantics() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_collection_basic");
    hook_point
        .load_process_chain_lib(
            "test_collection_basic_lib",
            0,
            PROCESS_CHAIN_COLLECTION_BASIC,
        )
        .await?;

    let data_dir = new_test_data_dir("test-collection-basic")?;
    let hook_point_env = HookPointEnv::new("test-collection-basic", data_dir);
    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("test_collection_basic_lib").await?;
    assert_eq!(ret.value(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_map_reduce_external_vars_scope_cleanup() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_map_reduce_external_scope");
    hook_point
        .load_process_chain_lib(
            "test_map_reduce_external_scope_lib",
            0,
            PROCESS_CHAIN_MAP_REDUCE_EXTERNAL_SCOPE,
        )
        .await?;

    let data_dir = new_test_data_dir("test-map-reduce-external-scope")?;
    let hook_point_env = HookPointEnv::new("test-map-reduce-external-scope", data_dir);
    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec
        .execute_lib("test_map_reduce_external_scope_lib")
        .await?;
    assert_eq!(ret.value(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_collection_json_persistence_order() -> Result<(), String> {
    init_test_logger();

    let data_dir = new_test_data_dir("test-collection-persist-order")?;

    let write_hook_point = HookPoint::new("test_collection_persist_write");
    write_hook_point
        .load_process_chain_lib(
            "test_collection_persist_write_lib",
            0,
            PROCESS_CHAIN_COLLECTION_PERSIST_WRITE,
        )
        .await?;

    let write_env = HookPointEnv::new("test-collection-persist-write", data_dir.clone());
    write_env
        .load_collection(
            "p_list",
            CollectionType::List,
            CollectionFileFormat::Json,
            true,
        )
        .await?;
    write_env
        .load_collection(
            "p_set",
            CollectionType::Set,
            CollectionFileFormat::Json,
            true,
        )
        .await?;
    write_env
        .load_collection(
            "p_map",
            CollectionType::Map,
            CollectionFileFormat::Json,
            true,
        )
        .await?;
    write_env
        .load_collection(
            "p_mm",
            CollectionType::MultiMap,
            CollectionFileFormat::Json,
            true,
        )
        .await?;

    let write_exec = write_env.link_hook_point(&write_hook_point).await?;
    let write_ret = write_exec
        .execute_lib("test_collection_persist_write_lib")
        .await?;
    assert_eq!(write_ret.value(), "write_ok");
    write_env.flush_collections().await?;

    let read_hook_point = HookPoint::new("test_collection_persist_read");
    read_hook_point
        .load_process_chain_lib(
            "test_collection_persist_read_lib",
            0,
            PROCESS_CHAIN_COLLECTION_PERSIST_READ,
        )
        .await?;

    let read_env = HookPointEnv::new("test-collection-persist-read", data_dir.clone());
    read_env
        .load_collection(
            "p_list",
            CollectionType::List,
            CollectionFileFormat::Json,
            true,
        )
        .await?;
    read_env
        .load_collection(
            "p_set",
            CollectionType::Set,
            CollectionFileFormat::Json,
            true,
        )
        .await?;
    read_env
        .load_collection(
            "p_map",
            CollectionType::Map,
            CollectionFileFormat::Json,
            true,
        )
        .await?;
    read_env
        .load_collection(
            "p_mm",
            CollectionType::MultiMap,
            CollectionFileFormat::Json,
            true,
        )
        .await?;

    let read_exec = read_env.link_hook_point(&read_hook_point).await?;
    let read_ret = read_exec
        .execute_lib("test_collection_persist_read_lib")
        .await?;
    assert_eq!(read_ret.value(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_collection_sqlite_returns_explicit_error() -> Result<(), String> {
    init_test_logger();

    let data_dir = new_test_data_dir("test-collection-sqlite-unsupported")?;
    let hook_point_env = HookPointEnv::new("test-collection-sqlite-unsupported", data_dir);

    let cases = [
        ("sqlite_list", CollectionType::List),
        ("sqlite_set", CollectionType::Set),
        ("sqlite_map", CollectionType::Map),
        ("sqlite_mm", CollectionType::MultiMap),
    ];

    for (id, collection_type) in cases {
        let err = hook_point_env
            .load_collection(id, collection_type, CollectionFileFormat::Sqlite, true)
            .await
            .expect_err("sqlite collection should return explicit unsupported error");
        assert!(
            err.contains("Sqlite collection format is not supported yet"),
            "unexpected error: {}",
            err
        );
    }

    Ok(())
}
