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

#[tokio::test]
async fn test_for_list_break_and_accumulate() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            list-create --global values;
            list-push values "a" "b" "c";
            local out="";
            for item in $values then
                local out=$(append $out $item);
                eq $item "b" && break "stop";
            end
            return --from lib $out;
        ]]>
    </block>
</process_chain>
</root>
"#;

    let hook_point = HookPoint::new("test_for_list_break");
    hook_point
        .load_process_chain_lib("test_for_list_break_lib", 0, script)
        .await?;

    let data_dir = new_test_data_dir("test-for-list-break")?;
    let hook_point_env = HookPointEnv::new("test-for-list-break", data_dir);
    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("test_for_list_break_lib").await?;
    assert_eq!(ret.value(), "ab");

    Ok(())
}

#[tokio::test]
async fn test_for_map_key_value_iteration() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            map-create --global routes;
            map-add routes "/kapi/a/*" "up_a";
            map-add routes "/kapi/b/*" "up_b";

            set-create --global seen;
            map-create --global copied;

            for key, value in $routes then
                set-add seen $key;
                map-add copied $key $value;
            end

            match-include seen "/kapi/a/*" || error --from lib "missing_key_a";
            match-include seen "/kapi/b/*" || error --from lib "missing_key_b";
            eq ${copied["/kapi/a/*"]} "up_a" || error --from lib "copied_a_bad";
            eq ${copied["/kapi/b/*"]} "up_b" || error --from lib "copied_b_bad";
            return --from lib "ok";
        ]]>
    </block>
</process_chain>
</root>
"#;

    let hook_point = HookPoint::new("test_for_map_kv");
    hook_point
        .load_process_chain_lib("test_for_map_kv_lib", 0, script)
        .await?;

    let data_dir = new_test_data_dir("test-for-map-kv")?;
    let hook_point_env = HookPointEnv::new("test-for-map-kv", data_dir);
    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("test_for_map_kv_lib").await?;
    assert_eq!(ret.value(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_for_multimap_key_value_iteration() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            map-create --multi --global tags;
            map-add tags "svc1" "tag1" "tag2";
            map-add tags "svc2" "tag3";

            set-create --global seen_keys;
            set-create --global seen_values;

            for key, value in $tags then
                set-add seen_keys $key;
                match-include $value "tag1" && set-add seen_values "tag1";
                match-include $value "tag3" && set-add seen_values "tag3";
            end

            match-include seen_keys "svc1" || error --from lib "missing_svc1";
            match-include seen_keys "svc2" || error --from lib "missing_svc2";
            match-include seen_values "tag1" || error --from lib "missing_tag1";
            match-include seen_values "tag3" || error --from lib "missing_tag3";
            return --from lib "ok";
        ]]>
    </block>
</process_chain>
</root>
"#;

    let hook_point = HookPoint::new("test_for_multimap_kv");
    hook_point
        .load_process_chain_lib("test_for_multimap_kv_lib", 0, script)
        .await?;

    let data_dir = new_test_data_dir("test-for-multimap-kv")?;
    let hook_point_env = HookPointEnv::new("test-for-multimap-kv", data_dir);
    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("test_for_multimap_kv_lib").await?;
    assert_eq!(ret.value(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_for_loop_var_shadow_restored() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            list-create --global values;
            list-push values "x" "y";
            local item="outer";

            for item in $values then
                echo $item;
            end

            return --from lib $item;
        ]]>
    </block>
</process_chain>
</root>
"#;

    let hook_point = HookPoint::new("test_for_shadow_restore");
    hook_point
        .load_process_chain_lib("test_for_shadow_restore_lib", 0, script)
        .await?;

    let data_dir = new_test_data_dir("test-for-shadow-restore")?;
    let hook_point_env = HookPointEnv::new("test-for-shadow-restore", data_dir);
    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("test_for_shadow_restore_lib").await?;
    assert_eq!(ret.value(), "outer");

    Ok(())
}

#[tokio::test]
async fn test_for_loop_vars_are_local_only() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            list-create --global values;
            list-push values "x";

            for idx, item in $values then
                echo $idx $item;
            end

            return --from lib $idx;
        ]]>
    </block>
</process_chain>
</root>
"#;

    let hook_point = HookPoint::new("test_for_scope_cleanup");
    hook_point
        .load_process_chain_lib("test_for_scope_cleanup_lib", 0, script)
        .await?;

    let data_dir = new_test_data_dir("test-for-scope-cleanup")?;
    let hook_point_env = HookPointEnv::new("test-for-scope-cleanup", data_dir);
    hook_point_env.set_missing_var_policy(MissingVarPolicy::Strict);
    let exec = hook_point_env.link_hook_point(&hook_point).await?;

    let err = match exec.execute_lib("test_for_scope_cleanup_lib").await {
        Ok(ret) => return Err(format!("execute should fail, got: {:?}", ret)),
        Err(err) => err,
    };
    assert!(
        err.contains("Variable 'idx' not found"),
        "unexpected error: {}",
        err
    );

    Ok(())
}

#[tokio::test]
async fn test_for_map_disallow_write_during_iteration() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            map-create --global routes;
            map-add routes "k1" "v1";
            map-add routes "k2" "v2";

            for key, value in $routes then
                map-remove routes $key;
            end

            return --from lib "ok";
        ]]>
    </block>
</process_chain>
</root>
"#;

    let hook_point = HookPoint::new("test_for_map_write_guard");
    hook_point
        .load_process_chain_lib("test_for_map_write_guard_lib", 0, script)
        .await?;

    let data_dir = new_test_data_dir("test-for-map-write-guard")?;
    let hook_point_env = HookPointEnv::new("test-for-map-write-guard", data_dir);
    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let err = match exec.execute_lib("test_for_map_write_guard_lib").await {
        Ok(ret) => return Err(format!("execute should fail, got: {:?}", ret)),
        Err(err) => err,
    };
    assert!(
        err.contains("during traversal"),
        "unexpected error: {}",
        err
    );

    Ok(())
}

#[tokio::test]
async fn test_for_multimap_disallow_write_during_iteration() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            map-create --multi --global tags;
            map-add tags "svc1" "tag1";
            map-add tags "svc2" "tag2";

            for key in $tags then
                map-remove tags $key "tag1";
            end

            return --from lib "ok";
        ]]>
    </block>
</process_chain>
</root>
"#;

    let hook_point = HookPoint::new("test_for_multimap_write_guard");
    hook_point
        .load_process_chain_lib("test_for_multimap_write_guard_lib", 0, script)
        .await?;

    let data_dir = new_test_data_dir("test-for-multimap-write-guard")?;
    let hook_point_env = HookPointEnv::new("test-for-multimap-write-guard", data_dir);
    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let err = match exec.execute_lib("test_for_multimap_write_guard_lib").await {
        Ok(ret) => return Err(format!("execute should fail, got: {:?}", ret)),
        Err(err) => err,
    };
    assert!(
        err.contains("during traversal"),
        "unexpected error: {}",
        err
    );

    Ok(())
}

#[tokio::test]
async fn test_for_list_disallow_write_during_iteration() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            list-create --global values;
            list-push values "a" "b";

            for idx, item in $values then
                list-push values "x";
            end

            return --from lib "ok";
        ]]>
    </block>
</process_chain>
</root>
"#;

    let hook_point = HookPoint::new("test_for_list_write_guard");
    hook_point
        .load_process_chain_lib("test_for_list_write_guard_lib", 0, script)
        .await?;

    let data_dir = new_test_data_dir("test-for-list-write-guard")?;
    let hook_point_env = HookPointEnv::new("test-for-list-write-guard", data_dir);
    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let err = match exec.execute_lib("test_for_list_write_guard_lib").await {
        Ok(ret) => return Err(format!("execute should fail, got: {:?}", ret)),
        Err(err) => err,
    };
    assert!(
        err.contains("during traversal"),
        "unexpected error: {}",
        err
    );

    Ok(())
}

#[tokio::test]
async fn test_for_set_disallow_write_during_iteration() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            set-create --global tags;
            set-add tags "a" "b";

            for tag in $tags then
                set-add tags "x";
            end

            return --from lib "ok";
        ]]>
    </block>
</process_chain>
</root>
"#;

    let hook_point = HookPoint::new("test_for_set_write_guard");
    hook_point
        .load_process_chain_lib("test_for_set_write_guard_lib", 0, script)
        .await?;

    let data_dir = new_test_data_dir("test-for-set-write-guard")?;
    let hook_point_env = HookPointEnv::new("test-for-set-write-guard", data_dir);
    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let err = match exec.execute_lib("test_for_set_write_guard_lib").await {
        Ok(ret) => return Err(format!("execute should fail, got: {:?}", ret)),
        Err(err) => err,
    };
    assert!(
        err.contains("during traversal"),
        "unexpected error: {}",
        err
    );

    Ok(())
}
