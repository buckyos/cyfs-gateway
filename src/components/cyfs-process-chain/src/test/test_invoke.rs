use crate::*;
use simplelog::*;
use std::path::PathBuf;
use std::sync::Arc;
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
async fn test_invoke_chain_with_named_args() -> Result<(), String> {
    init_test_logger();

    let process_chain = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            local result = $(invoke --chain callee --arg user $REQ.user --arg pass "p1");
            eq $result "alice:p1" && return --from lib "ok";
            return --from lib "bad";
        ]]>
    </block>
</process_chain>
<process_chain id="callee">
    <block id="worker">
        <![CDATA[
            local user = $__args.user;
            local pass = $__args.pass;
            return --from chain $(append $user ":" $pass);
        ]]>
    </block>
</process_chain>
</root>
"#;

    let hook_point = HookPoint::new("test_invoke_named_args");
    hook_point
        .load_process_chain_lib("invoke_named_args_lib", 0, process_chain)
        .await?;

    let data_dir = new_test_data_dir("test-invoke-named-args")?;
    let hook_point_env = HookPointEnv::new("test-invoke-named-args", data_dir);

    let req = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    req.insert("user", CollectionValue::String("alice".to_string()))
        .await?;
    hook_point_env
        .hook_point_env()
        .create("REQ", CollectionValue::Map(req))
        .await?;

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("invoke_named_args_lib").await?;
    assert_eq!(ret.value(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_invoke_collection_reference_semantics() -> Result<(), String> {
    init_test_logger();

    let process_chain = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            map-create --chain input;
            map-add input key origin;
            invoke --chain mutate --arg req $input;
            return --from lib $input.key;
        ]]>
    </block>
</process_chain>
<process_chain id="mutate">
    <block id="worker">
        <![CDATA[
            map-add $__args.req key changed;
            return --from chain ok;
        ]]>
    </block>
</process_chain>
</root>
"#;

    let hook_point = HookPoint::new("test_invoke_reference_semantics");
    hook_point
        .load_process_chain_lib("invoke_reference_semantics_lib", 0, process_chain)
        .await?;

    let data_dir = new_test_data_dir("test-invoke-reference-semantics")?;
    let hook_point_env = HookPointEnv::new("test-invoke-reference-semantics", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("invoke_reference_semantics_lib").await?;
    assert_eq!(ret.value(), "changed");

    Ok(())
}

#[tokio::test]
async fn test_invoke_invalid_arg_key_rejected() -> Result<(), String> {
    init_test_logger();

    let process_chain = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            invoke --chain helper --arg 1bad_key value;
            return --from lib "unexpected";
        ]]>
    </block>
</process_chain>
<process_chain id="helper">
    <block id="worker">
        <![CDATA[
            return --from chain ok;
        ]]>
    </block>
</process_chain>
</root>
"#;

    let hook_point = HookPoint::new("test_invoke_invalid_arg_key");
    hook_point
        .load_process_chain_lib("invoke_invalid_arg_key_lib", 0, process_chain)
        .await?;

    let data_dir = new_test_data_dir("test-invoke-invalid-arg-key")?;
    let hook_point_env = HookPointEnv::new("test-invoke-invalid-arg-key", data_dir);
    let err = match hook_point_env.link_hook_point(&hook_point).await {
        Ok(_) => return Err("link_hook_point should fail for invalid invoke arg key".to_string()),
        Err(err) => err,
    };
    assert!(
        err.contains("Invalid invoke arg key"),
        "unexpected error: {}",
        err
    );

    Ok(())
}

#[tokio::test]
async fn test_invoke_duplicate_arg_key_rejected() -> Result<(), String> {
    init_test_logger();

    let process_chain = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            invoke --chain helper --arg key a --arg key b;
            return --from lib "unexpected";
        ]]>
    </block>
</process_chain>
<process_chain id="helper">
    <block id="worker">
        <![CDATA[
            return --from chain ok;
        ]]>
    </block>
</process_chain>
</root>
"#;

    let hook_point = HookPoint::new("test_invoke_duplicate_arg_key");
    hook_point
        .load_process_chain_lib("invoke_duplicate_arg_key_lib", 0, process_chain)
        .await?;

    let data_dir = new_test_data_dir("test-invoke-duplicate-arg-key")?;
    let hook_point_env = HookPointEnv::new("test-invoke-duplicate-arg-key", data_dir);
    let err = match hook_point_env.link_hook_point(&hook_point).await {
        Ok(_) => {
            return Err("link_hook_point should fail for duplicate invoke arg key".to_string());
        }
        Err(err) => err,
    };
    assert!(
        err.contains("Duplicate invoke arg key"),
        "unexpected error: {}",
        err
    );

    Ok(())
}

#[tokio::test]
async fn test_invoke_typed_return_payload_preserved() -> Result<(), String> {
    init_test_logger();

    let process_chain = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            local n = $(invoke --chain callee_number);
            is-number $n || return --from lib "not-number";

            local b = $(invoke --chain callee_bool);
            is-bool $b || return --from lib "not-bool";

            return --from lib $(append $(type $n) "|" $(type $b));
        ]]>
    </block>
</process_chain>
<process_chain id="callee_number">
    <block id="worker">
        <![CDATA[
            return --from chain 123;
        ]]>
    </block>
</process_chain>
<process_chain id="callee_bool">
    <block id="worker">
        <![CDATA[
            return --from chain true;
        ]]>
    </block>
</process_chain>
</root>
"#;

    let hook_point = HookPoint::new("test_invoke_typed_return_payload");
    hook_point
        .load_process_chain_lib("invoke_typed_payload_lib", 0, process_chain)
        .await?;

    let data_dir = new_test_data_dir("test-invoke-typed-return-payload")?;
    let hook_point_env = HookPointEnv::new("test-invoke-typed-return-payload", data_dir);
    let exec = hook_point_env.link_hook_point(&hook_point).await?;

    let ret = exec.execute_lib("invoke_typed_payload_lib").await?;
    assert_eq!(ret.value(), "Number|Bool");

    Ok(())
}
