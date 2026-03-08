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
    let data_dir = std::env::temp_dir().join(format!("cyfs-process-chain-{}-{}-{}", scope, pid, ts));
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| format!("create test data dir {:?} failed: {}", data_dir, e))?;
    Ok(data_dir)
}

async fn execute_with_req(script: &str, role: &str, protocol: &str, inner: &str) -> Result<String, String> {
    let hook_point = HookPoint::new("test_if_hook");
    hook_point
        .load_process_chain_lib("test_if_lib", 0, script)
        .await?;

    let data_dir = new_test_data_dir("test-if")?;
    let hook_point_env = HookPointEnv::new("test-if", data_dir);

    let req = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    req.insert("role", CollectionValue::String(role.to_string()))
        .await?;
    req.insert("protocol", CollectionValue::String(protocol.to_string()))
        .await?;
    req.insert("inner", CollectionValue::String(inner.to_string()))
        .await?;
    req.insert("stage", CollectionValue::String("outer".to_string()))
        .await?;

    hook_point_env
        .hook_point_env()
        .create("REQ", CollectionValue::Map(req))
        .await?;

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("test_if_lib").await?;
    Ok(ret.value().to_string())
}

#[tokio::test]
async fn test_if_elif_else_branch_selection() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            if eq $REQ.role "admin" then
                return --from lib "admin";
            elif eq $REQ.role "user" then
                return --from lib "user";
            else
                return --from lib "guest";
            end
        ]]>
    </block>
</process_chain>
</root>
"#;

    assert_eq!(execute_with_req(script, "admin", "https", "yes").await?, "admin");
    assert_eq!(execute_with_req(script, "user", "https", "yes").await?, "user");
    assert_eq!(execute_with_req(script, "visitor", "https", "yes").await?, "guest");
    Ok(())
}

#[tokio::test]
async fn test_if_not_condition() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            if !eq $REQ.protocol "https" then
                return --from lib "reject";
            else
                return --from lib "accept";
            end
        ]]>
    </block>
</process_chain>
</root>
"#;

    assert_eq!(execute_with_req(script, "user", "https", "yes").await?, "accept");
    assert_eq!(execute_with_req(script, "user", "http", "yes").await?, "reject");
    Ok(())
}

#[tokio::test]
async fn test_if_nested_branches() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            if eq $REQ.stage "outer" then
                if eq $REQ.inner "yes" then
                    return --from lib "nested_yes";
                else
                    return --from lib "nested_no";
                end
            else
                return --from lib "outer_no";
            end
        ]]>
    </block>
</process_chain>
</root>
"#;

    assert_eq!(execute_with_req(script, "user", "https", "yes").await?, "nested_yes");
    assert_eq!(execute_with_req(script, "user", "https", "no").await?, "nested_no");
    Ok(())
}

#[tokio::test]
async fn test_if_missing_end_rejected() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            if eq "a" "a" then
                return --from lib "ok";
        ]]>
    </block>
</process_chain>
</root>
"#;

    let hook_point = HookPoint::new("test_if_missing_end");
    let err = match hook_point.load_process_chain_lib("test_if_lib", 0, script).await {
        Ok(_) => return Err("load_process_chain_lib should fail for missing end".to_string()),
        Err(err) => err,
    };
    assert!(err.contains("Missing 'end'"), "unexpected error: {}", err);
    Ok(())
}

#[tokio::test]
async fn test_if_condition_rejects_control_action() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            if return "not_allowed" then
                return --from lib "bad";
            else
                return --from lib "ok";
            end
        ]]>
    </block>
</process_chain>
</root>
"#;

    let hook_point = HookPoint::new("test_if_control_in_condition");
    hook_point
        .load_process_chain_lib("test_if_lib", 0, script)
        .await?;

    let data_dir = new_test_data_dir("test-if-control-condition")?;
    let hook_point_env = HookPointEnv::new("test-if-control-condition", data_dir);
    let exec = hook_point_env.link_hook_point(&hook_point).await?;

    let err = match exec.execute_lib("test_if_lib").await {
        Ok(ret) => {
            return Err(format!(
                "execute_lib should fail when condition returns control action, got: {:?}",
                ret
            ));
        }
        Err(err) => err,
    };
    assert!(
        err.contains("Control action is not allowed in if condition"),
        "unexpected error: {}",
        err
    );
    Ok(())
}

#[tokio::test]
async fn test_if_comparison_operator_sugar() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            local one=1;
            if $one == "1" then
                if $one === "1" then
                    return --from lib "strict_should_fail";
                end
            else
                return --from lib "loose_should_match";
            end

            if $REQ.role === "admin" then
                return --from lib "strict_role_ok";
            end

            if $REQ.role == "ADMIN" then
                return --from lib "loose_case_should_not_match";
            end

            return --from lib "final";
        ]]>
    </block>
</process_chain>
</root>
"#;

    assert_eq!(
        execute_with_req(script, "admin", "https", "yes").await?,
        "strict_role_ok"
    );
    assert_eq!(
        execute_with_req(script, "user", "https", "yes").await?,
        "final"
    );
    Ok(())
}

#[tokio::test]
async fn test_if_not_equal_operator_sugar() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            local one=1;
            if $one != "1" then
                return --from lib "loose_ne_should_fail";
            end

            if $one !== "1" then
                if $REQ.role == "admin" then
                    return --from lib "strict_ne_branch";
                end
            end

            if $REQ.role !== "admin" then
                return --from lib "non_admin";
            end

            return --from lib "admin";
        ]]>
    </block>
</process_chain>
</root>
"#;

    assert_eq!(
        execute_with_req(script, "admin", "https", "yes").await?,
        "strict_ne_branch"
    );
    assert_eq!(
        execute_with_req(script, "user", "https", "yes").await?,
        "non_admin"
    );
    Ok(())
}

#[tokio::test]
async fn test_if_numeric_comparison_operator_sugar() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            local one=1;
            local pi=3.14;

            if $one > 0 then
            else
                return --from lib "gt_fail";
            end

            if $one >= 1 then
            else
                return --from lib "ge_fail";
            end

            if $one < 2 then
            else
                return --from lib "lt_fail";
            end

            if $one <= 1 then
            else
                return --from lib "le_fail";
            end

            if $pi >= 3.0 then
            else
                return --from lib "float_ge_fail";
            end

            if $one < "2" then
                return --from lib "strict_should_not_loose";
            end

            return --from lib "ok";
        ]]>
    </block>
</process_chain>
</root>
"#;

    assert_eq!(execute_with_req(script, "user", "https", "yes").await?, "ok");
    Ok(())
}
