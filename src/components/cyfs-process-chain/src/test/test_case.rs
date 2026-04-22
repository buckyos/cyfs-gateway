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

async fn execute_with_req(script: &str, host: &str, path: &str) -> Result<String, String> {
    let hook_point = HookPoint::new("test_case_hook");
    hook_point
        .load_process_chain_lib("test_case_lib", 0, script)
        .await?;

    let data_dir = new_test_data_dir("test-case")?;
    let hook_point_env = HookPointEnv::new("test-case", data_dir);

    let req = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    req.insert("host", CollectionValue::String(host.to_string()))
        .await?;
    req.insert("path", CollectionValue::String(path.to_string()))
        .await?;

    hook_point_env
        .hook_point_env()
        .create("REQ", CollectionValue::Map(req))
        .await?;

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("test_case_lib").await?;
    Ok(ret.value().to_string())
}

#[tokio::test]
async fn test_case_when_supports_existing_predicate_commands() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            case then
                when match-reg $REQ.host "^admin\\." then
                    return --from lib "host_admin";
                when strip-prefix $REQ.path "/api" then
                    return --from lib "api_path";
                else
                    return --from lib "default";
                end
        ]]>
    </block>
</process_chain>
</root>
"#;

    assert_eq!(
        execute_with_req(script, "admin.example.com", "/misc").await?,
        "host_admin"
    );
    assert_eq!(
        execute_with_req(script, "user.example.com", "/api/users").await?,
        "api_path"
    );
    assert_eq!(
        execute_with_req(script, "user.example.com", "/misc").await?,
        "default"
    );

    Ok(())
}

#[tokio::test]
async fn test_case_missing_when_rejected() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            case then
                return --from lib "bad";
            end
        ]]>
    </block>
</process_chain>
</root>
"#;

    let hook_point = HookPoint::new("test_case_missing_when");
    let err = match hook_point
        .load_process_chain_lib("test_case_lib", 0, script)
        .await
    {
        Ok(_) => {
            return Err("load_process_chain_lib should fail for missing when branch".to_string());
        }
        Err(err) => err,
    };
    assert!(
        err.contains("requires a 'when ... then' branch"),
        "unexpected error: {}",
        err
    );

    Ok(())
}

#[tokio::test]
async fn test_case_condition_rejects_control_action() -> Result<(), String> {
    init_test_logger();

    let script = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            case then
                when return "not_allowed" then
                    return --from lib "bad";
                else
                    return --from lib "ok";
                end
        ]]>
    </block>
</process_chain>
</root>
"#;

    let hook_point = HookPoint::new("test_case_control_in_condition");
    hook_point
        .load_process_chain_lib("test_case_lib", 0, script)
        .await?;

    let data_dir = new_test_data_dir("test-case-control")?;
    let hook_point_env = HookPointEnv::new("test-case-control", data_dir);
    let exec = hook_point_env.link_hook_point(&hook_point).await?;

    let err = match exec.execute_lib("test_case_lib").await {
        Ok(ret) => return Err(format!("expected runtime error, got {:?}", ret)),
        Err(err) => err,
    };
    assert!(
        err.contains("Control action is not allowed in case condition"),
        "unexpected error: {}",
        err
    );

    Ok(())
}
