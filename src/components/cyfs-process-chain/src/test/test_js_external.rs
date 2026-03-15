use crate::*;
use simplelog::*;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Once;
use std::time::{SystemTime, UNIX_EPOCH};

const JS_CHECK_HOST_COMMAND: &str = r#"
const host_list = [
    { host: "*.google.com" },
    { host: "*.buckyos.com" },
];

function test_set_coll() {
    let set = new SetCollection();
    let ret = set.insert("google.com");
    console.assert(ret, "Insert google.com failed");
    set.insert("buckyos.com");
    console.assert(set.contains("google.com"), "Set should contain google.com");
    console.assert(set.contains("buckyos.com"), "Set should contain buckyos.com");
    set.remove("google.com");
    console.assert(!set.contains("google.com"), "Set should not contain google.com after removal");
}

function test_map_coll() {
    let map = new MapCollection();
    let ret = map.insert("google.com", "tag1");
    console.assert(ret == null, "MapCollection first insert should return null");
    ret = map.insert("google.com", "tag2");
    console.assert(ret == "tag1", "MapCollection update should return old value");
    console.assert(map.get("google.com") == "tag2", "MapCollection get failed");
}

function test_multi_map_coll() {
    let coll = new MultiMapCollection();
    const ret = coll.insert_many("google.com", ["tag1", "tag2"]);
    console.assert(ret, "MultiMapCollection insert_many failed");
    const set = coll.get_many("google.com");
    console.assert(set.contains("tag1"), "MultiMapCollection missing tag1");
    console.assert(set.contains("tag2"), "MultiMapCollection missing tag2");
}

function check_host(context, host) {
    // Demonstrate collection wrappers in JS external command runtime.
    test_set_coll();
    test_map_coll();
    test_multi_map_coll();

    // Demonstrate context.env() read/write from JS.
    if (context.env().get("test_var") == null) {
        context.env().set("test_var", "test_value");
    }

    for (const item of host_list) {
        if (shExpMatch(host, item.host)) {
            return true;
        }
    }
    return false;
}
"#;

const PROCESS_CHAIN_JS_EXTERNAL: &str = r#"
<root>
<process_chain id="route">
    <block id="entry">
        <![CDATA[
            call check_host $REQ.host && return --from lib "matched";
            return --from lib "unmatched";
        ]]>
    </block>
</process_chain>
</root>
"#;

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

async fn set_req_host(req: &MapCollectionRef, host: &str) -> Result<(), String> {
    req.insert("host", CollectionValue::String(host.to_string()))
        .await?;
    Ok(())
}

#[tokio::test]
async fn test_js_external_command_usage() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_js_external");
    hook_point
        .load_process_chain_lib("js_external_lib", 0, PROCESS_CHAIN_JS_EXTERNAL)
        .await?;

    let data_dir = new_test_data_dir("test-js-external")?;
    let hook_point_env = HookPointEnv::new("test-js-external", data_dir);
    hook_point_env
        .register_js_external_command("check_host", JS_CHECK_HOST_COMMAND.to_owned())
        .await?;

    let req = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    set_req_host(&req, "www.buckyos.com").await?;
    hook_point_env
        .hook_point_env()
        .create("REQ", CollectionValue::Map(req.clone()))
        .await?;

    let exec = hook_point_env.link_hook_point(&hook_point).await?;

    let ret = exec.execute_lib("js_external_lib").await?;
    assert_eq!(ret.value(), "matched");

    set_req_host(&req, "www.example.com").await?;
    let ret = exec.execute_lib("js_external_lib").await?;
    assert_eq!(ret.value(), "unmatched");

    Ok(())
}
