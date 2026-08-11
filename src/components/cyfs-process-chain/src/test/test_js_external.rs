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

const JS_CLASSIFY_HOST_COMMAND: &str = r#"
function classify_host(context, host) {
    const created = context.env().create("js_tmp", "seed", "block");
    console.assert(created === true, "Expected js_tmp to be newly created");
    console.assert(context.env().get("js_tmp", "block") === "seed", "Expected js_tmp get to return seed");

    const prev = context.env().set("js_tmp", "updated", "block");
    console.assert(prev === "seed", "Expected js_tmp set to return previous value");
    console.assert(context.env().get("js_tmp", "block") === "updated", "Expected js_tmp get to return updated");

    const removed = context.env().remove("js_tmp", "block");
    console.assert(removed === "updated", "Expected js_tmp remove to return updated");
    console.assert(context.env().get("js_tmp", "block") == null, "Expected js_tmp to be removed");

    const set = new SetCollection();
    console.assert(set.insert("alpha"), "Expected set insert alpha to succeed");
    console.assert(set.contains("alpha"), "Expected set to contain alpha");
    console.assert(set.remove("alpha"), "Expected set remove alpha to succeed");

    const map = new MapCollection();
    console.assert(map.insert("host", host) == null, "Expected first map insert to return null");
    console.assert(map.contains_key("host"), "Expected map contains_key host");
    console.assert(map.remove("host") === host, "Expected map remove to return host");

    const multi = new MultiMapCollection();
    console.assert(multi.insert("host", host), "Expected multimap insert to succeed");
    console.assert(multi.contains_key("host"), "Expected multimap contains_key host");
    console.assert(multi.contains_value("host", [host]), "Expected multimap contains_value host");
    console.assert(multi.remove("host", host), "Expected multimap remove to succeed");

    if (shExpMatch(host, "*.buckyos.com")) {
        return { state: true, result: "allow" };
    }

    return { state: false, result: "deny" };
}
"#;

const PROCESS_CHAIN_JS_EXTERNAL_RESULT: &str = r#"
<root>
<process_chain id="route">
    <block id="entry">
        <![CDATA[
            match-result $(call classify_host $REQ.host)
            ok(value)
                return --from lib $(append "ok:" $value);
            err(err_value)
                return --from lib $(append "err:" $err_value);
            end
        ]]>
    </block>
</process_chain>
</root>
"#;

const JS_DESCRIBE_HOST_MAP_COMMAND: &str = r#"
function describe_host(context, host) {
    const payload = new MapCollection();
    console.assert(payload.insert("host", host) == null, "Expected host insert to return null");
    console.assert(
        payload.insert("suffix", shExpMatch(host, "*.buckyos.com") ? "buckyos" : "other") == null,
        "Expected suffix insert to return null"
    );

    return { state: true, result: payload };
}
"#;

const PROCESS_CHAIN_JS_EXTERNAL_MAP_RESULT: &str = r#"
<root>
<process_chain id="route">
    <block id="entry">
        <![CDATA[
            capture --value payload $(call describe_host $REQ.host);
            return --from lib $(append $payload.host "|" $payload.suffix);
        ]]>
    </block>
</process_chain>
</root>
"#;

const JS_CLASSIFY_HOST_TAGS_COMMAND: &str = r#"
function classify_host_tags(context, host) {
    const tags = new SetCollection();
    console.assert(tags.insert("seen"), "Expected seen tag insert to succeed");

    if (shExpMatch(host, "*.buckyos.com")) {
        console.assert(tags.insert("allow"), "Expected allow tag insert to succeed");
        return { state: true, result: tags };
    }

    console.assert(tags.insert("deny"), "Expected deny tag insert to succeed");
    return { state: false, result: tags };
}
"#;

const PROCESS_CHAIN_JS_EXTERNAL_SET_RESULT: &str = r#"
<root>
<process_chain id="route">
    <block id="entry">
        <![CDATA[
            match-result $(call classify_host_tags $REQ.host)
            ok(tags)
                match-include $tags "allow" && return --from lib "ok:set";
                return --from lib "ok:missing";
            err(tags)
                match-include $tags "deny" && return --from lib "err:set";
                return --from lib "err:missing";
            end
        ]]>
    </block>
</process_chain>
</root>
"#;

const JS_THROW_HOST_COMMAND: &str = r#"
function explode_host(context, host) {
    throw new Error("explode:" + host);
}
"#;

const PROCESS_CHAIN_JS_EXTERNAL_THROW: &str = r#"
<root>
<process_chain id="route">
    <block id="entry">
        <![CDATA[
            call explode_host $REQ.host;
            return --from lib "unreachable";
        ]]>
    </block>
</process_chain>
</root>
"#;

const JS_ASSERT_ONLY_COMMAND: &str = r#"
function assert_only(context, host) {
    console.assert(false, "assert:" + host);
    return { state: true, result: "after-assert" };
}
"#;

const PROCESS_CHAIN_JS_EXTERNAL_ASSERT: &str = r#"
<root>
<process_chain id="route">
    <block id="entry">
        <![CDATA[
            match-result $(call assert_only $REQ.host)
            ok(value)
                return --from lib $(append "ok:" $value);
            err(err_value)
                return --from lib $(append "err:" $err_value);
            end
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

#[tokio::test]
async fn test_js_external_command_structured_result_usage() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_js_external_result");
    hook_point
        .load_process_chain_lib(
            "js_external_result_lib",
            0,
            PROCESS_CHAIN_JS_EXTERNAL_RESULT,
        )
        .await?;

    let data_dir = new_test_data_dir("test-js-external-result")?;
    let hook_point_env = HookPointEnv::new("test-js-external-result", data_dir);
    hook_point_env
        .register_js_external_command("classify_host", JS_CLASSIFY_HOST_COMMAND.to_owned())
        .await?;

    let req = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    set_req_host(&req, "gateway.buckyos.com").await?;
    hook_point_env
        .hook_point_env()
        .create("REQ", CollectionValue::Map(req.clone()))
        .await?;

    let exec = hook_point_env.link_hook_point(&hook_point).await?;

    let ret = exec.execute_lib("js_external_result_lib").await?;
    assert_eq!(ret.value(), "ok:allow");

    set_req_host(&req, "gateway.example.net").await?;
    let ret = exec.execute_lib("js_external_result_lib").await?;
    assert_eq!(ret.value(), "err:deny");

    Ok(())
}

#[tokio::test]
async fn test_js_external_command_typed_map_result_usage() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_js_external_map_result");
    hook_point
        .load_process_chain_lib(
            "js_external_map_result_lib",
            0,
            PROCESS_CHAIN_JS_EXTERNAL_MAP_RESULT,
        )
        .await?;

    let data_dir = new_test_data_dir("test-js-external-map-result")?;
    let hook_point_env = HookPointEnv::new("test-js-external-map-result", data_dir);
    hook_point_env
        .register_js_external_command("describe_host", JS_DESCRIBE_HOST_MAP_COMMAND.to_owned())
        .await?;

    let req = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    set_req_host(&req, "gateway.buckyos.com").await?;
    hook_point_env
        .hook_point_env()
        .create("REQ", CollectionValue::Map(req.clone()))
        .await?;

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("js_external_map_result_lib").await?;
    assert_eq!(ret.value(), "gateway.buckyos.com|buckyos");

    set_req_host(&req, "gateway.example.net").await?;
    let ret = exec.execute_lib("js_external_map_result_lib").await?;
    assert_eq!(ret.value(), "gateway.example.net|other");

    Ok(())
}

#[tokio::test]
async fn test_js_external_command_typed_set_result_usage() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_js_external_set_result");
    hook_point
        .load_process_chain_lib(
            "js_external_set_result_lib",
            0,
            PROCESS_CHAIN_JS_EXTERNAL_SET_RESULT,
        )
        .await?;

    let data_dir = new_test_data_dir("test-js-external-set-result")?;
    let hook_point_env = HookPointEnv::new("test-js-external-set-result", data_dir);
    hook_point_env
        .register_js_external_command(
            "classify_host_tags",
            JS_CLASSIFY_HOST_TAGS_COMMAND.to_owned(),
        )
        .await?;

    let req = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    set_req_host(&req, "gateway.buckyos.com").await?;
    hook_point_env
        .hook_point_env()
        .create("REQ", CollectionValue::Map(req.clone()))
        .await?;

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("js_external_set_result_lib").await?;
    assert_eq!(ret.value(), "ok:set");

    set_req_host(&req, "gateway.example.net").await?;
    let ret = exec.execute_lib("js_external_set_result_lib").await?;
    assert_eq!(ret.value(), "err:set");

    Ok(())
}

#[tokio::test]
async fn test_js_external_command_throw_propagates_runtime_error() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_js_external_throw");
    hook_point
        .load_process_chain_lib("js_external_throw_lib", 0, PROCESS_CHAIN_JS_EXTERNAL_THROW)
        .await?;

    let data_dir = new_test_data_dir("test-js-external-throw")?;
    let hook_point_env = HookPointEnv::new("test-js-external-throw", data_dir);
    hook_point_env
        .register_js_external_command("explode_host", JS_THROW_HOST_COMMAND.to_owned())
        .await?;

    let req = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    set_req_host(&req, "gateway.example.net").await?;
    hook_point_env
        .hook_point_env()
        .create("REQ", CollectionValue::Map(req.clone()))
        .await?;

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let err = exec.execute_lib("js_external_throw_lib").await.unwrap_err();
    assert!(
        err.contains("Failed to execute external command")
            && err.contains("explode_host")
            && err.contains("Failed to call function explode_host"),
        "unexpected error: {err}"
    );

    Ok(())
}

#[tokio::test]
async fn test_js_external_console_assert_is_non_fatal() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_js_external_console_assert");
    hook_point
        .load_process_chain_lib(
            "js_external_console_assert_lib",
            0,
            PROCESS_CHAIN_JS_EXTERNAL_ASSERT,
        )
        .await?;

    let data_dir = new_test_data_dir("test-js-external-console-assert")?;
    let hook_point_env = HookPointEnv::new("test-js-external-console-assert", data_dir);
    hook_point_env
        .register_js_external_command("assert_only", JS_ASSERT_ONLY_COMMAND.to_owned())
        .await?;

    let req = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    set_req_host(&req, "gateway.buckyos.com").await?;
    hook_point_env
        .hook_point_env()
        .create("REQ", CollectionValue::Map(req.clone()))
        .await?;

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("js_external_console_assert_lib").await?;
    assert_eq!(ret.value(), "ok:after-assert");

    Ok(())
}
