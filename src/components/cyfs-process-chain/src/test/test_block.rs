use super::external::*;
use crate::*;
use simplelog::*;
use std::sync::Arc;
use std::sync::RwLock;

const JS_COMMAND: &str = r#"
const host_list = [
    { host: "*.google.com" },
    { host: "*.buckyos.com", },
];

function test_set_coll() {
    let set = new SetCollection();
    let ret = set.insert("google.com");
    console.assert(ret, "Insert google.com failed");
    set.insert("buckyos.com");
    
    let exists = set.contains("google.com");
    console.assert(exists, "Set should contain google.com");
    exists = set.contains("buckyos.com");
    console.assert(exists, "Set should contain buckyos.com");

    console.log(`Set contains google.com: ${set.contains("google.com")}`);
    console.log(`Set contains buckyos.com: ${set.contains("buckyos.com")}`);

    set.remove("google.com");
    console.assert(!set.contains("google.com"), "Set should not contain google.com after removal");
    console.log(`Set contains google.com after removal: ${set.contains("google.com")}`);
}

function test_map_coll() {
    let map = new MapCollection();
    let ret = map.insert("google.com", "tag1");
    console.assert(ret == null, "MapCollection insert google.com tag1 failed");

    ret = map.insert("google.com", "tag2");
    console.assert(ret == "tag1", "MapCollection insert google.com tag2 failed");

    ret = map.insert("baidu.com", "tag1");
    console.assert(ret == null, "MapCollection insert baidu.com tag1 failed");

    ret = map.contains_key("google.com");
    console.assert(ret, "MapCollection should contain google.com");
    ret = map.contains_key("baidu.com");
    console.assert(ret, "MapCollection should contain baidu.com");

    let value = map.get("google.com");
    console.assert(value == "tag2", "MapCollection get google.com failed, expected tag2, got " + value);

    value = map.get("baidu.com");
    console.assert(value == "tag1", "MapCollection get baidu.com failed, expected tag1, got " + value);

    value = map.get("not-exist.com");
    console.assert(value == null, "MapCollection get not-exist.com should return null");

    value = map.remove("google.com");
    console.assert(value == "tag2", "MapCollection remove google.com failed, expected tag2, got " + value);

    console.log(`MapCollection contains google.com: ${map.contains_key("google.com")}`);
    console.log(`MapCollection contains baidu.com: ${map.contains_key("baidu.com")}`);
}

function test_multi_map_coll() {
    let coll = new MultiMapCollection();
    let ret = coll.insert_many("google.com", ["tag1", "tag2"]);
    console.assert(ret, "MultiMapCollection insert_many google.com tag1 tag2 failed");
    ret = coll.insert("baidu.com", "tag1");
    console.assert(ret, "MultiMapCollection insert baidu.com tag1 failed");

    let set = coll.get_many("google.com");
    console.log(`MultiMapCollection google.com tags`);
    console.assert(set.contains("tag1"), "MultiMapCollection should contain google.com with tag1");
    console.assert(set.contains("tag2"), "MultiMapCollection should contain google.com with tag2");

    let tag = coll.get("google.com");
    console.assert(set.contains(tag), "MultiMapCollection should contain google.com with ${tag}");
    console.log(`MultiMapCollection contains google.com: ${coll.contains_key("google.com")}`);
    console.log(`MultiMapCollection contains baidu.com: ${coll.contains_key("baidu.com")}`);
}

function test_coll() {
    test_set_coll();
    test_map_coll();
    test_multi_map_coll();
}

function check_host(context, host) {
    console.log(`Checking host: ${host}`);
    test_coll();
    if (context.env().get("test_var") == null) {
        console.log("test_var not found in context.env, setting it now");
        context.env().set("test_var", "test_value");
    }

    for (const item of host_list) {
        console.log(`Checking host: ${host} against pattern: ${item.host}`);
        if (shExpMatch(host, item.host)) {
            console.log(`Host ${host} matches ${item.host}`);
            return true;
        }
    }

    console.log(`Host ${host} does not match any patterns`);
    return false;
}
"#;

const PROCESS_CHAIN: &str = r#"
<root>
<process_chain id="chain2">
    <block id="block1">
        <![CDATA[
            # We reject the request if the protocol is not https
            !(match $PROTOCOL https) && reject;

            call check_host "www.buckyos1.com" && reject;
            echo "\$get request url: ${REQ_url} \n ${PROTOCOL}";
            echo $(call add 1 2);
            local key1 = "value1";
            delete key1;
            echo $(eq $key1 "");

            set-create --block test_set1;
            set-add test_set1 "google.com" "buckyos.com";
            set-add test_set1 "buckyos.com";
            set-remove test_set1 "google.com";
            set-remove test_set1 "google.com" "x.com";
            map $test_set1 $(echo "=====>" ${__key});

            map-create --chain test1;
            # should not reject
            match-include test1 key1 && exit reject;
            match-include $test1 key1 && exit reject;

            map-add test1 key1 value1;
            map-add test1 key2 value2;

            map $test1 $(echo "=====>" ${__key} ${__value});

            !match-include test1 key1 && exit reject;
            !match-include test1 key1 value1 && exit reject;
            match-include test1 key1 value2 && exit reject;

            echo --verbose test1 $test1;
            delete test1.key1;
            echo --verbose test1 $test1;

            map-create --multi test1.test2;
            map-add test1.test2 key1 value1;
            map-add test1.test2 key2 value2;
            map-add test1.test2 key2 value22;
            echo --verbose $test1.test2 "key1:" ${test1.test2.key1};
            !match-include test1.test2 key1 value1 && exit reject;
            match-include $test1.test1 key2 value2 value3 && exit reject;
            !match-include $test1.test2 key2 value2 value22 && exit reject;

            map-add host "google.com" tag1 tag2;
            map-add host "baidu.com" tag1;
            match-include host "google.com" tag3 && reject;

            local key1 = value1;
            export key2 = $(append $key1 _value2);

            # We accept the request if the from buckyos.com
            echo ${REQ_url};
            match $REQ_url "*.buckyos.com" && accept;
        ]]>
    </block>
</process_chain>
<process_chain id="chain1">
    <block id="block1">
        local key1="key1";
        export key1=$(append $key1 '2');
        # key1 should be "key12"
        local key1
        export key2=$(append ${key1} _value2);
        # key2 should be "key1_value2"
        export key1;
        export key3=$(append ${key1} _value2);
        # key3 should be "key12_value2"

        map-create test;
        map-add test key1 value1;
        map-add test key2 $key2;

        map-create --multi test_multi;
        map-add test_multi key1 value1 value2 value3;
        map-add test_multi key2 value2;
        map-remove test_multi key1 value1;
    </block>
    <block id="block2">
        <![CDATA[
            match-include test_multi key1 value2 value3 && accept;
            match-include test key3 && accept;
            match-include test key1 && exit drop;
            match-include test key2;
        ]]>
    </block>
</process_chain>
</root>
"#;

async fn test_process_chain() -> Result<(), String> {
    let parser_context = Arc::new(ParserContext::new());

    // Parse the process chain to lib
    let chains = ProcessChainXMLLoader::parse(PROCESS_CHAIN)?;
    assert_eq!(chains.len(), 2);

    let lib = ProcessChainConstListLib::new_raw("test_lib", 0, chains).into_process_chain_lib();

    // Create process chain manager
    let manager = ProcessChainManager::new();
    let manager = Arc::new(manager);

    manager.add_lib(lib.clone()).unwrap();

    // Link the process chain manager with the parser context
    let manager = manager.link(&parser_context).await?;

    // Load host db and ip db from file
    let data_dir = std::env::temp_dir().join("cyfs-process-chain-test");
    std::fs::create_dir_all(&data_dir).unwrap();

    // Load host db, if not exists, it create a new one
    let host_db_file = data_dir.join("host.json");
    let host_db = JsonMultiMapCollection::new(host_db_file.clone()).unwrap();

    let host_collections = Arc::new(Box::new(host_db.clone()) as Box<dyn MultiMapCollection>);
    let global_env = Arc::new(Env::new(EnvLevel::Global, None));
    global_env
        .create("host", CollectionValue::MultiMap(host_collections))
        .await
        .unwrap();

    // Load ip db, if not exists, it create a new one
    let ip_db_file = data_dir.join("ip.json");
    let ip_db = JsonMultiMapCollection::new(ip_db_file.clone()).unwrap();
    let ip_collections = Arc::new(Box::new(ip_db.clone()) as Box<dyn MultiMapCollection>);
    global_env
        .create("ip", CollectionValue::MultiMap(ip_collections))
        .await
        .unwrap();

    let pipe = SharedMemoryPipe::new_empty();

    // Create a context with global and chain environment
    let exec = ProcessChainLibExecutor::new(
        lib,
        manager.clone(),
        global_env.clone(),
        pipe.pipe().clone(),
    );

    // Execute the lib
    let ret: CommandResult = exec.fork().execute_lib().await.unwrap();
    info!("Execution result: {:?}", ret);
    assert!(ret.is_accept());

    // Check the environment variables set by the first block
    assert_eq!(
        global_env.get("key1").await.unwrap().unwrap().as_str(),
        Some("key12")
    );
    assert_eq!(
        global_env.get("key2").await.unwrap().unwrap().as_str(),
        Some("key1_value2")
    );
    assert_eq!(
        global_env.get("key3").await.unwrap().unwrap().as_str(),
        Some("key12_value2")
    );

    // Execute the second chain
    exec.execute_chain("chain2").await.unwrap();

    Ok(())
}

#[derive(Clone)]
struct TestVisitor {
    url: Arc<RwLock<String>>,
}

impl TestVisitor {
    pub fn new() -> Self {
        Self {
            url: Arc::new(RwLock::new("http://www.buckyos.com".to_string())),
        }
    }

    pub async fn register(&self, env: &Env) -> Result<(), String> {
        let visitor = Arc::new(Box::new(self.clone()) as Box<dyn VariableVisitor>);
        env.create("PROTOCOL", CollectionValue::Visitor(visitor.clone()))
            .await?;

        env.create("REQ_from_ip", CollectionValue::Visitor(visitor.clone()))
            .await?;
        env.create("REQ_url", CollectionValue::Visitor(visitor.clone()))
            .await?;

        info!("TestVisitor registered successfully");
        Ok(())
    }
}

#[async_trait::async_trait]
impl VariableVisitor for TestVisitor {
    async fn get(&self, id: &str) -> Result<CollectionValue, String> {
        match id {
            "PROTOCOL" => Ok(CollectionValue::String("https".to_string())),
            "REQ_from_ip" => Ok(CollectionValue::String("127.0.0.1".to_string())),
            "REQ_url" => Ok(CollectionValue::String(self.url.read().unwrap().clone())),
            _ => Err(format!("Variable '{}' not found", id)),
        }
    }

    async fn set(
        &self,
        id: &str,
        value: CollectionValue,
    ) -> Result<Option<CollectionValue>, String> {
        match id {
            "$PROTOCOL" | "REQ_from_ip" => {
                let msg = format!("Cannot set read-only variable '{}'", id);
                warn!("{}", msg);
                return Err(msg);
            }
            "REQ_url" => {
                let mut url = self.url.write().unwrap();
                let old_value = url.clone();
                *url = value.try_as_str()?.to_string();

                info!("Set variable '{}' to '{}'", id, value);
                return Ok(Some(CollectionValue::String(old_value)));
            }
            _ => Err(format!("Variable '{}' is read-only", id)),
        }
    }
}

async fn test_hook_point() -> Result<(), String> {
    // Create a hook point
    let hook_point = HookPoint::new("test_hook_point");
    hook_point
        .load_process_chain_lib("main", 0, PROCESS_CHAIN)
        .await
        .unwrap();

    let data_dir = std::env::temp_dir().join("cyfs-process-chain-test");
    std::fs::create_dir_all(&data_dir).unwrap();

    // Create env to execute the hook point
    let hook_point_env = HookPointEnv::new("test-hook-point", data_dir);

    // Load some collections for file
    hook_point_env
        .load_collection(
            "host",
            CollectionType::MultiMap,
            CollectionFileFormat::Json,
            true,
        )
        .await
        .unwrap();

    hook_point_env
        .load_collection(
            "ip",
            CollectionType::MultiMap,
            CollectionFileFormat::Json,
            true,
        )
        .await
        .unwrap();

    // Init some visitors
    let test_visitor = TestVisitor::new();
    test_visitor
        .register(hook_point_env.global_env())
        .await
        .unwrap();

    let exec = hook_point_env.link_hook_point(&hook_point).await.unwrap();
    let ret = exec.execute_lib("main").await.unwrap();
    info!("Hook point execution result: {:?}", ret);
    assert!(ret.is_accept(), "Hook point execution failed: {:?}", ret);

    // Try save the collections to disk if they are persistent and there is changes
    hook_point_env.flush_collections().await.unwrap();

    // Get all output into string from the pipe
    let output = hook_point_env.pipe().stdout.clone_string();
    info!("Hook point output: {}", output);

    let global_env = hook_point_env.global_env();
    assert_eq!(
        global_env.get("key2").await.unwrap().unwrap().as_str(),
        Some("value1_value2")
    );

    Ok(())
}

#[tokio::test]
async fn test_process_chain_main() {
    TermLogger::init(
        LevelFilter::Debug,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap_or_else(|_| {
        // If TermLogger is not available (e.g., in some environments), fall back to SimpleLogger
        let _ = SimpleLogger::init(LevelFilter::Info, Config::default());
    });

    //std::panic::set_hook(Box::new(|info| {
    //    eprintln!("Panic occurred: {:?}", info);
    //}));

    EXTERNAL_COMMAND_FACTORY
        .register_js_external_command("check_host", JS_COMMAND.to_owned())
        .await
        .unwrap();

    EXTERNAL_COMMAND_FACTORY
        .register("add", Arc::new(Box::new(AddCommand::new())))
        .unwrap();

    match test_process_chain().await {
        Ok(_) => println!("Process chain executed successfully"),
        Err(e) => eprintln!("Error executing process chain: {}", e),
    }

    test_hook_point().await.unwrap_or_else(|e| {
        eprintln!("Error executing hook point: {}", e);
    });

    EXTERNAL_COMMAND_FACTORY.finalize();
}
