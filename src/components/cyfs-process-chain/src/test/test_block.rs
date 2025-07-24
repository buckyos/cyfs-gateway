use crate::*;
use std::sync::Arc;
use std::sync::RwLock;

const PROCESS_CHAIN: &str = r#"
<root>
<process_chain id="chain2">
    <block id="block1">
        <![CDATA[
            # We reject the request if the protocol is not https
            !(match $PROTOCOL https) && reject;

            map-create --multi --chain test1;
            map-add test1 key1 value1;
            map-add test1 key2 value2;
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
    // Parse the process chain
    let chains = ProcessChainXMLLoader::parse(PROCESS_CHAIN)?;
    assert_eq!(chains.len(), 2);

    let global_env = Arc::new(Env::new(EnvLevel::Global, None));

    let manager = ProcessChainManager::new();
    let manager = Arc::new(manager);

    // Append all chains to the manager
    for mut chain in chains {
        chain.translate().await.unwrap();
        manager.add_chain(chain).unwrap();
    }

    // Load host db and ip db from file
    let data_dir = std::env::temp_dir().join("cyfs-process-chain-test");
    std::fs::create_dir_all(&data_dir).unwrap();

    // Load host db, if not exists, it create a new one
    let host_db_file = data_dir.join("host.json");
    let host_db = JsonMultiMapCollection::new(host_db_file.clone()).unwrap();

    let host_collections = Arc::new(Box::new(host_db.clone()) as Box<dyn MultiMapCollection>);
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
    let exec = ProcessChainsExecutor::new(
        manager.clone(),
        global_env.clone(),
        pipe.pipe().clone(),
    );

    // Execute the first chain
    let ret: CommandResult = exec.execute_chain_by_id("chain1").await.unwrap();
    info!("Execution result: {:?}", ret);
    assert!(ret.is_accept());

    // Check the environment variables set by the first block
    assert_eq!(global_env.get("key1").await.unwrap().unwrap().as_str(), Some("key12"));
    assert_eq!(global_env.get("key2").await.unwrap().unwrap().as_str(), Some("key1_value2"));
    assert_eq!(global_env.get("key3").await.unwrap().unwrap().as_str(), Some("key12_value2"));

    // Execute the second chain
    exec.execute_chain_by_id("chain2").await.unwrap();

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

        env.create("REQ_from_ip", CollectionValue::Visitor(visitor.clone())).await?;
        env.create("REQ_url", CollectionValue::Visitor(visitor.clone())).await?;

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

    async fn set(&self, id: &str, value: CollectionValue) -> Result<Option<CollectionValue>, String> {
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
        .load_process_chain_list(PROCESS_CHAIN)
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
    test_visitor.register(hook_point_env.global_env()).await.unwrap();

    let exec = hook_point_env.prepare_exec_list(&hook_point);
    let ret = exec.execute_all().await.unwrap();
    assert!(ret.is_accept());

    // Try save the collections to disk if they are persistent and there is changes
    hook_point_env.flush_collections().await.unwrap();

    // Get all output into string from the pipe
    let output = hook_point_env.pipe().stdout.clone_string();
    info!("Hook point output: {}", output);

    let global_env = hook_point_env.global_env();
    assert_eq!(global_env.get("key2").await.unwrap().unwrap().as_str(), Some("value1_value2"));

    Ok(())
}

#[tokio::test]
async fn test_process_chain_main() {
    use simplelog::*;
    TermLogger::init(
        LevelFilter::Info,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap_or_else(|_| {
        // If TermLogger is not available (e.g., in some environments), fall back to SimpleLogger
        SimpleLogger::init(LevelFilter::Info, Config::default()).unwrap()
    });

    match test_process_chain().await {
        Ok(_) => println!("Process chain executed successfully"),
        Err(e) => eprintln!("Error executing process chain: {}", e),
    }

    test_hook_point().await.unwrap_or_else(|e| {
        eprintln!("Error executing hook point: {}", e);
    });
}
