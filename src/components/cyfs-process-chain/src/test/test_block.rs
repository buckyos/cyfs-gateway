use crate::*;
use std::sync::Arc;

const PROCESS_CHAIN: &str = r#"
<root>
<process_chain id="chain2">
    <block id="block1">
        <![CDATA[
            map-create test1;
            map-add test1 key1 value1;
            map-add test1 key2 value2;
            map-add host "google.com" tag1 tag2;
            map-add host "baidu.com" tag1;
            match-include host "google.com" tag3 && reject;
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

        map-create -multi test_multi;
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

    let collection_manager = CollectionManager::new();

    // Load host db and ip db from file
    let data_dir = std::env::temp_dir().join("cyfs-process-chain-test");
    std::fs::create_dir_all(&data_dir).unwrap();

    // Load host db, if not exists, it create a new one
    let host_db_file = data_dir.join("host.json");
    let host_db = JsonMultiMapCollection::new(host_db_file.clone()).unwrap();

    collection_manager
        .add_multi_map_collection("host", Arc::new(Box::new(host_db.clone())))
        .await
        .unwrap();

    // Load ip db, if not exists, it create a new one
    let ip_db_file = data_dir.join("ip.json");
    let ip_db = JsonMultiMapCollection::new(ip_db_file.clone()).unwrap();
    collection_manager
        .add_multi_map_collection("ip", Arc::new(Box::new(ip_db.clone())))
        .await
        .unwrap();

    let variable_visitor_manager = VariableVisitorManager::new();
    let pipe = SharedMemoryPipe::new_empty();

    // Create a context with global and chain environment
    let exec = ProcessChainsExecutor::new(
        manager.clone(),
        global_env.clone(),
        collection_manager.clone(),
        variable_visitor_manager.clone(),
        pipe.pipe().clone(),
    );

    // Execute the first chain
    let ret: CommandResult = exec.execute_chain_by_id("chain1").await.unwrap();
    info!("Execution result: {:?}", ret);
    assert!(ret.is_accept());

    // Check the environment variables set by the first block
    assert_eq!(global_env.get("key1"), Some("key12".to_string()));
    assert_eq!(global_env.get("key2"), Some("key1_value2".to_string()));
    assert_eq!(global_env.get("key3"), Some("key12_value2".to_string()));

    // Execute the second chain
    exec.execute_chain_by_id("chain2").await.unwrap();

    Ok(())
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

    let ret = hook_point_env.exec_list(&hook_point).await.unwrap();
    assert!(ret.is_accept());

    // Rry save the collections to disk if they are persistent and there is changes
    hook_point_env.flush_collections().await.unwrap();

    let global_env = hook_point_env.global_env();
    assert_eq!(global_env.get("key1"), Some("key12".to_string()));

    Ok(())
}

#[tokio::test]
async fn test_process_chain_main() {
    use simplelog::*;
    TermLogger::init(
        LevelFilter::Debug,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap_or_else(|_| {
        // 如果 TermLogger 不可用（如在某些环境），回退到 SimpleLogger
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
