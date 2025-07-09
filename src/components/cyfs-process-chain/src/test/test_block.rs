use crate::*;
use std::sync::Arc;

const PROCESS_CHAIN: &str = r#"
<root>
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
    </block>
    <block id="block2">
        <![CDATA[
            match-include key3 test && accept;
            match-include key1 test && exit drop;
            match-include key2 test;
        ]]>
    </block>
</process_chain>

<process_chain id="chain2">
    <block id="block1">
        map-create test;
        map-add test key1 value1;
        map-add test key2 value2;
    </block>
</process_chain>
</root>
"#;

async fn test_process_chain() -> Result<(), String> {
    // Parse the process chain
    let chains = ProcessChainParser::parse(PROCESS_CHAIN)?;
    assert_eq!(chains.len(), 2);

    let manager = ProcessChainManager::new();
    let manager = Arc::new(manager);

    // Append all chains to the manager
    for mut chain in chains {
        chain.translate().await.unwrap();
        manager.add_chain(chain).unwrap();
    }

    let collection_manager = CollectionManager::new();
    let variable_visitor_manager = VariableVisitorManager::new();

    // Create a context with global and chain environment
    let exec = ProcessChainsExecutor::new(
        manager.clone(),
        collection_manager.clone(),
        variable_visitor_manager.clone(),
    );

    // Execute the first chain
    exec.execute_chain_by_id("chain1").await.unwrap();

    let global_env = manager.get_global_env();

    // Check the environment variables set by the first block
    assert_eq!(global_env.get("key1"), Some("key12".to_string()));
    assert_eq!(global_env.get("key2"), Some("key1_value2".to_string()));
    assert_eq!(global_env.get("key3"), Some("key12_value2".to_string()));

    // Execute the second chain
    exec.execute_chain_by_id("chain2").await.unwrap();

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
}
