use crate::*;
use std::sync::Arc;

const PROCESS_CHAIN: &str = r#"
<root>
<process_chain id="chain1">
    <block id="block1">
        local key1="test.key1";
        export key2=$(append ${key1} _value2);
        map_create test;
        map_set test key1 value1;
        map_set test key2 $key2;
    </block>
    <block id="block2">
        map_get test key1;
        map_get test key2;
    </block>
</process_chain>

<process_chain id="chain2">
    <block id="block1">
        map_create test;
        map_set test key1 value1;
        map_set test key2 value2;
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

    let global_env = manager.get_global_env();
    let chain_env = manager.create_chain_env();
    // Create a context with global and chain environment
    let context = Context::new(global_env.clone(), chain_env.clone(), manager.clone());

    // Execute the first chain
    let chain1: &ProcessChain = chains.get(0).unwrap();
    chain1.execute(&context).await?;

    // Check the environment variables set by the first block
    assert_eq!(
        context.get_env_value("key1").await?,
        Some("test.key1".to_string())
    );
    assert_eq!(
        context.get_env_value("key2").await?,
        Some("key1_value2".to_string())
    );

    // Execute the second chain
    let chain2 = chains.get(1).unwrap();
    chain2.execute(&context).await?;

    // Check the environment variables set by the second block
    assert_eq!(
        context.get_env_value("test.key1").await?,
        Some("value1".to_string())
    );
    assert_eq!(
        context.get_env_value("test.key2").await?,
        Some("value2".to_string())
    );

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
        // 如果 TermLogger 不可用（如在某些环境），回退到 SimpleLogger
        SimpleLogger::init(LevelFilter::Info, Config::default()).unwrap()
    });

    match test_process_chain().await {
        Ok(_) => println!("Process chain executed successfully"),
        Err(e) => eprintln!("Error executing process chain: {}", e),
    }
}
