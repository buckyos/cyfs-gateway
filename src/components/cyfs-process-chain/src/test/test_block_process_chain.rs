use crate::*;
use simplelog::*;
use std::sync::Arc;
use std::sync::Once;

const PROCESS_CHAIN_CHAIN1_ONLY: &str = r#"
<root>
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

async fn test_process_chain() -> Result<(), String> {
    let parser_context = Arc::new(ParserContext::new());

    let chains = ProcessChainXMLLoader::parse(PROCESS_CHAIN_CHAIN1_ONLY)?;
    assert_eq!(chains.len(), 1);

    let lib =
        ProcessChainConstListLib::new_raw("test_lib_chain1", 0, chains).into_process_chain_lib();

    let manager = Arc::new(ProcessChainManager::new());
    manager.add_lib(lib)?;

    let manager = manager.link(&parser_context).await?;
    let linked_lib = manager
        .get_lib("test_lib_chain1")
        .ok_or_else(|| "linked lib 'test_lib_chain1' not found".to_string())?;

    let pipe = SharedMemoryPipe::new_empty();
    let exec = ProcessChainLibExecutor::new(linked_lib, manager, None, pipe.pipe().clone());

    let exec2 = exec.fork();
    let global_env = exec2.global_env().clone();
    let ret = exec2.execute_lib().await?;
    assert!(
        ret.is_accept(),
        "chain1 execution should accept, got: {:?}",
        ret
    );

    let key1 = global_env
        .get("key1")
        .await?
        .ok_or_else(|| "key1 missing in global env".to_string())?;
    assert_eq!(key1.as_str(), Some("key12"));

    let key2 = global_env
        .get("key2")
        .await?
        .ok_or_else(|| "key2 missing in global env".to_string())?;
    assert_eq!(key2.as_str(), Some("key1_value2"));

    let key3 = global_env
        .get("key3")
        .await?
        .ok_or_else(|| "key3 missing in global env".to_string())?;
    assert_eq!(key3.as_str(), Some("key12_value2"));

    Ok(())
}

#[tokio::test]
async fn test_process_chain_block_env() -> Result<(), String> {
    init_test_logger();
    test_process_chain().await
}
