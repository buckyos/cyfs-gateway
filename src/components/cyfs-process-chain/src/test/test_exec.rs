use crate::*;
use simplelog::*;

const PROCESS_CHAIN_LIB1: &str = r#"
<process_chain_lib id="test_lib1" priority="100">
    <process_chain id="chain1">
        <block id="block1">
            <![CDATA[
                return $(exec block2);
            ]]>
        </block>
        <block id="block2">
            <![CDATA[
                return $(exec --chain chain2);
            ]]>
        </block>
    </process_chain>
    <process_chain id="chain2">
        <block id="block3">
            <![CDATA[
                exec --block 'chain2:block4';
                return $(exec block4);
            ]]>
        </block>
        <block id="block4">
            <![CDATA[
                exec --lib test_lib2;
                return $(exec --chain 'test_lib2:chain3');
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_LIB2: &str = r#"
<process_chain_lib id="test_lib2" priority="200">
    <process_chain id="chain3">
        <block id="block5">
            <![CDATA[
                return $(exec block6);
            ]]>
        </block>
        <block id="block6">
            <![CDATA[
                return $(exec --chain 'test_lib2:chain4');
            ]]>
        </block>
    </process_chain>
    <process_chain id="chain4">
        <block id="block7">
            <![CDATA[
                return $(exec block8);
            ]]>
        </block>
        <block id="block8">
            <![CDATA[
                return --from block "test_lib2:chain4:block8";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_RETURN: &str = r#"
<process_chain_lib id="test_return" priority="300">
    <process_chain id="chain5">
        <block id="block9">
            <![CDATA[
                return --from block "chain5:block9";
            ]]>
        </block>
        <block id="block10">
            <![CDATA[
                return --from chain "test_lib3:chain5:block10";
            ]]>
        </block>
        <block id="block11">
            <![CDATA[
                return --from lib "test_return:chain5:block11";
            ]]>
        </block>
    </process_chain>
    <process_chain id="chain6">
        <block id="block12">
            <![CDATA[
                return "test_lib3:chain6:block12";
            ]]>
        </block>
        <block id="block13">
            <![CDATA[
                return --from lib "test_lib3:chain6:block13";
            ]]>
        </block>
        <block id="block14">
            <![CDATA[
                return --from chain "test_lib3:chain6:block14";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

async fn test_exec() -> Result<(), String> {
    // Create a hook point
    let hook_point = HookPoint::new("test_exec");
    hook_point
        .load_process_chain_lib("test_lib1", 0, PROCESS_CHAIN_LIB1)
        .await
        .unwrap();

    hook_point
        .load_process_chain_lib("test_lib2", 10, PROCESS_CHAIN_LIB2)
        .await
        .unwrap();

    hook_point
        .load_process_chain_lib("test_return", 20, PROCESS_CHAIN_RETURN)
        .await
        .unwrap();

    let data_dir = std::env::temp_dir().join("cyfs-process-chain-test");
    std::fs::create_dir_all(&data_dir).unwrap();

    // Create env to execute the hook point
    let hook_point_env = HookPointEnv::new("test-exec", data_dir);

    // Test exec cases
    {
        let exec = hook_point_env.link_hook_point(&hook_point).await.unwrap();
        let ret = exec.execute_lib("test_lib1").await.unwrap();
        info!("Hook point execution result: {:?}", ret);
        let value = ret.value();
        assert!(value == "test_lib2:chain4:block8", "Expected value from execution is 'test_lib2:chain4:block8', got: {:?}", value);

        // Get all output into string from the pipe
        let output = hook_point_env.pipe().stdout.clone_string();
        info!("Hook point output: {}", output);
    }

    // Test return cases
    {
        let exec = hook_point_env.link_hook_point(&hook_point).await.unwrap();
        let ret = exec.execute_lib("test_return").await.unwrap();
        info!("Hook point execution result: {:?}", ret);
        let value = ret.value();
        assert!(value == "test_lib3:chain6:block13", "Expected value from execution is 'test_lib3:chain6:block13', got: {:?}", value);

        // Get all output into string from the pipe
        let output = hook_point_env.pipe().stdout.clone_string();
        info!("Hook point output: {}", output);
    }

    Ok(())
}

#[tokio::test]
async fn test_exec_main() {
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

    test_exec().await.unwrap_or_else(|e| {
        eprintln!("Error executing hook point: {}", e);
    });

    EXTERNAL_COMMAND_FACTORY.finalize();
}
