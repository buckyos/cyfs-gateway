use super::external::AddCommand;
use crate::*;
use simplelog::*;
use std::sync::Arc;

const PROCESS_CHAIN_LIB1: &str = r#"
<process_chain_lib id="test_env" priority="100">
    <process_chain id="chain1">
        <block id="block1">
            <![CDATA[
                echo $static_var_1;
            ]]>
        </block>
        <block id="block2">
            <![CDATA[
                echo $static_var_1;
            ]]>
        </block>
    </process_chain>
    <process_chain id="chain2">
        <block id="block3">
            <![CDATA[
                static_var_1="modified_in_chain2_block3";
            ]]>
        </block>
        <block id="block4">
            <![CDATA[
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

#[tokio::test]
async fn test_env() {
    TermLogger::init(
        LevelFilter::Info,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap_or_else(|_| {
        // If TermLogger is not available (e.g., in some environments), fall back to SimpleLogger
        let _ = SimpleLogger::init(LevelFilter::Info, Config::default());
    });

    // Register the add command in the external command factory for global scope
    EXTERNAL_COMMAND_FACTORY
        .register("add", Arc::new(Box::new(AddCommand::new())))
        .unwrap();

    // Create a hook point environment to execute the target hook point
    let data_dir = std::env::temp_dir().join("cyfs-process-chain-test-env");
    std::fs::create_dir_all(&data_dir).unwrap();
    let hook_point_env = HookPointEnv::new("test_env", data_dir);

    // Register the add_2 command in the hook point environment only
    hook_point_env
        .register_external_command("add_2", Arc::new(Box::new(AddCommand::new())))
        .unwrap();

    // Set some static variables in the hook point environment
    hook_point_env
        .hook_point_env()
        .set(
            "static_var_1",
            CollectionValue::String("static1".to_string()),
        )
        .await
        .unwrap();

    // Create a hook point
    let hook_point = HookPoint::new("test_env_hook_point");
    hook_point
        .load_process_chain_lib("test_env_lib1", 0, PROCESS_CHAIN_LIB1)
        .await
        .unwrap();

    // Link the hook point with the hook point environment and get the executor
    let exec = hook_point_env.link_hook_point(&hook_point).await.unwrap();

    // There are two ways to execute the process chain lib in the hook point environment
    // First way: prepare the lib executor and execute it in a loop
    {
        let lib_exec = exec.prepare_exec_lib("test_env_lib1").unwrap();

        for _ in 0..10 {
            let exec = lib_exec.fork();

            // The executor's global env is different from the hook point env
            // And shared between all lib/chains in this 'exec' executor item
            exec.global_env()
                .set(
                    "static_var_1",
                    CollectionValue::String("overridden_in_exec".to_string()),
                )
                .await
                .unwrap();

            exec.execute_lib().await.unwrap();
        }
    }

    // Second way: directly execute the lib in a loop
    // The execute_lib will create a new executor each time
    {
        for _ in 0..10 {
            exec.execute_lib("test_env_lib1").await.unwrap();
        }
    }
}
