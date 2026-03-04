use crate::*;
use simplelog::*;

const PROCESS_CHAIN_COERCION_LEGACY: &str = r#"
<process_chain_lib id="coercion_legacy_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                match $flag "true" || return --from lib "flag-fail";
                match $num "7" || return --from lib "num-fail";
                match $none "" || return --from lib "none-fail";
                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_COERCION_STRICT: &str = r#"
<process_chain_lib id="coercion_strict_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                match $flag "true";
                return --from lib "unexpected";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_VALUE_COMMANDS: &str = r#"
<process_chain_lib id="value_commands_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                local b=$(to-bool $flag);
                local n=$(to-number $numText);
                is-null $none || return --from lib "is-null-fail";
                is-bool $flag || return --from lib "is-bool-fail";
                is-number $num || return --from lib "is-number-fail";
                return --from lib $(append $b "|" $n);
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_VALUE_CONVERSION_FALLBACK: &str = r#"
<process_chain_lib id="value_conversion_fallback_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                to-number "abc" || return --from lib "fallback";
                return --from lib "unexpected";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_VALUE_CONVERSION_STRICT_POLICY: &str = r#"
<process_chain_lib id="value_conversion_strict_policy_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                to-number $flag || return --from lib "coercion_failed";
                return --from lib "unexpected";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_LITERAL_MODE_BASIC: &str = r#"
<process_chain_lib id="literal_mode_basic_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                local b=true;
                local n1=123;
                local n2=12.5;
                local z=null;
                return --from lib $(append $(type $b) "|" $(type $n1) "|" $(type $n2) "|" $(type $z));
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_LITERAL_MODE_QUOTED: &str = r#"
<process_chain_lib id="literal_mode_quoted_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                local q1="123";
                local q2='false';
                local u=123;
                return --from lib $(append $(type $q1) "|" $(type $q2) "|" $(type $u));
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

fn init_logger() {
    TermLogger::init(
        LevelFilter::Info,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap_or_else(|_| {
        let _ = SimpleLogger::init(LevelFilter::Info, Config::default());
    });
}

#[tokio::test]
async fn test_string_coercion_legacy_policy_allows_bool_number_null() {
    init_logger();

    let hook_point = HookPoint::new("test_coercion_legacy");
    hook_point
        .load_process_chain_lib("coercion_legacy_lib", 0, PROCESS_CHAIN_COERCION_LEGACY)
        .await
        .unwrap();

    let data_dir = std::env::temp_dir().join("cyfs-process-chain-test-coercion-legacy");
    std::fs::create_dir_all(&data_dir).unwrap();
    let hook_point_env = HookPointEnv::new("test-coercion-legacy", data_dir);

    hook_point_env
        .hook_point_env()
        .create("flag", CollectionValue::Bool(true))
        .await
        .unwrap();
    hook_point_env
        .hook_point_env()
        .create("num", CollectionValue::Number(NumberValue::Int(7)))
        .await
        .unwrap();
    hook_point_env
        .hook_point_env()
        .create("none", CollectionValue::Null)
        .await
        .unwrap();

    let exec = hook_point_env.link_hook_point(&hook_point).await.unwrap();
    let ret = exec.execute_lib("coercion_legacy_lib").await.unwrap();
    assert_eq!(ret.value(), "ok");
}

#[tokio::test]
async fn test_string_coercion_strict_policy_rejects_bool_number_null() {
    init_logger();

    let hook_point = HookPoint::new("test_coercion_strict");
    hook_point
        .load_process_chain_lib("coercion_strict_lib", 0, PROCESS_CHAIN_COERCION_STRICT)
        .await
        .unwrap();

    let data_dir = std::env::temp_dir().join("cyfs-process-chain-test-coercion-strict");
    std::fs::create_dir_all(&data_dir).unwrap();
    let hook_point_env = HookPointEnv::new("test-coercion-strict", data_dir);
    hook_point_env.set_coercion_policy(CoercionPolicy::Strict);

    hook_point_env
        .hook_point_env()
        .create("flag", CollectionValue::Bool(true))
        .await
        .unwrap();

    let exec = hook_point_env.link_hook_point(&hook_point).await.unwrap();
    let err = exec.execute_lib("coercion_strict_lib").await.unwrap_err();
    assert!(
        err.contains("Expected string value, found Bool (strict coercion)"),
        "unexpected error: {}",
        err
    );
}

#[tokio::test]
async fn test_value_commands_to_bool_to_number_and_is_checks() {
    init_logger();

    let hook_point = HookPoint::new("test_value_commands");
    hook_point
        .load_process_chain_lib("value_commands_lib", 0, PROCESS_CHAIN_VALUE_COMMANDS)
        .await
        .unwrap();

    let data_dir = std::env::temp_dir().join("cyfs-process-chain-test-value-commands");
    std::fs::create_dir_all(&data_dir).unwrap();
    let hook_point_env = HookPointEnv::new("test-value-commands", data_dir);

    hook_point_env
        .hook_point_env()
        .create("flag", CollectionValue::Bool(true))
        .await
        .unwrap();
    hook_point_env
        .hook_point_env()
        .create("numText", CollectionValue::String("12.5".to_string()))
        .await
        .unwrap();
    hook_point_env
        .hook_point_env()
        .create("none", CollectionValue::Null)
        .await
        .unwrap();
    hook_point_env
        .hook_point_env()
        .create("num", CollectionValue::Number(NumberValue::Int(9)))
        .await
        .unwrap();

    let exec = hook_point_env.link_hook_point(&hook_point).await.unwrap();
    let ret = exec.execute_lib("value_commands_lib").await.unwrap();
    assert_eq!(ret.value(), "true|12.5");
}

#[tokio::test]
async fn test_to_number_can_be_handled_by_or_fallback() {
    init_logger();

    let hook_point = HookPoint::new("test_value_conversion_fallback");
    hook_point
        .load_process_chain_lib(
            "value_conversion_fallback_lib",
            0,
            PROCESS_CHAIN_VALUE_CONVERSION_FALLBACK,
        )
        .await
        .unwrap();

    let data_dir = std::env::temp_dir().join("cyfs-process-chain-test-value-conversion-fallback");
    std::fs::create_dir_all(&data_dir).unwrap();
    let hook_point_env = HookPointEnv::new("test-value-conversion-fallback", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await.unwrap();
    let ret = exec
        .execute_lib("value_conversion_fallback_lib")
        .await
        .unwrap();
    assert_eq!(ret.value(), "fallback");
}

#[tokio::test]
async fn test_to_number_respects_strict_coercion_policy() {
    init_logger();

    let hook_point = HookPoint::new("test_value_conversion_strict_policy");
    hook_point
        .load_process_chain_lib(
            "value_conversion_strict_policy_lib",
            0,
            PROCESS_CHAIN_VALUE_CONVERSION_STRICT_POLICY,
        )
        .await
        .unwrap();

    let data_dir =
        std::env::temp_dir().join("cyfs-process-chain-test-value-conversion-strict-policy");
    std::fs::create_dir_all(&data_dir).unwrap();
    let hook_point_env = HookPointEnv::new("test-value-conversion-strict-policy", data_dir);
    hook_point_env.set_coercion_policy(CoercionPolicy::Strict);

    hook_point_env
        .hook_point_env()
        .create("flag", CollectionValue::Bool(true))
        .await
        .unwrap();

    let exec = hook_point_env.link_hook_point(&hook_point).await.unwrap();
    let ret = exec
        .execute_lib("value_conversion_strict_policy_lib")
        .await
        .unwrap();
    assert_eq!(ret.value(), "coercion_failed");
}

#[tokio::test]
async fn test_typed_literal_default_promotes_basic_literals() {
    init_logger();

    let hook_point = HookPoint::new("test_typed_literal_default");
    hook_point
        .load_process_chain_lib(
            "literal_mode_basic_lib",
            0,
            PROCESS_CHAIN_LITERAL_MODE_BASIC,
        )
        .await
        .unwrap();

    let data_dir = std::env::temp_dir().join("cyfs-process-chain-test-typed-literal-default");
    std::fs::create_dir_all(&data_dir).unwrap();
    let hook_point_env = HookPointEnv::new("test-typed-literal-default", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await.unwrap();
    let ret = exec.execute_lib("literal_mode_basic_lib").await.unwrap();
    assert_eq!(ret.value(), "Bool|Number|Number|Null");
}

#[tokio::test]
async fn test_typed_literal_preserves_quoted_string_literals() {
    init_logger();

    let hook_point = HookPoint::new("test_literal_mode_typed_quoted");
    hook_point
        .load_process_chain_lib(
            "literal_mode_quoted_lib",
            0,
            PROCESS_CHAIN_LITERAL_MODE_QUOTED,
        )
        .await
        .unwrap();

    let data_dir = std::env::temp_dir().join("cyfs-process-chain-test-literal-mode-typed-quoted");
    std::fs::create_dir_all(&data_dir).unwrap();
    let hook_point_env = HookPointEnv::new("test-literal-mode-typed-quoted", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await.unwrap();
    let ret = exec.execute_lib("literal_mode_quoted_lib").await.unwrap();
    assert_eq!(ret.value(), "String|String|Number");
}
