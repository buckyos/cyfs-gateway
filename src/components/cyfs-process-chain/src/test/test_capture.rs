use crate::*;
use simplelog::*;

const PROCESS_CHAIN_CAPTURE: &str = r#"
<process_chain_lib id="capture_lib" priority="100">
    <process_chain id="chain1">
        <block id="block1">
            <![CDATA[
                capture --value v1 --status s1 --ok ok1 --error err1 --control ctl1 --control-kind kind1 --from from1 $(match "abc" "a*") || return --from lib "fail_capture_success";
                echo --verbose "Captured value:" $v1 "status:" $s1 "ok:" $ok1 "err:" $err1 "ctl:" $ctl1
                eq $s1 "success" && eq $v1 true || return --from lib "fail_value_success";
                eq $ok1 true && eq $err1 false && eq $ctl1 false || return --from lib "fail_flags_success";
                is-null $kind1 || return --from lib "fail_kind_success";
                is-null $from1 || return --from lib "fail_from_success";

                capture --value v2 --status s2 --ok ok2 --error err2 --control ctl2 --control-kind kind2 --from from2 $(match "abc" "z*") && return --from lib "fail_capture_error";
                echo --verbose "Captured value:" $v2 "status:" $s2 "ok:" $ok2 "err:" $err2 "ctl:" $ctl2
                eq $s2 "error" && eq $v2 false || return --from lib "fail_value_error";
                eq $ok2 false && eq $err2 true && eq $ctl2 false || return --from lib "fail_flags_error";
                is-null $kind2 || return --from lib "fail_kind_error";
                is-null $from2 || return --from lib "fail_from_error";

                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

#[tokio::test]
async fn test_capture_command() {
    TermLogger::init(
        LevelFilter::Info,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap_or_else(|_| {
        let _ = SimpleLogger::init(LevelFilter::Info, Config::default());
    });

    let hook_point = HookPoint::new("test_capture");
    hook_point
        .load_process_chain_lib("capture_lib", 0, PROCESS_CHAIN_CAPTURE)
        .await
        .unwrap();

    let data_dir = std::env::temp_dir().join("cyfs-process-chain-test-capture");
    std::fs::create_dir_all(&data_dir).unwrap();
    let hook_point_env = HookPointEnv::new("test-capture", data_dir);
    let exec = hook_point_env.link_hook_point(&hook_point).await.unwrap();

    let ret = exec.execute_lib("capture_lib").await.unwrap();
    assert_eq!(ret.value(), "ok");

    let output = hook_point_env.pipe().stdout.clone_string();
    info!("{}", output);
}
