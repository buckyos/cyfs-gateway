use super::external::*;
use crate::*;
use simplelog::*;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Once;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

const LOCAL_ADD_COMMAND: &str = "add_hook_point";

const PROCESS_CHAIN_HOOK: &str = r#"
<root>
<process_chain id="chain2">
    <block id="block1">
        <![CDATA[
            # We reject the request if the protocol is not https
            !(match $PROTOCOL https) && reject;

            local key1="key1";
            echo $(type key2);
            echo "\$get request url: ${REQ_url} \n ${PROTOCOL}";
            echo $(call add_hook_point 1 2);
            echo $(add_hook_point 1 2);
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
            map-add test1 key3 key2;

            echo --verbose "====> test nest" test1.($test1.key3);
            echo --verbose "====> test nest value" $test1.($test1.key3);
            echo --verbose "====> test nest value" ${test1.($test1.key3)};
            echo --verbose "====> test nest value not exist" ${test1.($test1.key4)};

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

fn new_test_data_dir(scope: &str) -> Result<PathBuf, String> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system time error: {}", e))?
        .as_nanos();
    let pid = std::process::id();
    let data_dir =
        std::env::temp_dir().join(format!("cyfs-process-chain-{}-{}-{}", scope, pid, ts));
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| format!("create test data dir {:?} failed: {}", data_dir, e))?;
    Ok(data_dir)
}

fn register_local_external_commands(hook_point_env: &HookPointEnv) -> Result<(), String> {
    hook_point_env
        .register_external_command(LOCAL_ADD_COMMAND, Arc::new(Box::new(AddCommand::new())))?;
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
                Err(msg)
            }
            "REQ_url" => {
                let mut url = self.url.write().unwrap();
                let old_value = url.clone();
                *url = value.try_as_str()?.to_string();
                info!("Set variable '{}' to '{}'", id, value);
                Ok(Some(CollectionValue::String(old_value)))
            }
            _ => Err(format!("Variable '{}' is read-only", id)),
        }
    }
}

async fn test_hook_point() -> Result<(), String> {
    let hook_point = HookPoint::new("test_hook_point");
    hook_point
        .load_process_chain_lib("main", 0, PROCESS_CHAIN_HOOK)
        .await?;

    let data_dir = new_test_data_dir("test-block-hook-point")?;
    let hook_point_env = HookPointEnv::new("test-hook-point", data_dir);

    hook_point_env
        .load_collection(
            "host",
            CollectionType::MultiMap,
            CollectionFileFormat::Json,
            true,
        )
        .await?;
    hook_point_env
        .load_collection(
            "ip",
            CollectionType::MultiMap,
            CollectionFileFormat::Json,
            true,
        )
        .await?;

    register_local_external_commands(&hook_point_env)?;

    let test_visitor = TestVisitor::new();
    test_visitor
        .register(hook_point_env.hook_point_env())
        .await?;

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let lib_exec = exec.prepare_exec_lib("main")?;
    let global_env = lib_exec.global_env().clone();
    let ret = lib_exec.execute_lib().await?;
    assert!(ret.is_accept(), "Hook point execution failed: {:?}", ret);

    hook_point_env.flush_collections().await?;

    let output = hook_point_env.pipe().stdout.clone_string();
    assert!(
        output.contains("http://www.buckyos.com"),
        "Hook point output should contain REQ_url, got: {}",
        output
    );

    let key2 = global_env
        .get("key2")
        .await?
        .ok_or_else(|| "key2 missing in hook-point global env".to_string())?;
    assert_eq!(key2.as_str(), Some("value1_value2"));

    Ok(())
}

#[tokio::test]
async fn test_hook_point_block_integration() -> Result<(), String> {
    init_test_logger();
    test_hook_point().await
}
