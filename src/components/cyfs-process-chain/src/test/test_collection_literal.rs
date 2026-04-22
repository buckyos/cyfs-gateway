use crate::*;
use simplelog::*;
use std::path::PathBuf;
use std::sync::Once;
use std::time::{SystemTime, UNIX_EPOCH};

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

const PROCESS_CHAIN_COLLECTION_LITERAL: &str = r#"
<process_chain_lib id="collection_literal_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                local route={"kind": "app", "app_id": $REQ.appId, "target": {"node_id": $REQ.nodeId, "port": $REQ.port}, "tags": ["alpha", "beta"]};
                eq $route.kind "app" || return --from lib "route_kind_fail";
                eq $route.target.node_id $REQ.nodeId || return --from lib "route_target_fail";
                eq $route.tags[1] "beta" || return --from lib "route_tag_fail";

                capture --value helper_ret $(exec helper);
                eq $helper_ret.kind "service" || return --from lib "helper_kind_fail";
                eq $helper_ret.service_id $REQ.serviceId || return --from lib "helper_service_fail";
                eq $helper_ret.ports[0] $REQ.port || return --from lib "helper_port_fail";
                eq $helper_ret.meta["region.code"] $REQ.regionCode || return --from lib "helper_region_fail";
                eq $helper_ret.meta.enabled true || return --from lib "helper_enabled_fail";

                return --from lib $helper_ret;
            ]]>
        </block>

        <block id="helper">
            <![CDATA[
                return --from block {"kind": "service", "service_id": $REQ.serviceId, "ports": [$REQ.port, 3180], "meta": {"region.code": $REQ.regionCode, "enabled": true}};
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

async fn make_req() -> MapCollectionRef {
    let req = MemoryMapCollection::new_ref();
    req.insert("appId", CollectionValue::String("notes".to_string()))
        .await
        .unwrap();
    req.insert("nodeId", CollectionValue::String("ood1".to_string()))
        .await
        .unwrap();
    req.insert("port", CollectionValue::String("3180".to_string()))
        .await
        .unwrap();
    req.insert(
        "serviceId",
        CollectionValue::String("system_config".to_string()),
    )
    .await
    .unwrap();
    req.insert("regionCode", CollectionValue::String("CN-SZ".to_string()))
        .await
        .unwrap();
    req
}

#[tokio::test]
async fn test_collection_literals_support_typed_return_and_fresh_instances() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_collection_literal");
    hook_point
        .load_process_chain_lib(
            "collection_literal_lib",
            0,
            PROCESS_CHAIN_COLLECTION_LITERAL,
        )
        .await?;

    let data_dir = new_test_data_dir("test-collection-literal")?;
    let hook_point_env = HookPointEnv::new("test-collection-literal", data_dir);
    hook_point_env
        .hook_point_env()
        .create("REQ", CollectionValue::Map(make_req().await))
        .await?;

    let exec = hook_point_env.link_hook_point(&hook_point).await?;

    let first = exec.execute_lib("collection_literal_lib").await?;
    let first_map = first.value_ref().try_as_map()?.clone();
    assert_eq!(
        first_map.get("kind").await?.unwrap().as_str(),
        Some("service")
    );
    assert_eq!(
        first_map.get("service_id").await?.unwrap().as_str(),
        Some("system_config")
    );

    let first_ports = first_map
        .get("ports")
        .await?
        .unwrap()
        .try_as_list()?
        .clone();
    assert_eq!(first_ports.get(0).await?.unwrap().as_str(), Some("3180"));
    assert!(matches!(
        first_ports.get(1).await?.unwrap(),
        CollectionValue::Number(NumberValue::Int(3180))
    ));

    let first_meta = first_map.get("meta").await?.unwrap().try_as_map()?.clone();
    assert_eq!(
        first_meta.get("region.code").await?.unwrap().as_str(),
        Some("CN-SZ")
    );
    assert_eq!(
        first_meta.get("enabled").await?.unwrap().as_bool(),
        Some(true)
    );

    first_map
        .insert("kind", CollectionValue::String("mutated".to_string()))
        .await?;
    first_ports
        .set(0, CollectionValue::String("changed".to_string()))
        .await?;

    let second = exec.execute_lib("collection_literal_lib").await?;
    let second_map = second.value_ref().try_as_map()?.clone();
    assert_eq!(
        second_map.get("kind").await?.unwrap().as_str(),
        Some("service")
    );

    let second_ports = second_map
        .get("ports")
        .await?
        .unwrap()
        .try_as_list()?
        .clone();
    assert_eq!(second_ports.get(0).await?.unwrap().as_str(), Some("3180"));

    Ok(())
}
