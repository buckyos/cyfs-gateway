use crate::*;
use simplelog::*;
use std::sync::Arc;

const PROCESS_CHAIN_LIB_VAR: &str = r#"
<process_chain_lib id="test_var_lib" priority="100">
    <process_chain id="route_chain">
        <block id="route">
            <![CDATA[
                local clientIp=$REQ.clientIp;
                local geo_country=$geoByIp.($clientIp).country;
                local geo_isp=$geoByIp.($clientIp).isp;

                match $geo_country "CN" && match $geo_isp "*中国电信*" && return --from lib "upstreamA";
                match $geo_country "CN" && match $geo_isp "*中国联通*" && return --from lib "upstreamB";
                match $geo_country "*" && !match $geo_country "CN" && return --from lib "upstreamC";
                return --from lib "upstreamDefault";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

async fn make_geo_entry(country: &str, isp: &str, city: &str) -> MapCollectionRef {
    let map = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    map.insert("country", CollectionValue::String(country.to_string()))
        .await
        .unwrap();
    map.insert("isp", CollectionValue::String(isp.to_string()))
        .await
        .unwrap();
    map.insert("city", CollectionValue::String(city.to_string()))
        .await
        .unwrap();
    map
}

async fn set_client_ip(req: &MapCollectionRef, client_ip: &str) {
    req.insert(
        "clientIp",
        CollectionValue::String(client_ip.to_string()),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn test_dynamic_map_lookup_routing() {
    TermLogger::init(
        LevelFilter::Info,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap_or_else(|_| {
        let _ = SimpleLogger::init(LevelFilter::Info, Config::default());
    });

    let hook_point = HookPoint::new("test_var");
    hook_point
        .load_process_chain_lib("test_var_lib", 0, PROCESS_CHAIN_LIB_VAR)
        .await
        .unwrap();

    let data_dir = std::env::temp_dir().join("cyfs-process-chain-test-var");
    std::fs::create_dir_all(&data_dir).unwrap();
    let hook_point_env = HookPointEnv::new("test-var", data_dir);

    let geo_by_ip = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    // Use '_' instead of '.' in keys because '.' is the path separator in process-chain vars.
    geo_by_ip
        .insert(
            "1_2_3_4",
            CollectionValue::Map(make_geo_entry("CN", "中国电信", "Shenzhen").await),
        )
        .await
        .unwrap();
    geo_by_ip
        .insert(
            "5_6_7_8",
            CollectionValue::Map(make_geo_entry("CN", "中国联通", "Guangzhou").await),
        )
        .await
        .unwrap();
    geo_by_ip
        .insert(
            "9_9_9_9",
            CollectionValue::Map(make_geo_entry("US", "Comcast", "SanJose").await),
        )
        .await
        .unwrap();
    geo_by_ip
        .insert(
            "8_8_8_8",
            CollectionValue::Map(make_geo_entry("CN", "OtherIsp", "Beijing").await),
        )
        .await
        .unwrap();

    let req = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    set_client_ip(&req, "1_2_3_4").await;

    hook_point_env
        .hook_point_env()
        .create("geoByIp", CollectionValue::Map(geo_by_ip))
        .await
        .unwrap();
    hook_point_env
        .hook_point_env()
        .create("REQ", CollectionValue::Map(req.clone()))
        .await
        .unwrap();

    let exec = hook_point_env.link_hook_point(&hook_point).await.unwrap();

    set_client_ip(&req, "1_2_3_4").await;
    let ret = exec.execute_lib("test_var_lib").await.unwrap();
    assert_eq!(ret.value(), "upstreamA");

    set_client_ip(&req, "5_6_7_8").await;
    let ret = exec.execute_lib("test_var_lib").await.unwrap();
    assert_eq!(ret.value(), "upstreamB");

    set_client_ip(&req, "9_9_9_9").await;
    let ret = exec.execute_lib("test_var_lib").await.unwrap();
    assert_eq!(ret.value(), "upstreamC");

    set_client_ip(&req, "8_8_8_8").await;
    let ret = exec.execute_lib("test_var_lib").await.unwrap();
    assert_eq!(ret.value(), "upstreamDefault");
}
