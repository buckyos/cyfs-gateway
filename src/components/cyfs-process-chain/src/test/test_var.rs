use crate::*;
use simplelog::*;
use std::sync::Arc;

const PROCESS_CHAIN_LIB_VAR: &str = r#"
<process_chain_lib id="test_var_lib" priority="100">
    <process_chain id="route_chain">
        <block id="route">
            <![CDATA[
                local clientIp=$REQ.clientIp;
                local tmp = $geoByIp.($REQ.clientIp).country;
                local geo_country=$geoByIp.($clientIp).country;
                local geo_country_bracket=$geoByIp[$clientIp].country;
                local geo_isp=$geoByIp.($clientIp).isp;
                eq $geo_country $geo_country_bracket || error --from lib "country_mismatch";

                match $geo_country "CN" && match $geo_isp "*中国电信*" && return --from lib "upstreamA";
                match $geo_country "CN" && match $geo_isp "*中国联通*" && return --from lib "upstreamB";
                match $geo_country "*" && !match $geo_country "CN" && return --from lib "upstreamC";
                return --from lib "upstreamDefault";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_LIB_VAR_COMPLEX: &str = r#"
<process_chain_lib id="test_var_complex_lib" priority="100">
    <process_chain id="route_chain_complex">
        <block id="route">
            <![CDATA[
                local clientIp=$REQ.clientIp;
                local metaField=$REQ.metaField;

                local country_legacy=$geoByIp.($clientIp).country;
                local country_bracket=$geoByIp[$clientIp]["country"];
                eq $country_legacy $country_bracket || error --from lib "country_syntax_mismatch";

                local region_code_quoted=$geoByIp[$clientIp].meta["region.code"];
                local region_code_dynamic=$geoByIp[$clientIp].meta[$metaField];
                eq $region_code_quoted $region_code_dynamic || error --from lib "region_code_mismatch";

                local zone_quoted=${geoByIp[$REQ.clientIp].meta["zone-name"]};
                local zone_legacy=$geoByIp.($REQ.clientIp).meta.zone-name;
                eq $zone_quoted $zone_legacy || error --from lib "zone_name_mismatch";

                local target=$routes[$region_code_dynamic]["target.chain"];
                return --from lib $target;
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_LIB_VAR_POLICY: &str = r#"
<process_chain_lib id="test_var_policy_lib" priority="100">
    <process_chain id="route_chain_policy">
        <block id="route">
            <![CDATA[
                local country=$geoByIp[$REQ.clientIp].country;
                return --from lib $country;
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_LIB_VAR_SAFE_DEFAULT: &str = r#"
<process_chain_lib id="test_var_safe_default_lib" priority="100">
    <process_chain id="route_chain_safe_default">
        <block id="route">
            <![CDATA[
                local country=${geoByIp[$REQ.clientIp]?.country ?? "unknown_country"};
                local region=${geoByIp[$REQ.clientIp]?.meta?.["region.code"] ?? "unknown_region"};
                local safe_only=${geoByIp[$REQ.clientIp]?.meta?.["missing.field"]};
                return --from lib $(append $country "|" $region "|" $safe_only);
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_LIB_VAR_SAFE_TYPE_MISMATCH: &str = r#"
<process_chain_lib id="test_var_safe_type_mismatch_lib" priority="100">
    <process_chain id="route_chain_safe_type_mismatch">
        <block id="route">
            <![CDATA[
                local region=${geoByIp[$REQ.clientIp]?.meta?.["region.code"] ?? "fallback_region"};
                return --from lib $region;
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_LIB_VAR_COLLECTION_ASSIGN: &str = r#"
<process_chain_lib id="test_var_collection_assign_lib" priority="100">
    <process_chain id="collection_assign_chain">
        <block id="route">
            <![CDATA[
                local currentGeo=$geoByIp[$REQ.clientIp];
                local country=$currentGeo.country;

                local trustedSet=$trustedCountrySet;
                match-include $trustedSet $country || error --from lib "country_not_trusted";

                return --from lib $country;
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

async fn make_geo_entry_with_meta(
    country: &str,
    isp: &str,
    city: &str,
    region_code: &str,
    zone_name: &str,
) -> MapCollectionRef {
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

    let meta = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    meta.insert(
        "region.code",
        CollectionValue::String(region_code.to_string()),
    )
    .await
    .unwrap();
    meta.insert("zone-name", CollectionValue::String(zone_name.to_string()))
        .await
        .unwrap();

    map.insert("meta", CollectionValue::Map(meta))
        .await
        .unwrap();
    map
}

async fn make_geo_entry_with_bad_meta(
    country: &str,
    isp: &str,
    city: &str,
    bad_meta: &str,
) -> MapCollectionRef {
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
    map.insert("meta", CollectionValue::String(bad_meta.to_string()))
        .await
        .unwrap();
    map
}

async fn make_route_entry(target_chain: &str) -> MapCollectionRef {
    let map = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    map.insert(
        "target.chain",
        CollectionValue::String(target_chain.to_string()),
    )
    .await
    .unwrap();
    map
}

async fn set_client_ip(req: &MapCollectionRef, client_ip: &str) {
    req.insert("clientIp", CollectionValue::String(client_ip.to_string()))
        .await
        .unwrap();
}

async fn set_meta_field(req: &MapCollectionRef, field: &str) {
    req.insert("metaField", CollectionValue::String(field.to_string()))
        .await
        .unwrap();
}

#[tokio::test]
async fn test_collection_assignment_supports_map_and_set() {
    TermLogger::init(
        LevelFilter::Debug,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap_or_else(|_| {
        let _ = SimpleLogger::init(LevelFilter::Debug, Config::default());
    });

    let hook_point = HookPoint::new("test_var_collection_assign");
    hook_point
        .load_process_chain_lib(
            "test_var_collection_assign_lib",
            0,
            PROCESS_CHAIN_LIB_VAR_COLLECTION_ASSIGN,
        )
        .await
        .unwrap();

    let data_dir = std::env::temp_dir().join("cyfs-process-chain-test-var-collection-assign");
    std::fs::create_dir_all(&data_dir).unwrap();
    let hook_point_env = HookPointEnv::new("test-var-collection-assign", data_dir);

    let geo_by_ip = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    geo_by_ip
        .insert(
            "1.2.3.4",
            CollectionValue::Map(make_geo_entry("CN", "中国电信", "Shenzhen").await),
        )
        .await
        .unwrap();

    let req = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    set_client_ip(&req, "1.2.3.4").await;

    let trusted_country_set =
        Arc::new(Box::new(MemorySetCollection::new()) as Box<dyn SetCollection>);
    trusted_country_set.insert("CN").await.unwrap();
    trusted_country_set.insert("US").await.unwrap();

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
    hook_point_env
        .hook_point_env()
        .create(
            "trustedCountrySet",
            CollectionValue::Set(trusted_country_set),
        )
        .await
        .unwrap();

    let exec = hook_point_env.link_hook_point(&hook_point).await.unwrap();
    let ret = exec
        .execute_lib("test_var_collection_assign_lib")
        .await
        .unwrap();
    assert_eq!(ret.value(), "CN");
}

#[tokio::test]
async fn test_dynamic_map_lookup_routing() {
    TermLogger::init(
        LevelFilter::Debug,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap_or_else(|_| {
        let _ = SimpleLogger::init(LevelFilter::Debug, Config::default());
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
    // Dot keys are accessed through dynamic segments (`.(...)`) and bracket path syntax (`[...]`).
    geo_by_ip
        .insert(
            "1.2.3.4",
            CollectionValue::Map(make_geo_entry("CN", "中国电信", "Shenzhen").await),
        )
        .await
        .unwrap();
    geo_by_ip
        .insert(
            "5.6.7.8",
            CollectionValue::Map(make_geo_entry("CN", "中国联通", "Guangzhou").await),
        )
        .await
        .unwrap();
    geo_by_ip
        .insert(
            "9.9.9.9",
            CollectionValue::Map(make_geo_entry("US", "Comcast", "SanJose").await),
        )
        .await
        .unwrap();
    geo_by_ip
        .insert(
            "8.8.8.8",
            CollectionValue::Map(make_geo_entry("CN", "OtherIsp", "Beijing").await),
        )
        .await
        .unwrap();

    let req = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    set_client_ip(&req, "1.2.3.4").await;

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

    set_client_ip(&req, "1.2.3.4").await;
    let ret = exec.execute_lib("test_var_lib").await.unwrap();
    assert_eq!(ret.value(), "upstreamA");

    set_client_ip(&req, "5.6.7.8").await;
    let ret = exec.execute_lib("test_var_lib").await.unwrap();
    assert_eq!(ret.value(), "upstreamB");

    set_client_ip(&req, "9.9.9.9").await;
    let ret = exec.execute_lib("test_var_lib").await.unwrap();
    assert_eq!(ret.value(), "upstreamC");

    set_client_ip(&req, "8.8.8.8").await;
    let ret = exec.execute_lib("test_var_lib").await.unwrap();
    assert_eq!(ret.value(), "upstreamDefault");
}

#[tokio::test]
async fn test_dynamic_map_lookup_complex_nested() {
    TermLogger::init(
        LevelFilter::Debug,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap_or_else(|_| {
        let _ = SimpleLogger::init(LevelFilter::Debug, Config::default());
    });

    let hook_point = HookPoint::new("test_var_complex");
    hook_point
        .load_process_chain_lib("test_var_complex_lib", 0, PROCESS_CHAIN_LIB_VAR_COMPLEX)
        .await
        .unwrap();

    let data_dir = std::env::temp_dir().join("cyfs-process-chain-test-var-complex");
    std::fs::create_dir_all(&data_dir).unwrap();
    let hook_point_env = HookPointEnv::new("test-var-complex", data_dir);

    let geo_by_ip = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    geo_by_ip
        .insert(
            "1.2.3.4",
            CollectionValue::Map(
                make_geo_entry_with_meta("CN", "中国电信", "Shenzhen", "CN.SZ", "south-zone").await,
            ),
        )
        .await
        .unwrap();
    geo_by_ip
        .insert(
            "5.6.7.8",
            CollectionValue::Map(
                make_geo_entry_with_meta("CN", "中国联通", "Guangzhou", "CN.GZ", "south-zone")
                    .await,
            ),
        )
        .await
        .unwrap();
    geo_by_ip
        .insert(
            "9.9.9.9",
            CollectionValue::Map(
                make_geo_entry_with_meta("US", "Comcast", "SanJose", "US.SJC", "west-zone").await,
            ),
        )
        .await
        .unwrap();

    let routes = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    routes
        .insert(
            "CN.SZ",
            CollectionValue::Map(make_route_entry("upstreamA").await),
        )
        .await
        .unwrap();
    routes
        .insert(
            "CN.GZ",
            CollectionValue::Map(make_route_entry("upstreamB").await),
        )
        .await
        .unwrap();
    routes
        .insert(
            "US.SJC",
            CollectionValue::Map(make_route_entry("upstreamC").await),
        )
        .await
        .unwrap();

    let req = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    set_client_ip(&req, "1.2.3.4").await;
    set_meta_field(&req, "region.code").await;

    hook_point_env
        .hook_point_env()
        .create("geoByIp", CollectionValue::Map(geo_by_ip))
        .await
        .unwrap();
    hook_point_env
        .hook_point_env()
        .create("routes", CollectionValue::Map(routes))
        .await
        .unwrap();
    hook_point_env
        .hook_point_env()
        .create("REQ", CollectionValue::Map(req.clone()))
        .await
        .unwrap();

    let exec = hook_point_env.link_hook_point(&hook_point).await.unwrap();

    set_client_ip(&req, "1.2.3.4").await;
    let ret = exec.execute_lib("test_var_complex_lib").await.unwrap();
    assert_eq!(ret.value(), "upstreamA");

    set_client_ip(&req, "5.6.7.8").await;
    let ret = exec.execute_lib("test_var_complex_lib").await.unwrap();
    assert_eq!(ret.value(), "upstreamB");

    set_client_ip(&req, "9.9.9.9").await;
    let ret = exec.execute_lib("test_var_complex_lib").await.unwrap();
    assert_eq!(ret.value(), "upstreamC");
}

#[tokio::test]
async fn test_dynamic_map_lookup_missing_ip_lenient_returns_empty() {
    TermLogger::init(
        LevelFilter::Debug,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap_or_else(|_| {
        let _ = SimpleLogger::init(LevelFilter::Debug, Config::default());
    });

    let hook_point = HookPoint::new("test_var_missing_ip_lenient");
    hook_point
        .load_process_chain_lib("test_var_policy_lib", 0, PROCESS_CHAIN_LIB_VAR_POLICY)
        .await
        .unwrap();

    let data_dir = std::env::temp_dir().join("cyfs-process-chain-test-var-missing-ip-lenient");
    std::fs::create_dir_all(&data_dir).unwrap();
    let hook_point_env = HookPointEnv::new("test-var-missing-ip-lenient", data_dir);

    let geo_by_ip = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    geo_by_ip
        .insert(
            "1.2.3.4",
            CollectionValue::Map(make_geo_entry("CN", "中国电信", "Shenzhen").await),
        )
        .await
        .unwrap();

    let req = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    set_client_ip(&req, "10.10.10.10").await;

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
    let ret = exec.execute_lib("test_var_policy_lib").await.unwrap();
    assert_eq!(ret.value(), "");
}

#[tokio::test]
async fn test_dynamic_map_lookup_missing_ip_strict_returns_error() {
    TermLogger::init(
        LevelFilter::Debug,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap_or_else(|_| {
        let _ = SimpleLogger::init(LevelFilter::Debug, Config::default());
    });

    let hook_point = HookPoint::new("test_var_missing_ip_strict");
    hook_point
        .load_process_chain_lib("test_var_policy_lib", 0, PROCESS_CHAIN_LIB_VAR_POLICY)
        .await
        .unwrap();

    let data_dir = std::env::temp_dir().join("cyfs-process-chain-test-var-missing-ip-strict");
    std::fs::create_dir_all(&data_dir).unwrap();
    let hook_point_env = HookPointEnv::new("test-var-missing-ip-strict", data_dir);

    let geo_by_ip = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    geo_by_ip
        .insert(
            "1.2.3.4",
            CollectionValue::Map(make_geo_entry("CN", "中国电信", "Shenzhen").await),
        )
        .await
        .unwrap();

    let req = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    set_client_ip(&req, "10.10.10.10").await;

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
    hook_point_env.set_execution_policy(ExecutionPolicy {
        missing_var: MissingVarPolicy::Strict,
    });

    let exec = hook_point_env.link_hook_point(&hook_point).await.unwrap();
    let err = exec.execute_lib("test_var_policy_lib").await.unwrap_err();
    assert!(
        err.contains("[PC-RUNTIME-0101]"),
        "unexpected error: {}",
        err
    );
    assert!(
        err.contains("lib=test_var_policy_lib"),
        "unexpected error: {}",
        err
    );
    assert!(
        err.contains("chain=route_chain_policy"),
        "unexpected error: {}",
        err
    );
    assert!(err.contains("block=route"), "unexpected error: {}", err);
    assert!(err.contains("line=1"), "unexpected error: {}", err);
    assert!(
        err.contains("source=local country=$geoByIp[$REQ.clientIp].country;"),
        "unexpected error: {}",
        err
    );
    assert!(
        err.contains("Variable 'geoByIp.10\\.10\\.10\\.10.country' not found in context"),
        "unexpected error: {}",
        err
    );
}

#[tokio::test]
async fn test_dynamic_map_lookup_missing_dynamic_segment_strict_returns_error() {
    TermLogger::init(
        LevelFilter::Debug,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap_or_else(|_| {
        let _ = SimpleLogger::init(LevelFilter::Debug, Config::default());
    });

    let hook_point = HookPoint::new("test_var_missing_dynamic_segment_strict");
    hook_point
        .load_process_chain_lib("test_var_policy_lib", 0, PROCESS_CHAIN_LIB_VAR_POLICY)
        .await
        .unwrap();

    let data_dir =
        std::env::temp_dir().join("cyfs-process-chain-test-var-missing-dynamic-segment-strict");
    std::fs::create_dir_all(&data_dir).unwrap();
    let hook_point_env = HookPointEnv::new("test-var-missing-dynamic-segment-strict", data_dir);

    let geo_by_ip = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    geo_by_ip
        .insert(
            "1.2.3.4",
            CollectionValue::Map(make_geo_entry("CN", "中国电信", "Shenzhen").await),
        )
        .await
        .unwrap();

    let req = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    // No clientIp on purpose: dynamic segment `$REQ.clientIp` should fail in strict mode.

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
    hook_point_env.set_missing_var_policy(MissingVarPolicy::Strict);

    let exec = hook_point_env.link_hook_point(&hook_point).await.unwrap();
    let err = exec.execute_lib("test_var_policy_lib").await.unwrap_err();
    assert!(
        err.contains(
            "Dynamic segment variable 'REQ.clientIp' not found while resolving 'geoByIp[$REQ.clientIp].country'"
        ),
        "unexpected error: {}",
        err
    );
}

#[tokio::test]
async fn test_safe_access_and_default_with_strict_policy() {
    TermLogger::init(
        LevelFilter::Debug,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap_or_else(|_| {
        let _ = SimpleLogger::init(LevelFilter::Debug, Config::default());
    });

    let hook_point = HookPoint::new("test_var_safe_default");
    hook_point
        .load_process_chain_lib(
            "test_var_safe_default_lib",
            0,
            PROCESS_CHAIN_LIB_VAR_SAFE_DEFAULT,
        )
        .await
        .unwrap();

    let data_dir = std::env::temp_dir().join("cyfs-process-chain-test-var-safe-default");
    std::fs::create_dir_all(&data_dir).unwrap();
    let hook_point_env = HookPointEnv::new("test-var-safe-default", data_dir);
    hook_point_env.set_missing_var_policy(MissingVarPolicy::Strict);

    let geo_by_ip = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    geo_by_ip
        .insert(
            "1.2.3.4",
            CollectionValue::Map(
                make_geo_entry_with_meta("CN", "中国电信", "Shenzhen", "CN.SZ", "south-zone").await,
            ),
        )
        .await
        .unwrap();

    let req = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    set_client_ip(&req, "1.2.3.4").await;

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

    let ret = exec.execute_lib("test_var_safe_default_lib").await.unwrap();
    assert_eq!(ret.value(), "CN|CN.SZ|");

    set_client_ip(&req, "10.10.10.10").await;
    let ret = exec.execute_lib("test_var_safe_default_lib").await.unwrap();
    assert_eq!(ret.value(), "unknown_country|unknown_region|");
}

#[tokio::test]
async fn test_safe_access_type_mismatch_uses_default() {
    TermLogger::init(
        LevelFilter::Debug,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap_or_else(|_| {
        let _ = SimpleLogger::init(LevelFilter::Debug, Config::default());
    });

    let hook_point = HookPoint::new("test_var_safe_type_mismatch");
    hook_point
        .load_process_chain_lib(
            "test_var_safe_type_mismatch_lib",
            0,
            PROCESS_CHAIN_LIB_VAR_SAFE_TYPE_MISMATCH,
        )
        .await
        .unwrap();

    let data_dir = std::env::temp_dir().join("cyfs-process-chain-test-var-safe-type-mismatch");
    std::fs::create_dir_all(&data_dir).unwrap();
    let hook_point_env = HookPointEnv::new("test-var-safe-type-mismatch", data_dir);
    hook_point_env.set_missing_var_policy(MissingVarPolicy::Strict);

    let geo_by_ip = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    geo_by_ip
        .insert(
            "1.2.3.4",
            CollectionValue::Map(
                make_geo_entry_with_bad_meta("CN", "中国电信", "Shenzhen", "not-a-map").await,
            ),
        )
        .await
        .unwrap();

    let req = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    set_client_ip(&req, "1.2.3.4").await;

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
    let ret = exec
        .execute_lib("test_var_safe_type_mismatch_lib")
        .await
        .unwrap();
    assert_eq!(ret.value(), "fallback_region");
}

#[tokio::test]
async fn test_dynamic_map_lookup_complex_missing_dynamic_field_returns_lib_error() {
    TermLogger::init(
        LevelFilter::Debug,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap_or_else(|_| {
        let _ = SimpleLogger::init(LevelFilter::Debug, Config::default());
    });

    let hook_point = HookPoint::new("test_var_complex_missing_dynamic_field");
    hook_point
        .load_process_chain_lib("test_var_complex_lib", 0, PROCESS_CHAIN_LIB_VAR_COMPLEX)
        .await
        .unwrap();

    let data_dir =
        std::env::temp_dir().join("cyfs-process-chain-test-var-complex-missing-dynamic-field");
    std::fs::create_dir_all(&data_dir).unwrap();
    let hook_point_env = HookPointEnv::new("test-var-complex-missing-dynamic-field", data_dir);

    let geo_by_ip = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    geo_by_ip
        .insert(
            "1.2.3.4",
            CollectionValue::Map(
                make_geo_entry_with_meta("CN", "中国电信", "Shenzhen", "CN.SZ", "south-zone").await,
            ),
        )
        .await
        .unwrap();

    let routes = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    routes
        .insert(
            "CN.SZ",
            CollectionValue::Map(make_route_entry("upstreamA").await),
        )
        .await
        .unwrap();

    let req = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    set_client_ip(&req, "1.2.3.4").await;
    set_meta_field(&req, "region_not_exists").await;

    hook_point_env
        .hook_point_env()
        .create("geoByIp", CollectionValue::Map(geo_by_ip))
        .await
        .unwrap();
    hook_point_env
        .hook_point_env()
        .create("routes", CollectionValue::Map(routes))
        .await
        .unwrap();
    hook_point_env
        .hook_point_env()
        .create("REQ", CollectionValue::Map(req.clone()))
        .await
        .unwrap();

    let exec = hook_point_env.link_hook_point(&hook_point).await.unwrap();
    let ret = exec.execute_lib("test_var_complex_lib").await.unwrap();
    assert!(ret.is_control());
    assert_eq!(ret.value(), "region_code_mismatch");
}

#[tokio::test]
async fn test_dynamic_map_lookup_complex_type_mismatch_returns_error() {
    TermLogger::init(
        LevelFilter::Debug,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap_or_else(|_| {
        let _ = SimpleLogger::init(LevelFilter::Debug, Config::default());
    });

    let hook_point = HookPoint::new("test_var_complex_type_mismatch");
    hook_point
        .load_process_chain_lib("test_var_complex_lib", 0, PROCESS_CHAIN_LIB_VAR_COMPLEX)
        .await
        .unwrap();

    let data_dir = std::env::temp_dir().join("cyfs-process-chain-test-var-complex-type-mismatch");
    std::fs::create_dir_all(&data_dir).unwrap();
    let hook_point_env = HookPointEnv::new("test-var-complex-type-mismatch", data_dir);

    let geo_by_ip = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    geo_by_ip
        .insert(
            "1.2.3.4",
            CollectionValue::Map(
                make_geo_entry_with_bad_meta("CN", "中国电信", "Shenzhen", "not-a-map").await,
            ),
        )
        .await
        .unwrap();

    let routes = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    routes
        .insert(
            "CN.SZ",
            CollectionValue::Map(make_route_entry("upstreamA").await),
        )
        .await
        .unwrap();

    let req = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
    set_client_ip(&req, "1.2.3.4").await;
    set_meta_field(&req, "region.code").await;

    hook_point_env
        .hook_point_env()
        .create("geoByIp", CollectionValue::Map(geo_by_ip))
        .await
        .unwrap();
    hook_point_env
        .hook_point_env()
        .create("routes", CollectionValue::Map(routes))
        .await
        .unwrap();
    hook_point_env
        .hook_point_env()
        .create("REQ", CollectionValue::Map(req.clone()))
        .await
        .unwrap();

    let exec = hook_point_env.link_hook_point(&hook_point).await.unwrap();
    let err = exec.execute_lib("test_var_complex_lib").await.unwrap_err();
    assert!(
        err.contains("Expected a map at 'meta'"),
        "unexpected error: {}",
        err
    );
}
