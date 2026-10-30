// 顶层 `name_client.zone_locker_bypass`：启动时在任何 stack 接收流量之前设给全局 name
// client，reload 时替换；坏条目让 reload 失败且不改动现有名单。全局 OnceCell 只能初始化
// 一次，所以放在独立的集成测试二进制里按顺序验证。
use cyfs_gateway::*;
use cyfs_gateway_lib::*;
use name_lib::DID;
use serde_json::{json, Value};
use std::sync::Arc;

fn bypassed(did: &str) -> bool {
    name_client::get_name_client()
        .unwrap()
        .is_zone_locker_bypassed(&DID::from_str(did).unwrap())
}

fn with_bypass(base: &Value, entries: Value) -> Value {
    let mut config = base.clone();
    config["name_client"] = json!({ "zone_locker_bypass": entries });
    config
}

#[tokio::test]
async fn zone_locker_bypass_is_applied_on_start_and_reload() {
    let temp_dir = tempfile::tempdir().unwrap();
    std::env::set_var(
        "BUCKYOS_ROOT",
        temp_dir.path().to_string_lossy().to_string(),
    );
    let control_port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let mut base: Value = serde_yaml_ng::from_str(GATEWAY_CONTROL_SERVER_CONFIG).unwrap();
    base["stacks"]["__control_server__"]["bind"] = json!(format!("127.0.0.1:{control_port}"));

    let parser = Arc::new(GatewayConfigParser::new(Arc::new(
        build_gateway_composition().unwrap(),
    )));
    // 未知字段按配置错误拒绝。
    let mut unknown = base.clone();
    unknown["name_client"] = json!({ "zone_locker_bypas": [] });
    assert!(parser.parse(unknown).is_err());
    // 不写该节：名单为空。
    assert!(parser
        .parse(base.clone())
        .unwrap()
        .name_client
        .zone_locker_bypass
        .is_empty());

    let config = parser
        .parse(with_bypass(
            &base,
            json!(["ood1.example.com", "did:bns:ood2.alice"]),
        ))
        .unwrap();
    let gateway = GatewayFactory::new(ConnectionManager::new(), parser.clone())
        .create_gateway(None, config.clone(), config)
        .await
        .unwrap();
    gateway
        .start(GatewayParams {
            keep_tunnel: vec![],
        })
        .await
        .unwrap();
    // 主机名按 RTCP 的同一规则（DID::from_str）转成 DID。
    assert!(bypassed("did:web:ood1.example.com"));
    assert!(bypassed("did:bns:ood2.alice"));

    let reloaded = parser
        .parse(with_bypass(&base, json!(["sn.example.net"])))
        .unwrap();
    gateway.reload(reloaded).await.unwrap();
    assert!(bypassed("did:web:sn.example.net"));
    assert!(!bypassed("did:web:ood1.example.com"));

    // 坏条目：reload 失败，现有名单不变。
    let broken = parser.parse(with_bypass(&base, json!([""]))).unwrap();
    assert!(gateway.reload(broken).await.is_err());
    assert!(bypassed("did:web:sn.example.net"));
}
