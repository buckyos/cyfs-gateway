use serde_json::Value;
use std::path::Path;

#[test]
fn web3_gateway_uses_one_sn_server_and_a_fixed_loopback_zone_resolver_stack() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../web3-gateway/web3_gateway.yaml");
    let config: Value =
        serde_yaml_ng::from_str(std::fs::read_to_string(path).unwrap().as_str()).unwrap();

    let sn_servers: Vec<_> = config["servers"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(_, server)| server["type"] == "sn")
        .collect();
    assert_eq!(sn_servers.len(), 1);
    assert_eq!(sn_servers[0].0, "web3_sn");

    let stack = &config["stacks"]["sn_zone_resolver_tcp"];
    assert_eq!(stack["protocol"], "tcp");
    assert_eq!(stack["bind"], "127.0.0.1:3180");
    assert_eq!(stack["transparent"], false);
    let dispatch = stack["hook_point"]["main"]["blocks"]["default"]["block"]
        .as_str()
        .unwrap();
    assert!(dispatch.contains("return \"server web3_sn\""));

    let rtcp = &config["stacks"]["main_rtcp"];
    assert_eq!(
        rtcp["inbound_admission"]["named_min_relation"],
        "known_owner"
    );
    assert_eq!(rtcp["inbound_admission"]["anonymous"], "reject");
    for hook in ["hook_point", "on_new_tunnel_hook_point"] {
        let policy = rtcp[hook]["main"]["blocks"]["default"]["block"]
            .as_str()
            .unwrap();
        assert!(policy.contains("trusted_zone_snapshot"));
        assert!(policy.contains("method_authority_current"));
        assert!(!policy.contains("source_identity_trust} \"key_did\""));
        assert!(policy.contains("deviceinfo.resolve_ood_by_did"));
    }
}
