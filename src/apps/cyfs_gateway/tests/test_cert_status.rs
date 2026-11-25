// `get_cert_status` through the control server: what the TLS stack has loaded, merged
// with the ACME state, for uploaded certificates and for hosts still to be issued.
use cyfs_gateway::*;
use cyfs_gateway_lib::*;
use cyfs_identity_cert::{
    CertManager, PreparedCertificate, clear_manual_mark, install_manual_certificates,
};
use name_client::IdentityRoots;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

async fn cert_status(url: &str, token: &str) -> CertStatusReport {
    let result = kRPC::kRPC::new(url, Some(token.to_string()))
        .call("get_cert_status", json!({}))
        .await
        .unwrap();
    serde_json::from_value(result).unwrap()
}

async fn wait_for(
    url: &str,
    token: &str,
    condition: impl Fn(&CertStatusReport) -> bool,
) -> CertStatusReport {
    for _ in 0..200 {
        let report = cert_status(url, token).await;
        if condition(&report) {
            return report;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("unexpected status {:?}", cert_status(url, token).await);
}

#[tokio::test]
async fn cert_status_covers_tls_and_acme_hosts() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_var("BUCKYOS_ROOT", temp.path().to_string_lossy().to_string());
    let roots = IdentityRoots::new(temp.path().join("identity"), temp.path().join("security"));
    let issued = rcgen::generate_simple_self_signed(vec![
        "home.example.com".to_string(),
        "*.home.example.com".to_string(),
    ])
    .unwrap();
    let uploaded = |host: &str| PreparedCertificate {
        host: host.to_string(),
        fullchain_pem: issued.cert.pem().into_bytes(),
        key_pem: issued.signing_key.serialize_pem().into_bytes(),
    };
    install_manual_certificates(&roots, &[uploaded("home.example.com")]).unwrap();

    let control_port = free_port();
    let mut config: Value = serde_yaml_ng::from_str(GATEWAY_CONTROL_SERVER_CONFIG).unwrap();
    config["stacks"]["__control_server__"]["bind"] = json!(format!("127.0.0.1:{control_port}"));
    config["user_name"] = json!("test");
    config["password"] = json!("123456");
    config["identity_manager"] = json!({
        "public_root_path": roots.public_root, "security_root_path": roots.security_root
    });
    config["stacks"]["zone_tls"] = json!({
        "bind": format!("127.0.0.1:{}", free_port()),
        "protocol": "tls",
        "hosts": ["*.home.example.com", "home.example.com"],
        "hook_point": {}
    });
    config["self_cert_report"] = json!({
        "sn": "http://127.0.0.1:1/kapi/sn", "key_path": "missing",
        "device_config_path": "missing", "hosts": ["*.home.example.com", "home.example.com"]
    });

    let parser = Arc::new(GatewayConfigParser::new(Arc::new(
        build_gateway_composition().unwrap(),
    )));
    let parsed = parser.parse(config.clone()).unwrap();
    let gateway = GatewayFactory::new(ConnectionManager::new(), parser.clone())
        .create_gateway(None, parsed.clone(), parsed)
        .await
        .unwrap();
    gateway
        .start(GatewayParams {
            keep_tunnel: vec![],
        })
        .await
        .unwrap();

    let url = format!("http://127.0.0.1:{control_port}");
    let client = GatewayControlClient::new(url.clone(), None);
    assert!(
        kRPC::kRPC::new(&url, None)
            .call("get_cert_status", json!({}))
            .await
            .is_err()
    );
    let token = client.login("test", "123456").await.unwrap();

    let report = cert_status(&url, &token).await;
    assert_eq!(
        report
            .hosts
            .iter()
            .map(|host| (host.host.as_str(), host.loaded, host.manager))
            .collect::<Vec<_>>(),
        vec![
            ("*.home.example.com", false, None),
            ("home.example.com", true, Some(CertManager::Manual)),
        ]
    );
    assert!(report.hosts.iter().all(|host| host.acme.is_none()));
    assert!(
        report.hosts[1]
            .fingerprint
            .as_ref()
            .unwrap()
            .starts_with("sha256:")
    );
    assert!(report.hosts[1].not_after.is_some() && report.hosts[1].issuer.is_some());

    // Automatic issuing through a DNS service whose credential is not there, at an
    // ACME server that is not there either: the gateway reloads all the same.
    config["acme"] = json!({
        "issuer": "http://127.0.0.1:1/directory",
        "dns_providers": { "dns-api": { "credential_path": temp.path().join("missing.json") } },
        "hosts": [
            { "host": "*.home.example.com", "challenge_type": "dns-01", "dns_provider": "dns-api" },
            { "host": "home.example.com", "challenge_type": "dns-01", "dns_provider": "dns-api" },
            { "host": "other.example.com", "challenge_type": "dns-01", "dns_provider": "dns-api" }
        ]
    });
    gateway
        .reload(parser.parse(config.clone()).unwrap())
        .await
        .unwrap();
    let report = wait_for(&url, &token, |report| {
        report.hosts.len() == 3
            && report
                .hosts
                .iter()
                .filter(|host| host.host != "home.example.com")
                .all(|host| host.acme.as_ref().unwrap().last_error.is_some())
    })
    .await;
    let acme = |index: usize| {
        (
            acme_state(&report, index),
            report.hosts[index]
                .acme
                .as_ref()
                .unwrap()
                .next_retry_at
                .is_some(),
        )
    };
    assert_eq!(acme(0), (json!("ordering"), true));
    assert_eq!(acme(1), (json!("manual"), false));
    assert_eq!(report.hosts[2].host, "other.example.com");
    assert_eq!(acme(2), (json!("ordering"), true));
    assert!(!report.hosts[2].loaded);

    // Asking again answers with the state of that host, and only hosts ACME manages can be asked for.
    let restart = async |params: Value| {
        kRPC::kRPC::new(&url, Some(token.clone()))
            .call("restart_cert_order", params)
            .await
    };
    let restarted = restart(json!({ "host": "*.home.example.com" }))
        .await
        .unwrap();
    assert_eq!(restarted["host"], "*.home.example.com");
    assert_eq!(restarted["acme"]["state"], "ordering");
    assert!(
        restart(json!({ "host": "unknown.example.com" }))
            .await
            .is_err()
    );
    assert!(restart(json!({})).await.is_err());
    assert!(
        kRPC::kRPC::new(&url, None)
            .call("restart_cert_order", json!({ "host": "*.home.example.com" }))
            .await
            .is_err()
    );

    // Back to automatic issuing: the uploaded certificate serves until the new one is there.
    clear_manual_mark(&roots, "home.example.com").unwrap();
    gateway
        .reload(parser.parse(config.clone()).unwrap())
        .await
        .unwrap();
    let report = wait_for(&url, &token, |report| {
        report.hosts[1].acme.as_ref().unwrap().last_error.is_some()
    })
    .await;
    assert_eq!(acme_state(&report, 1), json!("renewing"));
    assert!(report.hosts[1].loaded);
    assert_eq!(report.hosts[1].manager, Some(CertManager::Acme));

    // Without the ACME section nothing of it is left in the status.
    config.as_object_mut().unwrap().remove("acme");
    gateway.reload(parser.parse(config).unwrap()).await.unwrap();
    let report = cert_status(&url, &token).await;
    assert_eq!(report.hosts.len(), 2);
    assert!(report.hosts.iter().all(|host| host.acme.is_none()));
}

fn acme_state(report: &CertStatusReport, index: usize) -> Value {
    serde_json::to_value(report.hosts[index].acme.as_ref().unwrap().state).unwrap()
}
