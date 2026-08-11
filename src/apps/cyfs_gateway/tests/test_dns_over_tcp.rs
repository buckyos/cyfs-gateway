use cyfs_gateway::{gateway_service_main, GatewayParams};
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

fn dns_query(id: u16, name: &str, query_type: u16) -> Vec<u8> {
    let mut query = Vec::new();
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&[0x01, 0x00]);
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    for label in name.trim_end_matches('.').split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&query_type.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query
}

fn response_code(response: &[u8]) -> u8 {
    response[3] & 0x0f
}

fn answer_count(response: &[u8]) -> u16 {
    u16::from_be_bytes([response[6], response[7]])
}

async fn read_tcp_response(stream: &mut TcpStream) -> Vec<u8> {
    let mut length = [0u8; 2];
    stream.read_exact(&mut length).await.unwrap();
    let mut response = vec![0u8; u16::from_be_bytes(length) as usize];
    stream.read_exact(&mut response).await.unwrap();
    response
}

async fn send_tcp_query(stream: &mut TcpStream, query: &[u8]) -> Vec<u8> {
    stream
        .write_all(&(query.len() as u16).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(query).await.unwrap();
    read_tcp_response(stream).await
}

async fn send_udp_query(socket: &UdpSocket, server: SocketAddr, query: &[u8]) -> Vec<u8> {
    socket.send_to(query, server).await.unwrap();
    let mut response = vec![0u8; u16::MAX as usize];
    let (len, _) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut response))
        .await
        .unwrap()
        .unwrap();
    response.truncate(len);
    response
}

async fn wait_for_tcp_listener(addr: SocketAddr) -> TcpStream {
    for _ in 0..100 {
        if let Ok(stream) = TcpStream::connect(addr).await {
            return stream;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("DNS-over-TCP listener did not start at {addr}");
}

fn write_test_config(config_path: &Path, dns_path: &Path, port: u16) {
    let config = format!(
        r#"
stacks:
  dns_udp:
    protocol: udp
    bind: 127.0.0.1:{port}
    hook_point:
      main:
        blocks:
          default:
            block: |
              return "server main_dns";

  dns_tcp:
    protocol: tcp
    bind: 127.0.0.1:{port}
    hook_point:
      main:
        blocks:
          default:
            block: |
              return "server main_dns";

servers:
  main_dns:
    type: dns
    hook_point:
      main:
        blocks:
          default:
            block: |
              eq ${{REQ.name}} "servfail.test." && return "invalid";
              resolve ${{REQ.name}} ${{REQ.record_type}} local_dns && return;

  local_dns:
    type: local_dns
    file_path: {}
"#,
        dns_path.display()
    );
    std::fs::write(config_path, config).unwrap();
}

#[tokio::test]
async fn dns_server_routes_udp_and_tcp_through_the_same_yaml_server() {
    let root = tempfile::TempDir::new().unwrap();
    unsafe {
        std::env::set_var("BUCKYOS_ROOT", root.path());
    }

    let port = loop {
        let tcp_probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let candidate = tcp_probe.local_addr().unwrap().port();
        if let Ok(udp_probe) = UdpSocket::bind(("127.0.0.1", candidate)).await {
            drop(udp_probe);
            drop(tcp_probe);
            break candidate;
        }
    };
    let server_addr = SocketAddr::from(([127, 0, 0, 1], port));

    let large_txt = (0..12)
        .map(|index| format!("\"{:02}{}\"", index, "x".repeat(198)))
        .collect::<Vec<_>>()
        .join(",\n");
    let dns_file = root.path().join("local_dns.toml");
    std::fs::write(
        &dns_file,
        format!(
            r#"
["www.test"]
ttl = 300
address = ["192.0.2.1"]
txt = ["first", "second"]

["v6.test"]
ttl = 300
address = ["2001:db8::1"]

["large.test"]
ttl = 300
txt = [
{large_txt}
]
"#
        ),
    )
    .unwrap();

    let config_file = root.path().join("gateway.yaml");
    write_test_config(&config_file, &dns_file, port);
    let gateway_task = tokio::spawn(async move {
        gateway_service_main(
            &config_file,
            GatewayParams {
                keep_tunnel: vec![],
            },
        )
        .await
    });

    let mut tcp = wait_for_tcp_listener(server_addr).await;
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // A, AAAA, TXT, NXDOMAIN, NODATA, and SERVFAIL have equivalent DNS
    // results over both transports.
    for (id, name, query_type, expected_rcode, expect_answers) in [
        (0x1001, "www.test.", 1, 0, true),
        (0x1002, "v6.test.", 28, 0, true),
        (0x1003, "www.test.", 16, 0, true),
        (0x1004, "missing.test.", 1, 3, false),
        (0x1005, "www.test.", 28, 0, false),
        (0x1006, "servfail.test.", 1, 2, false),
    ] {
        let query = dns_query(id, name, query_type);
        let udp_response = send_udp_query(&udp, server_addr, &query).await;
        let tcp_response = send_tcp_query(&mut tcp, &query).await;
        assert_eq!(response_code(&udp_response), expected_rcode, "UDP {name}");
        assert_eq!(response_code(&tcp_response), expected_rcode, "TCP {name}");
        assert_eq!(
            answer_count(&udp_response) > 0,
            expect_answers,
            "UDP {name}"
        );
        assert_eq!(
            answer_count(&tcp_response) > 0,
            expect_answers,
            "TCP {name}"
        );
    }

    // The connection remains reusable, and read_exact handles a frame whose
    // length and payload arrive across multiple TCP reads.
    let fragmented = dns_query(0x2001, "www.test.", 1);
    let fragmented_len = (fragmented.len() as u16).to_be_bytes();
    tcp.write_all(&fragmented_len[..1]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    tcp.write_all(&fragmented_len[1..]).await.unwrap();
    for chunk in fragmented.chunks(3) {
        tcp.write_all(chunk).await.unwrap();
        tokio::task::yield_now().await;
    }
    let fragmented_response = read_tcp_response(&mut tcp).await;
    assert_eq!(&fragmented_response[..2], &0x2001u16.to_be_bytes());

    let sequential = dns_query(0x2002, "www.test.", 16);
    let sequential_response = send_tcp_query(&mut tcp, &sequential).await;
    assert_eq!(&sequential_response[..2], &0x2002u16.to_be_bytes());

    // A classic UDP query advertises a 512-byte response limit. The same
    // large answer is complete over TCP and does not carry the TC bit.
    let large_query = dns_query(0x3001, "large.test.", 16);
    let udp_response = send_udp_query(&udp, server_addr, &large_query).await;
    assert_eq!(udp_response[2] & 0x02, 0x02);
    let tcp_response = send_tcp_query(&mut tcp, &large_query).await;
    assert_eq!(tcp_response[2] & 0x02, 0);
    assert!(tcp_response.len() > udp_response.len());

    // A client half-close after complete requests is a clean connection end.
    tcp.shutdown().await.unwrap();
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(2), tcp.read(&mut byte))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read, 0);

    // A zero-length frame is rejected by closing the connection.
    let mut malformed = TcpStream::connect(server_addr).await.unwrap();
    malformed.write_all(&[0, 0]).await.unwrap();
    let read = tokio::time::timeout(Duration::from_secs(2), malformed.read(&mut byte))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read, 0);

    // An incomplete frame followed by a write half-close is rejected without
    // spinning or treating the partial bytes as a DNS message.
    let mut incomplete = TcpStream::connect(server_addr).await.unwrap();
    incomplete.write_all(&10u16.to_be_bytes()).await.unwrap();
    incomplete.write_all(&[1, 2, 3]).await.unwrap();
    incomplete.shutdown().await.unwrap();
    let read = tokio::time::timeout(Duration::from_secs(2), incomplete.read(&mut byte))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read, 0);

    gateway_task.abort();
}
