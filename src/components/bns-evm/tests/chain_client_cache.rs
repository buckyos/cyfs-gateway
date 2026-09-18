use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bns_evm::{BnsChainClient, TransactionLookup, B256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const TX_HASH: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct MockRpc {
    endpoint: String,
    receipt_calls: Arc<AtomicUsize>,
    transaction_calls: Arc<AtomicUsize>,
    gas_price_calls: Arc<AtomicUsize>,
    priority_fee_calls: Arc<AtomicUsize>,
}

impl MockRpc {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let receipt_calls = Arc::new(AtomicUsize::new(0));
        let transaction_calls = Arc::new(AtomicUsize::new(0));
        let gas_price_calls = Arc::new(AtomicUsize::new(0));
        let priority_fee_calls = Arc::new(AtomicUsize::new(0));
        let receipt_counter = receipt_calls.clone();
        let transaction_counter = transaction_calls.clone();
        let gas_price_counter = gas_price_calls.clone();
        let priority_fee_counter = priority_fee_calls.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let receipt_counter = receipt_counter.clone();
                let transaction_counter = transaction_counter.clone();
                let gas_price_counter = gas_price_counter.clone();
                let priority_fee_counter = priority_fee_counter.clone();
                tokio::spawn(async move {
                    let request = read_http_request(&mut stream).await;
                    let body = request
                        .split_once("\r\n\r\n")
                        .map(|(_, body)| body)
                        .unwrap_or_default();
                    let request: serde_json::Value = serde_json::from_str(body).unwrap();
                    let method = request["method"].as_str().unwrap_or_default();
                    let result = match method {
                        "eth_getTransactionReceipt" => {
                            receipt_counter.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(25)).await;
                            serde_json::json!({
                                "transactionHash": TX_HASH,
                                "blockNumber": "0x8",
                                "status": "0x1"
                            })
                        }
                        "eth_getTransactionByHash" => {
                            transaction_counter.fetch_add(1, Ordering::SeqCst);
                            serde_json::Value::Null
                        }
                        "eth_gasPrice" => {
                            gas_price_counter.fetch_add(1, Ordering::SeqCst);
                            serde_json::Value::String("0x64".to_string())
                        }
                        "eth_maxPriorityFeePerGas" => {
                            priority_fee_counter.fetch_add(1, Ordering::SeqCst);
                            serde_json::Value::String("0x2".to_string())
                        }
                        _ => serde_json::Value::Null,
                    };
                    let response_body = serde_json::to_string(&serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": request["id"],
                        "result": result,
                    }))
                    .unwrap();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                        response_body.len(),
                        response_body
                    );
                    stream.write_all(response.as_bytes()).await.unwrap();
                });
            }
        });
        Self {
            endpoint,
            receipt_calls,
            transaction_calls,
            gas_price_calls,
            priority_fee_calls,
        }
    }
}

#[tokio::test]
async fn fee_suggestion_is_cached_within_one_head() {
    let mock = MockRpc::start().await;
    let client = BnsChainClient::new(&mock.endpoint);

    let first = client.suggest_eip1559_fees().await.unwrap();
    let second = client.suggest_eip1559_fees().await.unwrap();

    assert_eq!(first, second);
    assert_eq!(first.max_fee_per_gas, 202);
    assert_eq!(first.max_priority_fee_per_gas, 2);
    assert_eq!(mock.gas_price_calls.load(Ordering::SeqCst), 1);
    assert_eq!(mock.priority_fee_calls.load(Ordering::SeqCst), 1);
}

async fn read_http_request(stream: &mut TcpStream) -> String {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        let size = stream.read(&mut chunk).await.unwrap();
        if size == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..size]);
        let Some(header_end) = buffer.windows(4).position(|part| part == b"\r\n\r\n") else {
            continue;
        };
        let headers = String::from_utf8_lossy(&buffer[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
            })
            .unwrap_or(0);
        if buffer.len() >= header_end + 4 + content_length {
            break;
        }
    }
    String::from_utf8(buffer).unwrap()
}

#[tokio::test]
async fn concurrent_transaction_queries_share_and_cache_receipt() {
    let mock = MockRpc::start().await;
    let client = Arc::new(BnsChainClient::new(&mock.endpoint));
    let tx_hash: B256 = TX_HASH.parse().unwrap();

    let mut tasks = Vec::new();
    for _ in 0..100 {
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            match client.transaction_lookup(tx_hash).await.unwrap() {
                TransactionLookup::Mined(receipt) => assert_eq!(receipt.block_number, Some(8)),
                TransactionLookup::Pending | TransactionLookup::NotFound => {
                    panic!("expected mined receipt")
                }
            }
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }

    assert_eq!(mock.receipt_calls.load(Ordering::SeqCst), 1);
    assert_eq!(mock.transaction_calls.load(Ordering::SeqCst), 0);
    client.transaction_lookup(tx_hash).await.unwrap();
    assert_eq!(mock.receipt_calls.load(Ordering::SeqCst), 1);

    client.invalidate_mined_receipts_from(8);
    client.transaction_lookup(tx_hash).await.unwrap();
    assert_eq!(mock.receipt_calls.load(Ordering::SeqCst), 2);
}
