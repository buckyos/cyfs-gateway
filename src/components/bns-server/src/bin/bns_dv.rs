//! `bns-dv` —— DV（开发验证）集成环境的开发用守护/驱动二进制（对应 doc/SN/SN-测试计划.md §5）。
//!
//! 两个子命令：
//!
//! - `serve`：在一份共享 SQLite 投影库上同时跑
//!   * BNS-Indexer：轮询 `sync_once` 把链上事件投影进库；
//!   * BNS-Server：标准合约处理器 HTTP 服务（读查投影 / 写转发 `eth_sendRawTransaction`）。
//!   两者各开一条到同一 SQLite 文件的连接（WAL 并发读写）。
//!
//! - `smoke`：跨全分层冒烟驱动——Controller Client 经 BNS-Server 提交
//!   注册 → 发布(inline) → 轮询等待 indexer 投影 → 经 Server 读命中，打印每步耗时。
//!
//! 这是开发/调试用工具（被 scripts/dv-up.sh / dv-smoke.sh 调用），不是生产服务。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bns_client::{
    BnsEvmClientConfig, BnsEvmControllerClient, BnsIndexerApi, BnsIndexerClient,
    BnsPublishDocumentReq, BnsRegisterNameReq, StaticBnsEvmKeyManager,
};
use bns_indexer::{
    default_document_update, BnsBlockSyncSourceConfig, BnsContractEventIndexer,
    BnsIndexerSyncConfig, CallAuthority, DocumentRef, MutationGuard, NameStatus, Principal,
    RegisterOptions, SqliteBnsRegistryStore,
};
use bns_server::{bind_and_serve, BnsContractHttpServer};
use cyfs_gateway_lib::HttpServer;

type DynError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("bns-dv error: {err}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), DynError> {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_default();
    let flags = parse_flags(args.collect());
    match command.as_str() {
        "serve" => serve(flags).await,
        "smoke" => smoke(flags).await,
        other => Err(format!(
            "unknown subcommand `{other}`; expected `serve` or `smoke`\n\
             usage:\n  \
             bns-dv serve --rpc <url> --contract <addr> --chain-id <n> --db <path> --listen <addr> [--start-block n] [--confirmations n] [--interval-ms n]\n  \
             bns-dv smoke --server <url> --rpc <url> --contract <addr> --chain-id <n> --key <0x..> [--name alice] [--timeout-ms n]"
        )
        .into()),
    }
}

// ===== serve: indexer 轮询 + server HTTP =====

async fn serve(flags: HashMap<String, String>) -> Result<(), DynError> {
    let rpc = require(&flags, "rpc")?;
    let contract = require(&flags, "contract")?;
    let chain_id: u64 = require(&flags, "chain-id")?.parse()?;
    let db = require(&flags, "db")?;
    let listen = require(&flags, "listen")?;
    let start_block: u64 = flags.get("start-block").map_or(Ok(0), |v| v.parse())?;
    let confirmations: u64 = flags.get("confirmations").map_or(Ok(0), |v| v.parse())?;
    let interval_ms: u64 = flags.get("interval-ms").map_or(Ok(1000), |v| v.parse())?;

    let mut source = BnsBlockSyncSourceConfig::anvil(rpc.clone(), contract.clone(), start_block);
    source.chain_id = chain_id;
    let mut sync_config = BnsIndexerSyncConfig::new(source.clone());
    sync_config.confirmations = confirmations;
    sync_config.validate()?;
    let source_id = source.source_id()?;

    // server 与 indexer 各开一条到同一 SQLite 文件的连接（WAL 并发）。
    let server_store = SqliteBnsRegistryStore::open(&db)?;
    let indexer_store = SqliteBnsRegistryStore::open(&db)?;

    // indexer 轮询循环。
    tokio::spawn(async move {
        let indexer = match BnsContractEventIndexer::new(&indexer_store, sync_config.clone()) {
            Ok(indexer) => indexer,
            Err(err) => {
                eprintln!("[indexer] config error: {err}");
                return;
            }
        };
        indexer
            .run_polling_loop(
                Duration::from_millis(interval_ms),
                |outcome| match outcome {
                    Ok(outcome) => {
                        if outcome.registry_events_stored > 0 || outcome.reorg_detected {
                            eprintln!(
                                "[indexer] synced to block {:?}: +{} events (cursor {:?}, reorg={})",
                                outcome.to_block,
                                outcome.registry_events_stored,
                                outcome.cursor.as_ref().map(|c| c.block_number),
                                outcome.reorg_detected,
                            );
                        }
                    }
                    Err(err) => eprintln!("[indexer] sync_once error: {err}"),
                },
            )
            .await;
    });

    let server: Arc<dyn HttpServer> = Arc::new(BnsContractHttpServer::from_contract_store(
        server_store,
        rpc.clone(),
    ));

    eprintln!(
        "[serve] bns-dv ready\n  rpc={rpc}\n  contract={contract}\n  chain_id={chain_id}\n  \
         source={source_id}\n  db={db}\n  listen=http://{listen}  (rpc_path={})",
        server_rpc_path()
    );

    bind_and_serve(listen.as_str(), server).await?;
    Ok(())
}

fn server_rpc_path() -> &'static str {
    bns_client::BNS_SERVER_RPC_PATH
}

// ===== smoke: 跨分层冒烟 =====

async fn smoke(flags: HashMap<String, String>) -> Result<(), DynError> {
    let server_url = require(&flags, "server")?;
    let rpc = require(&flags, "rpc")?;
    let contract = require(&flags, "contract")?;
    let chain_id: u64 = require(&flags, "chain-id")?.parse()?;
    let key = require(&flags, "key")?;
    let name = flags
        .get("name")
        .cloned()
        .unwrap_or_else(|| "alice".to_string());
    let timeout_ms: u64 = flags.get("timeout-ms").map_or(Ok(30_000), |v| v.parse())?;

    let key_manager = Arc::new(StaticBnsEvmKeyManager::new(key.clone())?);
    let signer = format!("{:#x}", key_manager.signer_address());

    let server_api: Arc<dyn BnsIndexerApi> =
        Arc::new(BnsIndexerClient::new_bns_server_url(&server_url, None));
    let controller = BnsEvmControllerClient::new_with_bns_server_submitter(
        BnsEvmClientConfig::anvil(rpc.clone(), contract.clone(), chain_id),
        key_manager,
        server_api.clone(),
    );

    let body = format!(r#"{{"id":"did:bns:{name}","smoke":true}}"#);

    // 1) 注册（经 server tx.submit_raw → eth_sendRawTransaction）。
    let t = Instant::now();
    let registered = controller
        .register_name(&BnsRegisterNameReq {
            name: name.clone(),
            asset_owner: signer.clone(),
            options: RegisterOptions::default(),
            authority_key_updates: vec![],
            semantic_owner_after_authority: None,
            controller_policy: vec![],
            controller_policy_hash: String::new(),
            initial_documents: vec![],
            authority: CallAuthority::public(),
            guard: MutationGuard::default(),
        })
        .await?;
    println!(
        "[1/4] register {name}: tx={} nonce={} ({} ms)",
        registered.tx_hash,
        registered.nonce,
        t.elapsed().as_millis()
    );

    // 2) 发布 owner 文档（inline）。注册后 nameSeq=1。
    let t = Instant::now();
    let published = controller
        .publish_document(&BnsPublishDocumentReq {
            name: name.clone(),
            update: default_document_update("owner", 0, DocumentRef::inline(body.as_bytes()))?,
            authority: CallAuthority::owner(Principal::chain_account(signer.clone()), ""),
            guard: MutationGuard {
                expected_name_seq: 1,
                expected_parent_name_seq: 0,
            },
        })
        .await?;
    println!(
        "[2/4] publish owner doc: tx={} nonce={} ({} ms)",
        published.tx_hash,
        published.nonce,
        t.elapsed().as_millis()
    );

    // 3) 等待 indexer 投影（轮询 server 读）。
    let t = Instant::now();
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        if let Ok(Some(state)) = server_api.query_name_state(&name).await {
            if state.status == NameStatus::Active {
                break;
            }
        }
        if Instant::now() >= deadline {
            return Err(format!("timed out waiting for indexer to project `{name}`").into());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    println!(
        "[3/4] indexer projected {name} ({} ms)",
        t.elapsed().as_millis()
    );

    // 4) 经 server 读命中：resolveDocument 内容/版本一致。
    let t = Instant::now();
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let resolved = loop {
        if let Ok(result) = server_api.resolve_document(&name, "owner").await {
            if result.document_state.version >= 1 {
                break result;
            }
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for owner document projection".into());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    let projected_body = String::from_utf8_lossy(&resolved.document_state.document.inline_document);
    if projected_body != body {
        return Err(format!(
            "projected document mismatch: expected `{body}`, got `{projected_body}`"
        )
        .into());
    }
    println!(
        "[4/4] read owner doc v{} via server: {} ({} ms)",
        resolved.document_state.version,
        projected_body,
        t.elapsed().as_millis()
    );

    println!("SMOKE OK: full BNS<->Indexer<->Server<->Client<->Controller path verified");
    Ok(())
}

// ===== 简易 --flag value 解析 =====

fn parse_flags(args: Vec<String>) -> HashMap<String, String> {
    let mut flags = HashMap::new();
    let mut iter = args.into_iter().peekable();
    while let Some(arg) = iter.next() {
        if let Some(name) = arg.strip_prefix("--") {
            if let Some((k, v)) = name.split_once('=') {
                flags.insert(k.to_string(), v.to_string());
            } else {
                let value = iter.next().unwrap_or_default();
                flags.insert(name.to_string(), value);
            }
        }
    }
    flags
}

fn require(flags: &HashMap<String, String>, key: &str) -> Result<String, DynError> {
    flags
        .get(key)
        .cloned()
        .ok_or_else(|| format!("missing required flag --{key}").into())
}
