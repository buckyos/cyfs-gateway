use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bns_evm::{
    decode_bns_call, decode_contract_return, Address, AliasKind as EvmAliasKind,
    AliasState as EvmAliasState, AuthorityKey as EvmAuthorityKey,
    AuthorityKeyStatus as EvmAuthorityKeyStatus, AuthorityKeyUpdate as EvmAuthorityKeyUpdate,
    AuthoritySetState as EvmAuthoritySetState, BlockRange, Bns, BnsCall, BnsChainClient,
    ContractRead, DocumentRef as EvmDocumentRef, DocumentState as EvmDocumentState,
    DocumentStatus as EvmDocumentStatus, EthBlock, NameState as EvmNameState,
    NameStatus as EvmNameStatus, OwnerSource as EvmOwnerSource, Principal as EvmPrincipal,
    PrincipalKind as EvmPrincipalKind, RpcLogFilter, B256,
};
use serde::{Deserialize, Serialize};

use crate::{
    canonical_bns_name, canonical_doc_type, now_timestamp, AliasKind, AliasState, AuthorityKey,
    AuthorityKeyStatus, AuthoritySetState, BnsRegistryError, BnsRegistryResult, BnsRegistryStore,
    BnsRegistryStoreTx, ContractEventProjector, DocumentRef, DocumentState, DocumentStatus,
    EventLogRecord, IndexerCursor, LogCheckpoint, NameState, NameStatus, OwnerSource, Principal,
    ProjectedContractEvent, RegistryEvent, ZERO_HASH,
};

const CHAIN_ERROR_RETRY_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BnsBlockSyncSourceConfig {
    pub network: String,
    pub chain_id: u64,
    pub rpc_endpoint: String,
    pub contract_address: String,
    pub start_block: u64,
}

impl BnsBlockSyncSourceConfig {
    pub fn anvil(
        rpc_endpoint: impl Into<String>,
        contract_address: impl Into<String>,
        start_block: u64,
    ) -> Self {
        Self {
            network: "anvil-local".to_string(),
            chain_id: 31_337,
            rpc_endpoint: rpc_endpoint.into(),
            contract_address: contract_address.into(),
            start_block,
        }
    }

    pub fn source_id(&self) -> BnsRegistryResult<String> {
        let contract = self.contract_address()?;
        self.validate()?;
        Ok(format!(
            "evm:{}:{}:{contract:#x}",
            self.network, self.chain_id
        ))
    }

    pub fn contract_address(&self) -> BnsRegistryResult<Address> {
        Address::from_str(&self.contract_address).map_err(|err| {
            BnsRegistryError::InvalidConfig(format!(
                "invalid BNS contract_address `{}`: {err}",
                self.contract_address
            ))
        })
    }

    pub fn validate(&self) -> BnsRegistryResult<()> {
        if self.network.trim().is_empty() {
            return Err(BnsRegistryError::InvalidConfig(
                "BNS block sync source network must not be empty".to_string(),
            ));
        }
        if self.rpc_endpoint.trim().is_empty() {
            return Err(BnsRegistryError::InvalidConfig(
                "BNS block sync source rpc_endpoint must not be empty".to_string(),
            ));
        }
        if self.chain_id == 0 {
            return Err(BnsRegistryError::InvalidConfig(
                "BNS block sync source chain_id must be non-zero".to_string(),
            ));
        }
        self.contract_address()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BnsIndexerSyncConfig {
    pub source: BnsBlockSyncSourceConfig,
    pub confirmations: u64,
    pub max_block_span: u64,
}

impl BnsIndexerSyncConfig {
    pub fn new(source: BnsBlockSyncSourceConfig) -> Self {
        Self {
            source,
            confirmations: 0,
            max_block_span: 500,
        }
    }

    pub fn validate(&self) -> BnsRegistryResult<()> {
        self.source.validate()?;
        if self.max_block_span == 0 {
            return Err(BnsRegistryError::InvalidConfig(
                "BNS indexer max_block_span must be non-zero".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BnsIndexerSyncOutcome {
    pub source: String,
    pub chain_id: u64,
    pub contract_address: String,
    pub latest_block: u64,
    pub from_block: u64,
    pub to_block: Option<u64>,
    pub reorg_detected: bool,
    pub logs_seen: usize,
    pub protocol_events_seen: usize,
    pub registry_events_stored: usize,
    pub cursor: Option<IndexerCursor>,
}

pub struct BnsContractEventIndexer<'a, S>
where
    S: BnsRegistryStore,
{
    store: &'a S,
    config: BnsIndexerSyncConfig,
    chain_client: Arc<BnsChainClient>,
    contract: Address,
    source: String,
}

impl<'a, S> BnsContractEventIndexer<'a, S>
where
    S: BnsRegistryStore,
{
    pub fn new(store: &'a S, config: BnsIndexerSyncConfig) -> BnsRegistryResult<Self> {
        let chain_client = Arc::new(BnsChainClient::new(config.source.rpc_endpoint.clone()));
        Self::new_with_chain_client(store, config, chain_client)
    }

    pub fn new_with_chain_client(
        store: &'a S,
        config: BnsIndexerSyncConfig,
        chain_client: Arc<BnsChainClient>,
    ) -> BnsRegistryResult<Self> {
        config.validate()?;
        let contract = config.source.contract_address()?;
        if let Some(configured_contract) = chain_client.contract_address() {
            if configured_contract != contract {
                return Err(BnsRegistryError::InvalidConfig(format!(
                    "BNS chain client contract {configured_contract:#x} does not match indexer contract {contract:#x}"
                )));
            }
        }
        if let Some(configured_chain_id) = chain_client.configured_chain_id() {
            if configured_chain_id != config.source.chain_id {
                return Err(BnsRegistryError::InvalidConfig(format!(
                    "BNS chain client chain_id {configured_chain_id} does not match indexer chain_id {}",
                    config.source.chain_id
                )));
            }
        }
        let source = config.source.source_id()?;
        Ok(Self {
            store,
            config,
            chain_client,
            contract,
            source,
        })
    }

    pub fn config(&self) -> &BnsIndexerSyncConfig {
        &self.config
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub async fn sync_once(&self) -> BnsRegistryResult<BnsIndexerSyncOutcome> {
        self.sync_once_with_head_refresh(true).await
    }

    async fn sync_once_with_head_refresh(
        &self,
        refresh_head: bool,
    ) -> BnsRegistryResult<BnsIndexerSyncOutcome> {
        let remote_chain_id = self.chain_client.chain_id().await?;
        if remote_chain_id != self.config.source.chain_id {
            return Err(BnsRegistryError::InvalidConfig(format!(
                "BNS indexer configured for chain_id {}, but RPC {} returned chain_id {}",
                self.config.source.chain_id, self.config.source.rpc_endpoint, remote_chain_id
            )));
        }

        let (latest_head, head_changed) = self.chain_client.latest_block(refresh_head).await?;
        let latest_block = latest_head.number.ok_or_else(|| {
            BnsRegistryError::InvalidConfig(format!(
                "BNS indexer latest block from RPC {} has no number",
                self.config.source.rpc_endpoint
            ))
        })?;
        let reorg_detected = if head_changed {
            self.reset_projection_if_reorged(&latest_head).await?
        } else {
            false
        };
        let target_block = latest_block.saturating_sub(self.config.confirmations);
        let from_block = self.next_block_to_sync()?;
        if from_block > target_block {
            return Ok(BnsIndexerSyncOutcome {
                source: self.source.clone(),
                chain_id: self.config.source.chain_id,
                contract_address: format!("{:#x}", self.contract),
                latest_block,
                from_block,
                to_block: None,
                reorg_detected,
                logs_seen: 0,
                protocol_events_seen: 0,
                registry_events_stored: 0,
                cursor: self.cursor()?,
            });
        }

        let to_block = target_block.min(from_block + self.config.max_block_span - 1);
        let filter = RpcLogFilter {
            address: self.contract,
            from_block: BlockRange::Number(from_block),
            to_block: BlockRange::Number(to_block),
            topics: Vec::new(),
        };
        let logs = self.chain_client.get_logs(&filter).await?;
        let mut projector = ContractEventProjector::new();
        let mut protocol_events_seen = 0;
        let mut registry_records = Vec::new();

        for log in logs.iter().filter(|log| !log.removed) {
            let observed_at = now_timestamp();
            match projector.project_log(log, observed_at)? {
                ProjectedContractEvent::Protocol(_) => {
                    protocol_events_seen += 1;
                }
                ProjectedContractEvent::Registry(record) => {
                    registry_records.push((record, log.transaction_hash));
                }
                ProjectedContractEvent::Router | ProjectedContractEvent::Infrastructure => {}
            }
        }

        let mut decoded_txs: HashMap<B256, Option<BnsCall>> = HashMap::new();
        let mut projection_records = Vec::with_capacity(registry_records.len());
        for (record, transaction_hash) in registry_records {
            let decoded_call = if record_needs_decoded_call(&record) {
                self.decoded_call_for_hash(transaction_hash, &mut decoded_txs)
                    .await?
            } else {
                None
            };
            projection_records.push((record, decoded_call));
        }

        let snapshot = self
            .load_projection_snapshot(&projection_records, to_block)
            .await?;
        let mut registry_events_stored = 0;
        for (record, decoded_call) in projection_records {
            let projection =
                self.projection_for_record(&record, decoded_call.as_ref(), &snapshot)?;
            self.store.transact(|tx| {
                tx.put_event_record(&record)?;
                projection.apply(tx)
            })?;
            registry_events_stored += 1;
        }

        let block_hash = self.block_hash_string(to_block, Some(&latest_head)).await?;
        let cursor = IndexerCursor {
            source: self.source.clone(),
            block_number: to_block,
            block_hash: Some(block_hash),
            log_index: i64::MAX as u64,
            updated_at: now_timestamp(),
        };
        self.store.transact(|tx| tx.put_indexer_cursor(&cursor))?;

        Ok(BnsIndexerSyncOutcome {
            source: self.source.clone(),
            chain_id: self.config.source.chain_id,
            contract_address: format!("{:#x}", self.contract),
            latest_block,
            from_block,
            to_block: Some(to_block),
            reorg_detected,
            logs_seen: logs.len(),
            protocol_events_seen,
            registry_events_stored,
            cursor: Some(cursor),
        })
    }

    pub async fn run_polling_loop<F>(&self, interval: Duration, mut on_sync: F)
    where
        F: FnMut(BnsRegistryResult<BnsIndexerSyncOutcome>),
    {
        let interval = if interval.is_zero() {
            Duration::from_millis(1)
        } else {
            interval
        };
        let mut refresh_head = true;
        loop {
            let outcome = self.sync_once_with_head_refresh(refresh_head).await;
            let has_backlog = outcome.as_ref().is_ok_and(|outcome| {
                outcome.to_block.is_some_and(|to_block| {
                    to_block
                        < outcome
                            .latest_block
                            .saturating_sub(self.config.confirmations)
                })
            });
            let delay = polling_delay(interval, outcome.is_err(), has_backlog);
            on_sync(outcome);
            refresh_head = !has_backlog;
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
        }
    }

    fn next_block_to_sync(&self) -> BnsRegistryResult<u64> {
        let cursor = self.cursor()?;
        Ok(cursor
            .map(|cursor| cursor.block_number.saturating_add(1))
            .unwrap_or(self.config.source.start_block)
            .max(self.config.source.start_block))
    }

    fn cursor(&self) -> BnsRegistryResult<Option<IndexerCursor>> {
        self.store
            .transact(|tx| tx.get_indexer_cursor(&self.source))
    }

    async fn reset_projection_if_reorged(&self, latest_head: &EthBlock) -> BnsRegistryResult<bool> {
        let Some(mut cursor) = self.cursor()? else {
            return Ok(false);
        };
        let latest_block = latest_head.number.ok_or_else(|| {
            BnsRegistryError::InvalidConfig("BNS latest block has no number".to_string())
        })?;

        let should_reset = if cursor.block_number > latest_block {
            true
        } else if let Some(expected_hash) = cursor.block_hash.as_deref() {
            self.block_hash_string(cursor.block_number, Some(latest_head))
                .await?
                != expected_hash
        } else {
            cursor.block_hash = Some(
                self.block_hash_string(cursor.block_number, Some(latest_head))
                    .await?,
            );
            cursor.updated_at = now_timestamp();
            self.store.transact(|tx| tx.put_indexer_cursor(&cursor))?;
            false
        };

        if should_reset {
            self.chain_client.invalidate_mined_receipts_from(0);
            self.store
                .transact(|tx| tx.reset_indexer_projection(&self.source))?;
        }
        Ok(should_reset)
    }

    async fn block_hash_string(
        &self,
        block_number: u64,
        latest_head: Option<&EthBlock>,
    ) -> BnsRegistryResult<String> {
        let block = if latest_head.is_some_and(|head| head.number == Some(block_number)) {
            latest_head.cloned().unwrap()
        } else {
            self.chain_client
                .block_by_number(block_number)
                .await?
                .ok_or_else(|| {
                    BnsRegistryError::InvalidConfig(format!(
                        "BNS indexer cannot read block {block_number} from RPC {}",
                        self.config.source.rpc_endpoint
                    ))
                })?
        };
        if let Some(actual_number) = block.number {
            if actual_number != block_number {
                return Err(BnsRegistryError::InvalidConfig(format!(
                    "BNS indexer requested block {block_number}, RPC returned block {actual_number}"
                )));
            }
        }
        block.hash.map(hash_string).ok_or_else(|| {
            BnsRegistryError::InvalidConfig(format!(
                "BNS indexer block {block_number} from RPC {} has no hash",
                self.config.source.rpc_endpoint
            ))
        })
    }

    async fn decoded_call_for_hash(
        &self,
        tx_hash: Option<B256>,
        decoded_txs: &mut HashMap<B256, Option<BnsCall>>,
    ) -> BnsRegistryResult<Option<BnsCall>> {
        let Some(tx_hash) = tx_hash else {
            return Ok(None);
        };
        if let Some(decoded) = decoded_txs.get(&tx_hash) {
            return Ok(decoded.clone());
        }

        let decoded = match self.chain_client.transaction_by_hash(tx_hash).await? {
            Some(tx) => Some(decode_bns_call(&tx.input)?),
            None => None,
        };
        decoded_txs.insert(tx_hash, decoded.clone());
        Ok(decoded)
    }

    async fn load_projection_snapshot(
        &self,
        records: &[(EventLogRecord, Option<BnsCall>)],
        to_block: u64,
    ) -> BnsRegistryResult<ProjectionSnapshot> {
        let mut seen = HashSet::new();
        let mut reads = Vec::new();
        for (record, decoded_call) in records {
            for read in projection_reads_for_record(record, decoded_call.as_ref()) {
                if seen.insert(read.clone()) {
                    reads.push(read);
                }
            }
        }
        let calls = reads
            .iter()
            .map(|read| read.contract_read(self.contract))
            .collect::<Vec<_>>();
        let outputs = self
            .chain_client
            .multicall_at(&calls, BlockRange::Number(to_block))
            .await?;
        if outputs.len() != reads.len() {
            return Err(BnsRegistryError::InvalidConfig(format!(
                "BNS projection batch returned {} values for {} reads",
                outputs.len(),
                reads.len()
            )));
        }
        let mut snapshot = ProjectionSnapshot::default();
        for (read, output) in reads.into_iter().zip(outputs) {
            snapshot.insert(read, &output)?;
        }
        Ok(snapshot)
    }

    fn projection_for_record(
        &self,
        record: &EventLogRecord,
        decoded_call: Option<&BnsCall>,
        snapshot: &ProjectionSnapshot,
    ) -> BnsRegistryResult<ContractProjectionWrite> {
        snapshot.projection_for_record(record, decoded_call)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ProjectionReadKey {
    Name(String),
    Document(String, String, u64),
    AuthoritySet(String),
    Alias(String),
    LatestCheckpoint,
}

impl ProjectionReadKey {
    fn contract_read(&self, contract: Address) -> ContractRead {
        match self {
            Self::Name(name) => {
                ContractRead::new(contract, &Bns::queryNameStateCall { name: name.clone() })
            }
            Self::Document(name, doc_type, version) => ContractRead::new(
                contract,
                &Bns::getDocumentVersionCall {
                    name: name.clone(),
                    docType: doc_type.clone(),
                    version: *version,
                },
            ),
            Self::AuthoritySet(name) => {
                ContractRead::new(contract, &Bns::getAuthoritySetCall { name: name.clone() })
            }
            Self::Alias(name) => {
                ContractRead::new(contract, &Bns::getAliasCall { name: name.clone() })
            }
            Self::LatestCheckpoint => ContractRead::new(contract, &Bns::latestCheckpointCall {}),
        }
    }
}

#[derive(Default)]
struct ProjectionSnapshot {
    names: HashMap<String, Option<NameState>>,
    documents: HashMap<(String, String, u64), Option<DocumentState>>,
    authority_sets: HashMap<String, AuthoritySetState>,
    aliases: HashMap<String, AliasState>,
    checkpoint: Option<LogCheckpoint>,
}

impl ProjectionSnapshot {
    fn insert(&mut self, read: ProjectionReadKey, output: &[u8]) -> BnsRegistryResult<()> {
        match read {
            ProjectionReadKey::Name(name) => {
                let state = name_state_from_evm(
                    decode_contract_return::<Bns::queryNameStateCall>(output)?,
                )?;
                self.names.insert(
                    name,
                    (state.status != NameStatus::Available).then_some(state),
                );
            }
            ProjectionReadKey::Document(name, doc_type, version) => {
                let state = document_state_from_evm(decode_contract_return::<
                    Bns::getDocumentVersionCall,
                >(output)?)?;
                self.documents.insert(
                    (name, doc_type, version),
                    (state.status != DocumentStatus::Missing).then_some(state),
                );
            }
            ProjectionReadKey::AuthoritySet(name) => {
                let state = authority_set_from_evm(decode_contract_return::<
                    Bns::getAuthoritySetCall,
                >(output)?)?;
                self.authority_sets.insert(name, state);
            }
            ProjectionReadKey::Alias(name) => {
                let state =
                    alias_state_from_evm(decode_contract_return::<Bns::getAliasCall>(output)?)?;
                self.aliases.insert(name, state);
            }
            ProjectionReadKey::LatestCheckpoint => {
                self.checkpoint = Some(checkpoint_from_evm(decode_contract_return::<
                    Bns::latestCheckpointCall,
                >(output)?)?);
            }
        }
        Ok(())
    }

    fn projection_for_record(
        &self,
        record: &EventLogRecord,
        decoded_call: Option<&BnsCall>,
    ) -> BnsRegistryResult<ContractProjectionWrite> {
        let mut write = ContractProjectionWrite::default();
        match &record.event {
            RegistryEvent::NameRegistered { name, .. } => {
                let name = canonical_bns_name(name)?;
                write.lineage_resets.push(name.clone());
                self.push_name(&mut write, &name)?;
            }
            RegistryEvent::NameRenewed { name, .. }
            | RegistryEvent::NameAssetTransferred { name, .. }
            | RegistryEvent::NameOwnerUpdated { name, .. }
            | RegistryEvent::NameReleased { name, .. }
            | RegistryEvent::OwnerDocumentIatFloorUpdated { name, .. }
            | RegistryEvent::NamespacePolicyUpdated { name, .. } => {
                self.push_name(&mut write, name)?;
            }
            RegistryEvent::DocumentPublished {
                name,
                doc_type,
                version,
                ..
            } => {
                self.push_name(&mut write, name)?;
                self.push_document(&mut write, name, doc_type, *version)?;
            }
            RegistryEvent::DocumentRevoked {
                name,
                doc_type,
                new_version,
                ..
            } => {
                self.push_name(&mut write, name)?;
                self.push_document(&mut write, name, doc_type, *new_version)?;
            }
            RegistryEvent::AuthorityKeysUpdated { name, .. } => {
                let set =
                    self.authority_sets.get(name).cloned().ok_or_else(|| {
                        missing_projection_read(format!("authority set for {name}"))
                    })?;
                write.authority_sets.push(set);
                for key in authority_keys_from_call(decoded_call, name)? {
                    write.authority_keys.push((canonical_bns_name(name)?, key));
                }
            }
            RegistryEvent::ControllerPolicyUpdated {
                name, policy_hash, ..
            } => {
                self.push_name(&mut write, name)?;
                if let Some(rules) = controller_rules_from_call(decoded_call, name)? {
                    write.controller_policies.push((
                        canonical_bns_name(name)?,
                        rules,
                        policy_hash.clone(),
                    ));
                }
            }
            RegistryEvent::DidAliasSet { name, .. } => {
                self.push_name(&mut write, name)?;
                write.aliases.push(
                    self.aliases
                        .get(name)
                        .cloned()
                        .ok_or_else(|| missing_projection_read(format!("alias for {name}")))?,
                );
            }
            RegistryEvent::PaymentTargetUpdated {
                name,
                doc_type,
                version,
                ..
            } => {
                self.push_name(&mut write, name)?;
                self.push_document(&mut write, name, doc_type, *version)?;
            }
            RegistryEvent::LogCheckpointPublished { .. } => {
                if let Some(checkpoint) = checkpoint_from_event_and_call(record, decoded_call)? {
                    write.checkpoints.push(checkpoint);
                } else {
                    write.checkpoints.push(
                        self.checkpoint
                            .clone()
                            .ok_or_else(|| missing_projection_read("latest checkpoint"))?,
                    );
                }
            }
        }
        Ok(write)
    }

    fn push_name(&self, write: &mut ContractProjectionWrite, name: &str) -> BnsRegistryResult<()> {
        let state = self
            .names
            .get(name)
            .ok_or_else(|| missing_projection_read(format!("name state for {name}")))?;
        if let Some(state) = state {
            write.names.push(state.clone());
        }
        Ok(())
    }

    fn push_document(
        &self,
        write: &mut ContractProjectionWrite,
        name: &str,
        doc_type: &str,
        version: u64,
    ) -> BnsRegistryResult<()> {
        let state = self
            .documents
            .get(&(name.to_string(), doc_type.to_string(), version))
            .ok_or_else(|| {
                missing_projection_read(format!("document {name}/{doc_type}/{version}"))
            })?;
        if let Some(state) = state {
            write.documents.push(state.clone());
        }
        Ok(())
    }
}

fn projection_reads_for_record(
    record: &EventLogRecord,
    decoded_call: Option<&BnsCall>,
) -> Vec<ProjectionReadKey> {
    match &record.event {
        RegistryEvent::NameRegistered { name, .. }
        | RegistryEvent::NameRenewed { name, .. }
        | RegistryEvent::NameAssetTransferred { name, .. }
        | RegistryEvent::NameOwnerUpdated { name, .. }
        | RegistryEvent::NameReleased { name, .. }
        | RegistryEvent::OwnerDocumentIatFloorUpdated { name, .. }
        | RegistryEvent::NamespacePolicyUpdated { name, .. }
        | RegistryEvent::ControllerPolicyUpdated { name, .. } => {
            vec![ProjectionReadKey::Name(name.clone())]
        }
        RegistryEvent::DocumentPublished {
            name,
            doc_type,
            version,
            ..
        }
        | RegistryEvent::PaymentTargetUpdated {
            name,
            doc_type,
            version,
            ..
        } => vec![
            ProjectionReadKey::Name(name.clone()),
            ProjectionReadKey::Document(name.clone(), doc_type.clone(), *version),
        ],
        RegistryEvent::DocumentRevoked {
            name,
            doc_type,
            new_version,
            ..
        } => vec![
            ProjectionReadKey::Name(name.clone()),
            ProjectionReadKey::Document(name.clone(), doc_type.clone(), *new_version),
        ],
        RegistryEvent::AuthorityKeysUpdated { name, .. } => {
            vec![ProjectionReadKey::AuthoritySet(name.clone())]
        }
        RegistryEvent::DidAliasSet { name, .. } => vec![
            ProjectionReadKey::Name(name.clone()),
            ProjectionReadKey::Alias(name.clone()),
        ],
        RegistryEvent::LogCheckpointPublished { .. }
            if matches!(decoded_call, Some(BnsCall::publishLogCheckpoint(_))) =>
        {
            Vec::new()
        }
        RegistryEvent::LogCheckpointPublished { .. } => vec![ProjectionReadKey::LatestCheckpoint],
    }
}

fn missing_projection_read(detail: impl Into<String>) -> BnsRegistryError {
    BnsRegistryError::InvalidConfig(format!("BNS projection batch is missing {}", detail.into()))
}

fn record_needs_decoded_call(record: &EventLogRecord) -> bool {
    matches!(
        &record.event,
        RegistryEvent::AuthorityKeysUpdated { .. }
            | RegistryEvent::ControllerPolicyUpdated { .. }
            | RegistryEvent::LogCheckpointPublished { .. }
    )
}

fn checkpoint_from_event_and_call(
    record: &EventLogRecord,
    decoded_call: Option<&BnsCall>,
) -> BnsRegistryResult<Option<LogCheckpoint>> {
    let RegistryEvent::LogCheckpointPublished {
        log_root,
        last_seq,
        issued_at,
        external_anchor,
    } = &record.event
    else {
        return Ok(None);
    };
    let Some(BnsCall::publishLogCheckpoint(call)) = decoded_call else {
        return Ok(None);
    };
    let call_anchor = hash_string(call.externalAnchor);
    if call_anchor != *external_anchor {
        return Err(BnsRegistryError::InvalidMutation(format!(
            "checkpoint event external anchor {external_anchor} does not match transaction calldata {call_anchor}"
        )));
    }
    Ok(Some(LogCheckpoint {
        log_root: log_root.clone(),
        last_seq: *last_seq,
        issued_at: *issued_at,
        issuer: principal_from_evm(call.issuer.clone())?,
        external_anchor: external_anchor.clone(),
    }))
}

fn polling_delay(idle_interval: Duration, failed: bool, has_backlog: bool) -> Duration {
    if failed {
        CHAIN_ERROR_RETRY_INTERVAL
    } else if has_backlog {
        Duration::ZERO
    } else {
        idle_interval
    }
}

#[cfg(test)]
mod polling_tests {
    use super::*;

    #[test]
    fn chain_errors_use_fixed_retry_delay() {
        assert_eq!(
            polling_delay(Duration::from_secs(15), true, true),
            Duration::from_secs(30)
        );
        assert_eq!(
            polling_delay(Duration::from_secs(15), false, false),
            Duration::from_secs(15)
        );
        assert_eq!(
            polling_delay(Duration::from_secs(15), false, true),
            Duration::ZERO
        );
    }
}

pub async fn sync_bns_contract_once<S>(
    store: &S,
    config: BnsIndexerSyncConfig,
) -> BnsRegistryResult<BnsIndexerSyncOutcome>
where
    S: BnsRegistryStore,
{
    BnsContractEventIndexer::new(store, config)?
        .sync_once()
        .await
}

#[derive(Default)]
struct ContractProjectionWrite {
    lineage_resets: Vec<String>,
    names: Vec<NameState>,
    documents: Vec<DocumentState>,
    authority_sets: Vec<AuthoritySetState>,
    authority_keys: Vec<(String, AuthorityKey)>,
    controller_policies: Vec<(String, Vec<crate::ControllerRule>, String)>,
    aliases: Vec<AliasState>,
    checkpoints: Vec<LogCheckpoint>,
}

impl ContractProjectionWrite {
    fn apply(self, tx: &mut dyn BnsRegistryStoreTx) -> BnsRegistryResult<()> {
        for name in self.lineage_resets {
            tx.reset_name_lineage(&name)?;
        }
        for name in self.names {
            tx.put_name(&name)?;
        }
        for document in self.documents {
            tx.put_document(&document)?;
        }
        for set in self.authority_sets {
            tx.put_authority_set(&set)?;
        }
        for (name, key) in self.authority_keys {
            tx.put_authority_key(&name, &key)?;
        }
        for (name, rules, policy_hash) in self.controller_policies {
            tx.put_controller_policy(&name, &rules, &policy_hash)?;
        }
        for alias in self.aliases {
            tx.put_alias(&alias)?;
        }
        for checkpoint in self.checkpoints {
            tx.put_checkpoint(&checkpoint)?;
        }
        Ok(())
    }
}

fn authority_keys_from_call(
    decoded_call: Option<&BnsCall>,
    name: &str,
) -> BnsRegistryResult<Vec<AuthorityKey>> {
    let Some(decoded_call) = decoded_call else {
        return Ok(Vec::new());
    };
    let updates = match decoded_call {
        BnsCall::registerName(call) if call.name == name => &call.authorityUpdates,
        BnsCall::updateAuthorityKeys(call) if call.name == name => &call.updates,
        BnsCall::applyMutations(call) if call.name == name => &call.authorityUpdates,
        _ => return Ok(Vec::new()),
    };
    updates.iter().map(authority_key_update_from_evm).collect()
}

fn controller_rules_from_call(
    decoded_call: Option<&BnsCall>,
    name: &str,
) -> BnsRegistryResult<Option<Vec<crate::ControllerRule>>> {
    let Some(decoded_call) = decoded_call else {
        return Ok(None);
    };
    let rules = match decoded_call {
        BnsCall::registerName(call) if call.name == name => &call.controllerPolicy,
        BnsCall::setControllerPolicy(call) if call.name == name => &call.rules,
        _ => return Ok(None),
    };
    rules
        .iter()
        .map(controller_rule_from_evm)
        .collect::<BnsRegistryResult<Vec<_>>>()
        .map(Some)
}

fn authority_key_update_from_evm(
    update: &EvmAuthorityKeyUpdate,
) -> BnsRegistryResult<AuthorityKey> {
    let mut key = authority_key_from_evm(&update.key)?;
    if update.active {
        if key.status == AuthorityKeyStatus::Missing {
            key.status = AuthorityKeyStatus::Active;
        }
    } else {
        key.status = AuthorityKeyStatus::Revoked;
    }
    Ok(key)
}

fn name_state_from_evm(state: EvmNameState) -> BnsRegistryResult<NameState> {
    Ok(NameState {
        name: canonical_bns_name_or_empty(&state.name)?,
        asset_owner: address_or_empty(state.assetOwner),
        semantic_owner: principal_from_evm(state.semanticOwner)?,
        effective_owner: principal_from_evm(state.effectiveOwner)?,
        owner_source: owner_source_from_evm(state.ownerSource)?,
        standard_transfer_enabled: state.standardTransferEnabled,
        status: name_status_from_evm(state.status)?,
        registered_at: state.registeredAt,
        expire_at: state.expireAt,
        grace_until: state.graceUntil,
        updated_at: state.updatedAt,
        name_seq: state.nameSeq,
        owner_document_version: state.ownerDocumentVersion,
        min_document_iat: state.minDocumentIat,
        owner_policy_seq: state.ownerPolicySeq,
        lineage_epoch: state.lineageEpoch,
        renewable: state.renewable,
        transferable: state.transferable,
        allow_delegated_subnames: state.allowDelegatedSubnames,
        namespace_policy_hash: hash_string(state.namespacePolicyHash),
        payment_policy_hash: hash_string(state.paymentPolicyHash),
        alias_state_hash: hash_string(state.aliasStateHash),
    })
}

fn document_state_from_evm(state: EvmDocumentState) -> BnsRegistryResult<DocumentState> {
    Ok(DocumentState {
        name: canonical_bns_name_or_empty(&state.name)?,
        doc_type: canonical_doc_type_or_empty(&state.docType)?,
        version: state.version,
        previous_version: state.previousVersion,
        status: document_status_from_evm(state.status)?,
        document: document_ref_from_evm(state.document)?,
        controller: principal_from_evm(state.controller)?,
        beneficiary: principal_from_evm(state.beneficiary)?,
        payment_target: address_or_empty(state.paymentTarget),
        valid_from: state.validFrom,
        expire_at: state.expireAt,
        revoked_at: state.revokedAt,
        controller_policy_hash: hash_string(state.controllerPolicyHash),
        payment_policy_hash: hash_string(state.paymentPolicyHash),
        split_policy_hash: hash_string(state.splitPolicyHash),
        price_policy_hash: hash_string(state.pricePolicyHash),
        rights_policy_hash: hash_string(state.rightsPolicyHash),
        document_state_hash: hash_string(state.documentStateHash),
    })
}

fn authority_set_from_evm(state: EvmAuthoritySetState) -> BnsRegistryResult<AuthoritySetState> {
    Ok(AuthoritySetState {
        name: canonical_bns_name_or_empty(&state.name)?,
        authority_seq: state.authoritySeq,
        authority_root: hash_string(state.authorityRoot),
        active_key_count: state.activeKeyCount,
    })
}

fn authority_key_from_evm(key: &EvmAuthorityKey) -> BnsRegistryResult<AuthorityKey> {
    Ok(AuthorityKey {
        kid: hash_string(key.kid),
        verification_method: bytes32_label_or_hash(key.verificationMethod),
        key_data: key.keyData.to_vec(),
        purposes: key.purposes,
        valid_from: key.validFrom,
        valid_until: key.validUntil,
        status: authority_key_status_from_evm(key.status)?,
        metadata_hash: hash_string(key.metadataHash),
    })
}

fn controller_rule_from_evm(
    rule: &bns_evm::ControllerRule,
) -> BnsRegistryResult<crate::ControllerRule> {
    Ok(crate::ControllerRule {
        controller: principal_from_evm(rule.controller.clone())?,
        doc_type: canonical_doc_type_or_empty(&rule.docType)?,
        permissions: rule.permissions,
        namespace_scope_hash: hash_string(rule.namespaceScopeHash),
        valid_from: rule.validFrom,
        valid_until: rule.validUntil,
        constraint_hash: hash_string(rule.constraintHash),
    })
}

fn alias_state_from_evm(state: EvmAliasState) -> BnsRegistryResult<AliasState> {
    Ok(AliasState {
        name: canonical_bns_name_or_empty(&state.name)?,
        kind: alias_kind_from_evm(state.kind)?,
        target_did: state.targetDid,
        proof_hash: hash_string(state.proofHash),
        set_at: state.setAt,
        name_seq: state.nameSeq,
    })
}

fn checkpoint_from_evm(checkpoint: bns_evm::LogCheckpoint) -> BnsRegistryResult<LogCheckpoint> {
    Ok(LogCheckpoint {
        log_root: hash_string(checkpoint.logRoot),
        last_seq: checkpoint.lastSeq,
        issued_at: checkpoint.issuedAt,
        issuer: principal_from_evm(checkpoint.issuer)?,
        external_anchor: hash_string(checkpoint.externalAnchor),
    })
}

fn document_ref_from_evm(document: EvmDocumentRef) -> BnsRegistryResult<DocumentRef> {
    Ok(DocumentRef {
        storage_type: bytes32_label_or_hash(document.storageType),
        uri: document.uri,
        inline_document: document.inlineDocument.to_vec(),
        content_hash: hash_string(document.contentHash),
        schema: hash_string(document.schema),
        codec: hash_string(document.codec),
        extra_hash: hash_string(document.extraHash),
    })
}

fn principal_from_evm(principal: EvmPrincipal) -> BnsRegistryResult<Principal> {
    match principal.kind {
        EvmPrincipalKind::Unset => Ok(Principal::unset()),
        EvmPrincipalKind::ChainAccount => {
            let bytes = principal.value.as_ref();
            if bytes.len() != 20 && bytes.len() != 32 {
                return Err(BnsRegistryError::InvalidMutation(format!(
                    "chain account principal has {} bytes",
                    bytes.len()
                )));
            }
            let address_bytes = if bytes.len() == 20 {
                bytes
            } else {
                &bytes[12..]
            };
            Ok(Principal::chain_account(format!(
                "0x{}",
                hex::encode(address_bytes)
            )))
        }
        EvmPrincipalKind::BnsName => {
            let name = String::from_utf8(principal.value.to_vec()).map_err(|err| {
                BnsRegistryError::InvalidMutation(format!(
                    "BnsName principal is not valid UTF-8: {err}"
                ))
            })?;
            Principal::bns_name(name)
        }
        _ => Err(BnsRegistryError::InvalidMutation(
            "unknown contract principal kind".to_string(),
        )),
    }
}

fn name_status_from_evm(status: EvmNameStatus) -> BnsRegistryResult<NameStatus> {
    match status {
        EvmNameStatus::Available => Ok(NameStatus::Available),
        EvmNameStatus::Active => Ok(NameStatus::Active),
        EvmNameStatus::Expired => Ok(NameStatus::Expired),
        EvmNameStatus::Released => Ok(NameStatus::Released),
        EvmNameStatus::Tombstoned => Ok(NameStatus::Tombstoned),
        _ => Err(BnsRegistryError::InvalidMutation(
            "unknown contract name status".to_string(),
        )),
    }
}

fn document_status_from_evm(status: EvmDocumentStatus) -> BnsRegistryResult<DocumentStatus> {
    match status {
        EvmDocumentStatus::Missing => Ok(DocumentStatus::Missing),
        EvmDocumentStatus::Active => Ok(DocumentStatus::Active),
        EvmDocumentStatus::Revoked => Ok(DocumentStatus::Revoked),
        EvmDocumentStatus::Expired => Ok(DocumentStatus::Expired),
        EvmDocumentStatus::Migrated => Ok(DocumentStatus::Migrated),
        EvmDocumentStatus::Tombstoned => Ok(DocumentStatus::Tombstoned),
        _ => Err(BnsRegistryError::InvalidMutation(
            "unknown contract document status".to_string(),
        )),
    }
}

fn authority_key_status_from_evm(
    status: EvmAuthorityKeyStatus,
) -> BnsRegistryResult<AuthorityKeyStatus> {
    match status {
        EvmAuthorityKeyStatus::Missing => Ok(AuthorityKeyStatus::Missing),
        EvmAuthorityKeyStatus::Active => Ok(AuthorityKeyStatus::Active),
        EvmAuthorityKeyStatus::Revoked => Ok(AuthorityKeyStatus::Revoked),
        EvmAuthorityKeyStatus::Expired => Ok(AuthorityKeyStatus::Expired),
        _ => Err(BnsRegistryError::InvalidMutation(
            "unknown contract authority key status".to_string(),
        )),
    }
}

fn owner_source_from_evm(source: EvmOwnerSource) -> BnsRegistryResult<OwnerSource> {
    match source {
        EvmOwnerSource::None => Ok(OwnerSource::None),
        EvmOwnerSource::AssetOwnerFallback => Ok(OwnerSource::AssetOwnerFallback),
        EvmOwnerSource::ExplicitSemanticOwner => Ok(OwnerSource::ExplicitSemanticOwner),
        EvmOwnerSource::ParentInherited => Ok(OwnerSource::ParentInherited),
        _ => Err(BnsRegistryError::InvalidMutation(
            "unknown contract owner source".to_string(),
        )),
    }
}

fn alias_kind_from_evm(kind: EvmAliasKind) -> BnsRegistryResult<AliasKind> {
    match kind {
        EvmAliasKind::None => Ok(AliasKind::None),
        EvmAliasKind::Alias => Ok(AliasKind::Alias),
        EvmAliasKind::MigratedTo => Ok(AliasKind::MigratedTo),
        EvmAliasKind::Canonical => Ok(AliasKind::Canonical),
        _ => Err(BnsRegistryError::InvalidMutation(
            "unknown contract alias kind".to_string(),
        )),
    }
}

fn canonical_bns_name_or_empty(name: &str) -> BnsRegistryResult<String> {
    if name.is_empty() {
        Ok(String::new())
    } else {
        canonical_bns_name(name)
    }
}

fn canonical_doc_type_or_empty(doc_type: &str) -> BnsRegistryResult<String> {
    if doc_type.is_empty() {
        Ok(String::new())
    } else {
        canonical_doc_type(doc_type)
    }
}

fn address_or_empty(address: Address) -> String {
    if address == Address::ZERO {
        String::new()
    } else {
        format!("{address:#x}")
    }
}

fn hash_string(hash: B256) -> String {
    format!("{hash:#x}")
}

fn bytes32_label_or_hash(value: B256) -> String {
    if value == B256::ZERO {
        return ZERO_HASH.to_string();
    }
    let bytes = value.as_slice();
    let trimmed_len = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if trimmed_len > 0
        && bytes[trimmed_len..].iter().all(|byte| *byte == 0)
        && bytes[..trimmed_len]
            .iter()
            .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
    {
        if let Ok(label) = std::str::from_utf8(&bytes[..trimmed_len]) {
            return label.to_string();
        }
    }
    hash_string(value)
}
