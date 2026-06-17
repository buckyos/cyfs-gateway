use std::sync::Arc;

use crate::{
    canonical_bns_name, canonical_doc_type, compare_optional_projection, now_timestamp,
    reconciliation_plan, AliasState, BnsContractEventSource, BnsContractView, BnsDb,
    BnsIndexerError, BnsIndexerResult, ContractEvent, ContractEventEnvelope, DocumentState,
    DocumentStatus, IndexerCursor, NameState, NameStatus, ReconciliationPlan, ReleaseMode,
    TruthSource, ValidationReport, ValidationTarget, ZERO_HASH,
};

#[derive(Debug, Clone)]
pub struct BnsIndexerConfig {
    pub truth_source: TruthSource,
    pub validate_aliases: bool,
    pub validate_purchase_contexts: bool,
    pub project_contract_events: bool,
}

impl Default for BnsIndexerConfig {
    fn default() -> Self {
        Self {
            truth_source: TruthSource::BnsDb,
            validate_aliases: true,
            validate_purchase_contexts: true,
            project_contract_events: true,
        }
    }
}

pub struct BnsIndexer<D, C>
where
    D: BnsDb,
    C: BnsContractView,
{
    db: Arc<D>,
    contract: Arc<C>,
    config: BnsIndexerConfig,
}

impl<D, C> BnsIndexer<D, C>
where
    D: BnsDb,
    C: BnsContractView,
{
    pub fn new(db: Arc<D>, contract: Arc<C>) -> Self {
        Self::with_config(db, contract, BnsIndexerConfig::default())
    }

    pub fn with_config(db: Arc<D>, contract: Arc<C>, config: BnsIndexerConfig) -> Self {
        Self {
            db,
            contract,
            config,
        }
    }

    pub fn db(&self) -> &Arc<D> {
        &self.db
    }

    pub fn contract(&self) -> &Arc<C> {
        &self.contract
    }

    pub fn config(&self) -> &BnsIndexerConfig {
        &self.config
    }

    pub async fn validate_name_state(&self, name: &str) -> BnsIndexerResult<ValidationReport> {
        let name = canonical_bns_name(name)?;
        let bns_db = self.db.get_name_state(&name)?;
        let contract = self.contract.query_name_state(&name).await?;
        let report = compare_optional_projection(
            ValidationTarget::Name { name },
            self.config.truth_source,
            bns_db.as_ref(),
            contract.as_ref(),
        )?;
        self.db.put_validation_report(&report)?;
        Ok(report)
    }

    pub async fn validate_document_state(
        &self,
        name: &str,
        doc_type: &str,
        version: u64,
    ) -> BnsIndexerResult<ValidationReport> {
        let name = canonical_bns_name(name)?;
        let doc_type = canonical_doc_type(doc_type)?;
        let bns_db = self.db.get_document_state(&name, &doc_type, version)?;
        let contract = self
            .contract
            .get_document_version(&name, &doc_type, version)
            .await?;
        let report = compare_optional_projection(
            ValidationTarget::Document {
                name,
                doc_type,
                version,
            },
            self.config.truth_source,
            bns_db.as_ref(),
            contract.as_ref(),
        )?;
        self.db.put_validation_report(&report)?;
        Ok(report)
    }

    pub async fn validate_alias_state(&self, name: &str) -> BnsIndexerResult<ValidationReport> {
        let name = canonical_bns_name(name)?;
        let bns_db = self.db.get_alias_state(&name)?;
        let contract = self.contract.get_alias(&name).await?;
        let report = compare_optional_projection(
            ValidationTarget::Alias { name },
            self.config.truth_source,
            bns_db.as_ref(),
            contract.as_ref(),
        )?;
        self.db.put_validation_report(&report)?;
        Ok(report)
    }

    pub async fn validate_purchase_context(
        &self,
        content_name: &str,
        doc_type: &str,
    ) -> BnsIndexerResult<ValidationReport> {
        let content_name = canonical_bns_name(content_name)?;
        let doc_type = canonical_doc_type(doc_type)?;
        let bns_db = self.db.get_purchase_context(&content_name, &doc_type)?;
        let contract = self
            .contract
            .get_purchase_context(&content_name, &doc_type)
            .await?;
        let report = compare_optional_projection(
            ValidationTarget::PurchaseContext {
                content_name,
                doc_type,
            },
            self.config.truth_source,
            bns_db.as_ref(),
            contract.as_ref(),
        )?;
        self.db.put_validation_report(&report)?;
        Ok(report)
    }

    pub async fn validate_name_from_db(
        &self,
        name: &str,
    ) -> BnsIndexerResult<Vec<ValidationReport>> {
        let name = canonical_bns_name(name)?;
        let mut reports = Vec::new();
        reports.push(self.validate_name_state(&name).await?);

        for key in self.db.list_document_keys(Some(&name))? {
            reports.push(
                self.validate_document_state(&key.name, &key.doc_type, key.version)
                    .await?,
            );

            if self.config.validate_purchase_contexts {
                if self
                    .db
                    .get_purchase_context(&key.name, &key.doc_type)?
                    .is_some()
                {
                    reports.push(
                        self.validate_purchase_context(&key.name, &key.doc_type)
                            .await?,
                    );
                }
            }
        }

        if self.config.validate_aliases
            && (self.db.get_alias_state(&name)?.is_some()
                || self.contract.get_alias(&name).await?.is_some())
        {
            reports.push(self.validate_alias_state(&name).await?);
        }

        Ok(reports)
    }

    pub async fn validate_all_db_names(&self) -> BnsIndexerResult<Vec<ValidationReport>> {
        let mut reports = Vec::new();
        for name in self.db.list_names()? {
            reports.extend(self.validate_name_from_db(&name).await?);
        }
        Ok(reports)
    }

    pub fn reconciliation_plan(&self, report: &ValidationReport) -> ReconciliationPlan {
        reconciliation_plan(report)
    }

    pub async fn project_contract_event(
        &self,
        envelope: &ContractEventEnvelope,
    ) -> BnsIndexerResult<()> {
        match &envelope.event {
            ContractEvent::NameRegistered {
                name,
                asset_owner,
                expire_at,
                name_seq,
            } => {
                if !self.refresh_name_projection(name).await? {
                    let state = NameState {
                        name: canonical_bns_name(name)?,
                        asset_owner: asset_owner.clone(),
                        status: NameStatus::Active,
                        registered_at: envelope.observed_at,
                        expire_at: *expire_at,
                        grace_until: *expire_at,
                        updated_at: envelope.observed_at,
                        name_seq: *name_seq,
                        owner_document_version: 0,
                        namespace_policy_hash: ZERO_HASH.to_string(),
                        payment_policy_hash: ZERO_HASH.to_string(),
                        alias_state_hash: ZERO_HASH.to_string(),
                    };
                    self.db.put_name_state(&state)?;
                }
            }
            ContractEvent::NameRenewed {
                name,
                expire_at,
                name_seq,
            } => {
                if !self.refresh_name_projection(name).await? {
                    self.update_existing_name(name, envelope.observed_at, |state| {
                        state.expire_at = *expire_at;
                        state.name_seq = *name_seq;
                    })?;
                }
            }
            ContractEvent::NameTransferred {
                name,
                new_asset_owner,
                name_seq,
                ..
            } => {
                if !self.refresh_name_projection(name).await? {
                    self.update_existing_name(name, envelope.observed_at, |state| {
                        state.asset_owner = new_asset_owner.clone();
                        state.name_seq = *name_seq;
                    })?;
                }
            }
            ContractEvent::NameReleased {
                name,
                mode,
                name_seq,
                ..
            } => {
                if !self.refresh_name_projection(name).await? {
                    self.update_existing_name(name, envelope.observed_at, |state| {
                        state.status = name_status_from_release_mode(*mode);
                        state.name_seq = *name_seq;
                    })?;
                }
            }
            ContractEvent::DocumentPublished {
                name,
                doc_type,
                version,
                ..
            } => {
                self.refresh_name_projection(name).await?;
                self.refresh_document_projection(name, doc_type, *version)
                    .await?;
                self.refresh_purchase_context_projection(name, doc_type)
                    .await?;
            }
            ContractEvent::DocumentRevoked {
                name,
                doc_type,
                from_version,
                to_version,
                ..
            } => {
                if from_version > to_version {
                    return Err(BnsIndexerError::contract(format!(
                        "invalid document revoke range: {from_version}..={to_version}"
                    )));
                }

                self.refresh_name_projection(name).await?;
                for version in *from_version..=*to_version {
                    if !self
                        .refresh_document_projection(name, doc_type, version)
                        .await?
                    {
                        self.update_existing_document(
                            name,
                            doc_type,
                            version,
                            envelope.observed_at,
                            |state| {
                                state.status = DocumentStatus::Revoked;
                                state.revoked_at = envelope.observed_at;
                            },
                        )?;
                    }
                }
                self.refresh_purchase_context_projection(name, doc_type)
                    .await?;
            }
            ContractEvent::ControllerPolicyUpdated { name, .. } => {
                self.refresh_name_projection(name).await?;
            }
            ContractEvent::NamespacePolicyUpdated {
                name,
                namespace_policy_hash,
                name_seq,
                ..
            } => {
                if !self.refresh_name_projection(name).await? {
                    self.update_existing_name(name, envelope.observed_at, |state| {
                        state.namespace_policy_hash = namespace_policy_hash.clone();
                        state.name_seq = *name_seq;
                    })?;
                }
            }
            ContractEvent::OwnerKeyChanged {
                name,
                owner_document_version,
                ..
            } => {
                if !self.refresh_name_projection(name).await? {
                    self.update_existing_name(name, envelope.observed_at, |state| {
                        state.owner_document_version = *owner_document_version;
                    })?;
                }
                self.refresh_document_projection(name, "owner", *owner_document_version)
                    .await?;
            }
            ContractEvent::DidAliasSet {
                name,
                target_did,
                kind,
                proof_hash,
                name_seq,
            } => {
                let name_refreshed = self.refresh_name_projection(name).await?;
                if !self.refresh_alias_projection(name).await? {
                    let alias = AliasState {
                        name: canonical_bns_name(name)?,
                        kind: *kind,
                        target_did: target_did.clone(),
                        proof_hash: proof_hash.clone(),
                        set_at: envelope.observed_at,
                        name_seq: *name_seq,
                    };
                    self.db.put_alias_state(&alias)?;
                }

                if !name_refreshed {
                    self.update_existing_name(name, envelope.observed_at, |state| {
                        state.alias_state_hash = proof_hash.clone();
                        state.name_seq = *name_seq;
                    })?;
                }
            }
            ContractEvent::PaymentTargetUpdated {
                name,
                doc_type,
                payment_target,
                payment_policy_hash,
                version,
            } => {
                if !self.refresh_name_projection(name).await? {
                    self.update_existing_name(name, envelope.observed_at, |state| {
                        state.payment_policy_hash = payment_policy_hash.clone();
                    })?;
                }

                if !self
                    .refresh_document_projection(name, doc_type, *version)
                    .await?
                {
                    self.update_existing_document(
                        name,
                        doc_type,
                        *version,
                        envelope.observed_at,
                        |state| {
                            state.payment_target = payment_target.clone();
                        },
                    )?;
                }
                self.refresh_purchase_context_projection(name, doc_type)
                    .await?;
            }
        }

        Ok(())
    }

    async fn refresh_name_projection(&self, name: &str) -> BnsIndexerResult<bool> {
        let name = canonical_bns_name(name)?;
        if let Some(state) = self.contract.query_name_state(&name).await? {
            self.db.put_name_state(&state)?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn refresh_document_projection(
        &self,
        name: &str,
        doc_type: &str,
        version: u64,
    ) -> BnsIndexerResult<bool> {
        let name = canonical_bns_name(name)?;
        let doc_type = canonical_doc_type(doc_type)?;
        if let Some(state) = self
            .contract
            .get_document_version(&name, &doc_type, version)
            .await?
        {
            self.db.put_document_state(&state)?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn refresh_alias_projection(&self, name: &str) -> BnsIndexerResult<bool> {
        let name = canonical_bns_name(name)?;
        if let Some(state) = self.contract.get_alias(&name).await? {
            self.db.put_alias_state(&state)?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn refresh_purchase_context_projection(
        &self,
        content_name: &str,
        doc_type: &str,
    ) -> BnsIndexerResult<bool> {
        let content_name = canonical_bns_name(content_name)?;
        let doc_type = canonical_doc_type(doc_type)?;
        if let Some(context) = self
            .contract
            .get_purchase_context(&content_name, &doc_type)
            .await?
        {
            self.db.put_purchase_context(&context)?;
            return Ok(true);
        }
        Ok(false)
    }

    fn update_existing_name<F>(
        &self,
        name: &str,
        observed_at: u64,
        update: F,
    ) -> BnsIndexerResult<()>
    where
        F: FnOnce(&mut NameState),
    {
        let name = canonical_bns_name(name)?;
        if let Some(mut state) = self.db.get_name_state(&name)? {
            update(&mut state);
            state.updated_at = observed_at;
            self.db.put_name_state(&state)?;
        }
        Ok(())
    }

    fn update_existing_document<F>(
        &self,
        name: &str,
        doc_type: &str,
        version: u64,
        _observed_at: u64,
        update: F,
    ) -> BnsIndexerResult<()>
    where
        F: FnOnce(&mut DocumentState),
    {
        let name = canonical_bns_name(name)?;
        let doc_type = canonical_doc_type(doc_type)?;
        if let Some(mut state) = self.db.get_document_state(&name, &doc_type, version)? {
            update(&mut state);
            self.db.put_document_state(&state)?;
        }
        Ok(())
    }
}

impl<D, C> BnsIndexer<D, C>
where
    D: BnsDb,
    C: BnsContractView + BnsContractEventSource,
{
    pub async fn ingest_contract_events(
        &self,
        source: &str,
        limit: usize,
    ) -> BnsIndexerResult<Vec<ContractEventEnvelope>> {
        let cursor = self.db.get_indexer_cursor(source)?;
        let events = self
            .contract
            .fetch_events(source, cursor.as_ref(), limit)
            .await?;

        let mut latest_cursor = None;
        for event in &events {
            self.db.record_contract_event(event)?;
            if self.config.project_contract_events {
                self.project_contract_event(event).await?;
            }
            latest_cursor = Some(IndexerCursor {
                source: source.to_string(),
                block_number: event.block_number,
                block_hash: event.block_hash.clone(),
                log_index: event.log_index,
                updated_at: now_timestamp(),
            });
        }

        if let Some(cursor) = latest_cursor {
            self.db.put_indexer_cursor(&cursor)?;
        }

        Ok(events)
    }
}

fn name_status_from_release_mode(mode: ReleaseMode) -> NameStatus {
    match mode {
        ReleaseMode::ReleaseAfterGrace => NameStatus::Released,
        ReleaseMode::TombstoneForever => NameStatus::Tombstoned,
    }
}
