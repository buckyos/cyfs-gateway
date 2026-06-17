use std::sync::Arc;

use crate::{
    canonical_bns_name, canonical_doc_type, compare_optional_projection, now_timestamp,
    reconciliation_plan, BnsContractEventSource, BnsContractView, BnsDb, BnsIndexerResult,
    ContractEventEnvelope, IndexerCursor, ReconciliationPlan, TruthSource, ValidationReport,
    ValidationTarget,
};

#[derive(Debug, Clone)]
pub struct BnsIndexerConfig {
    pub truth_source: TruthSource,
    pub validate_aliases: bool,
    pub validate_purchase_contexts: bool,
}

impl Default for BnsIndexerConfig {
    fn default() -> Self {
        Self {
            truth_source: TruthSource::BnsDb,
            validate_aliases: true,
            validate_purchase_contexts: true,
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
