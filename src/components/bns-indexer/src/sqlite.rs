use rusqlite::{params, Connection, OptionalExtension};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use crate::{
    canonical_bns_name, canonical_doc_type, AliasState, BnsDb, BnsIndexerError, BnsIndexerResult,
    ContractEventEnvelope, DocumentKey, DocumentState, IndexerCursor, NameState, PurchaseContext,
    ValidationReport,
};

pub struct SqliteBnsDb {
    conn: Mutex<Connection>,
}

impl SqliteBnsDb {
    pub fn open(path: impl AsRef<Path>) -> BnsIndexerResult<Self> {
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let conn = Connection::open(path)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        let db = Self {
            conn: Mutex::new(conn),
        };
        db.initialize_schema()?;
        Ok(db)
    }

    pub fn open_memory() -> BnsIndexerResult<Self> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let db = Self {
            conn: Mutex::new(conn),
        };
        db.initialize_schema()?;
        Ok(db)
    }

    pub fn initialize_schema(&self) -> BnsIndexerResult<()> {
        let conn = self.conn()?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS bns_names (
                name TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                name_seq INTEGER NOT NULL,
                owner_document_version INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                payload_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS bns_documents (
                name TEXT NOT NULL,
                doc_type TEXT NOT NULL,
                version INTEGER NOT NULL,
                status TEXT NOT NULL,
                is_current INTEGER NOT NULL,
                content_hash TEXT NOT NULL,
                document_state_hash TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY (name, doc_type, version)
            );

            CREATE INDEX IF NOT EXISTS idx_bns_documents_current
                ON bns_documents (name, doc_type, is_current);

            CREATE TABLE IF NOT EXISTS bns_aliases (
                name TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                target_did TEXT NOT NULL,
                name_seq INTEGER NOT NULL,
                set_at INTEGER NOT NULL,
                payload_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS bns_purchase_contexts (
                content_name TEXT NOT NULL,
                doc_type TEXT NOT NULL,
                document_version INTEGER NOT NULL,
                status TEXT NOT NULL,
                proof_root TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY (content_name, doc_type)
            );

            CREATE TABLE IF NOT EXISTS bns_contract_events (
                source TEXT NOT NULL,
                block_number INTEGER NOT NULL,
                block_hash TEXT NULL,
                tx_hash TEXT NOT NULL,
                log_index INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                observed_at INTEGER NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY (source, block_number, tx_hash, log_index)
            );

            CREATE INDEX IF NOT EXISTS idx_bns_contract_events_source_block
                ON bns_contract_events (source, block_number, log_index);

            CREATE TABLE IF NOT EXISTS bns_indexer_cursors (
                source TEXT PRIMARY KEY,
                block_number INTEGER NOT NULL,
                block_hash TEXT NULL,
                log_index INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                payload_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS bns_validation_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_kind TEXT NOT NULL,
                name TEXT NULL,
                doc_type TEXT NULL,
                version INTEGER NULL,
                checked_at INTEGER NOT NULL,
                status TEXT NOT NULL,
                mismatch_count INTEGER NOT NULL,
                payload_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_bns_validation_reports_target
                ON bns_validation_reports (target_kind, name, doc_type, version, checked_at);

            PRAGMA user_version = 1;
            "#,
        )?;
        Ok(())
    }

    fn conn(&self) -> BnsIndexerResult<MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| BnsIndexerError::DbLockPoisoned)
    }
}

impl BnsDb for SqliteBnsDb {
    fn put_name_state(&self, state: &NameState) -> BnsIndexerResult<()> {
        state.validate()?;
        let conn = self.conn()?;
        conn.execute(
            r#"
            INSERT INTO bns_names
                (name, status, name_seq, owner_document_version, updated_at, payload_json)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(name) DO UPDATE SET
                status = excluded.status,
                name_seq = excluded.name_seq,
                owner_document_version = excluded.owner_document_version,
                updated_at = excluded.updated_at,
                payload_json = excluded.payload_json
            "#,
            params![
                state.name,
                state.status.as_str(),
                to_i64(state.name_seq, "name_seq")?,
                to_i64(state.owner_document_version, "owner_document_version")?,
                to_i64(state.updated_at, "updated_at")?,
                to_json(state)?
            ],
        )?;
        Ok(())
    }

    fn get_name_state(&self, name: &str) -> BnsIndexerResult<Option<NameState>> {
        let name = canonical_bns_name(name)?;
        let conn = self.conn()?;
        let payload = conn
            .query_row(
                "SELECT payload_json FROM bns_names WHERE name = ?1",
                params![name],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        payload.as_deref().map(from_json).transpose()
    }

    fn list_names(&self) -> BnsIndexerResult<Vec<String>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT name FROM bns_names ORDER BY name")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut names = Vec::new();
        for row in rows {
            names.push(row?);
        }
        Ok(names)
    }

    fn put_document_state(&self, state: &DocumentState) -> BnsIndexerResult<()> {
        state.validate()?;
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let max_version = tx
            .query_row(
                "SELECT MAX(version) FROM bns_documents WHERE name = ?1 AND doc_type = ?2",
                params![state.name, state.doc_type],
                |row| row.get::<_, Option<i64>>(0),
            )?
            .unwrap_or(-1);
        let incoming_version = to_i64(state.version, "version")?;
        let is_current = incoming_version >= max_version;
        if is_current {
            tx.execute(
                "UPDATE bns_documents SET is_current = 0 WHERE name = ?1 AND doc_type = ?2",
                params![state.name, state.doc_type],
            )?;
        }

        tx.execute(
            r#"
            INSERT INTO bns_documents
                (name, doc_type, version, status, is_current, content_hash,
                 document_state_hash, updated_at, payload_json)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(name, doc_type, version) DO UPDATE SET
                status = excluded.status,
                is_current = excluded.is_current,
                content_hash = excluded.content_hash,
                document_state_hash = excluded.document_state_hash,
                updated_at = excluded.updated_at,
                payload_json = excluded.payload_json
            "#,
            params![
                state.name,
                state.doc_type,
                incoming_version,
                state.status.as_str(),
                if is_current { 1 } else { 0 },
                state.document.content_hash,
                state.document_state_hash,
                to_i64(state.valid_from, "valid_from")?,
                to_json(state)?
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn get_document_state(
        &self,
        name: &str,
        doc_type: &str,
        version: u64,
    ) -> BnsIndexerResult<Option<DocumentState>> {
        let name = canonical_bns_name(name)?;
        let doc_type = canonical_doc_type(doc_type)?;
        let conn = self.conn()?;
        let payload = conn
            .query_row(
                r#"
                SELECT payload_json
                FROM bns_documents
                WHERE name = ?1 AND doc_type = ?2 AND version = ?3
                "#,
                params![name, doc_type, to_i64(version, "version")?],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        payload.as_deref().map(from_json).transpose()
    }

    fn get_current_document_state(
        &self,
        name: &str,
        doc_type: &str,
    ) -> BnsIndexerResult<Option<DocumentState>> {
        let name = canonical_bns_name(name)?;
        let doc_type = canonical_doc_type(doc_type)?;
        let conn = self.conn()?;
        let payload = conn
            .query_row(
                r#"
                SELECT payload_json
                FROM bns_documents
                WHERE name = ?1 AND doc_type = ?2
                ORDER BY is_current DESC, version DESC
                LIMIT 1
                "#,
                params![name, doc_type],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        payload.as_deref().map(from_json).transpose()
    }

    fn list_document_keys(&self, name: Option<&str>) -> BnsIndexerResult<Vec<DocumentKey>> {
        let conn = self.conn()?;
        let mut keys = Vec::new();
        if let Some(name) = name {
            let name = canonical_bns_name(name)?;
            let mut stmt = conn.prepare(
                r#"
                SELECT name, doc_type, version
                FROM bns_documents
                WHERE name = ?1
                ORDER BY name, doc_type, version
                "#,
            )?;
            let rows = stmt.query_map(params![name], document_key_from_row)?;
            for row in rows {
                keys.push(row?);
            }
        } else {
            let mut stmt = conn.prepare(
                r#"
                SELECT name, doc_type, version
                FROM bns_documents
                ORDER BY name, doc_type, version
                "#,
            )?;
            let rows = stmt.query_map([], document_key_from_row)?;
            for row in rows {
                keys.push(row?);
            }
        }
        Ok(keys)
    }

    fn put_alias_state(&self, state: &AliasState) -> BnsIndexerResult<()> {
        state.validate()?;
        let conn = self.conn()?;
        conn.execute(
            r#"
            INSERT INTO bns_aliases
                (name, kind, target_did, name_seq, set_at, payload_json)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(name) DO UPDATE SET
                kind = excluded.kind,
                target_did = excluded.target_did,
                name_seq = excluded.name_seq,
                set_at = excluded.set_at,
                payload_json = excluded.payload_json
            "#,
            params![
                state.name,
                state.kind.as_str(),
                state.target_did,
                to_i64(state.name_seq, "name_seq")?,
                to_i64(state.set_at, "set_at")?,
                to_json(state)?
            ],
        )?;
        Ok(())
    }

    fn get_alias_state(&self, name: &str) -> BnsIndexerResult<Option<AliasState>> {
        let name = canonical_bns_name(name)?;
        let conn = self.conn()?;
        let payload = conn
            .query_row(
                "SELECT payload_json FROM bns_aliases WHERE name = ?1",
                params![name],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        payload.as_deref().map(from_json).transpose()
    }

    fn put_purchase_context(&self, context: &PurchaseContext) -> BnsIndexerResult<()> {
        context.validate()?;
        let conn = self.conn()?;
        conn.execute(
            r#"
            INSERT INTO bns_purchase_contexts
                (content_name, doc_type, document_version, status, proof_root, payload_json)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(content_name, doc_type) DO UPDATE SET
                document_version = excluded.document_version,
                status = excluded.status,
                proof_root = excluded.proof_root,
                payload_json = excluded.payload_json
            "#,
            params![
                context.content_name,
                context.doc_type,
                to_i64(context.document_version, "document_version")?,
                context.status.as_str(),
                context.proof_root,
                to_json(context)?
            ],
        )?;
        Ok(())
    }

    fn get_purchase_context(
        &self,
        content_name: &str,
        doc_type: &str,
    ) -> BnsIndexerResult<Option<PurchaseContext>> {
        let content_name = canonical_bns_name(content_name)?;
        let doc_type = canonical_doc_type(doc_type)?;
        let conn = self.conn()?;
        let payload = conn
            .query_row(
                r#"
                SELECT payload_json
                FROM bns_purchase_contexts
                WHERE content_name = ?1 AND doc_type = ?2
                "#,
                params![content_name, doc_type],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        payload.as_deref().map(from_json).transpose()
    }

    fn record_contract_event(&self, event: &ContractEventEnvelope) -> BnsIndexerResult<()> {
        let conn = self.conn()?;
        conn.execute(
            r#"
            INSERT INTO bns_contract_events
                (source, block_number, block_hash, tx_hash, log_index, event_type,
                 observed_at, payload_json)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(source, block_number, tx_hash, log_index) DO UPDATE SET
                block_hash = excluded.block_hash,
                event_type = excluded.event_type,
                observed_at = excluded.observed_at,
                payload_json = excluded.payload_json
            "#,
            params![
                event.source,
                to_i64(event.block_number, "block_number")?,
                event.block_hash,
                event.tx_hash,
                to_i64(event.log_index, "log_index")?,
                event_type(event),
                to_i64(event.observed_at, "observed_at")?,
                to_json(event)?
            ],
        )?;
        Ok(())
    }

    fn list_contract_events(
        &self,
        source: &str,
        from_block: u64,
        limit: usize,
    ) -> BnsIndexerResult<Vec<ContractEventEnvelope>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT payload_json
            FROM bns_contract_events
            WHERE source = ?1 AND block_number >= ?2
            ORDER BY block_number, log_index
            LIMIT ?3
            "#,
        )?;
        let rows = stmt.query_map(
            params![
                source,
                to_i64(from_block, "from_block")?,
                to_i64(limit as u64, "limit")?
            ],
            |row| row.get::<_, String>(0),
        )?;

        let mut events = Vec::new();
        for row in rows {
            events.push(from_json(&row?)?);
        }
        Ok(events)
    }

    fn get_indexer_cursor(&self, source: &str) -> BnsIndexerResult<Option<IndexerCursor>> {
        let conn = self.conn()?;
        let payload = conn
            .query_row(
                "SELECT payload_json FROM bns_indexer_cursors WHERE source = ?1",
                params![source],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        payload.as_deref().map(from_json).transpose()
    }

    fn put_indexer_cursor(&self, cursor: &IndexerCursor) -> BnsIndexerResult<()> {
        let conn = self.conn()?;
        conn.execute(
            r#"
            INSERT INTO bns_indexer_cursors
                (source, block_number, block_hash, log_index, updated_at, payload_json)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(source) DO UPDATE SET
                block_number = excluded.block_number,
                block_hash = excluded.block_hash,
                log_index = excluded.log_index,
                updated_at = excluded.updated_at,
                payload_json = excluded.payload_json
            "#,
            params![
                cursor.source,
                to_i64(cursor.block_number, "block_number")?,
                cursor.block_hash,
                to_i64(cursor.log_index, "log_index")?,
                to_i64(cursor.updated_at, "updated_at")?,
                to_json(cursor)?
            ],
        )?;
        Ok(())
    }

    fn put_validation_report(&self, report: &ValidationReport) -> BnsIndexerResult<()> {
        let conn = self.conn()?;
        let target_kind = report.target.kind();
        let name = report.target.name();
        let doc_type = report.target.doc_type();
        let version = report
            .target
            .version()
            .map(|version| to_i64(version, "version"))
            .transpose()?;
        conn.execute(
            r#"
            INSERT INTO bns_validation_reports
                (target_kind, name, doc_type, version, checked_at, status,
                 mismatch_count, payload_json)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                target_kind,
                name,
                doc_type,
                version,
                to_i64(report.checked_at, "checked_at")?,
                report.status.as_str(),
                to_i64(report.mismatch_count() as u64, "mismatch_count")?,
                to_json(report)?
            ],
        )?;
        Ok(())
    }

    fn list_validation_reports(&self, limit: usize) -> BnsIndexerResult<Vec<ValidationReport>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT payload_json
            FROM bns_validation_reports
            ORDER BY id DESC
            LIMIT ?1
            "#,
        )?;
        let rows = stmt.query_map(params![to_i64(limit as u64, "limit")?], |row| {
            row.get::<_, String>(0)
        })?;

        let mut reports = Vec::new();
        for row in rows {
            reports.push(from_json(&row?)?);
        }
        Ok(reports)
    }
}

fn to_json<T: Serialize>(value: &T) -> BnsIndexerResult<String> {
    Ok(serde_json::to_string(value)?)
}

fn from_json<T: DeserializeOwned>(value: &str) -> BnsIndexerResult<T> {
    Ok(serde_json::from_str(value)?)
}

fn to_i64(value: u64, field: &'static str) -> BnsIndexerResult<i64> {
    if value > i64::MAX as u64 {
        return Err(BnsIndexerError::IntegerOutOfRange { field, value });
    }
    Ok(value as i64)
}

fn document_key_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DocumentKey> {
    let version: i64 = row.get(2)?;
    Ok(DocumentKey {
        name: row.get(0)?,
        doc_type: row.get(1)?,
        version: version as u64,
    })
}

fn event_type(event: &ContractEventEnvelope) -> &'static str {
    match &event.event {
        crate::ContractEvent::NameRegistered { .. } => "name_registered",
        crate::ContractEvent::NameRenewed { .. } => "name_renewed",
        crate::ContractEvent::NameTransferred { .. } => "name_transferred",
        crate::ContractEvent::NameReleased { .. } => "name_released",
        crate::ContractEvent::DocumentPublished { .. } => "document_published",
        crate::ContractEvent::DocumentRevoked { .. } => "document_revoked",
        crate::ContractEvent::ControllerPolicyUpdated { .. } => "controller_policy_updated",
        crate::ContractEvent::NamespacePolicyUpdated { .. } => "namespace_policy_updated",
        crate::ContractEvent::OwnerKeyChanged { .. } => "owner_key_changed",
        crate::ContractEvent::DidAliasSet { .. } => "did_alias_set",
        crate::ContractEvent::PaymentTargetUpdated { .. } => "payment_target_updated",
    }
}
