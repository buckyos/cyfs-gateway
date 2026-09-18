use crate::{
    BnsEvmPreparedTx, BnsWriteOperation, BnsWriteRequestState, SnBnsControllerError,
    SnBnsControllerResult, SnBnsTryBeginResult, SnBnsWriteRequestRecord, SnBnsWriteRequestStore,
    EVM_TX_RECOVERY_DATA_INVALID,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;
use std::path::Path;
use std::sync::Mutex;

pub struct SqliteSnBnsWriteRequestStore {
    conn: Mutex<Connection>,
    execution_lock: tokio::sync::Mutex<()>,
}

impl SqliteSnBnsWriteRequestStore {
    pub fn open(path: impl AsRef<Path>) -> SnBnsControllerResult<Self> {
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| SnBnsControllerError::Store(e.to_string()))?;
            }
        }

        let conn =
            Connection::open(path).map_err(|e| SnBnsControllerError::Store(e.to_string()))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| SnBnsControllerError::Store(e.to_string()))?;
        let store = Self {
            conn: Mutex::new(conn),
            execution_lock: tokio::sync::Mutex::new(()),
        };
        store.initialize_schema()?;
        Ok(store)
    }

    fn initialize_schema(&self) -> SnBnsControllerResult<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| SnBnsControllerError::Store("sqlite store lock poisoned".to_string()))?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS sn_bns_write_requests (
                request_id TEXT PRIMARY KEY,
                operation TEXT NOT NULL,
                name TEXT NOT NULL,
                doc_type TEXT NULL,
                payload_hash TEXT NOT NULL,
                state TEXT NOT NULL,
                result_json TEXT NULL,
                error_code TEXT NULL,
                error_message TEXT NULL,
                lease_owner TEXT NULL,
                lease_expires_at INTEGER NULL,
                evm_chain_id INTEGER NULL,
                evm_nonce INTEGER NULL,
                evm_tx_hash TEXT NULL,
                evm_raw_tx TEXT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_sn_bns_write_requests_name
                ON sn_bns_write_requests (name, operation, state);

            CREATE TABLE IF NOT EXISTS sn_bns_write_store_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            "#,
        )
        .map_err(|e| SnBnsControllerError::Store(e.to_string()))?;
        ensure_column(&conn, "evm_chain_id", "INTEGER NULL")?;
        ensure_column(&conn, "evm_nonce", "INTEGER NULL")?;
        ensure_column(&conn, "evm_tx_hash", "TEXT NULL")?;
        ensure_column(&conn, "evm_raw_tx", "TEXT NULL")?;
        ensure_column(&conn, "lease_owner", "TEXT NULL")?;
        ensure_column(&conn, "lease_expires_at", "INTEGER NULL")?;
        conn.execute_batch(
            r#"
            BEGIN IMMEDIATE;

            UPDATE sn_bns_write_requests
               SET state = 'pending'
             WHERE state = 'succeeded'
               AND evm_tx_hash IS NOT NULL
               AND evm_raw_tx IS NOT NULL
               AND NOT EXISTS (
                    SELECT 1 FROM sn_bns_write_store_meta
                     WHERE key = 'tx_state_model' AND value = '2'
               );

            UPDATE sn_bns_write_requests
               SET state = 'reverted'
             WHERE state = 'failed'
               AND error_code = 'EVM_TX_REVERTED'
               AND NOT EXISTS (
                    SELECT 1 FROM sn_bns_write_store_meta
                     WHERE key = 'tx_state_model' AND value = '2'
               );

            DELETE FROM sn_bns_write_requests
             WHERE state = 'pending'
               AND evm_tx_hash IS NULL
               AND evm_raw_tx IS NULL
               AND NOT EXISTS (
                    SELECT 1 FROM sn_bns_write_store_meta
                     WHERE key = 'tx_state_model' AND value = '2'
               );

            INSERT INTO sn_bns_write_store_meta (key, value)
            VALUES ('tx_state_model', '2')
            ON CONFLICT(key) DO UPDATE SET value = excluded.value;

            COMMIT;
            "#,
        )
        .map_err(|e| SnBnsControllerError::Store(e.to_string()))?;
        Ok(())
    }

    fn parse_operation(value: String) -> SnBnsControllerResult<BnsWriteOperation> {
        serde_json::from_value(Value::String(value))
            .map_err(|e| SnBnsControllerError::Store(format!("parse operation failed: {}", e)))
    }

    fn parse_state(value: String) -> SnBnsControllerResult<BnsWriteRequestState> {
        serde_json::from_value(Value::String(value))
            .map_err(|e| SnBnsControllerError::Store(format!("parse state failed: {}", e)))
    }
}

impl SnBnsWriteRequestStore for SqliteSnBnsWriteRequestStore {
    fn execution_lock(&self) -> &tokio::sync::Mutex<()> {
        &self.execution_lock
    }

    fn get(&self, request_id: &str) -> SnBnsControllerResult<Option<SnBnsWriteRequestRecord>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| SnBnsControllerError::Store("sqlite store lock poisoned".to_string()))?;
        let record = conn
            .query_row(
                "SELECT request_id, operation, name, doc_type, payload_hash, state,
                        result_json, error_code, error_message,
                        lease_owner, lease_expires_at,
                        evm_chain_id, evm_nonce, evm_tx_hash, evm_raw_tx,
                        created_at, updated_at
                 FROM sn_bns_write_requests
                 WHERE request_id = ?1",
                params![request_id],
                |row| {
                    let result_json: Option<String> = row.get(6)?;
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        result_json,
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, Option<String>>(8)?,
                        row.get::<_, Option<String>>(9)?,
                        row.get::<_, Option<i64>>(10)?,
                        row.get::<_, Option<i64>>(11)?,
                        row.get::<_, Option<i64>>(12)?,
                        row.get::<_, Option<String>>(13)?,
                        row.get::<_, Option<String>>(14)?,
                        row.get::<_, i64>(15)?,
                        row.get::<_, i64>(16)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| SnBnsControllerError::Store(e.to_string()))?;

        record
            .map(
                |(
                    request_id,
                    operation,
                    name,
                    doc_type,
                    payload_hash,
                    state,
                    result_json,
                    error_code,
                    error_message,
                    lease_owner,
                    lease_expires_at,
                    evm_chain_id,
                    evm_nonce,
                    evm_tx_hash,
                    evm_raw_tx,
                    created_at,
                    updated_at,
                )| {
                    Ok(SnBnsWriteRequestRecord {
                        request_id,
                        operation: Self::parse_operation(operation)?,
                        name,
                        doc_type,
                        payload_hash,
                        state: Self::parse_state(state)?,
                        result_json: result_json
                            .map(|value| serde_json::from_str(value.as_str()))
                            .transpose()
                            .map_err(|e| {
                                SnBnsControllerError::Store(format!(
                                    "parse result_json failed: {}",
                                    e
                                ))
                            })?,
                        error_code,
                        error_message,
                        lease_owner,
                        lease_expires_at: lease_expires_at.map(|value| value.max(0) as u64),
                        evm_chain_id: evm_chain_id.map(|value| value.max(0) as u64),
                        evm_nonce: evm_nonce.map(|value| value.max(0) as u64),
                        evm_tx_hash,
                        evm_raw_tx,
                        created_at: created_at.max(0) as u64,
                        updated_at: updated_at.max(0) as u64,
                    })
                },
            )
            .transpose()
    }

    fn try_begin(
        &self,
        record: SnBnsWriteRequestRecord,
    ) -> SnBnsControllerResult<SnBnsTryBeginResult> {
        if record.state != BnsWriteRequestState::Sending
            || record.result_json.is_none()
            || record.evm_chain_id.is_none()
            || record.evm_nonce.is_none()
            || record.evm_tx_hash.is_none()
            || record.evm_raw_tx.is_none()
        {
            return Err(SnBnsControllerError::Store(
                "try_begin requires a fully prepared sending record".to_string(),
            ));
        }
        let conn = self
            .conn
            .lock()
            .map_err(|_| SnBnsControllerError::Store("sqlite store lock poisoned".to_string()))?;
        let operation = serde_json::to_value(record.operation)
            .ok()
            .and_then(|value| value.as_str().map(ToString::to_string))
            .unwrap_or_else(|| record.operation.as_str().to_string());
        let state = serde_json::to_value(record.state)
            .ok()
            .and_then(|value| value.as_str().map(ToString::to_string))
            .unwrap_or_else(|| format!("{:?}", record.state).to_ascii_lowercase());
        let result_json = record
            .result_json
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| SnBnsControllerError::Store(e.to_string()))?;

        let request_id = record.request_id.clone();
        let inserted = conn
            .execute(
                "INSERT INTO sn_bns_write_requests
                (request_id, operation, name, doc_type, payload_hash, state,
                 result_json, error_code, error_message,
                 lease_owner, lease_expires_at,
                 evm_chain_id, evm_nonce, evm_tx_hash, evm_raw_tx,
                 created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
             ON CONFLICT(request_id) DO NOTHING",
                params![
                    record.request_id,
                    operation,
                    record.name,
                    record.doc_type,
                    record.payload_hash,
                    state,
                    result_json,
                    record.error_code,
                    record.error_message,
                    record.lease_owner,
                    record.lease_expires_at.map(|value| value as i64),
                    record.evm_chain_id.map(|value| value as i64),
                    record.evm_nonce.map(|value| value as i64),
                    record.evm_tx_hash,
                    record.evm_raw_tx,
                    record.created_at as i64,
                    record.updated_at as i64,
                ],
            )
            .map_err(|e| SnBnsControllerError::Store(e.to_string()))?;
        drop(conn);

        if inserted == 1 {
            return Ok(SnBnsTryBeginResult::Acquired);
        }
        self.get(request_id.as_str())?
            .map(SnBnsTryBeginResult::Existing)
            .ok_or_else(|| {
                SnBnsControllerError::Store(format!(
                    "request `{request_id}` conflicted but could not be reloaded"
                ))
            })
    }

    fn list_inflight(&self) -> SnBnsControllerResult<Vec<SnBnsWriteRequestRecord>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| SnBnsControllerError::Store("sqlite store lock poisoned".to_string()))?;
        let mut statement = conn
            .prepare(
                "SELECT request_id, operation, name, doc_type, payload_hash, state,
                        result_json, error_code, error_message,
                        lease_owner, lease_expires_at,
                        evm_chain_id, evm_nonce, evm_tx_hash, evm_raw_tx,
                        created_at, updated_at
                 FROM sn_bns_write_requests
                 WHERE state IN ('sending', 'pending')
                 ORDER BY created_at, request_id",
            )
            .map_err(|e| SnBnsControllerError::Store(e.to_string()))?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<i64>>(10)?,
                    row.get::<_, Option<i64>>(11)?,
                    row.get::<_, Option<i64>>(12)?,
                    row.get::<_, Option<String>>(13)?,
                    row.get::<_, Option<String>>(14)?,
                    row.get::<_, i64>(15)?,
                    row.get::<_, i64>(16)?,
                ))
            })
            .map_err(|e| SnBnsControllerError::Store(e.to_string()))?;
        let mut records = Vec::new();
        for row in rows {
            let (
                request_id,
                operation,
                name,
                doc_type,
                payload_hash,
                state,
                result_json,
                error_code,
                error_message,
                lease_owner,
                lease_expires_at,
                evm_chain_id,
                evm_nonce,
                evm_tx_hash,
                evm_raw_tx,
                created_at,
                updated_at,
            ) = row.map_err(|e| SnBnsControllerError::Store(e.to_string()))?;
            records.push(SnBnsWriteRequestRecord {
                request_id,
                operation: Self::parse_operation(operation)?,
                name,
                doc_type,
                payload_hash,
                state: Self::parse_state(state)?,
                result_json: result_json
                    .map(|value| serde_json::from_str(value.as_str()))
                    .transpose()
                    .map_err(|e| {
                        SnBnsControllerError::Store(format!("parse result_json failed: {}", e))
                    })?,
                error_code,
                error_message,
                lease_owner,
                lease_expires_at: lease_expires_at.map(|value| value.max(0) as u64),
                evm_chain_id: evm_chain_id.map(|value| value.max(0) as u64),
                evm_nonce: evm_nonce.map(|value| value.max(0) as u64),
                evm_tx_hash,
                evm_raw_tx,
                created_at: created_at.max(0) as u64,
                updated_at: updated_at.max(0) as u64,
            });
        }
        Ok(records)
    }

    fn update_inflight(&self, record: SnBnsWriteRequestRecord) -> SnBnsControllerResult<bool> {
        if record.state == BnsWriteRequestState::Sending {
            return Err(SnBnsControllerError::Store(
                "update_inflight cannot transition back to sending".to_string(),
            ));
        }
        let conn = self
            .conn
            .lock()
            .map_err(|_| SnBnsControllerError::Store("sqlite store lock poisoned".to_string()))?;
        let operation = serde_json::to_value(record.operation)
            .ok()
            .and_then(|value| value.as_str().map(ToString::to_string))
            .unwrap_or_else(|| record.operation.as_str().to_string());
        let state = serde_json::to_value(record.state)
            .ok()
            .and_then(|value| value.as_str().map(ToString::to_string))
            .unwrap_or_else(|| format!("{:?}", record.state).to_ascii_lowercase());
        let result_json = record
            .result_json
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| SnBnsControllerError::Store(e.to_string()))?;
        let expected_tx_hash = record.evm_tx_hash.clone();
        let expected_raw_tx = record.evm_raw_tx.clone();
        let updated = conn
            .execute(
                "UPDATE sn_bns_write_requests SET
                    operation = ?2,
                    name = ?3,
                    doc_type = ?4,
                    state = ?5,
                    result_json = ?6,
                    error_code = ?7,
                    error_message = ?8,
                    evm_chain_id = ?9,
                    evm_nonce = ?10,
                    evm_tx_hash = ?11,
                    evm_raw_tx = ?12,
                    updated_at = ?13
                 WHERE request_id = ?1
                   AND payload_hash = ?14
                   AND state IN ('sending', 'pending')
                   AND ((evm_tx_hash IS NULL AND ?15 IS NULL) OR evm_tx_hash = ?15)
                   AND ((evm_raw_tx IS NULL AND ?16 IS NULL) OR evm_raw_tx = ?16)
                   AND ((lease_owner IS NULL AND ?17 IS NULL) OR lease_owner = ?17)",
                params![
                    record.request_id,
                    operation,
                    record.name,
                    record.doc_type,
                    state,
                    result_json,
                    record.error_code,
                    record.error_message,
                    record.evm_chain_id.map(|value| value as i64),
                    record.evm_nonce.map(|value| value as i64),
                    record.evm_tx_hash,
                    record.evm_raw_tx,
                    record.updated_at as i64,
                    record.payload_hash,
                    expected_tx_hash,
                    expected_raw_tx,
                    record.lease_owner,
                ],
            )
            .map_err(|e| SnBnsControllerError::Store(e.to_string()))?;
        Ok(updated == 1)
    }

    fn repair_prepared_metadata(
        &self,
        request_id: &str,
        payload_hash: &str,
        expected_raw_tx: &str,
        expected_tx_hash: Option<&str>,
        prepared: &BnsEvmPreparedTx,
        updated_at: u64,
    ) -> SnBnsControllerResult<bool> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| SnBnsControllerError::Store("sqlite store lock poisoned".to_string()))?;
        let updated = conn
            .execute(
                "UPDATE sn_bns_write_requests SET
                    evm_chain_id = ?4,
                    evm_nonce = ?5,
                    evm_tx_hash = ?6,
                    evm_raw_tx = ?7,
                    updated_at = ?8
                 WHERE request_id = ?1
                   AND payload_hash = ?2
                   AND state IN ('sending', 'pending')
                   AND evm_raw_tx = ?3
                   AND ((evm_tx_hash IS NULL AND ?9 IS NULL) OR evm_tx_hash = ?9)",
                params![
                    request_id,
                    payload_hash,
                    expected_raw_tx,
                    prepared.chain_id as i64,
                    prepared.nonce as i64,
                    prepared.tx_hash,
                    prepared.raw_tx,
                    updated_at as i64,
                    expected_tx_hash,
                ],
            )
            .map_err(|e| SnBnsControllerError::Store(e.to_string()))?;
        Ok(updated == 1)
    }

    fn resolve_recovery_failed(
        &self,
        record: SnBnsWriteRequestRecord,
    ) -> SnBnsControllerResult<bool> {
        if !matches!(
            record.state,
            BnsWriteRequestState::Pending
                | BnsWriteRequestState::Succeeded
                | BnsWriteRequestState::Reverted
        ) {
            return Err(SnBnsControllerError::Store(
                "resolve_recovery_failed requires a chain-derived state".to_string(),
            ));
        }
        let conn = self
            .conn
            .lock()
            .map_err(|_| SnBnsControllerError::Store("sqlite store lock poisoned".to_string()))?;
        let state = serde_json::to_value(record.state)
            .ok()
            .and_then(|value| value.as_str().map(ToString::to_string))
            .unwrap_or_else(|| format!("{:?}", record.state).to_ascii_lowercase());
        let updated = conn
            .execute(
                "UPDATE sn_bns_write_requests SET
                    state = ?2,
                    error_code = ?3,
                    error_message = ?4,
                    updated_at = ?5
                 WHERE request_id = ?1
                   AND state = 'failed'
                   AND error_code = ?6
                   AND payload_hash = ?7
                   AND ((evm_tx_hash IS NULL AND ?8 IS NULL) OR evm_tx_hash = ?8)
                   AND ((evm_raw_tx IS NULL AND ?9 IS NULL) OR evm_raw_tx = ?9)",
                params![
                    record.request_id,
                    state,
                    record.error_code,
                    record.error_message,
                    record.updated_at as i64,
                    EVM_TX_RECOVERY_DATA_INVALID,
                    record.payload_hash,
                    record.evm_tx_hash,
                    record.evm_raw_tx,
                ],
            )
            .map_err(|e| SnBnsControllerError::Store(e.to_string()))?;
        Ok(updated == 1)
    }

    fn remove_recovery_failed(
        &self,
        request_id: &str,
        payload_hash: &str,
        tx_hash: Option<&str>,
        raw_tx: Option<&str>,
    ) -> SnBnsControllerResult<bool> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| SnBnsControllerError::Store("sqlite store lock poisoned".to_string()))?;
        let removed = conn
            .execute(
                "DELETE FROM sn_bns_write_requests
                 WHERE request_id = ?1
                   AND payload_hash = ?2
                   AND state = 'failed'
                   AND error_code = ?3
                   AND ((evm_tx_hash IS NULL AND ?4 IS NULL) OR evm_tx_hash = ?4)
                   AND ((evm_raw_tx IS NULL AND ?5 IS NULL) OR evm_raw_tx = ?5)",
                params![
                    request_id,
                    payload_hash,
                    EVM_TX_RECOVERY_DATA_INVALID,
                    tx_hash,
                    raw_tx,
                ],
            )
            .map_err(|e| SnBnsControllerError::Store(e.to_string()))?;
        Ok(removed == 1)
    }

    fn remove_unprepared(
        &self,
        request_id: &str,
        payload_hash: &str,
    ) -> SnBnsControllerResult<bool> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| SnBnsControllerError::Store("sqlite store lock poisoned".to_string()))?;
        let removed = conn
            .execute(
                "DELETE FROM sn_bns_write_requests
                 WHERE request_id = ?1
                   AND payload_hash = ?2
                   AND state IN ('sending', 'pending')
                   AND evm_tx_hash IS NULL
                   AND evm_raw_tx IS NULL",
                params![request_id, payload_hash],
            )
            .map_err(|e| SnBnsControllerError::Store(e.to_string()))?;
        Ok(removed == 1)
    }
}

fn ensure_column(conn: &Connection, column: &str, column_def: &str) -> SnBnsControllerResult<()> {
    let exists = conn
        .query_row(
            "SELECT 1 FROM pragma_table_info('sn_bns_write_requests') WHERE name = ?1",
            params![column],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|e| SnBnsControllerError::Store(e.to_string()))?;
    if exists.is_none() {
        conn.execute(
            &format!("ALTER TABLE sn_bns_write_requests ADD COLUMN {column} {column_def}"),
            [],
        )
        .map_err(|e| SnBnsControllerError::Store(e.to_string()))?;
    }
    Ok(())
}
