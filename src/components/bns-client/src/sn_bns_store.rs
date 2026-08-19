use crate::{
    BnsWriteOperation, BnsWriteRequestState, SnBnsControllerError, SnBnsControllerResult,
    SnBnsTryBeginResult, SnBnsWriteRequestRecord, SnBnsWriteRequestStore,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;
use std::path::Path;
use std::sync::Mutex;

pub struct SqliteSnBnsWriteRequestStore {
    conn: Mutex<Connection>,
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
            "#,
        )
        .map_err(|e| SnBnsControllerError::Store(e.to_string()))?;
        ensure_column(&conn, "evm_chain_id", "INTEGER NULL")?;
        ensure_column(&conn, "evm_nonce", "INTEGER NULL")?;
        ensure_column(&conn, "evm_tx_hash", "TEXT NULL")?;
        ensure_column(&conn, "evm_raw_tx", "TEXT NULL")?;
        ensure_column(&conn, "lease_owner", "TEXT NULL")?;
        ensure_column(&conn, "lease_expires_at", "INTEGER NULL")?;
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
        if record.state != BnsWriteRequestState::Pending {
            return Err(SnBnsControllerError::Store(
                "try_begin requires a pending record".to_string(),
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

    fn save_prepared(&self, record: SnBnsWriteRequestRecord) -> SnBnsControllerResult<bool> {
        if record.state != BnsWriteRequestState::Pending
            || record.result_json.is_none()
            || record.evm_chain_id.is_none()
            || record.evm_nonce.is_none()
            || record.evm_tx_hash.is_none()
            || record.evm_raw_tx.is_none()
        {
            return Err(SnBnsControllerError::Store(
                "save_prepared requires pending state, provisional result and complete EVM metadata"
                    .to_string(),
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
        let result_json = record
            .result_json
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| SnBnsControllerError::Store(e.to_string()))?;
        let updated = conn
            .execute(
                "UPDATE sn_bns_write_requests SET
                    operation = ?2,
                    name = ?3,
                    doc_type = ?4,
                    result_json = ?5,
                    error_code = NULL,
                    error_message = NULL,
                    evm_chain_id = ?6,
                    evm_nonce = ?7,
                    evm_tx_hash = ?8,
                    evm_raw_tx = ?9,
                    updated_at = ?10
                 WHERE request_id = ?1
                   AND payload_hash = ?11
                   AND state = 'pending'
                   AND evm_tx_hash IS NULL
                   AND lease_owner = ?12",
                params![
                    record.request_id,
                    operation,
                    record.name,
                    record.doc_type,
                    result_json,
                    record.evm_chain_id.map(|value| value as i64),
                    record.evm_nonce.map(|value| value as i64),
                    record.evm_tx_hash,
                    record.evm_raw_tx,
                    record.updated_at as i64,
                    record.payload_hash,
                    record.lease_owner,
                ],
            )
            .map_err(|e| SnBnsControllerError::Store(e.to_string()))?;
        Ok(updated == 1)
    }

    fn try_takeover(
        &self,
        request_id: &str,
        payload_hash: &str,
        lease_owner: &str,
        lease_expires_at: u64,
        now: u64,
    ) -> SnBnsControllerResult<Option<SnBnsWriteRequestRecord>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| SnBnsControllerError::Store("sqlite store lock poisoned".to_string()))?;
        let updated = conn
            .execute(
                "UPDATE sn_bns_write_requests SET
                    lease_owner = ?3,
                    lease_expires_at = ?4,
                    updated_at = ?5
                 WHERE request_id = ?1
                   AND payload_hash = ?2
                   AND state = 'pending'
                   AND COALESCE(lease_expires_at, 0) <= ?5",
                params![
                    request_id,
                    payload_hash,
                    lease_owner,
                    lease_expires_at as i64,
                    now as i64,
                ],
            )
            .map_err(|e| SnBnsControllerError::Store(e.to_string()))?;
        drop(conn);
        if updated != 1 {
            return Ok(None);
        }
        self.get(request_id)
    }

    fn finish(&self, record: SnBnsWriteRequestRecord) -> SnBnsControllerResult<bool> {
        if record.state == BnsWriteRequestState::Pending {
            return Err(SnBnsControllerError::Store(
                "finish requires a terminal state".to_string(),
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
                   AND state = 'pending'
                   AND ((evm_tx_hash IS NULL AND ?15 IS NULL) OR evm_tx_hash = ?15)
                   AND ((lease_owner IS NULL AND ?16 IS NULL) OR lease_owner = ?16)",
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
                    record.lease_owner,
                ],
            )
            .map_err(|e| SnBnsControllerError::Store(e.to_string()))?;
        Ok(updated == 1)
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
