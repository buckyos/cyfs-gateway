use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{now_timestamp, BnsIndexerResult, DocumentKey, TruthSource};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    Consistent,
    MissingInContract,
    MissingInBnsDb,
    Mismatch,
}

impl ValidationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Consistent => "consistent",
            Self::MissingInContract => "missing_in_contract",
            Self::MissingInBnsDb => "missing_in_bns_db",
            Self::Mismatch => "mismatch",
        }
    }

    pub fn is_consistent(self) -> bool {
        self == Self::Consistent
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidationMismatch {
    pub path: String,
    pub bns_db: Value,
    pub contract: Value,
    pub severity: ValidationSeverity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ValidationTarget {
    Name {
        name: String,
    },
    Document {
        name: String,
        doc_type: String,
        version: u64,
    },
    Alias {
        name: String,
    },
    PurchaseContext {
        content_name: String,
        doc_type: String,
    },
}

impl ValidationTarget {
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Name { name } | Self::Alias { name } | Self::Document { name, .. } => Some(name),
            Self::PurchaseContext { content_name, .. } => Some(content_name),
        }
    }

    pub fn doc_type(&self) -> Option<&str> {
        match self {
            Self::Document { doc_type, .. } | Self::PurchaseContext { doc_type, .. } => {
                Some(doc_type)
            }
            _ => None,
        }
    }

    pub fn version(&self) -> Option<u64> {
        match self {
            Self::Document { version, .. } => Some(*version),
            _ => None,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::Name { .. } => "name",
            Self::Document { .. } => "document",
            Self::Alias { .. } => "alias",
            Self::PurchaseContext { .. } => "purchase_context",
        }
    }
}

impl From<DocumentKey> for ValidationTarget {
    fn from(value: DocumentKey) -> Self {
        Self::Document {
            name: value.name,
            doc_type: value.doc_type,
            version: value.version,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidationReport {
    pub target: ValidationTarget,
    pub checked_at: u64,
    pub truth_source: TruthSource,
    pub status: ValidationStatus,
    pub mismatches: Vec<ValidationMismatch>,
    pub notes: Vec<String>,
}

impl ValidationReport {
    pub fn consistent(target: ValidationTarget, truth_source: TruthSource) -> Self {
        Self {
            target,
            checked_at: now_timestamp(),
            truth_source,
            status: ValidationStatus::Consistent,
            mismatches: Vec::new(),
            notes: Vec::new(),
        }
    }

    pub fn mismatch_count(&self) -> usize {
        self.mismatches.len()
    }

    pub fn is_consistent(&self) -> bool {
        self.status.is_consistent()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationAction {
    Noop,
    PublishToContract,
    UpdateBnsDbFromContract,
    ManualReview,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconciliationPlan {
    pub target: ValidationTarget,
    pub truth_source: TruthSource,
    pub action: ReconciliationAction,
    pub reason: String,
}

pub fn compare_optional_projection<T>(
    target: ValidationTarget,
    truth_source: TruthSource,
    bns_db: Option<&T>,
    contract: Option<&T>,
) -> BnsIndexerResult<ValidationReport>
where
    T: Serialize,
{
    match (bns_db, contract) {
        (Some(left), Some(right)) => {
            let left = serde_json::to_value(left)?;
            let right = serde_json::to_value(right)?;
            let mismatches = compare_json("$", &left, &right);
            let status = if mismatches.is_empty() {
                ValidationStatus::Consistent
            } else {
                ValidationStatus::Mismatch
            };
            Ok(ValidationReport {
                target,
                checked_at: now_timestamp(),
                truth_source,
                status,
                mismatches,
                notes: Vec::new(),
            })
        }
        (Some(_), None) => Ok(ValidationReport {
            target,
            checked_at: now_timestamp(),
            truth_source,
            status: ValidationStatus::MissingInContract,
            mismatches: Vec::new(),
            notes: vec!["bns-db has the record but the contract view does not".to_string()],
        }),
        (None, Some(_)) => Ok(ValidationReport {
            target,
            checked_at: now_timestamp(),
            truth_source,
            status: ValidationStatus::MissingInBnsDb,
            mismatches: Vec::new(),
            notes: vec!["contract view has the record but bns-db does not".to_string()],
        }),
        (None, None) => Ok(ValidationReport::consistent(target, truth_source)),
    }
}

pub fn reconciliation_plan(report: &ValidationReport) -> ReconciliationPlan {
    let (action, reason) = match (report.truth_source, report.status) {
        (_, ValidationStatus::Consistent) => (
            ReconciliationAction::Noop,
            "bns-db and contract projections are aligned".to_string(),
        ),
        (TruthSource::BnsDb, ValidationStatus::MissingInContract) => (
            ReconciliationAction::PublishToContract,
            "bns-db is the configured truth source; contract should be updated".to_string(),
        ),
        (TruthSource::Contract, ValidationStatus::MissingInBnsDb) => (
            ReconciliationAction::UpdateBnsDbFromContract,
            "contract is the configured truth source; bns-db should be updated".to_string(),
        ),
        (TruthSource::Contract, ValidationStatus::Mismatch) => (
            ReconciliationAction::UpdateBnsDbFromContract,
            "contract is the configured truth source; bns-db projection differs".to_string(),
        ),
        _ => (
            ReconciliationAction::ManualReview,
            "state differs and cannot be reconciled safely without a writer policy".to_string(),
        ),
    };

    ReconciliationPlan {
        target: report.target.clone(),
        truth_source: report.truth_source,
        action,
        reason,
    }
}

fn compare_json(path: &str, left: &Value, right: &Value) -> Vec<ValidationMismatch> {
    match (left, right) {
        (Value::Object(left), Value::Object(right)) => {
            let mut keys: Vec<&String> = left.keys().chain(right.keys()).collect();
            keys.sort();
            keys.dedup();

            let mut mismatches = Vec::new();
            for key in keys {
                let next_path = format!("{}.{}", path, key);
                match (left.get(key), right.get(key)) {
                    (Some(left), Some(right)) => {
                        mismatches.extend(compare_json(&next_path, left, right));
                    }
                    (Some(left), None) => mismatches.push(ValidationMismatch {
                        path: next_path,
                        bns_db: left.clone(),
                        contract: Value::Null,
                        severity: ValidationSeverity::Error,
                    }),
                    (None, Some(right)) => mismatches.push(ValidationMismatch {
                        path: next_path,
                        bns_db: Value::Null,
                        contract: right.clone(),
                        severity: ValidationSeverity::Error,
                    }),
                    (None, None) => {}
                }
            }
            mismatches
        }
        (Value::Array(left), Value::Array(right)) => {
            let max = left.len().max(right.len());
            let mut mismatches = Vec::new();
            for index in 0..max {
                let next_path = format!("{}[{}]", path, index);
                match (left.get(index), right.get(index)) {
                    (Some(left), Some(right)) => {
                        mismatches.extend(compare_json(&next_path, left, right));
                    }
                    (Some(left), None) => mismatches.push(ValidationMismatch {
                        path: next_path,
                        bns_db: left.clone(),
                        contract: Value::Null,
                        severity: ValidationSeverity::Error,
                    }),
                    (None, Some(right)) => mismatches.push(ValidationMismatch {
                        path: next_path,
                        bns_db: Value::Null,
                        contract: right.clone(),
                        severity: ValidationSeverity::Error,
                    }),
                    (None, None) => {}
                }
            }
            mismatches
        }
        _ => {
            if left == right {
                Vec::new()
            } else {
                vec![ValidationMismatch {
                    path: path.to_string(),
                    bns_db: left.clone(),
                    contract: right.clone(),
                    severity: ValidationSeverity::Error,
                }]
            }
        }
    }
}
