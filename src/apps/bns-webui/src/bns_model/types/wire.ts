/**
 * 与 bns-server JSON **1:1** 的线上类型（snake_case）。
 *
 * 真值来源：
 * - `doc/BNS/BNS-API.md` §5
 * - `src/components/bns-client/src/rpc.rs`（请求/响应结构）
 * - `src/components/bns-client/src/model.rs`（投影数据结构）
 *
 * 这一层不做任何语义加工：
 * - Rust `u64` / `u32` / `usize` 都是 JSON number；是否安全由 infra/numeric 校验；
 * - Rust `Vec<u8>` 是 JSON number[]，不是 base64；
 * - bytes32 字段在投影里已经是 `0x` + 64 hex 字符串（`storage_type` 例外，见下）。
 */

export type WireNameStatus = 'available' | 'active' | 'expired' | 'released' | 'tombstoned'

export type WireDocumentStatus =
  | 'missing'
  | 'active'
  | 'revoked'
  | 'expired'
  | 'migrated'
  | 'tombstoned'

export type WireAliasKind = 'none' | 'alias' | 'migrated_to' | 'canonical'

export type WirePrincipalKind = 'unset' | 'chain_account' | 'bns_name'

export type WireOwnerSource =
  | 'none'
  | 'asset_owner_fallback'
  | 'explicit_semantic_owner'
  | 'parent_inherited'

export type WireAuthorityKeyStatus = 'missing' | 'active' | 'revoked' | 'expired'

export type WireReleaseMode = 'release_after_grace' | 'tombstone_forever'

export interface WirePrincipal {
  kind: WirePrincipalKind
  /** chain_account 为 `0x` 地址字符串，bns_name 为 canonical 名称，unset 为空串。 */
  value: string
}

export interface WireNameState {
  name: string
  asset_owner: string
  semantic_owner: WirePrincipal
  effective_owner: WirePrincipal
  owner_source: WireOwnerSource
  standard_transfer_enabled: boolean
  status: WireNameStatus
  registered_at: number
  expire_at: number
  grace_until: number
  updated_at: number
  name_seq: number
  owner_document_version: number
  min_document_iat: number
  owner_policy_seq: number
  lineage_epoch: number
  renewable: boolean
  transferable: boolean
  allow_delegated_subnames: boolean
  namespace_policy_hash: string
  payment_policy_hash: string
  alias_state_hash: string
}

export interface WireOwnerResolution {
  effective_owner: WirePrincipal
  source: WireOwnerSource
  authority_root: string
  authority_seq: number
}

export interface WireAuthoritySetState {
  name: string
  authority_seq: number
  authority_root: string
  active_key_count: number
}

export interface WireAuthorityKey {
  /** 投影中的 kid 是 bytes32 hex，而不是可读标签。 */
  kid: string
  verification_method: string
  key_data: number[]
  /** 位掩码：1 authentication / 2 recovery / 4 sign-document。 */
  purposes: number
  valid_from: number
  valid_until: number
  status: WireAuthorityKeyStatus
  metadata_hash: string
}

export interface WireDocumentRef {
  /**
   * 链上是 bytes32；投影会把可打印的 bytes32 还原成标签，
   * 所以 inline 文档这里是字符串 `"inline"`，其他情况可能是 `0x` hash。
   */
  storage_type: string
  uri: string
  inline_document: number[]
  content_hash: string
  schema: string
  codec: string
  extra_hash: string
}

export interface WireDocumentState {
  name: string
  doc_type: string
  version: number
  previous_version: number
  status: WireDocumentStatus
  document: WireDocumentRef
  controller: WirePrincipal
  beneficiary: WirePrincipal
  payment_target: string
  valid_from: number
  expire_at: number
  revoked_at: number
  controller_policy_hash: string
  payment_policy_hash: string
  split_policy_hash: string
  price_policy_hash: string
  rights_policy_hash: string
  document_state_hash: string
}

export interface WireResolveResult {
  name_state: WireNameState
  document_state: WireDocumentState
  owner: WireOwnerResolution
  effective_controller: WirePrincipal
  status: WireDocumentStatus
  alias_kind: WireAliasKind
  alias_target_did: string
  proof_root: string
}

export interface WireNamePage {
  names: string[]
  next_cursor: string | null
}

export type WireTxExecutionState = 'not_found' | 'pending' | 'succeeded' | 'reverted'

export interface WireTxState {
  tx_hash: string
  state: WireTxExecutionState
  block_number: number | null
  confirmations: number
}

export interface WireSystemInfo {
  ready: boolean
  chain_id: number
  contract_address: string
}

export interface WirePrepareTxResp {
  nonce: number
  chain_id: number
  contract_address: string
  estimated_gas: number
  gas_limit: number
  max_fee_per_gas: number
  max_priority_fee_per_gas: number
}

export interface WireLogCheckpoint {
  log_root: string
  last_seq: number
  issued_at: number
  issuer: WirePrincipal
  external_anchor: string
}

/**
 * `RegistryEvent` 的 serde 形式：`#[serde(tag = "type", content = "data")]`。
 *
 * 注意 `EventLogRecord.event_type`（外层）与 `event.type`（内层）可能不同：
 * `owner_document_iat_floor_updated` 的外层值是 `owner_iat_floor_updated`。
 * 消费方一律以内层 `event.type` 为准。
 */
export type WireRegistryEvent =
  | { type: 'name_registered'; data: { name: string; asset_owner: string; expire_at: number; lineage_epoch: number; name_seq: number } }
  | { type: 'name_renewed'; data: { name: string; expire_at: number; name_seq: number } }
  | { type: 'name_asset_transferred'; data: { name: string; old_asset_owner: string; new_asset_owner: string; standard_transfer: boolean; name_seq: number } }
  | { type: 'name_owner_updated'; data: { name: string; owner: WirePrincipal; owner_source: WireOwnerSource; standard_transfer_enabled: boolean; name_seq: number } }
  | { type: 'authority_keys_updated'; data: { name: string; authority_seq: number; authority_root: string } }
  | { type: 'name_released'; data: { name: string; mode: WireReleaseMode; reason_hash: string; name_seq: number } }
  | { type: 'document_published'; data: { name: string; doc_type: string; version: number; content_hash: string; document_state_hash: string } }
  | { type: 'document_revoked'; data: { name: string; doc_type: string; previous_version: number; new_version: number; reason_hash: string } }
  | { type: 'owner_document_iat_floor_updated'; data: { name: string; previous_min_document_iat: number; new_min_document_iat: number; owner_policy_seq: number; name_seq: number; reason_hash: string } }
  | { type: 'controller_policy_updated'; data: { name: string; policy_hash: string; name_seq: number } }
  | { type: 'namespace_policy_updated'; data: { name: string; allow_delegated_subnames: boolean; namespace_policy_hash: string; name_seq: number } }
  | { type: 'did_alias_set'; data: { name: string; target_did: string; kind: WireAliasKind; proof_hash: string; name_seq: number } }
  | { type: 'payment_target_updated'; data: { name: string; doc_type: string; payment_target: string; payment_policy_hash: string; version: number } }
  | { type: 'log_checkpoint_published'; data: { log_root: string; last_seq: number; issued_at: number; external_anchor: string } }

export type WireEventType = WireRegistryEvent['type']

export interface WireEventLogRecord {
  seq: number
  event_type: string
  observed_at: number
  event_hash: string
  previous_log_root: string
  log_root: string
  event: WireRegistryEvent
}

export interface WireRpcErrorInfo {
  code: string
  message: string
  name: string | null
  doc_type: string | null
  expected: number | null
  actual: number | null
}

export interface WireRpcEnvelope<T> {
  ok: boolean
  result: T | null
  error: WireRpcErrorInfo | null
}
