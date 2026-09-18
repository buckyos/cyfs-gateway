/**
 * wire -> domain 映射。
 *
 * 这是 u64 安全层的唯一入口：所有从 bns-server 来的数值都要经过
 * `u64FromWire`，非安全整数在这里就会抛错，不会流进视图。
 */

import { bytesToUtf8, didBnsFromName, parseBnsName, wireBytes } from '../infra/codec'
import { u32FromWire, u64FromWire } from '../infra/numeric'
import type {
  AliasKind,
  AuthorityKey,
  AuthorityKeyView,
  AuthoritySetState,
  DerivedNameStatus,
  DocumentRef,
  DocumentState,
  DocumentStatus,
  EventRecord,
  LogCheckpoint,
  NameOverview,
  NamePage,
  NameState,
  OwnerResolution,
  PrepareTxResult,
  Principal,
  RegistryEvent,
  ResolveResult,
  SystemInfo,
  TxState,
} from '../types/domain'
import {
  KEY_PURPOSE_AUTHENTICATION,
  KEY_PURPOSE_RECOVERY,
  KEY_PURPOSE_SIGN_DOCUMENT,
} from '../types/domain'
import type {
  WireAuthorityKey,
  WireAuthoritySetState,
  WireDocumentRef,
  WireDocumentState,
  WireEventLogRecord,
  WireLogCheckpoint,
  WireNamePage,
  WireNameState,
  WireOwnerResolution,
  WirePrepareTxResp,
  WirePrincipal,
  WireRegistryEvent,
  WireResolveResult,
  WireSystemInfo,
  WireTxState,
} from '../types/wire'

export function mapPrincipal(wire: WirePrincipal): Principal {
  return { kind: wire.kind, value: wire.value }
}

export function mapSystemInfo(wire: WireSystemInfo): SystemInfo {
  return {
    ready: wire.ready,
    chainId: wire.chain_id,
    contractAddress: wire.contract_address,
  }
}

export function mapNameState(wire: WireNameState): NameState {
  const f = (value: unknown, field: string) => u64FromWire(value, `name_state.${field}`)
  return {
    name: wire.name,
    assetOwner: wire.asset_owner,
    semanticOwner: mapPrincipal(wire.semantic_owner),
    effectiveOwner: mapPrincipal(wire.effective_owner),
    ownerSource: wire.owner_source,
    standardTransferEnabled: wire.standard_transfer_enabled,
    status: wire.status,
    registeredAt: f(wire.registered_at, 'registered_at'),
    expireAt: f(wire.expire_at, 'expire_at'),
    graceUntil: f(wire.grace_until, 'grace_until'),
    updatedAt: f(wire.updated_at, 'updated_at'),
    nameSeq: f(wire.name_seq, 'name_seq'),
    ownerDocumentVersion: f(wire.owner_document_version, 'owner_document_version'),
    minDocumentIat: f(wire.min_document_iat, 'min_document_iat'),
    ownerPolicySeq: f(wire.owner_policy_seq, 'owner_policy_seq'),
    lineageEpoch: f(wire.lineage_epoch, 'lineage_epoch'),
    renewable: wire.renewable,
    transferable: wire.transferable,
    allowDelegatedSubnames: wire.allow_delegated_subnames,
    namespacePolicyHash: wire.namespace_policy_hash,
    paymentPolicyHash: wire.payment_policy_hash,
    aliasStateHash: wire.alias_state_hash,
  }
}

/**
 * 派生名称状态。
 *
 * 唯一的时间判定入口。`expireAt = 0` 视为不设截止（PRD 6.3）。
 */
export function deriveNameStatus(state: NameState, nowSeconds: bigint): DerivedNameStatus {
  const hasDeadline = state.expireAt !== 0n
  const timeExpired = hasDeadline && nowSeconds >= state.expireAt
  const inGrace = timeExpired && state.graceUntil !== 0n && nowSeconds < state.graceUntil
  const secondsToExpire = hasDeadline ? state.expireAt - nowSeconds : null

  let label: DerivedNameStatus['label']
  switch (state.status) {
    case 'available':
      label = 'unregistered'
      break
    case 'active':
      label = timeExpired ? 'active_time_expired' : 'active'
      break
    case 'expired':
      label = 'expired'
      break
    case 'released':
      label = 'released'
      break
    case 'tombstoned':
      label = 'tombstoned'
      break
  }

  return { raw: state.status, timeExpired, inGrace, secondsToExpire, label }
}

export function mapNameOverview(wire: WireNameState, nowSeconds: bigint): NameOverview {
  const state = mapNameState(wire)
  const parsed = parseBnsName(state.name)
  return {
    state,
    derived: deriveNameStatus(state, nowSeconds),
    did: didBnsFromName(state.name),
    isTopLevel: parsed.isTopLevel,
    parent: parsed.parent,
  }
}

export function mapOwnerResolution(wire: WireOwnerResolution): OwnerResolution {
  return {
    effectiveOwner: mapPrincipal(wire.effective_owner),
    source: wire.source,
    authorityRoot: wire.authority_root,
    authoritySeq: u64FromWire(wire.authority_seq, 'owner.authority_seq'),
  }
}

export function mapAuthoritySet(wire: WireAuthoritySetState): AuthoritySetState {
  return {
    name: wire.name,
    authoritySeq: u64FromWire(wire.authority_seq, 'authority_set.authority_seq'),
    authorityRoot: wire.authority_root,
    activeKeyCount: u32FromWire(wire.active_key_count, 'authority_set.active_key_count'),
  }
}

export function mapAuthorityKey(wire: WireAuthorityKey): AuthorityKey {
  return {
    kid: wire.kid,
    verificationMethod: wire.verification_method,
    keyData: wireBytes(wire.key_data),
    purposes: u32FromWire(wire.purposes, 'authority_key.purposes'),
    validFrom: u64FromWire(wire.valid_from, 'authority_key.valid_from'),
    validUntil: u64FromWire(wire.valid_until, 'authority_key.valid_until'),
    status: wire.status,
    metadataHash: wire.metadata_hash,
  }
}

export function toAuthorityKeyView(key: AuthorityKey, nowSeconds: bigint): AuthorityKeyView {
  const withinWindow =
    key.validFrom <= nowSeconds && (key.validUntil === 0n || nowSeconds < key.validUntil)
  let addressFromKeyData: string | null = null
  if (key.keyData.length === 20) {
    let hex = '0x'
    for (const byte of key.keyData) hex += byte.toString(16).padStart(2, '0')
    addressFromKeyData = hex
  }
  return {
    ...key,
    purposeFlags: {
      authentication: (key.purposes & KEY_PURPOSE_AUTHENTICATION) !== 0,
      recovery: (key.purposes & KEY_PURPOSE_RECOVERY) !== 0,
      signDocument: (key.purposes & KEY_PURPOSE_SIGN_DOCUMENT) !== 0,
    },
    addressFromKeyData,
    usableNow: key.status === 'active' && withinWindow,
  }
}

export function mapDocumentRef(wire: WireDocumentRef): DocumentRef {
  return {
    storageType: wire.storage_type,
    uri: wire.uri,
    inlineDocument: wireBytes(wire.inline_document),
    contentHash: wire.content_hash,
    schema: wire.schema,
    codec: wire.codec,
    extraHash: wire.extra_hash,
  }
}

export function mapDocumentState(wire: WireDocumentState): DocumentState {
  const f = (value: unknown, field: string) => u64FromWire(value, `document_state.${field}`)
  return {
    name: wire.name,
    docType: wire.doc_type,
    version: f(wire.version, 'version'),
    previousVersion: f(wire.previous_version, 'previous_version'),
    status: wire.status,
    document: mapDocumentRef(wire.document),
    controller: mapPrincipal(wire.controller),
    beneficiary: mapPrincipal(wire.beneficiary),
    paymentTarget: wire.payment_target,
    validFrom: f(wire.valid_from, 'valid_from'),
    expireAt: f(wire.expire_at, 'expire_at'),
    revokedAt: f(wire.revoked_at, 'revoked_at'),
    controllerPolicyHash: wire.controller_policy_hash,
    paymentPolicyHash: wire.payment_policy_hash,
    splitPolicyHash: wire.split_policy_hash,
    pricePolicyHash: wire.price_policy_hash,
    rightsPolicyHash: wire.rights_policy_hash,
    documentStateHash: wire.document_state_hash,
  }
}

export function mapResolveResult(wire: WireResolveResult): ResolveResult {
  return {
    nameState: mapNameState(wire.name_state),
    documentState: mapDocumentState(wire.document_state),
    owner: mapOwnerResolution(wire.owner),
    effectiveController: mapPrincipal(wire.effective_controller),
    status: wire.status,
    aliasKind: wire.alias_kind,
    aliasTargetDid: wire.alias_target_did,
    proofRoot: wire.proof_root,
  }
}

/**
 * 与 bns-server DID Resolver 同口径的文档状态派生
 * （`did_resolver_document_status`，protocol §4）。
 *
 * 复制这段规则的理由：`document.resolve` 只返回 raw status，
 * 而页面需要和 DID Resolver 显示一致的结论。两者不一致时并列展示。
 */
export function deriveDocumentStatus(result: ResolveResult, nowSeconds: bigint): DocumentStatus {
  if (result.nameState.status === 'tombstoned') return 'tombstoned'
  if (result.status !== 'active') return result.status
  if (result.aliasKind === 'migrated_to' && result.aliasTargetDid.startsWith('did:')) {
    return 'migrated'
  }
  // 只看名称的 **raw status** 和文档自身的 expire_at；刻意不看名称的 expire_at。
  // 名称“时间上过期”是名称层面的派生标签（deriveNameStatus），不连坐文档 ——
  // 否则页面结论会和 DID Resolver 不一致。
  const nameLapsed = result.nameState.status === 'expired' || result.nameState.status === 'released'
  const docExpired =
    result.documentState.expireAt !== 0n && nowSeconds >= result.documentState.expireAt
  if (nameLapsed || docExpired) return 'expired'
  return 'active'
}

export function mapNamePage(wire: WireNamePage): NamePage {
  return { names: wire.names, nextCursor: wire.next_cursor }
}

export function mapTxState(wire: WireTxState): TxState {
  return {
    txHash: wire.tx_hash,
    state: wire.state,
    blockNumber: wire.block_number === null ? null : u64FromWire(wire.block_number, 'tx.block_number'),
    confirmations: u64FromWire(wire.confirmations, 'tx.confirmations'),
  }
}

export function mapPrepareTx(wire: WirePrepareTxResp): PrepareTxResult {
  const f = (value: unknown, field: string) => u64FromWire(value, `prepare_tx.${field}`)
  return {
    nonce: f(wire.nonce, 'nonce'),
    chainId: wire.chain_id,
    contractAddress: wire.contract_address,
    estimatedGas: f(wire.estimated_gas, 'estimated_gas'),
    gasLimit: f(wire.gas_limit, 'gas_limit'),
    // Rust 侧是 u128；当前链上 fee 远低于 2^53，越界会被 u64 安全层拦下而不是静默截断。
    maxFeePerGas: f(wire.max_fee_per_gas, 'max_fee_per_gas'),
    maxPriorityFeePerGas: f(wire.max_priority_fee_per_gas, 'max_priority_fee_per_gas'),
  }
}

export function mapCheckpoint(wire: WireLogCheckpoint): LogCheckpoint {
  return {
    logRoot: wire.log_root,
    lastSeq: u64FromWire(wire.last_seq, 'checkpoint.last_seq'),
    issuedAt: u64FromWire(wire.issued_at, 'checkpoint.issued_at'),
    issuer: mapPrincipal(wire.issuer),
    externalAnchor: wire.external_anchor,
  }
}

// ---------------------------------------------------------------------------
// 事件
// ---------------------------------------------------------------------------

export function mapEventRecord(wire: WireEventLogRecord): EventRecord {
  const event = mapRegistryEvent(wire.event)
  return {
    seq: u64FromWire(wire.seq, 'event.seq'),
    outerEventType: wire.event_type,
    observedAt: u64FromWire(wire.observed_at, 'event.observed_at'),
    eventHash: wire.event_hash,
    previousLogRoot: wire.previous_log_root,
    logRoot: wire.log_root,
    event,
    name: eventName(event),
  }
}

export function eventName(event: RegistryEvent): string | null {
  return event.type === 'log_checkpoint_published' ? null : event.data.name
}

function mapRegistryEvent(wire: WireRegistryEvent): RegistryEvent {
  const u = (value: unknown, field: string) => u64FromWire(value, `event.${wire.type}.${field}`)
  switch (wire.type) {
    case 'name_registered':
      return {
        type: 'name_registered',
        data: {
          name: wire.data.name,
          assetOwner: wire.data.asset_owner,
          expireAt: u(wire.data.expire_at, 'expire_at'),
          lineageEpoch: u(wire.data.lineage_epoch, 'lineage_epoch'),
          nameSeq: u(wire.data.name_seq, 'name_seq'),
        },
      }
    case 'name_renewed':
      return {
        type: 'name_renewed',
        data: {
          name: wire.data.name,
          expireAt: u(wire.data.expire_at, 'expire_at'),
          nameSeq: u(wire.data.name_seq, 'name_seq'),
        },
      }
    case 'name_asset_transferred':
      return {
        type: 'name_asset_transferred',
        data: {
          name: wire.data.name,
          oldAssetOwner: wire.data.old_asset_owner,
          newAssetOwner: wire.data.new_asset_owner,
          standardTransfer: wire.data.standard_transfer,
          nameSeq: u(wire.data.name_seq, 'name_seq'),
        },
      }
    case 'name_owner_updated':
      return {
        type: 'name_owner_updated',
        data: {
          name: wire.data.name,
          owner: mapPrincipal(wire.data.owner),
          ownerSource: wire.data.owner_source,
          standardTransferEnabled: wire.data.standard_transfer_enabled,
          nameSeq: u(wire.data.name_seq, 'name_seq'),
        },
      }
    case 'authority_keys_updated':
      return {
        type: 'authority_keys_updated',
        data: {
          name: wire.data.name,
          authoritySeq: u(wire.data.authority_seq, 'authority_seq'),
          authorityRoot: wire.data.authority_root,
        },
      }
    case 'name_released':
      return {
        type: 'name_released',
        data: {
          name: wire.data.name,
          mode: wire.data.mode,
          reasonHash: wire.data.reason_hash,
          nameSeq: u(wire.data.name_seq, 'name_seq'),
        },
      }
    case 'document_published':
      return {
        type: 'document_published',
        data: {
          name: wire.data.name,
          docType: wire.data.doc_type,
          version: u(wire.data.version, 'version'),
          contentHash: wire.data.content_hash,
          documentStateHash: wire.data.document_state_hash,
        },
      }
    case 'document_revoked':
      return {
        type: 'document_revoked',
        data: {
          name: wire.data.name,
          docType: wire.data.doc_type,
          previousVersion: u(wire.data.previous_version, 'previous_version'),
          newVersion: u(wire.data.new_version, 'new_version'),
          reasonHash: wire.data.reason_hash,
        },
      }
    case 'owner_document_iat_floor_updated':
      return {
        type: 'owner_document_iat_floor_updated',
        data: {
          name: wire.data.name,
          previousMinDocumentIat: u(wire.data.previous_min_document_iat, 'previous_min_document_iat'),
          newMinDocumentIat: u(wire.data.new_min_document_iat, 'new_min_document_iat'),
          ownerPolicySeq: u(wire.data.owner_policy_seq, 'owner_policy_seq'),
          nameSeq: u(wire.data.name_seq, 'name_seq'),
          reasonHash: wire.data.reason_hash,
        },
      }
    case 'controller_policy_updated':
      return {
        type: 'controller_policy_updated',
        data: {
          name: wire.data.name,
          policyHash: wire.data.policy_hash,
          nameSeq: u(wire.data.name_seq, 'name_seq'),
        },
      }
    case 'namespace_policy_updated':
      return {
        type: 'namespace_policy_updated',
        data: {
          name: wire.data.name,
          allowDelegatedSubnames: wire.data.allow_delegated_subnames,
          namespacePolicyHash: wire.data.namespace_policy_hash,
          nameSeq: u(wire.data.name_seq, 'name_seq'),
        },
      }
    case 'did_alias_set':
      return {
        type: 'did_alias_set',
        data: {
          name: wire.data.name,
          targetDid: wire.data.target_did,
          kind: wire.data.kind as AliasKind,
          proofHash: wire.data.proof_hash,
          nameSeq: u(wire.data.name_seq, 'name_seq'),
        },
      }
    case 'payment_target_updated':
      return {
        type: 'payment_target_updated',
        data: {
          name: wire.data.name,
          docType: wire.data.doc_type,
          paymentTarget: wire.data.payment_target,
          paymentPolicyHash: wire.data.payment_policy_hash,
          version: u(wire.data.version, 'version'),
        },
      }
    case 'log_checkpoint_published':
      return {
        type: 'log_checkpoint_published',
        data: {
          logRoot: wire.data.log_root,
          lastSeq: u(wire.data.last_seq, 'last_seq'),
          issuedAt: u(wire.data.issued_at, 'issued_at'),
          externalAnchor: wire.data.external_anchor,
        },
      }
  }
}

/** inline 文档解码：按不可信内容处理，只做解码，不做渲染决策。 */
export function decodeInlineDocument(ref: DocumentRef): {
  isInline: boolean
  text: string | null
  json: unknown | null
  byteLength: number
} {
  const isInline = ref.storageType === 'inline' && ref.inlineDocument.length > 0
  if (!isInline) {
    return { isInline: false, text: null, json: null, byteLength: ref.inlineDocument.length }
  }
  let text: string | null = null
  let json: unknown | null = null
  try {
    text = bytesToUtf8(ref.inlineDocument)
  } catch {
    text = null
  }
  if (text !== null) {
    try {
      json = JSON.parse(text)
    } catch {
      json = null
    }
  }
  return { isInline: true, text, json, byteLength: ref.inlineDocument.length }
}
