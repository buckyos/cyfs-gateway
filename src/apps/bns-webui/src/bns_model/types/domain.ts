/**
 * 前端领域模型。
 *
 * 与 wire 层的差别：
 * - u64 一律是 `bigint`（表单内部也用 bigint，显示时才格式化）；
 * - `Vec<u8>` 是 `Uint8Array`；
 * - 字段名 camelCase；
 * - 额外携带 **派生** 字段。派生值永远和 raw 值并列存在，不覆盖 raw
 *   （PRD 12.1：raw status 与基于时间派生的状态必须同时可见）。
 */

import type {
  WireAliasKind,
  WireAuthorityKeyStatus,
  WireDocumentStatus,
  WireNameStatus,
  WireOwnerSource,
  WirePrincipalKind,
  WireReleaseMode,
  WireTxExecutionState,
} from './wire'

export type NameStatus = WireNameStatus
export type DocumentStatus = WireDocumentStatus
export type AliasKind = WireAliasKind
export type PrincipalKind = WirePrincipalKind
export type OwnerSource = WireOwnerSource
export type AuthorityKeyStatus = WireAuthorityKeyStatus
export type ReleaseMode = WireReleaseMode
export type TxExecutionState = WireTxExecutionState

export interface Principal {
  kind: PrincipalKind
  value: string
}

export interface SystemInfo {
  ready: boolean
  chainId: number
  contractAddress: string
}

// ---------------------------------------------------------------------------
// 名称
// ---------------------------------------------------------------------------

export interface NameState {
  name: string
  assetOwner: string
  semanticOwner: Principal
  effectiveOwner: Principal
  ownerSource: OwnerSource
  standardTransferEnabled: boolean
  status: NameStatus
  registeredAt: bigint
  expireAt: bigint
  graceUntil: bigint
  updatedAt: bigint
  nameSeq: bigint
  ownerDocumentVersion: bigint
  minDocumentIat: bigint
  ownerPolicySeq: bigint
  lineageEpoch: bigint
  renewable: boolean
  transferable: boolean
  allowDelegatedSubnames: boolean
  namespacePolicyHash: string
  paymentPolicyHash: string
  aliasStateHash: string
}

/**
 * 基于当前时间派生的名称状态。
 *
 * 合约不会因为时间流逝自动把 status 改成 Expired（PRD 6.4.1），
 * 所以“有效期已过”只能在读取时算出来，并且必须与 raw status 并列展示。
 */
export interface DerivedNameStatus {
  raw: NameStatus
  /** raw 仍是 active，但已越过 expire_at。 */
  timeExpired: boolean
  /** 越过 expire_at 但仍在 grace_until 之内。 */
  inGrace: boolean
  /** 剩余秒数；null 表示 expire_at = 0（不设截止）。 */
  secondsToExpire: bigint | null
  /** 给 UI 用的合成标签，仅用于展示，不参与任何鉴权判断。 */
  label:
    | 'unregistered'
    | 'active'
    | 'active_time_expired'
    | 'expired'
    | 'released'
    | 'tombstoned'
}

export interface NameOverview {
  state: NameState
  derived: DerivedNameStatus
  did: string
  isTopLevel: boolean
  parent: string | null
}

export interface OwnerResolution {
  effectiveOwner: Principal
  source: OwnerSource
  authorityRoot: string
  authoritySeq: bigint
}

export interface NamePage {
  names: string[]
  nextCursor: string | null
}

// ---------------------------------------------------------------------------
// Authority
// ---------------------------------------------------------------------------

export const KEY_PURPOSE_AUTHENTICATION = 1
export const KEY_PURPOSE_RECOVERY = 2
export const KEY_PURPOSE_SIGN_DOCUMENT = 4

export const PERMISSION_PUBLISH_DOCUMENT = 1
export const PERMISSION_REVOKE_DOCUMENT = 2
export const PERMISSION_SET_PAYMENT = 4
export const PERMISSION_SET_ALIAS = 8
export const PERMISSION_SET_NAMESPACE = 16

export interface AuthoritySetState {
  name: string
  authoritySeq: bigint
  authorityRoot: string
  activeKeyCount: number
}

export interface AuthorityKey {
  /** 投影里的 kid 是 bytes32 hex。 */
  kid: string
  verificationMethod: string
  keyData: Uint8Array
  purposes: number
  validFrom: bigint
  validUntil: bigint
  status: AuthorityKeyStatus
  metadataHash: string
}

export interface AuthorityKeyView extends AuthorityKey {
  purposeFlags: {
    authentication: boolean
    recovery: boolean
    signDocument: boolean
  }
  /**
   * key_data 恰好 20 字节时还原出的 EVM 地址。
   * 合约当前只用 20 字节地址 + Authentication bit 做 msg.sender 验证，
   * Recovery / SignDocument 不授予链上写权限（PRD 6.4.11）。
   */
  addressFromKeyData: string | null
  /** 处于 status=active 且在有效期窗口内。 */
  usableNow: boolean
}

// ---------------------------------------------------------------------------
// 文档
// ---------------------------------------------------------------------------

export interface DocumentRef {
  storageType: string
  uri: string
  inlineDocument: Uint8Array
  contentHash: string
  schema: string
  codec: string
  extraHash: string
}

export interface DocumentState {
  name: string
  docType: string
  version: bigint
  previousVersion: bigint
  status: DocumentStatus
  document: DocumentRef
  controller: Principal
  beneficiary: Principal
  paymentTarget: string
  validFrom: bigint
  expireAt: bigint
  revokedAt: bigint
  controllerPolicyHash: string
  paymentPolicyHash: string
  splitPolicyHash: string
  pricePolicyHash: string
  rightsPolicyHash: string
  documentStateHash: string
}

export interface ResolveResult {
  nameState: NameState
  documentState: DocumentState
  owner: OwnerResolution
  effectiveController: Principal
  status: DocumentStatus
  aliasKind: AliasKind
  aliasTargetDid: string
  proofRoot: string
}

export interface DocumentView {
  name: string
  docType: string
  /** 从未发布过该 doc_type 时为 null（DOCUMENT_NOT_FOUND 的缺失态）。 */
  state: DocumentState | null
  /** `document.resolve` 返回的 raw status。 */
  rawStatus: DocumentStatus
  /**
   * 与 DID Resolver 同口径的派生状态（结合名称状态、时间和 alias）。
   * 与 rawStatus 不一致时视图应并列展示，不覆盖原始数据（PRD 12.2）。
   */
  derivedStatus: DocumentStatus
  aliasKind: AliasKind
  aliasTargetDid: string
  isInline: boolean
  inlineText: string | null
  inlineJson: unknown | null
  inlineByteLength: number
  effectiveController: Principal
}

/** alias 信息只能从 `document.resolve` 或事件推断，bns-server 没有 getAlias。 */
export interface AliasView {
  name: string
  kind: AliasKind
  targetDid: string
  /** 数据来源，视图必须如实标注。 */
  source: 'document_resolve' | 'event_log'
  observedAtSeq: bigint | null
}

// ---------------------------------------------------------------------------
// 事件与 checkpoint
// ---------------------------------------------------------------------------

export type RegistryEvent =
  | { type: 'name_registered'; data: { name: string; assetOwner: string; expireAt: bigint; lineageEpoch: bigint; nameSeq: bigint } }
  | { type: 'name_renewed'; data: { name: string; expireAt: bigint; nameSeq: bigint } }
  | { type: 'name_asset_transferred'; data: { name: string; oldAssetOwner: string; newAssetOwner: string; standardTransfer: boolean; nameSeq: bigint } }
  | { type: 'name_owner_updated'; data: { name: string; owner: Principal; ownerSource: OwnerSource; standardTransferEnabled: boolean; nameSeq: bigint } }
  | { type: 'authority_keys_updated'; data: { name: string; authoritySeq: bigint; authorityRoot: string } }
  | { type: 'name_released'; data: { name: string; mode: ReleaseMode; reasonHash: string; nameSeq: bigint } }
  | { type: 'document_published'; data: { name: string; docType: string; version: bigint; contentHash: string; documentStateHash: string } }
  | { type: 'document_revoked'; data: { name: string; docType: string; previousVersion: bigint; newVersion: bigint; reasonHash: string } }
  | { type: 'owner_document_iat_floor_updated'; data: { name: string; previousMinDocumentIat: bigint; newMinDocumentIat: bigint; ownerPolicySeq: bigint; nameSeq: bigint; reasonHash: string } }
  | { type: 'controller_policy_updated'; data: { name: string; policyHash: string; nameSeq: bigint } }
  | { type: 'namespace_policy_updated'; data: { name: string; allowDelegatedSubnames: boolean; namespacePolicyHash: string; nameSeq: bigint } }
  | { type: 'did_alias_set'; data: { name: string; targetDid: string; kind: AliasKind; proofHash: string; nameSeq: bigint } }
  | { type: 'payment_target_updated'; data: { name: string; docType: string; paymentTarget: string; paymentPolicyHash: string; version: bigint } }
  | { type: 'log_checkpoint_published'; data: { logRoot: string; lastSeq: bigint; issuedAt: bigint; externalAnchor: string } }

export type RegistryEventType = RegistryEvent['type']

export interface EventRecord {
  seq: bigint
  /** 外层 event_type，可能与 `event.type` 不同（owner_iat_floor_updated）。 */
  outerEventType: string
  observedAt: bigint
  eventHash: string
  previousLogRoot: string
  logRoot: string
  event: RegistryEvent
  /** 从事件负载里提取的名称，log_checkpoint_published 没有名称。 */
  name: string | null
}

export interface LogCheckpoint {
  logRoot: string
  lastSeq: bigint
  issuedAt: bigint
  issuer: Principal
  externalAnchor: string
}

// ---------------------------------------------------------------------------
// 交易
// ---------------------------------------------------------------------------

export interface TxState {
  txHash: string
  state: TxExecutionState
  blockNumber: bigint | null
  confirmations: bigint
}

/**
 * `tx.prepare` 的结果：一个外部签名方在**没有自己的链 RPC** 时
 * 构造 EIP-1559 交易所需的全部参数。只有服务端中继投递模式会用到。
 */
export interface PrepareTxResult {
  nonce: bigint
  chainId: number
  contractAddress: string
  estimatedGas: bigint
  gasLimit: bigint
  maxFeePerGas: bigint
  maxPriorityFeePerGas: bigint
}
