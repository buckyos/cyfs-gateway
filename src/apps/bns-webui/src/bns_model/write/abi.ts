/**
 * 聚合 IBns ABI（写方法 + custom error）与 Intent -> ABI 参数转换。
 *
 * 设计取舍：**ABI 编码本身**依赖具体库（viem / ethers），所以只保留为端口；
 * 但 **参数怎么摆** 是协议语义，属于 Model，必须在这里定死并可单测。
 * 于是适配器只剩一行：
 *
 * ```ts
 * encodeFunctionData({
 *   abi: parseAbi([...BNS_ABI_STRUCTS, ...BNS_WRITE_FUNCTIONS, ...BNS_ERRORS]),
 *   functionName: WRITE_INTENT_META[intent.kind].method,
 *   args: toAbiArgs(intent),
 * })
 * ```
 *
 * 签名真值来源：`src/apps/bns/src/IBns.sol` + `BnsTypes.sol`。
 * 所有 enum 在 ABI 里都是 uint8，序号见 BnsTypes.sol 的声明顺序。
 */

import {
  bytes32OrZero,
  bytesToHex,
  normalizeAddress,
  normalizeBytes32,
  storageTypeToBytes32,
  utf8ToBytes,
  ZERO_ADDRESS,
  type Hex,
} from '../infra/codec'
import { BNS_ERROR_CODE, BnsError } from '../types/errors'
import type { AuthorityKeyStatus, Principal, ReleaseMode } from '../types/domain'
import type {
  AliasKindInput,
  AuthorityKeyUpdateInput,
  AuthorityRole,
  CallAuthority,
  ControllerRuleInput,
  DocumentRefInput,
  DocumentUpdateInput,
  MutationGuard,
  RegisterOptionsInput,
  WriteIntent,
} from './intents'

// ---------------------------------------------------------------------------
// ABI（human-readable 形式，viem `parseAbi` 可直接消费）
// ---------------------------------------------------------------------------

export const BNS_ABI_STRUCTS = [
  'struct Principal { uint8 kind; bytes value; }',
  'struct CallAuthority { uint8 role; Principal actor; bytes32 kid; }',
  'struct MutationGuard { uint64 expectedNameSeq; uint64 expectedParentNameSeq; }',
  'struct AuthorityKey { bytes32 kid; bytes32 verificationMethod; bytes keyData; uint32 purposes; uint64 validFrom; uint64 validUntil; uint8 status; bytes32 metadataHash; }',
  'struct AuthorityKeyUpdate { AuthorityKey key; bool active; }',
  'struct DocumentRef { bytes32 storageType; string uri; bytes inlineDocument; bytes32 contentHash; bytes32 schema; bytes32 codec; bytes32 extraHash; }',
  'struct DocumentUpdate { string docType; uint64 expectedVersion; DocumentRef document; Principal controller; Principal beneficiary; address paymentTarget; uint64 expireAt; bytes32 controllerPolicyHash; bytes32 paymentPolicyHash; bytes32 splitPolicyHash; bytes32 pricePolicyHash; bytes32 rightsPolicyHash; }',
  'struct ControllerRule { Principal controller; string docType; uint32 permissions; bytes32 namespaceScopeHash; uint64 validFrom; uint64 validUntil; bytes32 constraintHash; }',
  'struct RegisterOptions { uint64 duration; uint64 gracePeriod; bool renewable; bool transferable; Principal initialSemanticOwner; bool allowDelegatedSubnames; address initialPaymentTarget; bytes32 initialPaymentPolicyHash; bytes32 initialNamespacePolicyHash; }',
  'struct OwnerPolicyUpdate { bool updateMinDocumentIat; uint64 minDocumentIat; bytes32 reasonHash; }',
] as const

export const BNS_WRITE_FUNCTIONS = [
  'function registerName(string name, address assetOwner, RegisterOptions options, AuthorityKeyUpdate[] authorityUpdates, Principal semanticOwnerAfterAuthority, ControllerRule[] controllerPolicy, bytes32 controllerPolicyHash, DocumentUpdate[] initialDocuments, CallAuthority authority, MutationGuard guard) payable returns (uint64 nameSeq, uint64 authoritySeq, bytes32 authorityRoot)',
  'function renewName(string name, uint64 duration) payable returns (uint64 expireAt)',
  'function transferName(string name, address newAssetOwner, Principal newSemanticOwner, DocumentUpdate[] atomicDocumentUpdates, CallAuthority authority, MutationGuard guard) returns (uint64 nameSeq)',
  'function setNameOwner(string name, Principal semanticOwner, CallAuthority authority, MutationGuard guard) returns (uint64 nameSeq)',
  'function releaseName(string name, uint8 mode, bytes32 reasonHash, CallAuthority authority, MutationGuard guard) returns (uint64 nameSeq)',
  'function setNamespacePolicy(string name, bool allowDelegatedSubnames, bytes32 namespacePolicyHash, CallAuthority authority, MutationGuard guard) returns (uint64 nameSeq)',
  'function updateAuthorityKeys(string name, AuthorityKeyUpdate[] updates, CallAuthority authority, MutationGuard guard) returns (uint64 authoritySeq, bytes32 authorityRoot)',
  'function setMinDocumentIat(string name, uint64 minDocumentIat, bytes32 reasonHash, CallAuthority authority, MutationGuard guard) returns (uint64 nameSeq, uint64 ownerPolicySeq)',
  'function publishDocument(string name, string docType, uint64 expectedVersion, DocumentRef document, Principal controller, Principal beneficiary, address paymentTarget, uint64 expireAt, bytes32 controllerPolicyHash, bytes32 paymentPolicyHash, bytes32 splitPolicyHash, bytes32 pricePolicyHash, bytes32 rightsPolicyHash, CallAuthority authority, MutationGuard guard) returns (uint64 version)',
  'function revokeDocument(string name, string docType, uint64 expectedVersion, bytes32 reasonHash, CallAuthority authority, MutationGuard guard) returns (uint64 newVersion, uint64 nameSeq)',
  'function setControllerPolicy(string name, ControllerRule[] rules, bytes32 policyHash, CallAuthority authority, MutationGuard guard) returns (uint64 nameSeq)',
  'function setDidAlias(string name, string targetDid, uint8 kind, bytes32 proofHash, CallAuthority authority, MutationGuard guard) returns (uint64 nameSeq)',
  'function setPaymentTarget(string name, string docType, uint64 expectedVersion, address paymentTarget, Principal beneficiary, bytes32 paymentPolicyHash, bytes32 splitPolicyHash, bytes32 pricePolicyHash, bytes32 rightsPolicyHash, CallAuthority authority, MutationGuard guard) returns (uint64 version)',
  'function applyMutations(string name, AuthorityKeyUpdate[] authorityUpdates, DocumentUpdate[] documents, OwnerPolicyUpdate ownerPolicy, CallAuthority authority, MutationGuard guard) returns (uint64 nameSeq, uint64 authoritySeq, bytes32 authorityRoot, uint64 ownerPolicySeq)',
  'function publishLogCheckpoint(Principal issuer, bytes32 externalAnchor) returns (bytes32 logRoot, uint64 lastSeq, uint64 issuedAt, Principal issuerOut, bytes32 externalAnchorOut)',
] as const

/** 前端必须能解码的 custom error（PRD 12.4）。 */
export const BNS_ERRORS = [
  'error InvalidName(string name)',
  'error InvalidDocType(string docType)',
  'error InvalidPrincipal()',
  'error InvalidKid(bytes32 kid)',
  'error NameAlreadyExists(string name)',
  'error NameNotFound(string name)',
  'error DocumentNotFound(string name, string docType)',
  'error StaleNameSeq(string name, uint64 expected, uint64 actual)',
  'error StaleParentNameSeq(string name, uint64 expected, uint64 actual)',
  'error StaleDocumentVersion(string name, string docType, uint64 expected, uint64 actual)',
  'error NotEffectiveOwner(string name)',
  'error ControllerScopeDenied(string name, string docType, bytes32 operation)',
  'error StandardTransferDisabled(string name)',
  'error OwnerGraphCycle()',
  'error NoConcreteSigner()',
  'error OwnerGraphTooDeep(uint256 maxDepth)',
  'error InlineDocumentTooLarge(uint256 len, uint256 max)',
  'error InvalidMutation(bytes32 reason)',
] as const

export const BNS_ABI_SOURCE = [...BNS_ABI_STRUCTS, ...BNS_WRITE_FUNCTIONS, ...BNS_ERRORS]

/** guard 类 revert：不自动重放，重读状态后让用户重新确认（PRD 8.6）。 */
export const STALE_GUARD_ERRORS = new Set([
  'StaleNameSeq',
  'StaleParentNameSeq',
  'StaleDocumentVersion',
])

// ---------------------------------------------------------------------------
// enum 序号（BnsTypes.sol 声明顺序）
// ---------------------------------------------------------------------------

const PRINCIPAL_KIND_ORDINAL: Record<Principal['kind'], number> = {
  unset: 0,
  chain_account: 1,
  bns_name: 2,
}

const AUTHORITY_ROLE_ORDINAL: Record<AuthorityRole, number> = {
  none: 0,
  owner: 1,
  controller: 2,
}

const AUTHORITY_KEY_STATUS_ORDINAL: Record<AuthorityKeyStatus, number> = {
  missing: 0,
  active: 1,
  revoked: 2,
  expired: 3,
}

const ALIAS_KIND_ORDINAL: Record<AliasKindInput, number> = {
  none: 0,
  alias: 1,
  migrated_to: 2,
  canonical: 3,
}

const RELEASE_MODE_ORDINAL: Record<ReleaseMode, number> = {
  release_after_grace: 0,
  tombstone_forever: 1,
}

// ---------------------------------------------------------------------------
// 结构体转换
// ---------------------------------------------------------------------------

export interface AbiPrincipal {
  kind: number
  value: Hex
}

/**
 * Principal 的 ABI 形态：`value` 是 bytes。
 * - ChainAccount -> 20 字节裸地址
 * - BnsName      -> 名称的 UTF-8 bytes
 * - Unset        -> 空 bytes
 * 读投影里的 Principal.value 是字符串，这里是唯一的反向转换点（PRD 5.3）。
 */
export function toAbiPrincipal(principal: Principal): AbiPrincipal {
  switch (principal.kind) {
    case 'unset':
      return { kind: PRINCIPAL_KIND_ORDINAL.unset, value: '0x' as Hex }
    case 'chain_account':
      return {
        kind: PRINCIPAL_KIND_ORDINAL.chain_account,
        value: normalizeAddress(principal.value) as Hex,
      }
    case 'bns_name':
      if (principal.value.length === 0) {
        throw BnsError.validation(BNS_ERROR_CODE.INVALID_NAME, 'bns_name principal 的值不能为空')
      }
      return {
        kind: PRINCIPAL_KIND_ORDINAL.bns_name,
        value: bytesToHex(utf8ToBytes(principal.value)),
      }
  }
}

export function toAbiCallAuthority(authority: CallAuthority): {
  role: number
  actor: AbiPrincipal
  kid: Hex
} {
  return {
    role: AUTHORITY_ROLE_ORDINAL[authority.role],
    actor: toAbiPrincipal(authority.actor),
    kid: bytes32OrZero(authority.kid, 'authority.kid'),
  }
}

export function toAbiGuard(guard: MutationGuard): {
  expectedNameSeq: bigint
  expectedParentNameSeq: bigint
} {
  return {
    expectedNameSeq: guard.expectedNameSeq,
    expectedParentNameSeq: guard.expectedParentNameSeq,
  }
}

export function toAbiDocumentRef(ref: DocumentRefInput): {
  storageType: Hex
  uri: string
  inlineDocument: Hex
  contentHash: Hex
  schema: Hex
  codec: Hex
  extraHash: Hex
} {
  return {
    storageType: storageTypeToBytes32(ref.storageType),
    uri: ref.uri,
    inlineDocument: bytesToHex(ref.inlineDocument),
    contentHash: bytes32OrZero(ref.contentHash, 'document.contentHash'),
    schema: bytes32OrZero(ref.schema, 'document.schema'),
    codec: bytes32OrZero(ref.codec, 'document.codec'),
    extraHash: bytes32OrZero(ref.extraHash, 'document.extraHash'),
  }
}

export function toAbiDocumentUpdate(update: DocumentUpdateInput) {
  return {
    docType: update.docType,
    expectedVersion: update.expectedVersion,
    document: toAbiDocumentRef(update.document),
    controller: toAbiPrincipal(update.controller),
    beneficiary: toAbiPrincipal(update.beneficiary),
    paymentTarget: addressOrZero(update.paymentTarget),
    expireAt: update.expireAt,
    controllerPolicyHash: bytes32OrZero(update.controllerPolicyHash),
    paymentPolicyHash: bytes32OrZero(update.paymentPolicyHash),
    splitPolicyHash: bytes32OrZero(update.splitPolicyHash),
    pricePolicyHash: bytes32OrZero(update.pricePolicyHash),
    rightsPolicyHash: bytes32OrZero(update.rightsPolicyHash),
  }
}

export function toAbiAuthorityKeyUpdate(update: AuthorityKeyUpdateInput) {
  return {
    key: {
      kid: normalizeBytes32(update.key.kid, 'authority_key.kid'),
      verificationMethod: bytes32OrZero(update.key.verificationMethod, 'authority_key.verificationMethod'),
      keyData: bytesToHex(update.key.keyData),
      purposes: update.key.purposes,
      validFrom: update.key.validFrom,
      validUntil: update.key.validUntil,
      status: AUTHORITY_KEY_STATUS_ORDINAL[update.key.status],
      metadataHash: bytes32OrZero(update.key.metadataHash),
    },
    active: update.active,
  }
}

export function toAbiControllerRule(rule: ControllerRuleInput) {
  return {
    controller: toAbiPrincipal(rule.controller),
    docType: rule.docType,
    permissions: rule.permissions,
    namespaceScopeHash: bytes32OrZero(rule.namespaceScopeHash),
    validFrom: rule.validFrom,
    validUntil: rule.validUntil,
    constraintHash: bytes32OrZero(rule.constraintHash),
  }
}

export function toAbiRegisterOptions(options: RegisterOptionsInput) {
  return {
    duration: options.duration,
    gracePeriod: options.gracePeriod,
    renewable: options.renewable,
    transferable: options.transferable,
    initialSemanticOwner: toAbiPrincipal(options.initialSemanticOwner),
    allowDelegatedSubnames: options.allowDelegatedSubnames,
    initialPaymentTarget: addressOrZero(options.initialPaymentTarget),
    initialPaymentPolicyHash: bytes32OrZero(options.initialPaymentPolicyHash),
    initialNamespacePolicyHash: bytes32OrZero(options.initialNamespacePolicyHash),
  }
}

function addressOrZero(value: string | null | undefined): string {
  if (!value || value.length === 0) return ZERO_ADDRESS
  return normalizeAddress(value)
}

// ---------------------------------------------------------------------------
// Intent -> 位置参数
// ---------------------------------------------------------------------------

/** 返回值顺序必须与 `BNS_WRITE_FUNCTIONS` 里对应签名一致。 */
export function toAbiArgs(intent: WriteIntent): readonly unknown[] {
  switch (intent.kind) {
    case 'register_name':
      return [
        intent.name,
        normalizeAddress(intent.assetOwner),
        toAbiRegisterOptions(intent.options),
        intent.authorityUpdates.map(toAbiAuthorityKeyUpdate),
        toAbiPrincipal(intent.semanticOwnerAfterAuthority),
        intent.controllerPolicy.map(toAbiControllerRule),
        bytes32OrZero(intent.controllerPolicyHash),
        intent.initialDocuments.map(toAbiDocumentUpdate),
        toAbiCallAuthority(intent.authority),
        toAbiGuard(intent.guard),
      ]
    case 'renew_name':
      return [intent.name, intent.duration]
    case 'transfer_name':
      return [
        intent.name,
        normalizeAddress(intent.newAssetOwner),
        toAbiPrincipal(intent.newSemanticOwner),
        intent.atomicDocumentUpdates.map(toAbiDocumentUpdate),
        toAbiCallAuthority(intent.authority),
        toAbiGuard(intent.guard),
      ]
    case 'set_name_owner':
      return [
        intent.name,
        toAbiPrincipal(intent.semanticOwner),
        toAbiCallAuthority(intent.authority),
        toAbiGuard(intent.guard),
      ]
    case 'release_name':
      return [
        intent.name,
        RELEASE_MODE_ORDINAL[intent.mode],
        bytes32OrZero(intent.reasonHash),
        toAbiCallAuthority(intent.authority),
        toAbiGuard(intent.guard),
      ]
    case 'set_namespace_policy':
      return [
        intent.name,
        intent.allowDelegatedSubnames,
        bytes32OrZero(intent.namespacePolicyHash),
        toAbiCallAuthority(intent.authority),
        toAbiGuard(intent.guard),
      ]
    case 'update_authority_keys':
      return [
        intent.name,
        intent.updates.map(toAbiAuthorityKeyUpdate),
        toAbiCallAuthority(intent.authority),
        toAbiGuard(intent.guard),
      ]
    case 'set_min_document_iat':
      return [
        intent.name,
        intent.minDocumentIat,
        bytes32OrZero(intent.reasonHash),
        toAbiCallAuthority(intent.authority),
        toAbiGuard(intent.guard),
      ]
    case 'publish_document':
      return [
        intent.name,
        intent.docType,
        intent.expectedVersion,
        toAbiDocumentRef(intent.document),
        toAbiPrincipal(intent.controller),
        toAbiPrincipal(intent.beneficiary),
        addressOrZero(intent.paymentTarget),
        intent.expireAt,
        bytes32OrZero(intent.controllerPolicyHash),
        bytes32OrZero(intent.paymentPolicyHash),
        bytes32OrZero(intent.splitPolicyHash),
        bytes32OrZero(intent.pricePolicyHash),
        bytes32OrZero(intent.rightsPolicyHash),
        toAbiCallAuthority(intent.authority),
        toAbiGuard(intent.guard),
      ]
    case 'revoke_document':
      return [
        intent.name,
        intent.docType,
        intent.expectedVersion,
        bytes32OrZero(intent.reasonHash),
        toAbiCallAuthority(intent.authority),
        toAbiGuard(intent.guard),
      ]
    case 'set_controller_policy':
      return [
        intent.name,
        intent.rules.map(toAbiControllerRule),
        bytes32OrZero(intent.policyHash),
        toAbiCallAuthority(intent.authority),
        toAbiGuard(intent.guard),
      ]
    case 'set_did_alias':
      return [
        intent.name,
        intent.targetDid,
        ALIAS_KIND_ORDINAL[intent.aliasKind],
        bytes32OrZero(intent.proofHash),
        toAbiCallAuthority(intent.authority),
        toAbiGuard(intent.guard),
      ]
    case 'set_payment_target':
      return [
        intent.name,
        intent.docType,
        intent.expectedVersion,
        addressOrZero(intent.paymentTarget),
        toAbiPrincipal(intent.beneficiary),
        bytes32OrZero(intent.paymentPolicyHash),
        bytes32OrZero(intent.splitPolicyHash),
        bytes32OrZero(intent.pricePolicyHash),
        bytes32OrZero(intent.rightsPolicyHash),
        toAbiCallAuthority(intent.authority),
        toAbiGuard(intent.guard),
      ]
    case 'apply_mutations':
      return [
        intent.name,
        intent.authorityUpdates.map(toAbiAuthorityKeyUpdate),
        intent.documents.map(toAbiDocumentUpdate),
        {
          updateMinDocumentIat: intent.ownerPolicy.updateMinDocumentIat,
          minDocumentIat: intent.ownerPolicy.minDocumentIat,
          reasonHash: bytes32OrZero(intent.ownerPolicy.reasonHash),
        },
        toAbiCallAuthority(intent.authority),
        toAbiGuard(intent.guard),
      ]
    case 'publish_log_checkpoint':
      return [toAbiPrincipal(intent.issuer), bytes32OrZero(intent.externalAnchor)]
  }
}
