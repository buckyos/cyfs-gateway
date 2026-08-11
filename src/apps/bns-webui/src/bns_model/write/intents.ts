/**
 * 写意图（Command）：把 15 个合约写方法表达成领域对象。
 *
 * 一个 Intent 是「用户想做什么」的完整、可序列化描述，不含钱包、不含 ABI。
 * 它同时决定三件事：
 * 1. 调用哪个合约方法；
 * 2. 需要哪种 MutationGuard；
 * 3. 交易成功后，投影上应该出现什么变化（收敛期望）。
 *
 * 参数结构真值来源：`src/apps/bns/src/IBns.sol` 与 `BnsTypes.sol`。
 */

import { ZERO_ADDRESS, ZERO_BYTES32 } from '../infra/codec'
import type { AuthorityKeyStatus, Principal, ReleaseMode } from '../types/domain'

export type AuthorityRole = 'none' | 'owner' | 'controller'
export type AliasKindInput = 'none' | 'alias' | 'migrated_to' | 'canonical'

export interface CallAuthority {
  role: AuthorityRole
  actor: Principal
  /** bytes32 hex；chain account 路径固定 zero bytes32。 */
  kid: string
}

export interface MutationGuard {
  expectedNameSeq: bigint
  expectedParentNameSeq: bigint
}

export interface AuthorityKeyInput {
  kid: string
  /** 当前不参与 signer 验证，属于承诺/元数据（PRD 6.4.10）。 */
  verificationMethod: string
  /** 合约只认 20 字节地址 key data。 */
  keyData: Uint8Array
  purposes: number
  validFrom: bigint
  validUntil: bigint
  status: AuthorityKeyStatus
  metadataHash: string
}

export interface AuthorityKeyUpdateInput {
  key: AuthorityKeyInput
  active: boolean
}

export interface DocumentRefInput {
  /** 标签形式（如 `inline`）或 bytes32 hex，编码阶段统一转 bytes32。 */
  storageType: string
  uri: string
  inlineDocument: Uint8Array
  contentHash: string
  schema: string
  codec: string
  extraHash: string
}

export interface DocumentUpdateInput {
  docType: string
  expectedVersion: bigint
  document: DocumentRefInput
  controller: Principal
  beneficiary: Principal
  paymentTarget: string
  expireAt: bigint
  controllerPolicyHash: string
  paymentPolicyHash: string
  splitPolicyHash: string
  pricePolicyHash: string
  rightsPolicyHash: string
}

export interface ControllerRuleInput {
  controller: Principal
  docType: string
  permissions: number
  /** 当前只存储、不参与授权判断（PRD 6.4.10）。 */
  namespaceScopeHash: string
  validFrom: bigint
  validUntil: bigint
  constraintHash: string
}

export interface RegisterOptionsInput {
  duration: bigint
  gracePeriod: bigint
  renewable: boolean
  transferable: boolean
  initialSemanticOwner: Principal
  allowDelegatedSubnames: boolean
  /** 合约当前不读取该字段，前端固定传 zero address（PRD 6.4.9）。 */
  initialPaymentTarget: string
  initialPaymentPolicyHash: string
  initialNamespacePolicyHash: string
}

export interface OwnerPolicyUpdateInput {
  updateMinDocumentIat: boolean
  minDocumentIat: bigint
  reasonHash: string
}

interface IntentBase {
  name: string
  authority: CallAuthority
  guard: MutationGuard
}

export type WriteIntent =
  | (IntentBase & {
      kind: 'register_name'
      assetOwner: string
      options: RegisterOptionsInput
      authorityUpdates: AuthorityKeyUpdateInput[]
      semanticOwnerAfterAuthority: Principal
      controllerPolicy: ControllerRuleInput[]
      controllerPolicyHash: string
      initialDocuments: DocumentUpdateInput[]
    })
  /** renewName 没有 authority / guard 参数，但保留基类字段以统一处理。 */
  | (IntentBase & { kind: 'renew_name'; duration: bigint })
  | (IntentBase & {
      kind: 'transfer_name'
      newAssetOwner: string
      newSemanticOwner: Principal
      atomicDocumentUpdates: DocumentUpdateInput[]
    })
  | (IntentBase & { kind: 'set_name_owner'; semanticOwner: Principal })
  | (IntentBase & { kind: 'release_name'; mode: ReleaseMode; reasonHash: string })
  | (IntentBase & {
      kind: 'set_namespace_policy'
      allowDelegatedSubnames: boolean
      namespacePolicyHash: string
    })
  | (IntentBase & { kind: 'update_authority_keys'; updates: AuthorityKeyUpdateInput[] })
  | (IntentBase & { kind: 'set_min_document_iat'; minDocumentIat: bigint; reasonHash: string })
  | (IntentBase & {
      kind: 'publish_document'
      docType: string
      expectedVersion: bigint
      document: DocumentRefInput
      controller: Principal
      beneficiary: Principal
      paymentTarget: string
      expireAt: bigint
      controllerPolicyHash: string
      paymentPolicyHash: string
      splitPolicyHash: string
      pricePolicyHash: string
      rightsPolicyHash: string
    })
  | (IntentBase & {
      kind: 'revoke_document'
      docType: string
      expectedVersion: bigint
      reasonHash: string
    })
  | (IntentBase & { kind: 'set_controller_policy'; rules: ControllerRuleInput[]; policyHash: string })
  | (IntentBase & {
      kind: 'set_did_alias'
      targetDid: string
      aliasKind: AliasKindInput
      proofHash: string
    })
  | (IntentBase & {
      kind: 'set_payment_target'
      docType: string
      expectedVersion: bigint
      paymentTarget: string
      beneficiary: Principal
      paymentPolicyHash: string
      splitPolicyHash: string
      pricePolicyHash: string
      rightsPolicyHash: string
    })
  | (IntentBase & {
      kind: 'apply_mutations'
      authorityUpdates: AuthorityKeyUpdateInput[]
      documents: DocumentUpdateInput[]
      ownerPolicy: OwnerPolicyUpdateInput
    })
  | (IntentBase & { kind: 'publish_log_checkpoint'; issuer: Principal; externalAnchor: string })

export type WriteIntentKind = WriteIntent['kind']

export interface WriteIntentMeta {
  /** 合约方法名，同时是 ABI encode 的 functionName。 */
  method: string
  label: string
  /** 是否需要在弹钱包之前重读状态刷新 guard（PRD 8.6）。 */
  requiresGuard: boolean
  /** 二级名称注册需要父名称 name_seq。 */
  requiresParentGuard: boolean
  /** 高风险操作：UI 必须显示 before/after 并二次确认。 */
  highRisk: boolean
  /** 普通用户界面是否开放。 */
  userFacing: boolean
}

export const WRITE_INTENT_META: Record<WriteIntentKind, WriteIntentMeta> = {
  register_name: { method: 'registerName', label: '注册名称', requiresGuard: false, requiresParentGuard: true, highRisk: false, userFacing: true },
  renew_name: { method: 'renewName', label: '续期名称', requiresGuard: false, requiresParentGuard: false, highRisk: false, userFacing: true },
  transfer_name: { method: 'transferName', label: '转移名称', requiresGuard: true, requiresParentGuard: false, highRisk: true, userFacing: true },
  set_name_owner: { method: 'setNameOwner', label: '设置 Semantic Owner', requiresGuard: true, requiresParentGuard: false, highRisk: true, userFacing: true },
  release_name: { method: 'releaseName', label: '释放 / 永久停用', requiresGuard: true, requiresParentGuard: false, highRisk: true, userFacing: true },
  set_namespace_policy: { method: 'setNamespacePolicy', label: 'Namespace 策略', requiresGuard: true, requiresParentGuard: false, highRisk: false, userFacing: true },
  update_authority_keys: { method: 'updateAuthorityKeys', label: '更新 Authority Keys', requiresGuard: true, requiresParentGuard: false, highRisk: true, userFacing: true },
  set_min_document_iat: { method: 'setMinDocumentIat', label: 'Owner IAT Floor', requiresGuard: true, requiresParentGuard: false, highRisk: true, userFacing: true },
  publish_document: { method: 'publishDocument', label: '发布 / 更新文档', requiresGuard: true, requiresParentGuard: false, highRisk: false, userFacing: true },
  revoke_document: { method: 'revokeDocument', label: '撤销文档', requiresGuard: true, requiresParentGuard: false, highRisk: true, userFacing: true },
  set_controller_policy: { method: 'setControllerPolicy', label: '替换 Controller 规则', requiresGuard: true, requiresParentGuard: false, highRisk: true, userFacing: true },
  set_did_alias: { method: 'setDidAlias', label: '设置 DID Alias', requiresGuard: true, requiresParentGuard: false, highRisk: true, userFacing: true },
  set_payment_target: { method: 'setPaymentTarget', label: '设置支付目标', requiresGuard: true, requiresParentGuard: false, highRisk: false, userFacing: true },
  apply_mutations: { method: 'applyMutations', label: '原子批量更新', requiresGuard: true, requiresParentGuard: false, highRisk: true, userFacing: true },
  // publishLogCheckpoint 当前没有把 issuer 与 msg.sender 绑定，不进普通用户入口（PRD 6.4.6）。
  publish_log_checkpoint: { method: 'publishLogCheckpoint', label: '发布 Checkpoint', requiresGuard: false, requiresParentGuard: false, highRisk: true, userFacing: false },
}

/**
 * 交易上链成功后，投影上应当出现的变化。
 * 只有它被满足，交易才算 `completed`；否则停在 `indexing`。
 */
export type ConvergenceExpectation =
  | { kind: 'none' }
  | { kind: 'name_exists'; name: string }
  | { kind: 'name_seq_at_least'; name: string; value: bigint }
  | { kind: 'expire_at_greater_than'; name: string; value: bigint }
  | { kind: 'authority_seq_at_least'; name: string; value: bigint }
  | { kind: 'document_version_at_least'; name: string; docType: string; value: bigint }

// ---------------------------------------------------------------------------
// 默认值与构造助手
// ---------------------------------------------------------------------------

export const UNSET_PRINCIPAL: Principal = { kind: 'unset', value: '' }

export function chainAccountPrincipal(address: string): Principal {
  return { kind: 'chain_account', value: address }
}

export function bnsNamePrincipal(name: string): Principal {
  return { kind: 'bns_name', value: name }
}

export const PUBLIC_AUTHORITY: CallAuthority = {
  role: 'none',
  actor: UNSET_PRINCIPAL,
  kid: ZERO_BYTES32,
}

export const EMPTY_GUARD: MutationGuard = {
  expectedNameSeq: 0n,
  expectedParentNameSeq: 0n,
}

export function defaultRegisterOptions(duration: bigint, gracePeriod: bigint): RegisterOptionsInput {
  return {
    duration,
    gracePeriod,
    renewable: true,
    transferable: true,
    initialSemanticOwner: UNSET_PRINCIPAL,
    allowDelegatedSubnames: false,
    // 合约不读取该字段，固定 zero address，不作为有效注册选项展示。
    initialPaymentTarget: ZERO_ADDRESS,
    initialPaymentPolicyHash: ZERO_BYTES32,
    initialNamespacePolicyHash: ZERO_BYTES32,
  }
}

export function inlineDocumentRef(bytes: Uint8Array, contentHash: string): DocumentRefInput {
  return {
    storageType: 'inline',
    // inline 文档的 uri 必须为空（PRD 6.2）。
    uri: '',
    inlineDocument: bytes,
    contentHash,
    schema: ZERO_BYTES32,
    codec: ZERO_BYTES32,
    extraHash: ZERO_BYTES32,
  }
}

export function uriDocumentRef(uri: string, contentHash: string, storageType = 'uri'): DocumentRefInput {
  return {
    storageType,
    uri,
    // 非 inline 文档的 inline_document 必须为空。
    inlineDocument: new Uint8Array(0),
    contentHash,
    schema: ZERO_BYTES32,
    codec: ZERO_BYTES32,
    extraHash: ZERO_BYTES32,
  }
}
