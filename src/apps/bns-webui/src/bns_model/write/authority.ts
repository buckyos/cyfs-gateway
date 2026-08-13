/**
 * 授权路径构造与写前预检（PRD 5.3 / 8.4 / 8.6）。
 *
 * 两条铁律：
 * 1. `CallAuthority` 只是**声明**给合约看的授权路径，最终身份始终由合约用
 *    `msg.sender` 校验。预检通过 ≠ 交易一定成功，文案不得这样描述。
 * 2. 账户或网络变化后，之前算出来的 authority 与表单确认结果必须作废。
 */

import { isSameAddress, ZERO_BYTES32 } from '../infra/codec'
import type { AuthorityKeyView, NameState, OwnerResolution } from '../types/domain'
import { KEY_PURPOSE_AUTHENTICATION } from '../types/domain'
import {
  bnsNamePrincipal,
  chainAccountPrincipal,
  PUBLIC_AUTHORITY,
  UNSET_PRINCIPAL,
  type CallAuthority,
  type MutationGuard,
  type WriteIntentKind,
} from './intents'

export type AuthorityPath =
  | { kind: 'public' }
  | { kind: 'chain_account_owner'; address: string }
  | { kind: 'bns_name_owner'; ownerName: string; kid: string }
  | { kind: 'chain_account_controller'; address: string }
  | { kind: 'bns_name_controller'; controllerName: string; kid: string }

export function buildCallAuthority(path: AuthorityPath): CallAuthority {
  switch (path.kind) {
    case 'public':
      return PUBLIC_AUTHORITY
    case 'chain_account_owner':
      return { role: 'owner', actor: chainAccountPrincipal(path.address), kid: ZERO_BYTES32 }
    case 'bns_name_owner':
      return { role: 'owner', actor: bnsNamePrincipal(path.ownerName), kid: path.kid }
    case 'chain_account_controller':
      return { role: 'controller', actor: chainAccountPrincipal(path.address), kid: ZERO_BYTES32 }
    case 'bns_name_controller':
      return { role: 'controller', actor: bnsNamePrincipal(path.controllerName), kid: path.kid }
  }
}

export function describeAuthorityPath(path: AuthorityPath): string {
  switch (path.kind) {
    case 'public':
      return '公开注册（无需授权声明）'
    case 'chain_account_owner':
      return `Chain Account Owner · ${path.address}`
    case 'bns_name_owner':
      return `BNS Name Owner · ${path.ownerName} (kid ${path.kid.slice(0, 10)}…)`
    case 'chain_account_controller':
      return `Chain Account Controller · ${path.address}`
    case 'bns_name_controller':
      return `BNS Name Controller · ${path.controllerName} (kid ${path.kid.slice(0, 10)}…)`
  }
}

/**
 * 构造 MutationGuard。
 *
 * - 普通名称 mutation：`expectedNameSeq = name_state.name_seq`
 * - 二级名称注册：`expectedParentNameSeq = parent.name_seq`
 * - 文档写入的 `expectedVersion` 不在 guard 里，而是方法自身参数
 */
export function buildGuard(options: {
  nameState?: NameState | null
  parentState?: NameState | null
}): MutationGuard {
  return {
    expectedNameSeq: options.nameState?.nameSeq ?? 0n,
    expectedParentNameSeq: options.parentState?.nameSeq ?? 0n,
  }
}

export interface AuthorityAssessmentInput {
  /** 目标名称的投影状态；注册新名称时为 null。 */
  nameState: NameState | null
  /** 目标名称（或二级名称注册时的父名称）的 owner 解析结果。 */
  owner: OwnerResolution | null
  walletAddress: string | null
  /**
   * effective owner 是 BNS name 时，已探测到的该名称 authority key。
   * bns-server 没有列举接口，所以这里天然是「已知 kid 的子集」。
   */
  ownerAuthorityKeys: AuthorityKeyView[]
  operation: WriteIntentKind
  /** 顶级名称的公开注册不需要授权声明。 */
  isPublicRegistration?: boolean
}

export interface AuthorityAssessment {
  paths: AuthorityPath[]
  recommended: AuthorityPath | null
  /** 是否存在可尝试的授权路径。false 时 UI 应禁用提交并解释原因。 */
  canAttempt: boolean
  /** 可解释的预检说明，逐条展示给用户。 */
  notes: string[]
  /** 只能由用户手动声明、前端无法验证的路径（controller）。 */
  manualOnly: boolean
}

/**
 * 计算当前钱包可用的授权路径。
 *
 * 已知能力缺口：bns-server 没有「列出 controller rules」的接口，
 * `setControllerPolicy` 也只在事件里留下 policy_hash。因此 controller 路径
 * 无法被前端验证，只能作为用户手动声明的高级选项，并如实标注。
 */
export function assessAuthority(input: AuthorityAssessmentInput): AuthorityAssessment {
  const notes: string[] = []
  const paths: AuthorityPath[] = []

  if (input.isPublicRegistration) {
    notes.push('顶级名称公开注册：role = None，actor = Unset，kid = zero bytes32。')
    return { paths: [{ kind: 'public' }], recommended: { kind: 'public' }, canAttempt: true, notes, manualOnly: false }
  }

  if (!input.walletAddress) {
    notes.push('未连接钱包，页面保持只读。')
    return { paths: [], recommended: null, canAttempt: false, notes, manualOnly: false }
  }

  const owner = input.owner
  if (!owner) {
    notes.push('无法解析 effective owner（名称可能不存在或投影缺失），不能预检授权路径。')
    return { paths: [], recommended: null, canAttempt: false, notes, manualOnly: false }
  }

  switch (owner.source) {
    case 'asset_owner_fallback':
      notes.push('Semantic Owner 未设置，effective owner 回退到 asset_owner。')
      break
    case 'explicit_semantic_owner':
      notes.push('Semantic Owner 已显式设置为 BNS name，授权走该名称的 authority set。')
      break
    case 'parent_inherited':
      notes.push('二级名称未设置 Semantic Owner，effective owner 继承自父名称。')
      break
    case 'none':
      notes.push('owner_source = none，投影没有给出有效 owner。')
      break
  }

  if (owner.effectiveOwner.kind === 'chain_account') {
    if (isSameAddress(owner.effectiveOwner.value, input.walletAddress)) {
      paths.push({ kind: 'chain_account_owner', address: input.walletAddress })
      notes.push('当前钱包地址与 effective owner 一致。')
    } else {
      notes.push(
        `effective owner 是 ${owner.effectiveOwner.value}，与当前钱包不一致；` +
          '作为 Owner 的写操作会被合约拒绝。',
      )
    }
  } else if (owner.effectiveOwner.kind === 'bns_name') {
    const ownerName = owner.effectiveOwner.value
    const usable = input.ownerAuthorityKeys.filter(
      (key) =>
        key.usableNow &&
        key.purposeFlags.authentication &&
        isSameAddress(key.addressFromKeyData, input.walletAddress),
    )
    for (const key of usable) {
      paths.push({ kind: 'bns_name_owner', ownerName, kid: key.kid })
    }
    if (usable.length === 0) {
      notes.push(
        `effective owner 是 BNS name \`${ownerName}\`，但在已探测到的 authority key 中` +
          '没有匹配当前钱包地址、状态为 active 且带 authentication 位的 key。',
      )
      notes.push(
        'bns-server 没有「列出全部 authority key」接口，此结论只覆盖已知 kid，' +
          '可能存在未被探测到的 key。',
      )
    } else {
      notes.push(`匹配到 ${usable.length} 个可用的 owner authority key。`)
    }
  } else {
    notes.push('effective owner 为 Unset，没有可用的 Owner 授权路径。')
  }

  const manualOnly = paths.length === 0
  if (manualOnly) {
    notes.push(
      '如果你是 controller，可在高级模式手动声明 Controller 授权路径；' +
        '前端无法验证 controller rule（bns-server 没有对应查询接口）。',
    )
  }

  notes.push('预检只做可解释的检查，最终授权由合约按 msg.sender 判定。')

  return {
    paths,
    recommended: paths[0] ?? null,
    canAttempt: paths.length > 0,
    notes,
    manualOnly,
  }
}

/** 账户/网络切换时，作废之前算出来的授权结果。 */
export function isAssessmentStillValid(
  path: AuthorityPath,
  walletAddress: string | null,
): boolean {
  if (!walletAddress) return false
  switch (path.kind) {
    case 'public':
      return true
    case 'chain_account_owner':
    case 'chain_account_controller':
      return isSameAddress(path.address, walletAddress)
    case 'bns_name_owner':
    case 'bns_name_controller':
      // key 与地址的绑定要重新探测，这里只能保证路径本身没被清空。
      return true
  }
}

export const AUTHENTICATION_PURPOSE_MASK = KEY_PURPOSE_AUTHENTICATION
export { UNSET_PRINCIPAL }
