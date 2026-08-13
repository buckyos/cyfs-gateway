/**
 * 写流程：Intent -> 预检 -> guard 刷新 -> calldata -> 签名 -> 投递 -> 交易记录。
 *
 * 本文件只负责「把交易组装正确」；**往哪投**由 `write/delivery.ts` 的策略决定：
 * - `wallet_direct`（默认）= PRD 4.2 的产品写路径 WebUI -> Wallet -> EVM RPC -> BNS Proxy；
 * - `server_relay`（需显式开启）= 测试链/私链没有浏览器可达 RPC 时的中继路径。
 * 两者的取舍、前提和硬约束见 delivery.ts 顶部的长注释。
 *
 * 无论走哪条路，组装规则完全一致：calldata 目标恒为 `system.info.contract_address`，
 * `value` 恒为 0，guard 必须在签名**之前**重读（PRD 8.6）——
 * 否则用户在确认框里停留的时间足够让 name_seq 过期。
 */

import { BnsError, MODEL_ERROR_CODE, toWalletError } from '../types/errors'
import type { CalldataCodec, DecodedContractError, SendTxRequest, WalletPort } from '../ports'
import { WalletDirectDelivery, type DeliveryReadiness, type TxDelivery, type TxDeliveryMode, type TxDeliveryResult } from './delivery'
import type { ReadRepository } from '../services/read_repository'
import type { NameState } from '../types/domain'
import { STALE_GUARD_ERRORS } from './abi'
import { buildCallAuthority, buildGuard, describeAuthorityPath, type AuthorityPath } from './authority'
import {
  WRITE_INTENT_META,
  type ConvergenceExpectation,
  type MutationGuard,
  type WriteIntent,
} from './intents'

export interface WriteContext {
  chainId: number
  /** 必须来自 `system.info.contract_address`，不允许构建期硬编码（PRD 8.1）。 */
  contractAddress: string
  from: string
}

export interface PreparedWrite {
  intent: WriteIntent
  path: AuthorityPath
  request: SendTxRequest
  context: WriteContext
  guard: MutationGuard
  /** guard 重读完成的时间戳，用于展示“刚刚校验”。 */
  guardRefreshedAt: number
  gasEstimate: bigint | null
  /** 提交前模拟失败的解码结果；`reverted` 时优先展示它。 */
  simulationError: DecodedContractError | null
  /** 模拟失败原因为 guard 过期：不允许提交，必须重读后重新确认。 */
  staleGuard: boolean
  expectation: ConvergenceExpectation
  /** 钱包确认前展示给用户的摘要：方法名、Proxy、chain ID、value、关键参数。 */
  summary: WriteSummary
  /** 这笔交易将走哪条投递路径，以及是否可用。见 write/delivery.ts 的长注释。 */
  delivery: { mode: TxDeliveryMode; readiness: DeliveryReadiness }
}

export interface WriteSummary {
  method: string
  label: string
  target: string
  chainId: number
  contractAddress: string
  value: '0x0'
  authority: string
  guard: { expectedNameSeq: string; expectedParentNameSeq: string }
  highRisk: boolean
  /** 投递路径也要写进确认摘要：中继模式下广播方不是钱包，用户有权知道。 */
  deliveryMode: TxDeliveryMode
}

export class WriteFlow {
  constructor(
    private readonly repo: ReadRepository,
    private readonly getWallet: () => WalletPort | null,
    private readonly getCodec: () => CalldataCodec | null,
    private readonly now: () => number = () => Date.now(),
    /**
     * 投递策略，默认直连。
     * 只有在链节点浏览器不可达（典型：内网 anvil）且钱包支持 eth_signTransaction 时，
     * 才应该换成 ServerRelayDelivery。
     */
    private readonly delivery: TxDelivery = new WalletDirectDelivery(),
  ) {}

  get deliveryMode(): TxDeliveryMode {
    return this.delivery.mode
  }

  /** 投递路径是否可用；UI 应在进入写表单前就展示，而不是等到弹钱包才失败。 */
  deliveryReadiness(): DeliveryReadiness {
    return this.delivery.readiness(this.getWallet())
  }

  /**
   * 组装一笔可提交的交易。不会弹钱包，只做读 + 编码 + 预检。
   * 视图应当把返回的 summary 展示出来，再让用户点“提交”。
   */
  async prepare(intent: WriteIntent, path: AuthorityPath, context: WriteContext): Promise<PreparedWrite> {
    const codec = this.getCodec()
    if (!codec) {
      throw BnsError.config(
        MODEL_ERROR_CODE.NO_CALLDATA_CODEC,
        '未注入 CalldataCodec 适配器，无法编码合约调用',
      )
    }

    const meta = WRITE_INTENT_META[intent.kind]

    // 1. 重读投影，刷新 guard 并计算收敛期望的基线。
    this.repo.invalidateName(intent.name)
    const overview = await this.repo.nameOverview(intent.name)
    const nameState = overview?.state ?? null
    let parentState: NameState | null = null
    if (meta.requiresParentGuard && overview?.parent) {
      const parentOverview = await this.repo.nameOverview(overview.parent)
      parentState = parentOverview?.state ?? null
    } else if (meta.requiresParentGuard && !overview) {
      // 注册尚不存在的二级名称：父名称从名称本身推导。
      const parent = splitParent(intent.name)
      if (parent) {
        const parentOverview = await this.repo.nameOverview(parent)
        parentState = parentOverview?.state ?? null
      }
    }

    const guard = meta.requiresGuard || meta.requiresParentGuard
      ? buildGuard({ nameState, parentState })
      : intent.guard
    const authority = buildCallAuthority(path)
    const finalIntent = { ...intent, guard, authority } as WriteIntent

    const expectation = await this.expectationFor(finalIntent, nameState)

    // 2. 编码 calldata，目标固定为 system.info 给出的 Proxy 地址。
    const data = await codec.encode(finalIntent)
    const request: SendTxRequest = {
      from: context.from,
      to: context.contractAddress,
      data,
      value: '0x0',
    }

    // 3. 预检：估算 gas，失败时尝试解码 custom error。
    let gasEstimate: bigint | null = null
    let simulationError: DecodedContractError | null = null
    const wallet = this.getWallet()
    if (wallet) {
      try {
        gasEstimate = await wallet.estimateGas(request)
      } catch (error) {
        simulationError = decodeRevert(codec, error)
      }
    }

    const staleGuard = simulationError !== null && STALE_GUARD_ERRORS.has(simulationError.name)

    return {
      intent: finalIntent,
      path,
      request,
      context,
      guard,
      guardRefreshedAt: this.now(),
      gasEstimate,
      simulationError,
      staleGuard,
      expectation,
      delivery: { mode: this.delivery.mode, readiness: this.delivery.readiness(wallet) },
      summary: {
        method: meta.method,
        label: meta.label,
        target: intent.name,
        chainId: context.chainId,
        contractAddress: context.contractAddress,
        value: '0x0',
        authority: describeAuthorityPath(path),
        guard: {
          expectedNameSeq: guard.expectedNameSeq.toString(),
          expectedParentNameSeq: guard.expectedParentNameSeq.toString(),
        },
        highRisk: meta.highRisk,
        deliveryMode: this.delivery.mode,
      },
    }
  }

  /**
   * 弹钱包并提交。
   *
   * 直连模式下由钱包决定最终 gas/fee，本模块不覆盖用户的费用设置（PRD 8.5.4）；
   * 中继模式下 gas/fee 只能来自 `tx.prepare`，因为钱包不连链、算不出来 ——
   * 这个差异必须在确认页告诉用户。
   */
  async submit(prepared: PreparedWrite): Promise<TxDeliveryResult> {
    const wallet = this.getWallet()
    if (!wallet) {
      throw BnsError.config(MODEL_ERROR_CODE.NO_WALLET, '未连接钱包，无法提交交易')
    }
    if (prepared.staleGuard) {
      throw BnsError.validation(
        MODEL_ERROR_CODE.STALE_GUARD,
        'MutationGuard 已过期：请重新读取状态并确认新的交易，不做自动重放',
      )
    }
    const current = wallet.getState()
    if (!current.connected || !current.address) {
      throw BnsError.config(MODEL_ERROR_CODE.NO_WALLET, '钱包已断开')
    }
    // 用户在准备阶段之后切换了账户：预检结果必须作废。
    if (current.address.toLowerCase() !== prepared.request.from.toLowerCase()) {
      throw BnsError.validation(
        MODEL_ERROR_CODE.NOT_AUTHORIZED_PATH,
        '钱包账户已切换，之前的授权预检结果已作废，请重新发起操作',
      )
    }
    if (current.chainId !== prepared.context.chainId) {
      throw BnsError.validation(
        MODEL_ERROR_CODE.CHAIN_MISMATCH,
        `钱包当前链 ${current.chainId} 与 bns-server 的 ${prepared.context.chainId} 不一致`,
      )
    }

    const readiness = this.delivery.readiness(wallet)
    if (!readiness.ready) {
      throw BnsError.config(
        MODEL_ERROR_CODE.WALLET_ERROR,
        `投递路径不可用：${readiness.reason ?? '未知原因'}${readiness.hint ? `（${readiness.hint}）` : ''}`,
      )
    }

    return this.delivery.deliver(prepared.request, prepared.context, wallet)
  }

  /**
   * 交易成功后，投影上应当出现的变化。
   * 基线取自 prepare 阶段刚刚读到的状态，因此“已收敛”判定是可靠的。
   */
  private async expectationFor(
    intent: WriteIntent,
    nameState: NameState | null,
  ): Promise<ConvergenceExpectation> {
    switch (intent.kind) {
      case 'register_name':
        return { kind: 'name_exists', name: intent.name }
      case 'renew_name':
        return {
          kind: 'expire_at_greater_than',
          name: intent.name,
          value: nameState?.expireAt ?? 0n,
        }
      case 'update_authority_keys': {
        const set = await this.repo.authoritySet(intent.name).catch(() => null)
        return {
          kind: 'authority_seq_at_least',
          name: intent.name,
          value: (set?.authoritySeq ?? 0n) + 1n,
        }
      }
      case 'publish_document':
      case 'revoke_document':
      case 'set_payment_target':
        return {
          kind: 'document_version_at_least',
          name: intent.name,
          docType: intent.docType,
          value: intent.expectedVersion + 1n,
        }
      case 'publish_log_checkpoint':
        return { kind: 'none' }
      default:
        return {
          kind: 'name_seq_at_least',
          name: intent.name,
          value: (nameState?.nameSeq ?? 0n) + 1n,
        }
    }
  }
}

/** 检查投影是否已经追上这笔交易的效果。 */
export async function isConverged(
  expectation: ConvergenceExpectation,
  repo: ReadRepository,
): Promise<boolean> {
  switch (expectation.kind) {
    case 'none':
      return true
    case 'name_exists': {
      repo.invalidateName(expectation.name)
      return (await repo.nameOverview(expectation.name)) !== null
    }
    case 'name_seq_at_least': {
      repo.invalidateName(expectation.name)
      const overview = await repo.nameOverview(expectation.name)
      return overview !== null && overview.state.nameSeq >= expectation.value
    }
    case 'expire_at_greater_than': {
      repo.invalidateName(expectation.name)
      const overview = await repo.nameOverview(expectation.name)
      return overview !== null && overview.state.expireAt > expectation.value
    }
    case 'authority_seq_at_least': {
      repo.invalidateName(expectation.name)
      const set = await repo.authoritySet(expectation.name)
      return set.authoritySeq >= expectation.value
    }
    case 'document_version_at_least': {
      repo.invalidateName(expectation.name)
      const view = await repo.documentView(expectation.name, expectation.docType)
      return view.state !== null && view.state.version >= expectation.value
    }
  }
}

export function describeExpectation(expectation: ConvergenceExpectation): string {
  switch (expectation.kind) {
    case 'none':
      return '无需等待投影'
    case 'name_exists':
      return `等待 ${expectation.name} 出现在查询投影`
    case 'name_seq_at_least':
      return `等待 ${expectation.name} 的 name_seq ≥ ${expectation.value}`
    case 'expire_at_greater_than':
      return `等待 ${expectation.name} 的 expire_at 超过 ${expectation.value}`
    case 'authority_seq_at_least':
      return `等待 ${expectation.name} 的 authority_seq ≥ ${expectation.value}`
    case 'document_version_at_least':
      return `等待 ${expectation.name} 的 ${expectation.docType} 文档版本 ≥ ${expectation.value}`
  }
}

function decodeRevert(codec: CalldataCodec, error: unknown): DecodedContractError | null {
  const walletError = toWalletError(error)
  const data = walletError.detail.revertData
  if (!data) {
    return { name: 'UnknownError', args: [], raw: walletError.message }
  }
  return codec.decodeError(data) ?? { name: 'UndecodedRevert', args: [], raw: data }
}

function splitParent(name: string): string | null {
  const index = name.indexOf('.')
  return index === -1 ? null : name.slice(index + 1)
}
