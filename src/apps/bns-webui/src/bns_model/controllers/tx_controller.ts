/**
 * 交易 Controller：两阶段轮询调度。
 *
 * 阶段一 `tx.query_state`：pending / succeeded / reverted / not_found
 * 阶段二 业务查询：投影是否已经出现预期变化（ConvergenceExpectation）
 *
 * 只有两个阶段都完成才是 `completed`。
 * 超过 indexerTimeoutMs 仍未收敛 -> `indexer_lagging`，**不是失败**。
 */

import type { BnsModelConfig } from '../config'
import {
  describeProgress,
  isSettled,
  nextPollDelay,
  type TxModel,
  type TxRecord,
  type TxStage,
} from '../models/tx_model'
import type { ReadRepository } from '../services/read_repository'
import { toBnsError } from '../types/errors'
import { WRITE_INTENT_META } from '../write/intents'
import { isConverged, type PreparedWrite } from '../write/write_flow'
import type { TxDeliveryMode } from '../write/delivery'

export interface TxControllerHooks {
  /** 投影收敛后触发，用于让名称详情页自动刷新。 */
  onConverged?: (record: TxRecord) => void
  onStageChange?: (record: TxRecord) => void
}

export class TxController {
  private readonly timers = new Map<string, ReturnType<typeof setTimeout>>()

  constructor(
    private readonly model: TxModel,
    private readonly repo: ReadRepository,
    private readonly config: BnsModelConfig,
    private readonly hooks: TxControllerHooks = {},
    private readonly now: () => number = () => Date.now(),
  ) {}

  /** 页面加载时恢复本地交易并继续轮询（移动钱包跳转返回后必须能接上）。 */
  restore(): void {
    this.model.restore()
    for (const record of this.model.pollable()) this.schedule(record.id, 0)
  }

  /** 拿到 tx_hash 后立即登记，先写本地再开始轮询。 */
  track(prepared: PreparedWrite, txHash: string, deliveryMode: TxDeliveryMode = 'wallet_direct'): TxRecord {
    const meta = WRITE_INTENT_META[prepared.intent.kind]
    const record: TxRecord = {
      id: `${txHash}:${this.now()}`,
      txHash,
      intentKind: prepared.intent.kind,
      method: meta.method,
      label: meta.label,
      target: prepared.intent.name,
      chainId: prepared.context.chainId,
      contractAddress: prepared.context.contractAddress,
      from: prepared.context.from,
      submittedAt: this.now(),
      deliveryMode,
      stage: 'submitted',
      blockNumber: null,
      confirmations: 0n,
      expectation: prepared.expectation,
      chainSucceededAt: null,
      convergedAt: null,
      lastPolledAt: null,
      stopped: false,
      error: null,
      simulationError: prepared.simulationError
        ? { name: prepared.simulationError.name, raw: prepared.simulationError.raw }
        : null,
    }
    this.model.add(record)
    this.schedule(record.id, 0)
    return record
  }

  /** 用户在钱包里取消签名：记录下来，但不算失败。 */
  trackRejected(prepared: PreparedWrite, message: string): TxRecord {
    const meta = WRITE_INTENT_META[prepared.intent.kind]
    const record: TxRecord = {
      id: `rejected:${this.now()}`,
      txHash: null,
      intentKind: prepared.intent.kind,
      method: meta.method,
      label: meta.label,
      target: prepared.intent.name,
      chainId: prepared.context.chainId,
      contractAddress: prepared.context.contractAddress,
      from: prepared.context.from,
      submittedAt: this.now(),
      deliveryMode: 'wallet_direct',
      stage: 'wallet_rejected',
      blockNumber: null,
      confirmations: 0n,
      expectation: { kind: 'none' },
      chainSucceededAt: null,
      convergedAt: null,
      lastPolledAt: null,
      stopped: true,
      error: { code: 'WALLET_REJECTED', message },
      simulationError: null,
    }
    this.model.add(record)
    return record
  }

  stop(id: string): void {
    this.clearTimer(id)
    this.model.patch(id, { stopped: true })
  }

  resume(id: string): void {
    this.model.patch(id, { stopped: false })
    this.schedule(id, 0)
  }

  remove(id: string): void {
    this.clearTimer(id)
    this.model.remove(id)
  }

  clearSettled(): void {
    for (const record of this.model.records) {
      if (isSettled(record.stage)) this.clearTimer(record.id)
    }
    this.model.clearSettled()
  }

  progress(record: TxRecord) {
    return describeProgress(record, this.now(), this.config.polling)
  }

  dispose(): void {
    for (const id of [...this.timers.keys()]) this.clearTimer(id)
  }

  // -------------------------------------------------------------------------

  private schedule(id: string, delayMs: number): void {
    this.clearTimer(id)
    const timer = setTimeout(() => {
      this.timers.delete(id)
      void this.poll(id)
    }, delayMs)
    this.timers.set(id, timer)
  }

  private clearTimer(id: string): void {
    const timer = this.timers.get(id)
    if (timer !== undefined) {
      clearTimeout(timer)
      this.timers.delete(id)
    }
  }

  private async poll(id: string): Promise<void> {
    const record = this.model.records.find((item) => item.id === id)
    if (!record || record.stopped || record.txHash === null || isSettled(record.stage)) return

    const now = this.now()
    try {
      const state = await this.repo.txState(record.txHash)
      let stage: TxStage = record.stage
      let chainSucceededAt = record.chainSucceededAt
      let convergedAt = record.convergedAt

      switch (state.state) {
        case 'pending':
          stage = 'pending'
          break
        case 'not_found':
          // 不是确定失败，继续轮询直到用户停止。
          stage = 'not_found'
          break
        case 'reverted':
          stage = 'chain_reverted'
          break
        case 'succeeded': {
          chainSucceededAt = chainSucceededAt ?? now
          const converged = await isConverged(record.expectation, this.repo)
          if (converged) {
            stage = 'completed'
            convergedAt = now
          } else {
            stage = now - chainSucceededAt > this.config.polling.indexerTimeoutMs
              ? 'indexer_lagging'
              : 'indexing'
          }
          break
        }
      }

      this.model.patch(id, {
        stage,
        blockNumber: state.blockNumber,
        confirmations: state.confirmations,
        lastPolledAt: now,
        chainSucceededAt,
        convergedAt,
        error: null,
      })

      const updated = this.model.records.find((item) => item.id === id)
      if (updated) {
        if (stage !== record.stage) this.hooks.onStageChange?.(updated)
        if (stage === 'completed') {
          this.repo.invalidateName(updated.target)
          this.hooks.onConverged?.(updated)
        }
      }

      if (!isSettled(stage)) {
        this.schedule(id, nextPollDelay(this.config.polling, now - record.submittedAt))
      }
    } catch (error) {
      const bnsError = toBnsError(error)
      // 查询失败只是本次轮询失败，不改变交易结论。
      this.model.patch(id, {
        lastPolledAt: now,
        error: { code: bnsError.code, message: bnsError.message },
      })
      this.schedule(id, nextPollDelay(this.config.polling, now - record.submittedAt))
    }
  }
}
