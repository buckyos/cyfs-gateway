/**
 * 交易中心 Model：两阶段交易状态机 + 本地恢复。
 *
 * “交易成功”在 BNS 里有两个阶段，缺一不可（PRD 3.G4 / 8.5）：
 *   钱包确认 -> 链上 receipt 成功 -> **bns-indexer 投影收敛**
 * receipt 成功但投影没跟上时必须显示 Indexing，不能显示 Completed。
 *
 * `not_found` 永远不是确定失败：它可能是节点没见过、mempool 丢弃、
 * 同 nonce 替换或历史裁剪。
 */

import type { TxPollingPolicy } from '../config'
import { Store } from '../infra/observable'
import type { StoragePort } from '../ports'
import type { ConvergenceExpectation, WriteIntentKind } from '../write/intents'
import type { TxDeliveryMode } from '../write/delivery'

export type TxStage =
  | 'awaiting_wallet'
  | 'wallet_rejected'
  | 'submitted'
  | 'pending'
  | 'not_found'
  | 'chain_reverted'
  | 'indexing'
  | 'completed'
  | 'indexer_lagging'

export interface TxRecord {
  /** 本地 id，在拿到 tx_hash 之前就存在。 */
  id: string
  txHash: string | null
  intentKind: WriteIntentKind
  method: string
  label: string
  target: string
  chainId: number
  contractAddress: string
  from: string
  submittedAt: number
  /** 这笔交易是谁广播的：钱包自己的 RPC，还是 bns-server 中继。 */
  deliveryMode: TxDeliveryMode
  stage: TxStage
  blockNumber: bigint | null
  confirmations: bigint
  expectation: ConvergenceExpectation
  /** 链上 receipt 成功的时间，用于计算投影等待时长。 */
  chainSucceededAt: number | null
  convergedAt: number | null
  lastPolledAt: number | null
  /** 用户主动停止轮询。 */
  stopped: boolean
  error: { code: string; message: string } | null
  /** 提交前模拟解码出的 custom error，reverted 时优先展示。 */
  simulationError: { name: string; raw: string } | null
}

/** 交易中心的 store 状态。与 `types/domain` 的 `TxState`（链上查询结果）不是一回事。 */
export interface TxCenterState {
  records: TxRecord[]
}

/** 视图用的三段式进度，与 PRD 的交易状态机一致。 */
export interface TxProgress {
  wallet: 'pending' | 'done' | 'failed'
  chain: 'waiting' | 'pending' | 'done' | 'failed' | 'unknown'
  projection: 'waiting' | 'indexing' | 'done' | 'lagging'
  /** 是否为终态（不再轮询）。 */
  settled: boolean
  tone: 'neutral' | 'progress' | 'success' | 'warning' | 'danger'
  headline: string
}

export class TxModel {
  readonly store = new Store<TxCenterState>({ records: [] })

  constructor(
    private readonly storage: StoragePort,
    private readonly storageKey: string,
  ) {}

  get records(): TxRecord[] {
    return this.store.get().records
  }

  add(record: TxRecord): void {
    this.store.set({ records: [record, ...this.records] })
    this.persist()
  }

  patch(id: string, partial: Partial<TxRecord>): void {
    this.store.set({
      records: this.records.map((record) => (record.id === id ? { ...record, ...partial } : record)),
    })
    this.persist()
  }

  remove(id: string): void {
    this.store.set({ records: this.records.filter((record) => record.id !== id) })
    this.persist()
  }

  clearSettled(): void {
    this.store.set({ records: this.records.filter((record) => !isSettled(record.stage)) })
    this.persist()
  }

  /** 还需要继续轮询的交易。 */
  pollable(): TxRecord[] {
    return this.records.filter(
      (record) => record.txHash !== null && !record.stopped && !isSettled(record.stage),
    )
  }

  // -------------------------------------------------------------------------
  // 本地恢复：刷新页面、移动钱包跳转返回后不能丢交易
  // -------------------------------------------------------------------------

  restore(): void {
    const raw = this.storage.get(this.storageKey)
    if (!raw) return
    try {
      const parsed: unknown = JSON.parse(raw)
      if (!Array.isArray(parsed)) return
      this.store.set({ records: parsed.map(reviveRecord).filter((r): r is TxRecord => r !== null) })
    } catch {
      // 本地数据损坏不影响使用，直接忽略。
    }
  }

  private persist(): void {
    try {
      this.storage.set(this.storageKey, JSON.stringify(this.records.map(serializeRecord)))
    } catch {
      // 存储不可用（隐私模式等）时静默降级为内存态。
    }
  }
}

export function isSettled(stage: TxStage): boolean {
  return stage === 'completed' || stage === 'chain_reverted' || stage === 'wallet_rejected'
}

/**
 * 按 PRD 8.5.6 的分段节奏计算下一次轮询延迟。
 * 超过全部分段后降到 tail 间隔，UI 必须同时提供“停止轮询”。
 */
export function nextPollDelay(policy: TxPollingPolicy, elapsedMs: number): number {
  for (const phase of policy.phases) {
    if (elapsedMs < phase.untilMs) return phase.intervalMs
  }
  return policy.tailIntervalMs
}

export function describeProgress(record: TxRecord, now: number, policy: TxPollingPolicy): TxProgress {
  switch (record.stage) {
    case 'awaiting_wallet':
      return {
        wallet: 'pending',
        chain: 'waiting',
        projection: 'waiting',
        settled: false,
        tone: 'neutral',
        headline: '等待钱包确认',
      }
    case 'wallet_rejected':
      return {
        wallet: 'failed',
        chain: 'waiting',
        projection: 'waiting',
        settled: true,
        tone: 'neutral',
        headline: '用户取消了签名',
      }
    case 'submitted':
    case 'pending':
      return {
        wallet: 'done',
        chain: 'pending',
        projection: 'waiting',
        settled: false,
        tone: 'progress',
        headline: '已提交，等待打包',
      }
    case 'not_found':
      return {
        wallet: 'done',
        chain: 'unknown',
        projection: 'waiting',
        settled: false,
        tone: 'warning',
        // not_found 不等于失败，措辞必须保留不确定性。
        headline: '节点暂时找不到该交易（可能被替换或尚未广播）',
      }
    case 'chain_reverted':
      return {
        wallet: 'done',
        chain: 'failed',
        projection: 'waiting',
        settled: true,
        tone: 'danger',
        headline: '交易已回退',
      }
    case 'indexing': {
      const waited = record.chainSucceededAt === null ? 0 : now - record.chainSucceededAt
      const lagging = waited > policy.indexerTimeoutMs
      return {
        wallet: 'done',
        chain: 'done',
        projection: lagging ? 'lagging' : 'indexing',
        settled: false,
        tone: 'warning',
        headline: lagging
          ? '链上已成功，Indexer 尚未同步'
          : '链上已成功，正在等待查询投影更新',
      }
    }
    case 'indexer_lagging':
      return {
        wallet: 'done',
        chain: 'done',
        projection: 'lagging',
        settled: false,
        tone: 'warning',
        headline: '链上已成功，Indexer 尚未同步',
      }
    case 'completed':
      return {
        wallet: 'done',
        chain: 'done',
        projection: 'done',
        settled: true,
        tone: 'success',
        headline: '已确认并完成索引',
      }
  }
}

// ---------------------------------------------------------------------------
// 序列化：bigint 不能直接进 JSON
// ---------------------------------------------------------------------------

function serializeRecord(record: TxRecord): Record<string, unknown> {
  return {
    ...record,
    blockNumber: record.blockNumber === null ? null : record.blockNumber.toString(),
    confirmations: record.confirmations.toString(),
    expectation: serializeExpectation(record.expectation),
  }
}

function serializeExpectation(expectation: ConvergenceExpectation): Record<string, unknown> {
  if ('value' in expectation) {
    return { ...expectation, value: expectation.value.toString() }
  }
  return { ...expectation }
}

function reviveRecord(raw: unknown): TxRecord | null {
  if (typeof raw !== 'object' || raw === null) return null
  const record = raw as Record<string, unknown>
  if (typeof record.id !== 'string') return null
  return {
    ...(record as unknown as TxRecord),
    blockNumber: typeof record.blockNumber === 'string' ? BigInt(record.blockNumber) : null,
    confirmations: typeof record.confirmations === 'string' ? BigInt(record.confirmations) : 0n,
    expectation: reviveExpectation(record.expectation),
  }
}

function reviveExpectation(raw: unknown): ConvergenceExpectation {
  if (typeof raw !== 'object' || raw === null) return { kind: 'none' }
  const value = raw as Record<string, unknown>
  if (typeof value.value === 'string') {
    return { ...(value as unknown as ConvergenceExpectation), value: BigInt(value.value) } as ConvergenceExpectation
  }
  return value as unknown as ConvergenceExpectation
}
