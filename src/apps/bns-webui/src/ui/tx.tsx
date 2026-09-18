/**
 * 交易展示组件：三段进度（钱包 → 链上 → 索引）与阶段徽标。
 *
 * 口径与 PRD G4 一致：链上成功 ≠ 完成，必须等投影收敛；
 * not_found 不是确定失败；indexer 滞后不显示为失败。
 */

import { clsx } from 'clsx'
import { Check, Clock, Database, Link as LinkIcon, Wallet, X } from 'lucide-react'

import type { TxProgress, TxRecord } from '../bns_model'
import { useBnsModel, useStore } from '../bns_model/react'
import { Pill } from './kit'
import { TX_STAGE_LABEL, TX_STAGE_TONE } from './format'

export function TxStagePill({ record }: { record: TxRecord }) {
  return (
    <Pill tone={TX_STAGE_TONE[record.stage]} dot>
      {TX_STAGE_LABEL[record.stage]}
    </Pill>
  )
}

function stepClass(state: 'idle' | 'active' | 'done' | 'warn' | 'failed'): string {
  return clsx('txsteps__step', {
    'is-done': state === 'done',
    'is-active': state === 'active',
    'is-warn': state === 'warn',
    'is-failed': state === 'failed',
  })
}

export function TxSteps({ progress }: { progress: TxProgress }) {
  const wallet =
    progress.wallet === 'done' ? 'done' : progress.wallet === 'failed' ? 'failed' : 'active'
  const chain =
    progress.chain === 'done'
      ? 'done'
      : progress.chain === 'failed'
        ? 'failed'
        : progress.chain === 'pending'
          ? 'active'
          : progress.chain === 'unknown'
            ? 'warn'
            : 'idle'
  const projection =
    progress.projection === 'done'
      ? 'done'
      : progress.projection === 'indexing'
        ? 'active'
        : progress.projection === 'lagging'
          ? 'warn'
          : 'idle'

  return (
    <div className="txsteps">
      <div className={stepClass(wallet)}>
        <span className="txsteps__dot">
          {progress.wallet === 'done' ? <Check /> : progress.wallet === 'failed' ? <X /> : <Wallet />}
        </span>
        钱包签名
      </div>
      <span className="txsteps__bar" />
      <div className={stepClass(chain)}>
        <span className="txsteps__dot">
          {progress.chain === 'done' ? <Check /> : progress.chain === 'failed' ? <X /> : <LinkIcon />}
        </span>
        链上确认
      </div>
      <span className="txsteps__bar" />
      <div className={stepClass(projection)}>
        <span className="txsteps__dot">
          {progress.projection === 'done' ? (
            <Check />
          ) : progress.projection === 'lagging' ? (
            <Clock />
          ) : (
            <Database />
          )}
        </span>
        投影索引
      </div>
    </div>
  )
}

/** 从交易中心 store 里订阅一条记录（提交后进度实时更新）。 */
export function useTxRecord(id: string | null): TxRecord | null {
  const model = useBnsModel()
  const state = useStore(model.models.tx.store)
  if (!id) return null
  return state.records.find((record) => record.id === id) ?? null
}
