/**
 * 交易中心（PRD 9.19）：本地交易记录 + 两阶段状态机。
 *
 * - 页面重开后对未终态交易恢复轮询（TxController.restore 已在启动时执行）；
 * - not_found 不显示为确定失败；
 * - 隐藏本地记录 ≠ 取消链上交易；
 * - 不提供加速 / 取消 / 替换入口（由钱包负责）。
 */

import {
  ArrowLeftRight,
  ArrowRight,
  Pause,
  Play,
  RefreshCw,
  Trash2,
} from 'lucide-react'
import { Link } from 'react-router-dom'

import { isSettled, type TxRecord } from '../bns_model'
import { useBnsModel, useTransactions } from '../bns_model/react'
import { formatTime, shortAddress } from '../ui/format'
import { CopyText, Note, Pill } from '../ui/kit'
import { TxStagePill, TxSteps } from '../ui/tx'

export function TxCenterPage() {
  const model = useBnsModel()
  const transactions = useTransactions()

  return (
    <div>
      <h1 className="page-title">
        <ArrowLeftRight style={{ width: 20, height: 20, color: 'var(--accent)' }} /> 交易中心
      </h1>
      <p className="page-sub">
        一笔写操作有两个完成阶段：链上交易成功，以及 bns-indexer 投影收敛。
        只有两者都满足才显示「已完成」。记录保存在本地浏览器，不含私钥或签名原文。
      </p>

      {transactions.records.length === 0 ? (
        <section className="card">
          <div className="empty">还没有本地交易记录。从注册、续期或文档发布等操作发起第一笔交易。</div>
        </section>
      ) : (
        <>
          <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
            <button type="button" className="btn btn--sm" onClick={() => model.controllers.tx.clearSettled()}>
              <Trash2 /> 清除已终态记录
            </button>
          </div>
          {transactions.records.map((record) => (
            <TxCard key={record.id} record={record} />
          ))}
        </>
      )}

      <Note tone="info">
        本页不提供交易加速 / 取消 / 替换：这些高级操作由钱包负责。
        隐藏本地记录不等于取消链上交易。
      </Note>
    </div>
  )
}

function TxCard({ record }: { record: TxRecord }) {
  const model = useBnsModel()
  const progress = model.controllers.tx.progress(record)
  const settled = isSettled(record.stage)

  return (
    <section className="card">
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', marginBottom: 6 }}>
        <b style={{ fontSize: 14 }}>{record.label}</b>
        <Link to={`/name/${encodeURIComponent(record.target)}`} className="mono" style={{ fontSize: 13 }}>
          {record.target}
        </Link>
        <TxStagePill record={record} />
        <span style={{ marginLeft: 'auto', fontSize: 11.5, color: 'var(--text-faint)' }}>
          提交于 {formatTime(BigInt(Math.floor(record.submittedAt / 1000)))}
        </span>
      </div>

      <TxSteps progress={progress} />
      <div style={{ fontSize: 12.5, color: 'var(--text-dim)', margin: '6px 0 8px' }}>{progress.headline}</div>

      <dl className="kv kv--tight">
        {record.txHash ? (
          <>
            <dt>tx hash</dt>
            <dd>
              <CopyText value={record.txHash} display={shortAddress(record.txHash, 10, 8)} />
            </dd>
          </>
        ) : null}
        <dt>方法 / 投递</dt>
        <dd className="mono">
          {record.method} · {record.deliveryMode === 'wallet_direct' ? '钱包直连' : '服务端中继'}
        </dd>
        <dt>区块 / 确认数</dt>
        <dd className="mono">
          {record.blockNumber?.toString() ?? '—'} / {record.confirmations.toString()}
        </dd>
        {record.simulationError ? (
          <>
            <dt>提交前模拟</dt>
            <dd style={{ color: 'var(--warn)' }}>
              {record.simulationError.name}
              <span className="mono" style={{ display: 'block', fontSize: 11, overflowWrap: 'anywhere' }}>
                {record.simulationError.raw}
              </span>
            </dd>
          </>
        ) : null}
        {record.error ? (
          <>
            <dt>最近一次轮询</dt>
            <dd style={{ color: 'var(--warn)', fontSize: 12 }}>
              {record.error.code}：{record.error.message}（查询失败不改变交易结论）
            </dd>
          </>
        ) : null}
      </dl>

      {record.stage === 'chain_reverted' ? (
        <Note tone="danger">
          交易已回退。tx.query_state 当前不提供 revert reason；
          {record.simulationError ? '优先参考上方提交前模拟错误。' : '请查看区块浏览器或 RPC 调试信息。'}
          如需重试，请回到业务页面重新构造交易（不复用旧 calldata）。
        </Note>
      ) : null}
      {record.stage === 'indexing' || record.stage === 'indexer_lagging' ? (
        <Note tone={record.stage === 'indexer_lagging' ? 'warn' : 'info'}>
          {record.stage === 'indexer_lagging'
            ? '链上已成功，但超过 5 分钟投影仍未收敛：Indexer 尚未同步，这不是失败。'
            : '链上已成功，正在等待投影出现预期变化。'}
          <Link to={`/name/${encodeURIComponent(record.target)}`} style={{ marginLeft: 6 }}>
            查看业务页面 <ArrowRight style={{ width: 12, height: 12 }} />
          </Link>
        </Note>
      ) : null}

      <div style={{ display: 'flex', gap: 8, marginTop: 10, flexWrap: 'wrap' }}>
        {!settled && record.txHash ? (
          record.stopped ? (
            <button type="button" className="btn btn--sm" onClick={() => model.controllers.tx.resume(record.id)}>
              <Play /> 恢复轮询
            </button>
          ) : (
            <button type="button" className="btn btn--sm" onClick={() => model.controllers.tx.stop(record.id)}>
              <Pause /> 停止轮询
            </button>
          )
        ) : null}
        {record.stopped && !settled ? <Pill tone="muted">轮询已停止</Pill> : null}
        {!settled && record.txHash ? (
          <button type="button" className="btn btn--sm" onClick={() => model.controllers.tx.resume(record.id)}>
            <RefreshCw /> 立即重查
          </button>
        ) : null}
        <button
          type="button"
          className="btn btn--ghost btn--sm"
          onClick={() => model.controllers.tx.remove(record.id)}
          title="仅隐藏本地记录，不取消链上交易"
        >
          <Trash2 /> 隐藏记录
        </button>
      </div>
    </section>
  )
}
