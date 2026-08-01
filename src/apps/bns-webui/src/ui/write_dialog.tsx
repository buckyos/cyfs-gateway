/**
 * 通用写流程对话框：所有 15 个写操作共用的两步交互（PRD 8.5 / 13.3）。
 *
 *   表单 --「预检并生成交易」--> 确认页 --「在钱包中确认」--> 交易进度
 *
 * 确认页展示 PreparedWrite.summary 的全部安全要素：
 * 方法名、Proxy 地址、chain ID、value=0、授权路径、guard、投递路径（谁广播）、
 * gas 估算与提交前模拟错误。高风险操作要求输入完整名称二次确认。
 *
 * stale guard（预检模拟解出 StaleNameSeq 等）时禁止提交、不自动重放，
 * 只提供「重新预检」——由用户确认新的交易（PRD 8.6）。
 */

import {
  AlertTriangle,
  ArrowRight,
  ExternalLink,
  RefreshCw,
  Send,
  ShieldCheck,
} from 'lucide-react'
import { useCallback, useMemo, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'

import type { PreparedWrite } from '../bns_model'
import { BnsError } from '../bns_model'
import { useBnsModel, useSession } from '../bns_model/react'
import { formatTime, shortAddress } from './format'
import { CopyText, Field, Modal, Note, Pill, Spinner } from './kit'
import { TxStagePill, TxSteps, useTxRecord } from './tx'

type Step = 'form' | 'review' | 'progress'

export interface WriteDialogProps {
  title: string
  icon?: ReactNode
  onClose: () => void
  /** 表单主体；为 null 表示没有表单（直接进入确认，如固定参数的操作）。 */
  form?: ReactNode
  /** 表单是否可以进入预检。 */
  formValid?: boolean
  /** 组装 intent 并调用 controller.prepare。 */
  prepare: () => Promise<PreparedWrite>
  /** 确认页附加内容（before/after 对比、影响说明）。 */
  review?: (prepared: PreparedWrite) => ReactNode
  /** 高风险确认：要求输入的文本（一般是完整名称）。null/undefined = 不要求。 */
  confirmText?: string | null
  /** 额外勾选确认（如 Tombstone 的不可逆确认）。 */
  acknowledge?: string | null
  danger?: boolean
  submitLabel?: string
  wide?: boolean
}

export function WriteDialog({
  title,
  icon,
  onClose,
  form,
  formValid = true,
  prepare,
  review,
  confirmText,
  acknowledge,
  danger = false,
  submitLabel = '在钱包中确认',
  wide = false,
}: WriteDialogProps) {
  const model = useBnsModel()
  const session = useSession()
  const [step, setStep] = useState<Step>('form')
  const [prepared, setPrepared] = useState<PreparedWrite | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<BnsError | null>(null)
  const [typed, setTyped] = useState('')
  const [acked, setAcked] = useState(false)
  const [recordId, setRecordId] = useState<string | null>(null)
  const record = useTxRecord(recordId)

  const runPrepare = useCallback(async () => {
    setBusy(true)
    setError(null)
    try {
      const result = await prepare()
      setPrepared(result)
      setStep('review')
    } catch (prepareError) {
      setError(
        prepareError instanceof BnsError
          ? prepareError
          : BnsError.validation('PREPARE_FAILED', String(prepareError)),
      )
    } finally {
      setBusy(false)
    }
  }, [prepare])

  const runSubmit = useCallback(async () => {
    if (!prepared) return
    setBusy(true)
    setError(null)
    try {
      const txRecord = await model.controllers.name.submit(prepared)
      setRecordId(txRecord.id)
      setStep('progress')
    } catch (submitError) {
      setError(
        submitError instanceof BnsError
          ? submitError
          : BnsError.validation('SUBMIT_FAILED', String(submitError)),
      )
    } finally {
      setBusy(false)
    }
  }, [model, prepared])

  const confirmOk = !confirmText || typed.trim() === confirmText
  const ackOk = !acknowledge || acked

  // 写闸门：唯一的允许/阻断判断来源（PRD README §5）。
  if (!session.writeGate.allowed) {
    return (
      <Modal title={title} icon={icon} onClose={onClose} wide={wide}>
        <Note tone="warn">
          <b>当前不允许提交写交易。</b>
          <div style={{ marginTop: 4 }}>{session.writeGate.reason}</div>
        </Note>
        {session.writeGate.canSwitchChain ? (
          <button
            type="button"
            className="btn"
            onClick={() => void model.controllers.session.switchToServerChain().catch(() => undefined)}
          >
            切换到 bns-server 所在网络
          </button>
        ) : null}
      </Modal>
    )
  }

  const footer =
    step === 'form' ? (
      <>
        <button type="button" className="btn btn--ghost" onClick={onClose}>
          取消
        </button>
        <button
          type="button"
          className="btn btn--primary"
          disabled={!formValid || busy}
          onClick={() => void runPrepare()}
        >
          {busy ? <Spinner /> : <ShieldCheck />}
          预检并生成交易
        </button>
      </>
    ) : step === 'review' && prepared ? (
      <>
        <button type="button" className="btn btn--ghost" onClick={() => setStep('form')} disabled={busy}>
          返回修改
        </button>
        <button type="button" className="btn" onClick={() => void runPrepare()} disabled={busy}>
          <RefreshCw /> 重新预检
        </button>
        <button
          type="button"
          className={danger ? 'btn btn--danger' : 'btn btn--primary'}
          disabled={busy || prepared.staleGuard || !confirmOk || !ackOk}
          onClick={() => void runSubmit()}
        >
          {busy ? <Spinner /> : <Send />}
          {submitLabel}
        </button>
      </>
    ) : (
      <>
        <Link to="/tx" className="btn" onClick={onClose}>
          <ExternalLink /> 打开交易中心
        </Link>
        <button type="button" className="btn btn--primary" onClick={onClose}>
          完成
        </button>
      </>
    )

  return (
    <Modal title={title} icon={icon} onClose={onClose} footer={footer} wide={wide}>
      {step === 'form' ? (
        <>
          {form}
          {error ? (
            <Note tone="danger">
              <b>预检失败（{error.code}）</b>
              <div style={{ marginTop: 4 }}>{error.message}</div>
            </Note>
          ) : null}
        </>
      ) : null}

      {step === 'review' && prepared ? (
        <ReviewStep
          prepared={prepared}
          danger={danger}
          extra={review?.(prepared)}
          confirmText={confirmText ?? null}
          typed={typed}
          onTyped={setTyped}
          acknowledge={acknowledge ?? null}
          acked={acked}
          onAcked={setAcked}
          error={error}
        />
      ) : null}

      {step === 'progress' ? (
        <div>
          {record ? (
            <>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
                <TxStagePill record={record} />
                <span style={{ color: 'var(--text-dim)', fontSize: 12.5 }}>
                  {model.controllers.tx.progress(record).headline}
                </span>
              </div>
              <TxSteps progress={model.controllers.tx.progress(record)} />
              {record.txHash ? (
                <div style={{ marginTop: 10 }}>
                  <span style={{ color: 'var(--text-faint)', fontSize: 12 }}>交易 hash：</span>
                  <CopyText value={record.txHash} display={shortAddress(record.txHash, 10, 8)} />
                </div>
              ) : null}
              {record.stage === 'wallet_rejected' ? (
                <Note tone="neutral">
                  用户在钱包中取消了签名。这不是失败——页面状态已恢复，可重新发起操作。
                </Note>
              ) : (
                <Note tone="info">
                  可以关闭此窗口，交易会继续在后台轮询；进度随时可在交易中心查看。
                </Note>
              )}
            </>
          ) : (
            <div className="loading-row">
              <Spinner /> 正在登记交易…
            </div>
          )}
        </div>
      ) : null}
    </Modal>
  )
}

// ---------------------------------------------------------------------------
// 确认页
// ---------------------------------------------------------------------------

function ReviewStep({
  prepared,
  danger,
  extra,
  confirmText,
  typed,
  onTyped,
  acknowledge,
  acked,
  onAcked,
  error,
}: {
  prepared: PreparedWrite
  danger: boolean
  extra: ReactNode
  confirmText: string | null
  typed: string
  onTyped: (value: string) => void
  acknowledge: string | null
  acked: boolean
  onAcked: (value: boolean) => void
  error: BnsError | null
}) {
  const summary = prepared.summary
  const deliveryLabel = useMemo(
    () =>
      summary.deliveryMode === 'wallet_direct'
        ? '钱包直连（由钱包自己的 RPC 广播）'
        : 'bns-server 中继（由服务端广播，gas/fee 来自 tx.prepare）',
    [summary.deliveryMode],
  )

  return (
    <div>
      {danger || summary.highRisk ? (
        <Note tone="danger">
          <b>高风险操作。</b> 请逐项核对以下参数；钱包确认后交易不可撤回。
        </Note>
      ) : null}

      <dl className="confirm-grid">
        <dt>合约方法</dt>
        <dd className="mono">{summary.method}</dd>
        <dt>操作</dt>
        <dd>
          {summary.label} <span className="mono">{summary.target}</span>
        </dd>
        <dt>BNS Proxy</dt>
        <dd>
          <CopyText value={summary.contractAddress} />
          <span style={{ color: 'var(--text-faint)', fontSize: 11.5, display: 'block' }}>
            地址来自 system.info（合约 Proxy，不是 Facet）
          </span>
        </dd>
        <dt>Chain ID</dt>
        <dd className="mono">{summary.chainId}</dd>
        <dt>Value</dt>
        <dd className="mono">0（当前合约不消费 msg.value）</dd>
        <dt>授权路径</dt>
        <dd>{summary.authority}</dd>
        <dt>MutationGuard</dt>
        <dd className="mono">
          expectedNameSeq = {summary.guard.expectedNameSeq}
          {summary.guard.expectedParentNameSeq !== '0'
            ? ` · expectedParentNameSeq = ${summary.guard.expectedParentNameSeq}`
            : ''}
          <span style={{ color: 'var(--text-faint)', fontSize: 11.5, display: 'block' }}>
            于 {formatTime(BigInt(Math.floor(prepared.guardRefreshedAt / 1000)))} 重读；
            投影可能落后于链上（无同步高度接口，PRD 6.4.7）
          </span>
        </dd>
        <dt>Gas 估算</dt>
        <dd className="mono">
          {prepared.gasEstimate !== null ? prepared.gasEstimate.toString() : '不可用'}
        </dd>
        <dt>投递路径</dt>
        <dd>{deliveryLabel}</dd>
        <dt>收敛条件</dt>
        <dd style={{ color: 'var(--text-dim)' }}>{describeExpectationText(prepared)}</dd>
      </dl>

      {extra ? <div style={{ marginTop: 12 }}>{extra}</div> : null}

      {prepared.staleGuard ? (
        <Note tone="danger">
          <b>预检发现 guard 已过期（Stale*）。</b>
          不会自动重放：请点击「重新预检」读取最新状态后重新确认。
        </Note>
      ) : prepared.simulationError ? (
        <Note tone="warn">
          <b>提交前模拟未通过：{prepared.simulationError.name}</b>
          <div className="mono" style={{ marginTop: 4, fontSize: 11.5, overflowWrap: 'anywhere' }}>
            {prepared.simulationError.raw}
          </div>
          <div style={{ marginTop: 4 }}>仍可尝试提交，但交易大概率会回退；请先核对授权与参数。</div>
        </Note>
      ) : null}

      {!prepared.delivery.readiness.ready ? (
        <Note tone="danger">
          <b>投递路径不可用：</b>
          {prepared.delivery.readiness.reason}
          {prepared.delivery.readiness.hint ? (
            <div style={{ marginTop: 4 }}>{prepared.delivery.readiness.hint}</div>
          ) : null}
        </Note>
      ) : null}

      {confirmText ? (
        <Field
          label={
            <>
              <AlertTriangle style={{ width: 13, height: 13, color: 'var(--danger)' }} />
              输入完整名称 <code>{confirmText}</code> 以确认
            </>
          }
          required
        >
          <input
            type="text"
            className="mono"
            value={typed}
            onChange={(event) => onTyped(event.target.value)}
            placeholder={confirmText}
            autoComplete="off"
          />
        </Field>
      ) : null}

      {acknowledge ? (
        <label className="check">
          <input type="checkbox" checked={acked} onChange={(event) => onAcked(event.target.checked)} />
          <span>{acknowledge}</span>
        </label>
      ) : null}

      {error ? (
        <Note tone="danger">
          <b>提交失败（{error.code}）</b>
          <div style={{ marginTop: 4 }}>{error.message}</div>
        </Note>
      ) : null}
    </div>
  )
}

function describeExpectationText(prepared: PreparedWrite): string {
  const expectation = prepared.expectation
  switch (expectation.kind) {
    case 'none':
      return '无需等待投影'
    case 'name_exists':
      return `等待 ${expectation.name} 出现在查询投影`
    case 'name_seq_at_least':
      return `等待 ${expectation.name} 的 name_seq ≥ ${expectation.value}`
    case 'expire_at_greater_than':
      return `等待 ${expectation.name} 的 expire_at 超过 ${formatTime(expectation.value)}`
    case 'authority_seq_at_least':
      return `等待 ${expectation.name} 的 authority_seq ≥ ${expectation.value}`
    case 'document_version_at_least':
      return `等待 ${expectation.name} 的 ${expectation.docType} 文档版本 ≥ ${expectation.value}`
  }
}

/** before/after 展示组件，转移/owner 变更等确认页复用。 */
export function DiffPair({
  label,
  before,
  after,
}: {
  label: string
  before: ReactNode
  after: ReactNode
}) {
  return (
    <div className="diff-pair">
      <div className="diff-pair__cell">
        <span className="diff-pair__label">{label} · 当前</span>
        {before}
      </div>
      <ArrowRight />
      <div className="diff-pair__cell">
        <span className="diff-pair__label">提交后</span>
        {after}
      </div>
    </div>
  )
}
