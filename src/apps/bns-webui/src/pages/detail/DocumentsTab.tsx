/**
 * 文档 tab（PRD 9.9 / 9.10 / 9.11 / 9.15）。
 *
 * 已知 doc type 入口 = 内置 6 个 + 本地历史 + 用户输入 + 事件发现，
 * 每项带来源标注；不宣称完整（bns-server 没有列举接口）。
 */

import { clsx } from 'clsx'
import { Ban, Coins, FileText, History, Plus, RefreshCw } from 'lucide-react'
import { useEffect, useState } from 'react'

import type { DocumentState, DocumentView, NameAggregate } from '../../bns_model'
import { bytesToHex } from '../../bns_model'
import { useBnsModel } from '../../bns_model/react'
import {
  DOC_STATUS_LABEL,
  DOC_STATUS_TONE,
  formatBytes,
  formatTime,
  isZeroHex,
  principalText,
  shortHash,
} from '../../ui/format'
import { CopyText, Note, Pill, RawDetails, Spinner } from '../../ui/kit'
import { PaymentTargetDialog, PublishDocumentDialog, RevokeDocumentDialog } from './dialogs'

const SOURCE_LABEL: Record<string, string> = {
  builtin: '内置',
  local_history: '本地历史',
  event_log: '事件发现',
  user_input: '手工输入',
}

export function DocumentsTab({ aggregate }: { aggregate: NameAggregate }) {
  const model = useBnsModel()
  const [selected, setSelected] = useState<string>(aggregate.docTypes[0]?.docType ?? 'zone')
  const [customType, setCustomType] = useState('')
  const [dialog, setDialog] = useState<'publish' | 'revoke' | 'payment' | null>(null)

  useEffect(() => {
    void model.controllers.name.loadKnownDocuments(aggregate.name)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [model, aggregate.name])

  const docState = aggregate.documents[selected]
  const view = docState?.data ?? null

  const loadCustom = () => {
    const type = customType.trim()
    if (!type) return
    void model.controllers.name.loadDocument(aggregate.name, type)
    setSelected(type)
    setCustomType('')
  }

  return (
    <div>
      <Note tone="info">
        bns-server 没有「列出一个名称全部 doc type」的接口。下方入口由内置常用类型、本地历史、
        手工输入与事件发现组成，<b>不保证完整</b>。
      </Note>

      <div className="chips" style={{ margin: '12px 0' }}>
        {aggregate.docTypes.map((entry) => {
          const loaded = aggregate.documents[entry.docType]?.data
          const exists = loaded?.state != null
          return (
            <span
              key={entry.docType}
              className={clsx('radio-card', selected === entry.docType && 'is-active')}
              onClick={() => setSelected(entry.docType)}
              title={`来源：${SOURCE_LABEL[entry.source]}`}
            >
              <span className="mono">{entry.docType}</span>
              {exists ? (
                <Pill tone={DOC_STATUS_TONE[loaded.rawStatus]} title="raw status">
                  v{loaded.state?.version.toString()}
                </Pill>
              ) : (
                <span style={{ color: 'var(--text-faint)', fontSize: 10.5, marginLeft: 5 }}>未发布</span>
              )}
            </span>
          )
        })}
        <span style={{ display: 'inline-flex', gap: 6 }}>
          <input
            type="text"
            className="mono"
            value={customType}
            onChange={(event) => setCustomType(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter') loadCustom()
            }}
            placeholder="其它 doc type…"
            style={{
              background: 'var(--bg-raise)',
              border: '1px solid var(--line)',
              borderRadius: 7,
              color: 'var(--text)',
              padding: '4px 9px',
              fontSize: 12,
              width: 130,
            }}
          />
          <button type="button" className="btn btn--sm" onClick={loadCustom}>
            查询
          </button>
        </span>
      </div>

      <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
        <button type="button" className="btn btn--primary btn--sm" onClick={() => setDialog('publish')}>
          <Plus /> 发布 / 更新 {selected}
        </button>
        {view?.state ? (
          <>
            <button type="button" className="btn btn--sm" onClick={() => setDialog('payment')}>
              <Coins /> 设置支付目标
            </button>
            <button type="button" className="btn btn--danger btn--sm" onClick={() => setDialog('revoke')}>
              <Ban /> 撤销文档
            </button>
          </>
        ) : null}
        <button
          type="button"
          className="btn btn--ghost btn--sm"
          onClick={() => void model.controllers.name.loadDocument(aggregate.name, selected)}
        >
          <RefreshCw /> 刷新
        </button>
      </div>

      {docState?.status === 'loading' && !view ? (
        <div className="loading-row">
          <Spinner /> 解析 {selected} …
        </div>
      ) : view ? (
        <DocumentCard aggregate={aggregate} view={view} />
      ) : (
        <div className="empty">该 doc type 尚未加载</div>
      )}

      {dialog === 'publish' ? (
        <PublishDocumentDialog aggregate={aggregate} initialDocType={selected} onClose={() => setDialog(null)} />
      ) : null}
      {dialog === 'revoke' ? (
        <RevokeDocumentDialog aggregate={aggregate} docType={selected} onClose={() => setDialog(null)} />
      ) : null}
      {dialog === 'payment' ? (
        <PaymentTargetDialog aggregate={aggregate} docType={selected} onClose={() => setDialog(null)} />
      ) : null}
    </div>
  )
}

// ---------------------------------------------------------------------------

function DocumentCard({ aggregate, view }: { aggregate: NameAggregate; view: DocumentView }) {
  const model = useBnsModel()
  const state = view.state

  if (state === null) {
    return (
      <section className="card">
        <h2 className="card__title">
          <FileText /> {view.docType}
        </h2>
        <div className="empty">从未发布过该 doc type（DOCUMENT_NOT_FOUND 缺失态）</div>
      </section>
    )
  }

  return (
    <section className="card">
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 10 }}>
        <h2 className="card__title" style={{ margin: 0 }}>
          <FileText /> {view.docType} · v{state.version.toString()}
        </h2>
        <Pill tone={DOC_STATUS_TONE[view.rawStatus]}>raw: {DOC_STATUS_LABEL[view.rawStatus]}</Pill>
        {view.derivedStatus !== view.rawStatus ? (
          <Pill tone={DOC_STATUS_TONE[view.derivedStatus]} title="与 DID Resolver 同口径的派生状态">
            派生: {DOC_STATUS_LABEL[view.derivedStatus]}
          </Pill>
        ) : null}
      </div>

      <dl className="kv">
        <dt>版本 / 前版本</dt>
        <dd className="mono">
          {state.version.toString()} / {state.previousVersion.toString()}
        </dd>
        <dt>存储</dt>
        <dd>
          {view.isInline ? `inline（${formatBytes(view.inlineByteLength)}）` : state.document.storageType}
          {state.document.uri ? (
            <span className="mono" style={{ display: 'block', fontSize: 11.5, color: 'var(--text-dim)' }}>
              {state.document.uri}
            </span>
          ) : null}
        </dd>
        <dt>content hash</dt>
        <dd>
          <CopyText value={state.document.contentHash} display={shortHash(state.document.contentHash)} />
        </dd>
        <dt>controller</dt>
        <dd>
          {principalText(state.controller)}
          <span style={{ color: 'var(--text-faint)', fontSize: 11.5, display: 'block' }}>
            effective controller：{principalText(view.effectiveController)}
          </span>
        </dd>
        <dt>beneficiary</dt>
        <dd>{principalText(state.beneficiary)}</dd>
        <dt>payment target</dt>
        <dd className="mono">{isZeroHex(state.paymentTarget) ? '未设置' : state.paymentTarget}</dd>
        <dt>有效期</dt>
        <dd>
          {formatTime(state.validFrom)} 起 · {formatTime(state.expireAt)} 止
          {state.revokedAt > 0n ? ` · 撤销于 ${formatTime(state.revokedAt)}` : ''}
        </dd>
        <dt>policy hashes</dt>
        <dd className="chips">
          {(
            [
              ['controller', state.controllerPolicyHash],
              ['payment', state.paymentPolicyHash],
              ['split', state.splitPolicyHash],
              ['price', state.pricePolicyHash],
              ['rights', state.rightsPolicyHash],
            ] as const
          ).map(([label, hash]) => (
            <Pill key={label} tone={isZeroHex(hash) ? 'muted' : 'neutral'} title={hash}>
              {label}: {isZeroHex(hash) ? 'zero' : shortHash(hash, 4, 4)}
            </Pill>
          ))}
        </dd>
        <dt>document state hash</dt>
        <dd>
          <CopyText value={state.documentStateHash} display={shortHash(state.documentStateHash)} />
        </dd>
        {view.aliasKind !== 'none' ? (
          <>
            <dt>alias</dt>
            <dd>
              {view.aliasKind} → <span className="mono">{view.aliasTargetDid}</span>
            </dd>
          </>
        ) : null}
      </dl>

      {view.isInline ? <InlinePreview view={view} /> : null}

      <HistorySection aggregate={aggregate} docType={view.docType} currentVersion={state.version} />

      <RawDetails label="文档原始数据（domain JSON）" value={state} />
      <div style={{ marginTop: 8, fontSize: 11.5, color: 'var(--text-faint)' }}>
        需要更多版本时使用 document.get_version 懒加载；页面重开后由{' '}
        <button
          type="button"
          className="btn btn--ghost btn--sm"
          onClick={() => void model.controllers.name.loadDocument(aggregate.name, view.docType)}
        >
          重新解析
        </button>{' '}
        获取最新版本。
      </div>
    </section>
  )
}

function InlinePreview({ view }: { view: DocumentView }) {
  const [mode, setMode] = useState<'auto' | 'hex'>('auto')
  const bytes = view.state?.document.inlineDocument ?? new Uint8Array(0)

  return (
    <div style={{ marginTop: 12 }}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 6 }}>
        <span style={{ fontSize: 12, color: 'var(--text-faint)' }}>inline 内容</span>
        <span
          className={clsx('radio-card', mode === 'auto' && 'is-active')}
          style={{ padding: '2px 8px', fontSize: 11 }}
          onClick={() => setMode('auto')}
        >
          {view.inlineJson !== null ? 'JSON' : '文本'}
        </span>
        <span
          className={clsx('radio-card', mode === 'hex' && 'is-active')}
          style={{ padding: '2px 8px', fontSize: 11 }}
          onClick={() => setMode('hex')}
        >
          原始 bytes
        </span>
      </div>
      {mode === 'hex' ? (
        <pre className="codeblock">{bytesToHex(bytes)}</pre>
      ) : view.inlineJson !== null ? (
        <pre className="codeblock">{JSON.stringify(view.inlineJson, null, 2)}</pre>
      ) : view.inlineText !== null ? (
        <pre className="codeblock">{view.inlineText}</pre>
      ) : (
        <Note tone="info">内容不是合法 UTF-8，请使用原始 bytes 视图。</Note>
      )}
      <div style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 4 }}>
        inline 内容按不可信数据处理，仅以文本渲染（PRD 13.2）。
      </div>
    </div>
  )
}

function HistorySection({
  aggregate,
  docType,
  currentVersion,
}: {
  aggregate: NameAggregate
  docType: string
  currentVersion: bigint
}) {
  const model = useBnsModel()
  const history = aggregate.documentHistory[docType]
  const [open, setOpen] = useState(false)

  const load = () => {
    setOpen(true)
    void model.controllers.name.loadDocumentHistory(aggregate.name, docType)
  }

  return (
    <div style={{ marginTop: 12 }}>
      {!open ? (
        <button type="button" className="btn btn--sm" onClick={load} disabled={currentVersion <= 1n}>
          <History /> 加载历史版本（按 1..{currentVersion.toString()} 懒加载）
        </button>
      ) : history?.status === 'loading' && !history.data ? (
        <div className="loading-row">
          <Spinner /> 逐版本拉取（无版本列表接口）…
        </div>
      ) : history?.data ? (
        <div className="table-wrap" style={{ marginTop: 8 }}>
          <table className="table">
            <thead>
              <tr>
                <th>版本</th>
                <th>状态</th>
                <th>content hash</th>
                <th>生效时间</th>
                <th>payment target</th>
              </tr>
            </thead>
            <tbody>
              {[...history.data]
                .sort((a: DocumentState, b: DocumentState) => (a.version > b.version ? -1 : 1))
                .map((doc) => (
                  <tr key={doc.version.toString()}>
                    <td className="mono">v{doc.version.toString()}</td>
                    <td>
                      <Pill tone={DOC_STATUS_TONE[doc.status]}>{DOC_STATUS_LABEL[doc.status]}</Pill>
                    </td>
                    <td className="mono">{shortHash(doc.document.contentHash, 6, 4)}</td>
                    <td>{formatTime(doc.validFrom)}</td>
                    <td className="mono">{isZeroHex(doc.paymentTarget) ? '—' : shortHash(doc.paymentTarget, 5, 4)}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  )
}
