/**
 * 名称详情页（PRD 7.3）：概览 / 文档 / Owner 与 Authority / Controller /
 * Alias 与支付 / Namespace / 活动记录 / 危险操作。
 */

import { clsx } from 'clsx'
import { AlertTriangle, ArrowLeftRight, Info, RotateCcw } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useParams, useSearchParams } from 'react-router-dom'

import type { NameAggregate } from '../bns_model'
import { didBnsFromName, isSettled } from '../bns_model'
import { useNameDetail, useTransactions } from '../bns_model/react'
import {
  derivedStatusLabel,
  formatRelative,
  formatTime,
  isZeroHex,
  NAME_STATUS_LABEL,
  NAME_STATUS_TONE,
  OWNER_SOURCE_LABEL,
  principalText,
  shortHash,
} from '../ui/format'
import { CopyText, ErrorBox, Note, Pill, RawDetails, Spinner } from '../ui/kit'
import { DocumentsTab } from './detail/DocumentsTab'
import { OwnerAuthorityTab } from './detail/OwnerAuthorityTab'
import {
  ActivityTab,
  AliasPaymentTab,
  ControllerTab,
  DangerTab,
  NamespaceTab,
} from './detail/MoreTabs'
import { RenewDialog, TransferDialog } from './detail/dialogs'

const TABS = [
  { id: 'overview', label: '概览' },
  { id: 'documents', label: '文档' },
  { id: 'owner', label: 'Owner 与 Authority' },
  { id: 'controller', label: 'Controller' },
  { id: 'alias', label: 'Alias 与支付' },
  { id: 'namespace', label: 'Namespace' },
  { id: 'activity', label: '活动记录' },
  { id: 'danger', label: '危险操作', danger: true },
] as const

type TabId = (typeof TABS)[number]['id']

export function NameDetailPage() {
  const params = useParams<{ name: string }>()
  const name = decodeURIComponent(params.name ?? '')
  const [searchParams, setSearchParams] = useSearchParams()
  const tab = (searchParams.get('tab') as TabId | null) ?? 'overview'
  const aggregate = useNameDetail(name)
  const transactions = useTransactions()
  const [dialog, setDialog] = useState<'renew' | 'transfer' | null>(null)

  const pendingTx = useMemo(
    () =>
      transactions.records.filter(
        (record) => record.target === name && !isSettled(record.stage) && !record.stopped,
      ).length,
    [transactions.records, name],
  )

  const overview = aggregate.overview.data ?? null
  const derived = overview ? derivedStatusLabel(overview.derived) : null

  return (
    <div>
      <div className="detail-head">
        <div>
          <div className="detail-head__title">{name}</div>
          <div className="detail-head__did">
            <CopyText value={didBnsFromName(name)} />
          </div>
        </div>
        <div className="chips" style={{ alignItems: 'center' }}>
          {overview ? (
            <>
              <Pill tone={NAME_STATUS_TONE[overview.state.status]}>
                raw: {NAME_STATUS_LABEL[overview.state.status]}
              </Pill>
              {derived && (overview.derived.timeExpired || overview.derived.label !== 'active') ? (
                <Pill tone={derived.tone}>{derived.text}</Pill>
              ) : null}
            </>
          ) : aggregate.overview.status === 'loading' ? (
            <Spinner />
          ) : null}
          {pendingTx > 0 ? <Pill tone="progress">{pendingTx} 笔交易进行中</Pill> : null}
        </div>
        <div className="detail-head__actions">
          <button type="button" className="btn" onClick={() => setDialog('renew')}>
            <RotateCcw /> 续期
          </button>
          <button
            type="button"
            className="btn"
            onClick={() => setDialog('transfer')}
            disabled={!overview}
            title="需要 effective owner 授权"
          >
            <ArrowLeftRight /> 转移
          </button>
        </div>
      </div>

      {aggregate.overview.status === 'error' ? <ErrorBox error={aggregate.overview.error} /> : null}
      {aggregate.overview.status === 'ready' && overview === null ? (
        <Note tone="warn">
          名称未在当前投影中找到。若刚提交注册，Indexer 可能尚未同步；也可以在
          「注册名称」页检查它是否可注册。
        </Note>
      ) : null}

      <div className="tabs">
        {TABS.map((item) => (
          <button
            key={item.id}
            type="button"
            className={clsx(
              'tabs__item',
              tab === item.id && 'is-active',
              'danger' in item && item.danger && 'is-danger',
            )}
            onClick={() => setSearchParams({ tab: item.id })}
          >
            {'danger' in item && item.danger ? <AlertTriangle style={{ width: 13, height: 13 }} /> : null}
            {item.label}
          </button>
        ))}
      </div>

      {tab === 'overview' ? <OverviewTab aggregate={aggregate} /> : null}
      {tab === 'documents' ? <DocumentsTab aggregate={aggregate} /> : null}
      {tab === 'owner' ? <OwnerAuthorityTab aggregate={aggregate} /> : null}
      {tab === 'controller' ? <ControllerTab aggregate={aggregate} /> : null}
      {tab === 'alias' ? <AliasPaymentTab aggregate={aggregate} /> : null}
      {tab === 'namespace' ? <NamespaceTab aggregate={aggregate} /> : null}
      {tab === 'activity' ? <ActivityTab aggregate={aggregate} /> : null}
      {tab === 'danger' ? <DangerTab aggregate={aggregate} /> : null}

      {dialog === 'renew' ? <RenewDialog aggregate={aggregate} onClose={() => setDialog(null)} /> : null}
      {dialog === 'transfer' ? <TransferDialog aggregate={aggregate} onClose={() => setDialog(null)} /> : null}
    </div>
  )
}

// ---------------------------------------------------------------------------
// 概览 tab（PRD 9.2 名称详情摘要）
// ---------------------------------------------------------------------------

function OverviewTab({ aggregate }: { aggregate: NameAggregate }) {
  const overview = aggregate.overview.data ?? null
  const parent = aggregate.parent.data ?? null

  if (!overview) {
    return aggregate.overview.status === 'loading' ? (
      <div className="loading-row">
        <Spinner /> 加载名称状态…
      </div>
    ) : (
      <div className="empty">没有可展示的投影数据</div>
    )
  }

  const state = overview.state

  return (
    <div>
      <div className="grid grid--2">
        <section className="card">
          <h2 className="card__title">
            <Info /> 基本信息
          </h2>
          <dl className="kv kv--tight">
            <dt>Asset Owner</dt>
            <dd>
              <CopyText value={state.assetOwner} />
            </dd>
            <dt>Semantic Owner</dt>
            <dd>{principalText(state.semanticOwner)}</dd>
            <dt>Effective Owner</dt>
            <dd>
              <b>{principalText(state.effectiveOwner)}</b>
              <span style={{ color: 'var(--text-faint)', fontSize: 11.5, display: 'block' }}>
                {OWNER_SOURCE_LABEL[state.ownerSource]}
              </span>
            </dd>
            <dt>name_seq / lineage_epoch</dt>
            <dd className="mono">
              {state.nameSeq.toString()} / {state.lineageEpoch.toString()}
            </dd>
            <dt>owner 文档版本</dt>
            <dd className="mono">{state.ownerDocumentVersion.toString()}</dd>
            <dt>min_document_iat</dt>
            <dd>
              {state.minDocumentIat === 0n ? '未设置' : formatTime(state.minDocumentIat)}
              <span style={{ color: 'var(--text-faint)', fontSize: 11.5, display: 'block' }}>
                owner_policy_seq {state.ownerPolicySeq.toString()}
              </span>
            </dd>
          </dl>
        </section>

        <section className="card">
          <h2 className="card__title">
            <Info /> 生命周期
          </h2>
          <dl className="kv kv--tight">
            <dt>注册时间</dt>
            <dd>{formatTime(state.registeredAt)}</dd>
            <dt>到期时间</dt>
            <dd>
              {formatTime(state.expireAt)}
              <span style={{ color: 'var(--text-faint)', fontSize: 11.5, display: 'block' }}>
                {formatRelative(state.expireAt)}
              </span>
            </dd>
            <dt>宽限期至</dt>
            <dd>{formatTime(state.graceUntil)}</dd>
            <dt>最近更新</dt>
            <dd>{formatTime(state.updatedAt)}</dd>
            <dt>标志</dt>
            <dd className="chips">
              <Pill tone={state.renewable ? 'ok' : 'muted'}>renewable</Pill>
              <Pill
                tone={state.transferable ? 'ok' : 'muted'}
                title="当前 transferName 未强制检查该 flag（PRD 6.4.2）"
              >
                transferable
              </Pill>
              <Pill tone={state.standardTransferEnabled ? 'ok' : 'muted'}>standard transfer</Pill>
              <Pill
                tone={state.allowDelegatedSubnames ? 'ok' : 'muted'}
                title="当前不参与注册鉴权（PRD 6.4.3）"
              >
                delegated subnames
              </Pill>
            </dd>
            <dt>hashes</dt>
            <dd className="chips">
              {(
                [
                  ['namespace', state.namespacePolicyHash],
                  ['payment', state.paymentPolicyHash],
                  ['alias', state.aliasStateHash],
                ] as const
              ).map(([label, hash]) => (
                <Pill key={label} tone={isZeroHex(hash) ? 'muted' : 'neutral'} title={hash}>
                  {label}: {isZeroHex(hash) ? 'zero' : shortHash(hash, 4, 4)}
                </Pill>
              ))}
            </dd>
          </dl>
        </section>
      </div>

      {overview.derived.timeExpired ? (
        <Note tone="warn">
          <b>有效期已过，但链上 raw status 仍为 {NAME_STATUS_LABEL[state.status]}。</b>
          合约不会因时间流逝自动改变状态（PRD 6.4.1）；两种口径并列展示，互不覆盖。
          {overview.derived.inGrace ? ' 当前仍在宽限期内，可以续期恢复。' : ''}
        </Note>
      ) : null}

      {overview.parent ? (
        <section className="card">
          <h2 className="card__title">
            <Info /> 父名称 {overview.parent}
          </h2>
          {parent ? (
            <div className="chips">
              <Pill tone={NAME_STATUS_TONE[parent.state.status]}>
                {NAME_STATUS_LABEL[parent.state.status]}
              </Pill>
              <span style={{ fontSize: 12.5, color: 'var(--text-dim)' }}>
                effective owner：{principalText(parent.state.effectiveOwner)} · name_seq{' '}
                {parent.state.nameSeq.toString()}
              </span>
            </div>
          ) : (
            <Spinner />
          )}
          {state.ownerSource === 'parent_inherited' ? (
            <Note tone="info">
              本名称未设置 semantic owner，控制权继承自父名称 effective owner（PRD 5.3）。
            </Note>
          ) : null}
        </section>
      ) : null}

      <RawDetails label="NameState 原始数据（domain JSON）" value={state} />
    </div>
  )
}
