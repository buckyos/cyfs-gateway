/**
 * 搜索与名称解析（PRD 9.2）。
 *
 * 单一输入框分流：BNS 名称 / did:bns / 其它 DID / EVM 地址 / 交易 hash。
 * 名称不存在时提示「投影中未找到」并给出注册入口与 Indexer 延迟提示。
 */

import { ArrowRight, FileQuestion, Globe, Hash, Search, Wallet } from 'lucide-react'
import { useMemo, useState, type FormEvent } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'

import type { DidResolution, NameOverview } from '../bns_model'
import { didBnsFromName, validateBnsName } from '../bns_model'
import { useBnsModel } from '../bns_model/react'
import {
  DOC_STATUS_LABEL,
  DOC_STATUS_TONE,
  derivedStatusLabel,
  formatTime,
  NAME_STATUS_LABEL,
  NAME_STATUS_TONE,
  OWNER_SOURCE_LABEL,
  principalText,
  shortAddress,
} from '../ui/format'
import { CopyText, ErrorBox, JsonBlock, Note, Pill, RawDetails, Spinner } from '../ui/kit'
import { useAsync } from '../ui/use_async'

export function SearchPage() {
  const [params, setParams] = useSearchParams()
  const query = params.get('q') ?? ''
  const [input, setInput] = useState(query)
  const model = useBnsModel()

  const classification = useMemo(
    () => (query ? model.controllers.registry.classify(query) : null),
    [model, query],
  )

  const onSubmit = (event: FormEvent) => {
    event.preventDefault()
    const value = input.trim()
    if (value) setParams({ q: value })
  }

  return (
    <div>
      <h1 className="page-title">搜索与解析</h1>
      <p className="page-sub">支持 BNS 名称、did:bns DID、EVM 地址与 32 字节交易 hash</p>

      <form className="hero__search" onSubmit={onSubmit} style={{ margin: '0 0 18px', maxWidth: 640 }}>
        <input
          value={input}
          onChange={(event) => setInput(event.target.value)}
          placeholder="alice · device.alice · did:bns:alice · 0x… · 交易 hash"
        />
        <button type="submit" className="btn btn--primary">
          <Search /> 查询
        </button>
      </form>

      {!classification ? (
        <Note tone="info">输入任意名称开始；访客无需连接钱包即可查看全部公共数据。</Note>
      ) : classification.kind === 'invalid' ? (
        <Note tone="warn">
          <b>无法识别的输入。</b> {classification.message}
        </Note>
      ) : classification.kind === 'name' ? (
        <NameResult name={classification.value} />
      ) : classification.kind === 'did_bns' ? (
        <>
          <NameResult name={classification.value} />
          <div className="section-gap" />
          <DidResolverPanel did={`did:bns:${classification.value}`} />
        </>
      ) : classification.kind === 'did_other' ? (
        <>
          <Note tone="info">{classification.message}</Note>
          <DidResolverPanel did={classification.value} />
        </>
      ) : classification.kind === 'address' ? (
        <AddressResult address={classification.value} />
      ) : (
        <TxResult txHash={classification.value} />
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// 名称结果
// ---------------------------------------------------------------------------

function NameResult({ name }: { name: string }) {
  const model = useBnsModel()
  const overview = useAsync<NameOverview | null>(
    () => model.repo.nameOverview(name),
    [model, name],
  )

  if (overview.status === 'loading' || overview.status === 'idle') {
    return (
      <div className="loading-row">
        <Spinner /> 查询 {name} …
      </div>
    )
  }
  if (overview.status === 'error') return <ErrorBox error={overview.error} />

  const data = overview.data
  if (data === null) {
    const formatOk = validateBnsName(name).ok
    return (
      <section className="card">
        <h2 className="card__title">
          <FileQuestion /> {name}
        </h2>
        <Note tone="warn">
          <b>名称未在当前投影中找到。</b>
          <div style={{ marginTop: 4 }}>
            如果你刚提交注册，Indexer 可能尚未同步——请稍后重试或在交易中心查看进度。
          </div>
        </Note>
        {formatOk ? (
          <Link to={`/register?name=${encodeURIComponent(name)}`} className="btn btn--primary">
            去注册 <ArrowRight />
          </Link>
        ) : (
          <Note tone="danger">该名称不满足合约格式规则，无法注册。</Note>
        )}
      </section>
    )
  }

  const derived = derivedStatusLabel(data.derived)
  const state = data.state
  return (
    <section className="card">
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', marginBottom: 10 }}>
        <span className="mono" style={{ fontSize: 18, fontWeight: 700 }}>
          {data.state.name}
        </span>
        <Pill tone={NAME_STATUS_TONE[state.status]}>raw: {NAME_STATUS_LABEL[state.status]}</Pill>
        {data.derived.timeExpired || data.derived.label !== 'active' ? (
          <Pill tone={derived.tone}>{derived.text}</Pill>
        ) : null}
        <Link
          to={`/name/${encodeURIComponent(state.name)}`}
          className="btn btn--primary btn--sm"
          style={{ marginLeft: 'auto' }}
        >
          打开名称详情 <ArrowRight />
        </Link>
      </div>
      <dl className="kv">
        <dt>DID</dt>
        <dd>
          <CopyText value={didBnsFromName(state.name)} />
        </dd>
        <dt>Asset Owner</dt>
        <dd>
          <CopyText value={state.assetOwner} display={shortAddress(state.assetOwner, 8, 6)} />
        </dd>
        <dt>Semantic Owner</dt>
        <dd>{principalText(state.semanticOwner)}</dd>
        <dt>Effective Owner</dt>
        <dd>
          {principalText(state.effectiveOwner)}
          <span style={{ color: 'var(--text-faint)', fontSize: 11.5, display: 'block' }}>
            来源：{OWNER_SOURCE_LABEL[state.ownerSource]}
          </span>
        </dd>
        <dt>name_seq / lineage</dt>
        <dd className="mono">
          {state.nameSeq.toString()} / {state.lineageEpoch.toString()}
        </dd>
        <dt>注册 / 到期 / 宽限</dt>
        <dd>
          {formatTime(state.registeredAt)} · {formatTime(state.expireAt)} · {formatTime(state.graceUntil)}
        </dd>
        <dt>标志</dt>
        <dd className="chips">
          <Pill tone={state.renewable ? 'ok' : 'muted'}>renewable</Pill>
          <Pill tone={state.transferable ? 'ok' : 'muted'}>transferable</Pill>
          <Pill tone={state.standardTransferEnabled ? 'ok' : 'muted'}>standard transfer</Pill>
          <Pill tone={state.allowDelegatedSubnames ? 'ok' : 'muted'}>delegated subnames</Pill>
        </dd>
        <dt>Owner 文档版本</dt>
        <dd className="mono">{state.ownerDocumentVersion.toString()}</dd>
      </dl>
    </section>
  )
}

// ---------------------------------------------------------------------------
// 地址结果
// ---------------------------------------------------------------------------

function AddressResult({ address }: { address: string }) {
  const model = useBnsModel()
  const page = useAsync(() => model.repo.namesByAddress(address, null), [model, address])

  return (
    <section className="card">
      <h2 className="card__title">
        <Wallet /> {shortAddress(address, 10, 8)} 持有的名称
      </h2>
      <p className="card__hint">
        按 asset_owner 查询；不含通过 authority key、controller 规则或父名称继承可管理的名称。
      </p>
      {page.status === 'loading' || page.status === 'idle' ? (
        <div className="loading-row">
          <Spinner /> 查询中…
        </div>
      ) : page.status === 'error' ? (
        <ErrorBox error={page.error} />
      ) : page.data && page.data.names.length > 0 ? (
        <>
          {page.data.names.map((name) => (
            <div key={name} className="name-row">
              <Link to={`/name/${encodeURIComponent(name)}`} className="name-row__name">
                {name}
              </Link>
            </div>
          ))}
          {page.data.nextCursor ? (
            <Note tone="info">还有更多结果，进入「我的账号」或使用分页查询查看。</Note>
          ) : null}
        </>
      ) : (
        <div className="empty">该地址名下没有名称</div>
      )}
    </section>
  )
}

// ---------------------------------------------------------------------------
// 交易结果
// ---------------------------------------------------------------------------

function TxResult({ txHash }: { txHash: string }) {
  const model = useBnsModel()
  const state = useAsync(() => model.repo.txState(txHash), [model, txHash])

  return (
    <section className="card">
      <h2 className="card__title">
        <Hash /> 交易状态
      </h2>
      <dl className="kv">
        <dt>Tx Hash</dt>
        <dd>
          <CopyText value={txHash} />
        </dd>
        {state.status === 'ready' && state.data ? (
          <>
            <dt>执行状态</dt>
            <dd>
              <Pill
                tone={
                  state.data.state === 'succeeded'
                    ? 'ok'
                    : state.data.state === 'reverted'
                      ? 'danger'
                      : state.data.state === 'pending'
                        ? 'progress'
                        : 'warn'
                }
              >
                {state.data.state}
              </Pill>
              {state.data.state === 'not_found' ? (
                <span style={{ color: 'var(--text-faint)', fontSize: 11.5, display: 'block' }}>
                  not_found 不是确定失败：可能节点未见过、mempool 丢弃、同 nonce 替换或历史裁剪
                </span>
              ) : null}
            </dd>
            <dt>区块 / 确认数</dt>
            <dd className="mono">
              {state.data.blockNumber?.toString() ?? '—'} / {state.data.confirmations.toString()}
            </dd>
          </>
        ) : state.status === 'error' ? (
          <>
            <dt>结果</dt>
            <dd>
              <ErrorBox error={state.error} />
            </dd>
          </>
        ) : (
          <>
            <dt>结果</dt>
            <dd>
              <Spinner />
            </dd>
          </>
        )}
      </dl>
      <Note tone="info">
        本地发起的交易在 <Link to="/tx">交易中心</Link> 有完整的两阶段进度（链上确认 + 投影收敛）。
      </Note>
    </section>
  )
}

// ---------------------------------------------------------------------------
// DID Resolver
// ---------------------------------------------------------------------------

export function DidResolverPanel({ did, defaultDocType = 'zone' }: { did: string; defaultDocType?: string }) {
  const model = useBnsModel()
  const [docType, setDocType] = useState(defaultDocType)
  const resolution = useAsync<DidResolution>(
    () => model.controllers.registry.resolveDid(did, docType),
    [model, did, docType],
  )

  return (
    <section className="card">
      <h2 className="card__title">
        <Globe /> DID Resolver
      </h2>
      <p className="card__hint">
        GET /1.0/identifiers/{did}?type={docType} —— Resolver 的派生状态口径可能与
        document.resolve 的 raw status 不同，两者并列展示、互不覆盖。
      </p>
      <div style={{ display: 'flex', gap: 8, marginBottom: 12, alignItems: 'center' }}>
        <span style={{ fontSize: 12, color: 'var(--text-faint)' }}>doc type</span>
        <select
          value={docType}
          onChange={(event) => setDocType(event.target.value)}
          style={{
            background: 'var(--bg-raise)',
            color: 'var(--text)',
            border: '1px solid var(--line)',
            borderRadius: 7,
            padding: '5px 9px',
            fontSize: 12.5,
          }}
        >
          {['zone', 'owner', 'boot', 'device', 'relay', 'payment'].map((type) => (
            <option key={type} value={type}>
              {type}
            </option>
          ))}
        </select>
      </div>
      {resolution.status === 'loading' || resolution.status === 'idle' ? (
        <div className="loading-row">
          <Spinner /> 解析中…
        </div>
      ) : resolution.status === 'error' ? (
        <ErrorBox error={resolution.error} />
      ) : resolution.data ? (
        <DidResolutionView resolution={resolution.data} />
      ) : null}
    </section>
  )
}

function DidResolutionView({ resolution }: { resolution: DidResolution }) {
  const kindLabel: Record<DidResolution['kind'], { text: string; tone: 'ok' | 'warn' | 'danger' | 'neutral' }> = {
    answer: { text: '权威回答', tone: 'ok' },
    not_applicable: { text: '无意见（非本解析器权威的方法）', tone: 'neutral' },
    bad_request: { text: '请求无效', tone: 'warn' },
    not_implemented: { text: '能力未实现（历史查询）', tone: 'warn' },
    server_failure: { text: '解析器故障', tone: 'danger' },
  }
  const kind = kindLabel[resolution.kind]

  return (
    <div>
      <div className="chips" style={{ marginBottom: 10 }}>
        <Pill tone={kind.tone}>{kind.text}</Pill>
        <Pill tone="neutral">HTTP {resolution.httpStatus}</Pill>
        {resolution.documentStatus ? (
          <Pill tone={DOC_STATUS_TONE[resolution.documentStatus]}>
            resolver 状态：{DOC_STATUS_LABEL[resolution.documentStatus]}
          </Pill>
        ) : null}
        {resolution.deactivated ? <Pill tone="danger">deactivated</Pill> : null}
      </div>
      {resolution.kind === 'answer' ? (
        <dl className="kv kv--tight">
          <dt>doc type / 版本</dt>
          <dd className="mono">
            {resolution.docType ?? '—'} / {resolution.documentVersion?.toString() ?? '—'}
          </dd>
          <dt>Effective Owner</dt>
          <dd className="mono">{resolution.effectiveOwner || '—'}</dd>
          <dt>authority_seq</dt>
          <dd className="mono">{resolution.authoritySeq?.toString() ?? '—'}</dd>
          {resolution.migrationTarget ? (
            <>
              <dt>迁移目标</dt>
              <dd className="mono">{resolution.migrationTarget}</dd>
            </>
          ) : null}
        </dl>
      ) : resolution.error ? (
        <Note tone={resolution.kind === 'server_failure' ? 'danger' : 'info'}>
          <b>{resolution.error}</b>
          {resolution.errorMessage ? <div style={{ marginTop: 4 }}>{resolution.errorMessage}</div> : null}
        </Note>
      ) : null}
      {resolution.didDocument ? (
        <>
          <div className="divider" />
          <div style={{ fontSize: 12, color: 'var(--text-faint)', marginBottom: 6 }}>DID Document</div>
          <JsonBlock value={resolution.didDocument} />
        </>
      ) : null}
      <RawDetails label="完整 DID Resolution Result（原始 JSON）" value={resolution.raw} />
    </div>
  )
}
