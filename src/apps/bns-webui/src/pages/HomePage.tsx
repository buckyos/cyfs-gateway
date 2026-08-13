/**
 * 首页（PRD 9.1）：访客快速搜索；已连接用户快速进入持有名称与未完成交易。
 */

import {
  Activity,
  ArrowLeftRight,
  ArrowRight,
  Crown,
  FileText,
  Globe,
  Plus,
  Search,
  Server,
  Wallet,
} from 'lucide-react'
import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'

import { EVENT_TYPE_LABELS, isSettled } from '../bns_model'
import { useBnsModel, useEvents, useSession, useTransactions } from '../bns_model/react'
import { useAccounts } from '../ui/account'
import { formatRelative, shortAddress } from '../ui/format'
import { CopyText, Note, Pill, Spinner } from '../ui/kit'
import { NameRow } from '../ui/name_list'

export function HomePage() {
  const navigate = useNavigate()
  const [query, setQuery] = useState('')

  const onSearch = (event: FormEvent) => {
    event.preventDefault()
    const value = query.trim()
    if (value) navigate(`/search?q=${encodeURIComponent(value)}`)
  }

  return (
    <div>
      <div className="hero">
        <h1>搜索、注册和管理你的链上名称</h1>
        <p>输入 BNS 名称、did:bns DID、EVM 地址或交易 hash</p>
        <form className="hero__search" onSubmit={onSearch}>
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="例如 alice、did:bns:alice、0x…、交易 hash"
            autoFocus
          />
          <button type="submit" className="btn btn--primary">
            <Search /> 搜索
          </button>
        </form>
      </div>

      <div className="grid grid--2">
        <ServiceCard />
        <WalletCard />
      </div>
      <div className="section-gap" />
      <div className="grid grid--2">
        <AccountCard />
        <TxSummaryCard />
      </div>
      <div className="section-gap" />
      <div className="grid grid--2">
        <LatestEventsCard />
        <QuickEntryCard />
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------

function ServiceCard() {
  const session = useSession()
  const info = session.systemInfo.data

  return (
    <section className="card">
      <h2 className="card__title">
        <Server /> 服务状态
      </h2>
      <dl className="kv kv--tight">
        <dt>bns-server</dt>
        <dd>
          {session.serverHealthy === null ? (
            <Spinner />
          ) : session.serverHealthy ? (
            <Pill tone="ok" dot>
              HTTP 可达
            </Pill>
          ) : (
            <Pill tone="danger" dot>
              不可达
            </Pill>
          )}
        </dd>
        <dt>Indexer 投影</dt>
        <dd>
          {info ? (
            info.ready ? (
              <Pill tone="ok" dot>
                ready
              </Pill>
            ) : (
              <Pill tone="warn" dot>
                ready = false
              </Pill>
            )
          ) : (
            '—'
          )}
          <span style={{ color: 'var(--text-faint)', fontSize: 11.5, display: 'block' }}>
            无同步高度接口，无法证明已追到链上最新状态（PRD 6.4.7）
          </span>
        </dd>
        <dt>Chain ID</dt>
        <dd className="mono">{info?.chainId ?? '—'}</dd>
        <dt>合约 Proxy</dt>
        <dd>
          {info ? <CopyText value={info.contractAddress} display={shortAddress(info.contractAddress, 8, 6)} /> : '—'}
          <span style={{ color: 'var(--text-faint)', fontSize: 11.5, display: 'block' }}>
            所有写交易的唯一目标地址（不向 Facet 发交易）
          </span>
        </dd>
      </dl>
    </section>
  )
}

function WalletCard() {
  const session = useSession()

  return (
    <section className="card">
      <h2 className="card__title">
        <Wallet /> 钱包
      </h2>
      {session.wallet.connected && session.wallet.address ? (
        <dl className="kv kv--tight">
          <dt>地址</dt>
          <dd>
            <CopyText value={session.wallet.address} display={shortAddress(session.wallet.address, 8, 6)} />
          </dd>
          <dt>钱包网络</dt>
          <dd className="mono">{session.wallet.chainId ?? '—'}</dd>
          <dt>写入状态</dt>
          <dd>
            {session.writeGate.allowed ? (
              <Pill tone="ok" dot>
                允许写操作
              </Pill>
            ) : (
              <>
                <Pill tone="warn" dot>
                  只读
                </Pill>
                <span style={{ color: 'var(--text-faint)', fontSize: 11.5, display: 'block' }}>
                  {session.writeGate.reason}
                </span>
              </>
            )}
          </dd>
        </dl>
      ) : (
        <>
          <p style={{ color: 'var(--text-dim)', fontSize: 13, margin: '2px 0 10px' }}>
            未连接钱包。搜索与查看公共数据无需钱包；注册、续期、文档发布等写操作需要连接。
          </p>
          <Note tone="info">
            使用右上角「连接钱包」。钱包只负责账户授权、网络切换与签名，页面永不接触私钥。
          </Note>
        </>
      )}
    </section>
  )
}

function AccountCard() {
  const session = useSession()
  const { accounts, currentAccount, works, acquired } = useAccounts()

  return (
    <section className="card">
      <h2 className="card__title">
        <Crown /> 当前账号
      </h2>
      {!session.wallet.connected ? (
        <div className="empty">连接钱包后展示你的账号与资产</div>
      ) : accounts.length === 0 ? (
        <>
          <div className="empty">当前地址名下还没有一级名称（账号）</div>
          <Link to="/register" className="btn btn--primary" style={{ width: '100%' }}>
            <Plus /> 注册我的第一个账号
          </Link>
        </>
      ) : (
        <>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
            <span className="mono" style={{ fontSize: 17, fontWeight: 700 }}>
              {currentAccount}
            </span>
            {accounts.length > 1 ? <Pill tone="neutral">{accounts.length} 个账号，可切换</Pill> : null}
          </div>
          <div style={{ color: 'var(--text-dim)', fontSize: 12.5, marginBottom: 6 }}>
            名下作品 {works.length} 项
            {acquired.length > 0 ? ` · 另有买来的资产 ${acquired.length} 项（钱包维度）` : ''}
          </div>
          {works.slice(0, 5).map((entry) => (
            <NameRow key={entry.name} entry={entry} />
          ))}
          <div style={{ marginTop: 10 }}>
            <Link to="/account" className="btn btn--sm">
              进入我的账号 <ArrowRight />
            </Link>
          </div>
        </>
      )}
    </section>
  )
}

function TxSummaryCard() {
  const transactions = useTransactions()
  const counts = useMemo(() => {
    let active = 0
    let indexing = 0
    let failed = 0
    for (const record of transactions.records) {
      if (record.stage === 'indexing' || record.stage === 'indexer_lagging') indexing += 1
      else if (record.stage === 'chain_reverted') failed += 1
      else if (!isSettled(record.stage)) active += 1
    }
    return { active, indexing, failed }
  }, [transactions.records])

  return (
    <section className="card">
      <h2 className="card__title">
        <ArrowLeftRight /> 交易
      </h2>
      {transactions.records.length === 0 ? (
        <div className="empty">本地还没有交易记录</div>
      ) : (
        <>
          <div className="chips" style={{ marginBottom: 10 }}>
            <Pill tone="progress">进行中 {counts.active}</Pill>
            <Pill tone="warn">等待索引 {counts.indexing}</Pill>
            <Pill tone="danger">已回退 {counts.failed}</Pill>
            <Pill tone="neutral">共 {transactions.records.length} 笔</Pill>
          </div>
          {transactions.records.slice(0, 3).map((record) => (
            <div key={record.id} className="name-row">
              <div>
                <div style={{ fontSize: 13 }}>{record.label}</div>
                <div className="name-row__meta mono">{record.target}</div>
              </div>
              <div className="name-row__right">
                <Pill tone="neutral">{record.stage}</Pill>
              </div>
            </div>
          ))}
        </>
      )}
      <div style={{ marginTop: 10 }}>
        <Link to="/tx" className="btn btn--sm">
          打开交易中心 <ArrowRight />
        </Link>
      </div>
    </section>
  )
}

function LatestEventsCard() {
  const model = useBnsModel()
  const events = useEvents()

  useEffect(() => {
    if (events.records.length === 0 && events.page.status === 'idle') {
      void model.controllers.events.loadLatest()
    }
  }, [model, events.records.length, events.page.status])

  return (
    <section className="card">
      <h2 className="card__title">
        <Activity /> 最新事件
      </h2>
      {events.page.status === 'loading' && events.records.length === 0 ? (
        <div className="loading-row">
          <Spinner /> 正在定位日志尾部…
        </div>
      ) : events.records.length === 0 ? (
        <div className="empty">还没有事件</div>
      ) : (
        events.records.slice(0, 6).map((record) => (
          <div key={record.seq.toString()} className="event-line">
            <span className="event-line__seq">#{record.seq.toString()}</span>
            <div className="event-line__body">
              <span>{EVENT_TYPE_LABELS[record.event.type]}</span>
              {record.name ? (
                <>
                  {' · '}
                  <Link to={`/name/${encodeURIComponent(record.name)}`} className="mono">
                    {record.name}
                  </Link>
                </>
              ) : null}
              <div className="event-line__meta">{formatRelative(record.observedAt)}</div>
            </div>
          </div>
        ))
      )}
      <div style={{ marginTop: 10 }}>
        <Link to="/events" className="btn btn--sm">
          事件浏览器 <ArrowRight />
        </Link>
      </div>
    </section>
  )
}

function QuickEntryCard() {
  return (
    <section className="card">
      <h2 className="card__title">
        <Globe /> 常用入口
      </h2>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        <Link to="/register" className="btn" style={{ justifyContent: 'flex-start' }}>
          <Plus /> 注册名称
        </Link>
        <Link to="/account" className="btn" style={{ justifyContent: 'flex-start' }}>
          <FileText /> 发布 / 更新文档
        </Link>
        <Link to="/search" className="btn" style={{ justifyContent: 'flex-start' }}>
          <Globe /> 查看 DID 解析
        </Link>
      </div>
    </section>
  )
}
