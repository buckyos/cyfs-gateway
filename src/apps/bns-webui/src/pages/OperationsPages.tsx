import clsx from 'clsx'
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Braces,
  Check,
  ChevronLeft,
  ChevronRight,
  CircleHelp,
  Clock3,
  Code2,
  Copy,
  Database,
  ExternalLink,
  FileKey2,
  Filter,
  Fingerprint,
  Gauge,
  Globe2,
  KeyRound,
  Layers3,
  Network,
  Play,
  RefreshCw,
  Search,
  Server,
  Settings2,
  ShieldCheck,
  SlidersHorizontal,
  TerminalSquare,
  WalletCards,
  X,
} from 'lucide-react'
import { useMemo, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'

import {
  Button,
  CopyValue,
  DetailRow,
  SectionHeading,
  StageIcon,
  StatusDot,
  Tag,
} from '../components'
import {
  events,
  proxyAddress,
  shortAddress,
  type EventRecord,
  type TransactionRecord,
  walletAddress,
} from '../data'
import { useAppState } from '../state'

const transactionFilters = [
  { id: 'all', label: '全部' },
  { id: 'open', label: '进行中' },
  { id: 'completed', label: '已完成' },
  { id: 'failed', label: '异常' },
] as const

export function TransactionsPage() {
  const { transactions, openAction } = useAppState()
  const [params] = useSearchParams()
  const [filter, setFilter] = useState<(typeof transactionFilters)[number]['id']>('all')
  const selectedHash = params.get('tx')
  const visible = transactions.filter((transaction) => {
    if (filter === 'open') return ['awaiting', 'pending', 'indexing'].includes(transaction.stage)
    if (filter === 'completed') return transaction.stage === 'completed'
    if (filter === 'failed') return transaction.stage === 'reverted'
    return true
  })

  return (
    <div className="page">
      <header className="page-header reveal">
        <div>
          <span className="eyebrow">Local transaction center</span>
          <h1>交易中心</h1>
          <p>从钱包确认到链上结果，再到可查询投影；每个阶段都可以独立恢复。</p>
        </div>
        <Button tone="secondary" icon={RefreshCw}>重新查询全部</Button>
      </header>

      <section className="transaction-overview reveal reveal--2">
        <div>
          <span className="transaction-overview__icon is-pending"><Clock3 size={19} /></span>
          <span><small>链上 Pending</small><strong>1</strong></span>
        </div>
        <div>
          <span className="transaction-overview__icon is-indexing"><Layers3 size={19} /></span>
          <span><small>等待 Indexer</small><strong>1</strong></span>
        </div>
        <div>
          <span className="transaction-overview__icon is-complete"><Check size={19} /></span>
          <span><small>本周完成</small><strong>12</strong></span>
        </div>
        <div>
          <span className="transaction-overview__icon is-failed"><AlertTriangle size={19} /></span>
          <span><small>需要处理</small><strong>1</strong></span>
        </div>
      </section>

      <div className="collection-toolbar reveal reveal--3">
        <div className="segmented-control">
          {transactionFilters.map(({ id, label }) => (
            <button
              className={clsx(filter === id && 'is-active')}
              key={id}
              type="button"
              onClick={() => setFilter(id)}
            >
              {label}
            </button>
          ))}
        </div>
        <span className="local-only-label">
          <Database size={15} />
          本地记录 · 当前账户
        </span>
      </div>

      <section className="transaction-list reveal reveal--3">
        {visible.map((transaction) => (
          <TransactionRow
            key={transaction.hash}
            transaction={transaction}
            highlighted={transaction.hash === selectedHash}
            onOpen={() => openAction({ kind: 'transaction', transaction })}
          />
        ))}
      </section>

      <div className="inline-notice inline-notice--wide">
        <CircleHelp size={17} />
        <p>
          “Not Found” 不是确定失败：节点可能未见过该交易、同 nonce 已替换，或历史被裁剪。
          本地隐藏记录也不会取消链上交易。
        </p>
      </div>
    </div>
  )
}

function TransactionRow({
  transaction,
  highlighted,
  onOpen,
}: {
  transaction: TransactionRecord
  highlighted: boolean
  onOpen: () => void
}) {
  const status = transactionStatus(transaction.stage)
  const walletState = transaction.stage === 'awaiting' ? 'active' : transaction.stage === 'reverted' ? 'done' : 'done'
  const chainState = transaction.stage === 'reverted'
    ? 'error'
    : transaction.stage === 'pending'
      ? 'active'
      : transaction.stage === 'awaiting'
        ? 'waiting'
        : 'done'
  const indexerState = transaction.stage === 'indexing'
    ? 'active'
    : transaction.stage === 'completed'
      ? 'done'
      : 'waiting'

  return (
    <button
      className={clsx('transaction-row', highlighted && 'is-highlighted')}
      type="button"
      onClick={onOpen}
    >
      <div className="transaction-row__identity">
        <span className={clsx('transaction-symbol', `is-${transaction.stage}`)}>
          {transaction.stage === 'reverted' ? <AlertTriangle size={18} /> : <Fingerprint size={18} />}
        </span>
        <div>
          <strong>{transaction.operation}</strong>
          <span>{transaction.target} · {shortAddress(transaction.hash)}</span>
        </div>
      </div>
      <div className="tx-route tx-route--compact">
        <div className="tx-route__step">
          <StageIcon state={walletState} />
          <span>Wallet</span>
        </div>
        <div className={clsx('tx-route__line', walletState === 'done' && 'is-done')} />
        <div className="tx-route__step">
          <StageIcon state={chainState} />
          <span>Chain</span>
        </div>
        <div className={clsx('tx-route__line', chainState === 'done' && 'is-done', indexerState === 'active' && 'is-active')} />
        <div className="tx-route__step">
          <StageIcon state={indexerState} />
          <span>Indexer</span>
        </div>
      </div>
      <div className="transaction-row__status">
        <Tag tone={status.tone}>{status.label}</Tag>
        <small>{transaction.submittedAt}</small>
      </div>
      <ChevronRight size={17} />
    </button>
  )
}

function transactionStatus(stage: TransactionRecord['stage']): {
  label: string
  tone: 'neutral' | 'success' | 'warning' | 'danger' | 'accent'
} {
  if (stage === 'pending') return { label: '链上 Pending', tone: 'accent' }
  if (stage === 'indexing') return { label: '正在索引', tone: 'warning' }
  if (stage === 'completed') return { label: '已完成', tone: 'success' }
  if (stage === 'reverted') return { label: 'Reverted', tone: 'danger' }
  return { label: '等待钱包', tone: 'neutral' }
}

export function EventsPage() {
  const [selected, setSelected] = useState<EventRecord | null>(null)
  const [type, setType] = useState('全部事件')
  const [query, setQuery] = useState('')
  const visibleEvents = useMemo(
    () => events.filter((event) =>
      (!query || event.name.includes(query) || event.type.includes(query))
      && (type === '全部事件' || event.type === type),
    ),
    [query, type],
  )

  return (
    <div className="page">
      <header className="page-header reveal">
        <div>
          <span className="eyebrow">Append-only projection</span>
          <h1>事件浏览器</h1>
          <p>浏览 bns-indexer 已投影的公共事件，验证名称和文档的状态变化。</p>
        </div>
        <div className="event-head-status">
          <StatusDot tone="success" pulse />
          <span><small>Latest sequence</small><strong>#1,402</strong></span>
        </div>
      </header>

      <div className="event-toolbar reveal reveal--2">
        <label className="mini-search mini-search--wide">
          <Search size={17} />
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="在已加载事件中筛选名称或类型"
          />
        </label>
        <label className="filter-select">
          <Filter size={16} />
          <select value={type} onChange={(event) => setType(event.target.value)}>
            <option>全部事件</option>
            {[...new Set(events.map((event) => event.type))].map((eventType) => (
              <option key={eventType}>{eventType}</option>
            ))}
          </select>
        </label>
        <Button tone="secondary" icon={RefreshCw}>刷新</Button>
      </div>

      <section className="event-table reveal reveal--3">
        <div className="event-table__head">
          <span>Seq</span><span>Event</span><span>Name / Detail</span><span>Actor</span><span>Observed</span><span />
        </div>
        {visibleEvents.map((event) => (
          <button
            className="event-table__row"
            key={event.seq}
            type="button"
            onClick={() => setSelected(event)}
          >
            <strong>#{event.seq}</strong>
            <span><i className={eventTone(event.type)} /><strong>{event.type}</strong></span>
            <span><strong>{event.name}</strong><small>{event.detail}</small></span>
            <span>{shortAddress(event.actor)}</span>
            <span><strong>{event.observedAt}</strong><small>2026-07-30</small></span>
            <ChevronRight size={16} />
          </button>
        ))}
      </section>

      <div className="collection-footer">
        <span>客户端筛选 · 已加载 6 个事件</span>
        <Button tone="ghost" size="sm">从 #1,403 加载下一页</Button>
      </div>

      <div className={clsx('drawer-layer', selected && 'is-open')} aria-hidden={!selected}>
        <button className="drawer-backdrop" type="button" aria-label="关闭事件详情" onClick={() => setSelected(null)} />
        <aside className="side-drawer">
          {selected && (
            <>
              <div className="side-drawer__header">
                <div><span className="eyebrow">Event #{selected.seq}</span><h2>{selected.type}</h2></div>
                <button className="icon-button" type="button" aria-label="关闭" onClick={() => setSelected(null)}><X size={19} /></button>
              </div>
              <div className="event-detail-hero">
                <span className="event-detail-hero__icon"><Activity size={21} /></span>
                <div><strong>{selected.name}</strong><small>{selected.detail}</small></div>
                <Tag tone="success">Projected</Tag>
              </div>
              <div className="document-meta">
                <DetailRow label="Observed"><strong>2026-07-30 · {selected.observedAt}</strong></DetailRow>
                <DetailRow label="Actor"><CopyValue value={selected.actor} compact /></DetailRow>
                <DetailRow label="Event hash"><CopyValue value={selected.hash} compact /></DetailRow>
                <DetailRow label="Log root"><CopyValue value="0xaa5fe83c4f12402c45dd7aa991c3fd30c49ce2381a6e90c8" compact /></DetailRow>
              </div>
              <div className="code-view">
                <div className="code-view__bar"><span>Raw JSON</span><button type="button">复制</button></div>
                <pre>{JSON.stringify({
                  seq: selected.seq,
                  event_type: selected.type,
                  event: {
                    type: selected.type,
                    name: selected.name,
                    detail: selected.detail,
                    actor: selected.actor,
                  },
                  observed_at: '2026-07-30T16:42:18Z',
                  event_hash: selected.hash,
                }, null, 2)}</pre>
              </div>
            </>
          )}
        </aside>
      </div>
    </div>
  )
}

function eventTone(type: string) {
  if (type.includes('registered') || type.includes('renewed')) return 'event-tone event-tone--green'
  if (type.includes('authority')) return 'event-tone event-tone--purple'
  if (type.includes('payment')) return 'event-tone event-tone--amber'
  return 'event-tone event-tone--blue'
}

export function AdvancedPage() {
  const navigate = useNavigate()
  const { notify } = useAppState()
  const [tool, setTool] = useState('did')
  const [did, setDid] = useState('did:bns:alice')

  return (
    <div className="page">
      <header className="page-header reveal">
        <div>
          <span className="eyebrow">Protocol workbench</span>
          <h1>高级工具</h1>
          <p>面向 Authority、批量 Mutation、DID Resolution 和协议审计的可解释工作台。</p>
        </div>
        <Tag tone="warning">Advanced</Tag>
      </header>

      <div className="advanced-workbench reveal reveal--2">
        <nav className="tool-menu">
          {[
            { id: 'did', label: 'DID Resolver', icon: Fingerprint },
            { id: 'authority', label: 'Authority Key', icon: KeyRound },
            { id: 'batch', label: '原子 Batch', icon: Braces },
            { id: 'checkpoint', label: 'Checkpoint', icon: ShieldCheck },
          ].map(({ id, label, icon: Icon }) => (
            <button className={clsx(tool === id && 'is-active')} key={id} type="button" onClick={() => setTool(id)}>
              <Icon size={18} />
              <span>{label}</span>
              <ChevronRight size={15} />
            </button>
          ))}
        </nav>

        <section className="tool-canvas" key={tool}>
          {tool === 'did' && (
            <div className="tool-view tab-enter">
              <span className="eyebrow">HTTP · /1.0/identifiers/:did</span>
              <h2>DID Resolver</h2>
              <p>查询标准 DID Resolution Result，并与 BNS 文档的 raw status 并列查看。</p>
              <div className="tool-input-row">
                <input value={did} onChange={(event) => setDid(event.target.value)} />
                <select defaultValue="zone"><option>zone</option><option>owner</option><option>boot</option></select>
                <Button tone="primary" icon={Play} onClick={() => navigate(`/search?did=${encodeURIComponent(did)}`)}>运行</Button>
              </div>
              <div className="tool-result-preview">
                <span className="tool-result-preview__icon"><Check size={18} /></span>
                <div><small>READY TO RESOLVE</small><strong>{did}</strong></div>
                <Tag tone="neutral">type · zone</Tag>
              </div>
              <div className="inline-notice">
                <CircleHelp size={17} />
                <p>历史 iat 查询当前返回 501，并会标记 historicalQuerySupported=false。</p>
              </div>
            </div>
          )}

          {tool === 'authority' && (
            <div className="tool-view tab-enter">
              <span className="eyebrow">kRPC · authority.get_key</span>
              <h2>按 KID 查询 Authority Key</h2>
              <p>服务暂不支持完整 key 列表；在此输入已知 kid 获取单个 Key 状态。</p>
              <div className="field-group">
                <label htmlFor="authority-name">BNS Name</label>
                <input id="authority-name" defaultValue="alice" />
              </div>
              <div className="field-group">
                <label htmlFor="authority-kid">KID · bytes32</label>
                <input id="authority-kid" defaultValue="0x5b655cb329a5c6f968d29953a3ab47a0f7f13235e8a3abf7051a3ef323ec6f08" />
              </div>
              <Button tone="primary" icon={Search} onClick={() => notify('演示：已查询到 active authentication key')}>查询 Key</Button>
            </div>
          )}

          {tool === 'batch' && (
            <div className="tool-view tab-enter">
              <span className="eyebrow">Contract · applyMutations</span>
              <h2>原子批量 Mutation</h2>
              <p>任意一项失败，整笔交易回滚。所有 Guard 必须来自同一轮最终预检。</p>
              <div className="batch-stats">
                <div><span>Items</span><strong>3 / 32</strong></div>
                <div><span>Inline bytes</span><strong>2.4 / 64 KiB</strong></div>
                <div><span>Calldata</span><strong>~4.1 KiB</strong></div>
              </div>
              <div className="batch-item"><span>01</span><FileKey2 size={17} /><strong>Authority Update</strong><Tag tone="warning">Owner-only</Tag></div>
              <div className="batch-item"><span>02</span><Code2 size={17} /><strong>zone · version 7 → 8</strong><Tag tone="accent">Inline</Tag></div>
              <div className="batch-item"><span>03</span><Code2 size={17} /><strong>payment · version 2 → 3</strong><Tag tone="neutral">URI</Tag></div>
              <div className="tool-actions"><Button tone="secondary">导入 JSON</Button><Button tone="primary">预检 Batch</Button></div>
            </div>
          )}

          {tool === 'checkpoint' && (
            <div className="tool-view tab-enter">
              <span className="eyebrow">kRPC · checkpoint.latest</span>
              <h2>最新日志 Checkpoint</h2>
              <p>只读查看事件日志根与外部锚点。普通用户界面不开放发布能力。</p>
              <div className="checkpoint-seal">
                <span><ShieldCheck size={28} /></span>
                <div><small>LAST VERIFIED SEQUENCE</small><strong>1,402</strong></div>
                <Tag tone="success">Verified</Tag>
              </div>
              <div className="document-meta">
                <DetailRow label="Log root"><CopyValue value="0x69c15be13233da15c7630b24930827ff4d4e22c4e26f4448440c0a3dc6a6d8ba" compact /></DetailRow>
                <DetailRow label="Issued at"><strong>2026-07-30 09:42:21</strong></DetailRow>
                <DetailRow label="Issuer"><strong>bns-indexer-01</strong></DetailRow>
                <DetailRow label="External anchor"><CopyValue value="ipfs://bafybeia4n..." compact /></DetailRow>
              </div>
            </div>
          )}
        </section>

        <aside className="tool-reference">
          <span className="eyebrow">Boundary</span>
          <h3>工具边界</h3>
          <div className="boundary-item">
            <Server size={17} />
            <span><strong>读取</strong><small>bns-server / kRPC</small></span>
          </div>
          <div className="boundary-item">
            <WalletCards size={17} />
            <span><strong>写入</strong><small>Wallet → BNS Proxy</small></span>
          </div>
          <div className="boundary-item">
            <ShieldCheck size={17} />
            <span><strong>Guard</strong><small>提交前重新读取</small></span>
          </div>
          <div className="drawer-note">
            <AlertTriangle size={17} />
            <p>未知 bytes32 或 hash 始终保留原始值，不猜测其含义。</p>
          </div>
        </aside>
      </div>
    </div>
  )
}

export function SettingsPage() {
  const { theme, toggleTheme, notify } = useAppState()
  const [sessionEnabled, setSessionEnabled] = useState(false)

  return (
    <div className="page settings-page">
      <header className="page-header reveal">
        <div>
          <span className="eyebrow">Connection & safety</span>
          <h1>设置</h1>
          <p>配置查询服务、部署期望和本地显示偏好。</p>
        </div>
      </header>

      <div className="settings-layout">
        <section className="settings-main reveal reveal--2">
          <div className="settings-section">
            <SectionHeading eyebrow="Server discovery" title="BNS 查询服务" />
            <div className="field-group">
              <label htmlFor="server-url">bns-server URL</label>
              <div className="settings-input-action">
                <input id="server-url" defaultValue="http://127.0.0.1:8080" />
                <Button tone="secondary" onClick={() => notify('演示：服务连接正常 · 42 ms')}>测试连接</Button>
              </div>
            </div>
            <div className="connection-checks">
              <div><StatusDot tone="success" /><span>GET /health</span><strong>200 · 28 ms</strong></div>
              <div><StatusDot tone="success" /><span>system.info</span><strong>ready · 42 ms</strong></div>
              <div><StatusDot tone="warning" /><span>Indexer state</span><strong>约落后 1 block</strong></div>
            </div>
          </div>

          <div className="settings-section">
            <SectionHeading eyebrow="Deployment guard" title="期望网络与合约" />
            <div className="two-field-grid">
              <div className="field-group">
                <label htmlFor="chain-id">Expected chain ID</label>
                <input id="chain-id" defaultValue="11155420" />
              </div>
              <div className="field-group">
                <label htmlFor="explorer">Block explorer</label>
                <input id="explorer" defaultValue="https://sepolia-optimism.etherscan.io" />
              </div>
            </div>
            <div className="field-group">
              <label htmlFor="proxy-address">Expected BNS Proxy</label>
              <input id="proxy-address" defaultValue={proxyAddress} />
            </div>
            <div className="match-status">
              <ShieldCheck size={18} />
              <span><strong>部署配置与 system.info 匹配</strong><small>允许提交写交易</small></span>
            </div>
          </div>

          <div className="settings-section">
            <SectionHeading eyebrow="Session" title="可选 Session Token" />
            <div className="policy-toggle">
              <div><strong>启用当前会话 Token</strong><small>仅存于会话内存，不写入 URL 或普通日志</small></div>
              <button
                className={clsx('toggle-switch', sessionEnabled && 'is-on')}
                type="button"
                role="switch"
                aria-checked={sessionEnabled}
                onClick={() => setSessionEnabled((value) => !value)}
              ><span /></button>
            </div>
            {sessionEnabled && (
              <div className="field-group tab-enter">
                <label htmlFor="session-token">Token</label>
                <input id="session-token" type="password" placeholder="仅保存在当前标签页" />
              </div>
            )}
          </div>
        </section>

        <aside className="settings-aside reveal reveal--3">
          <section className="side-section">
            <span className="eyebrow">Appearance</span>
            <h3>界面主题</h3>
            <button className="theme-choice" type="button" onClick={toggleTheme}>
              <span className={clsx('theme-preview', theme === 'dark' && 'is-dark')}>
                <i /><i /><i />
              </span>
              <span><strong>{theme === 'light' ? '浅色 Registry' : '深色 Registry'}</strong><small>点击切换主题</small></span>
              <Check size={16} />
            </button>
          </section>
          <section className="side-section">
            <span className="eyebrow">Local data</span>
            <h3>本地交易记录</h3>
            <p>只保存交易 Hash、操作摘要、Guard 快照与预期投影条件。</p>
            <Button tone="ghost" size="sm">导出 JSON</Button>
          </section>
          <section className="side-section side-section--tinted">
            <span className="eyebrow">Privacy</span>
            <ul className="check-list">
              <li><Check size={14} />不接触私钥或助记词</li>
              <li><Check size={14} />不保存 WalletConnect 会话密钥</li>
              <li><Check size={14} />日志自动脱敏 Token</li>
            </ul>
          </section>
        </aside>
      </div>
    </div>
  )
}
