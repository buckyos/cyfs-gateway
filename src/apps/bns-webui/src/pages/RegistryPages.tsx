import clsx from 'clsx'
import {
  ArrowRight,
  BadgeCheck,
  BookOpen,
  Check,
  ChevronLeft,
  ChevronRight,
  CircleHelp,
  Clock3,
  FileCode2,
  Fingerprint,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  WalletCards,
} from 'lucide-react'
import { useMemo, useState, type FormEvent } from 'react'
import {
  useNavigate,
  useSearchParams,
} from 'react-router-dom'

import {
  Button,
  CopyValue,
  DetailRow,
  EmptyState,
  SectionHeading,
  Tag,
} from '../components'
import {
  nameRecordFor,
  names,
  proxyAddress,
  shortAddress,
  walletAddress,
} from '../data'
import { useAppState } from '../state'

export function SearchPage() {
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const initial = params.get('did')?.replace(/^did:bns:/, '') ?? 'alice'
  const [query, setQuery] = useState(initial)
  const [resolvedQuery, setResolvedQuery] = useState(initial)
  const [mode, setMode] = useState<'summary' | 'did' | 'raw'>(
    params.get('mode') === 'did' || params.has('did') ? 'did' : 'summary',
  )
  const record = nameRecordFor(resolvedQuery.replace(/^did:bns:/, ''))

  const submit = (event: FormEvent) => {
    event.preventDefault()
    if (!query.trim()) return
    setResolvedQuery(query.trim())
  }

  return (
    <div className="page">
      <header className="page-header reveal">
        <div>
          <span className="eyebrow">Universal lookup</span>
          <h1>搜索与解析</h1>
          <p>名称、DID、EVM 地址与交易 Hash 共用一个查询入口。</p>
        </div>
      </header>

      <form className="lookup-bar reveal reveal--2" onSubmit={submit}>
        <Search size={21} />
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="alice / did:bns:alice / 0x…"
        />
        <Button tone="primary" type="submit">解析</Button>
      </form>

      <div className="lookup-context reveal reveal--2">
        <span>已识别为</span>
        <Tag tone="accent">{resolvedQuery.startsWith('did:bns:') ? 'BNS DID' : 'BNS Name'}</Tag>
        <span>数据源</span>
        <Tag tone="neutral">bns-server projection</Tag>
        <span>上次查询</span>
        <strong>刚刚 · 36 ms</strong>
      </div>

      <div className="result-switcher reveal reveal--3">
        {[
          ['summary', '名称摘要'],
          ['did', 'DID Resolver'],
          ['raw', '原始状态'],
        ].map(([id, label]) => (
          <button
            className={clsx(mode === id && 'is-active')}
            key={id}
            type="button"
            onClick={() => setMode(id as typeof mode)}
          >
            {label}
          </button>
        ))}
      </div>

      {mode === 'summary' && (
        <section className="lookup-result tab-enter">
          <div className="lookup-result__identity">
            <span className="name-monogram">{record.name.slice(0, 1).toUpperCase()}</span>
            <div>
              <span className="eyebrow">Name found</span>
              <h2>{record.name}</h2>
              <span>did:bns:{record.name}</span>
            </div>
            <Tag tone="success">Active</Tag>
            <Button tone="primary" onClick={() => navigate(`/name/${record.name}`)}>
              打开名称详情
              <ArrowRight size={16} />
            </Button>
          </div>
          <div className="lookup-result__facts">
            <div>
              <span>Asset Owner</span>
              <CopyValue value={record.assetOwner} compact />
            </div>
            <div>
              <span>Effective Owner</span>
              <strong>{shortAddress(record.effectiveOwner)}</strong>
            </div>
            <div>
              <span>有效期</span>
              <strong>{record.derivedStatus}</strong>
            </div>
            <div>
              <span>Name seq / lineage</span>
              <strong>{record.nameSeq} / {record.lineageEpoch}</strong>
            </div>
          </div>
          <div className="ownership-mini-map">
            <span><WalletCards size={16} />Asset · {shortAddress(record.assetOwner)}</span>
            <ArrowRight size={17} />
            <span>Semantic · unset</span>
            <ArrowRight size={17} />
            <span className="is-final"><BadgeCheck size={16} />Effective · wallet</span>
          </div>
        </section>
      )}

      {mode === 'did' && (
        <section className="resolver-result tab-enter">
          <div className="resolver-result__formatted">
            <SectionHeading
              eyebrow="DID Resolution Result"
              title={`did:bns:${record.name}`}
              description="默认解析文档类型 · zone"
              action={<Tag tone="success">Resolved</Tag>}
            />
            <div className="resolver-status">
              <div><span>didResolutionMetadata</span><strong>contentType · application/did+ld+json</strong></div>
              <div><span>didDocumentMetadata</span><strong>version · 7</strong></div>
            </div>
            <div className="did-document-card">
              <div>
                <Fingerprint size={20} />
                <span><small>Document ID</small><strong>did:bns:{record.name}</strong></span>
              </div>
              <div>
                <ShieldCheck size={20} />
                <span><small>Verification Method</small><strong>#primary-wallet</strong></span>
              </div>
              <div>
                <BookOpen size={20} />
                <span><small>Service</small><strong>LinkedDomains · https://alice.me</strong></span>
              </div>
            </div>
          </div>
          <div className="resolver-result__raw">
            <div className="code-view__bar"><span>Raw JSON</span><button type="button">复制</button></div>
            <pre>{JSON.stringify({
              didResolutionMetadata: {
                contentType: 'application/did+ld+json',
                retrieved: '2026-07-30T16:42:18Z',
              },
              didDocument: {
                id: `did:bns:${record.name}`,
                alsoKnownAs: ['did:web:alice.me'],
                verificationMethod: [{
                  id: `did:bns:${record.name}#primary-wallet`,
                  type: 'EcdsaSecp256k1RecoveryMethod2020',
                }],
                service: [{
                  id: `did:bns:${record.name}#linked-domain`,
                  type: 'LinkedDomains',
                  serviceEndpoint: 'https://alice.me',
                }],
              },
              didDocumentMetadata: { version: 7, status: 'Active' },
            }, null, 2)}</pre>
          </div>
        </section>
      )}

      {mode === 'raw' && (
        <section className="raw-state-result tab-enter">
          <div className="raw-state-result__header">
            <div><span className="eyebrow">name.query_state</span><h2>原始投影状态</h2></div>
            <Tag tone="neutral">ok: true</Tag>
          </div>
          <pre>{JSON.stringify({
            name: record.name,
            raw_status: record.status,
            asset_owner: record.assetOwner,
            semantic_owner: { kind: 'unset', value: '0x' },
            effective_owner: { kind: 'chain_account', value: record.effectiveOwner },
            owner_source: record.ownerSource,
            name_seq: record.nameSeq,
            lineage_epoch: record.lineageEpoch,
            expire_at: 1809940800,
            grace_until: 1812532800,
          }, null, 2)}</pre>
        </section>
      )}
    </div>
  )
}

export function NamesPage() {
  const navigate = useNavigate()
  const { walletConnected, openWallet } = useAppState()
  const [filter, setFilter] = useState<'all' | 'active' | 'expiring'>('all')
  const [search, setSearch] = useState('')
  const visibleNames = names.filter((name) =>
    name.name.toLowerCase().includes(search.toLowerCase()),
  )

  return (
    <div className="page">
      <header className="page-header reveal">
        <div>
          <span className="eyebrow">Asset ownership</span>
          <h1>我持有的名称</h1>
          <p>此列表只按当前地址的 asset_owner 查询，不包含仅通过 Authority 或 Controller 管理的名称。</p>
        </div>
        <Button tone="primary" onClick={() => navigate('/register')}>
          注册名称
        </Button>
      </header>

      {!walletConnected ? (
        <EmptyState
          icon={WalletCards}
          title="连接钱包后查看持有名称"
          description="公共查询不需要钱包；此页面需要地址才能调用 name.query_by_addr。"
          action={<Button tone="primary" icon={WalletCards} onClick={openWallet}>连接钱包</Button>}
        />
      ) : (
        <>
          <div className="collection-toolbar reveal reveal--2">
            <div className="segmented-control">
              {[
                ['all', '全部 3'],
                ['active', '活跃 3'],
                ['expiring', '即将到期 1'],
              ].map(([id, label]) => (
                <button
                  className={clsx(filter === id && 'is-active')}
                  key={id}
                  type="button"
                  onClick={() => setFilter(id as typeof filter)}
                >
                  {label}
                </button>
              ))}
            </div>
            <label className="mini-search">
              <Search size={17} />
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="筛选当前列表"
              />
            </label>
            <Button tone="ghost" icon={SlidersHorizontal}>更多筛选</Button>
          </div>

          <section className="names-table reveal reveal--3">
            <div className="names-table__head">
              <span>名称</span><span>状态</span><span>Effective Owner</span><span>到期</span><span>Seq</span><span />
            </div>
            {visibleNames.map((name) => (
              <button
                className="names-table__row"
                key={name.name}
                type="button"
                onClick={() => navigate(`/name/${name.name}`)}
              >
                <div>
                  <span className="small-monogram">{name.name.slice(0, 1).toUpperCase()}</span>
                  <span><strong>{name.name}</strong><small>did:bns:{name.name}</small></span>
                </div>
                <span><Tag tone="success">{name.status}</Tag></span>
                <span>
                  <strong>{name.effectiveOwner.startsWith('0x') ? shortAddress(name.effectiveOwner) : name.effectiveOwner}</strong>
                  <small>{name.ownerSource.replaceAll('_', ' ')}</small>
                </span>
                <span><strong>{name.derivedStatus.replace('有效 · ', '')}</strong><small>{name.expiresAt.split(' ')[0]}</small></span>
                <strong>#{name.nameSeq}</strong>
                <ArrowRight size={16} />
              </button>
            ))}
          </section>

          <div className="collection-footer">
            <span>显示 3 / 3 · address {shortAddress(walletAddress)}</span>
            <Button tone="ghost" size="sm">加载更多</Button>
          </div>

          <div className="inline-notice inline-notice--wide">
            <CircleHelp size={17} />
            <p>
              想管理不由当前地址持有的名称？通过
              <button type="button" onClick={() => navigate('/search')}>搜索与解析</button>
              进入名称详情，页面会预检 Authority、Controller 或父名称继承路径。
            </p>
          </div>
        </>
      )}
    </div>
  )
}

export function RegisterPage() {
  const navigate = useNavigate()
  const {
    walletConnected,
    openWallet,
    addTransaction,
  } = useAppState()
  const [step, setStep] = useState(1)
  const [name, setName] = useState('my-name')
  const [duration, setDuration] = useState('365')
  const [grace, setGrace] = useState('30')
  const [advanced, setAdvanced] = useState(false)
  const [renewable, setRenewable] = useState(true)
  const [transferable, setTransferable] = useState(true)
  const [delegated, setDelegated] = useState(false)

  const normalized = name.toLowerCase().trim()
  const valid = /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(normalized)
    && normalized.split('.').length <= 2
  const isSecondLevel = normalized.includes('.')

  const submit = () => {
    if (!walletConnected) {
      openWallet()
      return
    }
    const hash = `0x${Date.now().toString(16).padStart(64, '0')}`
    addTransaction({
      hash,
      operation: '注册名称',
      target: normalized,
      submittedAt: '刚刚',
      stage: 'pending',
      chainLabel: '等待链上确认',
      detail: '已提交 registerName · value 0',
    })
    navigate(`/transactions?tx=${hash}`)
  }

  return (
    <div className="page register-page">
      <button className="back-link reveal" type="button" onClick={() => navigate(-1)}>
        <ChevronLeft size={16} />
        返回
      </button>
      <header className="register-header reveal">
        <div>
          <span className="eyebrow">Register name</span>
          <h1>创建一个新的 BNS 名称</h1>
          <p>写交易将由钱包直接发送到 Canonical BNS Proxy，固定 value = 0。</p>
        </div>
        <div className="step-indicator">
          {[1, 2, 3].map((value) => (
            <div className={clsx(value <= step && 'is-active')} key={value}>
              <span>{value < step ? <Check size={14} /> : value}</span>
              <strong>{['名称', '策略', '确认'][value - 1]}</strong>
            </div>
          ))}
        </div>
      </header>

      <div className="register-layout">
        <section className="register-form-panel reveal reveal--2">
          {step === 1 && (
            <div className="form-step tab-enter">
              <span className="eyebrow">Step 01 · Identity</span>
              <h2>你想注册什么名称？</h2>
              <p>仅支持小写 ASCII 字母、数字、连字符和最多一个点。</p>
              <div className="name-input-wrap">
                <Fingerprint size={22} />
                <input
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  autoFocus
                  spellCheck={false}
                />
                <span>.bns</span>
              </div>
              {name !== normalized && (
                <button className="normalize-hint" type="button" onClick={() => setName(normalized)}>
                  输入不会被静默修改。转换为 “{normalized}”
                </button>
              )}
              <div className={clsx('availability-result', valid ? 'is-available' : 'is-invalid')}>
                {valid ? <Check size={18} /> : <CircleHelp size={18} />}
                <div>
                  <strong>{valid ? `${normalized} 当前可注册` : '名称格式不符合协议约束'}</strong>
                  <small>{isSecondLevel ? '二级名称 · 需要父名称 Owner 签名' : '顶级名称 · 公共注册'}</small>
                </div>
              </div>
              <div className="form-navigation">
                <span />
                <Button tone="primary" disabled={!valid} onClick={() => setStep(2)}>
                  配置策略
                  <ChevronRight size={16} />
                </Button>
              </div>
            </div>
          )}

          {step === 2 && (
            <div className="form-step tab-enter">
              <span className="eyebrow">Step 02 · Policy</span>
              <h2>生命周期与权限</h2>
              <p>简单模式会使用安全默认值；高级设置可在同一交易写入 Authority 与文档。</p>
              <div className="two-field-grid">
                <div className="field-group">
                  <label htmlFor="register-duration">注册时长</label>
                  <div className="input-with-unit">
                    <input id="register-duration" value={duration} onChange={(event) => setDuration(event.target.value)} />
                    <span>天</span>
                  </div>
                </div>
                <div className="field-group">
                  <label htmlFor="register-grace">Grace period</label>
                  <div className="input-with-unit">
                    <input id="register-grace" value={grace} onChange={(event) => setGrace(event.target.value)} />
                    <span>天</span>
                  </div>
                </div>
              </div>
              <div className="policy-toggles">
                <PolicyToggle label="允许续期" description="名称到期前后可以延长有效期" value={renewable} onChange={setRenewable} />
                <PolicyToggle label="可转移" description="影响 standard_transfer_enabled 派生字段" value={transferable} onChange={setTransferable} />
                <PolicyToggle label="委托子名称意图" description="当前不改变二级名称链上鉴权" value={delegated} onChange={setDelegated} warning />
              </div>
              <button
                className={clsx('advanced-toggle', advanced && 'is-open')}
                type="button"
                onClick={() => setAdvanced((value) => !value)}
              >
                <span><Sparkles size={17} />高级注册设置</span>
                <ChevronRight size={16} />
              </button>
              <div className={clsx('advanced-fields', advanced && 'is-open')}>
                <div>
                  <span>Authority key updates</span><Button tone="ghost" size="sm">添加</Button>
                </div>
                <div>
                  <span>Initial documents</span><Button tone="ghost" size="sm">添加</Button>
                </div>
                <div>
                  <span>Controller rules</span><Button tone="ghost" size="sm">导入 JSON</Button>
                </div>
              </div>
              <div className="form-navigation">
                <Button tone="ghost" onClick={() => setStep(1)}><ChevronLeft size={16} />上一步</Button>
                <Button tone="primary" onClick={() => setStep(3)}>检查交易<ChevronRight size={16} /></Button>
              </div>
            </div>
          )}

          {step === 3 && (
            <div className="form-step tab-enter">
              <span className="eyebrow">Step 03 · Review</span>
              <h2>确认注册参数</h2>
              <p>钱包打开前的最后一次检查。链上最终授权可能仍因状态变化而失败。</p>
              <div className="review-name">
                <span className="name-monogram">{normalized.slice(0, 1).toUpperCase()}</span>
                <div><strong>{normalized}</strong><small>did:bns:{normalized}</small></div>
                <Tag tone="success">可注册</Tag>
              </div>
              <div className="review-grid">
                <DetailRow label="类型"><strong>{isSecondLevel ? '二级名称' : '顶级名称'}</strong></DetailRow>
                <DetailRow label="Asset Owner"><CopyValue value={walletAddress} compact /></DetailRow>
                <DetailRow label="Duration"><strong>{duration} 天</strong></DetailRow>
                <DetailRow label="Grace"><strong>{grace} 天</strong></DetailRow>
                <DetailRow label="Renewable"><strong>{renewable ? 'Yes' : 'No'}</strong></DetailRow>
                <DetailRow label="Transferable"><strong>{transferable ? 'Yes' : 'No'}</strong></DetailRow>
                <DetailRow label="CallAuthority"><strong>{isSecondLevel ? 'Owner · parent' : 'None'}</strong></DetailRow>
                <DetailRow label="Transaction value"><strong>0 ETH</strong></DetailRow>
              </div>
              <div className="transaction-boundary transaction-boundary--light">
                <div><span>TO · BNS Proxy</span><CopyValue value={proxyAddress} compact /></div>
                <div><span>CHAIN ID</span><strong>11155420</strong></div>
              </div>
              <label className="confirmation-check">
                <input type="checkbox" defaultChecked />
                <span><Check size={13} /></span>
                我已确认名称、Owner、网络和 Proxy 地址
              </label>
              <div className="form-navigation">
                <Button tone="ghost" onClick={() => setStep(2)}><ChevronLeft size={16} />上一步</Button>
                <Button tone="primary" icon={walletConnected ? ShieldCheck : WalletCards} onClick={submit}>
                  {walletConnected ? '打开钱包确认' : '连接钱包后继续'}
                </Button>
              </div>
            </div>
          )}
        </section>

        <aside className="register-aside reveal reveal--3">
          <span className="eyebrow">Live contract preview</span>
          <div className="registration-preview">
            <span className="registration-preview__mark"><Fingerprint size={25} /></span>
            <strong>{normalized || 'your-name'}</strong>
            <small>did:bns:{normalized || 'your-name'}</small>
          </div>
          <div className="preview-route">
            <div><span>Wallet</span><strong>{shortAddress(walletAddress)}</strong></div>
            <ArrowRight size={17} />
            <div><span>Proxy</span><strong>{shortAddress(proxyAddress)}</strong></div>
          </div>
          <div className="register-aside__facts">
            <div><span>Contract method</span><strong>registerName</strong></div>
            <div><span>Expected name seq</span><strong>{isSecondLevel ? 'parent current seq' : 'unused'}</strong></div>
            <div><span>Initial payment target</span><strong>zero address</strong></div>
            <div><span>msg.value</span><strong>0</strong></div>
          </div>
          <div className="drawer-note">
            <ShieldCheck size={18} />
            <p>交易成功后仍需等待 bns-indexer 投影。页面会在交易中心持续追踪。</p>
          </div>
        </aside>
      </div>
    </div>
  )
}

function PolicyToggle({
  label,
  description,
  value,
  onChange,
  warning = false,
}: {
  label: string
  description: string
  value: boolean
  onChange: (value: boolean) => void
  warning?: boolean
}) {
  return (
    <div className="policy-toggle">
      <div>
        <strong>{label}</strong>
        <small>{description}</small>
        {warning && <Tag tone="warning">仅保存意图</Tag>}
      </div>
      <button
        className={clsx('toggle-switch', value && 'is-on')}
        type="button"
        role="switch"
        aria-checked={value}
        onClick={() => onChange(!value)}
      >
        <span />
      </button>
    </div>
  )
}
