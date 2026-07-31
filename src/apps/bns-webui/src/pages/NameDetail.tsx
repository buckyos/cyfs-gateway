import clsx from 'clsx'
import {
  Activity,
  AlertTriangle,
  ArrowDown,
  ArrowRight,
  BadgeCheck,
  BookKey,
  Braces,
  CalendarClock,
  Check,
  ChevronLeft,
  CircleHelp,
  Database,
  FileCode2,
  FilePlus2,
  Fingerprint,
  Globe2,
  KeyRound,
  Link2,
  LockKeyhole,
  Network,
  Pencil,
  RefreshCw,
  Send,
  ShieldCheck,
  Trash2,
  UserRound,
  WalletCards,
} from 'lucide-react'
import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'

import {
  Button,
  CopyValue,
  DetailRow,
  SectionHeading,
  Tag,
} from '../components'
import {
  documents,
  events,
  nameRecordFor,
  shortAddress,
  walletAddress,
} from '../data'
import { useAppState } from '../state'

const tabs = [
  { id: 'overview', label: '概览' },
  { id: 'documents', label: '文档', count: 4 },
  { id: 'authority', label: 'Owner 与 Authority' },
  { id: 'controller', label: 'Controller' },
  { id: 'alias', label: 'Alias 与支付' },
  { id: 'namespace', label: 'Namespace' },
  { id: 'activity', label: '活动记录' },
  { id: 'danger', label: '危险操作' },
] as const

type TabId = (typeof tabs)[number]['id']

export function NameDetailPage() {
  const navigate = useNavigate()
  const { name: nameParam = 'alice' } = useParams()
  const decodedName = decodeURIComponent(nameParam)
  const record = nameRecordFor(decodedName)
  const [activeTab, setActiveTab] = useState<TabId>('overview')
  const { openAction } = useAppState()

  return (
    <div className="page name-page">
      <button className="back-link reveal" type="button" onClick={() => navigate(-1)}>
        <ChevronLeft size={16} />
        返回
      </button>

      <header className="name-header reveal">
        <div className="name-header__identity">
          <span className="name-monogram">{record.name.slice(0, 1).toUpperCase()}</span>
          <div>
            <div className="name-title-line">
              <h1>{record.name}</h1>
              <Tag tone="success">Active</Tag>
              <Tag tone="accent">Owner 权限通过</Tag>
            </div>
            <button
              className="did-value"
              type="button"
              onClick={() => navigate(`/search?did=did:bns:${record.name}`)}
            >
              did:bns:{record.name}
              <ArrowRight size={14} />
            </button>
          </div>
        </div>
        <div className="name-header__actions">
          <Button
            tone="secondary"
            icon={RefreshCw}
            onClick={() => openAction({ kind: 'renew', target: record.name })}
          >
            续期
          </Button>
          <Button
            tone="secondary"
            icon={FilePlus2}
            onClick={() => openAction({ kind: 'publish', target: record.name })}
          >
            发布文档
          </Button>
          <Button
            tone="primary"
            icon={Send}
            onClick={() => openAction({ kind: 'transfer', target: record.name })}
          >
            转移
          </Button>
        </div>
      </header>

      <div className="name-status-strip reveal reveal--2">
        <div>
          <span>原始状态</span>
          <strong><i className="status-light" />{record.status}</strong>
        </div>
        <div>
          <span>派生有效期</span>
          <strong>{record.derivedStatus}</strong>
        </div>
        <div>
          <span>Name sequence</span>
          <strong>#{record.nameSeq}</strong>
        </div>
        <div>
          <span>Lineage</span>
          <strong>Epoch {record.lineageEpoch}</strong>
        </div>
        <div>
          <span>写操作状态</span>
          <strong className="success-text"><Check size={15} />网络匹配</strong>
        </div>
      </div>

      <nav className="detail-tabs reveal reveal--2" aria-label="名称详情">
        {tabs.map((tab) => (
          <button
            className={clsx(activeTab === tab.id && 'is-active')}
            key={tab.id}
            type="button"
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
            {'count' in tab && <span>{tab.count}</span>}
          </button>
        ))}
      </nav>

      <div className="detail-tab-content" key={activeTab}>
        {activeTab === 'overview' && <OverviewTab name={record.name} />}
        {activeTab === 'documents' && <DocumentsTab name={record.name} />}
        {activeTab === 'authority' && <AuthorityTab name={record.name} />}
        {activeTab === 'controller' && <ControllerTab />}
        {activeTab === 'alias' && <AliasPaymentTab />}
        {activeTab === 'namespace' && <NamespaceTab name={record.name} />}
        {activeTab === 'activity' && <ActivityTab name={record.name} />}
        {activeTab === 'danger' && <DangerTab name={record.name} />}
      </div>
    </div>
  )
}

function OverviewTab({ name }: { name: string }) {
  const record = nameRecordFor(name)

  return (
    <div className="detail-layout">
      <div className="detail-main">
        <section className="detail-section">
          <SectionHeading
            eyebrow="Ownership map"
            title="谁持有，谁能管理"
            description="BNS 将资产持有人、语义 Owner 和最终生效的 Owner 分开表达。"
          />
          <div className="ownership-map">
            <div className="ownership-node">
              <span className="ownership-node__icon"><WalletCards size={19} /></span>
              <span>Asset Owner</span>
              <strong>{shortAddress(record.assetOwner)}</strong>
              <small>资产记录中的 EVM 地址</small>
            </div>
            <div className="ownership-connector">
              <span>semantic owner = unset</span>
              <ArrowRight size={22} />
            </div>
            <div className="ownership-node ownership-node--active">
              <span className="ownership-node__icon"><ShieldCheck size={19} /></span>
              <span>Effective Owner</span>
              <strong>
                {record.effectiveOwner.startsWith('0x')
                  ? shortAddress(record.effectiveOwner)
                  : record.effectiveOwner}
              </strong>
              <small>{ownerSourceLabel(record.ownerSource)}</small>
            </div>
          </div>
          {record.ownerSource === 'parent_inherited' && (
            <div className="inline-notice">
              <Network size={17} />
              <p>
                这是二级名称。Semantic Owner 未设置，因此继承父名称
                <strong> alice</strong> 的 Effective Owner。
              </p>
            </div>
          )}
        </section>

        <section className="detail-section">
          <SectionHeading
            eyebrow="Lifecycle"
            title="名称生命周期"
            action={<Tag tone="success">可续期</Tag>}
          />
          <div className="lifecycle">
            <div className="lifecycle__line">
              <span className="is-complete" />
              <span className="is-active" />
              <span />
            </div>
            <div className="lifecycle__labels">
              <div>
                <small>注册</small>
                <strong>{record.registeredAt}</strong>
              </div>
              <div>
                <small>当前</small>
                <strong>有效期剩余 284 天</strong>
              </div>
              <div>
                <small>到期 / Grace</small>
                <strong>{record.expiresAt}</strong>
                <span>Grace 至 {record.graceUntil}</span>
              </div>
            </div>
          </div>
        </section>

        <section className="detail-section">
          <SectionHeading eyebrow="Protocol state" title="链上状态字段" />
          <div className="detail-grid">
            <DetailRow label="Raw status">
              <Tag tone="success">{record.status}</Tag>
            </DetailRow>
            <DetailRow label="Name sequence">
              <strong>{record.nameSeq}</strong>
            </DetailRow>
            <DetailRow label="Lineage epoch">
              <strong>{record.lineageEpoch}</strong>
            </DetailRow>
            <DetailRow label="Renewable">
              <BooleanValue value={record.renewable} />
            </DetailRow>
            <DetailRow
              label="Transferable"
              help="当前合约的 transferName 未检查此 flag"
            >
              <BooleanValue value={record.transferable} />
            </DetailRow>
            <DetailRow label="Standard transfer">
              <BooleanValue value={record.transferable} />
            </DetailRow>
            <DetailRow label="Owner document">
              <strong>version {record.ownerDocumentVersion}</strong>
            </DetailRow>
            <DetailRow label="Min document IAT">
              <strong>1,742,387,200</strong>
            </DetailRow>
          </div>
        </section>
      </div>

      <aside className="detail-aside">
        <section className="side-section">
          <span className="eyebrow">Resolution summary</span>
          <h3>所有权解析</h3>
          <div className="resolution-stack">
            <div>
              <span><Fingerprint size={16} />Asset</span>
              <CopyValue value={record.assetOwner} compact />
            </div>
            <div>
              <span><BookKey size={16} />Semantic</span>
              <strong>{record.semanticOwner}</strong>
            </div>
            <div>
              <span><BadgeCheck size={16} />Effective</span>
              <strong>
                {record.effectiveOwner.startsWith('0x')
                  ? shortAddress(record.effectiveOwner)
                  : record.effectiveOwner}
              </strong>
            </div>
          </div>
        </section>

        <section className="side-section side-section--tinted">
          <span className="eyebrow">Authority preflight</span>
          <div className="preflight-score">
            <span><Check size={19} /></span>
            <div>
              <strong>Owner 路径可用</strong>
              <small>当前钱包与 concrete signer 匹配</small>
            </div>
          </div>
          <ul className="check-list">
            <li><Check size={14} />账户匹配</li>
            <li><Check size={14} />网络匹配</li>
            <li><Check size={14} />Proxy 地址已验证</li>
          </ul>
          <p>
            预检只帮助解释权限。合约仍是最终授权方，不能保证交易一定成功。
          </p>
        </section>

        <section className="side-section">
          <span className="eyebrow">Hashes</span>
          <div className="hash-list">
            <span>Owner policy</span>
            <CopyValue
              value="0x6c3de18ae9aeef7afe774a7e44ea4a88cd8f5425e6f0b781db12ae34d03721a8"
              compact
            />
            <span>Namespace policy</span>
            <CopyValue
              value="0x0000000000000000000000000000000000000000000000000000000000000000"
              compact
            />
          </div>
        </section>
      </aside>
    </div>
  )
}

function DocumentsTab({ name }: { name: string }) {
  const [selected, setSelected] = useState(documents[0])
  const { openAction } = useAppState()

  return (
    <div className="document-workspace">
      <section className="document-list-panel">
        <SectionHeading
          eyebrow="Known document types"
          title="文档"
          description="由内置类型、事件和本地历史汇总，可能不完整。"
          action={
            <Button
              tone="primary"
              size="sm"
              icon={FilePlus2}
              onClick={() => openAction({ kind: 'publish', target: name })}
            >
              发布
            </Button>
          }
        />
        <div className="document-list">
          {documents.map((document) => (
            <button
              className={clsx(
                'document-row',
                selected.type === document.type && 'is-active',
              )}
              key={document.type}
              type="button"
              onClick={() => setSelected(document)}
            >
              <span className="document-row__icon"><FileCode2 size={18} /></span>
              <div>
                <strong>{document.type}</strong>
                <small>{document.label}</small>
              </div>
              <span>
                v{document.version}
                <small>{document.updatedAt}</small>
              </span>
              <Tag tone={document.status === 'Active' ? 'success' : 'danger'}>
                {document.status}
              </Tag>
            </button>
          ))}
          <button className="document-row document-row--add" type="button">
            <span className="document-row__icon"><Braces size={18} /></span>
            <div>
              <strong>查询其他 doc type</strong>
              <small>按名称手动解析</small>
            </div>
            <ArrowRight size={16} />
          </button>
        </div>
      </section>

      <section className="document-preview-panel">
        <div className="document-preview__header">
          <div>
            <span className="eyebrow">Resolved document</span>
            <h2>{selected.type}</h2>
          </div>
          <Button
            tone="secondary"
            size="sm"
            icon={Pencil}
            onClick={() => openAction({ kind: 'publish', target: name })}
          >
            新版本
          </Button>
        </div>
        <div className="document-facts">
          <div><span>Version</span><strong>{selected.version}</strong></div>
          <div><span>Status</span><Tag tone={selected.status === 'Active' ? 'success' : 'danger'}>{selected.status}</Tag></div>
          <div><span>Storage</span><strong>{selected.storage}</strong></div>
        </div>
        <div className="code-view">
          <div className="code-view__bar">
            <span>UTF-8 · formatted</span>
            <button type="button">原始 bytes</button>
          </div>
          <pre>{selected.preview}</pre>
        </div>
        <div className="document-meta">
          <DetailRow label="Content hash">
            <CopyValue value={selected.hash} compact />
          </DetailRow>
          <DetailRow label="Controller"><strong>unset</strong></DetailRow>
          <DetailRow label="Beneficiary">
            <CopyValue value={walletAddress} compact />
          </DetailRow>
          <DetailRow label="Payment target">
            <CopyValue
              value="0x0000000000000000000000000000000000000000"
              compact
            />
          </DetailRow>
        </div>
        <div className="document-history">
          <div>
            <span className="eyebrow">Version history</span>
            <strong>1 — {selected.version}</strong>
          </div>
          {[...Array(Math.min(selected.version, 4))].map((_, index) => (
            <button key={index} type="button">
              v{selected.version - index}
            </button>
          ))}
          {selected.version > 4 && <button type="button">更早版本</button>}
        </div>
      </section>
    </div>
  )
}

function AuthorityTab({ name }: { name: string }) {
  return (
    <div className="detail-layout">
      <div className="detail-main">
        <section className="detail-section">
          <SectionHeading
            eyebrow="Authority set"
            title={`${name} 的签名权限`}
            description="Authority Key 让一个 BNS Name 成为可验证的 Owner 或 Controller。"
            action={<Button tone="primary" icon={KeyRound}>更新 Keys</Button>}
          />
          <div className="authority-summary">
            <div><span>Authority sequence</span><strong>12</strong></div>
            <div><span>Active keys</span><strong>2</strong></div>
            <div>
              <span>Authority root</span>
              <CopyValue
                value="0x93a5b61d720ea351c4922965f2e88051885202de381366b96c1f61020e32d540"
                compact
              />
            </div>
          </div>
        </section>
        <section className="detail-section">
          <div className="limitation-notice">
            <CircleHelp size={18} />
            <p>
              当前服务仅支持按 kid 查询。下方列表由本地记录、用户输入和已知
              key 组成，可能不完整。
            </p>
          </div>
          <div className="key-table">
            <div className="key-table__head">
              <span>Known key</span><span>Purpose</span><span>有效期</span><span>状态</span>
            </div>
            <div className="key-table__row">
              <div>
                <span className="key-glyph"><KeyRound size={17} /></span>
                <div>
                  <strong>primary-wallet</strong>
                  <CopyValue value="0x71c7656ec7ab88b098defb751b7401b5f6d8976f" compact />
                </div>
              </div>
              <span><Tag tone="accent">Authentication</Tag></span>
              <span>无截止时间</span>
              <span><Tag tone="success">Active</Tag></span>
            </div>
            <div className="key-table__row">
              <div>
                <span className="key-glyph"><KeyRound size={17} /></span>
                <div>
                  <strong>recovery-2026</strong>
                  <CopyValue value="0x419e3fcafbe17bb031d601472fd72c2cb722f43a" compact />
                </div>
              </div>
              <span><Tag tone="neutral">Recovery</Tag></span>
              <span>2027-01-01</span>
              <span><Tag tone="success">Active</Tag></span>
            </div>
          </div>
        </section>
      </div>
      <aside className="detail-aside">
        <section className="side-section side-section--tinted">
          <span className="eyebrow">Current signer</span>
          <div className="preflight-score">
            <span><BadgeCheck size={19} /></span>
            <div><strong>当前钱包匹配</strong><small>primary-wallet</small></div>
          </div>
          <ul className="check-list">
            <li><Check size={14} />Key data = 当前 20-byte 地址</li>
            <li><Check size={14} />Authentication bit = 1</li>
            <li><Check size={14} />处于有效时间窗</li>
          </ul>
        </section>
        <section className="side-section">
          <span className="eyebrow">Purpose semantics</span>
          <div className="purpose-list">
            <div><strong>1</strong><span>Authentication<small>授予链上写权限</small></span></div>
            <div><strong>2</strong><span>Recovery<small>当前不授予写权限</small></span></div>
            <div><strong>4</strong><span>Sign Document<small>当前不授予写权限</small></span></div>
          </div>
        </section>
      </aside>
    </div>
  )
}

function ControllerTab() {
  return (
    <div className="focused-panel">
      <div className="focused-panel__icon"><LockKeyhole size={24} /></div>
      <span className="eyebrow">Advanced · Full replacement</span>
      <h2>Controller Policy</h2>
      <p>
        Controller 可以在限定文档类型和权限范围内执行操作。当前 bns-server
        尚不能读取完整 rules，因此不能安全地将现有策略展示为可编辑列表。
      </p>
      <div className="limitation-grid">
        <div>
          <span>当前可确认</span>
          <strong>Policy hash</strong>
          <CopyValue
            value="0xb431aef18e24192d85784835ae42e55034a6663e839fac0d9a3ca741100bc90b"
            compact
          />
        </div>
        <div>
          <span>当前不可确认</span>
          <strong>完整 Rules</strong>
          <small>server 缺少 controller.get_policy</small>
        </div>
      </div>
      <div className="risk-banner">
        <AlertTriangle size={19} />
        <div>
          <strong>替换意味着覆盖全部现有规则</strong>
          <p>继续前需要导入或重新填写完整策略，并确认 canonical JSON 的最终 hash。</p>
        </div>
      </div>
      <div className="focused-panel__actions">
        <Button tone="secondary">导入 JSON 草稿</Button>
        <Button tone="primary">开始全量替换</Button>
      </div>
    </div>
  )
}

function AliasPaymentTab() {
  return (
    <div className="two-panel-layout">
      <section className="detail-section">
        <SectionHeading
          eyebrow="DID relationship"
          title="Alias"
          action={<Button tone="secondary" size="sm" icon={Pencil}>编辑</Button>}
        />
        <div className="alias-route">
          <span className="alias-route__source"><Fingerprint size={18} />did:bns:alice</span>
          <ArrowRight size={20} />
          <span className="alias-route__target"><Globe2 size={18} />did:web:alice.me</span>
        </div>
        <DetailRow label="Kind"><Tag tone="accent">Canonical</Tag></DetailRow>
        <DetailRow label="Proof hash">
          <CopyValue
            value="0x62ad7e5880d38fa0e0ac88d74241f42e7069d1843e80f756c02fe6ed17190081"
            compact
          />
        </DetailRow>
        <div className="inline-notice">
          <CircleHelp size={17} />
          <p>状态基于当前可查询文档与事件得到，服务暂不保证 Alias 信息完整。</p>
        </div>
      </section>
      <section className="detail-section">
        <SectionHeading
          eyebrow="Document settlement"
          title="Payment Target"
          action={<Button tone="secondary" size="sm" icon={Pencil}>编辑</Button>}
        />
        <DetailRow label="Document type"><strong>payment</strong></DetailRow>
        <DetailRow label="Target">
          <CopyValue value="0x48fEA792cF75f5Edf26B2c6523E269510113892d" compact />
        </DetailRow>
        <DetailRow label="Beneficiary">
          <CopyValue value={walletAddress} compact />
        </DetailRow>
        <DetailRow label="Version"><strong>2 · 不会因支付目标更新而增加</strong></DetailRow>
        <DetailRow label="State hash">
          <CopyValue
            value="0xaa33bc28e29646da56183d441625ce47263fcf6d8a2623919931541da778e28b"
            compact
          />
        </DetailRow>
      </section>
    </div>
  )
}

function NamespaceTab({ name }: { name: string }) {
  const [enabled, setEnabled] = useState(name === 'studio')

  return (
    <div className="focused-panel focused-panel--wide">
      <span className="eyebrow">Subname policy</span>
      <div className="focused-panel__title-row">
        <div>
          <h2>Namespace</h2>
          <p>控制二级名称的策略元数据和委托意图。</p>
        </div>
        <button
          className={clsx('toggle-switch', enabled && 'is-on')}
          type="button"
          role="switch"
          aria-checked={enabled}
          onClick={() => setEnabled((value) => !value)}
        >
          <span />
        </button>
      </div>
      <div className="namespace-visual">
        <div className="namespace-parent"><Network size={19} /><strong>{name}</strong></div>
        <ArrowDown size={18} />
        <div className="namespace-children">
          <span>device.{name}</span>
          <span>home.{name}</span>
          <span>api.{name}</span>
        </div>
      </div>
      <div className="risk-banner risk-banner--warning">
        <AlertTriangle size={19} />
        <div>
          <strong>这不是开放注册开关</strong>
          <p>
            当前 registerName 尚未使用 allowDelegatedSubnames 做鉴权；二级名称仍需父名称
            Effective Owner 签名。
          </p>
        </div>
      </div>
      <DetailRow label="Namespace policy hash">
        <CopyValue
          value="0x0000000000000000000000000000000000000000000000000000000000000000"
          compact
        />
      </DetailRow>
      <Button tone="primary">保存 Namespace Policy</Button>
    </div>
  )
}

function ActivityTab({ name }: { name: string }) {
  const records = events.filter((event) => event.name === name)
  const shown = records.length ? records : events.slice(0, 3)

  return (
    <section className="detail-section">
      <SectionHeading
        eyebrow="Projected events"
        title={`${name} 的活动记录`}
        description="按已加载事件过滤；不代表 server 端完整搜索结果。"
      />
      <div className="event-timeline">
        {shown.map((event) => (
          <div className="event-timeline__row" key={event.seq}>
            <span className="event-timeline__node"><Activity size={15} /></span>
            <div>
              <span>#{event.seq} · {event.type}</span>
              <strong>{event.detail}</strong>
              <small>Actor · {shortAddress(event.actor)}</small>
            </div>
            <span>{event.observedAt}</span>
            <CopyValue value={event.hash} compact />
          </div>
        ))}
      </div>
    </section>
  )
}

function DangerTab({ name }: { name: string }) {
  const { openAction } = useAppState()

  return (
    <div className="danger-zone">
      <div className="danger-zone__header">
        <div className="danger-zone__icon"><AlertTriangle size={24} /></div>
        <div>
          <span className="eyebrow">Irreversible actions</span>
          <h2>危险操作</h2>
          <p>这些操作不会自动重试。提交前会重新读取状态并生成新的 Mutation Guard。</p>
        </div>
      </div>
      <div className="danger-action">
        <div>
          <RefreshCw size={19} />
          <span>
            <strong>Release after grace</strong>
            <small>立即将 raw status 写为 Released。当前协议的旧关联状态清理存在风险。</small>
          </span>
        </div>
        <Button tone="secondary">释放名称</Button>
      </div>
      <div className="danger-action">
        <div>
          <Trash2 size={19} />
          <span>
            <strong>Tombstone forever</strong>
            <small>永久停用 {name}，协议层不可逆，也无法重新注册。</small>
          </span>
        </div>
        <Button tone="danger">永久 Tombstone</Button>
      </div>
      <div className="danger-action">
        <div>
          <Send size={19} />
          <span>
            <strong>转移所有权</strong>
            <small>同时变更 Asset Owner 与 Semantic Owner。</small>
          </span>
        </div>
        <Button
          tone="secondary"
          onClick={() => openAction({ kind: 'transfer', target: name })}
        >
          转移
        </Button>
      </div>
    </div>
  )
}

function BooleanValue({ value }: { value: boolean }) {
  return (
    <span className={clsx('boolean-value', value && 'is-true')}>
      {value ? <Check size={14} /> : '—'}
      {value ? 'Yes' : 'No'}
    </span>
  )
}

function ownerSourceLabel(source: string) {
  if (source === 'parent_inherited') return '继承父名称 Owner'
  if (source === 'explicit_semantic_owner') return '显式 BNS Name Owner'
  return 'Asset Owner fallback'
}
