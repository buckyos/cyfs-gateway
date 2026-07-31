import clsx from 'clsx'
import {
  Activity,
  BookOpen,
  Check,
  ChevronDown,
  CircleHelp,
  Clock3,
  Command,
  FileCode2,
  Gauge,
  KeyRound,
  Menu,
  Moon,
  Plus,
  Search,
  Settings,
  ShieldCheck,
  Sun,
  WalletCards,
  X,
} from 'lucide-react'
import { useMemo, useState, type ReactNode } from 'react'
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'

import { proxyAddress, shortAddress, walletAddress } from './data'
import {
  Button,
  CopyValue,
  GlobalSearch,
  LogoMark,
  StageIcon,
  StatusDot,
  Tag,
} from './components'
import { useAppState } from './state'

const navigation = [
  { to: '/', label: '概览', icon: Gauge, end: true },
  { to: '/search', label: '搜索与解析', icon: Search },
  { to: '/names', label: '我持有的名称', icon: BookOpen },
  { to: '/register', label: '注册名称', icon: Plus },
  { to: '/transactions', label: '交易中心', icon: Clock3, badge: '2' },
  { to: '/events', label: '事件浏览器', icon: Activity },
  { to: '/advanced', label: '高级工具', icon: Command },
]

const mobileNavigation = [
  navigation[0],
  navigation[2],
  navigation[3],
  navigation[4],
  { to: '/more', label: '更多', icon: Menu },
]

export function AppShell() {
  const { theme, toggleTheme, openWallet, walletConnected } = useAppState()
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar__top">
          <LogoMark />
          <div className="environment-chip">
            <StatusDot tone="success" pulse />
            OP Sepolia
            <span>·</span>
            Beta2.2
          </div>
        </div>

        <nav className="sidebar__nav" aria-label="主导航">
          <span className="nav-label">Registry</span>
          {navigation.map(({ to, label, icon: Icon, badge, end }) => (
            <NavLink
              className={({ isActive }) =>
                clsx('nav-item', isActive && 'is-active')
              }
              end={end}
              key={to}
              to={to}
            >
              <Icon size={18} />
              <span>{label}</span>
              {badge && <em>{badge}</em>}
            </NavLink>
          ))}
        </nav>

        <div className="sidebar__system">
          <div className="system-readout">
            <div>
              <StatusDot tone="success" />
              <span>查询服务正常</span>
            </div>
            <strong>42 ms</strong>
          </div>
          <div className="system-readout">
            <div>
              <StatusDot tone="warning" />
              <span>Indexer</span>
            </div>
            <strong>~1 block</strong>
          </div>
          <NavLink className="nav-item nav-item--quiet" to="/settings">
            <Settings size={18} />
            <span>连接设置</span>
          </NavLink>
          <button
            className="nav-item nav-item--quiet"
            type="button"
            onClick={toggleTheme}
          >
            {theme === 'light' ? <Moon size={18} /> : <Sun size={18} />}
            <span>{theme === 'light' ? '深色模式' : '浅色模式'}</span>
          </button>
        </div>
      </aside>

      <main className="main-shell">
        <header className="topbar">
          <div className="topbar__mobile-brand">
            <LogoMark compact />
          </div>
          <div className="topbar__search">
            <GlobalSearch />
          </div>
          <div className="topbar__right">
            <button className="network-button" type="button">
              <span className="network-glyph">OP</span>
              <span>
                <small>当前网络</small>
                OP Sepolia
              </span>
              <ChevronDown size={15} />
            </button>
            <button
              className={clsx(
                'wallet-button',
                walletConnected && 'is-connected',
              )}
              type="button"
              onClick={openWallet}
            >
              <WalletCards size={17} />
              {walletConnected ? shortAddress(walletAddress) : '连接钱包'}
            </button>
          </div>
        </header>

        <div className="demo-notice">
          <span>Prototype</span>
          当前使用演示投影数据。查询与写入边界、权限和交易阶段按 Beta2.2 PRD 呈现。
        </div>

        <div className="page-viewport">
          <Outlet />
        </div>
      </main>

      <nav className="mobile-bottom-nav" aria-label="移动端导航">
        {mobileNavigation.map(({ to, label, icon: Icon, end }) =>
          to === '/more' ? (
            <button
              className={clsx(mobileMenuOpen && 'is-active')}
              key={to}
              type="button"
              onClick={() => setMobileMenuOpen((value) => !value)}
            >
              <Icon size={20} />
              <span>{label}</span>
            </button>
          ) : (
            <NavLink
              className={({ isActive }) => clsx(isActive && 'is-active')}
              end={end}
              key={to}
              to={to}
            >
              <Icon size={20} />
              <span>{label}</span>
            </NavLink>
          ),
        )}
      </nav>

      {mobileMenuOpen && (
        <div className="mobile-more-menu">
          <button
            aria-label="关闭更多菜单"
            className="mobile-more-menu__backdrop"
            type="button"
            onClick={() => setMobileMenuOpen(false)}
          />
          <div className="mobile-more-menu__panel">
            <div className="drawer-handle" />
            <h2>更多</h2>
            {navigation.slice(1).map(({ to, label, icon: Icon }) => (
              <NavLink
                key={to}
                to={to}
                onClick={() => setMobileMenuOpen(false)}
              >
                <Icon size={19} />
                {label}
              </NavLink>
            ))}
            <NavLink to="/settings" onClick={() => setMobileMenuOpen(false)}>
              <Settings size={19} />
              连接设置
            </NavLink>
          </div>
        </div>
      )}

      <WalletDrawer />
      <ActionDrawer />
      <Toast />
    </div>
  )
}

function WalletDrawer() {
  const {
    walletOpen,
    closeWallet,
    connectWallet,
    disconnectWallet,
    walletConnected,
  } = useAppState()

  return (
    <div
      className={clsx('drawer-layer', walletOpen && 'is-open')}
      aria-hidden={!walletOpen}
    >
      <button
        className="drawer-backdrop"
        aria-label="关闭钱包面板"
        type="button"
        onClick={closeWallet}
      />
      <aside className="side-drawer">
        <div className="side-drawer__header">
          <div>
            <span className="eyebrow">Wallet channel</span>
            <h2>{walletConnected ? '当前钱包' : '连接你的钱包'}</h2>
          </div>
          <button
            className="icon-button"
            type="button"
            aria-label="关闭"
            onClick={closeWallet}
          >
            <X size={19} />
          </button>
        </div>

        {walletConnected ? (
          <>
            <div className="connected-wallet-card">
              <span className="wallet-identicon">A</span>
              <div>
                <strong>Account 01</strong>
                <CopyValue value={walletAddress} compact />
              </div>
              <Tag tone="success">已连接</Tag>
            </div>
            <div className="trust-summary">
              <div>
                <span>网络</span>
                <strong>OP Sepolia · 11155420</strong>
              </div>
              <div>
                <span>BNS Proxy</span>
                <CopyValue value={proxyAddress} compact />
              </div>
              <div>
                <span>写入状态</span>
                <strong className="success-text">校验通过</strong>
              </div>
            </div>
            <div className="drawer-note">
              <ShieldCheck size={18} />
              <p>
                写交易由钱包直达 BNS Proxy。页面不会请求助记词，也不会通过
                bns-server 代签。
              </p>
            </div>
            <Button tone="ghost" onClick={disconnectWallet}>
              断开连接
            </Button>
          </>
        ) : (
          <>
            <p className="drawer-intro">
              钱包只在你主动发起操作时请求授权。连接前仍可查询全部公共名称与事件。
            </p>
            <div className="wallet-options">
              <WalletOption
                color="#e2761b"
                label="MetaMask"
                note="浏览器扩展"
                onClick={connectWallet}
              />
              <WalletOption
                color="#8697ff"
                label="Rabby"
                note="已检测到"
                onClick={connectWallet}
              />
              <WalletOption
                color="#2864f0"
                label="WalletConnect"
                note="扫码或移动端"
                onClick={connectWallet}
              />
              <WalletOption
                color="#1754ee"
                label="Coinbase Wallet"
                note="浏览器 / 移动端"
                onClick={connectWallet}
              />
            </div>
            <div className="drawer-note">
              <CircleHelp size={18} />
              <p>
                钱包名称仅用于展示，不作为安全身份。最终账户与网络由 EIP-1193
                Provider 返回值确认。
              </p>
            </div>
          </>
        )}
      </aside>
    </div>
  )
}

function WalletOption({
  color,
  label,
  note,
  onClick,
}: {
  color: string
  label: string
  note: string
  onClick: () => void
}) {
  return (
    <button className="wallet-option" type="button" onClick={onClick}>
      <span style={{ background: color }}>{label.slice(0, 1)}</span>
      <div>
        <strong>{label}</strong>
        <small>{note}</small>
      </div>
      <ChevronDown size={16} />
    </button>
  )
}

function ActionDrawer() {
  const {
    activeAction,
    closeAction,
    walletConnected,
    openWallet,
    addTransaction,
  } = useAppState()
  const navigate = useNavigate()
  const [duration, setDuration] = useState('180')
  const [confirmName, setConfirmName] = useState('')

  const isOpen = activeAction.kind !== null && activeAction.kind !== 'wallet'
  const title = useMemo(() => {
    if (activeAction.kind === 'renew') return `续期 ${activeAction.target}`
    if (activeAction.kind === 'transfer') return `转移 ${activeAction.target}`
    if (activeAction.kind === 'publish') return `发布文档 · ${activeAction.target}`
    if (activeAction.kind === 'transaction') return '交易详情'
    return ''
  }, [activeAction])

  const submit = (operation: string) => {
    if (!walletConnected) {
      closeAction()
      openWallet()
      return
    }

    const hash = `0x${Date.now().toString(16).padStart(64, '0')}`
    addTransaction({
      hash,
      operation,
      target: activeAction.target ?? 'alice',
      submittedAt: '刚刚',
      stage: 'pending',
      chainLabel: '等待链上确认',
      detail: '已广播至钱包配置的 EVM RPC',
    })
    closeAction()
    navigate(`/transactions?tx=${hash}`)
  }

  return (
    <div
      className={clsx('drawer-layer', isOpen && 'is-open')}
      aria-hidden={!isOpen}
    >
      <button
        className="drawer-backdrop"
        aria-label="关闭操作面板"
        type="button"
        onClick={closeAction}
      />
      <aside className="side-drawer side-drawer--action">
        <div className="side-drawer__header">
          <div>
            <span className="eyebrow">Review before wallet</span>
            <h2>{title}</h2>
          </div>
          <button
            className="icon-button"
            type="button"
            aria-label="关闭"
            onClick={closeAction}
          >
            <X size={19} />
          </button>
        </div>

        {activeAction.kind === 'renew' && (
          <div className="action-form">
            <div className="field-group">
              <label htmlFor="renew-duration">续期时长</label>
              <div className="input-with-unit">
                <input
                  id="renew-duration"
                  value={duration}
                  onChange={(event) => setDuration(event.target.value)}
                  inputMode="numeric"
                />
                <span>天</span>
              </div>
              <div className="choice-row">
                {['90', '180', '365'].map((value) => (
                  <button
                    className={clsx(duration === value && 'is-selected')}
                    key={value}
                    type="button"
                    onClick={() => setDuration(value)}
                  >
                    {value} 天
                  </button>
                ))}
              </div>
            </div>
            <div className="before-after">
              <div>
                <span>当前到期</span>
                <strong>2027-05-10</strong>
              </div>
              <ChevronDown size={17} />
              <div>
                <span>预计到期</span>
                <strong>2027-11-06</strong>
              </div>
            </div>
            <div className="drawer-note">
              <CircleHelp size={18} />
              <p>当前合约允许任何账户代续期，且交易 value 固定为 0。</p>
            </div>
            <TransactionBoundary />
            <Button tone="primary" onClick={() => submit('续期名称')}>
              {walletConnected ? '用钱包确认交易' : '连接钱包后继续'}
            </Button>
          </div>
        )}

        {activeAction.kind === 'transfer' && (
          <div className="action-form">
            <div className="risk-banner">
              <ShieldCheck size={19} />
              <div>
                <strong>高风险操作</strong>
                <p>这不是 ERC-721 transfer。资产与语义 Owner 会在同一交易中更新。</p>
              </div>
            </div>
            <div className="field-group">
              <label htmlFor="new-owner">新的 Asset Owner</label>
              <input
                id="new-owner"
                defaultValue="0x44CA802eB3bb5D622fAaC51257C4B27aa9A74d05"
              />
              <small>提交前会按 checksum 地址再次展示。</small>
            </div>
            <div className="field-group">
              <label htmlFor="semantic-owner">新的 Semantic Owner</label>
              <select id="semantic-owner" defaultValue="unset">
                <option value="unset">Unset · 回退到新的 Asset Owner</option>
                <option value="bns">使用 BNS Name</option>
              </select>
            </div>
            <div className="field-group">
              <label htmlFor="confirm-transfer">
                输入完整名称 “{activeAction.target}” 确认
              </label>
              <input
                id="confirm-transfer"
                value={confirmName}
                onChange={(event) => setConfirmName(event.target.value)}
                placeholder={activeAction.target}
              />
            </div>
            <TransactionBoundary />
            <Button
              tone="danger"
              disabled={confirmName !== activeAction.target}
              onClick={() => submit('转移名称')}
            >
              {walletConnected ? '确认并打开钱包' : '连接钱包后继续'}
            </Button>
          </div>
        )}

        {activeAction.kind === 'publish' && (
          <div className="action-form">
            <div className="two-field-grid">
              <div className="field-group">
                <label htmlFor="doc-type">文档类型</label>
                <input id="doc-type" defaultValue="zone" />
              </div>
              <div className="field-group">
                <label htmlFor="storage">存储方式</label>
                <select id="storage" defaultValue="inline">
                  <option value="inline">Inline</option>
                  <option value="uri">URI</option>
                </select>
              </div>
            </div>
            <div className="field-group">
              <label htmlFor="doc-content">文档内容</label>
              <textarea
                id="doc-content"
                rows={9}
                defaultValue={'{\n  "records": [\n    { "type": "A", "value": "203.0.113.8" }\n  ]\n}'}
              />
              <small>浏览器会在本地计算 SHA-256 · 最大 4096 bytes</small>
            </div>
            <div className="hash-preview">
              <span>Expected version</span>
              <strong>7 → 8</strong>
              <span>Mutation guard</span>
              <strong>name_seq 42</strong>
            </div>
            <TransactionBoundary />
            <Button tone="primary" onClick={() => submit('发布 zone 文档')}>
              {walletConnected ? '预检并打开钱包' : '连接钱包后继续'}
            </Button>
          </div>
        )}

        {activeAction.kind === 'transaction' && activeAction.transaction && (
          <TransactionDetail>{activeAction.transaction.detail}</TransactionDetail>
        )}
      </aside>
    </div>
  )
}

function TransactionBoundary() {
  return (
    <div className="transaction-boundary">
      <div>
        <span>TO · BNS Proxy</span>
        <CopyValue value={proxyAddress} compact />
      </div>
      <div>
        <span>CHAIN / VALUE</span>
        <strong>11155420 · 0 ETH</strong>
      </div>
    </div>
  )
}

function TransactionDetail({ children }: { children: ReactNode }) {
  return (
    <div className="transaction-detail-panel">
      <div className="tx-route tx-route--vertical">
        <div className="tx-route__step is-done">
          <StageIcon state="done" />
          <div>
            <strong>Wallet</strong>
            <span>用户已确认</span>
          </div>
        </div>
        <div className="tx-route__line is-done" />
        <div className="tx-route__step is-done">
          <StageIcon state="done" />
          <div>
            <strong>Chain</strong>
            <span>Receipt succeeded</span>
          </div>
        </div>
        <div className="tx-route__line is-active" />
        <div className="tx-route__step is-active">
          <StageIcon state="active" />
          <div>
            <strong>Indexer</strong>
            <span>等待业务投影</span>
          </div>
        </div>
      </div>
      <p className="drawer-intro">{children}</p>
      <TransactionBoundary />
      <Button tone="secondary">立即重新查询</Button>
    </div>
  )
}

function Toast() {
  const { toast } = useAppState()
  return (
    <div className={clsx('toast', toast && 'is-visible')}>
      <Check size={16} />
      <span>{toast}</span>
    </div>
  )
}
