/**
 * 应用外壳：左侧一级导航 + 顶部全局区（PRD 7.1 / 7.2）。
 *
 * 顶部全局区：搜索、当前网络、bns-server 健康状态、连接钱包、
 * 当前账号（一级名称）快速切换器、交易中心入口。
 */

import { clsx } from 'clsx'
import {
  Activity,
  ArrowLeftRight,
  ChevronDown,
  Crown,
  Home,
  LogOut,
  Menu,
  Plus,
  Search,
  Settings,
  Shield,
  ShoppingBag,
  Terminal,
  User,
  Wallet,
  X,
} from 'lucide-react'
import { useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { NavLink, useLocation, useNavigate } from 'react-router-dom'

import { isSettled, type WalletProviderInfo } from '../bns_model'
import { useBnsModel, useSession, useTransactions } from '../bns_model/react'
import { useAccounts } from './account'
import { shortAddress } from './format'
import { Modal, Note, Pill, Spinner } from './kit'

const NAV_ITEMS: { to: string; label: string; icon: ReactNode; end?: boolean }[] = [
  { to: '/', label: '首页', icon: <Home />, end: true },
  { to: '/search', label: '搜索与解析', icon: <Search /> },
  { to: '/account', label: '我的账号', icon: <User /> },
  { to: '/acquired', label: '我买来的资产', icon: <ShoppingBag /> },
  { to: '/register', label: '注册名称', icon: <Plus /> },
  { to: '/security', label: '安全中心', icon: <Shield /> },
  { to: '/tx', label: '交易中心', icon: <ArrowLeftRight /> },
  { to: '/events', label: '事件浏览器', icon: <Activity /> },
  { to: '/advanced', label: '高级工具', icon: <Terminal /> },
  { to: '/settings', label: '设置', icon: <Settings /> },
]

export function Shell({ demoMode, children }: { demoMode: boolean; children: ReactNode }) {
  const [navOpen, setNavOpen] = useState(false)
  const location = useLocation()

  useEffect(() => {
    setNavOpen(false)
  }, [location.pathname])

  const transactions = useTransactions()
  const activeTxCount = useMemo(
    () => transactions.records.filter((record) => !isSettled(record.stage) && !record.stopped).length,
    [transactions.records],
  )

  return (
    <div className={clsx('shell', navOpen && 'nav-open')}>
      <aside className="shell__sidebar">
        <div className="brand">
          <div className="brand__logo">B</div>
          <div>
            <div className="brand__name">BNS</div>
            <div className="brand__tag">Name Registry · Beta2.2</div>
          </div>
        </div>
        <nav className="nav">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) => clsx('nav__item', isActive && 'is-active')}
            >
              {item.icon}
              {item.label}
              {item.to === '/tx' && activeTxCount > 0 ? (
                <span className="nav__badge">{activeTxCount}</span>
              ) : null}
            </NavLink>
          ))}
        </nav>
        <div className="nav__foot">
          {demoMode ? (
            <>
              演示模式：内置假 bns-server 与演示钱包，
              数据仅存于本页面内存。
            </>
          ) : (
            <>已连接真实 bns-server（只读浏览）。</>
          )}
        </div>
      </aside>
      {navOpen ? <div className="shell__scrim" onClick={() => setNavOpen(false)} /> : null}
      <div className="shell__main">
        <Topbar onToggleNav={() => setNavOpen((open) => !open)} />
        <main className="shell__content">{children}</main>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// 顶部全局区
// ---------------------------------------------------------------------------

function Topbar({ onToggleNav }: { onToggleNav: () => void }) {
  const navigate = useNavigate()
  const [query, setQuery] = useState('')

  const onSubmit = (event: FormEvent) => {
    event.preventDefault()
    const value = query.trim()
    if (!value) return
    navigate(`/search?q=${encodeURIComponent(value)}`)
    setQuery('')
  }

  return (
    <header className="topbar">
      <button type="button" className="btn btn--ghost btn--sm topbar__menu" onClick={onToggleNav} aria-label="导航">
        <Menu />
      </button>
      <form className="topbar__search" onSubmit={onSubmit}>
        <Search />
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="名称 / did:bns:… / 地址 / 交易 hash"
          aria-label="全局搜索"
        />
      </form>
      <div className="topbar__right">
        <NetworkStatus />
        <AccountSwitcher />
        <WalletButton />
      </div>
    </header>
  )
}

function NetworkStatus() {
  const session = useSession()
  const model = useBnsModel()
  const navigate = useNavigate()
  const info = session.systemInfo.data

  if (session.serverHealthy === null || session.systemInfo.status === 'loading') {
    return (
      <Pill tone="neutral" title="正在探测 bns-server">
        <Spinner /> 连接中
      </Pill>
    )
  }
  if (session.network === 'server_down') {
    return (
      <Pill tone="danger" dot title="bns-server 不可达，页面保持只读">
        服务不可达
      </Pill>
    )
  }
  if (session.network === 'server_not_ready') {
    return (
      <Pill tone="warn" dot title="bns-server 报告 ready = false">
        服务未就绪
      </Pill>
    )
  }
  if (session.network === 'config_mismatch' || session.network === 'contract_unpinned') {
    return (
      <Pill tone="danger" dot title={session.writeGate.reason ?? undefined}>
        配置不一致
      </Pill>
    )
  }
  if (session.network === 'chain_mismatch') {
    return (
      <button
        type="button"
        className="btn btn--sm"
        title={session.writeGate.reason ?? undefined}
        onClick={() => void model.controllers.session.switchToServerChain().catch(() => undefined)}
      >
        <Pill tone="warn" dot>
          链不一致
        </Pill>
        切换网络
      </button>
    )
  }
  return (
    <button
      type="button"
      className="btn btn--ghost btn--sm"
      onClick={() => navigate('/settings')}
      title={info ? `chain ${info.chainId} · Proxy ${info.contractAddress}` : undefined}
    >
      <Pill tone="ok" dot>
        Chain {info?.chainId ?? '—'}
      </Pill>
    </button>
  )
}

/** 当前账号（一级名称）切换器：仅一个账号时不显示切换（PRD 7.1）。 */
function AccountSwitcher() {
  const { accounts, currentAccount, setCurrentAccount } = useAccounts()
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const onClick = (event: MouseEvent) => {
      if (ref.current && !ref.current.contains(event.target as Node)) setOpen(false)
    }
    window.addEventListener('mousedown', onClick)
    return () => window.removeEventListener('mousedown', onClick)
  }, [open])

  if (!currentAccount) return null

  if (accounts.length === 1) {
    return (
      <Pill tone="accent" title="当前账号（一级名称）">
        <Crown style={{ width: 12, height: 12 }} /> {currentAccount}
      </Pill>
    )
  }

  return (
    <div className="account-switch" ref={ref}>
      <button type="button" className="btn btn--sm" onClick={() => setOpen((value) => !value)}>
        <Crown style={{ width: 13, height: 13, color: 'var(--accent)' }} />
        <span className="mono">{currentAccount}</span>
        <ChevronDown style={{ width: 13, height: 13 }} />
      </button>
      {open ? (
        <div className="account-menu">
          {accounts.map((entry) => (
            <div
              key={entry.name}
              className={clsx('account-menu__item', entry.name === currentAccount && 'is-active')}
              onClick={() => {
                setCurrentAccount(entry.name)
                setOpen(false)
              }}
            >
              <Crown style={{ width: 13, height: 13 }} />
              <span className="mono">{entry.name}</span>
            </div>
          ))}
          <div className="account-menu__hint">账号切换只改变页面视图，不发起链上交易。</div>
        </div>
      ) : null}
    </div>
  )
}

function WalletButton() {
  const session = useSession()
  const model = useBnsModel()
  const [pickerOpen, setPickerOpen] = useState(false)
  const [menuOpen, setMenuOpen] = useState(false)
  const [providers, setProviders] = useState<WalletProviderInfo[] | null>(null)
  const [connecting, setConnecting] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!menuOpen) return
    const onClick = (event: MouseEvent) => {
      if (ref.current && !ref.current.contains(event.target as Node)) setMenuOpen(false)
    }
    window.addEventListener('mousedown', onClick)
    return () => window.removeEventListener('mousedown', onClick)
  }, [menuOpen])

  const openPicker = async () => {
    setPickerOpen(true)
    setError(null)
    // 用户点击后才枚举 provider（PRD 8.2：不得提前请求权限）。
    const list = await model.controllers.session.listProviders().catch(() => [])
    setProviders(list)
  }

  const connect = async (providerId?: string) => {
    setConnecting(providerId ?? 'default')
    setError(null)
    try {
      await model.controllers.session.connect(providerId)
      setPickerOpen(false)
    } catch (connectError) {
      setError(connectError instanceof Error ? connectError.message : String(connectError))
    } finally {
      setConnecting(null)
    }
  }

  if (!session.wallet.connected || !session.wallet.address) {
    return (
      <>
        <button type="button" className="btn btn--primary btn--sm" onClick={() => void openPicker()}>
          <Wallet /> 连接钱包
        </button>
        {pickerOpen ? (
          <Modal title="连接钱包" icon={<Wallet />} onClose={() => setPickerOpen(false)}>
            <Note tone="info">
              钱包只负责账户授权、网络切换与交易签名；本页面永不接触私钥或助记词。
            </Note>
            {providers === null ? (
              <div className="loading-row">
                <Spinner /> 正在发现已安装钱包（EIP-6963）…
              </div>
            ) : providers.length === 0 ? (
              <div className="empty">未发现可用钱包适配器</div>
            ) : (
              providers.map((provider) => (
                <button
                  key={provider.id}
                  type="button"
                  className="btn"
                  style={{ width: '100%', justifyContent: 'flex-start', marginBottom: 8 }}
                  disabled={connecting !== null}
                  onClick={() => void connect(provider.id)}
                >
                  {connecting === provider.id ? <Spinner /> : <Wallet />}
                  {provider.name}
                  <span style={{ marginLeft: 'auto', color: 'var(--text-faint)', fontSize: 11 }}>
                    {provider.kind}
                  </span>
                </button>
              ))
            )}
            {error ? <Note tone="danger">{error}</Note> : null}
          </Modal>
        ) : null}
      </>
    )
  }

  return (
    <div className="account-switch" ref={ref}>
      <button type="button" className="btn btn--sm" onClick={() => setMenuOpen((value) => !value)}>
        <span
          className="dot"
          style={{ width: 7, height: 7, borderRadius: 99, background: 'var(--ok)' }}
        />
        <span className="mono">{shortAddress(session.wallet.address)}</span>
        <ChevronDown style={{ width: 13, height: 13 }} />
      </button>
      {menuOpen ? (
        <div className="account-menu">
          <div className="account-menu__item" style={{ cursor: 'default' }}>
            <span className="mono" style={{ fontSize: 11.5, overflowWrap: 'anywhere' }}>
              {session.wallet.address}
            </span>
          </div>
          <div
            className="account-menu__item"
            onClick={() => {
              void navigator.clipboard?.writeText(session.wallet.address ?? '')
              setMenuOpen(false)
            }}
          >
            复制地址
          </div>
          <div
            className="account-menu__item"
            onClick={() => {
              void model.controllers.session.disconnect()
              setMenuOpen(false)
            }}
          >
            <LogOut style={{ width: 13, height: 13 }} /> 断开连接
          </div>
        </div>
      ) : null}
    </div>
  )
}

export function CloseIcon() {
  return <X />
}
