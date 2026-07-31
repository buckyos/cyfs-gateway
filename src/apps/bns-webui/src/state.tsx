import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'

import {
  transactions as seededTransactions,
  type TransactionRecord,
  walletAddress,
} from './data'

type ActionKind =
  | 'renew'
  | 'transfer'
  | 'publish'
  | 'wallet'
  | 'transaction'
  | null

export type ActiveAction = {
  kind: ActionKind
  target?: string
  transaction?: TransactionRecord
}

type AppState = {
  walletConnected: boolean
  walletOpen: boolean
  theme: 'light' | 'dark'
  activeAction: ActiveAction
  transactions: TransactionRecord[]
  toast: string | null
  openWallet: () => void
  closeWallet: () => void
  connectWallet: () => void
  disconnectWallet: () => void
  toggleTheme: () => void
  openAction: (action: ActiveAction) => void
  closeAction: () => void
  addTransaction: (transaction: TransactionRecord) => void
  notify: (message: string) => void
}

const AppStateContext = createContext<AppState | null>(null)

export function AppStateProvider({ children }: { children: ReactNode }) {
  const [walletConnected, setWalletConnected] = useState(false)
  const [walletOpen, setWalletOpen] = useState(false)
  const [theme, setTheme] = useState<'light' | 'dark'>('light')
  const [activeAction, setActiveAction] = useState<ActiveAction>({ kind: null })
  const [transactions, setTransactions] =
    useState<TransactionRecord[]>(seededTransactions)
  const [toast, setToast] = useState<string | null>(null)

  useEffect(() => {
    document.documentElement.dataset.theme = theme
  }, [theme])

  useEffect(() => {
    if (!toast) return
    const timer = window.setTimeout(() => setToast(null), 2600)
    return () => window.clearTimeout(timer)
  }, [toast])

  const notify = useCallback((message: string) => {
    setToast(message)
  }, [])

  const value = useMemo<AppState>(
    () => ({
      walletConnected,
      walletOpen,
      theme,
      activeAction,
      transactions,
      toast,
      openWallet: () => setWalletOpen(true),
      closeWallet: () => setWalletOpen(false),
      connectWallet: () => {
        setWalletConnected(true)
        setWalletOpen(false)
        setToast(`已连接 ${walletAddress.slice(0, 6)}…${walletAddress.slice(-4)}`)
      },
      disconnectWallet: () => {
        setWalletConnected(false)
        setToast('钱包已断开，页面保持只读')
      },
      toggleTheme: () =>
        setTheme((current) => (current === 'light' ? 'dark' : 'light')),
      openAction: (action) => setActiveAction(action),
      closeAction: () => setActiveAction({ kind: null }),
      addTransaction: (transaction) => {
        setTransactions((current) => [transaction, ...current])
        setToast('交易已加入本地交易中心')
      },
      notify,
    }),
    [
      activeAction,
      notify,
      theme,
      toast,
      transactions,
      walletConnected,
      walletOpen,
    ],
  )

  return (
    <AppStateContext.Provider value={value}>
      {children}
    </AppStateContext.Provider>
  )
}

export function useAppState() {
  const value = useContext(AppStateContext)
  if (!value) throw new Error('useAppState must be used within AppStateProvider')
  return value
}
