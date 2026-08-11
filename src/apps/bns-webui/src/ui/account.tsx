/**
 * 账号与资产分组（PRD 5.1 / 9.3）。
 *
 * 纯前端视图层约定，数据只来自 `name.query_by_addr`（按 asset_owner 查询）：
 * 1. 账号 = 顶级名称；恰好一个时直接作为当前账号，多个进入切换器；
 * 2. 当前账号的作品 = 二级名称且 parent 属于我的顶级名称集合；
 * 3. 我买来的资产 = 二级名称且 parent 不属于我的任何顶级名称（钱包维度，不随账号切换）。
 *
 * 分组按名称结构推导，不追溯取得方式；账号切换是纯前端状态，不发起链上交易。
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'

import type { PortfolioEntry, PortfolioState } from '../bns_model'
import { usePortfolioSync } from '../bns_model/react'

export interface AccountGroups {
  /** 底层 portfolio 状态（含分页与口径说明）。 */
  portfolio: PortfolioState
  /** 我的账号 = 顶级名称列表。 */
  accounts: PortfolioEntry[]
  /** 当前账号（唯一顶级名称时自动选中）。 */
  currentAccount: string | null
  setCurrentAccount: (name: string) => void
  /** 当前账号名下的作品（随账号切换）。 */
  works: PortfolioEntry[]
  /** 指定账号名下的作品。 */
  worksOf: (account: string) => PortfolioEntry[]
  /** 我买来的资产：parent 不属于我的任何顶级名称（钱包维度）。 */
  acquired: PortfolioEntry[]
}

const AccountContext = createContext<AccountGroups | null>(null)

const STORAGE_KEY = 'bns.webui.currentAccount'

function parentOf(name: string): string | null {
  const index = name.indexOf('.')
  return index === -1 ? null : name.slice(index + 1)
}

export function AccountProvider({ children }: { children: ReactNode }) {
  const portfolio = usePortfolioSync()
  const [selected, setSelected] = useState<string | null>(() => {
    try {
      return window.localStorage.getItem(STORAGE_KEY)
    } catch {
      return null
    }
  })

  const accounts = useMemo(
    () => portfolio.entries.filter((entry) => parentOf(entry.name) === null),
    [portfolio.entries],
  )

  const accountNames = useMemo(() => new Set(accounts.map((entry) => entry.name)), [accounts])

  const currentAccount = useMemo(() => {
    if (accounts.length === 0) return null
    if (selected && accountNames.has(selected)) return selected
    return accounts[0].name
  }, [accounts, accountNames, selected])

  const setCurrentAccount = useCallback((name: string) => {
    setSelected(name)
    try {
      window.localStorage.setItem(STORAGE_KEY, name)
    } catch {
      // 忽略
    }
  }, [])

  // 钱包断开后清理选择。
  useEffect(() => {
    if (portfolio.address === null && selected !== null) setSelected(null)
  }, [portfolio.address, selected])

  const worksOf = useCallback(
    (account: string) =>
      portfolio.entries.filter((entry) => parentOf(entry.name) === account),
    [portfolio.entries],
  )

  const works = useMemo(
    () => (currentAccount ? worksOf(currentAccount) : []),
    [currentAccount, worksOf],
  )

  const acquired = useMemo(
    () =>
      portfolio.entries.filter((entry) => {
        const parent = parentOf(entry.name)
        return parent !== null && !accountNames.has(parent)
      }),
    [portfolio.entries, accountNames],
  )

  const value = useMemo<AccountGroups>(
    () => ({
      portfolio,
      accounts,
      currentAccount,
      setCurrentAccount,
      works,
      worksOf,
      acquired,
    }),
    [portfolio, accounts, currentAccount, setCurrentAccount, works, worksOf, acquired],
  )

  return <AccountContext.Provider value={value}>{children}</AccountContext.Provider>
}

export function useAccounts(): AccountGroups {
  const context = useContext(AccountContext)
  if (!context) throw new Error('useAccounts 必须在 AccountProvider 内使用')
  return context
}

/**
 * 「仅持有」判定（PRD 9.3）：parent 不属于我，且 semantic owner 保持 Unset，
 * effective owner 按继承规则仍在父名称 owner 手里。
 */
export function isHoldOnly(entry: PortfolioEntry): boolean {
  const overview = entry.overview.data
  if (!overview) return false
  const parent = parentOf(entry.name)
  if (parent === null) return false
  return overview.state.ownerSource === 'parent_inherited'
}
