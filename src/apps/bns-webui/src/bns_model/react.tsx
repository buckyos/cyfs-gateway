/**
 * View 层绑定：把 Model 的 Store 接到 React。
 *
 * 只做两件事：注入 BnsModel 实例、把 Store 变成组件状态。
 * 任何业务判断都不应写在这里，也不应写在组件里 —— 那是 Controller / Model 的事。
 */

import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useSyncExternalStore,
  type ReactNode,
} from 'react'

import type { BnsModel } from './index'
import type { ReadonlyStore } from './infra/observable'
import type { NameAggregate } from './models/name_model'
import { emptyAggregate } from './models/name_model'
import type { EventsState } from './models/events_model'
import type { PortfolioState } from './models/portfolio_model'
import type { SessionState } from './models/session_model'
import type { TxCenterState } from './models/tx_model'

const BnsModelContext = createContext<BnsModel | null>(null)

export function BnsModelProvider({
  model,
  autoStart = true,
  children,
}: {
  model: BnsModel
  autoStart?: boolean
  children: ReactNode
}) {
  useEffect(() => {
    if (!autoStart) return
    void model.start()
    return () => model.dispose()
  }, [model, autoStart])

  return <BnsModelContext.Provider value={model}>{children}</BnsModelContext.Provider>
}

export function useBnsModel(): BnsModel {
  const model = useContext(BnsModelContext)
  if (!model) throw new Error('useBnsModel 必须在 BnsModelProvider 内使用')
  return model
}

export function useStore<T>(store: ReadonlyStore<T>): T {
  return useSyncExternalStore(
    (listener) => store.subscribe(listener),
    () => store.get(),
    () => store.get(),
  )
}

export function useSession(): SessionState {
  return useStore(useBnsModel().models.session.store)
}

export function usePortfolio(): PortfolioState {
  return useStore(useBnsModel().models.portfolio.store)
}

export function useTransactions(): TxCenterState {
  return useStore(useBnsModel().models.tx.store)
}

export function useEvents(): EventsState {
  return useStore(useBnsModel().models.events.store)
}

/** 名称聚合：订阅整棵 name 表，再按 name 取片，避免每个 tab 各自请求。 */
export function useNameAggregate(name: string): NameAggregate {
  const all = useStore(useBnsModel().models.name.store)
  return useMemo(() => all[name] ?? emptyAggregate(name), [all, name])
}

/** 进入名称详情页时加载，并在钱包账户变化后重算授权预检。 */
export function useNameDetail(name: string): NameAggregate {
  const model = useBnsModel()
  const aggregate = useNameAggregate(name)
  const session = useSession()

  useEffect(() => {
    void model.controllers.name.load(name)
  }, [model, name])

  useEffect(() => {
    // accountsChanged / chainChanged 之后，旧的授权结论必须作废重算。
    void model.controllers.name.recomputeAuthority(name)
  }, [model, name, session.wallet.address, session.wallet.chainId])

  return aggregate
}

/** 钱包地址变化时自动重载「我持有的名称」。 */
export function usePortfolioSync(): PortfolioState {
  const model = useBnsModel()
  const session = useSession()
  const portfolio = usePortfolio()

  useEffect(() => {
    void model.controllers.registry.loadPortfolio(session.wallet.address)
  }, [model, session.wallet.address])

  return portfolio
}
