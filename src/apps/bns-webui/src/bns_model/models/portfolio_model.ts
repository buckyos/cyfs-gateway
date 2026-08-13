/**
 * 「我持有的名称」Model。
 *
 * 语义边界（PRD 5.2，必须在 UI 上如实呈现）：
 * `name.query_by_addr` 只按 `NameState.asset_owner` 查询，
 * **不包含**通过 BNS authority key、controller rule 或父名称继承可控制的名称。
 * 所以这个列表是「我持有的名称」，不是「我能管理的全部名称」。
 */

import { Store, idleState, type AsyncState } from '../infra/observable'
import type { NameOverview } from '../types/domain'

export interface PortfolioEntry {
  name: string
  overview: AsyncState<NameOverview | null>
}

export interface PortfolioState {
  address: string | null
  /** 已加载的名称，按 canonical 字典序（服务端稳定排序）。 */
  entries: PortfolioEntry[]
  page: AsyncState<string[]>
  nextCursor: string | null
  hasMore: boolean
  /** 供 UI 展示的口径说明，不允许被改写成“我能管理的名称”。 */
  scopeNote: string
}

export const PORTFOLIO_SCOPE_NOTE =
  '按当前钱包地址的 asset_owner 查询；不含通过 authority key、controller 规则或父名称继承可管理的名称。'

const INITIAL: PortfolioState = {
  address: null,
  entries: [],
  page: idleState(),
  nextCursor: null,
  hasMore: false,
  scopeNote: PORTFOLIO_SCOPE_NOTE,
}

export class PortfolioModel {
  readonly store = new Store<PortfolioState>(INITIAL)

  get state(): PortfolioState {
    return this.store.get()
  }

  reset(address: string | null): void {
    this.store.set({ ...INITIAL, address })
  }

  patch(partial: Partial<PortfolioState>): void {
    this.store.set({ ...this.state, ...partial })
  }

  appendNames(names: string[], nextCursor: string | null): void {
    const known = new Set(this.state.entries.map((entry) => entry.name))
    const appended = names
      .filter((name) => !known.has(name))
      .map((name) => ({ name, overview: idleState<NameOverview | null>() }))
    this.patch({
      entries: [...this.state.entries, ...appended],
      nextCursor,
      hasMore: nextCursor !== null,
    })
  }

  patchEntry(name: string, overview: AsyncState<NameOverview | null>): void {
    this.patch({
      entries: this.state.entries.map((entry) =>
        entry.name === name ? { ...entry, overview } : entry,
      ),
    })
  }
}
