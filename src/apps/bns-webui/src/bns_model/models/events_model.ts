/**
 * 事件浏览器 Model。
 *
 * `events.list` 只支持 `seq >= from_seq` 升序 + limit，没有任何过滤条件，
 * 所以「按名称/类型筛选」全部是客户端行为，且只在已加载窗口内生效。
 * 视图必须显示当前扫描区间，不能暗示这是全量检索结果。
 */

import { Store, idleState, type AsyncState } from '../infra/observable'
import type { EventRecord, LogCheckpoint, RegistryEventType } from '../types/domain'

export interface EventFilter {
  name: string | null
  types: RegistryEventType[]
}

export interface EventsState {
  page: AsyncState<EventRecord[]>
  /** 已加载的事件，按 seq 倒序。 */
  records: EventRecord[]
  /** 日志尾部 seq，null 表示还没有任何事件。 */
  tailSeq: bigint | null
  /** 已经向下扫描到的最小 seq。 */
  scannedDownToSeq: bigint | null
  hasMore: boolean
  filter: EventFilter
  checkpoint: AsyncState<LogCheckpoint | null>
}

const INITIAL: EventsState = {
  page: idleState(),
  records: [],
  tailSeq: null,
  scannedDownToSeq: null,
  hasMore: false,
  filter: { name: null, types: [] },
  checkpoint: idleState(),
}

export class EventsModel {
  readonly store = new Store<EventsState>(INITIAL)

  get state(): EventsState {
    return this.store.get()
  }

  reset(): void {
    this.store.set(INITIAL)
  }

  patch(partial: Partial<EventsState>): void {
    this.store.set({ ...this.state, ...partial })
  }

  prependOlder(records: EventRecord[], scannedDownToSeq: bigint | null): void {
    const known = new Set(this.state.records.map((record) => record.seq))
    const merged = [...this.state.records, ...records.filter((record) => !known.has(record.seq))]
    merged.sort((a, b) => (a.seq === b.seq ? 0 : a.seq > b.seq ? -1 : 1))
    this.patch({
      records: merged,
      scannedDownToSeq,
      hasMore: scannedDownToSeq !== null && scannedDownToSeq > 0n,
    })
  }

  setFilter(filter: Partial<EventFilter>): void {
    this.patch({ filter: { ...this.state.filter, ...filter } })
  }

  /** 客户端过滤，只在已加载窗口内生效。 */
  visibleRecords(): EventRecord[] {
    const { name, types } = this.state.filter
    return this.state.records.filter((record) => {
      if (name && record.name !== name) return false
      if (types.length > 0 && !types.includes(record.event.type)) return false
      return true
    })
  }
}

export const EVENT_TYPE_LABELS: Record<RegistryEventType, string> = {
  name_registered: '注册名称',
  name_renewed: '续期',
  name_asset_transferred: '资产转移',
  name_owner_updated: 'Owner 更新',
  authority_keys_updated: 'Authority Keys 更新',
  name_released: '释放 / 停用',
  document_published: '发布文档',
  document_revoked: '撤销文档',
  owner_document_iat_floor_updated: 'Owner IAT Floor',
  controller_policy_updated: 'Controller 策略',
  namespace_policy_updated: 'Namespace 策略',
  did_alias_set: 'DID Alias',
  payment_target_updated: '支付目标',
  log_checkpoint_published: 'Checkpoint',
}
