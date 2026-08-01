/**
 * 事件浏览器 Controller。
 *
 * 服务端只提供「从 seq 向后读」，所以“最新事件”需要先定位日志尾部，
 * 之后向前翻页就是把窗口整体往小 seq 方向挪。
 */

import { errorState, loadingState, readyState } from '../infra/observable'
import type { EventsModel, EventFilter } from '../models/events_model'
import type { ReadRepository } from '../services/read_repository'
import { toBnsError } from '../types/errors'

export class EventsController {
  constructor(
    private readonly model: EventsModel,
    private readonly repo: ReadRepository,
    private readonly pageSize: number,
    private readonly now: () => number = () => Date.now(),
  ) {}

  async loadLatest(): Promise<void> {
    this.model.reset()
    this.model.patch({ page: loadingState() })
    try {
      const tail = await this.repo.latestEventSeq()
      if (tail === null) {
        this.model.patch({ page: readyState([], this.now()), tailSeq: null, hasMore: false })
        return
      }
      const span = BigInt(this.pageSize)
      const from = tail + 1n > span ? tail + 1n - span : 0n
      const page = (await this.repo.events(from, this.pageSize)).reverse()
      this.model.patch({ page: readyState(page, this.now()), tailSeq: tail })
      this.model.prependOlder(page, from === 0n ? 0n : from - 1n)
    } catch (error) {
      this.model.patch({ page: errorState(toBnsError(error), this.now(), this.model.state.page) })
    }
  }

  async loadMore(): Promise<void> {
    const state = this.model.state
    const cursor = state.scannedDownToSeq
    if (cursor === null || cursor <= 0n) return

    this.model.patch({ page: loadingState(state.page) })
    try {
      const span = BigInt(this.pageSize)
      const from = cursor + 1n > span ? cursor + 1n - span : 0n
      const page = (await this.repo.events(from, this.pageSize)).reverse()
      this.model.patch({ page: readyState(page, this.now()) })
      this.model.prependOlder(page, from === 0n ? 0n : from - 1n)
    } catch (error) {
      this.model.patch({ page: errorState(toBnsError(error), this.now(), this.model.state.page) })
    }
  }

  /** 客户端过滤，只影响已加载窗口。 */
  setFilter(filter: Partial<EventFilter>): void {
    this.model.setFilter(filter)
  }

  /** 高级只读：checkpoint 只展示，不提供发布入口（issuer 未与 msg.sender 绑定）。 */
  async loadCheckpoint(): Promise<void> {
    this.model.patch({ checkpoint: loadingState(this.model.state.checkpoint) })
    try {
      this.model.patch({ checkpoint: readyState(await this.repo.latestCheckpoint(), this.now()) })
    } catch (error) {
      this.model.patch({
        checkpoint: errorState(toBnsError(error), this.now(), this.model.state.checkpoint),
      })
    }
  }
}
