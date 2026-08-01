/**
 * 读仓库：bns-server 的唯一读入口给 Model 层用的形态。
 *
 * 职责：
 * 1. wire -> domain 映射（含 u64 安全层）；
 * 2. 「缺失态」翻译：NAME_NOT_FOUND / DOCUMENT_NOT_FOUND 是业务状态而不是故障，
 *    统一转成 `null` / `status: 'missing'`，其他错误照常抛；
 * 3. 同 key 并发合并 + 短 TTL 缓存（名称详情 8 个 tab 会重复请求同一份状态）；
 * 4. 服务端缺失能力的补齐：事件日志尾部定位、按名称过滤活动记录、文档历史链。
 *
 * 明确不做：不持有 UI 状态、不做写操作、不做轮询调度。
 */

import type { BnsModelConfig } from '../config'
import { RequestDeduper } from '../infra/observable'
import { BNS_ERROR_CODE, BnsError } from '../types/errors'
import type {
  AuthorityKeyView,
  AuthoritySetState,
  DocumentState,
  DocumentView,
  EventRecord,
  LogCheckpoint,
  NameOverview,
  NamePage,
  OwnerResolution,
  ResolveResult,
  SystemInfo,
  TxState,
} from '../types/domain'
import type { BnsServerApi } from './bns_server_api'
import {
  decodeInlineDocument,
  deriveDocumentStatus,
  mapAuthorityKey,
  mapAuthoritySet,
  mapCheckpoint,
  mapDocumentState,
  mapEventRecord,
  mapNameOverview,
  mapNamePage,
  mapOwnerResolution,
  mapResolveResult,
  mapSystemInfo,
  mapTxState,
  toAuthorityKeyView,
} from './mapper'

export interface NowProvider {
  /** 毫秒时间戳，用于缓存新鲜度。 */
  now(): number
  /** Unix 秒，用于所有链上时间字段的派生计算。 */
  nowSeconds(): bigint
}

export const systemClock: NowProvider = {
  now: () => Date.now(),
  nowSeconds: () => BigInt(Math.floor(Date.now() / 1000)),
}

interface CacheEntry {
  value: unknown
  at: number
}

export interface ActivityScan {
  records: EventRecord[]
  /** 是否已经扫到 seq=0，即结果是完整的。 */
  scanExhausted: boolean
  /** 实际扫描到的最小 seq，供“继续加载”使用。 */
  scannedDownToSeq: bigint | null
}

export class ReadRepository {
  private readonly cache = new Map<string, CacheEntry>()
  private readonly deduper = new RequestDeduper()

  constructor(
    private readonly api: BnsServerApi,
    private readonly config: BnsModelConfig,
    private readonly clock: NowProvider = systemClock,
  ) {}

  // -------------------------------------------------------------------------
  // 缓存控制
  // -------------------------------------------------------------------------

  invalidate(prefix?: string): void {
    if (!prefix) {
      this.cache.clear()
      return
    }
    for (const key of [...this.cache.keys()]) {
      if (key.startsWith(prefix)) this.cache.delete(key)
    }
  }

  /** 写操作确认后，把该名称相关的一切读缓存作废。 */
  invalidateName(name: string): void {
    this.invalidate(`name:${name}`)
    this.invalidate(`doc:${name}`)
    this.invalidate(`owner:${name}`)
    this.invalidate(`authority:${name}`)
  }

  private async cached<T>(key: string, factory: () => Promise<T>, ttlMs?: number): Promise<T> {
    const ttl = ttlMs ?? this.config.readCacheTtlMs
    const now = this.clock.now()
    if (ttl > 0) {
      const entry = this.cache.get(key)
      if (entry && now - entry.at <= ttl) return entry.value as T
    }
    return this.deduper.run(key, async () => {
      const value = await factory()
      if (ttl > 0) this.cache.set(key, { value, at: this.clock.now() })
      return value
    })
  }

  // -------------------------------------------------------------------------
  // 系统
  // -------------------------------------------------------------------------

  health(): Promise<boolean> {
    return this.api.health()
  }

  async systemInfo(): Promise<SystemInfo> {
    return this.cached('system:info', async () => mapSystemInfo(await this.api.systemInfo()))
  }

  // -------------------------------------------------------------------------
  // 名称
  // -------------------------------------------------------------------------

  /** 名称未注册 / 投影未发现时返回 null，而不是抛错。 */
  async nameOverview(name: string): Promise<NameOverview | null> {
    return this.cached(`name:${name}:state`, async () => {
      const wire = await this.api.queryNameState(name)
      if (wire === null) return null
      return mapNameOverview(wire, this.clock.nowSeconds())
    })
  }

  /** NAME_NOT_FOUND 翻译成 null，其余错误照抛。 */
  async ownerResolution(name: string): Promise<OwnerResolution | null> {
    return this.cached(`owner:${name}`, async () => {
      try {
        return mapOwnerResolution(await this.api.resolveOwner(name))
      } catch (error) {
        if (error instanceof BnsError && error.isNameNotFound) return null
        throw error
      }
    })
  }

  async authoritySet(name: string): Promise<AuthoritySetState> {
    return this.cached(`authority:${name}:set`, async () =>
      mapAuthoritySet(await this.api.getAuthoritySet(name)),
    )
  }

  /**
   * 按 kid 探测单个 authority key。
   *
   * bns-server 没有「列出全部 key」的接口，所以调用方必须自己维护候选 kid 列表
   * （来自 authority_keys_updated 事件 / 用户输入 / 本次注册表单）。
   */
  async authorityKey(name: string, kid: string): Promise<AuthorityKeyView | null> {
    return this.cached(`authority:${name}:key:${kid}`, async () => {
      const wire = await this.api.getAuthorityKey(name, kid)
      if (wire === null) return null
      return toAuthorityKeyView(mapAuthorityKey(wire), this.clock.nowSeconds())
    })
  }

  async namesByAddress(address: string, cursor: string | null, limit?: number): Promise<NamePage> {
    const size = limit ?? this.config.namesPageSize
    const key = `addr:${address.toLowerCase()}:${cursor ?? ''}:${size}`
    return this.cached(key, async () =>
      mapNamePage(await this.api.queryNamesByAddress(address, cursor, size)),
    )
  }

  // -------------------------------------------------------------------------
  // 文档
  // -------------------------------------------------------------------------

  /** 原始 resolve 结果，写前预检需要 name_seq / 当前版本 / controller。 */
  async resolveDocumentRaw(name: string, docType: string): Promise<ResolveResult | null> {
    return this.cached(`doc:${name}:${docType}:raw`, async () => {
      try {
        return mapResolveResult(await this.api.resolveDocument(name, docType))
      } catch (error) {
        if (error instanceof BnsError && (error.isDocumentNotFound || error.isNameNotFound)) {
          return null
        }
        throw error
      }
    })
  }

  /** 视图形态：从未发布过时返回 status='missing' 的空视图，而不是 null。 */
  async documentView(name: string, docType: string): Promise<DocumentView> {
    const result = await this.resolveDocumentRaw(name, docType)
    if (result === null) {
      return {
        name,
        docType,
        state: null,
        rawStatus: 'missing',
        derivedStatus: 'missing',
        aliasKind: 'none',
        aliasTargetDid: '',
        isInline: false,
        inlineText: null,
        inlineJson: null,
        inlineByteLength: 0,
        effectiveController: { kind: 'unset', value: '' },
      }
    }
    const inline = decodeInlineDocument(result.documentState.document)
    return {
      name,
      docType,
      state: result.documentState,
      rawStatus: result.status,
      derivedStatus: deriveDocumentStatus(result, this.clock.nowSeconds()),
      aliasKind: result.aliasKind,
      aliasTargetDid: result.aliasTargetDid,
      isInline: inline.isInline,
      inlineText: inline.text,
      inlineJson: inline.json,
      inlineByteLength: inline.byteLength,
      effectiveController: result.effectiveController,
    }
  }

  async documentVersion(name: string, docType: string, version: bigint): Promise<DocumentState | null> {
    return this.cached(`doc:${name}:${docType}:v${version}`, async () => {
      const wire = await this.api.getDocumentVersion(name, docType, version)
      return wire === null ? null : mapDocumentState(wire)
    })
  }

  /**
   * 文档历史：沿 `previous_version` 链回溯。
   * 用链而不是 `version-1` 遍历，因为撤销也会产生新版本，版本号未必连续可用。
   */
  async documentHistory(name: string, docType: string, maxVersions = 20): Promise<DocumentState[]> {
    const current = await this.resolveDocumentRaw(name, docType)
    if (current === null) return []
    const history: DocumentState[] = [current.documentState]
    let previous = current.documentState.previousVersion
    while (previous !== 0n && history.length < maxVersions) {
      const state = await this.documentVersion(name, docType, previous)
      if (state === null) break
      history.push(state)
      if (state.previousVersion === previous) break // 防御环
      previous = state.previousVersion
    }
    return history
  }

  // -------------------------------------------------------------------------
  // 交易
  // -------------------------------------------------------------------------

  /** 交易状态永远不缓存：它是轮询的目标。 */
  async txState(txHash: string): Promise<TxState> {
    return mapTxState(await this.api.queryTxState(txHash))
  }

  // -------------------------------------------------------------------------
  // 事件
  // -------------------------------------------------------------------------

  async latestCheckpoint(): Promise<LogCheckpoint | null> {
    return this.cached('checkpoint:latest', async () => {
      const wire = await this.api.latestCheckpoint()
      return wire === null ? null : mapCheckpoint(wire)
    })
  }

  async events(fromSeq: bigint, limit?: number): Promise<EventRecord[]> {
    const size = limit ?? this.config.eventsPageSize
    const wire = await this.api.listEvents(fromSeq, size)
    return wire.map(mapEventRecord)
  }

  /**
   * 定位事件日志的最大 seq。
   *
   * `events.list` 只能从 `from_seq` 向后读，服务端没有「最新 N 条」接口，
   * 所以要拿到最新事件必须先找到尾部。`exists(seq) = 存在 seq' >= seq 的事件`
   * 关于 seq 单调递减，可以指数探测 + 二分，代价 O(log n) 次请求。
   * `checkpoint.latest` 只作为下界加速，不能当成尾部（checkpoint 之后还会有新事件）。
   */
  async latestEventSeq(): Promise<bigint | null> {
    return this.cached(
      'events:tail',
      async () => {
        const exists = async (seq: bigint) => (await this.api.listEvents(seq, 1)).length > 0
        if (!(await exists(0n))) return null

        const checkpoint = await this.latestCheckpoint().catch(() => null)
        let low = checkpoint && (await exists(checkpoint.lastSeq)) ? checkpoint.lastSeq : 0n
        let high = low === 0n ? 1n : low * 2n

        let guard = 0
        while ((await exists(high)) && guard < 64) {
          low = high
          high *= 2n
          guard += 1
        }
        // 不变式：exists(low) === true，exists(high) === false
        while (high - low > 1n) {
          const mid = low + (high - low) / 2n
          if (await exists(mid)) low = mid
          else high = mid
        }
        return low
      },
      Math.max(this.config.readCacheTtlMs, 2_000),
    )
  }

  /** 最新 N 条事件（倒序）。 */
  async latestEvents(limit?: number): Promise<EventRecord[]> {
    const size = limit ?? this.config.eventsPageSize
    const tail = await this.latestEventSeq()
    if (tail === null) return []
    const from = tail + 1n > BigInt(size) ? tail + 1n - BigInt(size) : 0n
    const page = await this.events(from, size)
    return page.reverse()
  }

  /**
   * 某个名称的活动记录。
   *
   * bns-server 的 `events.list` 不支持按名称过滤，只能客户端回扫。
   * 因此结果**天然可能不完整**，`scanExhausted` 必须透传给视图，
   * 由 UI 显示“仅扫描了最近 N 条事件”，不能假装是全量历史。
   */
  async activityForName(name: string, options: { fromSeq?: bigint; maxPages?: number } = {}): Promise<ActivityScan> {
    const maxPages = options.maxPages ?? this.config.activityScanPages
    const pageSize = this.config.eventsPageSize
    const start = options.fromSeq ?? (await this.latestEventSeq())
    if (start === null) {
      return { records: [], scanExhausted: true, scannedDownToSeq: null }
    }

    let cursor: bigint = start
    const records: EventRecord[] = []
    let pages = 0
    let reachedBottom = false
    while (pages < maxPages && cursor >= 0n) {
      const span = BigInt(pageSize)
      const from: bigint = cursor + 1n > span ? cursor + 1n - span : 0n
      // 窗口是闭区间 [from, cursor]。limit 必须按窗口实际大小算，
      // 否则最后一页会读回上一页已经扫过的 seq，产生重复记录。
      const page = await this.events(from, Number(cursor - from + 1n))
      for (const record of page) {
        if (record.seq <= cursor && record.name === name) records.push(record)
      }
      pages += 1
      if (from === 0n) {
        reachedBottom = true
        break
      }
      cursor = from - 1n
    }

    records.sort((a, b) => (a.seq === b.seq ? 0 : a.seq > b.seq ? -1 : 1))
    return {
      records,
      scanExhausted: reachedBottom,
      scannedDownToSeq: reachedBottom ? 0n : cursor,
    }
  }

  /**
   * 从事件日志里收集某个名称出现过的 authority kid。
   * 事件只携带 authority_seq / authority_root，**不含 kid**，
   * 所以这里返回空数组是正常的 —— 它只是为将来事件补齐字段预留的入口。
   */
  async discoverAuthorityKids(_name: string): Promise<string[]> {
    return []
  }
}

export function isMissingStateError(error: unknown): boolean {
  return (
    error instanceof BnsError &&
    (error.code === BNS_ERROR_CODE.NAME_NOT_FOUND || error.code === BNS_ERROR_CODE.DOCUMENT_NOT_FOUND)
  )
}
