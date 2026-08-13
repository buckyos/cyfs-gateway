/**
 * ReadRepository：缺失态翻译、缓存/去重，以及服务端缺失能力的补齐。
 */

import { describe, expect, it } from 'vitest'

import { ReadRepository } from '../services/read_repository'
import { BnsError } from '../types/errors'
import {
  FakeBnsServerApi,
  LIVE_NAME_STATE,
  LIVE_RESOLVED,
  fakeClock,
  syntheticEvents,
  testConfig,
} from './fakes'
import type { WireDocumentState } from '../types/wire'

const NAME = LIVE_NAME_STATE.name

function repoWith(api: FakeBnsServerApi, config = testConfig()) {
  return new ReadRepository(api.asApi(), config, fakeClock())
}

describe('缺失态翻译', () => {
  it('名称不存在 -> null，而不是抛错', async () => {
    const repo = repoWith(new FakeBnsServerApi())
    await expect(repo.nameOverview('nope')).resolves.toBeNull()
  })

  it('NAME_NOT_FOUND 的 resolve_owner -> null', async () => {
    const repo = repoWith(new FakeBnsServerApi())
    await expect(repo.ownerResolution('nope')).resolves.toBeNull()
  })

  it('DOCUMENT_NOT_FOUND -> status=missing 的空视图', async () => {
    const repo = repoWith(new FakeBnsServerApi())
    const view = await repo.documentView(NAME, 'nonexistent')
    expect(view.state).toBeNull()
    expect(view.rawStatus).toBe('missing')
    expect(view.derivedStatus).toBe('missing')
    expect(view.isInline).toBe(false)
  })

  it('其他错误照常抛出，不会被当成缺失态吞掉', async () => {
    const api = new FakeBnsServerApi({
      systemInfo: () => {
        throw BnsError.transport('RPC_TRANSPORT_ERROR', 'upstream down')
      },
    })
    await expect(repoWith(api).systemInfo()).rejects.toThrowError(/upstream down/)
  })

  it('已发布的文档返回完整视图', async () => {
    const repo = repoWith(new FakeBnsServerApi())
    const view = await repo.documentView(NAME, LIVE_RESOLVED.document_state.doc_type)
    expect(view.state?.version).toBe(BigInt(LIVE_RESOLVED.document_state.version))
    expect(view.isInline).toBe(true)
    expect(view.inlineJson).toMatchObject({ name: NAME })
  })
})

describe('缓存与并发合并', () => {
  it('并发请求同一个名称只打一次服务端', async () => {
    const api = new FakeBnsServerApi()
    const repo = repoWith(api, testConfig({ readCacheTtlMs: 5_000 }))
    await Promise.all([repo.nameOverview(NAME), repo.nameOverview(NAME), repo.nameOverview(NAME)])
    expect(api.calls.queryNameState).toBe(1)
  })

  it('TTL 内命中缓存', async () => {
    const api = new FakeBnsServerApi()
    const repo = repoWith(api, testConfig({ readCacheTtlMs: 5_000 }))
    await repo.nameOverview(NAME)
    await repo.nameOverview(NAME)
    expect(api.calls.queryNameState).toBe(1)
  })

  it('invalidateName 之后重新读取', async () => {
    const api = new FakeBnsServerApi()
    const repo = repoWith(api, testConfig({ readCacheTtlMs: 5_000 }))
    await repo.nameOverview(NAME)
    repo.invalidateName(NAME)
    await repo.nameOverview(NAME)
    expect(api.calls.queryNameState).toBe(2)
  })

  it('交易状态永不缓存（它是轮询目标）', async () => {
    const api = new FakeBnsServerApi()
    const repo = repoWith(api, testConfig({ readCacheTtlMs: 60_000 }))
    const hash = `0x${'1'.repeat(64)}`
    await repo.txState(hash)
    await repo.txState(hash)
    expect(api.calls.queryTxState).toBe(2)
  })
})

describe('事件日志尾部定位', () => {
  it('空日志返回 null', async () => {
    const repo = repoWith(new FakeBnsServerApi({ events: [] }))
    await expect(repo.latestEventSeq()).resolves.toBeNull()
  })

  it('准确找到最大 seq', async () => {
    for (const count of [1, 2, 7, 137, 1000]) {
      const repo = repoWith(new FakeBnsServerApi({ events: syntheticEvents(count) }))
      expect(await repo.latestEventSeq(), `count=${count}`).toBe(BigInt(count))
    }
  })

  it('请求次数是 O(log n) 而不是 O(n)', async () => {
    const api = new FakeBnsServerApi({ events: syntheticEvents(1000) })
    const repo = repoWith(api)
    await repo.latestEventSeq()
    // 指数探测 + 二分：1000 条日志远不该产生上百次请求。
    expect(api.calls.listEvents).toBeLessThan(30)
  })

  it('checkpoint 只作为下界加速，不当成尾部', async () => {
    const api = new FakeBnsServerApi({
      events: syntheticEvents(50),
      checkpoint: {
        log_root: `0x${'0'.repeat(64)}`,
        last_seq: 10,
        issued_at: 1,
        issuer: { kind: 'unset', value: '' },
        external_anchor: `0x${'0'.repeat(64)}`,
      },
    })
    // checkpoint 说 10，但日志已经到 50，必须返回 50。
    await expect(repoWith(api).latestEventSeq()).resolves.toBe(50n)
  })

  it('latestEvents 返回倒序的最新一页', async () => {
    const repo = repoWith(
      new FakeBnsServerApi({ events: syntheticEvents(30) }),
      testConfig({ eventsPageSize: 5 }),
    )
    const page = await repo.latestEvents()
    expect(page).toHaveLength(5)
    expect(page[0].seq).toBe(30n)
    expect(page[4].seq).toBe(26n)
  })
})

describe('按名称回扫活动记录', () => {
  it('只保留目标名称的事件', async () => {
    const repo = repoWith(
      new FakeBnsServerApi({ events: syntheticEvents(20, 'alice') }),
      testConfig({ eventsPageSize: 10, activityScanPages: 10 }),
    )
    const scan = await repo.activityForName('alice')
    expect(scan.records.every((r) => r.name === 'alice')).toBe(true)
    expect(scan.records).toHaveLength(10) // 偶数下标是 alice
  })

  it('扫到底时 scanExhausted = true', async () => {
    const repo = repoWith(
      new FakeBnsServerApi({ events: syntheticEvents(20, 'alice') }),
      testConfig({ eventsPageSize: 10, activityScanPages: 10 }),
    )
    expect((await repo.activityForName('alice')).scanExhausted).toBe(true)
  })

  it('页数上限内没扫完时如实报 false，绝不假装是全量', async () => {
    const repo = repoWith(
      new FakeBnsServerApi({ events: syntheticEvents(500, 'alice') }),
      testConfig({ eventsPageSize: 10, activityScanPages: 2 }),
    )
    const scan = await repo.activityForName('alice')
    expect(scan.scanExhausted).toBe(false)
    expect(scan.scannedDownToSeq).not.toBeNull()
  })

  it('结果按 seq 倒序', async () => {
    const repo = repoWith(
      new FakeBnsServerApi({ events: syntheticEvents(20, 'alice') }),
      testConfig({ eventsPageSize: 10, activityScanPages: 10 }),
    )
    const seqs = (await repo.activityForName('alice')).records.map((r) => r.seq)
    expect([...seqs].sort((a, b) => (a > b ? -1 : 1))).toEqual(seqs)
  })

  it('空日志不报错', async () => {
    const repo = repoWith(new FakeBnsServerApi({ events: [] }))
    expect(await repo.activityForName('alice')).toEqual({
      records: [],
      scanExhausted: true,
      scannedDownToSeq: null,
    })
  })
})

describe('文档历史沿 previous_version 回溯', () => {
  const docType = LIVE_RESOLVED.document_state.doc_type

  function versioned(version: number, previous: number): WireDocumentState {
    return { ...LIVE_RESOLVED.document_state, version, previous_version: previous }
  }

  it('从当前版本一路走到 previous_version = 0', async () => {
    const api = new FakeBnsServerApi({
      documents: {
        [`${NAME}:${docType}`]: {
          ...LIVE_RESOLVED,
          document_state: versioned(3, 2),
        },
      },
      documentVersions: {
        [`${NAME}:${docType}:2`]: versioned(2, 1),
        [`${NAME}:${docType}:1`]: versioned(1, 0),
      },
    })
    const history = await repoWith(api).documentHistory(NAME, docType)
    expect(history.map((state) => state.version)).toEqual([3n, 2n, 1n])
  })

  it('遇到自引用时停止，不会死循环', async () => {
    const api = new FakeBnsServerApi({
      documents: { [`${NAME}:${docType}`]: { ...LIVE_RESOLVED, document_state: versioned(2, 1) } },
      documentVersions: { [`${NAME}:${docType}:1`]: versioned(1, 1) },
    })
    const history = await repoWith(api).documentHistory(NAME, docType)
    expect(history.map((state) => state.version)).toEqual([2n, 1n])
  })

  it('从未发布过时返回空数组', async () => {
    await expect(repoWith(new FakeBnsServerApi()).documentHistory(NAME, 'nonexistent')).resolves.toEqual([])
  })
})
