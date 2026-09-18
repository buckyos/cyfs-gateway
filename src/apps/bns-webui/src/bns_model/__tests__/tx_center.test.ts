/**
 * 交易中心：两阶段状态机、轮询节奏、投影收敛判定、本地恢复。
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { DEFAULT_TX_POLLING } from '../config'
import { TxController } from '../controllers/tx_controller'
import { TxModel, describeProgress, isSettled, nextPollDelay, type TxRecord } from '../models/tx_model'
import { ReadRepository } from '../services/read_repository'
import { isConverged } from '../write/write_flow'
import type { ConvergenceExpectation } from '../write/intents'
import {
  FakeBnsServerApi,
  LIVE_NAME_STATE,
  LIVE_RESOLVED,
  LIVE_SYSTEM_INFO,
  fakeClock,
  memoryStore,
  testConfig,
} from './fakes'
import type { PreparedWrite } from '../write/write_flow'
import type { WireTxState } from '../types/wire'

const NAME = LIVE_NAME_STATE.name
const HASH = `0x${'a'.repeat(64)}`

function preparedFor(expectation: ConvergenceExpectation): PreparedWrite {
  return {
    intent: { kind: 'renew_name', name: NAME, duration: 1n, authority: { role: 'none', actor: { kind: 'unset', value: '' }, kid: '' }, guard: { expectedNameSeq: 0n, expectedParentNameSeq: 0n } },
    path: { kind: 'public' },
    request: { from: '0x1', to: '0x2', data: '0x00', value: '0x0' },
    context: { chainId: LIVE_SYSTEM_INFO.chain_id, contractAddress: LIVE_SYSTEM_INFO.contract_address, from: '0x1' },
    guard: { expectedNameSeq: 0n, expectedParentNameSeq: 0n },
    guardRefreshedAt: 0,
    delivery: { mode: 'wallet_direct', readiness: { ready: true, reason: null, hint: null } },
    gasEstimate: 1n,
    simulationError: null,
    staleGuard: false,
    expectation,
    summary: {
      method: 'renewName',
      label: '续期名称',
      target: NAME,
      chainId: LIVE_SYSTEM_INFO.chain_id,
      contractAddress: LIVE_SYSTEM_INFO.contract_address,
      value: '0x0',
      authority: 'public',
      guard: { expectedNameSeq: '0', expectedParentNameSeq: '0' },
      highRisk: false,
      deliveryMode: 'wallet_direct',
    },
  }
}

describe('轮询节奏（PRD 8.5.6）', () => {
  it('前 30 秒每 2 秒', () => {
    expect(nextPollDelay(DEFAULT_TX_POLLING, 0)).toBe(2_000)
    expect(nextPollDelay(DEFAULT_TX_POLLING, 29_999)).toBe(2_000)
  })

  it('30 秒到 5 分钟每 5 秒', () => {
    expect(nextPollDelay(DEFAULT_TX_POLLING, 30_000)).toBe(5_000)
    expect(nextPollDelay(DEFAULT_TX_POLLING, 299_999)).toBe(5_000)
  })

  it('之后降到 15 秒', () => {
    expect(nextPollDelay(DEFAULT_TX_POLLING, 300_000)).toBe(15_000)
    expect(nextPollDelay(DEFAULT_TX_POLLING, 3_600_000)).toBe(15_000)
  })
})

describe('状态呈现', () => {
  const base: TxRecord = {
    id: 'x', txHash: HASH, intentKind: 'renew_name', method: 'renewName', label: '续期',
    target: NAME, chainId: 1, contractAddress: '0x0', from: '0x0', submittedAt: 0,
    deliveryMode: 'wallet_direct', stage: 'submitted', blockNumber: null, confirmations: 0n, expectation: { kind: 'none' },
    chainSucceededAt: null, convergedAt: null, lastPolledAt: null, stopped: false,
    error: null, simulationError: null,
  }

  it('not_found 不是失败', () => {
    const progress = describeProgress({ ...base, stage: 'not_found' }, 0, DEFAULT_TX_POLLING)
    expect(progress.chain).toBe('unknown')
    expect(progress.settled).toBe(false)
    expect(progress.tone).not.toBe('danger')
    expect(progress.headline).toMatch(/可能被替换|尚未广播/)
  })

  it('链上成功但投影未收敛 -> Indexing，不是 Completed', () => {
    const progress = describeProgress(
      { ...base, stage: 'indexing', chainSucceededAt: 0 },
      10_000,
      DEFAULT_TX_POLLING,
    )
    expect(progress.chain).toBe('done')
    expect(progress.projection).toBe('indexing')
    expect(progress.settled).toBe(false)
  })

  it('超过 5 分钟未收敛 -> “Indexer 尚未同步”，仍不是失败', () => {
    const progress = describeProgress(
      { ...base, stage: 'indexing', chainSucceededAt: 0 },
      DEFAULT_TX_POLLING.indexerTimeoutMs + 1,
      DEFAULT_TX_POLLING,
    )
    expect(progress.projection).toBe('lagging')
    expect(progress.headline).toMatch(/Indexer 尚未同步/)
    expect(progress.tone).toBe('warning')
  })

  it('两阶段都完成才是 completed', () => {
    const progress = describeProgress({ ...base, stage: 'completed' }, 0, DEFAULT_TX_POLLING)
    expect(progress).toMatchObject({ chain: 'done', projection: 'done', settled: true, tone: 'success' })
  })

  it('revert 才是失败', () => {
    expect(describeProgress({ ...base, stage: 'chain_reverted' }, 0, DEFAULT_TX_POLLING).tone).toBe('danger')
  })

  it('用户取消签名是终态但不是失败', () => {
    const progress = describeProgress({ ...base, stage: 'wallet_rejected' }, 0, DEFAULT_TX_POLLING)
    expect(progress.settled).toBe(true)
    expect(progress.tone).toBe('neutral')
  })

  it('终态判定', () => {
    expect(['completed', 'chain_reverted', 'wallet_rejected'].every(isSettled as never)).toBe(true)
    expect(['pending', 'indexing', 'not_found', 'submitted'].some(isSettled as never)).toBe(false)
  })
})

describe('投影收敛判定', () => {
  function repo(api = new FakeBnsServerApi()) {
    return new ReadRepository(api.asApi(), testConfig(), fakeClock())
  }

  it('name_exists', async () => {
    await expect(isConverged({ kind: 'name_exists', name: NAME }, repo())).resolves.toBe(true)
    await expect(isConverged({ kind: 'name_exists', name: 'nope' }, repo())).resolves.toBe(false)
  })

  it('name_seq_at_least', async () => {
    const current = BigInt(LIVE_NAME_STATE.name_seq)
    await expect(isConverged({ kind: 'name_seq_at_least', name: NAME, value: current }, repo())).resolves.toBe(true)
    await expect(
      isConverged({ kind: 'name_seq_at_least', name: NAME, value: current + 1n }, repo()),
    ).resolves.toBe(false)
  })

  it('expire_at_greater_than', async () => {
    const current = BigInt(LIVE_NAME_STATE.expire_at)
    await expect(
      isConverged({ kind: 'expire_at_greater_than', name: NAME, value: current - 1n }, repo()),
    ).resolves.toBe(true)
    await expect(
      isConverged({ kind: 'expire_at_greater_than', name: NAME, value: current }, repo()),
    ).resolves.toBe(false)
  })

  it('document_version_at_least', async () => {
    const docType = LIVE_RESOLVED.document_state.doc_type
    const current = BigInt(LIVE_RESOLVED.document_state.version)
    await expect(
      isConverged({ kind: 'document_version_at_least', name: NAME, docType, value: current }, repo()),
    ).resolves.toBe(true)
    await expect(
      isConverged({ kind: 'document_version_at_least', name: NAME, docType, value: current + 1n }, repo()),
    ).resolves.toBe(false)
  })

  it('none 直接算收敛', async () => {
    await expect(isConverged({ kind: 'none' }, repo())).resolves.toBe(true)
  })
})

describe('TxController 轮询', () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  function setup(states: WireTxState[], expectation: ConvergenceExpectation = { kind: 'none' }) {
    let index = 0
    const api = new FakeBnsServerApi()
    api.queryTxState = async () => {
      const state = states[Math.min(index, states.length - 1)]
      index += 1
      return state
    }
    const config = testConfig()
    const repo = new ReadRepository(api.asApi(), config, fakeClock())
    const model = new TxModel(memoryStore(), 'test.tx')
    const converged: TxRecord[] = []
    const controller = new TxController(model, repo, config, {
      onConverged: (record) => converged.push(record),
    })
    const record = controller.track(preparedFor(expectation), HASH)
    return { controller, model, record, converged }
  }

  const pending: WireTxState = { tx_hash: HASH, state: 'pending', block_number: null, confirmations: 0 }
  const succeeded: WireTxState = { tx_hash: HASH, state: 'succeeded', block_number: 100, confirmations: 3 }
  const reverted: WireTxState = { tx_hash: HASH, state: 'reverted', block_number: 100, confirmations: 1 }
  const notFound: WireTxState = { tx_hash: HASH, state: 'not_found', block_number: null, confirmations: 0 }

  it('pending -> 继续轮询，不是终态', async () => {
    const { model, controller } = setup([pending])
    await vi.advanceTimersByTimeAsync(1)
    expect(model.records[0].stage).toBe('pending')
    expect(model.pollable()).toHaveLength(1)
    controller.dispose()
  })

  it('succeeded 且期望满足 -> completed，并触发 onConverged', async () => {
    const { model, converged, controller } = setup([succeeded], { kind: 'name_exists', name: NAME })
    await vi.advanceTimersByTimeAsync(1)
    expect(model.records[0].stage).toBe('completed')
    expect(model.records[0].blockNumber).toBe(100n)
    expect(model.records[0].confirmations).toBe(3n)
    expect(converged).toHaveLength(1)
    controller.dispose()
  })

  it('succeeded 但期望未满足 -> indexing，继续轮询', async () => {
    const { model, controller } = setup([succeeded], { kind: 'name_exists', name: 'not-registered' })
    await vi.advanceTimersByTimeAsync(1)
    expect(model.records[0].stage).toBe('indexing')
    expect(model.records[0].chainSucceededAt).not.toBeNull()
    expect(isSettled(model.records[0].stage)).toBe(false)
    controller.dispose()
  })

  it('投影迟迟不收敛 -> indexer_lagging，仍然不是失败', async () => {
    const { model, controller } = setup([succeeded], { kind: 'name_exists', name: 'not-registered' })
    await vi.advanceTimersByTimeAsync(1)
    await vi.advanceTimersByTimeAsync(DEFAULT_TX_POLLING.indexerTimeoutMs + 20_000)
    expect(model.records[0].stage).toBe('indexer_lagging')
    expect(isSettled(model.records[0].stage)).toBe(false)
    controller.dispose()
  })

  it('reverted -> 终态，停止轮询', async () => {
    const { model, controller } = setup([reverted])
    await vi.advanceTimersByTimeAsync(1)
    expect(model.records[0].stage).toBe('chain_reverted')
    expect(model.pollable()).toHaveLength(0)
    controller.dispose()
  })

  it('not_found 不停止轮询', async () => {
    const { model, controller } = setup([notFound])
    await vi.advanceTimersByTimeAsync(1)
    expect(model.records[0].stage).toBe('not_found')
    expect(model.pollable()).toHaveLength(1)
    controller.dispose()
  })

  it('pending -> succeeded -> completed 的完整链路', async () => {
    const { model, controller } = setup([pending, succeeded], { kind: 'name_exists', name: NAME })
    await vi.advanceTimersByTimeAsync(1)
    expect(model.records[0].stage).toBe('pending')
    await vi.advanceTimersByTimeAsync(2_100)
    expect(model.records[0].stage).toBe('completed')
    controller.dispose()
  })

  it('用户停止后不再轮询，resume 可恢复', async () => {
    const { model, controller, record } = setup([pending])
    await vi.advanceTimersByTimeAsync(1)
    controller.stop(record.id)
    expect(model.records[0].stopped).toBe(true)
    expect(model.pollable()).toHaveLength(0)
    controller.resume(record.id)
    expect(model.pollable()).toHaveLength(1)
    controller.dispose()
  })

  it('查询失败只记错，不改变交易结论', async () => {
    const api = new FakeBnsServerApi()
    api.queryTxState = async () => {
      throw new Error('bns-server down')
    }
    const config = testConfig()
    const repo = new ReadRepository(api.asApi(), config, fakeClock())
    const model = new TxModel(memoryStore(), 'test.tx')
    const controller = new TxController(model, repo, config)
    controller.track(preparedFor({ kind: 'none' }), HASH)
    await vi.advanceTimersByTimeAsync(1)
    expect(model.records[0].stage).toBe('submitted')
    expect(model.records[0].error?.message).toMatch(/down/)
    controller.dispose()
  })

  it('用户拒绝签名记录为 wallet_rejected 且不轮询', () => {
    const config = testConfig()
    const repo = new ReadRepository(new FakeBnsServerApi().asApi(), config, fakeClock())
    const model = new TxModel(memoryStore(), 'test.tx')
    const controller = new TxController(model, repo, config)
    controller.trackRejected(preparedFor({ kind: 'none' }), 'User rejected')
    expect(model.records[0].stage).toBe('wallet_rejected')
    expect(model.records[0].txHash).toBeNull()
    expect(model.pollable()).toHaveLength(0)
    controller.dispose()
  })
})

describe('本地恢复', () => {
  it('bigint 字段能安全穿过 localStorage', () => {
    const storage = memoryStore()
    const model = new TxModel(storage, 'test.tx')
    model.add({
      id: 'a', txHash: HASH, intentKind: 'publish_document', method: 'publishDocument', label: '发布',
      target: NAME, chainId: 31337, contractAddress: '0x0', from: '0x0', submittedAt: 1,
      deliveryMode: 'wallet_direct', stage: 'indexing', blockNumber: 18492120n, confirmations: 5n,
      expectation: { kind: 'document_version_at_least', name: NAME, docType: 'owner', value: 8n },
      chainSucceededAt: 2, convergedAt: null, lastPolledAt: 3, stopped: false, error: null, simulationError: null,
    })

    const restored = new TxModel(storage, 'test.tx')
    restored.restore()
    const record = restored.records[0]
    expect(record.blockNumber).toBe(18492120n)
    expect(record.confirmations).toBe(5n)
    expect(record.expectation).toEqual({
      kind: 'document_version_at_least', name: NAME, docType: 'owner', value: 8n,
    })
  })

  it('本地数据损坏时静默降级，不影响使用', () => {
    const storage = memoryStore()
    storage.set('test.tx', '{ not json')
    const model = new TxModel(storage, 'test.tx')
    expect(() => model.restore()).not.toThrow()
    expect(model.records).toEqual([])
  })

  it('clearSettled 只清终态', () => {
    const model = new TxModel(memoryStore(), 'test.tx')
    const base = {
      txHash: HASH, intentKind: 'renew_name' as const, method: 'renewName', label: '续期',
      target: NAME, chainId: 1, contractAddress: '0x0', from: '0x0', submittedAt: 1,
      deliveryMode: 'wallet_direct' as const, blockNumber: null, confirmations: 0n, expectation: { kind: 'none' as const },
      chainSucceededAt: null, convergedAt: null, lastPolledAt: null, stopped: false,
      error: null, simulationError: null,
    }
    model.add({ ...base, id: '1', stage: 'completed' })
    model.add({ ...base, id: '2', stage: 'indexing' })
    model.clearSettled()
    expect(model.records.map((r) => r.id)).toEqual(['2'])
  })
})
