/**
 * BnsServerApi：method 名、params 形状、以及“参数校验必须走 rejected promise”的契约。
 */

import { describe, expect, it, vi } from 'vitest'

import { BnsServerApi, RPC_METHOD } from '../services/bns_server_api'
import { KrpcClient } from '../infra/krpc'
import { fixtures } from './fixtures'

function apiWith() {
  const sent: Array<{ method: string; params: Record<string, unknown> }> = []
  const fetchImpl = vi.fn(async (url: string, init?: RequestInit) => {
    if (url.endsWith('/health')) return { ok: true, status: 200 } as Response
    const body = JSON.parse(String(init?.body)) as { method: string; params: Record<string, unknown> }
    sent.push({ method: body.method, params: body.params })
    const envelope = fixtures.krpc[methodToFixture[body.method] ?? 'systemInfo']
    return {
      ok: true,
      status: 200,
      json: async () => envelope,
      text: async () => '',
    } as Response
  })
  const krpc = new KrpcClient({ endpoint: 'http://bns.test/kapi/bns', timeoutMs: 1_000, fetchImpl })
  const api = new BnsServerApi(krpc, 'http://bns.test/health', fetchImpl as unknown as typeof fetch)
  return { api, sent }
}

const methodToFixture: Record<string, string> = {
  [RPC_METHOD.SYSTEM_INFO]: 'systemInfo',
  [RPC_METHOD.QUERY_NAME_STATE]: 'queryNameState',
  [RPC_METHOD.RESOLVE_OWNER]: 'resolveOwner',
  [RPC_METHOD.GET_AUTHORITY_SET]: 'getAuthoritySet',
  [RPC_METHOD.RESOLVE_DOCUMENT]: 'resolveDocument',
  [RPC_METHOD.GET_DOCUMENT_VERSION]: 'getDocumentVersionMissing',
  [RPC_METHOD.QUERY_NAMES_BY_ADDRESS]: 'queryByAddr',
  [RPC_METHOD.QUERY_TX_STATE]: 'queryTxStateNotFound',
  [RPC_METHOD.LIST_EVENTS]: 'listEvents',
  [RPC_METHOD.LATEST_CHECKPOINT]: 'latestCheckpointEmpty',
}

describe('canonical method 名', () => {
  it('全部使用点号形式，不用下划线别名', () => {
    expect(Object.values(RPC_METHOD).every((method) => method.includes('.'))).toBe(true)
    expect(Object.values(RPC_METHOD)).toHaveLength(13)
  })
})

describe('params 形状', () => {
  const NAME = fixtures.name

  it('name.query_state', async () => {
    const { api, sent } = apiWith()
    await api.queryNameState(NAME)
    expect(sent[0]).toEqual({ method: 'name.query_state', params: { name: NAME } })
  })

  it('document.resolve 用 snake_case 的 doc_type', async () => {
    const { api, sent } = apiWith()
    await api.resolveDocument(NAME, 'owner')
    expect(sent[0]).toEqual({ method: 'document.resolve', params: { name: NAME, doc_type: 'owner' } })
  })

  it('document.get_version 把 bigint 版本编回 JSON number', async () => {
    const { api, sent } = apiWith()
    await api.getDocumentVersion(NAME, 'owner', 3n)
    expect(sent[0].params).toEqual({ name: NAME, doc_type: 'owner', version: 3 })
  })

  it('name.query_by_addr 地址归一为小写', async () => {
    const { api, sent } = apiWith()
    await api.queryNamesByAddress('0xB2D3A40E76042A8C4F0ECA5238C6D799C43B1A20', null, 50)
    expect(sent[0].params).toEqual({
      address: '0xb2d3a40e76042a8c4f0eca5238c6d799c43b1a20',
      cursor: null,
      limit: 50,
    })
  })

  it('events.list 的 from_seq 也编回 number', async () => {
    const { api, sent } = apiWith()
    await api.listEvents(100n, 20)
    expect(sent[0].params).toEqual({ from_seq: 100, limit: 20 })
  })

  it('checkpoint.latest 传空对象', async () => {
    const { api, sent } = apiWith()
    await api.latestCheckpoint()
    expect(sent[0].params).toEqual({})
  })
})

describe('参数校验必须是 rejected promise 而不是同步抛出', () => {
  // 同步抛出会让调用方的 .catch() / Promise.all 接不住，
  // 这是一个只在真实调用链里才会暴露的坑。
  const cases: Array<[string, (api: BnsServerApi) => Promise<unknown>]> = [
    ['queryNameState', (api) => api.queryNameState('BadName')],
    ['resolveOwner', (api) => api.resolveOwner('Bad')],
    ['getAuthoritySet', (api) => api.getAuthoritySet('a..b')],
    ['getAuthorityKey', (api) => api.getAuthorityKey('Bad', 'kid')],
    ['resolveDocument (name)', (api) => api.resolveDocument('Bad', 'owner')],
    ['resolveDocument (doc_type)', (api) => api.resolveDocument('alice', 'Owner')],
    ['getDocumentVersion', (api) => api.getDocumentVersion('alice', 'owner', -1n)],
    ['queryNamesByAddress (address)', (api) => api.queryNamesByAddress('0x123', null, 10)],
    ['queryNamesByAddress (limit)', (api) => api.queryNamesByAddress(`0x${'1'.repeat(40)}`, null, 5000)],
    ['queryTxState', (api) => api.queryTxState('0xabc')],
    ['listEvents', (api) => api.listEvents(0n, 0)],
  ]

  for (const [label, invoke] of cases) {
    it(`${label} 返回 rejected promise`, async () => {
      const { api, sent } = apiWith()
      let sync: unknown = null
      let promise: Promise<unknown> | null = null
      try {
        promise = invoke(api)
      } catch (error) {
        sync = error
      }
      expect(sync, '不应同步抛出').toBeNull()
      await expect(promise).rejects.toThrow()
      expect(sent, '校验失败不应发出网络请求').toHaveLength(0)
    })
  }
})

describe('读写边界', () => {
  it('tx.submit_raw 与 tx.prepare 只在 advanced 命名空间暴露', () => {
    const { api } = apiWith()
    expect('submitRawTx' in api).toBe(false)
    expect('prepareTx' in api).toBe(false)
    expect(typeof api.advanced.submitRawTx).toBe('function')
    expect(typeof api.advanced.prepareTx).toBe('function')
  })
})
