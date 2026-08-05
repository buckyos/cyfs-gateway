/**
 * 契约测试：直接打线上 bns-server。
 *
 * 默认跳过；需要显式提供地址：
 *   BNS_LIVE_URL=https://bns.buckyos.ai pnpm run test:live
 *
 * 它验证的是**服务端契约有没有变**（方法名、信封形状、错误码、可空语义、
 * DID Resolver 四种回答），而不是重复单测里的业务逻辑。全部只读，不含任何写操作。
 */

import { describe, expect, it } from 'vitest'

import { createBnsModel } from '../index'
import { BnsError } from '../types/errors'
import { parseBnsName } from '../infra/codec'
import { KrpcClient } from '../infra/krpc'
import { rpcEndpoint, resolveConfig } from '../config'

const LIVE_URL = process.env.BNS_LIVE_URL
const LIVE_NAME = process.env.BNS_LIVE_NAME ?? 'test-iobns-20260715-01'

describe.skipIf(!LIVE_URL)(`线上契约 @ ${LIVE_URL ?? '(未配置)'}`, () => {
  const model = createBnsModel({ serverUrl: LIVE_URL ?? '', readCacheTtlMs: 0 })
  const { api, repo, didResolver } = model

  /**
   * 绕过 BnsServerApi 的本地前置校验，直接发原始 kRPC。
   * 用来验证**服务端**的错误码，而不是我们自己的校验。
   */
  const rawKrpc = new KrpcClient({
    endpoint: rpcEndpoint(resolveConfig({ serverUrl: LIVE_URL ?? '' })),
    timeoutMs: 15_000,
  })

  it('GET /health 可达', async () => {
    await expect(api.health()).resolves.toBe(true)
  })

  it('system.info 返回 ready 与 20 字节合约地址', async () => {
    const info = await repo.systemInfo()
    expect(info.ready).toBe(true)
    expect(Number.isSafeInteger(info.chainId)).toBe(true)
    expect(info.contractAddress).toMatch(/^0x[0-9a-f]{40}$/)
  })

  it('name.query_state 的所有 u64 字段都在安全整数范围内', async () => {
    // u64 安全层会在越界时抛错，这条用例等于把线上数据体检一遍。
    const overview = await repo.nameOverview(LIVE_NAME)
    expect(overview).not.toBeNull()
    expect(overview?.state.name).toBe(LIVE_NAME)
    expect(typeof overview?.state.nameSeq).toBe('bigint')
    expect(overview?.did).toBe(`did:bns:${LIVE_NAME}`)
  })

  it('名称不存在时是 ok:true + result:null，而不是错误', async () => {
    await expect(repo.nameOverview('definitely-not-registered-xyz')).resolves.toBeNull()
  })

  it('name.resolve_owner 对不存在的名称返回 NAME_NOT_FOUND', async () => {
    // 与 query_state 的空值语义不同，这个差异一旦反转会打穿页面的缺失态。
    const error = await api.resolveOwner('definitely-not-registered-xyz').catch((e: unknown) => e)
    expect(error).toBeInstanceOf(BnsError)
    expect((error as BnsError).code).toBe('NAME_NOT_FOUND')
    await expect(repo.ownerResolution('definitely-not-registered-xyz')).resolves.toBeNull()
  })

  it('非法名称：本地校验先拦截，绕过后服务端返回 INVALID_NAME', async () => {
    // 本地先拦，省一次往返。
    expect(() => parseBnsName('BadName')).toThrow()
    await expect(api.queryNameState('BadName')).rejects.toThrowError(/小写/)
    // 绕过本地校验，确认服务端的错误码没变。
    const error = await rawKrpc.callOptional('name.query_state', { name: 'BadName' }).catch((e: unknown) => e)
    expect((error as BnsError).code).toBe('INVALID_NAME')
    expect((error as BnsError).detail.name).toBe('BadName')
  })

  it('authority.get_set 无记录时返回空集合而不是报错', async () => {
    const set = await repo.authoritySet(LIVE_NAME)
    expect(set.name).toBe(LIVE_NAME)
    expect(typeof set.authoritySeq).toBe('bigint')
    expect(set.activeKeyCount).toBeGreaterThanOrEqual(0)
  })

  it('document.resolve 返回 owner 文档，且 content_hash = sha256(inline)', async () => {
    const { sha256Hex } = await import('../infra/codec')
    const view = await repo.documentView(LIVE_NAME, 'owner')
    expect(view.state).not.toBeNull()
    if (view.state?.document.storageType === 'inline') {
      expect(await sha256Hex(view.state.document.inlineDocument)).toBe(view.state.document.contentHash)
    }
  })

  it('未发布的 doc_type 是 missing 视图而不是异常', async () => {
    const view = await repo.documentView(LIVE_NAME, 'nonexistent')
    expect(view.state).toBeNull()
    expect(view.rawStatus).toBe('missing')
  })

  it('document.get_version 对不存在的版本返回 null', async () => {
    await expect(repo.documentVersion(LIVE_NAME, 'owner', 99999n)).resolves.toBeNull()
  })

  it('name.query_by_addr 按 asset_owner 返回名称', async () => {
    const owner = (await repo.nameOverview(LIVE_NAME))?.state.assetOwner
    expect(owner).toBeDefined()
    const page = await repo.namesByAddress(owner!, null, 10)
    expect(page.names).toContain(LIVE_NAME)
  })

  it('分页 limit 越界：本地先拦，服务端也返回 INVALID_LIMIT', async () => {
    const owner = (await repo.nameOverview(LIVE_NAME))!.state.assetOwner
    await expect(api.queryNamesByAddress(owner, null, 5000)).rejects.toThrowError(/1\.\.=1000/)
    const error = await rawKrpc
      .call('name.query_by_addr', { address: owner, cursor: null, limit: 5000 })
      .catch((e: unknown) => e)
    expect((error as BnsError).code).toBe('INVALID_LIMIT')
  })

  it('tx.query_state 对未知 hash 返回 not_found 而不是报错', async () => {
    const state = await repo.txState(`0x${'0'.repeat(63)}1`)
    expect(state.state).toBe('not_found')
    expect(state.blockNumber).toBeNull()
  })

  it('events.list 升序返回，且全部事件类型都能映射', async () => {
    const events = await repo.events(0n, 20)
    expect(events.length).toBeGreaterThan(0)
    for (let i = 1; i < events.length; i += 1) {
      expect(events[i].seq > events[i - 1].seq).toBe(true)
    }
    // 出现未知事件类型时 mapEventRecord 会抛错，这里等于监控服务端新增事件。
    expect(events.every((record) => record.event.type.length > 0)).toBe(true)
  })

  it('日志尾部定位能命中真实最大 seq', async () => {
    const tail = await repo.latestEventSeq()
    expect(tail).not.toBeNull()
    if (tail !== null) {
      expect((await repo.events(tail, 1))).toHaveLength(1)
      expect((await repo.events(tail + 1n, 1))).toHaveLength(0)
    }
  })

  it('checkpoint.latest 允许为 null', async () => {
    await expect(repo.latestCheckpoint()).resolves.toBeDefined()
  })

  it('未知 method 走 kRPC 错误分支而不是业务信封', async () => {
    const error = await rawKrpc.call('no.such_method', {}).catch((e: unknown) => e)
    expect((error as BnsError).kind).toBe('transport')
    expect((error as BnsError).message).toMatch(/Unknown method/)
  })

  it('普通写路径不得走 tx.submit_raw（PRD 4.2），本模块只在 advanced 暴露', () => {
    expect(api.advanced.submitRawTx).toBeTypeOf('function')
    // 这里只断言隔离位置，不会真的提交任何交易。
  })

  it('DID Resolver：200 权威答案', async () => {
    const result = await didResolver.resolve(`did:bns:${LIVE_NAME}`, { docType: 'owner' })
    expect(result.kind).toBe('answer')
    expect(result.documentStatus).toBe('active')
    expect(result.documentVersion).not.toBeNull()
  })

  it('DID Resolver：404 + documentStatus=missing', async () => {
    const result = await didResolver.resolve(`did:bns:${LIVE_NAME}`, { docType: 'nonexistent' })
    expect(result.kind).toBe('answer')
    expect(result.documentStatus).toBe('missing')
  })

  it('DID Resolver：非 did:bns 是 NotApplicable 而不是 Missing', async () => {
    const result = await didResolver.resolve('did:web:example.com')
    expect(result.kind).toBe('not_applicable')
    expect(result.documentStatus).toBeNull()
  })

  it('DID Resolver：iat 历史查询返回能力缺口', async () => {
    const result = await didResolver.resolve(`did:bns:${LIVE_NAME}`, { docType: 'owner', iat: 1n })
    expect(result.kind).toBe('not_implemented')
    expect(result.historicalQuerySupported).toBe(false)
  })
})
