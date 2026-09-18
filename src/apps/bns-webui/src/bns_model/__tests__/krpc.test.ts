/**
 * kRPC 传输层：四类失败必须落到不同分支（PRD 11.3）。
 * 所有响应报文都取自线上 bns-server 的真实回包。
 */

import { describe, expect, it, vi } from 'vitest'

import { KrpcClient } from '../infra/krpc'
import { BNS_ERROR_CODE, BnsError, MODEL_ERROR_CODE } from '../types/errors'
import { fixtures } from './fixtures'

function clientWith(
  responder: (body: unknown) => { status?: number; json?: unknown; text?: string },
  options: { sessionToken?: string | null; timeoutMs?: number } = {},
) {
  const calls: unknown[] = []
  const fetchImpl = vi.fn(async (_url: string, init?: RequestInit) => {
    const body: unknown = JSON.parse(String(init?.body ?? '{}'))
    calls.push(body)
    const result = responder(body)
    return {
      ok: (result.status ?? 200) < 400,
      status: result.status ?? 200,
      json: async () => result.json,
      text: async () => result.text ?? '',
    } as Response
  })
  const client = new KrpcClient({
    endpoint: 'http://bns.test/kapi/bns',
    timeoutMs: options.timeoutMs ?? 5_000,
    sessionToken: options.sessionToken ?? null,
    fetchImpl,
  })
  return { client, calls, fetchImpl }
}

describe('请求格式', () => {
  it('发出 kRPC 报文而不是 JSON-RPC 2.0', async () => {
    const { client, calls } = clientWith(() => ({ json: fixtures.krpc.systemInfo }))
    await client.call('system.info', {})
    expect(calls[0]).toEqual({ method: 'system.info', params: {}, sys: [1] })
    expect(calls[0]).not.toHaveProperty('jsonrpc')
    expect(calls[0]).not.toHaveProperty('id')
  })

  it('seq 自增', async () => {
    const { client, calls } = clientWith(() => ({ json: fixtures.krpc.systemInfo }))
    await client.call('system.info', {})
    await client.call('system.info', {})
    expect((calls[0] as { sys: number[] }).sys[0]).toBe(1)
    expect((calls[1] as { sys: number[] }).sys[0]).toBe(2)
  })

  it('带 session token 时放在 sys[1]', async () => {
    const { client, calls } = clientWith(() => ({ json: fixtures.krpc.systemInfo }), {
      sessionToken: 'tok',
    })
    await client.call('system.info', {})
    expect((calls[0] as { sys: unknown[] }).sys).toEqual([1, 'tok'])
  })
})

describe('四类失败的区分', () => {
  it('1) HTTP 非 2xx -> transport', async () => {
    const { client } = clientWith(() => ({ status: 400, text: 'Failed to parse request body' }))
    const error = await client.call('system.info', {}).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(BnsError)
    expect((error as BnsError).kind).toBe('transport')
    expect((error as BnsError).code).toBe(MODEL_ERROR_CODE.HTTP_ERROR)
    expect((error as BnsError).detail.httpStatus).toBe(400)
  })

  it('2) kRPC UnknownMethod -> transport（服务端仍返回 HTTP 200）', async () => {
    const { client } = clientWith(() => ({ json: fixtures.krpc.unknownMethod }))
    const error = await client.call('no.such_method', {}).catch((e: unknown) => e)
    expect((error as BnsError).kind).toBe('transport')
    expect((error as BnsError).code).toBe(MODEL_ERROR_CODE.KRPC_ERROR)
    expect((error as BnsError).message).toMatch(/Unknown method/)
  })

  it('2) kRPC 参数解析失败也是 transport 而不是业务错误', async () => {
    const { client } = clientWith(() => ({ json: fixtures.krpc.badParams }))
    const error = await client.call('name.query_state', {}).catch((e: unknown) => e)
    expect((error as BnsError).kind).toBe('transport')
    expect((error as BnsError).message).toMatch(/missing field/)
  })

  it('3) 信封 ok:false -> registry，并带上业务上下文', async () => {
    const { client } = clientWith(() => ({ json: fixtures.krpc.resolveDocumentMissing }))
    const error = await client
      .call('document.resolve', { name: 'x', doc_type: 'y' })
      .catch((e: unknown) => e)
    const bns = error as BnsError
    expect(bns.kind).toBe('registry')
    expect(bns.code).toBe(BNS_ERROR_CODE.DOCUMENT_NOT_FOUND)
    expect(bns.isDocumentNotFound).toBe(true)
    expect(bns.detail.name).toBe(fixtures.name)
    expect(bns.detail.docType).toBe('nonexistent')
    expect(bns.detail.method).toBe('document.resolve')
  })

  it('3) INVALID_NAME 携带 name 上下文，供 UI 定位输入框', async () => {
    const { client } = clientWith(() => ({ json: fixtures.krpc.queryNameStateInvalid }))
    const error = await client.call('name.query_state', { name: 'BadName' }).catch((e: unknown) => e)
    expect((error as BnsError).code).toBe(BNS_ERROR_CODE.INVALID_NAME)
    expect((error as BnsError).detail.name).toBe('BadName')
  })

  it('4) ok:true + result:null 是合法空值，不是错误', async () => {
    const { client } = clientWith(() => ({ json: fixtures.krpc.queryNameStateMissing }))
    await expect(client.callOptional('name.query_state', { name: 'nope' })).resolves.toBeNull()
  })

  it('4) 但 call() 对约定非空的接口会报 MISSING_RESULT', async () => {
    const { client } = clientWith(() => ({ json: fixtures.krpc.queryNameStateMissing }))
    const error = await client.call('name.query_state', { name: 'nope' }).catch((e: unknown) => e)
    expect((error as BnsError).code).toBe(MODEL_ERROR_CODE.MISSING_RESULT)
    expect((error as BnsError).kind).toBe('protocol')
  })
})

describe('其他协议边界', () => {
  it('result 不是 BNS 信封 -> protocol', async () => {
    const { client } = clientWith(() => ({ json: { result: 42, sys: [1] } }))
    const error = await client.call('system.info', {}).catch((e: unknown) => e)
    expect((error as BnsError).kind).toBe('protocol')
    expect((error as BnsError).code).toBe(BNS_ERROR_CODE.INVALID_RESPONSE)
  })

  it('网络中断 -> RPC_TRANSPORT_ERROR', async () => {
    const client = new KrpcClient({
      endpoint: 'http://bns.test/kapi/bns',
      timeoutMs: 1_000,
      fetchImpl: async () => {
        throw new Error('ECONNREFUSED')
      },
    })
    const error = await client.call('system.info', {}).catch((e: unknown) => e)
    expect((error as BnsError).code).toBe(BNS_ERROR_CODE.RPC_TRANSPORT_ERROR)
    expect((error as BnsError).isServiceFailure).toBe(true)
  })

  it('超时 -> REQUEST_TIMEOUT', async () => {
    const client = new KrpcClient({
      endpoint: 'http://bns.test/kapi/bns',
      timeoutMs: 10,
      fetchImpl: (_url, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(new Error('aborted')))
        }),
    })
    const error = await client.call('system.info', {}).catch((e: unknown) => e)
    expect((error as BnsError).code).toBe(MODEL_ERROR_CODE.REQUEST_TIMEOUT)
  })
})
