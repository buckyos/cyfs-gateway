/**
 * 从线上 bns-server 抓取的真实响应。
 *
 * 重新抓取：`pnpm run capture:fixtures`（见 scripts/capture-fixtures.mjs）。
 * 不要手工编辑 live_responses.json —— 手写的报文会掩盖服务端的真实行为。
 */

import raw from './fixtures/live_responses.json'

export interface EnvelopeFixture {
  result?: { ok: boolean; result: unknown; error: unknown }
  error?: string
  sys: number[]
}

export interface DidFixture {
  httpStatus: number
  body: unknown
}

interface LiveFixtures {
  _note: string
  name: string
  address: string
  krpc: Record<string, EnvelopeFixture>
  didResolver: Record<string, DidFixture>
}

export const fixtures = raw as unknown as LiveFixtures

/** 取出 BNS 信封里的业务结果。 */
export function payload<T>(key: string): T {
  const envelope = fixtures.krpc[key]
  if (!envelope?.result) throw new Error(`fixture ${key} 没有 kRPC result`)
  return envelope.result.result as T
}

/** 取出信封里的业务错误。 */
export function envelopeError(key: string): { code: string; message: string; name: string | null; doc_type: string | null } {
  const envelope = fixtures.krpc[key]
  if (!envelope?.result?.error) throw new Error(`fixture ${key} 没有业务错误`)
  return envelope.result.error as never
}

export function didFixture(key: string): DidFixture {
  const value = fixtures.didResolver[key]
  if (!value) throw new Error(`没有 DID fixture ${key}`)
  return value
}
