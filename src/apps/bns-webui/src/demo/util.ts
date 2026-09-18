/**
 * 演示模式共用工具。
 *
 * 演示模式的定位（README §5 / PRD 附录）：
 * 在没有可达 bns-server、没有浏览器钱包扩展的环境下，让原型完整可交互。
 * 页面消费的仍然是真实的 bns_model 管线（mapper、写流程、交易状态机），
 * 只是把三个端口换成浏览器内实现：
 *   fetchImpl  -> demo/server.ts（假 bns-server）
 *   WalletPort -> demo/wallet.ts（演示钱包）
 *   CalldataCodec -> demo/codec.ts（JSON-hex 编码，够走通流程）
 */

import type { WriteIntent } from '../bns_model'

export const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms))

/** 演示网络抖动：让 loading 态可见但不拖沓。 */
export function jitter(baseMs = 140, spreadMs = 160): Promise<void> {
  return sleep(baseMs + Math.random() * spreadMs)
}

/**
 * 确定性伪 bytes32：只用于演示数据的观感（hash 列不为空），无任何密码学意义。
 */
export function pseudoHash(seed: string): string {
  let h1 = 0x811c9dc5
  let h2 = 0x01000193
  for (let i = 0; i < seed.length; i += 1) {
    h1 = Math.imul(h1 ^ seed.charCodeAt(i), 0x01000193) >>> 0
    h2 = Math.imul(h2 ^ (seed.charCodeAt(i) << (i % 8)), 0x85ebca6b) >>> 0
  }
  let out = ''
  for (let i = 0; i < 8; i += 1) {
    const word = (Math.imul(h1 ^ (h2 >>> (i % 5)), 0x9e3779b1) + i * 0x7f4a7c15) >>> 0
    out += word.toString(16).padStart(8, '0')
    h1 = (h1 ^ word) >>> 0
    h2 = (h2 + word) >>> 0
  }
  return `0x${out}`
}

// ---------------------------------------------------------------------------
// WriteIntent <-> JSON（演示 calldata 的内容格式）
//
// 演示 codec 不做真实 ABI 编码，而是把 intent 序列化成 JSON 再转 hex：
// 假链（demo world）解开它就知道要应用哪种投影变化。
// bigint / Uint8Array 不是 JSON 原生类型，用带标记的包装表达。
// ---------------------------------------------------------------------------

const BIGINT_TAG = '$bigint'
const BYTES_TAG = '$bytes'

export function intentToJson(intent: WriteIntent): string {
  return JSON.stringify(intent, (_key, value: unknown) => {
    if (typeof value === 'bigint') return { [BIGINT_TAG]: value.toString() }
    if (value instanceof Uint8Array) return { [BYTES_TAG]: Array.from(value) }
    return value
  })
}

export function intentFromJson(json: string): WriteIntent {
  return JSON.parse(json, (_key, value: unknown) => {
    if (typeof value === 'object' && value !== null) {
      const record = value as Record<string, unknown>
      if (typeof record[BIGINT_TAG] === 'string') return BigInt(record[BIGINT_TAG])
      if (Array.isArray(record[BYTES_TAG])) return new Uint8Array(record[BYTES_TAG] as number[])
    }
    return value
  }) as WriteIntent
}

export function utf8ToHex(text: string): `0x${string}` {
  const bytes = new TextEncoder().encode(text)
  let hex = ''
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0')
  return `0x${hex}`
}

export function hexToUtf8(hex: string): string {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex
  const bytes = new Uint8Array(clean.length / 2)
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  }
  return new TextDecoder().decode(bytes)
}
