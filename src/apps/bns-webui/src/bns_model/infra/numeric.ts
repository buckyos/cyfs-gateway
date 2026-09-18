/**
 * u64 数值安全层（PRD 6.3）。
 *
 * bns-server 把 Rust 的 u64 编码成 JSON number。JavaScript 的 `JSON.parse`
 * 对超过 2^53-1 的整数会静默丢精度，因此本层的契约是：
 *
 *   **宁可报错，也不静默舍入。**
 *
 * 已知限制：精度丢失发生在 `JSON.parse` 内部，本层只能事后发现
 * “这个值已经不是安全整数”，无法还原原值。当前投影里的 u64 字段
 * （seq / version / unix 秒 / 区块号）都远小于 2^53，触发即视为异常数据。
 */

import { BnsError } from '../types/errors'

export const U64_MAX = 18446744073709551615n

/** 线上 JSON number -> 领域 bigint。非安全整数直接抛错。 */
export function u64FromWire(value: unknown, field: string): bigint {
  if (typeof value === 'bigint') return assertU64(value, field)
  if (typeof value === 'string') {
    // 为将来 server 改用字符串编码 u64 预留；当前不会走到。
    if (!/^\d+$/.test(value)) {
      throw BnsError.numeric(`字段 ${field} 不是合法的 u64 字符串: ${value}`, field)
    }
    return assertU64(BigInt(value), field)
  }
  if (typeof value !== 'number') {
    throw BnsError.numeric(`字段 ${field} 缺失或不是 number: ${String(value)}`, field)
  }
  if (!Number.isSafeInteger(value)) {
    throw BnsError.numeric(
      `字段 ${field} 的值 ${value} 超出 JavaScript 安全整数范围，可能已在 JSON 解析阶段丢失精度`,
      field,
    )
  }
  return assertU64(BigInt(value), field)
}

/** 可空 u64（server 端 `Option<u64>` -> `number | null`）。 */
export function u64FromWireOptional(value: unknown, field: string): bigint | null {
  if (value === null || value === undefined) return null
  return u64FromWire(value, field)
}

/** u32 位掩码等小整数保持 number，但仍要校验范围。 */
export function u32FromWire(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw BnsError.numeric(`字段 ${field} 不是合法 u32: ${String(value)}`, field)
  }
  return value
}

export function assertU64(value: bigint, field: string): bigint {
  if (value < 0n || value > U64_MAX) {
    throw BnsError.numeric(`字段 ${field} 超出 u64 范围: ${value}`, field)
  }
  return value
}

/** 领域 bigint -> 线上 JSON number（仅用于请求参数，如 `document.get_version`）。 */
export function u64ToWire(value: bigint, field: string): number {
  assertU64(value, field)
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw BnsError.numeric(`字段 ${field} 的值 ${value} 无法安全编码为 JSON number`, field)
  }
  return Number(value)
}

/** Unix 秒 bigint -> JS Date；0 按“未设置”处理。 */
export function unixSecondsToDate(value: bigint): Date | null {
  if (value === 0n) return null
  return new Date(Number(value) * 1000)
}

/** 剩余秒数；`expireAt = 0` 表示不过期。 */
export function secondsUntil(expireAt: bigint, nowSeconds: bigint): bigint | null {
  if (expireAt === 0n) return null
  return expireAt - nowSeconds
}

export function formatDuration(seconds: bigint): string {
  const abs = seconds < 0n ? -seconds : seconds
  const days = abs / 86400n
  if (days > 0n) return `${days} 天`
  const hours = abs / 3600n
  if (hours > 0n) return `${hours} 小时`
  const minutes = abs / 60n
  if (minutes > 0n) return `${minutes} 分钟`
  return `${abs} 秒`
}
