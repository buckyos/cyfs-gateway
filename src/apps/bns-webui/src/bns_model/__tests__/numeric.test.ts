import { describe, expect, it } from 'vitest'

import {
  U64_MAX,
  formatDuration,
  secondsUntil,
  u32FromWire,
  u64FromWire,
  u64FromWireOptional,
  u64ToWire,
  unixSecondsToDate,
} from '../infra/numeric'

describe('u64 安全层', () => {
  it('普通 number 转 bigint', () => {
    expect(u64FromWire(1815646660, 'expire_at')).toBe(1815646660n)
    expect(u64FromWire(0, 'x')).toBe(0n)
  })

  it('超出安全整数范围时报错而不是静默舍入', () => {
    // 这是本层唯一的立身之本：JSON.parse 已经丢了精度，我们必须拒绝使用。
    expect(() => u64FromWire(2 ** 53, 'name_seq')).toThrowError(/安全整数/)
    expect(() => u64FromWire(9007199254740993, 'name_seq')).toThrowError(/安全整数/)
  })

  it('拒绝非数值', () => {
    expect(() => u64FromWire(undefined, 'x')).toThrowError(/缺失或不是 number/)
    expect(() => u64FromWire(null, 'x')).toThrow()
    expect(() => u64FromWire(1.5, 'x')).toThrowError(/安全整数/)
  })

  it('接受字符串编码的 u64（为服务端将来改口径预留）', () => {
    expect(u64FromWire('18446744073709551615', 'x')).toBe(U64_MAX)
    expect(() => u64FromWire('12a', 'x')).toThrowError(/u64 字符串/)
  })

  it('可空字段', () => {
    expect(u64FromWireOptional(null, 'block_number')).toBeNull()
    expect(u64FromWireOptional(undefined, 'block_number')).toBeNull()
    expect(u64FromWireOptional(7, 'block_number')).toBe(7n)
  })

  it('u32 位掩码校验', () => {
    expect(u32FromWire(5, 'purposes')).toBe(5)
    expect(() => u32FromWire(-1, 'purposes')).toThrow()
    expect(() => u32FromWire(2 ** 32, 'purposes')).toThrow()
  })

  it('回写 JSON number 时也要检查安全范围', () => {
    expect(u64ToWire(99n, 'version')).toBe(99)
    expect(() => u64ToWire(U64_MAX, 'version')).toThrowError(/无法安全编码/)
    expect(() => u64ToWire(-1n, 'version')).toThrowError(/u64 范围/)
  })
})

describe('时间派生', () => {
  it('0 表示不设截止', () => {
    expect(unixSecondsToDate(0n)).toBeNull()
    expect(secondsUntil(0n, 1000n)).toBeNull()
  })

  it('剩余秒数可以为负（已过期）', () => {
    expect(secondsUntil(2000n, 1000n)).toBe(1000n)
    expect(secondsUntil(1000n, 2000n)).toBe(-1000n)
  })

  it('时长格式化', () => {
    expect(formatDuration(86400n * 3n)).toBe('3 天')
    expect(formatDuration(3600n * 2n)).toBe('2 小时')
    expect(formatDuration(-90n)).toBe('1 分钟')
    expect(formatDuration(30n)).toBe('30 秒')
  })
})
