import { describe, expect, it } from 'vitest'

import {
  MAX_INLINE_DOCUMENT,
  STORAGE_INLINE_BYTES32,
  ZERO_BYTES32,
  bytes32OrZero,
  bytes32ToLabel,
  bytesToHex,
  canonicalDocType,
  didBnsFromName,
  hexToBytes,
  isSameAddress,
  isTxHash,
  labelToBytes32,
  nameFromDidBns,
  normalizeAddress,
  parseBnsName,
  sha256Hex,
  storageTypeToBytes32,
  validateBnsName,
  wireBytes,
} from '../infra/codec'
import { payload } from './fixtures'
import type { WireResolveResult } from '../types/wire'

describe('名称校验', () => {
  it('拆出二级名称的父名称与 leaf', () => {
    const parsed = parseBnsName('device.alice')
    expect(parsed).toMatchObject({ name: 'device.alice', parent: 'alice', leaf: 'device', isTopLevel: false })
  })

  it('顶级名称没有父名称', () => {
    expect(parseBnsName('alice')).toMatchObject({ isTopLevel: true, parent: null })
  })

  it('拒绝大写而不是静默转小写', () => {
    // PRD 6.1：不自动 lower-case，UI 只能提供显式的“转换为小写”按钮。
    expect(() => parseBnsName('Alice')).toThrowError(/小写/)
    expect(parseBnsName('alice').name).toBe('alice')
  })

  it('拒绝三级及以上名称', () => {
    // 合约最多允许一个 `.`。
    expect(() => parseBnsName('a.b.c')).toThrowError(/顶级名称和二级名称/)
  })

  it('拒绝 did:bns: 前缀', () => {
    expect(() => parseBnsName('did:bns:alice')).toThrowError(/did:bns:/)
  })

  it('拒绝以 - 开头或结尾的 label', () => {
    expect(() => parseBnsName('-alice')).toThrowError(/开头或结尾/)
    expect(() => parseBnsName('alice-')).toThrowError(/开头或结尾/)
    expect(parseBnsName('a-b').name).toBe('a-b')
  })

  it('拒绝空 label 与超长名称', () => {
    expect(() => parseBnsName('a..b')).toThrow()
    expect(() => parseBnsName(`${'a'.repeat(127)}.b`)).toThrowError(/126/)
  })

  it('validateBnsName 不抛错，供输入框实时反馈', () => {
    expect(validateBnsName('alice').ok).toBe(true)
    const bad = validateBnsName('Alice')
    expect(bad.ok).toBe(false)
    if (!bad.ok) expect(bad.message).toMatch(/小写/)
  })

  it('did:bns 双向转换', () => {
    expect(didBnsFromName('alice')).toBe('did:bns:alice')
    expect(nameFromDidBns('did:bns:device.alice')).toBe('device.alice')
    expect(() => nameFromDidBns('did:web:example.com')).toThrowError(/did:bns/)
  })
})

describe('doc_type 校验', () => {
  it('接受小写字母数字与 - _', () => {
    expect(canonicalDocType('dns_txt')).toBe('dns_txt')
    expect(canonicalDocType('owner')).toBe('owner')
  })

  it('拒绝大写、非法字符和超长', () => {
    expect(() => canonicalDocType('Owner')).toThrow()
    expect(() => canonicalDocType('own.er')).toThrow()
    expect(() => canonicalDocType('a'.repeat(33))).toThrowError(/32/)
  })
})

describe('bytes32 与地址', () => {
  it('STORAGE_INLINE 与合约常量逐字节一致', () => {
    // BnsCore.sol: bytes32 constant STORAGE_INLINE = 0x696e6c696e65...
    expect(STORAGE_INLINE_BYTES32).toBe(
      '0x696e6c696e650000000000000000000000000000000000000000000000000000',
    )
  })

  it('label <-> bytes32 往返', () => {
    expect(bytes32ToLabel(labelToBytes32('inline'))).toBe('inline')
    expect(bytes32ToLabel(labelToBytes32('uri'))).toBe('uri')
  })

  it('storageTypeToBytes32 同时接受标签与 hash', () => {
    // 投影里 storage_type 是标签，写入合约必须转回 bytes32。
    expect(storageTypeToBytes32('inline')).toBe(STORAGE_INLINE_BYTES32)
    expect(storageTypeToBytes32(ZERO_BYTES32)).toBe(ZERO_BYTES32)
  })

  it('真实 hash 值不会被误判成标签', () => {
    const hash = '0x376e070bb47087e6abd0254c6429ae7618a9ac26d1facaa03fe06577dd5fd6ca'
    expect(bytes32ToLabel(hash as `0x${string}`)).toBeNull()
  })

  it('地址规范化为小写并拒绝非法输入', () => {
    expect(normalizeAddress(' 0xB2D3a40E76042A8C4f0EcA5238C6D799C43B1A20 ')).toBe(
      '0xb2d3a40e76042a8c4f0eca5238c6d799c43b1a20',
    )
    expect(() => normalizeAddress('0x123')).toThrowError(/EVM 地址/)
    expect(isSameAddress('0xAB'.padEnd(42, '0'), '0xab'.padEnd(42, '0'))).toBe(true)
    expect(isSameAddress(null, '0x0')).toBe(false)
  })

  it('空字符串按 zero bytes32 处理', () => {
    expect(bytes32OrZero('')).toBe(ZERO_BYTES32)
    expect(bytes32OrZero(null)).toBe(ZERO_BYTES32)
  })

  it('交易 hash 判定', () => {
    expect(isTxHash(`0x${'a'.repeat(64)}`)).toBe(true)
    expect(isTxHash('0xabc')).toBe(false)
  })

  it('hex <-> bytes 往返', () => {
    const bytes = Uint8Array.from([0, 1, 254, 255])
    expect(hexToBytes(bytesToHex(bytes))).toEqual(bytes)
  })
})

describe('inline 文档 content_hash', () => {
  it('线上真实文档满足 content_hash = sha256(inline_document)', async () => {
    // PRD 6.2 的硬约束，用线上真实数据验证我们的实现口径一致。
    const resolved = payload<WireResolveResult>('resolveDocument')
    const inline = wireBytes(resolved.document_state.document.inline_document)
    expect(await sha256Hex(inline)).toBe(resolved.document_state.document.content_hash)
  })

  it('inline 上限是 4 KiB', () => {
    expect(MAX_INLINE_DOCUMENT).toBe(4096)
  })
})
