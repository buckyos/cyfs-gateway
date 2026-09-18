/**
 * 编解码与格式校验。
 *
 * 覆盖 PRD 19「前端」交付物中的：
 * bytes32 label/hash、address bytes、inline SHA-256 codec、名称与 doc_type 规则。
 *
 * 名称/doc_type 规则真值来源：doc/BNS/BNS-API.md §6 与 PRD §6.1 / §6.2。
 */

import { BNS_ERROR_CODE, BnsError, MODEL_ERROR_CODE } from '../types/errors'

export const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000'
export const ZERO_BYTES32 = `0x${'0'.repeat(64)}`
export const DID_BNS_PREFIX = 'did:bns:'

export const MAX_BNS_NAME_LEN = 253
export const MAX_BNS_LABEL_LEN = 126
export const MAX_DOC_TYPE_LEN = 32
/** 合约 `MAX_INLINE_DOCUMENT`，inline 文档上限 4 KiB。 */
export const MAX_INLINE_DOCUMENT = 4096
/** 产品上限：单次 mutation 的 item 数（合约对部分方法未强制，前端统一收敛）。 */
export const MAX_MUTATION_BATCH_ITEMS = 32

export type Hex = `0x${string}`

// ---------------------------------------------------------------------------
// hex / bytes
// ---------------------------------------------------------------------------

export function isHex(value: string): boolean {
  return /^0x[0-9a-fA-F]*$/.test(value) && value.length % 2 === 0
}

export function hexToBytes(value: string): Uint8Array {
  const body = value.startsWith('0x') ? value.slice(2) : value
  if (body.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(body)) {
    throw BnsError.validation(BNS_ERROR_CODE.SERIALIZATION_ERROR, `不是合法的 hex: ${value}`)
  }
  const out = new Uint8Array(body.length / 2)
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(body.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

export function bytesToHex(bytes: Uint8Array | number[]): Hex {
  let out = '0x'
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0')
  return out as Hex
}

export function utf8ToBytes(value: string): Uint8Array {
  return new TextEncoder().encode(value)
}

export function bytesToUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes)
}

/** 线上 `Vec<u8>`（number[]）-> Uint8Array。 */
export function wireBytes(value: number[] | undefined | null): Uint8Array {
  return Uint8Array.from(value ?? [])
}

// ---------------------------------------------------------------------------
// address / bytes32
// ---------------------------------------------------------------------------

export function isAddress(value: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(value)
}

/** 规范化成小写 `0x` 地址；非法地址报 INVALID_ADDRESS，与服务端错误码对齐。 */
export function normalizeAddress(value: string): string {
  const trimmed = value.trim()
  if (!isAddress(trimmed)) {
    throw BnsError.validation(BNS_ERROR_CODE.INVALID_ADDRESS, `不是合法的 EVM 地址: ${value}`)
  }
  return trimmed.toLowerCase()
}

export function isSameAddress(a: string | null | undefined, b: string | null | undefined): boolean {
  if (!a || !b) return false
  return a.trim().toLowerCase() === b.trim().toLowerCase()
}

export function isBytes32(value: string): boolean {
  return /^0x[0-9a-fA-F]{64}$/.test(value)
}

export function normalizeBytes32(value: string, field = 'bytes32'): Hex {
  const trimmed = value.trim()
  if (!isBytes32(trimmed)) {
    throw BnsError.validation(
      BNS_ERROR_CODE.SERIALIZATION_ERROR,
      `${field} 必须是 32 字节 hex: ${value}`,
      { field },
    )
  }
  return trimmed.toLowerCase() as Hex
}

/** 空值语义：`""` / `undefined` 都按 zero bytes32 处理（合约的“未设置”）。 */
export function bytes32OrZero(value: string | null | undefined, field = 'bytes32'): Hex {
  if (!value || value.length === 0) return ZERO_BYTES32 as Hex
  return normalizeBytes32(value, field)
}

/**
 * bytes32 标签编解码。
 *
 * 合约把 `storageType` 之类的字段存成右侧补零的 ASCII，例如
 * `"inline"` -> `0x696e6c696e65...`；bns-indexer 会把可打印的 bytes32
 * 还原成标签字符串再放进投影（`bytes32_label_or_hash`）。
 * 因此写入前必须做反向转换，否则会把标签当成 hash 发给合约。
 */
export function labelToBytes32(label: string): Hex {
  const bytes = utf8ToBytes(label)
  if (bytes.length > 32) {
    throw BnsError.validation(
      BNS_ERROR_CODE.SERIALIZATION_ERROR,
      `bytes32 标签超过 32 字节: ${label}`,
    )
  }
  const padded = new Uint8Array(32)
  padded.set(bytes, 0)
  return bytesToHex(padded)
}

export function bytes32ToLabel(value: Hex): string | null {
  const bytes = hexToBytes(value)
  const end = bytes.indexOf(0)
  const body = end === -1 ? bytes : bytes.subarray(0, end)
  if (body.length === 0) return null
  const tail = end === -1 ? new Uint8Array(0) : bytes.subarray(end)
  if (tail.some((byte) => byte !== 0)) return null
  if (body.some((byte) => byte < 0x20 || byte > 0x7e)) return null
  return bytesToUtf8(body)
}

/**
 * 投影里的 `storage_type` 可能是标签（`"inline"`）也可能是 hash 字符串；
 * 写入合约时统一转回 bytes32。
 */
export function storageTypeToBytes32(storageType: string): Hex {
  if (isBytes32(storageType)) return storageType.toLowerCase() as Hex
  return labelToBytes32(storageType)
}

export const STORAGE_TYPE_INLINE = 'inline'
export const STORAGE_INLINE_BYTES32 = labelToBytes32(STORAGE_TYPE_INLINE)

// ---------------------------------------------------------------------------
// sha256
// ---------------------------------------------------------------------------

/**
 * inline 文档的 `content_hash` 必须是 `sha256(inline_document)`（PRD 6.2）。
 * 依赖 WebCrypto，只在安全上下文（https / localhost）可用。
 */
export async function sha256Hex(data: Uint8Array): Promise<Hex> {
  if (typeof globalThis.crypto?.subtle?.digest !== 'function') {
    throw BnsError.validation(
      MODEL_ERROR_CODE.HTTP_ERROR,
      'WebCrypto 不可用：inline 文档的 content_hash 需要安全上下文（https 或 localhost）',
    )
  }
  const view = new Uint8Array(data)
  const digest = await globalThis.crypto.subtle.digest('SHA-256', view.buffer as ArrayBuffer)
  return bytesToHex(new Uint8Array(digest))
}

// ---------------------------------------------------------------------------
// name / doc_type
// ---------------------------------------------------------------------------

export interface ParsedBnsName {
  name: string
  labels: string[]
  isTopLevel: boolean
  /** 二级名称的父名称；顶级名称为 null。 */
  parent: string | null
  /** 二级名称的自身 label。 */
  leaf: string
}

/**
 * 校验并解析 BNS 名称。
 *
 * 注意：**不做静默 lower-case**。大写输入直接判非法，由 UI 提供显式
 * “转换为小写”按钮（PRD 6.1）。
 */
export function parseBnsName(input: string): ParsedBnsName {
  const name = input.trim()
  if (name.length === 0) {
    throw BnsError.validation(BNS_ERROR_CODE.INVALID_NAME, '名称不能为空')
  }
  if (name.startsWith(DID_BNS_PREFIX)) {
    throw BnsError.validation(
      BNS_ERROR_CODE.INVALID_NAME,
      `名称不得包含 ${DID_BNS_PREFIX} 前缀`,
      { name },
    )
  }
  if (utf8ToBytes(name).length > MAX_BNS_NAME_LEN) {
    throw BnsError.validation(
      BNS_ERROR_CODE.INVALID_NAME,
      `名称超过 ${MAX_BNS_NAME_LEN} 字节`,
      { name },
    )
  }
  const labels = name.split('.')
  if (labels.length > 2) {
    // 合约当前最多允许一个 `.`：只支持顶级和二级名称。
    throw BnsError.validation(
      BNS_ERROR_CODE.INVALID_NAME,
      '当前合约只支持顶级名称和二级名称（最多一个 `.`）',
      { name },
    )
  }
  for (const label of labels) {
    assertLabel(label, name)
  }
  const isTopLevel = labels.length === 1
  return {
    name,
    labels,
    isTopLevel,
    parent: isTopLevel ? null : labels.slice(1).join('.'),
    leaf: labels[0],
  }
}

function assertLabel(label: string, name: string): void {
  if (label.length === 0) {
    throw BnsError.validation(BNS_ERROR_CODE.INVALID_NAME, 'label 不能为空', { name })
  }
  if (utf8ToBytes(label).length > MAX_BNS_LABEL_LEN) {
    throw BnsError.validation(
      BNS_ERROR_CODE.INVALID_NAME,
      `label \`${label}\` 超过 ${MAX_BNS_LABEL_LEN} 字节`,
      { name },
    )
  }
  if (!/^[a-z0-9-]+$/.test(label)) {
    throw BnsError.validation(
      BNS_ERROR_CODE.INVALID_NAME,
      `label \`${label}\` 只允许小写字母、数字和 \`-\``,
      { name },
    )
  }
  if (label.startsWith('-') || label.endsWith('-')) {
    throw BnsError.validation(
      BNS_ERROR_CODE.INVALID_NAME,
      `label \`${label}\` 不能以 \`-\` 开头或结尾`,
      { name },
    )
  }
}

/** 只判断合法性，不抛错，用于输入框实时反馈。 */
export function validateBnsName(input: string): { ok: true; parsed: ParsedBnsName } | { ok: false; message: string } {
  try {
    return { ok: true, parsed: parseBnsName(input) }
  } catch (error) {
    return { ok: false, message: error instanceof Error ? error.message : String(error) }
  }
}

export function canonicalDocType(input: string): string {
  const docType = input.trim()
  if (docType.length === 0) {
    throw BnsError.validation(BNS_ERROR_CODE.INVALID_DOC_TYPE, 'doc_type 不能为空')
  }
  if (utf8ToBytes(docType).length > MAX_DOC_TYPE_LEN) {
    throw BnsError.validation(
      BNS_ERROR_CODE.INVALID_DOC_TYPE,
      `doc_type 超过 ${MAX_DOC_TYPE_LEN} 字节`,
      { docType },
    )
  }
  if (!/^[a-z0-9_-]+$/.test(docType)) {
    throw BnsError.validation(
      BNS_ERROR_CODE.INVALID_DOC_TYPE,
      'doc_type 只允许小写字母、数字、`-` 和 `_`',
      { docType },
    )
  }
  return docType
}

export function didBnsFromName(name: string): string {
  return `${DID_BNS_PREFIX}${parseBnsName(name).name}`
}

export function nameFromDidBns(did: string): string {
  if (!did.startsWith(DID_BNS_PREFIX)) {
    throw BnsError.validation(BNS_ERROR_CODE.INVALID_NAME, `不是 did:bns 标识: ${did}`)
  }
  return parseBnsName(did.slice(DID_BNS_PREFIX.length)).name
}

export function isTxHash(value: string): boolean {
  return /^0x[0-9a-fA-F]{64}$/.test(value.trim())
}

export function normalizeTxHash(value: string): Hex {
  return normalizeBytes32(value, 'tx_hash')
}

export function shortHex(value: string, head = 6, tail = 4): string {
  if (value.length <= head + tail + 1) return value
  return `${value.slice(0, head)}…${value.slice(-tail)}`
}
