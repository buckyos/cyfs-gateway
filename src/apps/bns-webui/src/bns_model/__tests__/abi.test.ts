/**
 * Intent -> ABI 位置参数。
 *
 * 参数摆放是协议语义，一旦错位会静默构造出一笔合法但语义错误的交易，
 * 所以 15 个写方法逐个对照 IBns.sol 的签名验证。
 */

import { describe, expect, it } from 'vitest'

import {
  BNS_ABI_SOURCE,
  BNS_ERRORS,
  BNS_WRITE_FUNCTIONS,
  STALE_GUARD_ERRORS,
  toAbiArgs,
  toAbiCallAuthority,
  toAbiDocumentRef,
  toAbiPrincipal,
} from '../write/abi'
import {
  EMPTY_GUARD,
  PUBLIC_AUTHORITY,
  WRITE_INTENT_META,
  bnsNamePrincipal,
  chainAccountPrincipal,
  defaultRegisterOptions,
  inlineDocumentRef,
  UNSET_PRINCIPAL,
  type WriteIntent,
  type WriteIntentKind,
} from '../write/intents'
import { STORAGE_INLINE_BYTES32, ZERO_ADDRESS, ZERO_BYTES32, bytesToHex, utf8ToBytes } from '../infra/codec'
import { buildCallAuthority } from '../write/authority'

const NAME = 'alice'
const ADDR = '0x71C7656EC7ab88b098defB751B7401B5f6d8976F'
const ADDR_LOWER = ADDR.toLowerCase()
const base = { name: NAME, authority: PUBLIC_AUTHORITY, guard: EMPTY_GUARD }

/** 从 human-readable 签名里取出参数名序列，用来对齐位置参数。 */
function paramNames(method: string): string[] {
  const signature = BNS_WRITE_FUNCTIONS.find((fn) => fn.startsWith(`function ${method}(`))
  if (!signature) throw new Error(`ABI 里没有 ${method}`)
  const body = signature.slice(signature.indexOf('(') + 1, signature.indexOf(')'))
  let depth = 0
  const parts: string[] = []
  let current = ''
  for (const char of body) {
    if (char === '[') depth += 1
    if (char === ']') depth -= 1
    if (char === ',' && depth === 0) {
      parts.push(current)
      current = ''
    } else {
      current += char
    }
  }
  if (current.trim()) parts.push(current)
  return parts.map((part) => part.trim().split(/\s+/).pop() ?? '')
}

describe('ABI 定义完整性', () => {
  it('15 个写方法全部有签名', () => {
    expect(BNS_WRITE_FUNCTIONS).toHaveLength(15)
    const kinds = Object.keys(WRITE_INTENT_META) as WriteIntentKind[]
    expect(kinds).toHaveLength(15)
    for (const kind of kinds) {
      expect(BNS_WRITE_FUNCTIONS.some((fn) => fn.startsWith(`function ${WRITE_INTENT_META[kind].method}(`))).toBe(true)
    }
  })

  it('18 个 custom error 全部收录（PRD 12.4）', () => {
    expect(BNS_ERRORS).toHaveLength(18)
    for (const name of ['StaleNameSeq', 'NotEffectiveOwner', 'InvalidMutation', 'InlineDocumentTooLarge']) {
      expect(BNS_ERRORS.some((e) => e.startsWith(`error ${name}(`))).toBe(true)
    }
  })

  it('guard 类 revert 被单独标记，不允许自动重放', () => {
    expect([...STALE_GUARD_ERRORS].sort()).toEqual([
      'StaleDocumentVersion',
      'StaleNameSeq',
      'StaleParentNameSeq',
    ])
  })

  it('BNS_ABI_SOURCE 汇总 struct + function + error', () => {
    expect(BNS_ABI_SOURCE.length).toBe(10 + 15 + 18)
  })

  it('registerName / renewName 标记为 payable（但 value 恒为 0）', () => {
    expect(BNS_WRITE_FUNCTIONS.find((f) => f.startsWith('function registerName('))).toMatch(/\bpayable\b/)
    expect(BNS_WRITE_FUNCTIONS.find((f) => f.startsWith('function renewName('))).toMatch(/\bpayable\b/)
  })
})

describe('Principal 的两种形态', () => {
  it('chain_account -> 20 字节裸地址（小写）', () => {
    expect(toAbiPrincipal(chainAccountPrincipal(ADDR))).toEqual({ kind: 1, value: ADDR_LOWER })
  })

  it('bns_name -> 名称的 UTF-8 bytes', () => {
    expect(toAbiPrincipal(bnsNamePrincipal('alice'))).toEqual({
      kind: 2,
      value: bytesToHex(utf8ToBytes('alice')),
    })
  })

  it('unset -> 空 bytes', () => {
    expect(toAbiPrincipal(UNSET_PRINCIPAL)).toEqual({ kind: 0, value: '0x' })
  })

  it('非法地址直接报错，不会悄悄编成错的 principal', () => {
    expect(() => toAbiPrincipal(chainAccountPrincipal('0x123'))).toThrow()
    expect(() => toAbiPrincipal({ kind: 'bns_name', value: '' })).toThrow()
  })
})

describe('CallAuthority 的 role 序号', () => {
  it('public / owner / controller 对应 0 / 1 / 2', () => {
    expect(toAbiCallAuthority(buildCallAuthority({ kind: 'public' }))).toEqual({
      role: 0,
      actor: { kind: 0, value: '0x' },
      kid: ZERO_BYTES32,
    })
    expect(toAbiCallAuthority(buildCallAuthority({ kind: 'chain_account_owner', address: ADDR })).role).toBe(1)
    expect(
      toAbiCallAuthority(buildCallAuthority({ kind: 'chain_account_controller', address: ADDR })).role,
    ).toBe(2)
  })

  it('BNS name owner 路径带上 kid', () => {
    const kid = `0x${'ab'.repeat(32)}`
    const authority = buildCallAuthority({ kind: 'bns_name_owner', ownerName: 'studio', kid })
    expect(toAbiCallAuthority(authority)).toMatchObject({ role: 1, kid })
  })
})

describe('DocumentRef', () => {
  it('storage_type 标签转回 bytes32', () => {
    const ref = toAbiDocumentRef(inlineDocumentRef(utf8ToBytes('{}'), ZERO_BYTES32))
    expect(ref.storageType).toBe(STORAGE_INLINE_BYTES32)
    expect(ref.uri).toBe('')
    expect(ref.inlineDocument).toBe(bytesToHex(utf8ToBytes('{}')))
  })
})

describe('位置参数与 IBns.sol 签名对齐', () => {
  const cases: Array<{ kind: WriteIntentKind; intent: WriteIntent; expectAt?: Record<number, unknown> }> = [
    {
      kind: 'register_name',
      intent: {
        ...base,
        kind: 'register_name',
        assetOwner: ADDR,
        options: defaultRegisterOptions(86400n, 3600n),
        authorityUpdates: [],
        semanticOwnerAfterAuthority: UNSET_PRINCIPAL,
        controllerPolicy: [],
        controllerPolicyHash: ZERO_BYTES32,
        initialDocuments: [],
      },
      expectAt: { 0: NAME, 1: ADDR_LOWER },
    },
    {
      kind: 'renew_name',
      intent: { ...base, kind: 'renew_name', duration: 15552000n },
      expectAt: { 0: NAME, 1: 15552000n },
    },
    {
      kind: 'transfer_name',
      intent: {
        ...base,
        kind: 'transfer_name',
        newAssetOwner: ADDR,
        newSemanticOwner: UNSET_PRINCIPAL,
        atomicDocumentUpdates: [],
      },
      expectAt: { 1: ADDR_LOWER },
    },
    {
      kind: 'set_name_owner',
      intent: { ...base, kind: 'set_name_owner', semanticOwner: bnsNamePrincipal('studio') },
    },
    {
      kind: 'release_name',
      intent: { ...base, kind: 'release_name', mode: 'tombstone_forever', reasonHash: '' },
      expectAt: { 1: 1, 2: ZERO_BYTES32 },
    },
    {
      kind: 'set_namespace_policy',
      intent: { ...base, kind: 'set_namespace_policy', allowDelegatedSubnames: true, namespacePolicyHash: '' },
      expectAt: { 1: true },
    },
    {
      kind: 'update_authority_keys',
      intent: { ...base, kind: 'update_authority_keys', updates: [] },
    },
    {
      kind: 'set_min_document_iat',
      intent: { ...base, kind: 'set_min_document_iat', minDocumentIat: 1700000000n, reasonHash: '' },
      expectAt: { 1: 1700000000n },
    },
    {
      kind: 'publish_document',
      intent: {
        ...base,
        kind: 'publish_document',
        docType: 'owner',
        expectedVersion: 3n,
        document: inlineDocumentRef(utf8ToBytes('{}'), ZERO_BYTES32),
        controller: UNSET_PRINCIPAL,
        beneficiary: UNSET_PRINCIPAL,
        paymentTarget: '',
        expireAt: 0n,
        controllerPolicyHash: '',
        paymentPolicyHash: '',
        splitPolicyHash: '',
        pricePolicyHash: '',
        rightsPolicyHash: '',
      },
      expectAt: { 1: 'owner', 2: 3n, 6: ZERO_ADDRESS },
    },
    {
      kind: 'revoke_document',
      intent: { ...base, kind: 'revoke_document', docType: 'zone', expectedVersion: 7n, reasonHash: '' },
      expectAt: { 1: 'zone', 2: 7n },
    },
    {
      kind: 'set_controller_policy',
      intent: { ...base, kind: 'set_controller_policy', rules: [], policyHash: '' },
    },
    {
      kind: 'set_did_alias',
      intent: {
        ...base,
        kind: 'set_did_alias',
        targetDid: 'did:web:mira.dev',
        aliasKind: 'canonical',
        proofHash: '',
      },
      expectAt: { 1: 'did:web:mira.dev', 2: 3 },
    },
    {
      kind: 'set_payment_target',
      intent: {
        ...base,
        kind: 'set_payment_target',
        docType: 'payment',
        expectedVersion: 2n,
        paymentTarget: ADDR,
        beneficiary: UNSET_PRINCIPAL,
        paymentPolicyHash: '',
        splitPolicyHash: '',
        pricePolicyHash: '',
        rightsPolicyHash: '',
      },
      expectAt: { 3: ADDR_LOWER },
    },
    {
      kind: 'apply_mutations',
      intent: {
        ...base,
        kind: 'apply_mutations',
        authorityUpdates: [],
        documents: [],
        ownerPolicy: { updateMinDocumentIat: true, minDocumentIat: 42n, reasonHash: '' },
      },
    },
    {
      kind: 'publish_log_checkpoint',
      intent: { ...base, kind: 'publish_log_checkpoint', issuer: UNSET_PRINCIPAL, externalAnchor: '' },
    },
  ]

  it('覆盖全部 15 个写方法', () => {
    expect(new Set(cases.map((c) => c.kind)).size).toBe(15)
  })

  for (const { kind, intent, expectAt } of cases) {
    it(`${kind} 的参数个数与顺序与签名一致`, () => {
      const method = WRITE_INTENT_META[kind].method
      const args = toAbiArgs(intent)
      expect(args.length, `${method} 参数个数`).toBe(paramNames(method).length)
      for (const [index, value] of Object.entries(expectAt ?? {})) {
        expect(args[Number(index)], `${method} 第 ${index} 个参数`).toEqual(value)
      }
    })
  }

  it('带 guard 的方法把 authority / guard 放在最后两位', () => {
    const args = toAbiArgs(cases.find((c) => c.kind === 'publish_document')!.intent)
    expect(args[args.length - 1]).toEqual({ expectedNameSeq: 0n, expectedParentNameSeq: 0n })
    expect(args[args.length - 2]).toMatchObject({ role: 0 })
  })

  it('renewName 没有 authority / guard 参数', () => {
    // 合约签名就是 (string, uint64)，多传会编码失败。
    expect(toAbiArgs(cases.find((c) => c.kind === 'renew_name')!.intent)).toHaveLength(2)
  })

  it('空 payment_target 编成 zero address（线上投影里就是空串）', () => {
    const args = toAbiArgs(cases.find((c) => c.kind === 'publish_document')!.intent)
    expect(args[6]).toBe(ZERO_ADDRESS)
  })

  it('registerName 的 initialPaymentTarget 固定为 zero address', () => {
    // 合约当前不读取该字段，前端不得把它当成有效注册选项（PRD 6.4.9）。
    const args = toAbiArgs(cases.find((c) => c.kind === 'register_name')!.intent)
    expect(args[2]).toMatchObject({ initialPaymentTarget: ZERO_ADDRESS })
  })
})
