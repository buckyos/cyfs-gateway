/**
 * wire -> domain 映射，输入全部是线上真实报文。
 */

import { describe, expect, it } from 'vitest'

import {
  decodeInlineDocument,
  deriveDocumentStatus,
  deriveNameStatus,
  mapEventRecord,
  mapNameOverview,
  mapNamePage,
  mapNameState,
  mapOwnerResolution,
  mapResolveResult,
  mapSystemInfo,
  mapTxState,
  toAuthorityKeyView,
} from '../services/mapper'
import { payload } from './fixtures'
import type {
  WireEventLogRecord,
  WireNamePage,
  WireNameState,
  WireOwnerResolution,
  WireResolveResult,
  WireSystemInfo,
  WireTxState,
} from '../types/wire'
import type { AuthorityKey } from '../types/domain'

const NAME_STATE = payload<WireNameState>('queryNameState')
const RESOLVED = payload<WireResolveResult>('resolveDocument')

describe('system.info', () => {
  it('映射为 camelCase', () => {
    const info = mapSystemInfo(payload<WireSystemInfo>('systemInfo'))
    expect(info.ready).toBe(true)
    expect(typeof info.chainId).toBe('number')
    expect(info.contractAddress).toMatch(/^0x[0-9a-f]{40}$/)
  })
})

describe('NameState', () => {
  it('u64 字段全部变成 bigint', () => {
    const state = mapNameState(NAME_STATE)
    expect(state.nameSeq).toBe(BigInt(NAME_STATE.name_seq))
    expect(state.expireAt).toBe(BigInt(NAME_STATE.expire_at))
    expect(state.registeredAt).toBe(BigInt(NAME_STATE.registered_at))
    expect(typeof state.nameSeq).toBe('bigint')
  })

  it('保留 asset_owner / semantic_owner / effective_owner 三者的区别', () => {
    const state = mapNameState(NAME_STATE)
    expect(state.semanticOwner.kind).toBe('unset')
    expect(state.effectiveOwner.kind).toBe('chain_account')
    expect(state.ownerSource).toBe('asset_owner_fallback')
    // 线上这条记录 semantic owner 未设置，effective owner 回退到 asset_owner。
    expect(state.effectiveOwner.value).toBe(state.assetOwner)
  })
})

describe('名称状态派生', () => {
  const state = mapNameState(NAME_STATE)

  it('未到期时 raw 与派生一致', () => {
    const derived = deriveNameStatus(state, state.expireAt - 1n)
    expect(derived).toMatchObject({ raw: 'active', label: 'active', timeExpired: false, inGrace: false })
    expect(derived.secondsToExpire).toBe(1n)
  })

  it('越过 expire_at 后 raw 仍是 active，但派生标记已过期', () => {
    // 合约不会因时间流逝改 status，所以两者必须并列展示（PRD 6.4.1 / 12.1）。
    const derived = deriveNameStatus(state, state.expireAt + 1n)
    expect(derived.raw).toBe('active')
    expect(derived.label).toBe('active_time_expired')
    expect(derived.timeExpired).toBe(true)
    expect(derived.inGrace).toBe(true)
    expect(derived.secondsToExpire).toBe(-1n)
  })

  it('越过 grace_until 后不再处于宽限期', () => {
    const derived = deriveNameStatus(state, state.graceUntil + 1n)
    expect(derived.inGrace).toBe(false)
    expect(derived.timeExpired).toBe(true)
  })

  it('expire_at = 0 视为不设截止', () => {
    const derived = deriveNameStatus({ ...state, expireAt: 0n }, 9_999_999_999n)
    expect(derived.timeExpired).toBe(false)
    expect(derived.secondsToExpire).toBeNull()
  })

  it('tombstoned 与 released 直接透传', () => {
    expect(deriveNameStatus({ ...state, status: 'tombstoned' }, 0n).label).toBe('tombstoned')
    expect(deriveNameStatus({ ...state, status: 'released' }, 0n).label).toBe('released')
  })
})

describe('NameOverview', () => {
  it('补上 did / 层级信息', () => {
    const overview = mapNameOverview(NAME_STATE, 0n)
    expect(overview.did).toBe(`did:bns:${NAME_STATE.name}`)
    expect(overview.isTopLevel).toBe(true)
    expect(overview.parent).toBeNull()
  })
})

describe('OwnerResolution', () => {
  it('authority_seq 变 bigint', () => {
    const owner = mapOwnerResolution(payload<WireOwnerResolution>('resolveOwner'))
    expect(typeof owner.authoritySeq).toBe('bigint')
    expect(owner.source).toBe('asset_owner_fallback')
  })
})

describe('文档', () => {
  it('inline 文档解码为文本与 JSON', () => {
    const result = mapResolveResult(RESOLVED)
    const decoded = decodeInlineDocument(result.documentState.document)
    expect(decoded.isInline).toBe(true)
    expect(decoded.byteLength).toBeGreaterThan(0)
    expect(decoded.json).toMatchObject({ name: RESOLVED.name_state.name })
  })

  it('payment_target 在投影里可能是空字符串而不是 zero address', () => {
    // 线上真实数据就是 ""，视图不能直接当地址渲染。
    expect(RESOLVED.document_state.payment_target).toBe('')
    expect(mapResolveResult(RESOLVED).documentState.paymentTarget).toBe('')
  })

  it('活跃文档的派生状态与 raw 一致', () => {
    const result = mapResolveResult(RESOLVED)
    expect(result.status).toBe('active')
    expect(deriveDocumentStatus(result, result.nameState.expireAt - 1n)).toBe('active')
  })

  it('名称 tombstoned 时所有文档都跟着 tombstoned', () => {
    const result = mapResolveResult(RESOLVED)
    const tombstoned = { ...result, nameState: { ...result.nameState, status: 'tombstoned' as const } }
    expect(deriveDocumentStatus(tombstoned, 0n)).toBe('tombstoned')
  })

  it('名称 raw status 已是 expired/released 时，文档派生为 expired', () => {
    const result = mapResolveResult(RESOLVED)
    for (const status of ['expired', 'released'] as const) {
      expect(deriveDocumentStatus({ ...result, nameState: { ...result.nameState, status } }, 0n)).toBe('expired')
    }
  })

  it('文档自身 expire_at 到期时派生为 expired', () => {
    const result = mapResolveResult(RESOLVED)
    const expiring = {
      ...result,
      documentState: { ...result.documentState, expireAt: 1_000n },
    }
    expect(deriveDocumentStatus(expiring, 999n)).toBe('active')
    expect(deriveDocumentStatus(expiring, 1_000n)).toBe('expired')
  })

  it('名称只是“时间上过期”（raw 仍是 active）时，文档仍然是 active', () => {
    // 与 bns-server 的 did_resolver_document_status 完全一致：
    // 它只看名称的 raw status 和文档自身的 expire_at，不看名称的 expire_at。
    // 名称的“有效期已过”只在名称层面派生展示，不会连坐下面的文档。
    const result = mapResolveResult(RESOLVED)
    expect(result.documentState.expireAt).toBe(0n)
    expect(deriveDocumentStatus(result, result.nameState.expireAt + 1n)).toBe('active')
  })

  it('migrated_to 且目标是 DID 时派生为 migrated', () => {
    const result = mapResolveResult(RESOLVED)
    const migrated = { ...result, aliasKind: 'migrated_to' as const, aliasTargetDid: 'did:web:x.dev' }
    expect(deriveDocumentStatus(migrated, 0n)).toBe('migrated')
  })

  it('migrated_to 但目标不是 DID 时忽略 alias', () => {
    // 与 bns-server 的实现一致：迁移结论必须能带上 migrationTarget，否则降级。
    const result = mapResolveResult(RESOLVED)
    const broken = { ...result, aliasKind: 'migrated_to' as const, aliasTargetDid: 'not-a-did' }
    expect(deriveDocumentStatus(broken, result.nameState.expireAt - 1n)).toBe('active')
  })
})

describe('事件', () => {
  const wire = payload<WireEventLogRecord[]>('listEvents')

  it('全部事件都能映射', () => {
    const records = wire.map(mapEventRecord)
    expect(records).toHaveLength(wire.length)
    expect(records.every((r) => typeof r.seq === 'bigint')).toBe(true)
  })

  it('按内层 event.type 判别，并抽出名称', () => {
    const registered = wire.map(mapEventRecord).find((r) => r.event.type === 'name_registered')
    expect(registered).toBeDefined()
    if (registered?.event.type === 'name_registered') {
      expect(typeof registered.event.data.nameSeq).toBe('bigint')
      expect(registered.name).toBe(registered.event.data.name)
    }
  })

  it('document_published 的 version 是 bigint', () => {
    const published = wire.map(mapEventRecord).find((r) => r.event.type === 'document_published')
    if (published?.event.type === 'document_published') {
      expect(typeof published.event.data.version).toBe('bigint')
      expect(published.event.data.docType.length).toBeGreaterThan(0)
    }
  })

  it('线上出现过的事件类型都在联合类型内', () => {
    const types = new Set(wire.map((r) => r.event.type))
    expect(types.size).toBeGreaterThan(1)
    for (const record of wire) expect(() => mapEventRecord(record)).not.toThrow()
  })
})

describe('分页与交易状态', () => {
  it('NamePage', () => {
    const page = mapNamePage(payload<WireNamePage>('queryByAddr'))
    expect(page.names.length).toBeGreaterThan(0)
    expect(page.nextCursor).toBeNull()
  })

  it('tx not_found 的 block_number 是 null', () => {
    const state = mapTxState(payload<WireTxState>('queryTxStateNotFound'))
    expect(state.state).toBe('not_found')
    expect(state.blockNumber).toBeNull()
    expect(state.confirmations).toBe(0n)
  })
})

describe('AuthorityKeyView', () => {
  const base: AuthorityKey = {
    kid: `0x${'1'.repeat(64)}`,
    verificationMethod: `0x${'0'.repeat(64)}`,
    keyData: Uint8Array.from(Array.from({ length: 20 }, (_, i) => i + 1)),
    purposes: 1,
    validFrom: 100n,
    validUntil: 0n,
    status: 'active',
    metadataHash: `0x${'0'.repeat(64)}`,
  }

  it('20 字节 key_data 还原成地址', () => {
    const view = toAuthorityKeyView(base, 200n)
    expect(view.addressFromKeyData).toBe('0x0102030405060708090a0b0c0d0e0f1011121314')
    expect(view.purposeFlags).toEqual({ authentication: true, recovery: false, signDocument: false })
    expect(view.usableNow).toBe(true)
  })

  it('非 20 字节不还原地址', () => {
    const view = toAuthorityKeyView({ ...base, keyData: Uint8Array.from([1, 2, 3]) }, 200n)
    expect(view.addressFromKeyData).toBeNull()
  })

  it('valid_until = 0 表示无上限，其他值参与窗口判断', () => {
    expect(toAuthorityKeyView({ ...base, validUntil: 150n }, 200n).usableNow).toBe(false)
    expect(toAuthorityKeyView({ ...base, validUntil: 300n }, 200n).usableNow).toBe(true)
    expect(toAuthorityKeyView(base, 50n).usableNow).toBe(false)
  })

  it('revoked 的 key 不可用', () => {
    expect(toAuthorityKeyView({ ...base, status: 'revoked' }, 200n).usableNow).toBe(false)
  })

  it('位掩码组合', () => {
    const view = toAuthorityKeyView({ ...base, purposes: 1 | 4 }, 200n)
    expect(view.purposeFlags).toEqual({ authentication: true, recovery: false, signDocument: true })
  })
})
