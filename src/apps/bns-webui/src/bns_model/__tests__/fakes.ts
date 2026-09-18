/**
 * 测试替身。
 *
 * FakeBnsServerApi 的默认返回值直接来自线上 fixture，
 * 所以「假 server」的报文形状和真 server 一致。
 */

import { resolveConfig, type BnsModelConfig } from '../config'
import type { BnsServerApi } from '../services/bns_server_api'
import type { NowProvider } from '../services/read_repository'
import { BnsError } from '../types/errors'
import type {
  WireAuthorityKey,
  WireAuthoritySetState,
  WireDocumentState,
  WireEventLogRecord,
  WireLogCheckpoint,
  WireNamePage,
  WireNameState,
  WireOwnerResolution,
  WireResolveResult,
  WireSystemInfo,
  WireTxState,
} from '../types/wire'
import type { CalldataCodec, SendTxRequest, StoragePort, WalletAccountState, WalletPort } from '../ports'
import type { Unsubscribe } from '../infra/observable'
import { payload } from './fixtures'

export const LIVE_NAME_STATE = payload<WireNameState>('queryNameState')
export const LIVE_OWNER = payload<WireOwnerResolution>('resolveOwner')
export const LIVE_AUTHORITY_SET = payload<WireAuthoritySetState>('getAuthoritySet')
export const LIVE_RESOLVED = payload<WireResolveResult>('resolveDocument')
export const LIVE_SYSTEM_INFO = payload<WireSystemInfo>('systemInfo')
export const LIVE_EVENTS = payload<WireEventLogRecord[]>('listEvents')

export interface FakeApiOptions {
  nameStates?: Record<string, WireNameState | null>
  documents?: Record<string, WireResolveResult | null>
  documentVersions?: Record<string, WireDocumentState | null>
  events?: WireEventLogRecord[]
  txStates?: Record<string, WireTxState>
  authorityKeys?: Record<string, WireAuthorityKey | null>
  namePage?: WireNamePage
  checkpoint?: WireLogCheckpoint | null
  healthy?: boolean
  systemInfo?: WireSystemInfo | (() => never)
}

/** 记录每个方法被调用的次数，用来验证缓存/去重/请求次数。 */
export class FakeBnsServerApi {
  readonly calls: Record<string, number> = {}
  private readonly options: FakeApiOptions

  constructor(options: FakeApiOptions = {}) {
    this.options = options
  }

  private hit(method: string): void {
    this.calls[method] = (this.calls[method] ?? 0) + 1
  }

  async health(): Promise<boolean> {
    this.hit('health')
    return this.options.healthy ?? true
  }

  async systemInfo(): Promise<WireSystemInfo> {
    this.hit('systemInfo')
    const value = this.options.systemInfo ?? LIVE_SYSTEM_INFO
    if (typeof value === 'function') value()
    return value as WireSystemInfo
  }

  async queryNameState(name: string): Promise<WireNameState | null> {
    this.hit('queryNameState')
    if (this.options.nameStates && name in this.options.nameStates) {
      return this.options.nameStates[name]
    }
    return name === LIVE_NAME_STATE.name ? LIVE_NAME_STATE : null
  }

  async resolveOwner(name: string): Promise<WireOwnerResolution> {
    this.hit('resolveOwner')
    const state = await this.queryNameState(name)
    if (state === null) {
      throw BnsError.registry({ code: 'NAME_NOT_FOUND', message: `name \`${name}\` was not found`, name })
    }
    return LIVE_OWNER
  }

  async getAuthoritySet(name: string): Promise<WireAuthoritySetState> {
    this.hit('getAuthoritySet')
    return { ...LIVE_AUTHORITY_SET, name }
  }

  async getAuthorityKey(name: string, kid: string): Promise<WireAuthorityKey | null> {
    this.hit('getAuthorityKey')
    return this.options.authorityKeys?.[`${name}:${kid}`] ?? null
  }

  async resolveDocument(name: string, docType: string): Promise<WireResolveResult> {
    this.hit('resolveDocument')
    const key = `${name}:${docType}`
    if (this.options.documents && key in this.options.documents) {
      const value = this.options.documents[key]
      if (value === null) {
        throw BnsError.registry({
          code: 'DOCUMENT_NOT_FOUND',
          message: `document \`${key}\` was not found`,
          name,
          doc_type: docType,
        })
      }
      return value
    }
    if (name === LIVE_RESOLVED.name_state.name && docType === LIVE_RESOLVED.document_state.doc_type) {
      return LIVE_RESOLVED
    }
    throw BnsError.registry({
      code: 'DOCUMENT_NOT_FOUND',
      message: `document \`${key}\` was not found`,
      name,
      doc_type: docType,
    })
  }

  async getDocumentVersion(name: string, docType: string, version: bigint): Promise<WireDocumentState | null> {
    this.hit('getDocumentVersion')
    return this.options.documentVersions?.[`${name}:${docType}:${version}`] ?? null
  }

  async queryNamesByAddress(_address: string, cursor: string | null, limit: number): Promise<WireNamePage> {
    this.hit('queryNamesByAddress')
    if (this.options.namePage) return this.options.namePage
    void cursor
    void limit
    return payload<WireNamePage>('queryByAddr')
  }

  async queryTxState(txHash: string): Promise<WireTxState> {
    this.hit('queryTxState')
    return (
      this.options.txStates?.[txHash] ?? {
        tx_hash: txHash,
        state: 'not_found',
        block_number: null,
        confirmations: 0,
      }
    )
  }

  async listEvents(fromSeq: bigint, limit: number): Promise<WireEventLogRecord[]> {
    this.hit('listEvents')
    const all = this.options.events ?? LIVE_EVENTS
    return all.filter((record) => BigInt(record.seq) >= fromSeq).slice(0, limit)
  }

  async latestCheckpoint(): Promise<WireLogCheckpoint | null> {
    this.hit('latestCheckpoint')
    return this.options.checkpoint ?? null
  }

  /** 默认拒绝：普通写路径不得使用；中继测试会整体替换掉它。 */
  advanced: {
    submitRawTx: (rawTx: string) => Promise<{ tx_hash: string }>
    prepareTx: (from: string, calldata: string) => Promise<unknown>
  } = {
    submitRawTx: async () => {
      throw new Error('普通写路径不得使用 tx.submit_raw')
    },
    prepareTx: async () => {
      throw new Error('普通写路径不得使用 tx.prepare')
    },
  }

  asApi(): BnsServerApi {
    return this as unknown as BnsServerApi
  }
}

/** 生成 count 条 name_registered 事件，seq 从 1 开始（与线上一致）。 */
export function syntheticEvents(count: number, name = 'alice'): WireEventLogRecord[] {
  const template = LIVE_EVENTS[0]
  return Array.from({ length: count }, (_, index) => ({
    ...template,
    seq: index + 1,
    event: {
      type: 'name_registered' as const,
      data: {
        name: index % 2 === 0 ? name : 'other',
        asset_owner: '0x' + '1'.repeat(40),
        expire_at: 1,
        lineage_epoch: 0,
        name_seq: 1,
      },
    },
  }))
}

export function testConfig(overrides: Partial<BnsModelConfig> = {}): BnsModelConfig {
  return resolveConfig({ serverUrl: 'http://bns.test', readCacheTtlMs: 0, ...overrides })
}

/** 可控时钟，避免测试依赖真实时间。 */
export function fakeClock(startMs = 1_700_000_000_000): NowProvider & { advance(ms: number): void } {
  let current = startMs
  return {
    now: () => current,
    nowSeconds: () => BigInt(Math.floor(current / 1000)),
    advance: (ms: number) => {
      current += ms
    },
  }
}

export function memoryStore(): StoragePort {
  const map = new Map<string, string>()
  return {
    get: (key) => map.get(key) ?? null,
    set: (key, value) => void map.set(key, value),
    remove: (key) => void map.delete(key),
  }
}

export interface FakeWalletOptions {
  address?: string
  chainId?: number
  estimateGas?: () => Promise<bigint>
  sendTransaction?: () => Promise<string>
}

export class FakeWallet implements WalletPort {
  private state: WalletAccountState
  private readonly listeners = new Set<(state: WalletAccountState) => void>()
  readonly sent: unknown[] = []

  constructor(private readonly options: FakeWalletOptions = {}) {
    this.state = {
      connected: true,
      address: options.address ?? '0x71c7656ec7ab88b098defb751b7401b5f6d8976f',
      chainId: options.chainId ?? 31337,
      providerId: 'fake',
    }
  }

  getState(): WalletAccountState {
    return this.state
  }

  setState(next: Partial<WalletAccountState>): void {
    this.state = { ...this.state, ...next }
    for (const listener of this.listeners) listener(this.state)
  }

  subscribe(listener: (state: WalletAccountState) => void): Unsubscribe {
    this.listeners.add(listener)
    return () => void this.listeners.delete(listener)
  }

  async listProviders() {
    return [{ id: 'fake', name: 'Fake Wallet', icon: null, kind: 'injected' as const }]
  }

  async connect() {
    return this.state
  }

  async disconnect() {
    this.setState({ connected: false, address: null, chainId: null })
  }

  async switchChain(chainId: number) {
    this.setState({ chainId })
  }

  async addChain() {}

  async estimateGas() {
    if (this.options.estimateGas) return this.options.estimateGas()
    return 120_000n
  }

  async simulate() {
    return '0x'
  }

  async sendTransaction(request: SendTxRequest): Promise<string> {
    this.sent.push(request)
    if (this.options.sendTransaction) return this.options.sendTransaction()
    return `0x${'a'.repeat(64)}`
  }
}

/** 不做真 ABI 编码，只把 intent 摘要塞进 calldata，够验证流程。 */
export function fakeCodec(overrides: Partial<CalldataCodec> = {}): CalldataCodec {
  return {
    encode: (intent) => `0x${Buffer.from(intent.kind).toString('hex')}` as `0x${string}`,
    decodeError: (data) => ({ name: 'UndecodedRevert', args: [], raw: data }),
    ...overrides,
  }
}
