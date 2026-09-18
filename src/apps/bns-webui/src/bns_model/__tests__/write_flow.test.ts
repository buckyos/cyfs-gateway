/**
 * 写路径：写闸门、授权预检、guard 重读、提交拦截。
 */

import { describe, expect, it } from 'vitest'

import { SessionModel } from '../models/session_model'
import { ReadRepository } from '../services/read_repository'
import { mapSystemInfo } from '../services/mapper'
import { assessAuthority, buildGuard, describeAuthorityPath } from '../write/authority'
import { EMPTY_GUARD, PUBLIC_AUTHORITY, WRITE_INTENT_META, type WriteIntent } from '../write/intents'
import { WriteFlow } from '../write/write_flow'
import { toAuthorityKeyView, mapNameState } from '../services/mapper'
import { MODEL_ERROR_CODE } from '../types/errors'
import {
  FakeBnsServerApi,
  FakeWallet,
  LIVE_NAME_STATE,
  LIVE_SYSTEM_INFO,
  fakeClock,
  fakeCodec,
  testConfig,
} from './fakes'
import type { AuthorityKey, OwnerResolution } from '../types/domain'

const NAME = LIVE_NAME_STATE.name
const ASSET_OWNER = LIVE_NAME_STATE.asset_owner
const CHAIN_ID = LIVE_SYSTEM_INFO.chain_id

/** 生产口径：合约地址由构建期钉死，与 system.info 逐字比对。 */
function readySession(overrides: { chainId?: number; address?: string | null } = {}) {
  const model = new SessionModel(null, LIVE_SYSTEM_INFO.contract_address)
  model.setHealth(true)
  model.setSystemInfo(mapSystemInfo(LIVE_SYSTEM_INFO))
  model.setWallet({
    connected: overrides.address !== null,
    address: overrides.address === undefined ? ASSET_OWNER : overrides.address,
    chainId: overrides.chainId ?? CHAIN_ID,
    providerId: 'fake',
  })
  return model
}

describe('写闸门', () => {
  it('初始状态不允许写', () => {
    const model = new SessionModel(null, null)
    expect(model.state.writeGate.allowed).toBe(false)
    expect(model.state.network).toBe('unknown')
  })

  it('server 不可达 -> 阻断', () => {
    const model = new SessionModel(null, null)
    model.setHealth(false)
    expect(model.state.network).toBe('server_down')
    expect(model.state.writeGate.allowed).toBe(false)
  })

  it('ready=false -> 阻断', () => {
    const model = new SessionModel(null, null)
    model.setHealth(true)
    model.setSystemInfo({ ...mapSystemInfo(LIVE_SYSTEM_INFO), ready: false })
    expect(model.state.network).toBe('server_not_ready')
  })

  it('默认 pinned 但没配合约地址 -> 只读，理由指向构建配置', () => {
    // 合约地址决定用户的签名打给谁，没有锚点就等于完全信任 bns-server。
    const model = new SessionModel(null, null)
    model.setHealth(true)
    model.setSystemInfo(mapSystemInfo(LIVE_SYSTEM_INFO))
    expect(model.state.contractPinned).toBe(false)
    expect(model.state.network).toBe('contract_unpinned')
    expect(model.state.writeGate.allowed).toBe(false)
    expect(model.state.writeGate.reason).toMatch(/expectedContractAddress/)
  })

  it('显式选择 contractTrust: server 时放行（仅开发用）', () => {
    const model = new SessionModel(null, null, () => 1, 'server')
    model.setHealth(true)
    model.setSystemInfo(mapSystemInfo(LIVE_SYSTEM_INFO))
    model.setWallet({ connected: true, address: ASSET_OWNER, chainId: CHAIN_ID, providerId: 'f' })
    expect(model.state.contractPinned).toBeNull()
    expect(model.state.network).toBe('matched')
    expect(model.state.writeGate.allowed).toBe(true)
  })

  it('钉死的地址与 system.info 一致时正常放行', () => {
    expect(readySession().state.contractPinned).toBe(true)
    expect(readySession().state.network).toBe('matched')
  })

  it('未连钱包 -> 只读', () => {
    const model = readySession({ address: null })
    expect(model.state.network).toBe('no_wallet')
    expect(model.state.writeGate.canSwitchChain).toBe(false)
  })

  it('链不一致 -> 阻断，但提示可切换', () => {
    const model = readySession({ chainId: CHAIN_ID + 1 })
    expect(model.state.network).toBe('chain_mismatch')
    expect(model.state.writeGate.allowed).toBe(false)
    expect(model.state.writeGate.canSwitchChain).toBe(true)
  })

  it('部署配置与 system.info 不一致 -> 阻断全部写操作，且不可通过切链解决', () => {
    const model = new SessionModel(CHAIN_ID + 99, LIVE_SYSTEM_INFO.contract_address)
    model.setHealth(true)
    model.setSystemInfo(mapSystemInfo(LIVE_SYSTEM_INFO))
    model.setWallet({ connected: true, address: ASSET_OWNER, chainId: CHAIN_ID, providerId: 'f' })
    expect(model.state.network).toBe('config_mismatch')
    expect(model.state.writeGate.canSwitchChain).toBe(false)
    expect(model.state.configMismatch).toMatch(/部署配置期望 chain/)
  })

  it('contract 地址不一致也阻断', () => {
    const model = new SessionModel(null, `0x${'9'.repeat(40)}`)
    model.setHealth(true)
    model.setSystemInfo(mapSystemInfo(LIVE_SYSTEM_INFO))
    expect(model.state.configMismatch).toMatch(/Proxy/)
  })

  it('全部匹配时放行，assertWritable 给出 chainId / contract / from', () => {
    const model = readySession()
    expect(model.state.writeGate.allowed).toBe(true)
    expect(model.assertWritable()).toEqual({
      chainId: CHAIN_ID,
      contractAddress: LIVE_SYSTEM_INFO.contract_address,
      from: ASSET_OWNER,
    })
  })

  it('不允许写时 assertWritable 抛错并带原因', () => {
    const model = readySession({ chainId: CHAIN_ID + 1 })
    expect(() => model.assertWritable()).toThrowError(/不一致/)
  })
})

describe('授权预检', () => {
  const chainOwner: OwnerResolution = {
    effectiveOwner: { kind: 'chain_account', value: ASSET_OWNER },
    source: 'asset_owner_fallback',
    authorityRoot: `0x${'0'.repeat(64)}`,
    authoritySeq: 0n,
  }

  it('顶级名称公开注册走 public 路径', () => {
    const assessment = assessAuthority({
      nameState: null,
      owner: null,
      walletAddress: ASSET_OWNER,
      ownerAuthorityKeys: [],
      operation: 'register_name',
      isPublicRegistration: true,
    })
    expect(assessment.recommended).toEqual({ kind: 'public' })
    expect(assessment.canAttempt).toBe(true)
  })

  it('未连钱包时没有任何路径', () => {
    const assessment = assessAuthority({
      nameState: null,
      owner: chainOwner,
      walletAddress: null,
      ownerAuthorityKeys: [],
      operation: 'publish_document',
    })
    expect(assessment.canAttempt).toBe(false)
    expect(assessment.notes.join()).toMatch(/未连接钱包/)
  })

  it('钱包地址等于 effective owner -> chain_account_owner', () => {
    const assessment = assessAuthority({
      nameState: mapNameState(LIVE_NAME_STATE),
      owner: chainOwner,
      walletAddress: ASSET_OWNER.toUpperCase(),
      ownerAuthorityKeys: [],
      operation: 'publish_document',
    })
    expect(assessment.recommended).toEqual({ kind: 'chain_account_owner', address: ASSET_OWNER.toUpperCase() })
  })

  it('钱包不是 owner 时给出可解释的拒绝理由', () => {
    const assessment = assessAuthority({
      nameState: mapNameState(LIVE_NAME_STATE),
      owner: chainOwner,
      walletAddress: `0x${'2'.repeat(40)}`,
      ownerAuthorityKeys: [],
      operation: 'publish_document',
    })
    expect(assessment.canAttempt).toBe(false)
    expect(assessment.manualOnly).toBe(true)
    expect(assessment.notes.join()).toMatch(/与当前钱包不一致/)
  })

  it('effective owner 是 BNS name 时按 authority key 匹配', () => {
    const wallet = '0x0102030405060708090a0b0c0d0e0f1011121314'
    const key: AuthorityKey = {
      kid: `0x${'a'.repeat(64)}`,
      verificationMethod: `0x${'0'.repeat(64)}`,
      keyData: Uint8Array.from(Array.from({ length: 20 }, (_, i) => i + 1)),
      purposes: 1,
      validFrom: 0n,
      validUntil: 0n,
      status: 'active',
      metadataHash: `0x${'0'.repeat(64)}`,
    }
    const assessment = assessAuthority({
      nameState: mapNameState(LIVE_NAME_STATE),
      owner: {
        effectiveOwner: { kind: 'bns_name', value: 'studio' },
        source: 'explicit_semantic_owner',
        authorityRoot: `0x${'0'.repeat(64)}`,
        authoritySeq: 3n,
      },
      walletAddress: wallet,
      ownerAuthorityKeys: [toAuthorityKeyView(key, 100n)],
      operation: 'publish_document',
    })
    expect(assessment.recommended).toEqual({ kind: 'bns_name_owner', ownerName: 'studio', kid: key.kid })
  })

  it('没有 authentication 位的 key 不能作为授权路径', () => {
    const wallet = '0x0102030405060708090a0b0c0d0e0f1011121314'
    const recoveryOnly: AuthorityKey = {
      kid: `0x${'b'.repeat(64)}`,
      verificationMethod: `0x${'0'.repeat(64)}`,
      keyData: Uint8Array.from(Array.from({ length: 20 }, (_, i) => i + 1)),
      purposes: 2, // 只有 recovery，合约不认
      validFrom: 0n,
      validUntil: 0n,
      status: 'active',
      metadataHash: `0x${'0'.repeat(64)}`,
    }
    const assessment = assessAuthority({
      nameState: null,
      owner: {
        effectiveOwner: { kind: 'bns_name', value: 'studio' },
        source: 'explicit_semantic_owner',
        authorityRoot: `0x${'0'.repeat(64)}`,
        authoritySeq: 1n,
      },
      walletAddress: wallet,
      ownerAuthorityKeys: [toAuthorityKeyView(recoveryOnly, 100n)],
      operation: 'publish_document',
    })
    expect(assessment.canAttempt).toBe(false)
    expect(assessment.notes.join()).toMatch(/没有「列出全部 authority key」接口|authentication/)
  })

  it('结论里必须写明最终授权由合约判定', () => {
    const assessment = assessAuthority({
      nameState: mapNameState(LIVE_NAME_STATE),
      owner: chainOwner,
      walletAddress: ASSET_OWNER,
      ownerAuthorityKeys: [],
      operation: 'renew_name',
    })
    expect(assessment.notes.join()).toMatch(/最终授权由合约按 msg.sender 判定/)
  })

  it('路径描述可读', () => {
    expect(describeAuthorityPath({ kind: 'public' })).toMatch(/公开注册/)
    expect(describeAuthorityPath({ kind: 'chain_account_owner', address: ASSET_OWNER })).toContain(ASSET_OWNER)
  })
})

describe('MutationGuard', () => {
  it('取当前 name_seq 与父名称 name_seq', () => {
    const state = mapNameState(LIVE_NAME_STATE)
    expect(buildGuard({ nameState: state })).toEqual({
      expectedNameSeq: state.nameSeq,
      expectedParentNameSeq: 0n,
    })
    expect(buildGuard({ nameState: state, parentState: { ...state, nameSeq: 9n } })).toEqual({
      expectedNameSeq: state.nameSeq,
      expectedParentNameSeq: 9n,
    })
  })

  it('名称不存在时是 0', () => {
    expect(buildGuard({})).toEqual(EMPTY_GUARD)
  })
})

describe('WriteFlow.prepare', () => {
  function flowWith(walletOptions: ConstructorParameters<typeof FakeWallet>[0] = {}) {
    const api = new FakeBnsServerApi()
    const repo = new ReadRepository(api.asApi(), testConfig(), fakeClock())
    const wallet = new FakeWallet(walletOptions)
    const flow = new WriteFlow(repo, () => wallet, () => fakeCodec(), () => 1_700_000_000_000)
    return { api, repo, wallet, flow }
  }

  const publishIntent: WriteIntent = {
    kind: 'publish_document',
    name: NAME,
    docType: 'owner',
    expectedVersion: 1n,
    document: { storageType: 'inline', uri: '', inlineDocument: new Uint8Array([1]), contentHash: '', schema: '', codec: '', extraHash: '' },
    controller: { kind: 'unset', value: '' },
    beneficiary: { kind: 'unset', value: '' },
    paymentTarget: '',
    expireAt: 0n,
    controllerPolicyHash: '',
    paymentPolicyHash: '',
    splitPolicyHash: '',
    pricePolicyHash: '',
    rightsPolicyHash: '',
    authority: PUBLIC_AUTHORITY,
    guard: EMPTY_GUARD,
  }

  const context = {
    chainId: CHAIN_ID,
    contractAddress: LIVE_SYSTEM_INFO.contract_address,
    from: ASSET_OWNER,
  }

  it('弹钱包之前重新读取 name_seq 刷新 guard', async () => {
    const { flow, api } = flowWith()
    const prepared = await flow.prepare(publishIntent, { kind: 'chain_account_owner', address: ASSET_OWNER }, context)
    expect(api.calls.queryNameState).toBeGreaterThanOrEqual(1)
    expect(prepared.guard.expectedNameSeq).toBe(BigInt(LIVE_NAME_STATE.name_seq))
    expect(prepared.guardRefreshedAt).toBe(1_700_000_000_000)
  })

  it('value 恒为 0，目标是 system.info 给的 Proxy 地址', async () => {
    const { flow } = flowWith()
    const prepared = await flow.prepare(publishIntent, { kind: 'chain_account_owner', address: ASSET_OWNER }, context)
    expect(prepared.request.value).toBe('0x0')
    expect(prepared.request.to).toBe(LIVE_SYSTEM_INFO.contract_address)
    expect(prepared.summary).toMatchObject({
      method: 'publishDocument',
      chainId: CHAIN_ID,
      value: '0x0',
      contractAddress: LIVE_SYSTEM_INFO.contract_address,
    })
  })

  it('算出收敛期望：文档版本 +1', async () => {
    const { flow } = flowWith()
    const prepared = await flow.prepare(publishIntent, { kind: 'chain_account_owner', address: ASSET_OWNER }, context)
    expect(prepared.expectation).toEqual({
      kind: 'document_version_at_least',
      name: NAME,
      docType: 'owner',
      value: 2n,
    })
  })

  it('续期的收敛期望是 expire_at 变大', async () => {
    const { flow } = flowWith()
    const prepared = await flow.prepare(
      { kind: 'renew_name', name: NAME, duration: 100n, authority: PUBLIC_AUTHORITY, guard: EMPTY_GUARD },
      { kind: 'chain_account_owner', address: ASSET_OWNER },
      context,
    )
    expect(prepared.expectation).toEqual({
      kind: 'expire_at_greater_than',
      name: NAME,
      value: BigInt(LIVE_NAME_STATE.expire_at),
    })
  })

  it('estimateGas 失败时记录模拟错误但不中断准备', async () => {
    const { flow } = flowWith({
      estimateGas: async () => {
        throw Object.assign(new Error('execution reverted'), { data: '0x1234' })
      },
    })
    const prepared = await flow.prepare(publishIntent, { kind: 'chain_account_owner', address: ASSET_OWNER }, context)
    expect(prepared.gasEstimate).toBeNull()
    expect(prepared.simulationError).not.toBeNull()
    expect(prepared.simulationError?.raw).toBe('0x1234')
  })

  it('模拟解出 guard 过期时标记 staleGuard，并拒绝提交', async () => {
    const api = new FakeBnsServerApi()
    const repo = new ReadRepository(api.asApi(), testConfig(), fakeClock())
    const wallet = new FakeWallet({
      estimateGas: async () => {
        throw Object.assign(new Error('reverted'), { data: '0xdead' })
      },
    })
    const codec = fakeCodec({
      decodeError: () => ({ name: 'StaleNameSeq', args: [NAME, 1n, 2n], raw: '0xdead' }),
    })
    const flow = new WriteFlow(repo, () => wallet, () => codec)
    const prepared = await flow.prepare(publishIntent, { kind: 'chain_account_owner', address: ASSET_OWNER }, context)
    expect(prepared.staleGuard).toBe(true)
    // 不自动重放：必须重读后由用户重新确认。
    await expect(flow.submit(prepared)).rejects.toThrowError(/不做自动重放/)
    expect(wallet.sent).toHaveLength(0)
  })

  it('没有注入 ABI 编码器时明确报错', async () => {
    const api = new FakeBnsServerApi()
    const repo = new ReadRepository(api.asApi(), testConfig(), fakeClock())
    const flow = new WriteFlow(repo, () => new FakeWallet(), () => null)
    await expect(
      flow.prepare(publishIntent, { kind: 'chain_account_owner', address: ASSET_OWNER }, context),
    ).rejects.toThrowError(/CalldataCodec/)
  })
})

describe('WriteFlow.submit 的最后一道防线', () => {
  const context = {
    chainId: CHAIN_ID,
    contractAddress: LIVE_SYSTEM_INFO.contract_address,
    from: ASSET_OWNER,
  }
  const intent: WriteIntent = {
    kind: 'renew_name',
    name: NAME,
    duration: 100n,
    authority: PUBLIC_AUTHORITY,
    guard: EMPTY_GUARD,
  }

  async function prepared(wallet: FakeWallet) {
    const api = new FakeBnsServerApi()
    const repo = new ReadRepository(api.asApi(), testConfig(), fakeClock())
    const flow = new WriteFlow(repo, () => wallet, () => fakeCodec())
    return { flow, prep: await flow.prepare(intent, { kind: 'public' }, context) }
  }

  it('准备之后用户切换账户 -> 拒绝提交', async () => {
    const wallet = new FakeWallet({ address: ASSET_OWNER })
    const { flow, prep } = await prepared(wallet)
    wallet.setState({ address: `0x${'3'.repeat(40)}` })
    await expect(flow.submit(prep)).rejects.toThrowError(/账户已切换/)
    expect(wallet.sent).toHaveLength(0)
  })

  it('准备之后用户切换网络 -> 拒绝提交', async () => {
    const wallet = new FakeWallet({ address: ASSET_OWNER })
    const { flow, prep } = await prepared(wallet)
    wallet.setState({ chainId: CHAIN_ID + 1 })
    await expect(flow.submit(prep)).rejects.toThrowError(/不一致/)
  })

  it('钱包断开 -> 拒绝提交', async () => {
    const wallet = new FakeWallet({ address: ASSET_OWNER })
    const { flow, prep } = await prepared(wallet)
    await wallet.disconnect()
    await expect(flow.submit(prep)).rejects.toThrowError(/钱包已断开/)
  })

  it('一切正常时返回投递结果（含走了哪条路径）', async () => {
    const wallet = new FakeWallet({ address: ASSET_OWNER })
    const { flow, prep } = await prepared(wallet)
    await expect(flow.submit(prep)).resolves.toEqual({
      txHash: `0x${'a'.repeat(64)}`,
      mode: 'wallet_direct',
      preparedNonce: null,
    })
    expect(wallet.sent).toHaveLength(1)
  })

  it('默认投递路径是直连，且写进确认摘要', async () => {
    const wallet = new FakeWallet({ address: ASSET_OWNER })
    const { flow, prep } = await prepared(wallet)
    expect(flow.deliveryMode).toBe('wallet_direct')
    expect(prep.summary.deliveryMode).toBe('wallet_direct')
    expect(prep.delivery.readiness.ready).toBe(true)
  })

  it('用户拒绝签名被识别为 WALLET_REJECTED 而不是故障', async () => {
    const wallet = new FakeWallet({
      address: ASSET_OWNER,
      sendTransaction: async () => {
        throw { code: 4001, message: 'User rejected the request.' }
      },
    })
    const { flow, prep } = await prepared(wallet)
    const error = await flow.submit(prep).catch((e: unknown) => e)
    expect((error as { code: string }).code).toBe(MODEL_ERROR_CODE.WALLET_REJECTED)
  })
})

describe('写方法元数据', () => {
  it('高风险操作被标记，UI 必须二次确认', () => {
    for (const kind of ['transfer_name', 'release_name', 'revoke_document', 'set_did_alias'] as const) {
      expect(WRITE_INTENT_META[kind].highRisk, kind).toBe(true)
    }
  })

  it('publishLogCheckpoint 不进普通用户界面', () => {
    // issuer 未与 msg.sender 绑定（PRD 6.4.6）。
    expect(WRITE_INTENT_META.publish_log_checkpoint.userFacing).toBe(false)
  })

  it('renewName 不需要 guard', () => {
    expect(WRITE_INTENT_META.renew_name.requiresGuard).toBe(false)
  })

  it('二级名称注册需要父名称 guard', () => {
    expect(WRITE_INTENT_META.register_name.requiresParentGuard).toBe(true)
  })
})
