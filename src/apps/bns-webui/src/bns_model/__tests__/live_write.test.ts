/**
 * Live 写路径契约验证 + UI 种子数据工具（显式 opt-in，会写测试链！）。
 *
 * ```bash
 * pnpm run seed:live     # = BNS_LIVE_WRITE_URL=https://bns.buckyos.ai vitest run 本文件
 * ```
 *
 * 做两件事：
 * 1. 验证 `write/abi.ts` 的 human-readable ABI 与 `toAbiArgs` 编码能被**真实合约**接受
 *    （单测只对齐了 IBns.sol 的签名文本，这里对齐链上字节码）；
 * 2. 用临时账号在测试链上留下一组有代表性的名称状态，供 live 模式 UI 走查：
 *    注册顶级名 -> 发布 zone 文档 -> 注册二级名 -> 转移二级名（semantic 保持 Unset，
 *    制造「仅持有」状态）-> 由无关账号公共续期。
 *
 * 投递走 PRD 8.5.3 的中继测试路径：tx.prepare 取 nonce/gas/fee，
 * 本地 eth_signTransaction（viem 临时密钥，链无手续费、无需注资），tx.submit_raw 广播。
 * 每步核对 tx.prepare 返回的 chain_id / contract 与 system.info 锚定值一致后才签名。
 */

import { beforeAll, describe, expect, it } from 'vitest'
import { encodeFunctionData, parseAbi, type Abi, type Hex } from 'viem'
import { generatePrivateKey, privateKeyToAccount, type PrivateKeyAccount } from 'viem/accounts'

import { BNS_ABI_SOURCE, toAbiArgs } from '../write/abi'
import { buildCallAuthority } from '../write/authority'
import {
  EMPTY_GUARD,
  PUBLIC_AUTHORITY,
  UNSET_PRINCIPAL,
  WRITE_INTENT_META,
  defaultRegisterOptions,
  inlineDocumentRef,
  type WriteIntent,
} from '../write/intents'
import { sha256Hex, utf8ToBytes, ZERO_BYTES32 } from '../infra/codec'
import type {
  WireNameState,
  WirePrepareTxResp,
  WireResolveResult,
  WireRpcEnvelope,
  WireSystemInfo,
  WireTxState,
} from '../types/wire'

const LIVE_URL = process.env.BNS_LIVE_WRITE_URL ?? null

// ---------------------------------------------------------------------------
// 最小 kRPC / 投递工具
// ---------------------------------------------------------------------------

let seq = 0

async function krpc<T>(method: string, params: unknown): Promise<T> {
  seq += 1
  const response = await fetch(`${LIVE_URL}/kapi/bns`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ method, params, sys: [seq] }),
  })
  expect(response.ok, `${method} HTTP ${response.status}`).toBe(true)
  const body = (await response.json()) as { result?: WireRpcEnvelope<T>; error?: string }
  expect(body.error, `${method} kRPC error: ${body.error}`).toBeUndefined()
  const envelope = body.result as WireRpcEnvelope<T>
  if (!envelope.ok) {
    throw new Error(`${method} -> ${envelope.error?.code}: ${envelope.error?.message}`)
  }
  return envelope.result as T
}

// BNS_ABI_SOURCE 是运行期拼接的数组，元素类型是 union 而非字面量元组，
// viem 的类型级解析器因此无法在编译期消解 struct 引用；运行期解析完全正常。
const abi: Abi = parseAbi(BNS_ABI_SOURCE as unknown as string[])

function encodeIntent(intent: WriteIntent): Hex {
  return encodeFunctionData({
    abi,
    functionName: WRITE_INTENT_META[intent.kind].method,
    args: toAbiArgs(intent) as unknown[],
  })
}

let sysInfo: WireSystemInfo

/** prepare -> 核对锚定 -> 签名 -> submit_raw -> 轮询到 succeeded。 */
async function sendIntent(account: PrivateKeyAccount, intent: WriteIntent): Promise<string> {
  const calldata = encodeIntent(intent)
  const prep = await krpc<WirePrepareTxResp>('tx.prepare', {
    from: account.address,
    calldata,
  })
  // PRD 8.5.3：tx.prepare 返回值必须与会话锚定的链/合约一致，否则中止，不得照签。
  expect(prep.chain_id).toBe(sysInfo.chain_id)
  expect(prep.contract_address.toLowerCase()).toBe(sysInfo.contract_address.toLowerCase())

  const rawTx = await account.signTransaction({
    type: 'eip1559',
    chainId: prep.chain_id,
    nonce: prep.nonce,
    gas: BigInt(prep.gas_limit),
    maxFeePerGas: BigInt(prep.max_fee_per_gas),
    maxPriorityFeePerGas: BigInt(prep.max_priority_fee_per_gas),
    to: prep.contract_address as Hex,
    value: 0n,
    data: calldata,
  })
  const { tx_hash } = await krpc<{ tx_hash: string }>('tx.submit_raw', { raw_tx: rawTx })

  for (let attempt = 0; attempt < 40; attempt += 1) {
    const state = await krpc<WireTxState>('tx.query_state', { tx_hash })
    if (state.state === 'succeeded') return tx_hash
    if (state.state === 'reverted') {
      throw new Error(`tx ${tx_hash} reverted (${WRITE_INTENT_META[intent.kind].method})`)
    }
    await new Promise((resolve) => setTimeout(resolve, 1_200))
  }
  throw new Error(`tx ${tx_hash} 未在时限内确认`)
}

async function nameState(name: string): Promise<WireNameState | null> {
  return krpc<WireNameState | null>('name.query_state', { name })
}

/** 投影收敛等待：条件满足前轮询（indexer 有延迟，PRD G4）。 */
async function waitProjection(check: () => Promise<boolean>, label: string): Promise<void> {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    if (await check()) return
    await new Promise((resolve) => setTimeout(resolve, 1_500))
  }
  throw new Error(`投影未收敛：${label}`)
}

// ---------------------------------------------------------------------------
// 场景
// ---------------------------------------------------------------------------

const stamp = new Date()
  .toISOString()
  .replace(/[-:TZ.]/g, '')
  .slice(0, 14)
const TOP_NAME = `uiproto-${stamp}`
const SUB_NAME = `blog.${TOP_NAME}`
const DAY = 86_400n

const ownerKey = generatePrivateKey()
const holderKey = generatePrivateKey()
const owner = privateKeyToAccount(ownerKey)
const holder = privateKeyToAccount(holderKey)

/**
 * 测试链 faucet：anvil/foundry 默认助记词的 0 号账户（公开的 well-known 测试私钥，
 * 仅在本地/测试链有余额，不构成任何机密）。链本身有正常 base fee，
 * 「无需手续费」靠预置账户注资实现——临时账号先从这里各领 1 ETH。
 */
const faucet = privateKeyToAccount(
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
)

async function fundFromFaucet(to: Hex, amountWei: bigint): Promise<void> {
  // tx.prepare 的 estimateGas 需要一个不 revert 的 BNS 调用；续期任何 Active 名称都满足。
  // 这里只取它返回的 nonce（faucet 的 pending nonce）与链级 fee 建议。
  const probe = await krpc<WirePrepareTxResp>('tx.prepare', {
    from: faucet.address,
    calldata: encodeFunctionData({
      abi,
      functionName: 'renewName',
      args: ['buckyosdev', DAY],
    }),
  })
  const rawTx = await faucet.signTransaction({
    type: 'eip1559',
    chainId: probe.chain_id,
    nonce: probe.nonce,
    gas: 21_000n,
    maxFeePerGas: BigInt(probe.max_fee_per_gas),
    maxPriorityFeePerGas: BigInt(probe.max_priority_fee_per_gas),
    to,
    value: amountWei,
    data: '0x',
  })
  const { tx_hash } = await krpc<{ tx_hash: string }>('tx.submit_raw', { raw_tx: rawTx })
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const state = await krpc<WireTxState>('tx.query_state', { tx_hash })
    if (state.state === 'succeeded') return
    if (state.state === 'reverted') throw new Error(`faucet 转账 ${tx_hash} 回退`)
    await new Promise((resolve) => setTimeout(resolve, 1_000))
  }
  throw new Error(`faucet 转账 ${tx_hash} 未确认`)
}

describe.skipIf(!LIVE_URL)('live 写路径（中继投递）+ UI 种子数据', () => {
  beforeAll(async () => {
    sysInfo = await krpc<WireSystemInfo>('system.info', {})
    expect(sysInfo.ready).toBe(true)
    console.log(`\n== live seed 目标 ==`)
    console.log(`server   : ${LIVE_URL}`)
    console.log(`chain    : ${sysInfo.chain_id} · proxy ${sysInfo.contract_address}`)
    console.log(`owner A  : ${owner.address}`)
    console.log(`holder B : ${holder.address}`)
    console.log(`top name : ${TOP_NAME}`)
    console.log(`sub name : ${SUB_NAME}`)
    await fundFromFaucet(owner.address, 10n ** 18n)
    await fundFromFaucet(holder.address, 10n ** 18n)
    console.log(`faucet   : A、B 各注资 1 ETH 完成\n`)
  }, 90_000)

  it('A 公开注册顶级名称', async () => {
    const hash = await sendIntent(owner, {
      kind: 'register_name',
      name: TOP_NAME,
      assetOwner: owner.address,
      options: defaultRegisterOptions(365n * DAY, 30n * DAY),
      authorityUpdates: [],
      semanticOwnerAfterAuthority: UNSET_PRINCIPAL,
      controllerPolicy: [],
      controllerPolicyHash: ZERO_BYTES32,
      initialDocuments: [],
      authority: PUBLIC_AUTHORITY,
      guard: EMPTY_GUARD,
    })
    console.log(`registerName(${TOP_NAME}) tx = ${hash}`)
    await waitProjection(async () => (await nameState(TOP_NAME)) !== null, `${TOP_NAME} 出现`)
  })

  it('A 以 owner 身份发布 inline zone 文档', async () => {
    const content = utf8ToBytes(
      JSON.stringify({ did: `did:bns:${TOP_NAME}`, oods: [`ood1.${TOP_NAME}`], seeded_by: 'bns-webui live seed' }),
    )
    const state = await nameState(TOP_NAME)
    expect(state).not.toBeNull()
    const hash = await sendIntent(owner, {
      kind: 'publish_document',
      name: TOP_NAME,
      docType: 'zone',
      expectedVersion: 0n,
      document: inlineDocumentRef(content, await sha256Hex(content)),
      controller: UNSET_PRINCIPAL,
      beneficiary: UNSET_PRINCIPAL,
      paymentTarget: owner.address,
      expireAt: 0n,
      controllerPolicyHash: ZERO_BYTES32,
      paymentPolicyHash: ZERO_BYTES32,
      splitPolicyHash: ZERO_BYTES32,
      pricePolicyHash: ZERO_BYTES32,
      rightsPolicyHash: ZERO_BYTES32,
      authority: buildCallAuthority({ kind: 'chain_account_owner', address: owner.address }),
      guard: { expectedNameSeq: BigInt(state!.name_seq), expectedParentNameSeq: 0n },
    })
    console.log(`publishDocument(${TOP_NAME}/zone) tx = ${hash}`)
    await waitProjection(async () => {
      const resolved = await krpc<WireResolveResult | null>('document.resolve', {
        name: TOP_NAME,
        doc_type: 'zone',
      }).catch(() => null)
      return resolved !== null && resolved.document_state.version >= 1
    }, `${TOP_NAME}/zone v1`)
  })

  it('A 注册二级名称（父名称 owner 授权 + parent guard）', async () => {
    const parent = await nameState(TOP_NAME)
    expect(parent).not.toBeNull()
    const hash = await sendIntent(owner, {
      kind: 'register_name',
      name: SUB_NAME,
      assetOwner: owner.address,
      options: defaultRegisterOptions(365n * DAY, 30n * DAY),
      authorityUpdates: [],
      semanticOwnerAfterAuthority: UNSET_PRINCIPAL,
      controllerPolicy: [],
      controllerPolicyHash: ZERO_BYTES32,
      initialDocuments: [],
      authority: buildCallAuthority({ kind: 'chain_account_owner', address: owner.address }),
      guard: { expectedNameSeq: 0n, expectedParentNameSeq: BigInt(parent!.name_seq) },
    })
    console.log(`registerName(${SUB_NAME}) tx = ${hash}`)
    await waitProjection(async () => (await nameState(SUB_NAME)) !== null, `${SUB_NAME} 出现`)
  })

  it('A 把二级名称转给 B（semantic 保持 Unset -> 「仅持有」）', async () => {
    const state = await nameState(SUB_NAME)
    expect(state).not.toBeNull()
    const hash = await sendIntent(owner, {
      kind: 'transfer_name',
      name: SUB_NAME,
      newAssetOwner: holder.address,
      newSemanticOwner: UNSET_PRINCIPAL,
      atomicDocumentUpdates: [],
      authority: buildCallAuthority({ kind: 'chain_account_owner', address: owner.address }),
      guard: { expectedNameSeq: BigInt(state!.name_seq), expectedParentNameSeq: 0n },
    })
    console.log(`transferName(${SUB_NAME} -> ${holder.address}) tx = ${hash}`)
    await waitProjection(async () => {
      const next = await nameState(SUB_NAME)
      return next !== null && next.asset_owner.toLowerCase() === holder.address.toLowerCase()
    }, `${SUB_NAME} asset_owner 变更`)
  })

  it('B 为 A 的顶级名称公共续期（renewName 无 authority 要求）', async () => {
    const before = await nameState(TOP_NAME)
    expect(before).not.toBeNull()
    const hash = await sendIntent(holder, {
      kind: 'renew_name',
      name: TOP_NAME,
      duration: 180n * DAY,
      authority: PUBLIC_AUTHORITY,
      guard: EMPTY_GUARD,
    })
    console.log(`renewName(${TOP_NAME}, 180d) by ${holder.address} tx = ${hash}`)
    await waitProjection(async () => {
      const next = await nameState(TOP_NAME)
      return next !== null && next.expire_at > before!.expire_at
    }, `${TOP_NAME} expire_at 增加`)
  })

  it('最终投影断言（UI 走查入口见输出）', async () => {
    const top = await nameState(TOP_NAME)
    const sub = await nameState(SUB_NAME)
    expect(top).not.toBeNull()
    expect(sub).not.toBeNull()
    // 注册 1 + 发布文档 + 二级注册（父 seq 也会走动）+ 续期，name_seq 至少走到 3。
    expect(top!.name_seq).toBeGreaterThanOrEqual(3)
    // 仅持有：B 持有资产，但 semantic 未设置 -> effective owner 继承父名称（A）。
    expect(sub!.asset_owner.toLowerCase()).toBe(holder.address.toLowerCase())
    expect(sub!.owner_source).toBe('parent_inherited')
    expect(sub!.effective_owner.value.toLowerCase()).toBe(owner.address.toLowerCase())

    console.log(`\n== UI 走查入口（live 模式 http://localhost:5179）==`)
    console.log(`名称详情   /name/${TOP_NAME}  （name_seq ${top!.name_seq}，zone v1，续期后到期）`)
    console.log(`仅持有案例 /name/${SUB_NAME}  （asset_owner=B，owner_source=parent_inherited）`)
    console.log(`地址检索   /search?q=${holder.address}  （B 名下应有 ${SUB_NAME}）`)
    console.log(`事件浏览器 /events  （尾部应出现本轮 5 笔操作的事件）\n`)
  })
})
