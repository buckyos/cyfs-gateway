/**
 * 两种交易投递路径。
 *
 * 直连（wallet_direct）：钱包 eth_sendTransaction，自己广播。
 * 中继（server_relay）：tx.prepare 取参数 -> 钱包 eth_signTransaction -> tx.submit_raw。
 *
 * 重点验证：中继模式在钱包不支持 eth_signTransaction 时**提前拒绝**，
 * 而不是等到用户点了提交才失败。
 */

import { describe, expect, it, vi } from 'vitest'

import {
  ServerRelayDelivery,
  WalletDirectDelivery,
  createDelivery,
  describeDeliveryMode,
} from '../write/delivery'
import { walletCapabilities, type SignTxRequest, type WalletPort } from '../ports'
import { MODEL_ERROR_CODE } from '../types/errors'
import { FakeBnsServerApi, FakeWallet, LIVE_SYSTEM_INFO } from './fakes'
import type { WirePrepareTxResp } from '../types/wire'
import type { WriteContext } from '../write/write_flow'
import type { SendTxRequest } from '../ports'

const CONTEXT: WriteContext = {
  chainId: LIVE_SYSTEM_INFO.chain_id,
  contractAddress: LIVE_SYSTEM_INFO.contract_address,
  from: '0x90f79bf6eb2c4f870365e785982e1f101e93b906',
}

const REQUEST: SendTxRequest = {
  from: CONTEXT.from,
  to: CONTEXT.contractAddress,
  data: '0xdeadbeef',
  value: '0x0',
}

/** 线上 tx.prepare 的真实形状（chain 31337 的 anvil）。 */
const PREPARED: WirePrepareTxResp = {
  nonce: 7,
  chain_id: LIVE_SYSTEM_INFO.chain_id,
  contract_address: LIVE_SYSTEM_INFO.contract_address,
  estimated_gas: 21901,
  gas_limit: 26282,
  max_fee_per_gas: 3135873238,
  max_priority_fee_per_gas: 1000000000,
}

/** 支持 eth_signTransaction 的钱包（Frame / 部分硬件签名器）。 */
class SigningWallet extends FakeWallet {
  readonly signed: SignTxRequest[] = []

  override async sendTransaction(): Promise<string> {
    throw new Error('中继模式不应该调用 eth_sendTransaction')
  }

  async signTransaction(request: SignTxRequest): Promise<`0x${string}`> {
    this.signed.push(request)
    return '0x02f86c8201'
  }
}

function relayWith(prepared: WirePrepareTxResp = PREPARED) {
  const api = new FakeBnsServerApi()
  const submitted: string[] = []
  api.advanced = {
    prepareTx: async () => prepared,
    submitRawTx: async (raw: string) => {
      submitted.push(raw)
      return { tx_hash: `0x${'c'.repeat(64)}` }
    },
  } as never
  return { api, submitted, delivery: new ServerRelayDelivery(api.asApi()) }
}

describe('能力探测', () => {
  it('没有钱包时全部能力为 false', () => {
    expect(walletCapabilities(null).signTransaction).toBe(false)
  })

  it('普通注入式钱包不实现 signTransaction', () => {
    // MetaMask 就属于这一类：只有 eth_sendTransaction。
    expect(walletCapabilities(new FakeWallet()).signTransaction).toBe(false)
  })

  it('实现了 signTransaction 的钱包被识别', () => {
    expect(walletCapabilities(new SigningWallet()).signTransaction).toBe(true)
  })

  it('适配器可以显式上报能力，覆盖方法探测', () => {
    const wallet = Object.assign(new SigningWallet(), {
      capabilities: () => ({ signTransaction: false, switchChain: true, addChain: false }),
    }) as WalletPort
    expect(walletCapabilities(wallet).signTransaction).toBe(false)
  })
})

describe('直连投递', () => {
  const delivery = new WalletDirectDelivery()

  it('未连钱包时不可用', () => {
    expect(delivery.readiness(null)).toMatchObject({ ready: false })
  })

  it('任何能发交易的钱包都可用', () => {
    expect(delivery.readiness(new FakeWallet())).toMatchObject({ ready: true, reason: null })
  })

  it('走 eth_sendTransaction，由钱包自己广播', async () => {
    const wallet = new FakeWallet()
    const result = await delivery.deliver(REQUEST, CONTEXT, wallet)
    expect(result.mode).toBe('wallet_direct')
    expect(result.txHash).toBe(`0x${'a'.repeat(64)}`)
    expect(result.preparedNonce).toBeNull()
    expect(wallet.sent).toEqual([REQUEST])
  })

  it('用户拒绝签名被识别为 WALLET_REJECTED', async () => {
    const wallet = new FakeWallet({
      sendTransaction: async () => {
        throw { code: 4001, message: 'User rejected the request.' }
      },
    })
    const error = await delivery.deliver(REQUEST, CONTEXT, wallet).catch((e: unknown) => e)
    expect((error as { code: string }).code).toBe(MODEL_ERROR_CODE.WALLET_REJECTED)
  })
})

describe('服务端中继投递', () => {
  it('钱包不支持 eth_signTransaction 时提前拒绝，并给出替代方案', () => {
    // 这条是中继模式最关键的边界：绝大多数浏览器钱包都走到这里。
    const { delivery } = relayWith()
    const readiness = delivery.readiness(new FakeWallet())
    expect(readiness.ready).toBe(false)
    expect(readiness.reason).toMatch(/eth_signTransaction/)
    expect(readiness.hint).toMatch(/wallet_addEthereumChain/)
  })

  it('支持签名的钱包可用', () => {
    const { delivery } = relayWith()
    expect(delivery.readiness(new SigningWallet())).toMatchObject({ ready: true })
  })

  it('三步走完：prepare -> 只签名 -> submit_raw', async () => {
    const { delivery, submitted } = relayWith()
    const wallet = new SigningWallet()
    const result = await delivery.deliver(REQUEST, CONTEXT, wallet)

    expect(result.mode).toBe('server_relay')
    expect(result.txHash).toBe(`0x${'c'.repeat(64)}`)
    expect(result.preparedNonce).toBe(7n)
    expect(submitted).toEqual(['0x02f86c8201'])
  })

  it('nonce / gas / fee 全部来自 tx.prepare —— 钱包不连链，自己算不出来', async () => {
    const { delivery } = relayWith()
    const wallet = new SigningWallet()
    await delivery.deliver(REQUEST, CONTEXT, wallet)
    expect(wallet.signed[0]).toMatchObject({
      chainId: LIVE_SYSTEM_INFO.chain_id,
      nonce: 7n,
      gasLimit: 26282n,
      maxFeePerGas: 3135873238n,
      maxPriorityFeePerGas: 1000000000n,
      to: CONTEXT.contractAddress,
      data: '0xdeadbeef',
      value: '0x0',
    })
  })

  it('tx.prepare 返回的 chain 与会话锚定值不一致时中止', async () => {
    // 服务端在会话期间被切到另一条链，绝不能照签。
    const { delivery } = relayWith({ ...PREPARED, chain_id: 999 })
    const error = await delivery.deliver(REQUEST, CONTEXT, new SigningWallet()).catch((e: unknown) => e)
    expect((error as { code: string }).code).toBe(MODEL_ERROR_CODE.CHAIN_MISMATCH)
  })

  it('tx.prepare 返回的 Proxy 与会话锚定值不一致时中止', async () => {
    const { delivery } = relayWith({ ...PREPARED, contract_address: `0x${'9'.repeat(40)}` })
    const error = await delivery.deliver(REQUEST, CONTEXT, new SigningWallet()).catch((e: unknown) => e)
    expect((error as { code: string }).code).toBe(MODEL_ERROR_CODE.CONTRACT_MISMATCH)
  })

  it('地址大小写不同不算不一致', async () => {
    const { delivery } = relayWith({
      ...PREPARED,
      contract_address: LIVE_SYSTEM_INFO.contract_address.toUpperCase().replace('0X', '0x'),
    })
    await expect(delivery.deliver(REQUEST, CONTEXT, new SigningWallet())).resolves.toBeDefined()
  })

  it('中继模式下不会调用 eth_sendTransaction', async () => {
    const { delivery } = relayWith()
    const wallet = new SigningWallet()
    await delivery.deliver(REQUEST, CONTEXT, wallet)
    expect(wallet.sent).toHaveLength(0)
  })

  it('钱包在签名阶段拒绝时按用户取消处理', async () => {
    const { delivery } = relayWith()
    const wallet = new SigningWallet()
    vi.spyOn(wallet, 'signTransaction').mockRejectedValue({ code: 4001, message: 'rejected' })
    const error = await delivery.deliver(REQUEST, CONTEXT, wallet).catch((e: unknown) => e)
    expect((error as { code: string }).code).toBe(MODEL_ERROR_CODE.WALLET_REJECTED)
  })
})

describe('工厂与文案', () => {
  it('createDelivery 按模式返回策略', () => {
    const api = new FakeBnsServerApi().asApi()
    expect(createDelivery('wallet_direct', api).mode).toBe('wallet_direct')
    expect(createDelivery('server_relay', api).mode).toBe('server_relay')
  })

  it('两种模式都有面向用户的说明', () => {
    expect(describeDeliveryMode('wallet_direct')).toMatch(/钱包自己的 RPC/)
    expect(describeDeliveryMode('server_relay')).toMatch(/eth_sendRawTransaction/)
  })
})
