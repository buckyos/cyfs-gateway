/**
 * 演示钱包：实现 WalletPort，模拟一个注入式浏览器钱包的行为节奏。
 *
 * - connect 之前不暴露账户（PRD 8.2：不得在用户点击前请求权限）；
 * - sendTransaction 有意停顿 ~1s，模拟「用户在钱包确认框里」的窗口，
 *   这样交易中心的 awaiting_wallet 阶段可见；
 * - 通过 `requestRejectNext()` 可以让下一笔签名被拒，演示 wallet_rejected 路径；
 * - 如实上报能力：不支持 eth_signTransaction（与 MetaMask 一致），
 *   因此中继投递在演示模式下也会被正确判定为不可用。
 */

import type {
  SendTxRequest,
  Unsubscribe,
  WalletAccountState,
  WalletCapabilities,
  WalletPort,
  WalletProviderInfo,
} from '../bns_model'
import { DEMO_CHAIN_ID, DEMO_WALLET_ADDRESS, type DemoWorld } from './world'
import { hexToUtf8, intentFromJson, sleep } from './util'

const REJECT_FLAG_KEY = 'bns.demo.rejectNextTx'
const CONNECTED_FLAG_KEY = 'bns.demo.walletConnected'

export class DemoWallet implements WalletPort {
  private state: WalletAccountState = {
    connected: false,
    address: null,
    chainId: null,
    providerId: null,
  }
  private readonly listeners = new Set<(state: WalletAccountState) => void>()

  constructor(private readonly world: DemoWorld) {
    // 模拟真实钱包扩展的行为：站点授权在刷新后仍然有效。
    if (readFlag(CONNECTED_FLAG_KEY)) {
      this.state = {
        connected: true,
        address: DEMO_WALLET_ADDRESS,
        chainId: DEMO_CHAIN_ID,
        providerId: 'bns-demo',
      }
    }
  }

  getState(): WalletAccountState {
    return this.state
  }

  subscribe(listener: (state: WalletAccountState) => void): Unsubscribe {
    this.listeners.add(listener)
    return () => void this.listeners.delete(listener)
  }

  private setState(next: Partial<WalletAccountState>): void {
    this.state = { ...this.state, ...next }
    for (const listener of this.listeners) listener(this.state)
  }

  async listProviders(): Promise<WalletProviderInfo[]> {
    return [
      { id: 'bns-demo', name: 'BNS 演示钱包', icon: null, kind: 'injected' },
    ]
  }

  async connect(): Promise<WalletAccountState> {
    await sleep(450)
    this.setState({
      connected: true,
      address: DEMO_WALLET_ADDRESS,
      chainId: DEMO_CHAIN_ID,
      providerId: 'bns-demo',
    })
    writeFlag(CONNECTED_FLAG_KEY, '1')
    return this.state
  }

  async disconnect(): Promise<void> {
    this.setState({ connected: false, address: null, chainId: null, providerId: null })
    writeFlag(CONNECTED_FLAG_KEY, null)
  }

  async switchChain(chainId: number): Promise<void> {
    await sleep(300)
    this.setState({ chainId })
  }

  async addChain(): Promise<void> {
    await sleep(300)
  }

  async estimateGas(request: SendTxRequest): Promise<bigint> {
    await sleep(160)
    // 粗糙但稳定的估算：基础 + calldata 长度。
    return 90_000n + BigInt(Math.floor((request.data.length - 2) / 2)) * 16n
  }

  async simulate(): Promise<string> {
    return '0x'
  }

  async sendTransaction(request: SendTxRequest): Promise<string> {
    // 「钱包确认框」窗口。
    await sleep(1_000)
    if (consumeRejectFlag()) {
      const error = new Error('User rejected the request.') as Error & { code: number }
      error.code = 4001
      throw error
    }
    const intent = intentFromJson(hexToUtf8(request.data))
    return this.world.submitTx(intent, request.from)
  }

  capabilities(): WalletCapabilities {
    return { signTransaction: false, switchChain: true, addChain: true }
  }
}

/** 设置页可以打开这个开关：下一笔交易在钱包阶段被拒签。 */
export function requestRejectNext(): void {
  try {
    window.localStorage.setItem(REJECT_FLAG_KEY, '1')
  } catch {
    // 忽略隐私模式
  }
}

export function rejectNextPending(): boolean {
  try {
    return window.localStorage.getItem(REJECT_FLAG_KEY) === '1'
  } catch {
    return false
  }
}

function consumeRejectFlag(): boolean {
  try {
    if (window.localStorage.getItem(REJECT_FLAG_KEY) === '1') {
      window.localStorage.removeItem(REJECT_FLAG_KEY)
      return true
    }
  } catch {
    // 忽略
  }
  return false
}

function readFlag(key: string): boolean {
  try {
    return window.localStorage.getItem(key) === '1'
  } catch {
    return false
  }
}

function writeFlag(key: string, value: string | null): void {
  try {
    if (value === null) window.localStorage.removeItem(key)
    else window.localStorage.setItem(key, value)
  } catch {
    // 忽略隐私模式
  }
}
