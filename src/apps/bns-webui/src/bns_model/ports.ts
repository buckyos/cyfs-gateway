/**
 * 外部适配器接口（端口）。
 *
 * bns_model 本身**零第三方依赖**：钱包、ABI 编码、持久化都以接口形式注入。
 * 这样做的直接好处：
 * - 原型阶段可以只注入读通道，页面照常跑（当前 bns-webui 就没有钱包依赖）；
 * - 换 viem / ethers / WalletConnect 不动 Model 层；
 * - 单测可以用假钱包和假编码器跑完整写流程。
 */

import type { Unsubscribe } from './infra/observable'
import type { Hex } from './infra/codec'
import type { WriteIntent } from './write/intents'

// ---------------------------------------------------------------------------
// 钱包
// ---------------------------------------------------------------------------

export interface WalletProviderInfo {
  /** EIP-6963 的 rdns。仅用于展示，不作为安全身份（PRD 13.1）。 */
  id: string
  name: string
  icon: string | null
  kind: 'injected' | 'eip6963' | 'walletconnect'
}

export interface WalletAccountState {
  connected: boolean
  address: string | null
  chainId: number | null
  providerId: string | null
}

export const DISCONNECTED_WALLET: WalletAccountState = {
  connected: false,
  address: null,
  chainId: null,
  providerId: null,
}

export interface SendTxRequest {
  from: string
  to: string
  data: Hex
  /** 普通交易固定为 0（PRD 8.5.2）：registerName/renewName 虽然 payable，但当前没有价格逻辑。 */
  value: '0x0'
}

/**
 * 只签名、不广播的请求（`eth_signTransaction`）。
 *
 * 与 `SendTxRequest` 的区别：钱包不会替你连链，所以 nonce / gas / fee / chainId
 * 必须由调用方补齐 —— 这些值在中继投递模式下来自 `tx.prepare`。
 */
export interface SignTxRequest extends SendTxRequest {
  chainId: number
  nonce: bigint
  gasLimit: bigint
  maxFeePerGas: bigint
  maxPriorityFeePerGas: bigint
}

export interface WalletCapabilities {
  /**
   * 是否支持 `eth_signTransaction`（签名后把 raw tx 交回来，不广播）。
   *
   * **多数注入式浏览器钱包不支持**：MetaMask 就没有实现这个方法。
   * 因此「服务端中继」投递模式不能作为通用回退，只能在确认钱包具备该能力时启用。
   * 适配器应当如实上报，不确定时报 false —— 谎报会让用户走到一半才失败。
   */
  signTransaction: boolean
  /** 是否支持 `wallet_switchEthereumChain`。 */
  switchChain: boolean
  /** 是否支持 `wallet_addEthereumChain`（私链/测试链需要）。 */
  addChain: boolean
}

export const NO_WALLET_CAPABILITIES: WalletCapabilities = {
  signTransaction: false,
  switchChain: false,
  addChain: false,
}

export interface AddChainParams {
  chainId: number
  chainName: string
  rpcUrls: string[]
  nativeCurrency: { name: string; symbol: string; decimals: number }
  blockExplorerUrls?: string[]
}

export interface WalletPort {
  getState(): WalletAccountState
  subscribe(listener: (state: WalletAccountState) => void): Unsubscribe
  /** 不得在用户点击前调用（PRD 8.2）。 */
  listProviders(): Promise<WalletProviderInfo[]>
  connect(providerId?: string): Promise<WalletAccountState>
  disconnect(): Promise<void>
  switchChain(chainId: number): Promise<void>
  addChain(params: AddChainParams): Promise<void>
  /** 提交前预检；失败时应尽量把 revert data 放在 error.data 里。 */
  estimateGas(request: SendTxRequest): Promise<bigint>
  /** eth_call 模拟，用于解码 custom error。不支持时可抛 UNSUPPORTED_METHOD。 */
  simulate(request: SendTxRequest): Promise<string>
  /** `eth_sendTransaction`：钱包签名并**通过钱包自己的 RPC** 广播。直连投递用这个。 */
  sendTransaction(request: SendTxRequest): Promise<string>

  /** 适配器自报能力；缺省视为都不支持。 */
  capabilities?(): WalletCapabilities
  /**
   * `eth_signTransaction`：只签名，返回 raw tx hex，由调用方决定往哪投。
   * 服务端中继投递依赖它。不支持的钱包**不要实现**这个方法。
   */
  signTransaction?(request: SignTxRequest): Promise<Hex>
}

export function walletCapabilities(wallet: WalletPort | null): WalletCapabilities {
  if (!wallet) return NO_WALLET_CAPABILITIES
  if (wallet.capabilities) return wallet.capabilities()
  return {
    signTransaction: typeof wallet.signTransaction === 'function',
    switchChain: true,
    addChain: true,
  }
}

// ---------------------------------------------------------------------------
// ABI 编码
// ---------------------------------------------------------------------------

export interface DecodedContractError {
  name: string
  args: readonly unknown[]
  /** 无法解码时保留原始 data 供复制（PRD 12.4）。 */
  raw: string
}

export interface CalldataCodec {
  /**
   * 把写意图编码为 calldata。
   * 实现方只需要 `BNS_WRITE_ABI` + `toAbiArgs(intent)`，见 write/abi.ts。
   */
  encode(intent: WriteIntent): Promise<Hex> | Hex
  /** 解码 revert data；未知 selector 返回 null，不猜测。 */
  decodeError(data: string): DecodedContractError | null
}

// ---------------------------------------------------------------------------
// 持久化 / 时钟
// ---------------------------------------------------------------------------

export interface StoragePort {
  get(key: string): string | null
  set(key: string, value: string): void
  remove(key: string): void
}

export const memoryStorage = (): StoragePort => {
  const map = new Map<string, string>()
  return {
    get: (key) => map.get(key) ?? null,
    set: (key, value) => {
      map.set(key, value)
    },
    remove: (key) => {
      map.delete(key)
    },
  }
}

export const browserStorage = (): StoragePort => {
  try {
    const probe = '__bns_probe__'
    window.localStorage.setItem(probe, '1')
    window.localStorage.removeItem(probe)
  } catch {
    return memoryStorage()
  }
  return {
    get: (key) => window.localStorage.getItem(key),
    set: (key, value) => window.localStorage.setItem(key, value),
    remove: (key) => window.localStorage.removeItem(key),
  }
}

export interface BnsModelAdapters {
  wallet?: WalletPort
  calldata?: CalldataCodec
  storage?: StoragePort
  fetchImpl?: typeof fetch
}
