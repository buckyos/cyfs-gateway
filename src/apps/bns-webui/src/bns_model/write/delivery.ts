/**
 * 交易投递（TX delivery）：一笔已经组装好的交易，走哪条路到链上。
 *
 * ============================================================================
 * 为什么需要两条路径
 * ============================================================================
 *
 * 写 BNS 需要三样东西：**calldata**、**签名**、**能把 raw tx 送进链节点的通道**。
 * calldata 由本模块生成（write/abi.ts），签名只能由用户的钱包做，
 * 分歧只在第三样 —— 谁来广播。
 *
 * ---------------------------------------------------------------------------
 * 模式 A：wallet_direct（直连投递，默认）
 * ---------------------------------------------------------------------------
 *
 *   WebUI --calldata--> Wallet --eth_sendTransaction--> 钱包自己的 RPC --> BNS Proxy
 *
 * 前提：**钱包必须为 `system.info.chain_id` 配置了可用的 RPC**。
 * WebUI 只需要知道 chainId + Proxy 地址，剩下的交给钱包，我们连节点地址都不需要知道。
 *
 * 这是 PRD 4.2 规定的唯一产品写路径，理由：
 * - `msg.sender` 就是钱包地址，授权链路最短、最容易解释；
 * - gas / fee 由钱包和用户决定，WebUI 不替用户静默改费用；
 * - 我们拿不到用户私钥，也不经手 raw tx。
 *
 * 对公链（主网、Base、Optimism…）这条路永远成立，钱包内置了 RPC。
 *
 * ---------------------------------------------------------------------------
 * 模式 B：server_relay（服务端中继投递，需显式开启）
 * ---------------------------------------------------------------------------
 *
 *   WebUI --tx.prepare--> bns-server            （拿 nonce / gas / fee）
 *   WebUI --eth_signTransaction--> Wallet       （只签名，拿回 raw tx）
 *   WebUI --tx.submit_raw--> bns-server --eth_sendRawTransaction--> 链节点
 *
 * 它要解决的正是**测试链/私链没有浏览器可达 RPC** 的问题：
 * anvil 常常只跑在开发机或 VM 内网里，bns-server 能连上，浏览器连不上。
 * 这时钱包即使加了自定义网络也广播不出去，只能借 bns-server 的链连接中继。
 * `tx.prepare` 的存在就是为此：它替代了「客户端自己查 nonce/gas/fee」，
 * 所以中继模式下 WebUI 完全不需要任何链 RPC。
 *
 * **但它不是通用回退**，有一条硬约束：
 *
 *   中继需要一份**已签名的 raw tx**，而拿到它只能靠 `eth_signTransaction`。
 *   EIP-1193 的主流注入式钱包（MetaMask 等）**不实现这个方法** ——
 *   它们只给 `eth_sendTransaction`（签名并自行广播）。
 *
 * 所以中继模式只在这些场景可用：
 * - 支持 `eth_signTransaction` 的钱包（Frame、部分硬件签名器、部分 WalletConnect 对端）；
 * - 浏览器之外的外部签名方（bns-client 的 `BnsEvmControllerClient` 就走这条路，
 *   见 doc/BNS/BNS-API.md §4.2）；
 * - e2e / 开发工具。
 *
 * 因此本模块的选择是：**默认直连，中继必须显式开启且先探测钱包能力**，
 * 能力不足时给出可解释的拒绝，而不是走到弹钱包那一步才失败。
 *
 * ---------------------------------------------------------------------------
 * 测试链还有第三个选项：wallet_addEthereumChain
 * ---------------------------------------------------------------------------
 *
 * 如果链节点**浏览器可达**（网络可达 + CORS 允许），更好的做法是让钱包
 * `wallet_addEthereumChain` 加上这条测试链，然后继续走直连（PRD 8.3）。
 * 只有在节点仅 bns-server 可达时，中继才是唯一选择。
 * 优先级：直连 > 加链后直连 > 中继。
 */

import type {
  SendTxRequest,
  SignTxRequest,
  WalletPort,
  WalletCapabilities,
} from '../ports'
import { walletCapabilities } from '../ports'
import type { BnsServerApi } from '../services/bns_server_api'
import { mapPrepareTx } from '../services/mapper'
import { isSameAddress } from '../infra/codec'
import { BnsError, MODEL_ERROR_CODE, toWalletError } from '../types/errors'
import type { WriteContext } from './write_flow'

export type TxDeliveryMode = 'wallet_direct' | 'server_relay'

export interface DeliveryReadiness {
  ready: boolean
  /** 不可用的原因，直接展示给用户。 */
  reason: string | null
  /** 建议的替代方案，供 UI 引导。 */
  hint: string | null
}

export interface TxDeliveryResult {
  txHash: string
  mode: TxDeliveryMode
  /** 中继模式下 tx.prepare 给出的参数，便于排查。 */
  preparedNonce: bigint | null
}

export interface TxDelivery {
  readonly mode: TxDeliveryMode
  /** 弹钱包之前的自检：能力是否满足。 */
  readiness(wallet: WalletPort | null): DeliveryReadiness
  deliver(
    request: SendTxRequest,
    context: WriteContext,
    wallet: WalletPort,
  ): Promise<TxDeliveryResult>
}

// ---------------------------------------------------------------------------
// 模式 A：直连
// ---------------------------------------------------------------------------

export class WalletDirectDelivery implements TxDelivery {
  readonly mode = 'wallet_direct' as const

  readiness(wallet: WalletPort | null): DeliveryReadiness {
    if (!wallet) {
      return { ready: false, reason: '未连接钱包', hint: null }
    }
    return { ready: true, reason: null, hint: null }
  }

  async deliver(
    request: SendTxRequest,
    _context: WriteContext,
    wallet: WalletPort,
  ): Promise<TxDeliveryResult> {
    try {
      const txHash = await wallet.sendTransaction(request)
      return { txHash, mode: this.mode, preparedNonce: null }
    } catch (error) {
      throw toWalletError(error)
    }
  }
}

// ---------------------------------------------------------------------------
// 模式 B：服务端中继
// ---------------------------------------------------------------------------

export class ServerRelayDelivery implements TxDelivery {
  readonly mode = 'server_relay' as const

  constructor(private readonly api: BnsServerApi) {}

  readiness(wallet: WalletPort | null): DeliveryReadiness {
    if (!wallet) {
      return { ready: false, reason: '未连接钱包', hint: null }
    }
    const capabilities: WalletCapabilities = walletCapabilities(wallet)
    if (!capabilities.signTransaction) {
      return {
        ready: false,
        reason:
          '当前钱包不支持 eth_signTransaction，无法产出可中继的 raw transaction。' +
          '（MetaMask 等主流注入式钱包都不实现该方法。）',
        hint:
          '改用直连投递：让钱包通过 wallet_addEthereumChain 添加这条链，' +
          '前提是链节点对浏览器可达。',
      }
    }
    return { ready: true, reason: null, hint: null }
  }

  /**
   * 三步：tx.prepare 取参数 -> 钱包只签名 -> tx.submit_raw 由服务端广播。
   *
   * 中间对 chainId / contract 做二次核对：`tx.prepare` 内部会重新读一次
   * `system.info`，如果它和本次会话锚定的值不一致，说明服务端在会话期间
   * 被换到了另一条链或另一份合约，必须中止而不是照签。
   */
  async deliver(
    request: SendTxRequest,
    context: WriteContext,
    wallet: WalletPort,
  ): Promise<TxDeliveryResult> {
    if (!wallet.signTransaction) {
      throw BnsError.config(
        MODEL_ERROR_CODE.WALLET_ERROR,
        '当前钱包不支持 eth_signTransaction，无法使用服务端中继投递',
      )
    }

    const preparedWire = await this.api.advanced.prepareTx(request.from, request.data)
    const prepared = mapPrepareTx(preparedWire)

    if (prepared.chainId !== context.chainId) {
      throw BnsError.validation(
        MODEL_ERROR_CODE.CHAIN_MISMATCH,
        `tx.prepare 返回 chain ${prepared.chainId}，与本次会话锚定的 ${context.chainId} 不一致`,
      )
    }
    if (!isSameAddress(prepared.contractAddress, context.contractAddress)) {
      throw BnsError.validation(
        MODEL_ERROR_CODE.CONTRACT_MISMATCH,
        `tx.prepare 返回的 Proxy ${prepared.contractAddress} 与本次会话锚定的 ${context.contractAddress} 不一致`,
      )
    }

    const signRequest: SignTxRequest = {
      ...request,
      chainId: prepared.chainId,
      // nonce 取自 eth_getTransactionCount(from, "pending")，已经把 mempool 里
      // 未打包的交易算进去，连续提交不会撞 nonce。
      nonce: prepared.nonce,
      gasLimit: prepared.gasLimit,
      maxFeePerGas: prepared.maxFeePerGas,
      maxPriorityFeePerGas: prepared.maxPriorityFeePerGas,
    }

    let rawTx: string
    try {
      rawTx = await wallet.signTransaction(signRequest)
    } catch (error) {
      throw toWalletError(error)
    }

    const { tx_hash: txHash } = await this.api.advanced.submitRawTx(rawTx)
    return { txHash, mode: this.mode, preparedNonce: prepared.nonce }
  }
}

export function createDelivery(mode: TxDeliveryMode, api: BnsServerApi): TxDelivery {
  return mode === 'server_relay' ? new ServerRelayDelivery(api) : new WalletDirectDelivery()
}

export function describeDeliveryMode(mode: TxDeliveryMode): string {
  return mode === 'server_relay'
    ? '服务端中继：钱包只签名，由 bns-server 调用 eth_sendRawTransaction 广播'
    : '直连：钱包签名并通过钱包自己的 RPC 广播'
}
