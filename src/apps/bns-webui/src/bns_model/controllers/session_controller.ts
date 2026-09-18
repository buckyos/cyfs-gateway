/**
 * 会话 Controller：启动、服务发现、钱包连接与网络校验。
 *
 * 启动顺序固定（PRD 8.1）：
 *   GET /health -> system.info -> 校验 contract_address 为 20 字节地址
 *   -> 作为本次会话唯一 Proxy 地址 -> 与部署期望二次比对
 */

import type { BnsModelConfig } from '../config'
import type { SessionModel } from '../models/session_model'
import { DISCONNECTED_WALLET, type WalletPort, type WalletProviderInfo, type AddChainParams } from '../ports'
import type { ReadRepository } from '../services/read_repository'
import { BnsError, MODEL_ERROR_CODE, toWalletError } from '../types/errors'
import type { Unsubscribe } from '../infra/observable'

export class SessionController {
  private walletUnsubscribe: Unsubscribe | null = null

  constructor(
    private readonly model: SessionModel,
    private readonly repo: ReadRepository,
    private readonly getWallet: () => WalletPort | null,
    private readonly config: BnsModelConfig,
  ) {}

  /** 页面启动调用一次。失败不阻塞公共只读页面，但会关闭写闸门。 */
  async bootstrap(): Promise<void> {
    this.attachWallet()
    const healthy = await this.repo.health()
    this.model.setHealth(healthy)

    this.model.beginSystemInfo()
    try {
      const info = await this.repo.systemInfo()
      this.model.setSystemInfo(info)
    } catch (error) {
      this.model.setSystemInfoError(error)
    }
  }

  /** 服务恢复后重新探测，不重连钱包。 */
  async refresh(): Promise<void> {
    this.repo.invalidate('system:')
    await this.bootstrap()
  }

  private attachWallet(): void {
    const wallet = this.getWallet()
    if (!wallet || this.walletUnsubscribe) return
    this.model.setWallet(wallet.getState())
    this.walletUnsubscribe = wallet.subscribe((state) => {
      // accountsChanged / chainChanged 后，写闸门会由 SessionModel 自动重算；
      // 各表单的授权预检结果由 NameController 重新计算。
      this.model.setWallet(state)
    })
  }

  dispose(): void {
    this.walletUnsubscribe?.()
    this.walletUnsubscribe = null
  }

  async listProviders(): Promise<WalletProviderInfo[]> {
    const wallet = this.getWallet()
    if (!wallet) return []
    const providers = await wallet.listProviders()
    this.model.setProviders(providers)
    return providers
  }

  async connect(providerId?: string): Promise<void> {
    const wallet = this.requireWallet()
    try {
      const state = await wallet.connect(providerId)
      this.model.setWallet(state)
    } catch (error) {
      throw toWalletError(error)
    }
  }

  async disconnect(): Promise<void> {
    const wallet = this.getWallet()
    if (!wallet) {
      this.model.setWallet(DISCONNECTED_WALLET)
      return
    }
    await wallet.disconnect()
    this.model.setWallet(wallet.getState())
  }

  /** 切换到 bns-server 报告的链。用户拒绝时保持只读，不重试。 */
  async switchToServerChain(): Promise<void> {
    const wallet = this.requireWallet()
    const info = this.model.state.systemInfo.data
    if (!info) {
      throw BnsError.config(MODEL_ERROR_CODE.CHAIN_MISMATCH, '尚未取得 system.info，无法切换网络')
    }
    try {
      await wallet.switchChain(info.chainId)
    } catch (error) {
      throw toWalletError(error)
    }
    this.model.setWallet(wallet.getState())
  }

  /** 钱包不认识该链时使用部署配置补充（PRD 8.3）。 */
  async addServerChain(params: AddChainParams): Promise<void> {
    const wallet = this.requireWallet()
    try {
      await wallet.addChain(params)
    } catch (error) {
      throw toWalletError(error)
    }
    this.model.setWallet(wallet.getState())
  }

  get expectedChainId(): number | null {
    return this.config.expectedChainId
  }

  private requireWallet(): WalletPort {
    const wallet = this.getWallet()
    if (!wallet) {
      throw BnsError.config(MODEL_ERROR_CODE.NO_WALLET, '未注入钱包适配器，页面保持只读')
    }
    return wallet
  }
}
