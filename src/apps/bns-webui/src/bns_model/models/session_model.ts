/**
 * 会话 Model：服务发现、钱包、网络校验和**唯一的写闸门**。
 *
 * 把 PRD 8.1 / 8.3 / 4.2 的所有阻断条件收敛到一个 `writeGate` 上，
 * 视图只需要读它，不需要自己拼判断条件。
 */

import { Store, idleState, loadingState, readyState, errorState, type AsyncState } from '../infra/observable'
import { isSameAddress, isAddress } from '../infra/codec'
import { DISCONNECTED_WALLET, type WalletAccountState, type WalletProviderInfo } from '../ports'
import { BnsError, toBnsError } from '../types/errors'
import type { SystemInfo } from '../types/domain'

export type NetworkStatus =
  | 'unknown'
  | 'server_down'
  | 'server_not_ready'
  /** 未钉死合约地址却按 pinned 策略运行：不知道该信谁，一律只读。 */
  | 'contract_unpinned'
  | 'config_mismatch'
  | 'no_wallet'
  | 'chain_mismatch'
  | 'matched'

export interface WriteGate {
  allowed: boolean
  /** 不允许写时的原因，直接展示给用户。 */
  reason: string | null
  /** 是否可以通过切换钱包网络解决。 */
  canSwitchChain: boolean
}

export interface SessionState {
  /** null = 还没探测过。 */
  serverHealthy: boolean | null
  systemInfo: AsyncState<SystemInfo>
  wallet: WalletAccountState
  providers: WalletProviderInfo[]
  /** `system.info` 与部署期望配置不一致的说明。 */
  configMismatch: string | null
  /**
   * 合约地址是否已由构建期配置钉死。
   * `false` 表示按 pinned 策略运行但没配锚点 —— 只读，不允许写。
   * `null` 表示采用 `contractTrust: 'server'`，显式选择信任服务端。
   */
  contractPinned: boolean | null
  network: NetworkStatus
  writeGate: WriteGate
}

const INITIAL: SessionState = {
  serverHealthy: null,
  systemInfo: idleState<SystemInfo>(),
  wallet: DISCONNECTED_WALLET,
  providers: [],
  configMismatch: null,
  contractPinned: null,
  network: 'unknown',
  writeGate: { allowed: false, reason: '正在初始化 bns-server 连接', canSwitchChain: false },
}

export class SessionModel {
  readonly store = new Store<SessionState>(INITIAL)

  constructor(
    private readonly expectedChainId: number | null,
    private readonly expectedContractAddress: string | null,
    private readonly now: () => number = () => Date.now(),
    /** 见 config.ts 的 contractTrust 说明。默认按生产口径要求钉死。 */
    private readonly contractTrust: 'pinned' | 'server' = 'pinned',
  ) {}

  get state(): SessionState {
    return this.store.get()
  }

  setHealth(healthy: boolean): void {
    this.patch({ serverHealthy: healthy })
  }

  beginSystemInfo(): void {
    this.patch({ systemInfo: loadingState(this.state.systemInfo) })
  }

  setSystemInfo(info: SystemInfo): void {
    const mismatch = this.checkDeploymentExpectation(info)
    this.patch({
      systemInfo: readyState(info, this.now()),
      configMismatch: mismatch,
      contractPinned:
        this.contractTrust === 'server' ? null : this.expectedContractAddress !== null,
    })
  }

  setSystemInfoError(error: unknown): void {
    this.patch({
      systemInfo: errorState(toBnsError(error), this.now(), this.state.systemInfo),
    })
  }

  setWallet(wallet: WalletAccountState): void {
    this.patch({ wallet })
  }

  setProviders(providers: WalletProviderInfo[]): void {
    this.patch({ providers })
  }

  /**
   * 与部署配置二次比对。
   * 禁止只信构建期硬编码的合约地址，但允许用它来发现「连错了服务」。
   */
  private checkDeploymentExpectation(info: SystemInfo): string | null {
    if (!isAddress(info.contractAddress)) {
      return `system.info 返回的 contract_address 不是 20 字节地址：${info.contractAddress}`
    }
    // 「按 pinned 策略运行却没配锚点」不是 mismatch，而是单独的 contract_unpinned 状态
    // （见 deriveNetworkStatus），措辞和处置都不一样，所以这里不合并。
    if (this.expectedChainId !== null && this.expectedChainId !== info.chainId) {
      return `部署配置期望 chain ${this.expectedChainId}，bns-server 返回 ${info.chainId}`
    }
    if (
      this.expectedContractAddress !== null &&
      !isSameAddress(this.expectedContractAddress, info.contractAddress)
    ) {
      return `部署配置期望 Proxy ${this.expectedContractAddress}，bns-server 返回 ${info.contractAddress}`
    }
    return null
  }

  private patch(partial: Partial<SessionState>): void {
    const next = { ...this.state, ...partial }
    const network = deriveNetworkStatus(next)
    this.store.set({ ...next, network, writeGate: deriveWriteGate(next, network) })
  }

  /** 写操作入口统一调用，不通过就抛错，避免每个 controller 各写一遍判断。 */
  assertWritable(): { chainId: number; contractAddress: string; from: string } {
    const state = this.state
    if (!state.writeGate.allowed) {
      throw BnsError.validation(
        'WRITE_BLOCKED',
        state.writeGate.reason ?? '当前不允许提交写交易',
      )
    }
    const info = state.systemInfo.data
    if (!info || !state.wallet.address || state.wallet.chainId === null) {
      throw BnsError.validation('WRITE_BLOCKED', '会话状态不完整，无法提交写交易')
    }
    return {
      chainId: info.chainId,
      contractAddress: info.contractAddress,
      from: state.wallet.address,
    }
  }
}

function deriveNetworkStatus(state: SessionState): NetworkStatus {
  if (state.serverHealthy === false) return 'server_down'
  if (state.systemInfo.status === 'error') return 'server_down'
  const info = state.systemInfo.data
  if (!info) return 'unknown'
  if (!info.ready) return 'server_not_ready'
  if (state.contractPinned === false) return 'contract_unpinned'
  if (state.configMismatch) return 'config_mismatch'
  if (!state.wallet.connected || state.wallet.chainId === null) return 'no_wallet'
  if (state.wallet.chainId !== info.chainId) return 'chain_mismatch'
  return 'matched'
}

function deriveWriteGate(state: SessionState, network: NetworkStatus): WriteGate {
  switch (network) {
    case 'unknown':
      return { allowed: false, reason: '正在获取 bns-server 系统信息', canSwitchChain: false }
    case 'server_down':
      return { allowed: false, reason: 'bns-server 不可达，页面保持只读', canSwitchChain: false }
    case 'server_not_ready':
      return { allowed: false, reason: 'bns-server 报告 ready = false', canSwitchChain: false }
    case 'contract_unpinned':
      return {
        allowed: false,
        reason:
          '未配置 expectedContractAddress：无法验证 system.info 给出的 Proxy 地址是否可信，' +
          '写操作已阻断。生产构建请注入合约地址；本地联调可显式设置 contractTrust: "server"。',
        canSwitchChain: false,
      }
    case 'config_mismatch':
      return {
        allowed: false,
        // chain / contract 不一致必须阻断全部写操作，而不是提示后放行。
        reason: state.configMismatch ?? 'system.info 与部署配置不一致',
        canSwitchChain: false,
      }
    case 'no_wallet':
      return { allowed: false, reason: '未连接钱包', canSwitchChain: false }
    case 'chain_mismatch':
      return {
        allowed: false,
        reason: `钱包当前链 ${state.wallet.chainId} 与 bns-server 的 ${state.systemInfo.data?.chainId} 不一致`,
        canSwitchChain: true,
      }
    case 'matched':
      return { allowed: true, reason: null, canSwitchChain: false }
  }
}
