/**
 * bns_model 运行配置。
 *
 * 端点与路径常量的真值来源：
 * - `src/components/bns-client/src/rpc.rs`（BNS_SERVER_RPC_PATH、MAX_BNS_NAMES_PAGE_SIZE）
 * - `src/components/bns-server/src/lib.rs`（DID_RESOLVER_PATH_PREFIX、/health）
 * 轮询节奏来源：`doc/BNS/BNS-WebUI-PRD.md` §8.5。
 */

import type { TxDeliveryMode } from './write/delivery'

/** BNS-Server 的 kRPC 路径。遗留独立 indexer 是 `/kapi/bns-indexer`。 */
export const BNS_SERVER_RPC_PATH = '/kapi/bns'

/** DID Resolver 绑定前缀：`GET /1.0/identifiers/{did}`。 */
export const DID_RESOLVER_PATH_PREFIX = '/1.0/identifiers/'

/** 进程健康检查。 */
export const HEALTH_PATH = '/health'

/** `name.query_by_addr` 的 limit 上限，超出返回 INVALID_LIMIT。 */
export const MAX_NAMES_PAGE_SIZE = 1000

/** 交易两阶段轮询节奏（PRD 8.5.6）。 */
export interface TxPollingPolicy {
  /** 分段节奏：在 `untilMs` 之前使用 `intervalMs`。 */
  phases: { untilMs: number; intervalMs: number }[]
  /** 超过所有分段后的兜底间隔，此时 UI 必须允许用户停止轮询。 */
  tailIntervalMs: number
  /** 链上成功后等待投影收敛的时限；超时显示“Indexer 尚未同步”，不显示失败。 */
  indexerTimeoutMs: number
}

export const DEFAULT_TX_POLLING: TxPollingPolicy = {
  phases: [
    { untilMs: 30_000, intervalMs: 2_000 },
    { untilMs: 300_000, intervalMs: 5_000 },
  ],
  tailIntervalMs: 15_000,
  indexerTimeoutMs: 300_000,
}

export interface BnsModelConfig {
  /** bns-server 基地址，只取 scheme://host:port，路径由下面几个字段拼接。 */
  serverUrl: string
  rpcPath: string
  didResolverPath: string
  healthPath: string
  /** 单次 kRPC / HTTP 请求超时。 */
  requestTimeoutMs: number
  namesPageSize: number
  eventsPageSize: number
  /** 读投影缓存 TTL；0 表示不缓存。 */
  readCacheTtlMs: number
  /**
   * 单个名称“活动记录”最多回扫多少页事件。
   * bns-server 的 `events.list` 没有按名称过滤，只能客户端扫描，
   * 因此必须有上限，并把是否扫完如实告诉视图。
   */
  activityScanPages: number
  /**
   * 部署期望值（**构建期钉死**），用于与 `system.info` 二次比对（PRD 8.1）。
   *
   * 合约地址决定了用户的签名会打给谁，属于安全关键参数，
   * 不应该由终端用户在界面上填写。正确姿势是构建时注入：
   * `expectedContractAddress: import.meta.env.VITE_BNS_CONTRACT_ADDRESS`。
   */
  expectedChainId: number | null
  expectedContractAddress: string | null
  /**
   * 合约地址的信任来源。
   *
   * - `pinned`（默认，生产用）：必须配置 `expectedContractAddress`，并与
   *   `system.info.contract_address` 逐字比对；缺失或不一致一律阻断写操作。
   *   这样即使 bns-server 被替换或被劫持，也无法把用户的签名引到别的合约上。
   * - `server`（仅开发/联调）：完全信任 `system.info` 返回的地址。
   *   方便对着临时部署的测试链跑，但不要用于生产构建。
   *
   * 注意：`pinned` 不等于“只用写死的地址”。运行时地址仍然来自 `system.info`
   * （PRD 8.1 禁止仅依赖构建期常量），钉死的值只作为比对锚点。
   */
  contractTrust: 'pinned' | 'server'
  /**
   * 交易投递路径，默认直连钱包。
   * 切到 `server_relay` 前请先读 `write/delivery.ts` 顶部的说明。
   */
  deliveryMode: TxDeliveryMode
  /** kRPC `sys[1]` 会话令牌，通常为空。不得进入普通日志。 */
  sessionToken: string | null
  polling: TxPollingPolicy
  /** 本地交易恢复的存储键前缀。 */
  storageKeyPrefix: string
}

export type BnsModelConfigInput = Partial<BnsModelConfig> & { serverUrl: string }

const DEFAULTS: Omit<BnsModelConfig, 'serverUrl'> = {
  rpcPath: BNS_SERVER_RPC_PATH,
  didResolverPath: DID_RESOLVER_PATH_PREFIX,
  healthPath: HEALTH_PATH,
  requestTimeoutMs: 15_000,
  namesPageSize: 50,
  eventsPageSize: 50,
  readCacheTtlMs: 5_000,
  activityScanPages: 10,
  expectedChainId: null,
  expectedContractAddress: null,
  contractTrust: 'pinned',
  deliveryMode: 'wallet_direct',
  sessionToken: null,
  polling: DEFAULT_TX_POLLING,
  storageKeyPrefix: 'bns.webui',
}

export function resolveConfig(input: BnsModelConfigInput): BnsModelConfig {
  const serverUrl = input.serverUrl.replace(/\/+$/, '')
  return { ...DEFAULTS, ...input, serverUrl }
}

export function rpcEndpoint(config: BnsModelConfig): string {
  return `${config.serverUrl}${config.rpcPath}`
}

export function healthEndpoint(config: BnsModelConfig): string {
  return `${config.serverUrl}${config.healthPath}`
}

export function didResolverEndpoint(config: BnsModelConfig, did: string): string {
  return `${config.serverUrl}${config.didResolverPath}${encodeDidPathSegment(did)}`
}

/**
 * DID 放进 URL path 时**不能**整体 encodeURIComponent。
 *
 * bns-server 对未解码的原始 path 直接做 `strip_prefix("/1.0/identifiers/")`
 * 再判断 `starts_with("did:")`，`%3A` 会让它认不出这是一个 DID 并返回 400 invalidDid。
 * 冒号在 path segment 里本来就是合法的 pchar（RFC 3986 §3.3），所以只编码其余字符。
 */
export function encodeDidPathSegment(did: string): string {
  return encodeURIComponent(did).replace(/%3A/gi, ':')
}
