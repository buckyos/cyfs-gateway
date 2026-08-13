/**
 * bns_model —— BNS WebUI 的 MVC「M + C」层。
 *
 * ```
 *  View (React 组件)
 *      |  只读 Model store，调用 Controller 方法
 *      v
 *  Controller  session / registry / name / tx / events
 *      |  编排用例，写回 Model
 *      v
 *  Model       session / name / portfolio / tx / events   （可观察状态）
 *      |  通过 ReadRepository 取数，通过 WriteFlow 写入
 *      v
 *  Service     BnsServerApi(kRPC) / DidResolverService / ReadRepository
 *      |
 *  Ports       WalletPort / CalldataCodec / StoragePort（外部注入）
 * ```
 *
 * 详细设计见同目录 README.md。
 */

import {
  healthEndpoint,
  resolveConfig,
  rpcEndpoint,
  type BnsModelConfig,
  type BnsModelConfigInput,
} from './config'
import { KrpcClient } from './infra/krpc'
import { EventsModel } from './models/events_model'
import { NameModel } from './models/name_model'
import { PortfolioModel } from './models/portfolio_model'
import { SessionModel } from './models/session_model'
import { TxModel } from './models/tx_model'
import { browserStorage, type BnsModelAdapters, type CalldataCodec, type WalletPort } from './ports'
import { BnsServerApi } from './services/bns_server_api'
import { DidResolverService } from './services/did_resolver'
import { ReadRepository, systemClock, type NowProvider } from './services/read_repository'
import { EventsController } from './controllers/events_controller'
import { NameController } from './controllers/name_controller'
import { RegistryController } from './controllers/registry_controller'
import { SessionController } from './controllers/session_controller'
import { TxController } from './controllers/tx_controller'
import { WriteFlow } from './write/write_flow'
import { createDelivery, describeDeliveryMode, type TxDeliveryMode } from './write/delivery'

export interface BnsModel {
  config: BnsModelConfig
  api: BnsServerApi
  repo: ReadRepository
  didResolver: DidResolverService
  models: {
    session: SessionModel
    name: NameModel
    portfolio: PortfolioModel
    tx: TxModel
    events: EventsModel
  }
  controllers: {
    session: SessionController
    registry: RegistryController
    name: NameController
    tx: TxController
    events: EventsController
  }
  /** 本次会话的交易投递路径，见 write/delivery.ts。 */
  deliveryMode: TxDeliveryMode
  /** 运行期替换钱包 / ABI 适配器，无需重建整棵对象树。 */
  setWallet(wallet: WalletPort | null): void
  setCalldataCodec(codec: CalldataCodec | null): void
  /** 启动：health -> system.info -> 恢复本地交易。 */
  start(): Promise<void>
  dispose(): void
}

export function createBnsModel(
  input: BnsModelConfigInput,
  adapters: BnsModelAdapters = {},
  clock: NowProvider = systemClock,
): BnsModel {
  const config = resolveConfig(input)
  const fetchImpl = adapters.fetchImpl ?? globalThis.fetch.bind(globalThis)

  const krpc = new KrpcClient({
    endpoint: rpcEndpoint(config),
    timeoutMs: config.requestTimeoutMs,
    sessionToken: config.sessionToken,
    fetchImpl,
  })
  const api = new BnsServerApi(krpc, healthEndpoint(config), fetchImpl)
  const repo = new ReadRepository(api, config, clock)
  const didResolver = new DidResolverService(config, fetchImpl)
  const storage = adapters.storage ?? browserStorage()

  let wallet: WalletPort | null = adapters.wallet ?? null
  let codec: CalldataCodec | null = adapters.calldata ?? null

  const sessionModel = new SessionModel(
    config.expectedChainId,
    config.expectedContractAddress,
    clock.now,
    config.contractTrust,
  )
  const nameModel = new NameModel(storage, config.storageKeyPrefix)
  const portfolioModel = new PortfolioModel()
  const txModel = new TxModel(storage, `${config.storageKeyPrefix}.transactions`)
  const eventsModel = new EventsModel()

  // 投递策略在这里定死：默认 wallet_direct，server_relay 需要在配置里显式选择。
  const delivery = createDelivery(config.deliveryMode, api)
  const writeFlow = new WriteFlow(repo, () => wallet, () => codec, clock.now, delivery)

  const txController = new TxController(
    txModel,
    repo,
    config,
    {
      onConverged: (record) => {
        // 投影收敛后让名称页拿到新数据；具体刷新由 View 订阅 store 触发。
        repo.invalidateName(record.target)
      },
    },
    clock.now,
  )
  const sessionController = new SessionController(sessionModel, repo, () => wallet, config)
  const nameController = new NameController(
    nameModel,
    repo,
    sessionModel,
    writeFlow,
    txController,
    clock.now,
  )
  const registryController = new RegistryController(
    portfolioModel,
    nameModel,
    sessionModel,
    repo,
    didResolver,
    writeFlow,
    clock.now,
  )
  const eventsController = new EventsController(eventsModel, repo, config.eventsPageSize, clock.now)

  return {
    config,
    api,
    repo,
    didResolver,
    models: {
      session: sessionModel,
      name: nameModel,
      portfolio: portfolioModel,
      tx: txModel,
      events: eventsModel,
    },
    controllers: {
      session: sessionController,
      registry: registryController,
      name: nameController,
      tx: txController,
      events: eventsController,
    },
    deliveryMode: config.deliveryMode,
    setWallet(next) {
      wallet = next
    },
    setCalldataCodec(next) {
      codec = next
    },
    async start() {
      txController.restore()
      await sessionController.bootstrap()
    },
    dispose() {
      sessionController.dispose()
      txController.dispose()
    },
  }
}

// ---------------------------------------------------------------------------
// 公开出口
// ---------------------------------------------------------------------------

export * from './config'
export * from './ports'
export { BnsError, BNS_ERROR_CODE, MODEL_ERROR_CODE, WALLET_ERROR_CODE, toBnsError, toWalletError } from './types/errors'
export type { BnsErrorKind, BnsErrorDetail } from './types/errors'
export * from './types/domain'
export type * from './types/wire'
export * from './infra/codec'
export * from './infra/numeric'
export { Store, idleState, loadingState, readyState, errorState, isStale } from './infra/observable'
export type { AsyncState, AsyncStatus, ReadonlyStore, Unsubscribe } from './infra/observable'
export { KrpcClient } from './infra/krpc'
export { BnsServerApi, RPC_METHOD } from './services/bns_server_api'
export { DidResolverService, parseDidResolution } from './services/did_resolver'
export type { DidResolution, DidResolutionKind } from './services/did_resolver'
export { ReadRepository, systemClock } from './services/read_repository'
export type { ActivityScan, NowProvider } from './services/read_repository'
export * from './services/mapper'
export * from './write/intents'
export * from './write/abi'
export * from './write/authority'
export { WriteFlow, isConverged, describeExpectation } from './write/write_flow'
export {
  WalletDirectDelivery,
  ServerRelayDelivery,
  createDelivery,
  describeDeliveryMode,
} from './write/delivery'
export type { TxDelivery, TxDeliveryMode, TxDeliveryResult, DeliveryReadiness } from './write/delivery'
export type { PreparedWrite, WriteContext, WriteSummary } from './write/write_flow'
export * from './models/session_model'
export * from './models/name_model'
export * from './models/portfolio_model'
export * from './models/tx_model'
export * from './models/events_model'
export { SessionController } from './controllers/session_controller'
export { RegistryController } from './controllers/registry_controller'
export type { SearchClassification, SearchKind, NameAvailability, RegisterForm } from './controllers/registry_controller'
export { NameController } from './controllers/name_controller'
export { TxController } from './controllers/tx_controller'
export type { TxControllerHooks } from './controllers/tx_controller'
export { EventsController } from './controllers/events_controller'
