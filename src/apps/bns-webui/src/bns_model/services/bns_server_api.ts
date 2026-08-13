/**
 * bns-server 的唯一读通道封装：13 个 kRPC method 与 2 个 HTTP 绑定，1:1 映射。
 *
 * 分层约定：
 * - 本文件只负责「协议正确」：method 名、params 形状、可空/非空语义、参数前置校验；
 * - 不做缓存、不做 wire->domain 转换、不做业务编排。那些在 read_repository / models。
 *
 * 所有方法都是 `async`：参数校验失败会走 **rejected promise** 而不是同步抛出，
 * 否则调用方的 `.catch()` / `Promise.all` 接不住本地校验错误。
 *
 * 读写边界（PRD 4.2）：
 * - 页面业务状态**只能**来自这里；
 * - `tx.submit_raw` 与 `tx.prepare` 虽然服务端存在，但普通写路径禁止使用，
 *   因此被隔离到 `advanced` 命名空间，且带显式注释。
 */

import { MAX_NAMES_PAGE_SIZE } from '../config'
import { isTxHash, normalizeAddress, normalizeTxHash, canonicalDocType, parseBnsName } from '../infra/codec'
import { KrpcClient, type KrpcCallOptions } from '../infra/krpc'
import { u64ToWire } from '../infra/numeric'
import { BNS_ERROR_CODE, BnsError } from '../types/errors'
import type {
  WireAuthorityKey,
  WireAuthoritySetState,
  WireEventLogRecord,
  WireLogCheckpoint,
  WireNamePage,
  WireNameState,
  WireOwnerResolution,
  WirePrepareTxResp,
  WireResolveResult,
  WireSystemInfo,
  WireTxState,
} from '../types/wire'

/** canonical method 名。下划线别名只用于兼容旧调用方，前端不使用。 */
export const RPC_METHOD = {
  SYSTEM_INFO: 'system.info',
  QUERY_NAME_STATE: 'name.query_state',
  RESOLVE_OWNER: 'name.resolve_owner',
  GET_AUTHORITY_SET: 'authority.get_set',
  GET_AUTHORITY_KEY: 'authority.get_key',
  RESOLVE_DOCUMENT: 'document.resolve',
  GET_DOCUMENT_VERSION: 'document.get_version',
  QUERY_NAMES_BY_ADDRESS: 'name.query_by_addr',
  QUERY_TX_STATE: 'tx.query_state',
  SUBMIT_RAW_TX: 'tx.submit_raw',
  PREPARE_TX: 'tx.prepare',
  LIST_EVENTS: 'events.list',
  LATEST_CHECKPOINT: 'checkpoint.latest',
} as const

export class BnsServerApi {
  constructor(
    private readonly krpc: KrpcClient,
    private readonly healthUrl: string,
    private readonly fetchImpl: typeof fetch = globalThis.fetch.bind(globalThis),
  ) {}

  /** `GET /health`：只证明进程活着，不代表链或投影可用。 */
  async health(signal?: AbortSignal): Promise<boolean> {
    try {
      const response = await this.fetchImpl(this.healthUrl, { method: 'GET', signal })
      return response.ok
    } catch {
      return false
    }
  }

  async systemInfo(options?: KrpcCallOptions): Promise<WireSystemInfo> {
    return this.krpc.call<WireSystemInfo>(RPC_METHOD.SYSTEM_INFO, {}, options)
  }

  /** 名称不存在时返回 null；名称格式非法时抛 INVALID_NAME。 */
  async queryNameState(name: string, options?: KrpcCallOptions): Promise<WireNameState | null> {
    const canonical = parseBnsName(name).name
    return this.krpc.callOptional<WireNameState>(
      RPC_METHOD.QUERY_NAME_STATE,
      { name: canonical },
      options,
    )
  }

  /** 名称不存在时抛 NAME_NOT_FOUND（与 query_name_state 的空值语义不同）。 */
  async resolveOwner(name: string, options?: KrpcCallOptions): Promise<WireOwnerResolution> {
    const canonical = parseBnsName(name).name
    return this.krpc.call<WireOwnerResolution>(
      RPC_METHOD.RESOLVE_OWNER,
      { name: canonical },
      options,
    )
  }

  /** 找不到记录时返回空集合（authority_seq = 0, active_key_count = 0），不报错。 */
  async getAuthoritySet(name: string, options?: KrpcCallOptions): Promise<WireAuthoritySetState> {
    const canonical = parseBnsName(name).name
    return this.krpc.call<WireAuthoritySetState>(
      RPC_METHOD.GET_AUTHORITY_SET,
      { name: canonical },
      options,
    )
  }

  /**
   * 按 kid 查询单个 key。
   *
   * 接口限制：bns-server **没有** “列出全部 authority key” 的方法，
   * 只能按已知 kid 逐个探测。UI 的 key 列表因此永远是「已知 kid 的子集」，
   * 必须如实标注（PRD 9.12）。kid 来源见 models/name_model 的 KnownKidRegistry。
   */
  async getAuthorityKey(name: string, kid: string, options?: KrpcCallOptions): Promise<WireAuthorityKey | null> {
    const canonical = parseBnsName(name).name
    return this.krpc.callOptional<WireAuthorityKey>(
      RPC_METHOD.GET_AUTHORITY_KEY,
      { name: canonical, kid },
      options,
    )
  }

  /** 名称不存在抛 NAME_NOT_FOUND；从未发布过该类型抛 DOCUMENT_NOT_FOUND。 */
  async resolveDocument(name: string, docType: string, options?: KrpcCallOptions): Promise<WireResolveResult> {
    const canonical = parseBnsName(name).name
    const canonicalDoc = canonicalDocType(docType)
    return this.krpc.call<WireResolveResult>(
      RPC_METHOD.RESOLVE_DOCUMENT,
      { name: canonical, doc_type: canonicalDoc },
      options,
    )
  }

  /** 指定版本不存在时返回 null。 */
  async getDocumentVersion(
    name: string,
    docType: string,
    version: bigint,
    options?: KrpcCallOptions,
  ): Promise<import('../types/wire').WireDocumentState | null> {
    const canonical = parseBnsName(name).name
    const canonicalDoc = canonicalDocType(docType)
    return this.krpc.callOptional(
      RPC_METHOD.GET_DOCUMENT_VERSION,
      { name: canonical, doc_type: canonicalDoc, version: u64ToWire(version, 'version') },
      options,
    )
  }

  /**
   * 按 EVM 地址列出名称。
   *
   * 语义边界：只按 `NameState.asset_owner` 查询，**不**包含通过 BNS authority key、
   * controller rule 或父名称继承可控制的名称（PRD 5.2）。文案不得写成“我能管理的名称”。
   */
  async queryNamesByAddress(
    address: string,
    cursor: string | null,
    limit: number,
    options?: KrpcCallOptions,
  ): Promise<WireNamePage> {
    const normalized = normalizeAddress(address)
    if (!Number.isInteger(limit) || limit < 1 || limit > MAX_NAMES_PAGE_SIZE) {
      throw BnsError.validation(
        BNS_ERROR_CODE.INVALID_LIMIT,
        `limit 必须在 1..=${MAX_NAMES_PAGE_SIZE}，收到 ${limit}`,
      )
    }
    return this.krpc.call<WireNamePage>(
      RPC_METHOD.QUERY_NAMES_BY_ADDRESS,
      { address: normalized, cursor, limit },
      options,
    )
  }

  /**
   * 交易状态。返回非 nullable 对象。
   *
   * `not_found` 不是确定失败：可能是节点没见过、mempool 丢弃、同 nonce 替换
   * 或历史裁剪，视图不得展示为失败（PRD 8.5.10）。
   */
  async queryTxState(txHash: string, options?: KrpcCallOptions): Promise<WireTxState> {
    if (!isTxHash(txHash)) {
      throw BnsError.validation(
        BNS_ERROR_CODE.SERIALIZATION_ERROR,
        `tx_hash 必须是 32 字节 hash: ${txHash}`,
      )
    }
    return this.krpc.call<WireTxState>(
      RPC_METHOD.QUERY_TX_STATE,
      { tx_hash: normalizeTxHash(txHash) },
      options,
    )
  }

  /** `seq >= from_seq` 升序，最多 limit 条。下一页 from_seq = 本页最后一条 seq + 1。 */
  async listEvents(fromSeq: bigint, limit: number, options?: KrpcCallOptions): Promise<WireEventLogRecord[]> {
    if (!Number.isInteger(limit) || limit < 1) {
      throw BnsError.validation(BNS_ERROR_CODE.INVALID_LIMIT, `limit 必须是正整数，收到 ${limit}`)
    }
    return this.krpc.call<WireEventLogRecord[]>(
      RPC_METHOD.LIST_EVENTS,
      { from_seq: u64ToWire(fromSeq, 'from_seq'), limit },
      options,
    )
  }

  /** 还没有 checkpoint 时返回 null。 */
  async latestCheckpoint(options?: KrpcCallOptions): Promise<WireLogCheckpoint | null> {
    return this.krpc.callOptional<WireLogCheckpoint>(RPC_METHOD.LATEST_CHECKPOINT, {}, options)
  }

  /**
   * 高级 / 运维专用通道。
   *
   * PRD 4.2 明确：普通 WebUI 的写路径是 钱包 -> EVM RPC -> BNS Proxy，
   * **禁止** 走 `tx.submit_raw`。这里保留封装只为高级工具页（外部签名调试），
   * 任何普通业务流程引用它都是设计错误。
   */
  readonly advanced = {
    submitRawTx: async (rawTx: string, options?: KrpcCallOptions): Promise<{ tx_hash: string }> =>
      this.krpc.call<{ tx_hash: string }>(RPC_METHOD.SUBMIT_RAW_TX, { raw_tx: rawTx }, options),

    prepareTx: async (from: string, calldata: string, options?: KrpcCallOptions): Promise<WirePrepareTxResp> =>
      this.krpc.call<WirePrepareTxResp>(
        RPC_METHOD.PREPARE_TX,
        { from: normalizeAddress(from), calldata },
        options,
      ),
  }
}
