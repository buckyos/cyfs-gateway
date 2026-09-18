/**
 * bns_model 的统一错误类型。
 *
 * 前端 API Client 必须同时处理四类失败（PRD 11.3）：
 * 1. HTTP 层错误                      -> kind: 'transport'
 * 2. kRPC parse / UnknownMethod       -> kind: 'transport'（服务端以 HTTP 200 + `error` 字段返回）
 * 3. BNS 业务信封 `ok: false`          -> kind: 'registry'（携带 code / name / doc_type / expected / actual）
 * 4. 合法的 `ok: true, result: null`   -> 不是错误，由调用方按可空语义处理
 */

/** BNS 业务错误码，来源 doc/BNS/BNS-API.md §6。 */
export const BNS_ERROR_CODE = {
  INVALID_NAME: 'INVALID_NAME',
  INVALID_DOC_TYPE: 'INVALID_DOC_TYPE',
  INVALID_ADDRESS: 'INVALID_ADDRESS',
  INVALID_LIMIT: 'INVALID_LIMIT',
  NAME_NOT_FOUND: 'NAME_NOT_FOUND',
  DOCUMENT_NOT_FOUND: 'DOCUMENT_NOT_FOUND',
  DOCUMENT_INCONSISTENT: 'DOCUMENT_INCONSISTENT',
  SERIALIZATION_ERROR: 'SERIALIZATION_ERROR',
  RPC_TRANSPORT_ERROR: 'RPC_TRANSPORT_ERROR',
  UNSUPPORTED_OPERATION: 'UNSUPPORTED_OPERATION',
  INVALID_RESPONSE: 'INVALID_RESPONSE',
} as const

/** 本模块自己产生的错误码（服务端不会返回这些）。 */
export const MODEL_ERROR_CODE = {
  HTTP_ERROR: 'HTTP_ERROR',
  KRPC_ERROR: 'KRPC_ERROR',
  REQUEST_TIMEOUT: 'REQUEST_TIMEOUT',
  UNSAFE_INTEGER: 'UNSAFE_INTEGER',
  MISSING_RESULT: 'MISSING_RESULT',
  WRITE_BLOCKED: 'WRITE_BLOCKED',
  WALLET_REJECTED: 'WALLET_REJECTED',
  WALLET_ERROR: 'WALLET_ERROR',
  NO_WALLET: 'NO_WALLET',
  NO_CALLDATA_CODEC: 'NO_CALLDATA_CODEC',
  CHAIN_MISMATCH: 'CHAIN_MISMATCH',
  CONTRACT_MISMATCH: 'CONTRACT_MISMATCH',
  STALE_GUARD: 'STALE_GUARD',
  NOT_AUTHORIZED_PATH: 'NOT_AUTHORIZED_PATH',
  INLINE_TOO_LARGE: 'INLINE_TOO_LARGE',
} as const

/** EIP-1193 标准错误码。 */
export const WALLET_ERROR_CODE = {
  USER_REJECTED: 4001,
  UNAUTHORIZED: 4100,
  UNSUPPORTED_METHOD: 4200,
  DISCONNECTED: 4900,
  CHAIN_DISCONNECTED: 4901,
  CHAIN_NOT_ADDED: 4902,
} as const

export type BnsErrorKind =
  | 'config'
  | 'transport'
  | 'protocol'
  | 'registry'
  | 'numeric'
  | 'validation'
  | 'wallet'
  | 'contract'

export interface BnsErrorDetail {
  /** registry 错误上下文，服务端只在相关错误里填充。 */
  name?: string | null
  docType?: string | null
  expected?: number | null
  actual?: number | null
  httpStatus?: number
  method?: string
  field?: string
  walletCode?: number
  /** 合约 revert data，未能解码时保留原始 hex 供用户复制。 */
  revertData?: string
}

export class BnsError extends Error {
  readonly kind: BnsErrorKind
  readonly code: string
  readonly detail: BnsErrorDetail

  constructor(
    kind: BnsErrorKind,
    code: string,
    message: string,
    detail: BnsErrorDetail = {},
    options?: { cause?: unknown },
  ) {
    super(message, options)
    this.name = 'BnsError'
    this.kind = kind
    this.code = code
    this.detail = detail
  }

  is(code: string): boolean {
    return this.code === code
  }

  /** 名称在投影里不存在：这是“缺失态”，不是故障。 */
  get isNameNotFound(): boolean {
    return this.code === BNS_ERROR_CODE.NAME_NOT_FOUND
  }

  /** 该 doc_type 从未发布过：文档缺失态。 */
  get isDocumentNotFound(): boolean {
    return this.code === BNS_ERROR_CODE.DOCUMENT_NOT_FOUND
  }

  get isUserRejected(): boolean {
    return (
      this.code === MODEL_ERROR_CODE.WALLET_REJECTED ||
      this.detail.walletCode === WALLET_ERROR_CODE.USER_REJECTED
    )
  }

  /** 服务不可用类错误：视图应展示“服务故障”而不是“数据不存在”。 */
  get isServiceFailure(): boolean {
    return (
      this.kind === 'transport' ||
      this.code === BNS_ERROR_CODE.RPC_TRANSPORT_ERROR
    )
  }

  static registry(
    info: { code?: string; message?: string; name?: string | null; doc_type?: string | null; expected?: number | null; actual?: number | null },
    method?: string,
  ): BnsError {
    const code = info.code ?? BNS_ERROR_CODE.INVALID_RESPONSE
    return new BnsError('registry', code, info.message ?? code, {
      name: info.name ?? null,
      docType: info.doc_type ?? null,
      expected: info.expected ?? null,
      actual: info.actual ?? null,
      method,
    })
  }

  static transport(code: string, message: string, detail: BnsErrorDetail = {}, cause?: unknown): BnsError {
    return new BnsError('transport', code, message, detail, { cause })
  }

  static protocol(code: string, message: string, detail: BnsErrorDetail = {}): BnsError {
    return new BnsError('protocol', code, message, detail)
  }

  static validation(code: string, message: string, detail: BnsErrorDetail = {}): BnsError {
    return new BnsError('validation', code, message, detail)
  }

  static numeric(message: string, field: string): BnsError {
    return new BnsError('numeric', MODEL_ERROR_CODE.UNSAFE_INTEGER, message, { field })
  }

  static wallet(code: string, message: string, walletCode?: number, cause?: unknown): BnsError {
    return new BnsError('wallet', code, message, { walletCode }, { cause })
  }

  static config(code: string, message: string, detail: BnsErrorDetail = {}): BnsError {
    return new BnsError('config', code, message, detail)
  }
}

export function toBnsError(error: unknown, fallbackCode = MODEL_ERROR_CODE.KRPC_ERROR): BnsError {
  if (error instanceof BnsError) return error
  if (error instanceof Error) {
    return BnsError.transport(fallbackCode, error.message, {}, error)
  }
  return BnsError.transport(fallbackCode, String(error))
}

/**
 * 把 EIP-1193 provider 抛出的对象转成 BnsError。
 * 用户拒绝签名（4001）是正常路径，不是故障，视图不应报红。
 */
export function toWalletError(error: unknown): BnsError {
  const raw = error as { code?: unknown; message?: unknown; data?: unknown } | null
  const walletCode = typeof raw?.code === 'number' ? raw.code : undefined
  const message = typeof raw?.message === 'string' ? raw.message : String(error)
  if (walletCode === WALLET_ERROR_CODE.USER_REJECTED) {
    return BnsError.wallet(MODEL_ERROR_CODE.WALLET_REJECTED, message, walletCode, error)
  }
  const bnsError = BnsError.wallet(MODEL_ERROR_CODE.WALLET_ERROR, message, walletCode, error)
  const data = (raw?.data as { data?: unknown } | undefined)?.data ?? raw?.data
  if (typeof data === 'string' && data.startsWith('0x')) {
    bnsError.detail.revertData = data
  }
  return bnsError
}
