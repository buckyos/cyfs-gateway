/**
 * kRPC 传输层 + BNS 业务信封解码。
 *
 * kRPC 不是 JSON-RPC 2.0：
 *   请求 `{ method, params, sys: [seq] | [seq, token] | [seq, null, trace_id] }`
 *   成功 `{ result: <BnsRpcEnvelope>, sys: [seq, trace_id?] }`
 *   失败 `{ error: "<string>", sys: [seq] }`   <- 注意仍然是 HTTP 200
 *
 * 四类失败必须区分（PRD 11.3）：
 * 1. HTTP 非 2xx / 网络中断        -> transport
 * 2. kRPC `error`（含 UnknownMethod）-> transport（不是业务错误）
 * 3. 信封 `ok: false`               -> registry（带业务 code）
 * 4. 信封 `ok: true, result: null`  -> 合法空值，由 callOptional 返回 null
 */

import { BNS_ERROR_CODE, BnsError, MODEL_ERROR_CODE } from '../types/errors'
import type { WireRpcEnvelope } from '../types/wire'

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>

export interface KrpcClientOptions {
  endpoint: string
  timeoutMs: number
  sessionToken?: string | null
  fetchImpl?: FetchLike
  /** 链路追踪 ID 生成器，返回 null 表示不带 trace。 */
  traceIdFactory?: () => string | null
}

export interface KrpcCallOptions {
  signal?: AbortSignal
  timeoutMs?: number
}

export class KrpcClient {
  private seq = 0
  private readonly options: KrpcClientOptions

  constructor(options: KrpcClientOptions) {
    this.options = options
  }

  get endpoint(): string {
    return this.options.endpoint
  }

  /** 结果可空的接口用这个；`ok: true, result: null` 会返回 null。 */
  async callOptional<T>(method: string, params: unknown, options: KrpcCallOptions = {}): Promise<T | null> {
    const envelope = await this.callEnvelope<T>(method, params, options)
    if (!envelope.ok) {
      throw BnsError.registry(envelope.error ?? { code: BNS_ERROR_CODE.INVALID_RESPONSE, message: '信封缺少 error' }, method)
    }
    return envelope.result ?? null
  }

  /** 结果非空的接口用这个；拿到 null 说明服务端违约。 */
  async call<T>(method: string, params: unknown, options: KrpcCallOptions = {}): Promise<T> {
    const result = await this.callOptional<T>(method, params, options)
    if (result === null) {
      throw BnsError.protocol(
        MODEL_ERROR_CODE.MISSING_RESULT,
        `方法 ${method} 返回了空 result，但该接口约定非空`,
        { method },
      )
    }
    return result
  }

  private async callEnvelope<T>(
    method: string,
    params: unknown,
    options: KrpcCallOptions,
  ): Promise<WireRpcEnvelope<T>> {
    this.seq = (this.seq + 1) % Number.MAX_SAFE_INTEGER
    const seq = this.seq
    const body = {
      method,
      params: params ?? {},
      sys: this.buildSys(seq),
    }

    const raw = await this.post(method, body, options)
    if (typeof raw !== 'object' || raw === null) {
      throw BnsError.protocol(MODEL_ERROR_CODE.KRPC_ERROR, `方法 ${method} 的响应不是 JSON 对象`, { method })
    }

    const record = raw as Record<string, unknown>
    if (typeof record.error === 'string') {
      // kRPC 层失败：参数反序列化失败、method 未注册等。不是 BNS 业务错误。
      throw BnsError.transport(MODEL_ERROR_CODE.KRPC_ERROR, record.error, { method })
    }
    if (!('result' in record)) {
      throw BnsError.protocol(MODEL_ERROR_CODE.KRPC_ERROR, `方法 ${method} 的响应缺少 result`, { method })
    }

    const envelope = record.result
    if (typeof envelope !== 'object' || envelope === null || !('ok' in envelope)) {
      throw BnsError.protocol(
        BNS_ERROR_CODE.INVALID_RESPONSE,
        `方法 ${method} 的 result 不是 BNS 信封`,
        { method },
      )
    }
    return envelope as WireRpcEnvelope<T>
  }

  private buildSys(seq: number): unknown[] {
    const token = this.options.sessionToken ?? null
    const traceId = this.options.traceIdFactory?.() ?? null
    if (traceId !== null) return [seq, token, traceId]
    if (token !== null) return [seq, token]
    return [seq]
  }

  private async post(method: string, body: unknown, options: KrpcCallOptions): Promise<unknown> {
    const fetchImpl = this.options.fetchImpl ?? globalThis.fetch.bind(globalThis)
    const timeoutMs = options.timeoutMs ?? this.options.timeoutMs
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeoutMs)
    const onAbort = () => controller.abort()
    options.signal?.addEventListener('abort', onAbort)

    let response: Response
    try {
      response = await fetchImpl(this.options.endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: controller.signal,
      })
    } catch (error) {
      if (controller.signal.aborted && !options.signal?.aborted) {
        throw BnsError.transport(
          MODEL_ERROR_CODE.REQUEST_TIMEOUT,
          `调用 ${method} 超时（${timeoutMs}ms）`,
          { method },
          error,
        )
      }
      throw BnsError.transport(
        BNS_ERROR_CODE.RPC_TRANSPORT_ERROR,
        `无法连接 bns-server: ${error instanceof Error ? error.message : String(error)}`,
        { method },
        error,
      )
    } finally {
      clearTimeout(timer)
      options.signal?.removeEventListener('abort', onAbort)
    }

    if (!response.ok) {
      // kRPC 的 body 解析失败会走这里（HTTP 400 + 纯文本）。
      const text = await safeText(response)
      throw BnsError.transport(
        MODEL_ERROR_CODE.HTTP_ERROR,
        `bns-server 返回 HTTP ${response.status}: ${text}`,
        { method, httpStatus: response.status },
      )
    }

    try {
      return await response.json()
    } catch (error) {
      throw BnsError.protocol(
        BNS_ERROR_CODE.SERIALIZATION_ERROR,
        `方法 ${method} 的响应不是合法 JSON`,
        { method },
      )
    }
  }
}

async function safeText(response: Response): Promise<string> {
  try {
    return (await response.text()).slice(0, 500)
  } catch {
    return '<no body>'
  }
}
