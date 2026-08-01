/**
 * DID Resolver 绑定：`GET /1.0/identifiers/{did}?type={doc_type}[&iat=]`。
 *
 * 协议真值来源：`src/components/bns-server/src/lib.rs` 的 DID resolver 段落
 * （buckyos-base doc/http_did_resolver_api.md）。
 *
 * 关键语义（视图必须区分，不能都当成“没找到”）：
 * - 404 且 `didDocumentMetadata.buckyos.documentStatus` 存在  -> 权威的 Missing
 * - 404 且缺少 documentStatus（error = notApplicable）        -> 解析器“无意见”
 * - 410                                                      -> Revoked / Tombstoned
 * - 501 + historicalQuerySupported:false                      -> 能力缺口，不是错误
 * - 5xx                                                      -> 解析器/依赖故障，绝不能当成 Missing
 */

import { didResolverEndpoint, type BnsModelConfig } from '../config'
import { u64FromWireOptional } from '../infra/numeric'
import { BnsError, MODEL_ERROR_CODE } from '../types/errors'
import type { DocumentStatus } from '../types/domain'

export type DidResolutionKind =
  | 'answer'
  | 'not_applicable'
  | 'bad_request'
  | 'not_implemented'
  | 'server_failure'

export interface DidResolution {
  kind: DidResolutionKind
  httpStatus: number
  /** 只有 kind='answer' 时才有权威 documentStatus。 */
  documentStatus: DocumentStatus | null
  docType: string | null
  documentVersion: bigint | null
  authoritySeq: bigint | null
  effectiveOwner: string | null
  migrationTarget: string | null
  versionId: string | null
  deactivated: boolean
  contentType: string | null
  didDocument: unknown | null
  error: string | null
  errorMessage: string | null
  historicalQuerySupported: boolean | null
  /** 原始 envelope，高级视图可以直接展示 JSON。 */
  raw: unknown
}

export interface DidResolveOptions {
  docType?: string
  /** 历史查询；当前 server 一律回 501。 */
  iat?: bigint
  signal?: AbortSignal
}

export class DidResolverService {
  constructor(
    private readonly config: BnsModelConfig,
    private readonly fetchImpl: typeof fetch = globalThis.fetch.bind(globalThis),
  ) {}

  async resolve(did: string, options: DidResolveOptions = {}): Promise<DidResolution> {
    const query: string[] = []
    if (options.docType) query.push(`type=${encodeURIComponent(options.docType)}`)
    if (options.iat !== undefined) query.push(`iat=${options.iat.toString()}`)
    const url = `${didResolverEndpoint(this.config, did)}${query.length ? `?${query.join('&')}` : ''}`

    let response: Response
    try {
      response = await this.fetchImpl(url, {
        method: 'GET',
        headers: { Accept: 'application/did-resolution+json' },
        signal: options.signal,
      })
    } catch (error) {
      throw BnsError.transport(
        MODEL_ERROR_CODE.HTTP_ERROR,
        `DID Resolver 不可达: ${error instanceof Error ? error.message : String(error)}`,
        {},
        error,
      )
    }

    let raw: unknown = null
    try {
      raw = await response.json()
    } catch {
      raw = null
    }

    return parseDidResolution(response.status, raw)
  }
}

export function parseDidResolution(httpStatus: number, raw: unknown): DidResolution {
  const envelope = (raw ?? {}) as Record<string, unknown>
  const resolutionMeta = (envelope.didResolutionMetadata ?? {}) as Record<string, unknown>
  const documentMeta = (envelope.didDocumentMetadata ?? {}) as Record<string, unknown>
  const buckyos = (documentMeta.buckyos ?? {}) as Record<string, unknown>

  const documentStatus = typeof buckyos.documentStatus === 'string'
    ? (buckyos.documentStatus as DocumentStatus)
    : null
  const error = typeof resolutionMeta.error === 'string' ? resolutionMeta.error : null

  let kind: DidResolutionKind
  // 501 必须先于 5xx 判断：它是能力缺口（历史查询未实现），不是解析器故障，
  // 客户端应当回退到当前状态而不是报错。
  if (httpStatus === 501) {
    kind = 'not_implemented'
  } else if (httpStatus >= 500) {
    kind = 'server_failure'
  } else if (httpStatus === 400) {
    kind = 'bad_request'
  } else if (documentStatus === null) {
    // 404 + 缺少 documentStatus == NotApplicable：解析器对该 DID 无意见。
    kind = 'not_applicable'
  } else {
    kind = 'answer'
  }

  return {
    kind,
    httpStatus,
    documentStatus,
    docType: typeof buckyos.docType === 'string' ? buckyos.docType : null,
    documentVersion: u64FromWireOptional(buckyos.documentVersion ?? null, 'buckyos.documentVersion'),
    authoritySeq: u64FromWireOptional(buckyos.authoritySeq ?? null, 'buckyos.authoritySeq'),
    effectiveOwner: typeof buckyos.effectiveOwner === 'string' ? buckyos.effectiveOwner : null,
    migrationTarget: typeof buckyos.migrationTarget === 'string' ? buckyos.migrationTarget : null,
    versionId: typeof documentMeta.versionId === 'string' ? documentMeta.versionId : null,
    deactivated: documentMeta.deactivated === true,
    contentType: typeof resolutionMeta.contentType === 'string' ? resolutionMeta.contentType : null,
    didDocument: envelope.didDocument ?? null,
    error,
    errorMessage: typeof resolutionMeta.errorMessage === 'string' ? resolutionMeta.errorMessage : null,
    historicalQuerySupported:
      typeof buckyos.historicalQuerySupported === 'boolean' ? buckyos.historicalQuerySupported : null,
    raw,
  }
}
