/**
 * 演示模式的假 bns-server：一个实现了 fetch 签名的浏览器内 HTTP 端点。
 *
 * 覆盖真实 server 的三个绑定（PRD 11.1）：
 *   GET  /health
 *   POST /kapi/bns          （13 个 kRPC method，kRPC + BNS 双层信封）
 *   GET  /1.0/identifiers/* （DID Resolver 四种回答）
 *
 * 报文形状与 `types/wire.ts` 一致，错误码与 PRD 12.3 一致，
 * 这样 KrpcClient / ReadRepository / mapper 的真实代码路径全部被走到。
 */

import type { WireRpcErrorInfo } from '../bns_model'
import { DID_BNS_PREFIX, validateBnsName } from '../bns_model'
import { DemoWorld } from './world'
import { jitter, pseudoHash } from './util'

const JSON_HEADERS = { 'Content-Type': 'application/json' }

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS })
}

/** BNS 业务信封（kRPC result 内层）。 */
function envelope(result: unknown): { ok: true; result: unknown; error: null } {
  return { ok: true, result, error: null }
}

function envelopeError(info: Partial<WireRpcErrorInfo> & { code: string; message: string }): {
  ok: false
  result: null
  error: WireRpcErrorInfo
} {
  return {
    ok: false,
    result: null,
    error: {
      name: null,
      doc_type: null,
      expected: null,
      actual: null,
      ...info,
    },
  }
}

export function createDemoFetch(world: DemoWorld): typeof fetch {
  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const target =
      typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    const url = new URL(target, 'http://demo.local')
    await jitter()

    if (url.pathname === '/health') {
      return new Response('ok', { status: 200 })
    }
    if (url.pathname === '/kapi/bns' && (init?.method ?? 'GET').toUpperCase() === 'POST') {
      return handleKrpc(world, init?.body)
    }
    if (url.pathname.startsWith('/1.0/identifiers/')) {
      return handleDidResolve(world, url)
    }
    return new Response('not found', { status: 404 })
  }
}

// ---------------------------------------------------------------------------
// kRPC
// ---------------------------------------------------------------------------

function handleKrpc(world: DemoWorld, rawBody: BodyInit | null | undefined): Response {
  let body: { method?: string; params?: Record<string, unknown>; sys?: unknown[] }
  try {
    body = JSON.parse(typeof rawBody === 'string' ? rawBody : '{}') as typeof body
  } catch {
    return new Response('invalid body', { status: 400 })
  }
  const seq = Array.isArray(body.sys) ? body.sys[0] : 0
  const params = body.params ?? {}
  const method = body.method ?? ''

  const reply = (payload: unknown): Response => json({ result: payload, sys: [seq] })
  const krpcError = (message: string): Response => json({ error: message, sys: [seq] })

  switch (method) {
    case 'system.info':
      return reply(envelope(world.systemInfo()))

    case 'name.query_state': {
      const name = String(params.name ?? '')
      const invalid = validateName(name)
      if (invalid) return reply(invalid)
      return reply(envelope(world.nameState(name)))
    }

    case 'name.resolve_owner': {
      const name = String(params.name ?? '')
      const invalid = validateName(name)
      if (invalid) return reply(invalid)
      const owner = world.ownerResolution(name)
      if (!owner) {
        return reply(
          envelopeError({
            code: 'NAME_NOT_FOUND',
            message: `name \`${name}\` was not found`,
            name,
          }),
        )
      }
      return reply(envelope(owner))
    }

    case 'authority.get_set': {
      const name = String(params.name ?? '')
      return reply(envelope(world.authoritySet(name)))
    }

    case 'authority.get_key': {
      const name = String(params.name ?? '')
      const kid = String(params.kid ?? '')
      return reply(envelope(world.authorityKey(name, kid)))
    }

    case 'document.resolve': {
      const name = String(params.name ?? '')
      const docType = String(params.doc_type ?? '')
      const resolved = world.resolveDocument(name, docType)
      if (!resolved) {
        return reply(
          envelopeError({
            code: world.nameState(name) === null ? 'NAME_NOT_FOUND' : 'DOCUMENT_NOT_FOUND',
            message: `document \`${name}/${docType}\` was not found`,
            name,
            doc_type: docType,
          }),
        )
      }
      return reply(envelope(resolved))
    }

    case 'document.get_version': {
      const name = String(params.name ?? '')
      const docType = String(params.doc_type ?? '')
      const version = Number(params.version ?? 0)
      return reply(envelope(world.documentVersion(name, docType, version)))
    }

    case 'name.query_by_addr': {
      const address = String(params.address ?? '')
      if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
        return reply(
          envelopeError({ code: 'INVALID_ADDRESS', message: `invalid address: ${address}` }),
        )
      }
      const limit = Number(params.limit ?? 50)
      if (limit < 1 || limit > 1000) {
        return reply(envelopeError({ code: 'INVALID_LIMIT', message: `invalid limit: ${limit}` }))
      }
      const cursor = params.cursor === null || params.cursor === undefined ? null : String(params.cursor)
      return reply(envelope(world.namesByAddress(address, cursor, limit)))
    }

    case 'tx.query_state': {
      const txHash = String(params.tx_hash ?? '')
      return reply(envelope(world.txState(txHash)))
    }

    case 'events.list': {
      const fromSeq = Number(params.from_seq ?? 0)
      const limit = Number(params.limit ?? 100)
      return reply(envelope(world.listEvents(fromSeq, limit)))
    }

    case 'checkpoint.latest':
      return reply(envelope(world.latestCheckpoint()))

    case 'tx.prepare':
    case 'tx.submit_raw':
      // 演示部署走 wallet_direct 直连；中继两件套如实报告未开启（PRD 8.5）。
      return reply(
        envelopeError({
          code: 'UNSUPPORTED_OPERATION',
          message: `\`${method}\` 未在本部署开启（演示模式走钱包直连投递）`,
        }),
      )

    default:
      return krpcError(`unknown method: ${method}`)
  }
}

function validateName(name: string): ReturnType<typeof envelopeError> | null {
  const validated = validateBnsName(name)
  if (validated.ok) return null
  return envelopeError({ code: 'INVALID_NAME', message: validated.message, name })
}

// ---------------------------------------------------------------------------
// DID Resolver（四种回答：answer / notApplicable / 501 / 400）
// ---------------------------------------------------------------------------

function handleDidResolve(world: DemoWorld, url: URL): Response {
  const did = decodeURIComponent(url.pathname.slice('/1.0/identifiers/'.length))
  const docType = url.searchParams.get('type') ?? 'zone'
  const iat = url.searchParams.get('iat')

  const resolutionBase = {
    '@context': 'https://w3id.org/did-resolution/v1',
  }

  if (!did.startsWith('did:')) {
    return json(
      {
        ...resolutionBase,
        didDocument: null,
        didResolutionMetadata: { error: 'invalidDid', errorMessage: `not a DID: ${did}` },
        didDocumentMetadata: {},
      },
      400,
    )
  }

  // 历史 iat 查询：当前实现统一 501（PRD 9.21）。
  if (iat !== null) {
    return json(
      {
        ...resolutionBase,
        didDocument: null,
        didResolutionMetadata: {
          error: 'notImplemented',
          errorMessage: 'historical (iat) resolution is not implemented',
        },
        didDocumentMetadata: { buckyos: { historicalQuerySupported: false } },
      },
      501,
    )
  }

  if (!did.startsWith(DID_BNS_PREFIX)) {
    // 非 did:bns 方法：解析器无意见（notApplicable），不能解释成名称缺失。
    return json(
      {
        ...resolutionBase,
        didDocument: null,
        didResolutionMetadata: {
          error: 'notApplicable',
          errorMessage: `resolver is not authoritative for \`${did.split(':').slice(0, 2).join(':')}\``,
        },
        didDocumentMetadata: {},
      },
      404,
    )
  }

  const name = did.slice(DID_BNS_PREFIX.length)
  const state = world.nameState(name)
  const owner = world.ownerResolution(name)
  const doc = world.currentDocument(name, docType)

  if (!state || !doc) {
    // 权威 Missing：带 documentStatus 的 404（假设投影已完成同步）。
    return json(
      {
        ...resolutionBase,
        didDocument: null,
        didResolutionMetadata: { error: 'notFound', errorMessage: `\`${did}\` (${docType}) not found` },
        didDocumentMetadata: {
          buckyos: {
            documentStatus: 'missing',
            docType,
            historicalQuerySupported: false,
          },
        },
      },
      404,
    )
  }

  const nowSec = Math.floor(Date.now() / 1000)
  const timeExpired = doc.expire_at !== 0 && doc.expire_at < nowSec
  const nameDead = state.status === 'tombstoned' || state.status === 'released'
  const derivedStatus = nameDead
    ? 'tombstoned'
    : doc.status !== 'active'
      ? doc.status
      : timeExpired
        ? 'expired'
        : 'active'
  const inlineText = new TextDecoder().decode(new Uint8Array(doc.document.inline_document))
  let didDocument: unknown = null
  try {
    didDocument = JSON.parse(inlineText)
  } catch {
    didDocument = { id: did, raw: inlineText }
  }

  const gone = derivedStatus === 'revoked' || derivedStatus === 'tombstoned'
  return json(
    {
      ...resolutionBase,
      didDocument: gone ? null : didDocument,
      didResolutionMetadata: gone
        ? { error: 'gone', errorMessage: `document status: ${derivedStatus}` }
        : { contentType: 'application/json' },
      didDocumentMetadata: {
        versionId: String(doc.version),
        deactivated: gone,
        buckyos: {
          documentStatus: derivedStatus,
          docType,
          documentVersion: doc.version,
          authoritySeq: owner?.authority_seq ?? 0,
          effectiveOwner: owner ? principalLabel(owner.effective_owner) : '',
          historicalQuerySupported: false,
          proofRoot: pseudoHash(`proof/${name}/${docType}/${doc.version}`),
        },
      },
    },
    gone ? 410 : 200,
  )
}

function principalLabel(principal: { kind: string; value: string }): string {
  if (principal.kind === 'bns_name') return `did:bns:${principal.value}`
  return principal.value
}
