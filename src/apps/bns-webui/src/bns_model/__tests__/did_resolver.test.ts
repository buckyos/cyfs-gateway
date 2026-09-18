/**
 * DID Resolver 的四种回答必须落到不同的 kind 上。
 * 状态机使用线上历史回包；版本语义使用当前协议构造的报文。
 */

import { describe, expect, it } from 'vitest'

import { parseDidResolution } from '../services/did_resolver'
import { didResolverEndpoint, encodeDidPathSegment, resolveConfig } from '../config'
import { didFixture, fixtures } from './fixtures'
import { createDemoFetch } from '../../demo/server'
import { DemoWorld } from '../../demo/world'

function parse(key: string) {
  const { httpStatus, body } = didFixture(key)
  return parseDidResolution(httpStatus, body)
}

describe('DID Resolver 状态机', () => {
  it('200：权威答案，带 buckyos 扩展块', () => {
    const answer = parseDidResolution(200, {
      didResolutionMetadata: { contentType: 'application/did+ld+json', error: null },
      didDocument: { id: 'did:bns:alice', iat: 1751500000 },
      didDocumentMetadata: {
        versionId: '1751500000',
        deactivated: false,
        buckyos: {
          docType: 'owner', documentStatus: 'active',
          documentVersion: 1751500000, registryVersion: 3, authoritySeq: 0,
        },
      },
    })
    expect(answer.kind).toBe('answer')
    expect(answer.httpStatus).toBe(200)
    expect(answer.documentStatus).toBe('active')
    expect(answer.docType).toBe('owner')
    expect(answer.documentVersion).toBe(1751500000n)
    expect(answer.registryVersion).toBe(3n)
    expect(answer.authoritySeq).toBe(0n)
    expect(answer.versionId).toBe('1751500000')
    expect(answer.deactivated).toBe(false)
    expect(answer.contentType).toBe('application/did+ld+json')
    expect(answer.didDocument).not.toBeNull()
  })

  it('404 + documentStatus=missing：权威的“没有”', () => {
    const missing = parse('missing')
    expect(missing.kind).toBe('answer')
    expect(missing.httpStatus).toBe(404)
    expect(missing.documentStatus).toBe('missing')
    expect(missing.error).toBe('notFound')
    expect(missing.didDocument).toBeNull()
  })

  it('404 且缺少 documentStatus：解析器“无意见”，不是权威的 missing', () => {
    // 这两种 404 必须区分，否则会把 did:web 当成“BNS 说它不存在”。
    const na = parse('notApplicable')
    expect(na.kind).toBe('not_applicable')
    expect(na.httpStatus).toBe(404)
    expect(na.documentStatus).toBeNull()
    expect(na.error).toBe('notApplicable')
  })

  it('501：历史查询能力缺口，不是错误也不是负面状态', () => {
    const historical = parse('historical')
    expect(historical.kind).toBe('not_implemented')
    expect(historical.historicalQuerySupported).toBe(false)
    expect(historical.error).toBe('historicalQueryNotSupported')
    expect(historical.documentStatus).toBeNull()
  })

  it('5xx 归入 server_failure，绝不能被当成 Missing', () => {
    const failure = parseDidResolution(502, {
      didResolutionMetadata: { contentType: null, error: 'internalError', errorMessage: 'upstream down' },
      didDocument: null,
      didDocumentMetadata: {},
    })
    expect(failure.kind).toBe('server_failure')
    expect(failure.documentStatus).toBeNull()
    expect(failure.errorMessage).toBe('upstream down')
  })

  it('400 是请求错误', () => {
    const bad = parseDidResolution(400, {
      didResolutionMetadata: { contentType: null, error: 'invalidDid', errorMessage: 'not a DID' },
      didDocument: null,
      didDocumentMetadata: {},
    })
    expect(bad.kind).toBe('bad_request')
  })

  it('chain account owner 时 effectiveOwner 缺席（服务端不泄漏内部编码）', () => {
    expect(parse('answer').effectiveOwner).toBeNull()
  })

  it('原始 envelope 完整保留，供高级视图展示', () => {
    expect(parse('answer').raw).toEqual(didFixture('answer').body)
  })

  it('旧响应没有 registryVersion 时不从 documentVersion 推断登记版本', () => {
    expect(parse('answer').registryVersion).toBeNull()
  })

  it('demo 将文档 iat 与登记版本分开，缺 iat 时省略文档版本', async () => {
    const fetchDemo = createDemoFetch(new DemoWorld())
    const zoneResponse = await fetchDemo('http://demo.local/1.0/identifiers/did:bns:alice?type=zone')
    const zone = parseDidResolution(zoneResponse.status, await zoneResponse.json())
    const iat = (zone.didDocument as { iat: number }).iat
    expect(zone.documentVersion).toBe(BigInt(iat))
    expect(zone.versionId).toBe(String(iat))
    expect(zone.registryVersion).toBe(2n)

    const response = await fetchDemo('http://demo.local/1.0/identifiers/did:bns:alice?type=payment')
    const raw = await response.json()
    const payment = parseDidResolution(response.status, raw)
    expect(payment.registryVersion).toBe(1n)
    expect(raw.didDocumentMetadata.buckyos).not.toHaveProperty('documentVersion')
    expect(raw.didDocumentMetadata).not.toHaveProperty('versionId')
  })
})

describe('DID 在 URL 里的编码', () => {
  const config = resolveConfig({ serverUrl: 'https://bns.buckyos.ai' })

  it('冒号必须保持原样', () => {
    // bns-server 对未解码的原始 path 做 strip_prefix + starts_with("did:")，
    // 整体 encodeURIComponent 会让它 400 invalidDid。
    expect(encodeDidPathSegment(`did:bns:${fixtures.name}`)).toBe(`did:bns:${fixtures.name}`)
    expect(didResolverEndpoint(config, 'did:bns:alice')).toBe(
      'https://bns.buckyos.ai/1.0/identifiers/did:bns:alice',
    )
  })

  it('其余不安全字符仍然编码', () => {
    expect(encodeDidPathSegment('did:web:ex.com/a b')).toBe('did:web:ex.com%2Fa%20b')
    expect(encodeDidPathSegment('did:bns:a?b#c')).toBe('did:bns:a%3Fb%23c')
  })
})
