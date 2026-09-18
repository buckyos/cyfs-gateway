/**
 * 注册表 Controller：统一搜索、DID 解析、我持有的名称、注册向导。
 */

import { errorState, loadingState, readyState } from '../infra/observable'
import {
  DID_BNS_PREFIX,
  isAddress,
  isTxHash,
  nameFromDidBns,
  parseBnsName,
  validateBnsName,
  ZERO_BYTES32,
} from '../infra/codec'
import type { PortfolioModel } from '../models/portfolio_model'
import type { SessionModel } from '../models/session_model'
import type { NameModel } from '../models/name_model'
import type { DidResolution, DidResolverService } from '../services/did_resolver'
import type { ReadRepository } from '../services/read_repository'
import { BnsError, MODEL_ERROR_CODE, toBnsError } from '../types/errors'
import type { NameOverview, Principal } from '../types/domain'
import type { AuthorityPath } from '../write/authority'
import { assessAuthority } from '../write/authority'
import {
  EMPTY_GUARD,
  PUBLIC_AUTHORITY,
  defaultRegisterOptions,
  type AuthorityKeyUpdateInput,
  type ControllerRuleInput,
  type DocumentUpdateInput,
  type RegisterOptionsInput,
  type WriteIntent,
} from '../write/intents'
import type { PreparedWrite, WriteFlow } from '../write/write_flow'

export type SearchKind = 'name' | 'did_bns' | 'did_other' | 'address' | 'tx_hash' | 'invalid'

export interface SearchClassification {
  kind: SearchKind
  /** 归一化后的查询值：name / did / address / tx hash。 */
  value: string
  message: string | null
}

export interface NameAvailability {
  name: string
  /** null = 投影里没有该名称（未注册）。 */
  overview: NameOverview | null
  /**
   * 是否可注册。Released 名称按当前合约**可以**重新注册，
   * 但旧 authority/文档/policy 不会被清理，普通流程不开放（PRD 6.4.8）。
   */
  registrable: boolean
  reason: string
}

export interface RegisterForm {
  name: string
  assetOwner: string
  durationSeconds: bigint
  gracePeriodSeconds: bigint
  renewable: boolean
  transferable: boolean
  allowDelegatedSubnames: boolean
  /** 注册完成后立即生效的 semantic owner（只能是 unset 或 bns_name）。 */
  initialSemanticOwner?: Principal
  semanticOwnerAfterAuthority?: Principal
  authorityUpdates?: AuthorityKeyUpdateInput[]
  controllerPolicy?: ControllerRuleInput[]
  controllerPolicyHash?: string
  initialDocuments?: DocumentUpdateInput[]
}

export class RegistryController {
  constructor(
    private readonly portfolio: PortfolioModel,
    private readonly nameModel: NameModel,
    private readonly session: SessionModel,
    private readonly repo: ReadRepository,
    private readonly didResolver: DidResolverService,
    private readonly writeFlow: WriteFlow,
    private readonly now: () => number = () => Date.now(),
  ) {}

  // -------------------------------------------------------------------------
  // 搜索
  // -------------------------------------------------------------------------

  /** 单一输入框的分流：名称 / DID / 地址 / 交易 hash。 */
  classify(input: string): SearchClassification {
    const value = input.trim()
    if (value.length === 0) return { kind: 'invalid', value, message: '请输入名称、DID、地址或交易 hash' }
    if (isTxHash(value)) return { kind: 'tx_hash', value: value.toLowerCase(), message: null }
    if (isAddress(value)) return { kind: 'address', value: value.toLowerCase(), message: null }
    if (value.startsWith(DID_BNS_PREFIX)) {
      try {
        return { kind: 'did_bns', value: nameFromDidBns(value), message: null }
      } catch (error) {
        return { kind: 'invalid', value, message: error instanceof Error ? error.message : null }
      }
    }
    if (value.startsWith('did:')) {
      return {
        kind: 'did_other',
        value,
        // 非 did:bns 的方法本解析器不权威，会返回 NotApplicable。
        message: 'BNS 解析器只对 did:bns 权威，其它方法只会返回“无意见”',
      }
    }
    const validated = validateBnsName(value)
    return validated.ok
      ? { kind: 'name', value: validated.parsed.name, message: null }
      : { kind: 'invalid', value, message: validated.message }
  }

  resolveDid(did: string, docType?: string): Promise<DidResolution> {
    return this.didResolver.resolve(did, { docType })
  }

  // -------------------------------------------------------------------------
  // 我持有的名称
  // -------------------------------------------------------------------------

  /** 钱包地址变化时调用。address 为 null 表示断开，列表清空。 */
  async loadPortfolio(address: string | null): Promise<void> {
    this.portfolio.reset(address)
    if (!address) return
    await this.loadMore()
  }

  async loadMore(): Promise<void> {
    const state = this.portfolio.state
    if (!state.address) return
    if (state.entries.length > 0 && !state.hasMore) return

    this.portfolio.patch({ page: loadingState(state.page) })
    try {
      const page = await this.repo.namesByAddress(state.address, state.nextCursor)
      this.portfolio.appendNames(page.names, page.nextCursor)
      this.portfolio.patch({ page: readyState(page.names, this.now()) })
      // 列表字段（状态、到期时间）需要逐个 query_state，服务端没有批量接口。
      await Promise.all(page.names.map((name) => this.hydrateEntry(name)))
    } catch (error) {
      this.portfolio.patch({
        page: errorState(toBnsError(error), this.now(), this.portfolio.state.page),
      })
    }
  }

  private async hydrateEntry(name: string): Promise<void> {
    this.portfolio.patchEntry(name, loadingState())
    try {
      this.portfolio.patchEntry(name, readyState(await this.repo.nameOverview(name), this.now()))
    } catch (error) {
      this.portfolio.patchEntry(name, errorState(toBnsError(error), this.now()))
    }
  }

  // -------------------------------------------------------------------------
  // 注册
  // -------------------------------------------------------------------------

  async checkAvailability(input: string): Promise<NameAvailability> {
    const parsed = parseBnsName(input)
    const overview = await this.repo.nameOverview(parsed.name)
    if (overview === null) {
      return { name: parsed.name, overview: null, registrable: true, reason: '未注册，可以注册' }
    }
    switch (overview.state.status) {
      case 'available':
        return { name: parsed.name, overview, registrable: true, reason: '投影中标记为 available' }
      case 'released':
        return {
          name: parsed.name,
          overview,
          registrable: false,
          reason:
            'Released 名称在当前合约中可以被重新注册，但旧 authority key、文档版本、' +
            'controller policy 和 alias 不会被清理，普通流程暂不开放。',
        }
      case 'tombstoned':
        return { name: parsed.name, overview, registrable: false, reason: '已永久停用，无法再注册' }
      case 'active':
      case 'expired':
        return { name: parsed.name, overview, registrable: false, reason: '名称已被注册' }
    }
  }

  /**
   * 注册意图。
   *
   * - 顶级名称：公开注册，`CallAuthority` 用 public 路径；
   * - 二级名称：需要父名称 effective owner 授权，guard 带 expectedParentNameSeq。
   *   `allow_delegated_subnames` 当前不参与链上鉴权（PRD 6.4.3），UI 不得据此放行。
   */
  buildRegisterIntent(form: RegisterForm): WriteIntent {
    const parsed = parseBnsName(form.name)
    const options: RegisterOptionsInput = {
      ...defaultRegisterOptions(form.durationSeconds, form.gracePeriodSeconds),
      renewable: form.renewable,
      transferable: form.transferable,
      allowDelegatedSubnames: form.allowDelegatedSubnames,
      initialSemanticOwner: form.initialSemanticOwner ?? { kind: 'unset', value: '' },
    }
    if (options.initialSemanticOwner.kind === 'chain_account') {
      throw BnsError.validation(
        'INVALID_PRINCIPAL',
        'Semantic Owner 只能是 unset 或 BNS name，不能直接设置为链账户',
      )
    }
    return {
      kind: 'register_name',
      name: parsed.name,
      assetOwner: form.assetOwner,
      options,
      authorityUpdates: form.authorityUpdates ?? [],
      semanticOwnerAfterAuthority: form.semanticOwnerAfterAuthority ?? { kind: 'unset', value: '' },
      controllerPolicy: form.controllerPolicy ?? [],
      controllerPolicyHash: form.controllerPolicyHash ?? ZERO_BYTES32,
      initialDocuments: form.initialDocuments ?? [],
      authority: PUBLIC_AUTHORITY,
      guard: EMPTY_GUARD,
    }
  }

  /** 计算注册所需的授权路径：顶级公开，二级要父名称 owner。 */
  async resolveRegisterPath(name: string): Promise<AuthorityPath> {
    const parsed = parseBnsName(name)
    if (parsed.isTopLevel) return { kind: 'public' }

    const parent = parsed.parent
    if (!parent) {
      throw BnsError.validation('INVALID_NAME', `无法从 ${name} 推导父名称`)
    }
    const parentOwner = await this.repo.ownerResolution(parent)
    if (!parentOwner) {
      throw BnsError.validation(
        'NAME_NOT_FOUND',
        `父名称 ${parent} 不存在，无法注册二级名称`,
      )
    }
    const walletAddress = this.session.state.wallet.address
    const ownerKeys =
      parentOwner.effectiveOwner.kind === 'bns_name'
        ? await this.collectOwnerKeys(parentOwner.effectiveOwner.value)
        : []
    const assessment = assessAuthority({
      nameState: null,
      owner: parentOwner,
      walletAddress,
      ownerAuthorityKeys: ownerKeys,
      operation: 'register_name',
    })
    if (!assessment.recommended) {
      throw BnsError.validation(
        MODEL_ERROR_CODE.NOT_AUTHORIZED_PATH,
        `当前钱包不是父名称 ${parent} 的 effective owner，无法注册二级名称`,
      )
    }
    return assessment.recommended
  }

  async prepareRegister(form: RegisterForm): Promise<PreparedWrite> {
    const context = this.session.assertWritable()
    const intent = this.buildRegisterIntent(form)
    const path = await this.resolveRegisterPath(intent.name)
    return this.writeFlow.prepare(intent, path, context)
  }

  private async collectOwnerKeys(ownerName: string) {
    const kids = this.nameModel.knownKids(ownerName)
    const keys = []
    for (const kid of kids) {
      const key = await this.repo.authorityKey(ownerName, kid).catch(() => null)
      if (key) keys.push(key)
    }
    return keys
  }
}
