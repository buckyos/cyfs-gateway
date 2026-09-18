/**
 * 名称 Controller：名称详情页的全部读操作 + 名称域的全部写操作。
 *
 * 写操作一律两步，不允许一步到底：
 *   1. `prepare*` -> 返回 PreparedWrite（含 guard 重读结果、模拟错误、收敛期望、确认摘要）
 *   2. `submit`   -> 弹钱包并登记到交易中心
 * 中间那一步就是 UI 展示 before/after 与二次确认的位置。
 */

import { canonicalDocType, sha256Hex, utf8ToBytes, MAX_INLINE_DOCUMENT, ZERO_ADDRESS, ZERO_BYTES32 } from '../infra/codec'
import { errorState, loadingState, readyState } from '../infra/observable'
import type { NameModel, ControllerPolicySnapshot, AuthorityKeyProbe, DocTypeEntry } from '../models/name_model'
import { CONTROLLER_POLICY_NOTE } from '../models/name_model'
import type { SessionModel } from '../models/session_model'
import type { TxController } from './tx_controller'
import type { ReadRepository } from '../services/read_repository'
import { BnsError, MODEL_ERROR_CODE, toBnsError } from '../types/errors'
import type { AliasView, AuthorityKeyView, Principal, ReleaseMode } from '../types/domain'
import { assessAuthority, type AuthorityPath } from '../write/authority'
import {
  EMPTY_GUARD,
  PUBLIC_AUTHORITY,
  UNSET_PRINCIPAL,
  inlineDocumentRef,
  uriDocumentRef,
  type AuthorityKeyUpdateInput,
  type ControllerRuleInput,
  type DocumentUpdateInput,
  type OwnerPolicyUpdateInput,
  type WriteIntent,
} from '../write/intents'
import type { PreparedWrite, WriteFlow } from '../write/write_flow'
import type { TxRecord } from '../models/tx_model'

export class NameController {
  constructor(
    private readonly model: NameModel,
    private readonly repo: ReadRepository,
    private readonly session: SessionModel,
    private readonly writeFlow: WriteFlow,
    private readonly tx: TxController,
    private readonly now: () => number = () => Date.now(),
  ) {}

  // -------------------------------------------------------------------------
  // 读
  // -------------------------------------------------------------------------

  /** 概览 tab 需要的最小集合：state + owner + authority set + 父名称。 */
  async load(name: string): Promise<void> {
    this.model.ensure(name)
    await Promise.all([this.loadOverview(name), this.loadOwner(name), this.loadAuthoritySet(name)])
    await this.recomputeAuthority(name)
  }

  async loadOverview(name: string): Promise<void> {
    this.model.patch(name, { overview: loadingState(this.model.get(name).overview) })
    try {
      const overview = await this.repo.nameOverview(name)
      this.model.patch(name, { overview: readyState(overview, this.now()) })
      if (overview?.parent) {
        const parent = await this.repo.nameOverview(overview.parent)
        this.model.patch(name, { parent: readyState(parent, this.now()) })
      }
    } catch (error) {
      this.model.patch(name, {
        overview: errorState(toBnsError(error), this.now(), this.model.get(name).overview),
      })
    }
  }

  async loadOwner(name: string): Promise<void> {
    this.model.patch(name, { owner: loadingState(this.model.get(name).owner) })
    try {
      this.model.patch(name, { owner: readyState(await this.repo.ownerResolution(name), this.now()) })
    } catch (error) {
      this.model.patch(name, {
        owner: errorState(toBnsError(error), this.now(), this.model.get(name).owner),
      })
    }
  }

  async loadAuthoritySet(name: string): Promise<void> {
    this.model.patch(name, { authoritySet: loadingState(this.model.get(name).authoritySet) })
    try {
      this.model.patch(name, {
        authoritySet: readyState(await this.repo.authoritySet(name), this.now()),
      })
    } catch (error) {
      this.model.patch(name, {
        authoritySet: errorState(toBnsError(error), this.now(), this.model.get(name).authoritySet),
      })
    }
  }

  /**
   * 探测已知 kid。
   * bns-server 没有列举接口，所以结果只是「已知 kid 的子集」，
   * UI 必须显示 `authority_set.active_key_count` 与这里的条数差异。
   */
  async probeKnownKeys(name: string): Promise<void> {
    const kids = this.model.knownKids(name)
    this.model.patch(name, { authorityKeys: loadingState(this.model.get(name).authorityKeys) })
    try {
      const probes: AuthorityKeyProbe[] = []
      for (const kid of kids) {
        const key = await this.repo.authorityKey(name, kid)
        probes.push({ kid, key, source: 'local_history' })
      }
      this.model.patch(name, { authorityKeys: readyState(probes, this.now()) })
    } catch (error) {
      this.model.patch(name, {
        authorityKeys: errorState(toBnsError(error), this.now(), this.model.get(name).authorityKeys),
      })
    }
  }

  /** 用户手工输入 kid 后探测一次并记入本地已知列表。 */
  async probeAuthorityKey(name: string, kid: string): Promise<AuthorityKeyView | null> {
    const key = await this.repo.authorityKey(name, kid)
    this.model.addKnownKid(name, kid)
    const current = this.model.get(name).authorityKeys.data ?? []
    const merged = [
      ...current.filter((probe) => probe.kid !== kid),
      { kid, key, source: 'user_input' as const },
    ]
    this.model.patch(name, { authorityKeys: readyState(merged, this.now()) })
    await this.recomputeAuthority(name)
    return key
  }

  async loadDocument(name: string, docTypeInput: string): Promise<void> {
    const docType = canonicalDocType(docTypeInput)
    const current = this.model.get(name).documents[docType]
    this.model.patchDocument(name, docType, loadingState(current))
    try {
      const view = await this.repo.documentView(name, docType)
      this.model.patchDocument(name, docType, readyState(view, this.now()))
      if (view.state !== null) this.model.addDocType(name, docType, 'user_input')
    } catch (error) {
      this.model.patchDocument(name, docType, errorState(toBnsError(error), this.now(), current))
    }
  }

  /** 批量加载已知 doc type 入口，用于文档 tab 的首屏。 */
  async loadKnownDocuments(name: string): Promise<void> {
    const entries: DocTypeEntry[] = this.model.get(name).docTypes
    await Promise.all(entries.map((entry) => this.loadDocument(name, entry.docType)))
  }

  async loadDocumentHistory(name: string, docTypeInput: string, maxVersions = 20): Promise<void> {
    const docType = canonicalDocType(docTypeInput)
    const current = this.model.get(name).documentHistory[docType]
    this.model.patchDocumentHistory(name, docType, loadingState(current))
    try {
      const history = await this.repo.documentHistory(name, docType, maxVersions)
      this.model.patchDocumentHistory(name, docType, readyState(history, this.now()))
    } catch (error) {
      this.model.patchDocumentHistory(name, docType, errorState(toBnsError(error), this.now(), current))
    }
  }

  /**
   * 活动记录，同时顺带推导 alias 与 controller policy 快照。
   * 这两项没有专门的查询接口，只能从事件里读，因此都带来源标注。
   */
  async loadActivity(name: string, options: { fromSeq?: bigint } = {}): Promise<void> {
    this.model.patch(name, { activity: loadingState(this.model.get(name).activity) })
    try {
      const scan = await this.repo.activityForName(name, options)
      this.model.patch(name, { activity: readyState(scan, this.now()) })

      // 事件里发现的 doc type 是 doc type 入口的第 4 个来源。
      for (const record of scan.records) {
        if (record.event.type === 'document_published' || record.event.type === 'document_revoked') {
          this.model.addDocType(name, record.event.data.docType, 'event_log')
        }
      }

      this.model.patch(name, {
        alias: readyState(deriveAliasFromEvents(name, scan.records), this.now()),
        controllerPolicy: readyState(deriveControllerPolicy(scan.records), this.now()),
      })
    } catch (error) {
      this.model.patch(name, {
        activity: errorState(toBnsError(error), this.now(), this.model.get(name).activity),
      })
    }
  }

  /**
   * 重算当前钱包对该名称的授权路径。
   * 钱包 `accountsChanged` / `chainChanged` 之后必须调用，旧结果一律作废。
   */
  async recomputeAuthority(name: string): Promise<void> {
    const aggregate = this.model.get(name)
    const owner = aggregate.owner.data ?? null
    const walletAddress = this.session.state.wallet.address

    let ownerKeys: AuthorityKeyView[] = []
    if (owner?.effectiveOwner.kind === 'bns_name') {
      const ownerName = owner.effectiveOwner.value
      const kids = this.model.knownKids(ownerName)
      for (const kid of kids) {
        const key = await this.repo.authorityKey(ownerName, kid).catch(() => null)
        if (key) ownerKeys.push(key)
      }
    }

    this.model.patch(name, {
      authority: assessAuthority({
        nameState: aggregate.overview.data?.state ?? null,
        owner,
        walletAddress,
        ownerAuthorityKeys: ownerKeys,
        operation: 'publish_document',
      }),
    })
  }

  // -------------------------------------------------------------------------
  // 写：通用两步流程
  // -------------------------------------------------------------------------

  /** 组装并预检，不弹钱包。 */
  async prepare(intent: WriteIntent, path?: AuthorityPath): Promise<PreparedWrite> {
    const context = this.session.assertWritable()
    const resolvedPath = path ?? this.model.get(intent.name).authority?.recommended ?? null
    if (!resolvedPath) {
      throw BnsError.validation(
        MODEL_ERROR_CODE.NOT_AUTHORIZED_PATH,
        '没有可用的授权路径：当前钱包不是 effective owner，也没有已验证的 authority key',
      )
    }
    return this.writeFlow.prepare(intent, resolvedPath, context)
  }

  /** 弹钱包提交并登记交易中心。用户取消会记录为 wallet_rejected，不算失败。 */
  async submit(prepared: PreparedWrite): Promise<TxRecord> {
    try {
      const delivered = await this.writeFlow.submit(prepared)
      return this.tx.track(prepared, delivered.txHash, delivered.mode)
    } catch (error) {
      const bnsError = toBnsError(error)
      if (bnsError.isUserRejected) {
        return this.tx.trackRejected(prepared, bnsError.message)
      }
      throw bnsError
    }
  }

  // -------------------------------------------------------------------------
  // 写意图构造器（authority / guard 由 WriteFlow 在弹钱包前统一刷新）
  // -------------------------------------------------------------------------

  buildRenew(name: string, durationSeconds: bigint): WriteIntent {
    return { kind: 'renew_name', name, duration: durationSeconds, authority: PUBLIC_AUTHORITY, guard: EMPTY_GUARD }
  }

  buildTransfer(
    name: string,
    newAssetOwner: string,
    options: { newSemanticOwner?: Principal; atomicDocumentUpdates?: DocumentUpdateInput[] } = {},
  ): WriteIntent {
    return {
      kind: 'transfer_name',
      name,
      newAssetOwner,
      newSemanticOwner: options.newSemanticOwner ?? UNSET_PRINCIPAL,
      atomicDocumentUpdates: options.atomicDocumentUpdates ?? [],
      authority: PUBLIC_AUTHORITY,
      guard: EMPTY_GUARD,
    }
  }

  /** semantic owner 只允许 unset 或 bns_name，不允许直接设成 chain_account。 */
  buildSetSemanticOwner(name: string, semanticOwner: Principal): WriteIntent {
    if (semanticOwner.kind === 'chain_account') {
      throw BnsError.validation(
        'INVALID_PRINCIPAL',
        'Semantic Owner 只能是 unset 或 BNS name，不能直接设置为链账户',
      )
    }
    return { kind: 'set_name_owner', name, semanticOwner, authority: PUBLIC_AUTHORITY, guard: EMPTY_GUARD }
  }

  buildRelease(name: string, mode: ReleaseMode, reasonHash = ZERO_BYTES32): WriteIntent {
    return { kind: 'release_name', name, mode, reasonHash, authority: PUBLIC_AUTHORITY, guard: EMPTY_GUARD }
  }

  buildNamespacePolicy(
    name: string,
    allowDelegatedSubnames: boolean,
    namespacePolicyHash = ZERO_BYTES32,
  ): WriteIntent {
    return {
      kind: 'set_namespace_policy',
      name,
      allowDelegatedSubnames,
      namespacePolicyHash,
      authority: PUBLIC_AUTHORITY,
      guard: EMPTY_GUARD,
    }
  }

  buildUpdateAuthorityKeys(name: string, updates: AuthorityKeyUpdateInput[]): WriteIntent {
    assertBatchSize(updates.length, 'authority key')
    return { kind: 'update_authority_keys', name, updates, authority: PUBLIC_AUTHORITY, guard: EMPTY_GUARD }
  }

  buildSetMinDocumentIat(name: string, minDocumentIat: bigint, reasonHash = ZERO_BYTES32): WriteIntent {
    return {
      kind: 'set_min_document_iat',
      name,
      minDocumentIat,
      reasonHash,
      authority: PUBLIC_AUTHORITY,
      guard: EMPTY_GUARD,
    }
  }

  /**
   * 发布 inline 文档。
   * content_hash 由本函数计算，UI 不允许手填 —— 合约要求它必须等于 sha256(inline_document)。
   */
  async buildPublishInlineDocument(
    name: string,
    docTypeInput: string,
    content: string | Uint8Array,
    options: {
      controller?: Principal
      beneficiary?: Principal
      paymentTarget?: string
      expireAt?: bigint
      controllerPolicyHash?: string
      paymentPolicyHash?: string
      splitPolicyHash?: string
      pricePolicyHash?: string
      rightsPolicyHash?: string
    } = {},
  ): Promise<WriteIntent> {
    const docType = canonicalDocType(docTypeInput)
    const bytes = typeof content === 'string' ? utf8ToBytes(content) : content
    if (bytes.length > MAX_INLINE_DOCUMENT) {
      throw BnsError.validation(
        MODEL_ERROR_CODE.INLINE_TOO_LARGE,
        `inline 文档 ${bytes.length} 字节，超过上限 ${MAX_INLINE_DOCUMENT} 字节`,
      )
    }
    const contentHash = await sha256Hex(bytes)
    const currentVersion = await this.currentDocumentVersion(name, docType)
    return {
      kind: 'publish_document',
      name,
      docType,
      expectedVersion: currentVersion,
      document: inlineDocumentRef(bytes, contentHash),
      controller: options.controller ?? UNSET_PRINCIPAL,
      beneficiary: options.beneficiary ?? UNSET_PRINCIPAL,
      paymentTarget: options.paymentTarget ?? ZERO_ADDRESS,
      expireAt: options.expireAt ?? 0n,
      controllerPolicyHash: options.controllerPolicyHash ?? ZERO_BYTES32,
      paymentPolicyHash: options.paymentPolicyHash ?? ZERO_BYTES32,
      splitPolicyHash: options.splitPolicyHash ?? ZERO_BYTES32,
      pricePolicyHash: options.pricePolicyHash ?? ZERO_BYTES32,
      rightsPolicyHash: options.rightsPolicyHash ?? ZERO_BYTES32,
      authority: PUBLIC_AUTHORITY,
      guard: EMPTY_GUARD,
    }
  }

  /** 发布 URI 文档：inline_document 必须为空，content_hash 由用户提供并自负其责。 */
  async buildPublishUriDocument(
    name: string,
    docTypeInput: string,
    uri: string,
    contentHash: string,
    options: { storageType?: string; expireAt?: bigint; controller?: Principal } = {},
  ): Promise<WriteIntent> {
    const docType = canonicalDocType(docTypeInput)
    const currentVersion = await this.currentDocumentVersion(name, docType)
    return {
      kind: 'publish_document',
      name,
      docType,
      expectedVersion: currentVersion,
      document: uriDocumentRef(uri, contentHash, options.storageType ?? 'uri'),
      controller: options.controller ?? UNSET_PRINCIPAL,
      beneficiary: UNSET_PRINCIPAL,
      paymentTarget: ZERO_ADDRESS,
      expireAt: options.expireAt ?? 0n,
      controllerPolicyHash: ZERO_BYTES32,
      paymentPolicyHash: ZERO_BYTES32,
      splitPolicyHash: ZERO_BYTES32,
      pricePolicyHash: ZERO_BYTES32,
      rightsPolicyHash: ZERO_BYTES32,
      authority: PUBLIC_AUTHORITY,
      guard: EMPTY_GUARD,
    }
  }

  async buildRevokeDocument(name: string, docTypeInput: string, reasonHash = ZERO_BYTES32): Promise<WriteIntent> {
    const docType = canonicalDocType(docTypeInput)
    return {
      kind: 'revoke_document',
      name,
      docType,
      expectedVersion: await this.currentDocumentVersion(name, docType),
      reasonHash,
      authority: PUBLIC_AUTHORITY,
      guard: EMPTY_GUARD,
    }
  }

  /** 替换全部 controller 规则：这是覆盖式操作，UI 必须展示“替换”而不是“新增”。 */
  buildSetControllerPolicy(name: string, rules: ControllerRuleInput[], policyHash = ZERO_BYTES32): WriteIntent {
    assertBatchSize(rules.length, 'controller rule')
    return { kind: 'set_controller_policy', name, rules, policyHash, authority: PUBLIC_AUTHORITY, guard: EMPTY_GUARD }
  }

  buildSetDidAlias(
    name: string,
    targetDid: string,
    aliasKind: 'none' | 'alias' | 'migrated_to' | 'canonical',
    proofHash = ZERO_BYTES32,
  ): WriteIntent {
    return { kind: 'set_did_alias', name, targetDid, aliasKind, proofHash, authority: PUBLIC_AUTHORITY, guard: EMPTY_GUARD }
  }

  async buildSetPaymentTarget(
    name: string,
    docTypeInput: string,
    paymentTarget: string,
    options: {
      beneficiary?: Principal
      paymentPolicyHash?: string
      splitPolicyHash?: string
      pricePolicyHash?: string
      rightsPolicyHash?: string
    } = {},
  ): Promise<WriteIntent> {
    const docType = canonicalDocType(docTypeInput)
    return {
      kind: 'set_payment_target',
      name,
      docType,
      expectedVersion: await this.currentDocumentVersion(name, docType),
      paymentTarget,
      beneficiary: options.beneficiary ?? UNSET_PRINCIPAL,
      paymentPolicyHash: options.paymentPolicyHash ?? ZERO_BYTES32,
      splitPolicyHash: options.splitPolicyHash ?? ZERO_BYTES32,
      pricePolicyHash: options.pricePolicyHash ?? ZERO_BYTES32,
      rightsPolicyHash: options.rightsPolicyHash ?? ZERO_BYTES32,
      authority: PUBLIC_AUTHORITY,
      guard: EMPTY_GUARD,
    }
  }

  /** 原子批量：authority + document + owner policy 一次提交，全成或全败。 */
  buildApplyMutations(
    name: string,
    parts: {
      authorityUpdates?: AuthorityKeyUpdateInput[]
      documents?: DocumentUpdateInput[]
      ownerPolicy?: OwnerPolicyUpdateInput
    },
  ): WriteIntent {
    const authorityUpdates = parts.authorityUpdates ?? []
    const documents = parts.documents ?? []
    assertBatchSize(authorityUpdates.length + documents.length, 'mutation')
    const inlineTotal = documents.reduce(
      (sum, update) => sum + update.document.inlineDocument.length,
      0,
    )
    if (inlineTotal > 64 * 1024) {
      throw BnsError.validation(
        MODEL_ERROR_CODE.INLINE_TOO_LARGE,
        `批量 inline 文档合计 ${inlineTotal} 字节，超过 64 KiB 上限`,
      )
    }
    const docTypes = new Set(documents.map((update) => update.docType))
    if (docTypes.size !== documents.length) {
      throw BnsError.validation('INVALID_MUTATION', '同一批 mutation 中 doc type 不得重复')
    }
    return {
      kind: 'apply_mutations',
      name,
      authorityUpdates,
      documents,
      ownerPolicy: parts.ownerPolicy ?? {
        updateMinDocumentIat: false,
        minDocumentIat: 0n,
        reasonHash: ZERO_BYTES32,
      },
      authority: PUBLIC_AUTHORITY,
      guard: EMPTY_GUARD,
    }
  }

  /** 从未发布过时是 0，这正是合约要求的 expectedVersion 初值。 */
  private async currentDocumentVersion(name: string, docType: string): Promise<bigint> {
    const view = await this.repo.documentView(name, docType)
    return view.state?.version ?? 0n
  }
}

function assertBatchSize(count: number, label: string): void {
  if (count > 32) {
    throw BnsError.validation(
      'INVALID_MUTATION',
      `单次提交的 ${label} 数量 ${count} 超过 32 项产品上限`,
    )
  }
}

function deriveAliasFromEvents(name: string, records: import('../types/domain').EventRecord[]): AliasView | null {
  for (const record of records) {
    if (record.event.type === 'did_alias_set' && record.event.data.name === name) {
      return {
        name,
        kind: record.event.data.kind,
        targetDid: record.event.data.targetDid,
        source: 'event_log',
        observedAtSeq: record.seq,
      }
    }
  }
  return null
}

function deriveControllerPolicy(
  records: import('../types/domain').EventRecord[],
): ControllerPolicySnapshot {
  for (const record of records) {
    if (record.event.type === 'controller_policy_updated') {
      return {
        policyHash: record.event.data.policyHash,
        updatedAtSeq: record.seq,
        updatedNameSeq: record.event.data.nameSeq,
        rules: null,
        note: CONTROLLER_POLICY_NOTE,
      }
    }
  }
  return {
    policyHash: null,
    updatedAtSeq: null,
    updatedNameSeq: null,
    rules: null,
    note: CONTROLLER_POLICY_NOTE,
  }
}
