/**
 * 演示世界：一个装在浏览器里的「链 + indexer + bns-server 投影」。
 *
 * 它维护与真实 bns-server 同形状（wire 层 snake_case）的可变状态，
 * 并模拟写交易的两阶段生命周期（PRD G4）：
 *
 *   submitTx -> pending --(~1.2s)--> succeeded --(~2s, 投影延迟)--> 投影更新
 *
 * succeeded 与投影更新之间的窗口，正是 UI 必须显示「Indexing」的阶段；
 * 演示模式刻意保留这个窗口，让交易中心的三段进度真实可见。
 *
 * 注意：这里的一切都不做密码学校验，仅供原型演示。
 */

import type {
  WireAuthorityKey,
  WireAuthoritySetState,
  WireDocumentState,
  WireEventLogRecord,
  WireLogCheckpoint,
  WireNamePage,
  WireNameState,
  WireOwnerResolution,
  WirePrincipal,
  WireRegistryEvent,
  WireResolveResult,
  WireSystemInfo,
  WireTxState,
  WriteIntent,
} from '../bns_model'
import { ZERO_ADDRESS, ZERO_BYTES32 } from '../bns_model'
import type { AuthorityKeyUpdateInput, DocumentUpdateInput } from '../bns_model'
import { pseudoHash } from './util'

// ---------------------------------------------------------------------------
// 常量：演示身份
// ---------------------------------------------------------------------------

/** 演示钱包地址（与 bns_model 测试替身一致，便于对照）。 */
export const DEMO_WALLET_ADDRESS = '0x71c7656ec7ab88b098defb751b7401b5f6d8976f'
/** carol 的持有人：一个「别人」。 */
export const CAROL_ADDRESS = '0x8ba1f109551bd432803012645ac136ddd64dba72'
/** dave：代办注册服务商 / 另一个第三方。 */
export const DAVE_ADDRESS = '0x2546bcd3c84621e976d8185a91a922ae77ecec30'

export const DEMO_CHAIN_ID = 31337
export const DEMO_CONTRACT_ADDRESS = '0xb45c9ede610bd80b9e5b10c0f6ae2f0e4bfc1d0a'

/** alice 的 authority key（key_data = 演示钱包 20 字节地址）。 */
export const DEMO_ALICE_KID = pseudoHash('alice/authority-key/1')

const DAY = 86_400

// ---------------------------------------------------------------------------
// 内部结构
// ---------------------------------------------------------------------------

interface DemoAlias {
  kind: 'none' | 'alias' | 'migrated_to' | 'canonical'
  target_did: string
}

interface DemoNameEntry {
  state: WireNameState
  /** doc_type -> 各版本（version 升序，最后一个是当前版本）。 */
  documents: Map<string, WireDocumentState[]>
  authoritySet: WireAuthoritySetState
  authorityKeys: Map<string, WireAuthorityKey>
  alias: DemoAlias
}

interface DemoTx {
  tx_hash: string
  state: 'pending' | 'succeeded' | 'reverted'
  block_number: number | null
  confirmations: number
  intent: WriteIntent | null
  from: string
  /** 投影是否已应用（succeeded 之后仍要等一会才应用，模拟 indexer 延迟）。 */
  projected: boolean
}

const nowSeconds = (): number => Math.floor(Date.now() / 1000)

function principalUnset(): WirePrincipal {
  return { kind: 'unset', value: '' }
}

function chainAccount(address: string): WirePrincipal {
  return { kind: 'chain_account', value: address.toLowerCase() }
}

function bnsName(name: string): WirePrincipal {
  return { kind: 'bns_name', value: name }
}

function parentOf(name: string): string | null {
  const index = name.indexOf('.')
  return index === -1 ? null : name.slice(index + 1)
}

// ---------------------------------------------------------------------------
// DemoWorld
// ---------------------------------------------------------------------------

export interface DemoWorldOptions {
  /** 链确认延迟（提交 -> succeeded）。 */
  chainDelayMs?: number
  /** 投影延迟（succeeded -> 投影可查询）。设长一点能看清 Indexing 阶段。 */
  indexerDelayMs?: number
}

export class DemoWorld {
  readonly names = new Map<string, DemoNameEntry>()
  readonly events: WireEventLogRecord[] = []
  readonly txs = new Map<string, DemoTx>()
  private checkpoint: WireLogCheckpoint | null = null
  private txCounter = 0
  private blockNumber = 4_211_058
  private readonly chainDelayMs: number
  private readonly indexerDelayMs: number

  constructor(options: DemoWorldOptions = {}) {
    this.chainDelayMs = options.chainDelayMs ?? 1_300
    this.indexerDelayMs = options.indexerDelayMs ?? 2_200
    seedWorld(this)
  }

  systemInfo(): WireSystemInfo {
    return { ready: true, chain_id: DEMO_CHAIN_ID, contract_address: DEMO_CONTRACT_ADDRESS }
  }

  // -------------------------------------------------------------------------
  // 查询（全部返回 wire 形状）
  // -------------------------------------------------------------------------

  nameState(name: string): WireNameState | null {
    return this.names.get(name)?.state ?? null
  }

  ownerResolution(name: string): WireOwnerResolution | null {
    const entry = this.names.get(name)
    if (!entry) return null
    const effective = this.computeEffectiveOwner(entry.state)
    let authority_root = ZERO_BYTES32
    let authority_seq = 0
    if (effective.owner.kind === 'bns_name') {
      const ownerEntry = this.names.get(effective.owner.value)
      if (ownerEntry) {
        authority_root = ownerEntry.authoritySet.authority_root
        authority_seq = ownerEntry.authoritySet.authority_seq
      }
    }
    return {
      effective_owner: effective.owner,
      source: effective.source,
      authority_root,
      authority_seq,
    }
  }

  authoritySet(name: string): WireAuthoritySetState {
    const entry = this.names.get(name)
    if (!entry) {
      return { name, authority_seq: 0, authority_root: ZERO_BYTES32, active_key_count: 0 }
    }
    return entry.authoritySet
  }

  authorityKey(name: string, kid: string): WireAuthorityKey | null {
    return this.names.get(name)?.authorityKeys.get(kid.toLowerCase()) ?? null
  }

  currentDocument(name: string, docType: string): WireDocumentState | null {
    const versions = this.names.get(name)?.documents.get(docType)
    if (!versions || versions.length === 0) return null
    return versions[versions.length - 1]
  }

  documentVersion(name: string, docType: string, version: number): WireDocumentState | null {
    const versions = this.names.get(name)?.documents.get(docType)
    return versions?.find((doc) => doc.version === version) ?? null
  }

  resolveDocument(name: string, docType: string): WireResolveResult | null {
    const entry = this.names.get(name)
    const doc = this.currentDocument(name, docType)
    const owner = this.ownerResolution(name)
    if (!entry || !doc || !owner) return null
    const effectiveController =
      doc.controller.kind === 'unset' ? owner.effective_owner : doc.controller
    return {
      name_state: entry.state,
      document_state: doc,
      owner,
      effective_controller: effectiveController,
      status: doc.status,
      alias_kind: entry.alias.kind,
      alias_target_did: entry.alias.target_did,
      proof_root: pseudoHash(`proof/${name}/${docType}/${doc.version}`),
    }
  }

  namesByAddress(address: string, cursor: string | null, limit: number): WireNamePage {
    const lower = address.toLowerCase()
    const all = [...this.names.entries()]
      .filter(([, entry]) => entry.state.asset_owner.toLowerCase() === lower)
      .map(([name]) => name)
      .sort()
    const start = cursor ? all.findIndex((name) => name > cursor) : 0
    const safeStart = start === -1 ? all.length : start
    const page = all.slice(safeStart, safeStart + limit)
    const nextIndex = safeStart + page.length
    return {
      names: page,
      next_cursor: nextIndex < all.length ? page[page.length - 1] : null,
    }
  }

  txState(txHash: string): WireTxState {
    const tx = this.txs.get(txHash.toLowerCase())
    if (!tx) return { tx_hash: txHash, state: 'not_found', block_number: null, confirmations: 0 }
    if (tx.state === 'succeeded') tx.confirmations += 1
    return {
      tx_hash: tx.tx_hash,
      state: tx.state,
      block_number: tx.block_number,
      confirmations: tx.confirmations,
    }
  }

  listEvents(fromSeq: number, limit: number): WireEventLogRecord[] {
    return this.events.filter((record) => record.seq >= fromSeq).slice(0, limit)
  }

  latestCheckpoint(): WireLogCheckpoint | null {
    return this.checkpoint
  }

  // -------------------------------------------------------------------------
  // 写：假链的两阶段生命周期
  // -------------------------------------------------------------------------

  submitTx(intent: WriteIntent, from: string): string {
    this.txCounter += 1
    const txHash = pseudoHash(`tx/${this.txCounter}/${intent.kind}/${intent.name}`)
      .slice(0, 66)
      .toLowerCase()
    const tx: DemoTx = {
      tx_hash: txHash,
      state: 'pending',
      block_number: null,
      confirmations: 0,
      intent,
      from,
      projected: false,
    }
    this.txs.set(txHash, tx)

    setTimeout(() => {
      this.blockNumber += 1
      tx.state = 'succeeded'
      tx.block_number = this.blockNumber
      tx.confirmations = 1
      // 投影延迟：succeeded 之后一段时间内，查询仍看到旧状态。
      setTimeout(() => {
        if (tx.intent) this.applyIntent(tx.intent, tx.from)
        tx.projected = true
      }, this.indexerDelayMs)
    }, this.chainDelayMs)

    return txHash
  }

  // -------------------------------------------------------------------------
  // 投影变化（indexer 视角）
  // -------------------------------------------------------------------------

  pushEvent(event: WireRegistryEvent, outerType?: string): void {
    const seq = this.events.length + 1
    const previous = this.events[this.events.length - 1]?.log_root ?? ZERO_BYTES32
    this.events.push({
      seq,
      // owner_document_iat_floor_updated 的外层 event_type 与内层不同（wire.ts 注释）。
      event_type: outerType ?? event.type,
      observed_at: nowSeconds(),
      event_hash: pseudoHash(`event/${seq}/${event.type}`),
      previous_log_root: previous,
      log_root: pseudoHash(`log-root/${seq}`),
      event,
    })
  }

  private touch(entry: DemoNameEntry): void {
    entry.state.name_seq += 1
    entry.state.updated_at = nowSeconds()
  }

  private computeEffectiveOwner(state: WireNameState): {
    owner: WirePrincipal
    source: WireNameState['owner_source']
  } {
    if (state.semantic_owner.kind === 'bns_name') {
      return { owner: state.semantic_owner, source: 'explicit_semantic_owner' }
    }
    const parent = parentOf(state.name)
    if (parent) {
      const parentEntry = this.names.get(parent)
      if (parentEntry) {
        const parentOwner = this.computeEffectiveOwner(parentEntry.state)
        return { owner: parentOwner.owner, source: 'parent_inherited' }
      }
    }
    return { owner: chainAccount(state.asset_owner), source: 'asset_owner_fallback' }
  }

  /** 重算并回写投影里的 effective_owner / owner_source（投影字段是物化的）。 */
  private materializeOwner(entry: DemoNameEntry): void {
    const { owner, source } = this.computeEffectiveOwner(entry.state)
    entry.state.effective_owner = owner
    entry.state.owner_source = source
    entry.state.standard_transfer_enabled =
      entry.state.transferable && entry.state.status === 'active'
  }

  createName(input: {
    name: string
    assetOwner: string
    durationSeconds: number
    gracePeriodSeconds: number
    renewable: boolean
    transferable: boolean
    allowDelegatedSubnames: boolean
    semanticOwner?: WirePrincipal
    registeredAt?: number
    lineageEpoch?: number
  }): DemoNameEntry {
    const registered = input.registeredAt ?? nowSeconds()
    const expire = registered + input.durationSeconds
    const state: WireNameState = {
      name: input.name,
      asset_owner: input.assetOwner.toLowerCase(),
      semantic_owner: input.semanticOwner ?? principalUnset(),
      effective_owner: principalUnset(),
      owner_source: 'none',
      standard_transfer_enabled: false,
      status: 'active',
      registered_at: registered,
      expire_at: expire,
      grace_until: expire + input.gracePeriodSeconds,
      updated_at: registered,
      name_seq: 1,
      owner_document_version: 0,
      min_document_iat: 0,
      owner_policy_seq: 0,
      lineage_epoch: input.lineageEpoch ?? 0,
      renewable: input.renewable,
      transferable: input.transferable,
      allow_delegated_subnames: input.allowDelegatedSubnames,
      namespace_policy_hash: ZERO_BYTES32,
      payment_policy_hash: ZERO_BYTES32,
      alias_state_hash: ZERO_BYTES32,
    }
    const entry: DemoNameEntry = {
      state,
      documents: new Map(),
      authoritySet: {
        name: input.name,
        authority_seq: 0,
        authority_root: ZERO_BYTES32,
        active_key_count: 0,
      },
      authorityKeys: new Map(),
      alias: { kind: 'none', target_did: '' },
    }
    this.names.set(input.name, entry)
    this.materializeOwner(entry)
    return entry
  }

  publishDocument(
    entry: DemoNameEntry,
    update: DocumentUpdateInput,
    options: { emitEvent?: boolean } = {},
  ): WireDocumentState {
    const docType = update.docType
    const versions = entry.documents.get(docType) ?? []
    const version = (versions[versions.length - 1]?.version ?? 0) + 1
    const inline = Array.from(update.document.inlineDocument)
    const doc: WireDocumentState = {
      name: entry.state.name,
      doc_type: docType,
      version,
      previous_version: versions[versions.length - 1]?.version ?? 0,
      status: 'active',
      document: {
        storage_type: update.document.storageType || 'inline',
        uri: update.document.uri,
        inline_document: inline,
        content_hash: update.document.contentHash,
        schema: update.document.schema,
        codec: update.document.codec,
        extra_hash: update.document.extraHash,
      },
      controller: update.controller as WirePrincipal,
      beneficiary: update.beneficiary as WirePrincipal,
      payment_target: update.paymentTarget,
      valid_from: nowSeconds(),
      expire_at: Number(update.expireAt),
      revoked_at: 0,
      controller_policy_hash: update.controllerPolicyHash,
      payment_policy_hash: update.paymentPolicyHash,
      split_policy_hash: update.splitPolicyHash,
      price_policy_hash: update.pricePolicyHash,
      rights_policy_hash: update.rightsPolicyHash,
      document_state_hash: pseudoHash(`doc-state/${entry.state.name}/${docType}/${version}`),
    }
    versions.push(doc)
    entry.documents.set(docType, versions)
    if (docType === 'owner') entry.state.owner_document_version = version
    if (options.emitEvent !== false) {
      this.pushEvent({
        type: 'document_published',
        data: {
          name: entry.state.name,
          doc_type: docType,
          version,
          content_hash: doc.document.content_hash,
          document_state_hash: doc.document_state_hash,
        },
      })
    }
    return doc
  }

  applyAuthorityUpdates(entry: DemoNameEntry, updates: AuthorityKeyUpdateInput[]): void {
    for (const update of updates) {
      const kid = update.key.kid.toLowerCase()
      if (update.active) {
        entry.authorityKeys.set(kid, {
          kid,
          verification_method: update.key.verificationMethod,
          key_data: Array.from(update.key.keyData),
          purposes: update.key.purposes,
          valid_from: Number(update.key.validFrom),
          valid_until: Number(update.key.validUntil),
          status: update.key.status,
          metadata_hash: update.key.metadataHash,
        })
      } else {
        const existing = entry.authorityKeys.get(kid)
        if (existing) existing.status = 'revoked'
      }
    }
    const activeCount = [...entry.authorityKeys.values()].filter(
      (key) => key.status === 'active',
    ).length
    entry.authoritySet = {
      name: entry.state.name,
      authority_seq: entry.authoritySet.authority_seq + 1,
      authority_root: pseudoHash(
        `authority-root/${entry.state.name}/${entry.authoritySet.authority_seq + 1}`,
      ),
      active_key_count: activeCount,
    }
    this.pushEvent({
      type: 'authority_keys_updated',
      data: {
        name: entry.state.name,
        authority_seq: entry.authoritySet.authority_seq,
        authority_root: entry.authoritySet.authority_root,
      },
    })
  }

  /** indexer 视角应用一笔已上链交易的投影变化。 */
  applyIntent(intent: WriteIntent, from: string): void {
    switch (intent.kind) {
      case 'register_name': {
        const existing = this.names.get(intent.name)
        const entry = this.createName({
          name: intent.name,
          assetOwner: intent.assetOwner,
          durationSeconds: Number(intent.options.duration),
          gracePeriodSeconds: Number(intent.options.gracePeriod),
          renewable: intent.options.renewable,
          transferable: intent.options.transferable,
          allowDelegatedSubnames: intent.options.allowDelegatedSubnames,
          semanticOwner: intent.options.initialSemanticOwner as WirePrincipal,
          lineageEpoch: existing ? existing.state.lineage_epoch + 1 : 0,
        })
        this.pushEvent({
          type: 'name_registered',
          data: {
            name: intent.name,
            asset_owner: intent.assetOwner.toLowerCase(),
            expire_at: entry.state.expire_at,
            lineage_epoch: entry.state.lineage_epoch,
            name_seq: entry.state.name_seq,
          },
        })
        if (intent.authorityUpdates.length > 0) {
          this.applyAuthorityUpdates(entry, intent.authorityUpdates)
        }
        if (intent.semanticOwnerAfterAuthority.kind === 'bns_name') {
          entry.state.semantic_owner = intent.semanticOwnerAfterAuthority as WirePrincipal
          this.materializeOwner(entry)
        }
        if (intent.controllerPolicy.length > 0) {
          const policyHash =
            intent.controllerPolicyHash !== ZERO_BYTES32
              ? intent.controllerPolicyHash
              : pseudoHash(`controller-policy/${intent.name}/1`)
          this.pushEvent({
            type: 'controller_policy_updated',
            data: { name: intent.name, policy_hash: policyHash, name_seq: entry.state.name_seq },
          })
        }
        for (const doc of intent.initialDocuments) this.publishDocument(entry, doc)
        break
      }
      case 'renew_name': {
        const entry = this.names.get(intent.name)
        if (!entry) return
        const grace = entry.state.grace_until - entry.state.expire_at
        entry.state.expire_at += Number(intent.duration)
        entry.state.grace_until = entry.state.expire_at + grace
        this.touch(entry)
        this.pushEvent({
          type: 'name_renewed',
          data: {
            name: intent.name,
            expire_at: entry.state.expire_at,
            name_seq: entry.state.name_seq,
          },
        })
        break
      }
      case 'transfer_name': {
        const entry = this.names.get(intent.name)
        if (!entry) return
        const oldOwner = entry.state.asset_owner
        entry.state.asset_owner = intent.newAssetOwner.toLowerCase()
        entry.state.semantic_owner = intent.newSemanticOwner as WirePrincipal
        this.touch(entry)
        this.materializeOwner(entry)
        this.pushEvent({
          type: 'name_asset_transferred',
          data: {
            name: intent.name,
            old_asset_owner: oldOwner,
            new_asset_owner: entry.state.asset_owner,
            standard_transfer: false,
            name_seq: entry.state.name_seq,
          },
        })
        for (const doc of intent.atomicDocumentUpdates) this.publishDocument(entry, doc)
        break
      }
      case 'set_name_owner': {
        const entry = this.names.get(intent.name)
        if (!entry) return
        entry.state.semantic_owner = intent.semanticOwner as WirePrincipal
        this.touch(entry)
        this.materializeOwner(entry)
        this.pushEvent({
          type: 'name_owner_updated',
          data: {
            name: intent.name,
            owner: entry.state.effective_owner,
            owner_source: entry.state.owner_source,
            standard_transfer_enabled: entry.state.standard_transfer_enabled,
            name_seq: entry.state.name_seq,
          },
        })
        break
      }
      case 'release_name': {
        const entry = this.names.get(intent.name)
        if (!entry) return
        entry.state.status = intent.mode === 'tombstone_forever' ? 'tombstoned' : 'released'
        this.touch(entry)
        this.materializeOwner(entry)
        this.pushEvent({
          type: 'name_released',
          data: {
            name: intent.name,
            mode: intent.mode,
            reason_hash: intent.reasonHash,
            name_seq: entry.state.name_seq,
          },
        })
        break
      }
      case 'set_namespace_policy': {
        const entry = this.names.get(intent.name)
        if (!entry) return
        entry.state.allow_delegated_subnames = intent.allowDelegatedSubnames
        entry.state.namespace_policy_hash = intent.namespacePolicyHash
        this.touch(entry)
        this.pushEvent({
          type: 'namespace_policy_updated',
          data: {
            name: intent.name,
            allow_delegated_subnames: intent.allowDelegatedSubnames,
            namespace_policy_hash: intent.namespacePolicyHash,
            name_seq: entry.state.name_seq,
          },
        })
        break
      }
      case 'update_authority_keys': {
        const entry = this.names.get(intent.name)
        if (!entry) return
        this.applyAuthorityUpdates(entry, intent.updates)
        this.touch(entry)
        break
      }
      case 'set_min_document_iat': {
        const entry = this.names.get(intent.name)
        if (!entry) return
        const previous = entry.state.min_document_iat
        entry.state.min_document_iat = Number(intent.minDocumentIat)
        entry.state.owner_policy_seq += 1
        this.touch(entry)
        this.pushEvent(
          {
            type: 'owner_document_iat_floor_updated',
            data: {
              name: intent.name,
              previous_min_document_iat: previous,
              new_min_document_iat: entry.state.min_document_iat,
              owner_policy_seq: entry.state.owner_policy_seq,
              name_seq: entry.state.name_seq,
              reason_hash: intent.reasonHash,
            },
          },
          // 外层 event_type 与内层不同的真实怪癖（wire.ts 注释）。
          'owner_iat_floor_updated',
        )
        break
      }
      case 'publish_document': {
        const entry = this.names.get(intent.name)
        if (!entry) return
        this.publishDocument(entry, {
          docType: intent.docType,
          expectedVersion: intent.expectedVersion,
          document: intent.document,
          controller: intent.controller,
          beneficiary: intent.beneficiary,
          paymentTarget: intent.paymentTarget,
          expireAt: intent.expireAt,
          controllerPolicyHash: intent.controllerPolicyHash,
          paymentPolicyHash: intent.paymentPolicyHash,
          splitPolicyHash: intent.splitPolicyHash,
          pricePolicyHash: intent.pricePolicyHash,
          rightsPolicyHash: intent.rightsPolicyHash,
        })
        this.touch(entry)
        break
      }
      case 'revoke_document': {
        const entry = this.names.get(intent.name)
        if (!entry) return
        const versions = entry.documents.get(intent.docType)
        const current = versions?.[versions.length - 1]
        if (!versions || !current) return
        const revoked: WireDocumentState = {
          ...current,
          version: current.version + 1,
          previous_version: current.version,
          status: 'revoked',
          revoked_at: nowSeconds(),
          // 撤销版本清零 payment 与各 policy hash（PRD 9.11）。
          payment_target: ZERO_ADDRESS,
          controller_policy_hash: ZERO_BYTES32,
          payment_policy_hash: ZERO_BYTES32,
          split_policy_hash: ZERO_BYTES32,
          price_policy_hash: ZERO_BYTES32,
          rights_policy_hash: ZERO_BYTES32,
          document_state_hash: pseudoHash(
            `doc-state/${intent.name}/${intent.docType}/${current.version + 1}/revoked`,
          ),
        }
        versions.push(revoked)
        if (intent.docType === 'owner') entry.state.owner_document_version = revoked.version
        this.touch(entry)
        this.pushEvent({
          type: 'document_revoked',
          data: {
            name: intent.name,
            doc_type: intent.docType,
            previous_version: current.version,
            new_version: revoked.version,
            reason_hash: intent.reasonHash,
          },
        })
        break
      }
      case 'set_controller_policy': {
        const entry = this.names.get(intent.name)
        if (!entry) return
        this.touch(entry)
        const policyHash =
          intent.policyHash !== ZERO_BYTES32
            ? intent.policyHash
            : intent.rules.length === 0
              ? ZERO_BYTES32
              : pseudoHash(`controller-policy/${intent.name}/${entry.state.name_seq}`)
        this.pushEvent({
          type: 'controller_policy_updated',
          data: { name: intent.name, policy_hash: policyHash, name_seq: entry.state.name_seq },
        })
        break
      }
      case 'set_did_alias': {
        const entry = this.names.get(intent.name)
        if (!entry) return
        entry.alias = { kind: intent.aliasKind, target_did: intent.targetDid }
        entry.state.alias_state_hash =
          intent.aliasKind === 'none'
            ? ZERO_BYTES32
            : pseudoHash(`alias/${intent.name}/${intent.targetDid}`)
        this.touch(entry)
        this.pushEvent({
          type: 'did_alias_set',
          data: {
            name: intent.name,
            target_did: intent.targetDid,
            kind: intent.aliasKind,
            proof_hash: intent.proofHash,
            name_seq: entry.state.name_seq,
          },
        })
        break
      }
      case 'set_payment_target': {
        const entry = this.names.get(intent.name)
        if (!entry) return
        const versions = entry.documents.get(intent.docType)
        const current = versions?.[versions.length - 1]
        if (!current) return
        current.payment_target = intent.paymentTarget
        current.beneficiary = intent.beneficiary as WirePrincipal
        current.payment_policy_hash = intent.paymentPolicyHash
        current.split_policy_hash = intent.splitPolicyHash
        current.price_policy_hash = intent.pricePolicyHash
        current.rights_policy_hash = intent.rightsPolicyHash
        current.document_state_hash = pseudoHash(
          `doc-state/${intent.name}/${intent.docType}/${current.version}/payment/${entry.state.name_seq + 1}`,
        )
        entry.state.payment_policy_hash = intent.paymentPolicyHash
        this.touch(entry)
        this.pushEvent({
          type: 'payment_target_updated',
          data: {
            name: intent.name,
            doc_type: intent.docType,
            payment_target: intent.paymentTarget,
            payment_policy_hash: intent.paymentPolicyHash,
            version: current.version,
          },
        })
        break
      }
      case 'apply_mutations': {
        const entry = this.names.get(intent.name)
        if (!entry) return
        if (intent.authorityUpdates.length > 0) {
          this.applyAuthorityUpdates(entry, intent.authorityUpdates)
        }
        for (const doc of intent.documents) this.publishDocument(entry, doc)
        if (intent.ownerPolicy.updateMinDocumentIat) {
          const previous = entry.state.min_document_iat
          entry.state.min_document_iat = Number(intent.ownerPolicy.minDocumentIat)
          entry.state.owner_policy_seq += 1
          this.pushEvent(
            {
              type: 'owner_document_iat_floor_updated',
              data: {
                name: intent.name,
                previous_min_document_iat: previous,
                new_min_document_iat: entry.state.min_document_iat,
                owner_policy_seq: entry.state.owner_policy_seq,
                name_seq: entry.state.name_seq + 1,
                reason_hash: intent.ownerPolicy.reasonHash,
              },
            },
            'owner_iat_floor_updated',
          )
        }
        this.touch(entry)
        break
      }
      case 'publish_log_checkpoint': {
        this.setCheckpoint(from)
        break
      }
    }
  }

  setCheckpoint(issuer: string): void {
    const lastSeq = this.events.length
    this.checkpoint = {
      log_root: this.events[this.events.length - 1]?.log_root ?? ZERO_BYTES32,
      last_seq: lastSeq,
      issued_at: nowSeconds(),
      issuer: chainAccount(issuer),
      external_anchor: pseudoHash(`anchor/${lastSeq}`),
    }
    this.pushEvent({
      type: 'log_checkpoint_published',
      data: {
        log_root: this.checkpoint.log_root,
        last_seq: lastSeq,
        issued_at: this.checkpoint.issued_at,
        external_anchor: this.checkpoint.external_anchor,
      },
    })
  }
}

// ---------------------------------------------------------------------------
// 种子世界：覆盖 PRD 9.3 的账号 / 作品 / 买来的资产 / 仅持有等全部分组场景
// ---------------------------------------------------------------------------

function inlineDoc(json: unknown): { bytes: Uint8Array; hash: string } {
  const text = JSON.stringify(json, null, 2)
  const bytes = new TextEncoder().encode(text)
  return { bytes, hash: pseudoHash(`content/${text}`) }
}

function docUpdate(
  docType: string,
  json: unknown,
  overrides: Partial<DocumentUpdateInput> = {},
): DocumentUpdateInput {
  const { bytes, hash } = inlineDoc(json)
  return {
    docType,
    expectedVersion: 0n,
    document: {
      storageType: 'inline',
      uri: '',
      inlineDocument: bytes,
      contentHash: hash,
      schema: ZERO_BYTES32,
      codec: ZERO_BYTES32,
      extraHash: ZERO_BYTES32,
    },
    controller: { kind: 'unset', value: '' },
    beneficiary: { kind: 'unset', value: '' },
    paymentTarget: ZERO_ADDRESS,
    expireAt: 0n,
    controllerPolicyHash: ZERO_BYTES32,
    paymentPolicyHash: ZERO_BYTES32,
    splitPolicyHash: ZERO_BYTES32,
    pricePolicyHash: ZERO_BYTES32,
    rightsPolicyHash: ZERO_BYTES32,
    ...overrides,
  }
}

function seedWorld(world: DemoWorld): void {
  const now = nowSeconds()

  // ---- alice：主账号（一级名称 = 账号） -----------------------------------
  const alice = world.createName({
    name: 'alice',
    assetOwner: DEMO_WALLET_ADDRESS,
    durationSeconds: 730 * DAY,
    gracePeriodSeconds: 90 * DAY,
    renewable: true,
    transferable: true,
    allowDelegatedSubnames: true,
    registeredAt: now - 400 * DAY,
  })
  world.pushEvent({
    type: 'name_registered',
    data: {
      name: 'alice',
      asset_owner: DEMO_WALLET_ADDRESS,
      expire_at: alice.state.expire_at,
      lineage_epoch: 0,
      name_seq: 1,
    },
  })
  // 代办注册的故事：alice 由服务商 dave 代办注册，注册时写入了以 dave 为 principal 的
  // controller rule（PRD 9.24）。policy_hash 非零 -> UI 显示「可能存在代办授权」的推断提示。
  world.pushEvent({
    type: 'controller_policy_updated',
    data: {
      name: 'alice',
      policy_hash: pseudoHash('controller-policy/alice/registrar-dave'),
      name_seq: 1,
    },
  })
  // alice 自己的 authority key（key_data = 演示钱包地址，authentication + sign-document）。
  world.applyAuthorityUpdates(alice, [
    {
      active: true,
      key: {
        kid: DEMO_ALICE_KID,
        verificationMethod: pseudoHash('verification-method/eip191'),
        keyData: hexAddressBytes(DEMO_WALLET_ADDRESS),
        purposes: 1 | 4,
        validFrom: 0n,
        validUntil: 0n,
        status: 'active',
        metadataHash: ZERO_BYTES32,
      },
    },
  ])
  world.publishDocument(alice, docUpdate('owner', {
    did: 'did:bns:alice',
    display_name: 'Alice',
    profile: '演示账号：一级名称即账号',
  }))
  world.publishDocument(alice, docUpdate('zone', {
    did: 'did:bns:alice',
    oods: ['ood1.alice'],
    sn: 'sn.buckyos.io',
    version: 1,
  }))
  // zone 文档发布过第二版：历史版本演示。
  world.publishDocument(alice, docUpdate('zone', {
    did: 'did:bns:alice',
    oods: ['ood1.alice', 'ood2.alice'],
    sn: 'sn.buckyos.io',
    version: 2,
  }))
  world.publishDocument(alice, docUpdate('payment', {
    did: 'did:bns:alice',
    accept: ['evm'],
    note: '打赏地址见 payment_target',
  }, { paymentTarget: DEMO_WALLET_ADDRESS }))
  alice.state.name_seq = 6
  // alice 设置过 DID alias（事件 + 投影都有）。
  alice.alias = { kind: 'alias', target_did: 'did:web:alice.example.com' }
  alice.state.alias_state_hash = pseudoHash('alias/alice/did:web')
  world.pushEvent({
    type: 'did_alias_set',
    data: {
      name: 'alice',
      target_did: 'did:web:alice.example.com',
      kind: 'alias',
      proof_hash: ZERO_BYTES32,
      name_seq: 5,
    },
  })

  // ---- alice 的作品（二级名称） -------------------------------------------
  const blog = world.createName({
    name: 'blog.alice',
    assetOwner: DEMO_WALLET_ADDRESS,
    durationSeconds: 365 * DAY,
    gracePeriodSeconds: 30 * DAY,
    renewable: true,
    transferable: true,
    allowDelegatedSubnames: false,
    registeredAt: now - 200 * DAY,
  })
  world.pushEvent({
    type: 'name_registered',
    data: {
      name: 'blog.alice',
      asset_owner: DEMO_WALLET_ADDRESS,
      expire_at: blog.state.expire_at,
      lineage_epoch: 0,
      name_seq: 1,
    },
  })
  world.publishDocument(blog, docUpdate('zone', {
    did: 'did:bns:blog.alice',
    site: 'https://blog.alice.example',
  }))

  world.createName({
    name: 'laptop.alice',
    assetOwner: DEMO_WALLET_ADDRESS,
    durationSeconds: 365 * DAY,
    gracePeriodSeconds: 30 * DAY,
    renewable: true,
    transferable: false,
    allowDelegatedSubnames: false,
    registeredAt: now - 150 * DAY,
  })
  world.pushEvent({
    type: 'name_registered',
    data: {
      name: 'laptop.alice',
      asset_owner: DEMO_WALLET_ADDRESS,
      expire_at: now + 215 * DAY,
      lineage_epoch: 0,
      name_seq: 1,
    },
  })
  // laptop 丢过一次：owner 吊销历史签发（9.16 的故事线）。
  alice.state.min_document_iat = now - 30 * DAY
  alice.state.owner_policy_seq = 1
  world.pushEvent(
    {
      type: 'owner_document_iat_floor_updated',
      data: {
        name: 'alice',
        previous_min_document_iat: 0,
        new_min_document_iat: now - 30 * DAY,
        owner_policy_seq: 1,
        name_seq: 6,
        reason_hash: pseudoHash('reason/laptop-lost'),
      },
    },
    'owner_iat_floor_updated',
  )

  // ---- bob：第二个账号（触发账号切换器） -----------------------------------
  const bob = world.createName({
    name: 'bob',
    assetOwner: DEMO_WALLET_ADDRESS,
    durationSeconds: 400 * DAY,
    gracePeriodSeconds: 60 * DAY,
    renewable: true,
    transferable: true,
    allowDelegatedSubnames: false,
    registeredAt: now - 370 * DAY,
  })
  // bob 快到期了：首页/账号页显示续期提醒。
  bob.state.expire_at = now + 23 * DAY
  bob.state.grace_until = bob.state.expire_at + 60 * DAY
  world.pushEvent({
    type: 'name_registered',
    data: {
      name: 'bob',
      asset_owner: DEMO_WALLET_ADDRESS,
      expire_at: bob.state.expire_at,
      lineage_epoch: 0,
      name_seq: 1,
    },
  })
  world.createName({
    name: 'shop.bob',
    assetOwner: DEMO_WALLET_ADDRESS,
    durationSeconds: 365 * DAY,
    gracePeriodSeconds: 30 * DAY,
    renewable: true,
    transferable: true,
    allowDelegatedSubnames: false,
    registeredAt: now - 90 * DAY,
  })
  world.pushEvent({
    type: 'name_registered',
    data: {
      name: 'shop.bob',
      asset_owner: DEMO_WALLET_ADDRESS,
      expire_at: now + 275 * DAY,
      lineage_epoch: 0,
      name_seq: 1,
    },
  })

  // ---- carol：别人的账号 ---------------------------------------------------
  const carol = world.createName({
    name: 'carol',
    assetOwner: CAROL_ADDRESS,
    durationSeconds: 730 * DAY,
    gracePeriodSeconds: 90 * DAY,
    renewable: true,
    transferable: true,
    allowDelegatedSubnames: true,
    registeredAt: now - 500 * DAY,
  })
  world.pushEvent({
    type: 'name_registered',
    data: {
      name: 'carol',
      asset_owner: CAROL_ADDRESS,
      expire_at: carol.state.expire_at,
      lineage_epoch: 0,
      name_seq: 1,
    },
  })
  world.publishDocument(carol, docUpdate('zone', {
    did: 'did:bns:carol',
    oods: ['ood1.carol'],
  }))

  // book.carol：从 carol 买来产权，但 semantic owner 保持 Unset ->
  // 结构上仍继承 carol 的控制权（PRD 9.3「仅持有」状态的活教材）。
  const book = world.createName({
    name: 'book.carol',
    assetOwner: DEMO_WALLET_ADDRESS,
    durationSeconds: 365 * DAY,
    gracePeriodSeconds: 30 * DAY,
    renewable: true,
    transferable: true,
    allowDelegatedSubnames: false,
    registeredAt: now - 120 * DAY,
  })
  world.pushEvent({
    type: 'name_asset_transferred',
    data: {
      name: 'book.carol',
      old_asset_owner: CAROL_ADDRESS,
      new_asset_owner: DEMO_WALLET_ADDRESS,
      standard_transfer: false,
      name_seq: 2,
    },
  })
  book.state.name_seq = 2
  world.publishDocument(book, docUpdate('zone', {
    did: 'did:bns:book.carol',
    site: 'https://book.example',
  }))

  // column.carol：同样买来，但转移时正确设置了 semantic owner = alice ->
  // 控制权已随交易接管，与 book.carol 形成对照。
  const column = world.createName({
    name: 'column.carol',
    assetOwner: DEMO_WALLET_ADDRESS,
    durationSeconds: 365 * DAY,
    gracePeriodSeconds: 30 * DAY,
    renewable: true,
    transferable: true,
    allowDelegatedSubnames: false,
    semanticOwner: bnsName('alice'),
    registeredAt: now - 60 * DAY,
  })
  column.state.name_seq = 2
  world.pushEvent({
    type: 'name_asset_transferred',
    data: {
      name: 'column.carol',
      old_asset_owner: CAROL_ADDRESS,
      new_asset_owner: DEMO_WALLET_ADDRESS,
      standard_transfer: false,
      name_seq: 2,
    },
  })
  world.pushEvent({
    type: 'name_owner_updated',
    data: {
      name: 'column.carol',
      owner: bnsName('alice'),
      owner_source: 'explicit_semantic_owner',
      standard_transfer_enabled: true,
      name_seq: 2,
    },
  })

  // ---- 各种状态的第三方名称：搜索/详情演示 --------------------------------
  const lapsed = world.createName({
    name: 'expired-demo',
    assetOwner: DAVE_ADDRESS,
    durationSeconds: 365 * DAY,
    gracePeriodSeconds: 60 * DAY,
    renewable: true,
    transferable: true,
    allowDelegatedSubnames: false,
    registeredAt: now - 385 * DAY,
  })
  // raw status 仍是 active，但时间上已过期、处于 grace 窗口（PRD 6.4.1 双状态展示）。
  lapsed.state.expire_at = now - 20 * DAY
  lapsed.state.grace_until = now + 40 * DAY

  const released = world.createName({
    name: 'released-demo',
    assetOwner: DAVE_ADDRESS,
    durationSeconds: 365 * DAY,
    gracePeriodSeconds: 30 * DAY,
    renewable: true,
    transferable: true,
    allowDelegatedSubnames: false,
    registeredAt: now - 300 * DAY,
  })
  released.state.status = 'released'
  world.pushEvent({
    type: 'name_released',
    data: {
      name: 'released-demo',
      mode: 'release_after_grace',
      reason_hash: ZERO_BYTES32,
      name_seq: 2,
    },
  })

  const tomb = world.createName({
    name: 'tomb-demo',
    assetOwner: DAVE_ADDRESS,
    durationSeconds: 365 * DAY,
    gracePeriodSeconds: 30 * DAY,
    renewable: false,
    transferable: false,
    allowDelegatedSubnames: false,
    registeredAt: now - 260 * DAY,
  })
  tomb.state.status = 'tombstoned'
  world.pushEvent({
    type: 'name_released',
    data: {
      name: 'tomb-demo',
      mode: 'tombstone_forever',
      reason_hash: pseudoHash('reason/impersonation'),
      name_seq: 2,
    },
  })

  const dave = world.createName({
    name: 'dave',
    assetOwner: DAVE_ADDRESS,
    durationSeconds: 500 * DAY,
    gracePeriodSeconds: 60 * DAY,
    renewable: true,
    transferable: true,
    allowDelegatedSubnames: false,
    registeredAt: now - 30 * DAY,
  })
  world.pushEvent({
    type: 'name_renewed',
    data: { name: 'dave', expire_at: dave.state.expire_at, name_seq: 2 },
  })

  // ---- checkpoint ----------------------------------------------------------
  world.setCheckpoint(DAVE_ADDRESS)
}

function hexAddressBytes(address: string): Uint8Array {
  const clean = address.slice(2)
  const bytes = new Uint8Array(20)
  for (let i = 0; i < 20; i += 1) {
    bytes[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}
