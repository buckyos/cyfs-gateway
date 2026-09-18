/**
 * 名称聚合 Model：名称详情页 8 个 tab 的唯一状态源。
 *
 * 三个必须诚实表达的能力缺口（bns-server 没有对应接口）：
 * 1. 无法列出一个名称的全部 doc type   -> 内置 + 本地历史 + 事件发现，标注“可能不完整”
 * 2. 无法列出全部 authority key         -> 只能按已知 kid 探测
 * 3. 无法读取 controller rules 明细     -> 只有事件里的 policy_hash
 */

import { Store, idleState, type AsyncState } from '../infra/observable'
import type { StoragePort } from '../ports'
import type { ActivityScan } from '../services/read_repository'
import type {
  AliasView,
  AuthorityKeyView,
  AuthoritySetState,
  DocumentState,
  DocumentView,
  NameOverview,
  OwnerResolution,
} from '../types/domain'
import type { AuthorityAssessment } from '../write/authority'

/** 内置常用 doc type（PRD 9.9），只是入口，不代表完整列表。 */
export const BUILTIN_DOC_TYPES = ['owner', 'zone', 'boot', 'device', 'relay', 'payment'] as const

export interface AuthorityKeyProbe {
  kid: string
  /** null = 已探测但该 kid 不存在。 */
  key: AuthorityKeyView | null
  source: 'user_input' | 'local_history' | 'event_log'
}

/** controller 规则明细无法查询，只能给出可验证的部分。 */
export interface ControllerPolicySnapshot {
  /** 来自 controller_policy_updated 事件。 */
  policyHash: string | null
  updatedAtSeq: bigint | null
  updatedNameSeq: bigint | null
  /** 恒为 null：bns-server 没有返回规则明细的接口。 */
  rules: null
  note: string
}

export interface DocTypeEntry {
  docType: string
  source: 'builtin' | 'local_history' | 'event_log' | 'user_input'
}

export interface NameAggregate {
  name: string
  overview: AsyncState<NameOverview | null>
  parent: AsyncState<NameOverview | null>
  owner: AsyncState<OwnerResolution | null>
  authoritySet: AsyncState<AuthoritySetState | null>
  authorityKeys: AsyncState<AuthorityKeyProbe[]>
  /** 已知 doc type 入口，标注来源，UI 必须提示可能不完整。 */
  docTypes: DocTypeEntry[]
  documents: Record<string, AsyncState<DocumentView>>
  documentHistory: Record<string, AsyncState<DocumentState[]>>
  alias: AsyncState<AliasView | null>
  controllerPolicy: AsyncState<ControllerPolicySnapshot>
  activity: AsyncState<ActivityScan>
  /** 当前钱包对该名称的授权预检结果；钱包/网络变化后由 controller 重算。 */
  authority: AuthorityAssessment | null
}

export function emptyAggregate(name: string): NameAggregate {
  return {
    name,
    overview: idleState(),
    parent: idleState(),
    owner: idleState(),
    authoritySet: idleState(),
    authorityKeys: idleState(),
    docTypes: BUILTIN_DOC_TYPES.map((docType) => ({ docType, source: 'builtin' as const })),
    documents: {},
    documentHistory: {},
    alias: idleState(),
    controllerPolicy: idleState(),
    activity: idleState(),
    authority: null,
  }
}

export class NameModel {
  readonly store = new Store<Record<string, NameAggregate>>({})

  constructor(
    private readonly storage: StoragePort,
    private readonly storageKeyPrefix: string,
  ) {}

  get(name: string): NameAggregate {
    return this.store.get()[name] ?? emptyAggregate(name)
  }

  ensure(name: string): NameAggregate {
    const existing = this.store.get()[name]
    if (existing) return existing
    const created = emptyAggregate(name)
    created.docTypes = mergeDocTypes(created.docTypes, this.loadLocalDocTypes(name))
    this.store.update((all) => ({ ...all, [name]: created }))
    return created
  }

  patch(name: string, partial: Partial<NameAggregate>): void {
    this.store.update((all) => {
      const current = all[name] ?? emptyAggregate(name)
      return { ...all, [name]: { ...current, ...partial } }
    })
  }

  patchDocument(name: string, docType: string, state: AsyncState<DocumentView>): void {
    this.store.update((all) => {
      const current = all[name] ?? emptyAggregate(name)
      return {
        ...all,
        [name]: { ...current, documents: { ...current.documents, [docType]: state } },
      }
    })
  }

  patchDocumentHistory(name: string, docType: string, state: AsyncState<DocumentState[]>): void {
    this.store.update((all) => {
      const current = all[name] ?? emptyAggregate(name)
      return {
        ...all,
        [name]: {
          ...current,
          documentHistory: { ...current.documentHistory, [docType]: state },
        },
      }
    })
  }

  /** 用户手工输入或事件里发现的 doc type，加入入口列表并持久化。 */
  addDocType(name: string, docType: string, source: DocTypeEntry['source']): void {
    const current = this.get(name)
    const merged = mergeDocTypes(current.docTypes, [{ docType, source }])
    this.patch(name, { docTypes: merged })
    this.saveLocalDocTypes(
      name,
      merged.filter((entry) => entry.source !== 'builtin').map((entry) => entry.docType),
    )
  }

  // -------------------------------------------------------------------------
  // 已知 kid 注册表
  // -------------------------------------------------------------------------

  knownKids(name: string): string[] {
    return readJsonArray(this.storage, this.kidKey(name))
  }

  addKnownKid(name: string, kid: string): void {
    const kids = new Set(this.knownKids(name))
    kids.add(kid)
    this.storage.set(this.kidKey(name), JSON.stringify([...kids]))
  }

  private kidKey(name: string): string {
    return `${this.storageKeyPrefix}.kids.${name}`
  }

  private docTypeKey(name: string): string {
    return `${this.storageKeyPrefix}.docTypes.${name}`
  }

  private loadLocalDocTypes(name: string): DocTypeEntry[] {
    return readJsonArray(this.storage, this.docTypeKey(name)).map((docType) => ({
      docType,
      source: 'local_history' as const,
    }))
  }

  private saveLocalDocTypes(name: string, docTypes: string[]): void {
    this.storage.set(this.docTypeKey(name), JSON.stringify(docTypes))
  }
}

function mergeDocTypes(current: DocTypeEntry[], extra: DocTypeEntry[]): DocTypeEntry[] {
  const seen = new Map(current.map((entry) => [entry.docType, entry]))
  for (const entry of extra) {
    if (!seen.has(entry.docType)) seen.set(entry.docType, entry)
  }
  return [...seen.values()]
}

function readJsonArray(storage: StoragePort, key: string): string[] {
  const raw = storage.get(key)
  if (!raw) return []
  try {
    const parsed: unknown = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === 'string') : []
  } catch {
    return []
  }
}

export const CONTROLLER_POLICY_NOTE =
  'bns-server 没有返回 controller rule 明细的接口，这里只能展示事件里的 policy_hash；' +
  '规则内容需要由发起方自行保存或从链上 calldata 还原。'
