export type NameRecord = {
  name: string
  status: 'Active' | 'Expired' | 'Released' | 'Tombstoned'
  derivedStatus: string
  assetOwner: string
  semanticOwner: string
  effectiveOwner: string
  ownerSource: 'asset_owner_fallback' | 'explicit_semantic_owner' | 'parent_inherited'
  expiresAt: string
  registeredAt: string
  graceUntil: string
  nameSeq: number
  lineageEpoch: number
  renewable: boolean
  transferable: boolean
  delegatedSubnames: boolean
  ownerDocumentVersion: number
}

export type DocumentRecord = {
  type: string
  label: string
  version: number
  status: 'Active' | 'Revoked' | 'Missing'
  storage: 'Inline' | 'URI'
  updatedAt: string
  preview: string
  hash: string
}

export type TransactionStage =
  | 'awaiting'
  | 'pending'
  | 'indexing'
  | 'completed'
  | 'reverted'

export type TransactionRecord = {
  hash: string
  operation: string
  target: string
  submittedAt: string
  stage: TransactionStage
  chainLabel: string
  detail: string
}

export type EventRecord = {
  seq: number
  type: string
  name: string
  actor: string
  observedAt: string
  hash: string
  detail: string
}

export const shortAddress = (address: string) =>
  `${address.slice(0, 6)}…${address.slice(-4)}`

export const walletAddress = '0x71C7656EC7ab88b098defB751B7401B5f6d8976F'
export const proxyAddress = '0xB2D3a40E76042A8C4f0EcA5238C6D799C43B1A20'

export const names: NameRecord[] = [
  {
    name: 'alice',
    status: 'Active',
    derivedStatus: '有效 · 余 284 天',
    assetOwner: walletAddress,
    semanticOwner: 'unset',
    effectiveOwner: walletAddress,
    ownerSource: 'asset_owner_fallback',
    expiresAt: '2027-05-10 12:00',
    registeredAt: '2025-05-10 12:00',
    graceUntil: '2027-06-09 12:00',
    nameSeq: 42,
    lineageEpoch: 1,
    renewable: true,
    transferable: true,
    delegatedSubnames: false,
    ownerDocumentVersion: 4,
  },
  {
    name: 'device.alice',
    status: 'Active',
    derivedStatus: '有效 · 余 91 天',
    assetOwner: walletAddress,
    semanticOwner: 'unset',
    effectiveOwner: 'alice',
    ownerSource: 'parent_inherited',
    expiresAt: '2026-10-29 09:30',
    registeredAt: '2026-04-29 09:30',
    graceUntil: '2026-11-28 09:30',
    nameSeq: 12,
    lineageEpoch: 1,
    renewable: true,
    transferable: false,
    delegatedSubnames: false,
    ownerDocumentVersion: 2,
  },
  {
    name: 'studio',
    status: 'Active',
    derivedStatus: '有效 · 余 612 天',
    assetOwner: walletAddress,
    semanticOwner: 'collective',
    effectiveOwner: 'collective',
    ownerSource: 'explicit_semantic_owner',
    expiresAt: '2028-04-02 16:20',
    registeredAt: '2026-04-02 16:20',
    graceUntil: '2028-05-02 16:20',
    nameSeq: 8,
    lineageEpoch: 1,
    renewable: true,
    transferable: true,
    delegatedSubnames: true,
    ownerDocumentVersion: 1,
  },
]

export const documents: DocumentRecord[] = [
  {
    type: 'owner',
    label: 'Owner Document',
    version: 4,
    status: 'Active',
    storage: 'Inline',
    updatedAt: '今天 09:42',
    preview: '{ "id": "did:bns:alice", "alsoKnownAs": ["did:web:alice.me"] }',
    hash: '0x4bfa60e5b92fdcd0d1a2fe99825183e2e9c27d61a1bf7aa2d8f84db0125f4bd2',
  },
  {
    type: 'zone',
    label: 'DNS Zone',
    version: 7,
    status: 'Active',
    storage: 'URI',
    updatedAt: '7 月 26 日',
    preview: 'https://gateway.example/zone/alice.json',
    hash: '0x8e7af3a228f61818a201678e8d4b30b2dcbb3d92f809b72f6c918a9d1a41a6c0',
  },
  {
    type: 'payment',
    label: 'Payment',
    version: 2,
    status: 'Active',
    storage: 'Inline',
    updatedAt: '7 月 14 日',
    preview: '{ "network": "eip155:8453", "asset": "USDC" }',
    hash: '0x5fa93d38186257977d596441201ac260353623e94aa27aa7ca5a534e9e8cf421',
  },
  {
    type: 'boot',
    label: 'Boot',
    version: 3,
    status: 'Revoked',
    storage: 'URI',
    updatedAt: '6 月 30 日',
    preview: 'ipfs://bafybeidv…',
    hash: '0xd027b32ff2037535592ce973344140e209a2fb1dd73f884ef12742522749575f',
  },
]

export const transactions: TransactionRecord[] = [
  {
    hash: '0x2fd4ae81b3a13ffb87f24a339b54f3818d0d142f543d8d5066a35f8cb8cc9f01',
    operation: '发布 zone 文档',
    target: 'alice',
    submittedAt: '刚刚',
    stage: 'indexing',
    chainLabel: '链上已确认',
    detail: '区块 #18,492,120 · 等待 bns-indexer 投影 version 8',
  },
  {
    hash: '0xaed541c9161f94bf98958e6e3b50eb29eb74410589a6bd6f0ea6a6aa1102ca4d',
    operation: '续期名称',
    target: 'device.alice',
    submittedAt: '12 分钟前',
    stage: 'completed',
    chainLabel: '已完成',
    detail: 'expire_at 与 name_seq 已在查询投影中更新',
  },
  {
    hash: '0x349bdd72f27c57fc6eac423e6538f4cb01c13585fcfa829b87c98a8d9d151288',
    operation: '更新 Authority Key',
    target: 'studio',
    submittedAt: '昨天 18:06',
    stage: 'reverted',
    chainLabel: '交易回退',
    detail: 'StaleNameSeq · 预期 7，当前 8',
  },
  {
    hash: '0x899cbf8ce25722b9e1f90882978459d4201e722e7f0eb07dca386207867a9e5f',
    operation: '注册名称',
    target: 'oak',
    submittedAt: '7 月 28 日',
    stage: 'completed',
    chainLabel: '已完成',
    detail: 'name_seq 1 · lineage_epoch 1',
  },
]

export const events: EventRecord[] = [
  {
    seq: 1402,
    type: 'document_published',
    name: 'alice',
    actor: walletAddress,
    observedAt: '09:42:18',
    hash: '0xc151ac8c49c5',
    detail: 'owner · version 4',
  },
  {
    seq: 1401,
    type: 'payment_target_updated',
    name: 'pixel',
    actor: '0x8a4Fc47A3c3406248f5bC6D504B48C5709462175',
    observedAt: '09:37:02',
    hash: '0x38a95f0a0271',
    detail: 'payment · version 2',
  },
  {
    seq: 1400,
    type: 'name_renewed',
    name: 'device.alice',
    actor: walletAddress,
    observedAt: '09:30:44',
    hash: '0x1c07aaf62e1e',
    detail: '+180 days · name_seq 12',
  },
  {
    seq: 1399,
    type: 'name_registered',
    name: 'orbit',
    actor: '0x44CA802eB3bb5D622fAaC51257C4B27aa9A74d05',
    observedAt: '09:21:16',
    hash: '0x41ea002249d8',
    detail: 'lineage_epoch 1',
  },
  {
    seq: 1398,
    type: 'authority_keys_updated',
    name: 'collective',
    actor: 'collective',
    observedAt: '09:09:58',
    hash: '0xa8d0021e4c77',
    detail: 'active keys 3 · seq 12',
  },
  {
    seq: 1397,
    type: 'did_alias_updated',
    name: 'mira',
    actor: '0xfC47291d62b47f12D3Ad38676B0a93F8a1695D90',
    observedAt: '08:57:20',
    hash: '0xd4ff9aa692f0',
    detail: 'Canonical → did:web:mira.dev',
  },
]

export const nameRecordFor = (name: string) =>
  names.find((record) => record.name === name) ?? {
    ...names[0],
    name,
    assetOwner: '0x44CA802eB3bb5D622fAaC51257C4B27aa9A74d05',
    effectiveOwner: '0x44CA802eB3bb5D622fAaC51257C4B27aa9A74d05',
    nameSeq: 3,
    ownerDocumentVersion: 1,
  }
