/**
 * 展示层格式化工具。
 *
 * 原则（PRD 6.3 / 12.1）：
 * - 时间字段是 Unix 秒（bigint），0 表示「不设截止」；
 * - 派生标签只用于展示，永远与 raw 值并列，不做鉴权判断；
 * - bigint 不悄悄转 number 展示，超界宁可原样输出字符串。
 */

import type { DerivedNameStatus, DocumentStatus, NameStatus, Principal, TxStage } from '../bns_model'

export function shortAddress(value: string, head = 6, tail = 4): string {
  if (value.length <= head + tail + 2) return value
  return `${value.slice(0, head + 2)}…${value.slice(-tail)}`
}

export function shortHash(value: string, head = 8, tail = 6): string {
  if (value.length <= head + tail + 2) return value
  return `${value.slice(0, head + 2)}…${value.slice(-tail)}`
}

const ZERO_RE = /^0x0+$/

export function isZeroHex(value: string | null | undefined): boolean {
  return !value || ZERO_RE.test(value)
}

/** Unix 秒 -> 本地时间；0 -> 「不设截止」。 */
export function formatTime(seconds: bigint | number | null | undefined): string {
  if (seconds === null || seconds === undefined) return '—'
  const value = typeof seconds === 'bigint' ? seconds : BigInt(Math.trunc(seconds))
  if (value === 0n) return '不设截止'
  if (value > 253_402_300_799n) return `${value.toString()}（超出可展示范围）`
  const date = new Date(Number(value) * 1000)
  return date.toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export function formatRelative(seconds: bigint | number | null | undefined): string {
  if (seconds === null || seconds === undefined) return '—'
  const value = typeof seconds === 'bigint' ? Number(seconds) : seconds
  if (value === 0) return '—'
  const diff = value * 1000 - Date.now()
  const abs = Math.abs(diff)
  const units: [number, string][] = [
    [365 * 86_400_000, '年'],
    [30 * 86_400_000, '个月'],
    [86_400_000, '天'],
    [3_600_000, '小时'],
    [60_000, '分钟'],
  ]
  for (const [ms, label] of units) {
    if (abs >= ms) {
      const count = Math.floor(abs / ms)
      return diff > 0 ? `${count} ${label}后` : `${count} ${label}前`
    }
  }
  return diff > 0 ? '不到 1 分钟后' : '刚刚'
}

export function formatDurationSeconds(seconds: bigint): string {
  const value = Number(seconds)
  if (value % (365 * 86_400) === 0) return `${value / (365 * 86_400)} 年`
  if (value % 86_400 === 0) return `${value / 86_400} 天`
  if (value % 3_600 === 0) return `${value / 3_600} 小时`
  return `${value} 秒`
}

export function formatBytes(count: number): string {
  if (count < 1024) return `${count} B`
  if (count < 1024 * 1024) return `${(count / 1024).toFixed(1)} KiB`
  return `${(count / (1024 * 1024)).toFixed(1)} MiB`
}

export function principalText(principal: Principal | null | undefined): string {
  if (!principal || principal.kind === 'unset') return 'Unset'
  if (principal.kind === 'bns_name') return principal.value
  return principal.value
}

export function principalKindLabel(principal: Principal | null | undefined): string {
  if (!principal || principal.kind === 'unset') return '未设置'
  if (principal.kind === 'bns_name') return 'BNS 名称'
  return '链账户'
}

// ---------------------------------------------------------------------------
// 状态标签
// ---------------------------------------------------------------------------

export type Tone = 'neutral' | 'ok' | 'progress' | 'warn' | 'danger' | 'muted'

export const NAME_STATUS_LABEL: Record<NameStatus, string> = {
  available: '未注册',
  active: '活跃',
  expired: '已过期',
  released: '已释放',
  tombstoned: '已永久停用',
}

export const NAME_STATUS_TONE: Record<NameStatus, Tone> = {
  available: 'muted',
  active: 'ok',
  expired: 'warn',
  released: 'warn',
  tombstoned: 'danger',
}

export function derivedStatusLabel(derived: DerivedNameStatus): { text: string; tone: Tone } {
  switch (derived.label) {
    case 'unregistered':
      return { text: '未注册', tone: 'muted' }
    case 'active':
      return { text: '活跃', tone: 'ok' }
    case 'active_time_expired':
      return {
        text: derived.inGrace ? '有效期已过（宽限期内）' : '有效期已过（raw 仍为 Active）',
        tone: 'warn',
      }
    case 'expired':
      return { text: '已过期', tone: 'warn' }
    case 'released':
      return { text: '已释放', tone: 'warn' }
    case 'tombstoned':
      return { text: '已永久停用', tone: 'danger' }
  }
}

export const DOC_STATUS_LABEL: Record<DocumentStatus, string> = {
  missing: '未发布',
  active: '活跃',
  revoked: '已撤销',
  expired: '已过期',
  migrated: '已迁移',
  tombstoned: '已停用',
}

export const DOC_STATUS_TONE: Record<DocumentStatus, Tone> = {
  missing: 'muted',
  active: 'ok',
  revoked: 'danger',
  expired: 'warn',
  migrated: 'warn',
  tombstoned: 'danger',
}

export const TX_STAGE_LABEL: Record<TxStage, string> = {
  awaiting_wallet: '等待钱包',
  wallet_rejected: '用户已取消',
  submitted: '已广播',
  pending: '链上 Pending',
  not_found: '节点未找到',
  chain_reverted: '已回退',
  indexing: '等待索引',
  completed: '已完成',
  indexer_lagging: 'Indexer 滞后',
}

export const TX_STAGE_TONE: Record<TxStage, Tone> = {
  awaiting_wallet: 'neutral',
  wallet_rejected: 'muted',
  submitted: 'progress',
  pending: 'progress',
  not_found: 'warn',
  chain_reverted: 'danger',
  indexing: 'warn',
  completed: 'ok',
  indexer_lagging: 'warn',
}

export const OWNER_SOURCE_LABEL: Record<string, string> = {
  none: '无有效 owner',
  asset_owner_fallback: '回退到 Asset Owner',
  explicit_semantic_owner: '显式 Semantic Owner',
  parent_inherited: '继承父名称',
}
