/**
 * 名称列表行：账号页 / 资产页 / 首页共用。
 *
 * 每行显示 raw status 与基于时间的派生标签（并列，不覆盖，PRD 12.1），
 * 以及「仅持有」提示（PRD 9.3：parent 不属于我且 owner 继承自父名称）。
 */

import { ChevronRight } from 'lucide-react'
import { useNavigate } from 'react-router-dom'

import type { PortfolioEntry } from '../bns_model'
import { derivedStatusLabel, formatRelative, NAME_STATUS_LABEL, NAME_STATUS_TONE } from './format'
import { Pill, Spinner } from './kit'

export function NameRow({
  entry,
  holdOnly = false,
  pendingTx = 0,
}: {
  entry: PortfolioEntry
  holdOnly?: boolean
  pendingTx?: number
}) {
  const navigate = useNavigate()
  const overview = entry.overview.data ?? null
  const derived = overview ? derivedStatusLabel(overview.derived) : null

  return (
    <div
      className="name-row"
      style={{ cursor: 'pointer' }}
      onClick={() => navigate(`/name/${encodeURIComponent(entry.name)}`)}
    >
      <div>
        <div className="name-row__name">{entry.name}</div>
        <div className="name-row__meta">
          {entry.overview.status === 'loading' && !overview ? (
            <Spinner />
          ) : overview ? (
            <>
              到期 {formatRelative(overview.state.expireAt)} · name_seq {overview.state.nameSeq.toString()}
            </>
          ) : entry.overview.status === 'error' ? (
            '状态加载失败'
          ) : (
            '投影中未找到'
          )}
        </div>
      </div>
      <div className="name-row__right">
        {pendingTx > 0 ? <Pill tone="progress">{pendingTx} 笔进行中</Pill> : null}
        {holdOnly ? (
          <Pill tone="warn" title="semantic owner 未设置，控制权仍随父名称 owner（PRD 5.3 继承规则）">
            仅持有
          </Pill>
        ) : null}
        {overview ? (
          <>
            <Pill tone={NAME_STATUS_TONE[overview.state.status]}>
              {NAME_STATUS_LABEL[overview.state.status]}
            </Pill>
            {derived && overview.derived.timeExpired ? (
              <Pill tone={derived.tone}>{derived.text}</Pill>
            ) : null}
          </>
        ) : null}
        <ChevronRight style={{ width: 15, height: 15, color: 'var(--text-faint)' }} />
      </div>
    </div>
  )
}
