/**
 * 事件浏览器（PRD 9.20）。
 *
 * events.list 只支持 seq 升序 + limit；「最新事件」通过先定位日志尾部实现，
 * 名称/类型过滤是客户端行为、只在已加载窗口内生效——页面必须如实说明。
 */

import { Activity, Filter, RefreshCw } from 'lucide-react'
import { useEffect } from 'react'
import { Link } from 'react-router-dom'

import { EVENT_TYPE_LABELS, type RegistryEventType } from '../bns_model'
import { useBnsModel, useEvents } from '../bns_model/react'
import { formatTime, shortHash } from '../ui/format'
import { ErrorBox, Note, Pill, RawDetails, Spinner } from '../ui/kit'

export function EventsPage() {
  const model = useBnsModel()
  const events = useEvents()

  useEffect(() => {
    if (events.records.length === 0 && events.page.status === 'idle') {
      void model.controllers.events.loadLatest()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [model])

  const visible = model.models.events.visibleRecords()
  const typeOptions = Object.entries(EVENT_TYPE_LABELS) as [RegistryEventType, string][]

  return (
    <div>
      <h1 className="page-title">
        <Activity style={{ width: 20, height: 20, color: 'var(--accent)' }} /> 事件浏览器
      </h1>
      <p className="page-sub">
        全局事件日志，按 seq 倒序展示（服务端仅支持升序读取，页面先定位日志尾部再向前翻页）。
      </p>

      <section className="card">
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', marginBottom: 10 }}>
          <Filter style={{ width: 14, height: 14, color: 'var(--text-faint)' }} />
          <input
            type="text"
            className="mono"
            placeholder="按名称过滤…"
            value={events.filter.name ?? ''}
            onChange={(event) =>
              model.controllers.events.setFilter({ name: event.target.value.trim() || null })
            }
            style={{
              background: 'var(--bg-raise)',
              border: '1px solid var(--line)',
              borderRadius: 8,
              color: 'var(--text)',
              padding: '6px 10px',
              fontSize: 12.5,
              width: 180,
            }}
          />
          <select
            value={events.filter.types[0] ?? ''}
            onChange={(event) =>
              model.controllers.events.setFilter({
                types: event.target.value ? [event.target.value as RegistryEventType] : [],
              })
            }
            style={{
              background: 'var(--bg-raise)',
              border: '1px solid var(--line)',
              borderRadius: 8,
              color: 'var(--text)',
              padding: '6px 10px',
              fontSize: 12.5,
            }}
          >
            <option value="">全部类型</option>
            {typeOptions.map(([type, label]) => (
              <option key={type} value={type}>
                {label}
              </option>
            ))}
          </select>
          <span style={{ fontSize: 11.5, color: 'var(--text-faint)' }}>
            过滤只作用于已加载的 {events.records.length} 条（
            {events.scannedDownToSeq !== null && events.tailSeq !== null
              ? `seq ${events.scannedDownToSeq} ~ ${events.tailSeq}`
              : '—'}
            ），不是服务端完整搜索
          </span>
          <button
            type="button"
            className="btn btn--ghost btn--sm"
            style={{ marginLeft: 'auto' }}
            onClick={() => void model.controllers.events.loadLatest()}
          >
            <RefreshCw /> 刷新
          </button>
        </div>

        {events.page.status === 'error' ? <ErrorBox error={events.page.error} /> : null}
        {events.page.status === 'loading' && events.records.length === 0 ? (
          <div className="loading-row">
            <Spinner /> 定位日志尾部（指数探测 + 二分）…
          </div>
        ) : visible.length === 0 ? (
          <div className="empty">已加载窗口内没有匹配的事件</div>
        ) : (
          visible.map((record) => (
            <div key={record.seq.toString()} className="event-line">
              <span className="event-line__seq">#{record.seq.toString()}</span>
              <div className="event-line__body">
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                  <Pill tone="neutral">{EVENT_TYPE_LABELS[record.event.type]}</Pill>
                  {record.name ? (
                    <Link to={`/name/${encodeURIComponent(record.name)}`} className="mono" style={{ fontSize: 12.5 }}>
                      {record.name}
                    </Link>
                  ) : null}
                  {record.outerEventType !== record.event.type ? (
                    <Pill tone="muted" title="外层 event_type 与内层不同；解析以内层为准（PRD 9.20）">
                      外层: {record.outerEventType}
                    </Pill>
                  ) : null}
                </div>
                <div className="event-line__meta">
                  {formatTime(record.observedAt)} · event hash {shortHash(record.eventHash, 6, 4)} · log root{' '}
                  {shortHash(record.logRoot, 6, 4)}
                </div>
                <RawDetails label="事件详情（原始 JSON）" value={record} />
              </div>
            </div>
          ))
        )}

        {events.hasMore ? (
          <button
            type="button"
            className="btn"
            style={{ width: '100%', marginTop: 10 }}
            onClick={() => void model.controllers.events.loadMore()}
          >
            加载更早的事件（向 seq 0 方向）
          </button>
        ) : events.records.length > 0 ? (
          <Note tone="info">已加载全部事件（seq 1 起）。</Note>
        ) : null}
      </section>
    </div>
  )
}
