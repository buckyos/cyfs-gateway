/**
 * 共享 UI 组件。
 *
 * 只做展示与最小交互，不写业务判断（业务判断在 bns_model 的 Controller/Model）。
 */

import { clsx } from 'clsx'
import { AlertCircle, AlertTriangle, Check, Copy, Inbox, Info, X } from 'lucide-react'
import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { createPortal } from 'react-dom'

import type { AsyncState } from '../bns_model'
import { BnsError } from '../bns_model'
import type { Tone } from './format'

// ---------------------------------------------------------------------------
// Pill
// ---------------------------------------------------------------------------

export function Pill({
  tone = 'neutral',
  children,
  dot = false,
  title,
}: {
  tone?: Tone | 'accent'
  children: ReactNode
  dot?: boolean
  title?: string
}) {
  return (
    <span className={clsx('pill', `pill--${tone}`)} title={title}>
      {dot ? <span className="dot" /> : null}
      {children}
    </span>
  )
}

// ---------------------------------------------------------------------------
// 复制
// ---------------------------------------------------------------------------

export function CopyText({
  value,
  display,
  className,
}: {
  value: string
  display?: ReactNode
  className?: string
}) {
  const [copied, setCopied] = useState(false)
  const onCopy = useCallback(() => {
    void navigator.clipboard?.writeText(value).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1_200)
    })
  }, [value])
  return (
    <button
      type="button"
      className={clsx('copy', copied && 'is-copied', className)}
      onClick={onCopy}
      title={copied ? '已复制' : `复制 ${value}`}
    >
      <span>{display ?? value}</span>
      {copied ? <Check /> : <Copy />}
    </button>
  )
}

// ---------------------------------------------------------------------------
// 提示条
// ---------------------------------------------------------------------------

export function Note({
  tone = 'neutral',
  children,
}: {
  tone?: 'neutral' | 'info' | 'warn' | 'danger' | 'ok'
  children: ReactNode
}) {
  const Icon = tone === 'danger' ? AlertTriangle : tone === 'warn' ? AlertCircle : Info
  return (
    <div className={clsx('note', tone !== 'neutral' && `note--${tone}`)}>
      <Icon />
      <div>{children}</div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// 异步区块：统一 idle/loading/error/ready 的渲染
// ---------------------------------------------------------------------------

export function AsyncSection<T>({
  state,
  loadingText = '加载中…',
  emptyText = '暂无数据',
  isEmpty,
  children,
}: {
  state: AsyncState<T>
  loadingText?: string
  emptyText?: string
  /** ready 后判断是否算空态（默认 null 算空）。 */
  isEmpty?: (data: T) => boolean
  children: (data: T) => ReactNode
}) {
  if (state.status === 'idle' || (state.status === 'loading' && state.data === null)) {
    return (
      <div className="loading-row">
        <span className="spinner" /> {loadingText}
      </div>
    )
  }
  if (state.status === 'error' && state.data === null) {
    return <ErrorBox error={state.error} />
  }
  const data = state.data
  const empty = data === null || (isEmpty ? isEmpty(data) : false)
  if (empty) {
    return (
      <div className="empty">
        <Inbox />
        <div>{emptyText}</div>
      </div>
    )
  }
  return (
    <>
      {state.status === 'loading' ? (
        <div className="loading-row">
          <span className="spinner" /> 正在刷新…
        </div>
      ) : null}
      {children(data as T)}
    </>
  )
}

export function ErrorBox({ error }: { error: unknown }) {
  const bnsError = error instanceof BnsError ? error : null
  return (
    <div className="error-box">
      <b>{bnsError ? `请求失败（${bnsError.kind} / ${bnsError.code}）` : '请求失败'}</b>
      <div style={{ marginTop: 4 }}>{bnsError?.message ?? String(error)}</div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// 模态
// ---------------------------------------------------------------------------

export function Modal({
  title,
  icon,
  onClose,
  children,
  footer,
  wide = false,
}: {
  title: ReactNode
  icon?: ReactNode
  onClose: () => void
  children: ReactNode
  footer?: ReactNode
  wide?: boolean
}) {
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  // Portal 到 body：topbar 的 backdrop-filter 会成为 fixed 定位的包含块，
  // 在原位置渲染会把全屏遮罩锁进顶栏区域。
  return createPortal(
    <div
      className="modal-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose()
      }}
    >
      <div className={clsx('modal', wide && 'modal--wide')} role="dialog" aria-modal>
        <div className="modal__head">
          {icon}
          <div className="modal__title">{title}</div>
          <button type="button" className="btn btn--ghost btn--sm" onClick={onClose} aria-label="关闭">
            <X />
          </button>
        </div>
        <div className="modal__body">{children}</div>
        {footer ? <div className="modal__foot">{footer}</div> : null}
      </div>
    </div>,
    document.body,
  )
}

// ---------------------------------------------------------------------------
// 表单
// ---------------------------------------------------------------------------

export function Field({
  label,
  required = false,
  help,
  error,
  children,
}: {
  label: ReactNode
  required?: boolean
  help?: ReactNode
  error?: string | null
  children: ReactNode
}) {
  return (
    <label className="field">
      <span className="field__label">
        {label}
        {required ? <span className="req">*</span> : null}
      </span>
      {children}
      {error ? <span className="field__error">{error}</span> : help ? <span className="field__help">{help}</span> : null}
    </label>
  )
}

export function CheckRow({
  checked,
  onChange,
  label,
  hint,
  disabled = false,
}: {
  checked: boolean
  onChange: (next: boolean) => void
  label: ReactNode
  hint?: ReactNode
  disabled?: boolean
}) {
  return (
    <label className="check">
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(event) => onChange(event.target.checked)}
      />
      <span>
        {label}
        {hint ? <span className="check__hint">{hint}</span> : null}
      </span>
    </label>
  )
}

// ---------------------------------------------------------------------------
// 杂项
// ---------------------------------------------------------------------------

export function KV({ items, tight = false }: { items: [ReactNode, ReactNode][]; tight?: boolean }) {
  return (
    <dl className={clsx('kv', tight && 'kv--tight')}>
      {items.map(([key, value], index) => (
        <FragmentKV key={index} k={key} v={value} />
      ))}
    </dl>
  )
}

function FragmentKV({ k, v }: { k: ReactNode; v: ReactNode }) {
  return (
    <>
      <dt>{k}</dt>
      <dd>{v}</dd>
    </>
  )
}

export function JsonBlock({ value }: { value: unknown }) {
  return (
    <pre className="codeblock">
      {JSON.stringify(
        value,
        (_key, item: unknown) => {
          if (typeof item === 'bigint') return item.toString()
          if (item instanceof Uint8Array) return `<${item.length} bytes>`
          return item
        },
        2,
      )}
    </pre>
  )
}

export function RawDetails({ label = '原始 JSON', value }: { label?: string; value: unknown }) {
  return (
    <details className="raw">
      <summary>{label}</summary>
      <JsonBlock value={value} />
    </details>
  )
}

export function Spinner() {
  return <span className="spinner" />
}
