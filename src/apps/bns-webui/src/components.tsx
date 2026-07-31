import clsx from 'clsx'
import {
  Check,
  ChevronRight,
  Copy,
  ExternalLink,
  LoaderCircle,
  Search,
  type LucideIcon,
} from 'lucide-react'
import {
  useId,
  useState,
  type ButtonHTMLAttributes,
  type FormEvent,
  type ReactNode,
} from 'react'
import { useNavigate } from 'react-router-dom'

import { useAppState } from './state'

export function LogoMark({ compact = false }: { compact?: boolean }) {
  return (
    <div className={clsx('brand-lockup', compact && 'brand-lockup--compact')}>
      <svg
        className="brand-mark"
        viewBox="0 0 48 48"
        aria-hidden="true"
        focusable="false"
      >
        <path d="M8 17.5 24 8l16 9.5v13L24 40 8 30.5z" />
        <path d="M8 17.5 24 27l16-9.5M24 27v13" />
        <circle cx="24" cy="8" r="2.7" />
        <circle cx="8" cy="30.5" r="2.7" />
        <circle cx="40" cy="30.5" r="2.7" />
      </svg>
      <span className="brand-copy">
        <strong>BNS</strong>
        <small>Name Registry</small>
      </span>
    </div>
  )
}

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  icon?: LucideIcon
  tone?: 'primary' | 'secondary' | 'ghost' | 'danger'
  size?: 'sm' | 'md'
}

export function Button({
  className,
  children,
  icon: Icon,
  tone = 'secondary',
  size = 'md',
  ...props
}: ButtonProps) {
  return (
    <button
      className={clsx(
        'button',
        `button--${tone}`,
        `button--${size}`,
        className,
      )}
      {...props}
    >
      {Icon && <Icon size={size === 'sm' ? 15 : 17} />}
      {children}
    </button>
  )
}

export function StatusDot({
  tone = 'success',
  pulse = false,
}: {
  tone?: 'success' | 'warning' | 'danger' | 'neutral' | 'accent'
  pulse?: boolean
}) {
  return (
    <span
      className={clsx('status-dot', `status-dot--${tone}`, pulse && 'is-pulsing')}
    />
  )
}

export function Tag({
  children,
  tone = 'neutral',
}: {
  children: ReactNode
  tone?: 'neutral' | 'success' | 'warning' | 'danger' | 'accent'
}) {
  return <span className={clsx('tag', `tag--${tone}`)}>{children}</span>
}

export function SectionHeading({
  eyebrow,
  title,
  description,
  action,
}: {
  eyebrow?: string
  title: string
  description?: string
  action?: ReactNode
}) {
  return (
    <div className="section-heading">
      <div>
        {eyebrow && <span className="eyebrow">{eyebrow}</span>}
        <h2>{title}</h2>
        {description && <p>{description}</p>}
      </div>
      {action && <div className="section-heading__action">{action}</div>}
    </div>
  )
}

export function CopyValue({
  value,
  compact = false,
}: {
  value: string
  compact?: boolean
}) {
  const { notify } = useAppState()
  const visible =
    compact && value.length > 18
      ? `${value.slice(0, 8)}…${value.slice(-6)}`
      : value

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value)
      notify('已复制到剪贴板')
    } catch {
      notify('复制失败，请手动选择文本')
    }
  }

  return (
    <button className="copy-value" type="button" onClick={copy} title={value}>
      <span>{visible}</span>
      <Copy size={14} />
    </button>
  )
}

export function GlobalSearch({ large = false }: { large?: boolean }) {
  const navigate = useNavigate()
  const [query, setQuery] = useState('')
  const id = useId()

  const submit = (event: FormEvent) => {
    event.preventDefault()
    const normalized = query.trim()
    if (!normalized) return

    if (/^0x[a-fA-F0-9]{64}$/.test(normalized)) {
      navigate(`/transactions?tx=${encodeURIComponent(normalized)}`)
      return
    }

    const name = normalized.replace(/^did:bns:/, '')
    navigate(`/name/${encodeURIComponent(name)}`)
  }

  return (
    <form
      className={clsx('global-search', large && 'global-search--large')}
      onSubmit={submit}
    >
      <Search size={large ? 22 : 18} />
      <label className="sr-only" htmlFor={id}>
        搜索 BNS 名称、DID、地址或交易
      </label>
      <input
        id={id}
        value={query}
        onChange={(event) => setQuery(event.target.value)}
        placeholder={large ? '输入名称、did:bns:、地址或交易 Hash' : '搜索 BNS'}
        autoComplete="off"
      />
      {large ? (
        <Button tone="primary" type="submit">
          解析
          <ChevronRight size={17} />
        </Button>
      ) : (
        <kbd>⌘ K</kbd>
      )}
    </form>
  )
}

export function DetailRow({
  label,
  children,
  help,
}: {
  label: string
  children: ReactNode
  help?: string
}) {
  return (
    <div className="detail-row">
      <span>
        {label}
        {help && <small>{help}</small>}
      </span>
      <div>{children}</div>
    </div>
  )
}

export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
}: {
  icon: LucideIcon
  title: string
  description: string
  action?: ReactNode
}) {
  return (
    <div className="empty-state">
      <span className="empty-state__icon">
        <Icon size={22} />
      </span>
      <h3>{title}</h3>
      <p>{description}</p>
      {action}
    </div>
  )
}

export function ProtocolLink({ children }: { children: ReactNode }) {
  return (
    <button className="protocol-link" type="button">
      {children}
      <ExternalLink size={13} />
    </button>
  )
}

export function StageIcon({
  state,
}: {
  state: 'done' | 'active' | 'waiting' | 'error'
}) {
  return (
    <span className={clsx('stage-icon', `stage-icon--${state}`)}>
      {state === 'done' ? (
        <Check size={13} />
      ) : state === 'active' ? (
        <LoaderCircle className="spin" size={13} />
      ) : state === 'error' ? (
        '!'
      ) : (
        <span />
      )}
    </span>
  )
}
