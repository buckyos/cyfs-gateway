/**
 * 注册名称（PRD 9.4 P0 简单模式）。
 *
 * - 顶级名称公开注册（CallAuthority.role = None）；
 * - 二级名称要求父名称 effective owner 授权，guard 带 expectedParentNameSeq；
 * - Released 名称按 PRD 6.4.8 阻断（旧状态不会被注册逻辑清理）；
 * - 代办注册（PRD 9.24）：asset owner 可以填他人地址，交易费由当前钱包承担。
 */

import { BadgeCheck, CircleSlash, Plus, Search } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'

import type { NameAvailability, RegisterForm } from '../bns_model'
import { isAddress, parseBnsName, validateBnsName } from '../bns_model'
import { useBnsModel, useSession } from '../bns_model/react'
import { formatTime, NAME_STATUS_LABEL, shortAddress } from '../ui/format'
import { CheckRow, Field, Note, Pill, Spinner } from '../ui/kit'
import { useAsync } from '../ui/use_async'
import { WriteDialog } from '../ui/write_dialog'

const DAY = 86_400n

const DURATION_OPTIONS: { label: string; seconds: bigint }[] = [
  { label: '1 年', seconds: 365n * DAY },
  { label: '2 年', seconds: 730n * DAY },
  { label: '3 年', seconds: 1095n * DAY },
]

const GRACE_OPTIONS: { label: string; seconds: bigint }[] = [
  { label: '30 天', seconds: 30n * DAY },
  { label: '60 天', seconds: 60n * DAY },
  { label: '90 天', seconds: 90n * DAY },
]

export function RegisterPage() {
  const [params] = useSearchParams()
  const model = useBnsModel()
  const session = useSession()

  const [name, setName] = useState(params.get('name') ?? '')
  const [assetOwner, setAssetOwner] = useState('')
  const [duration, setDuration] = useState(DURATION_OPTIONS[0].seconds)
  const [grace, setGrace] = useState(GRACE_OPTIONS[2].seconds)
  const [renewable, setRenewable] = useState(true)
  const [transferable, setTransferable] = useState(true)
  const [allowSubnames, setAllowSubnames] = useState(false)
  const [dialogOpen, setDialogOpen] = useState(false)

  // asset owner 默认当前钱包地址（可改为他人地址 = 代办注册）。
  useEffect(() => {
    if (!assetOwner && session.wallet.address) setAssetOwner(session.wallet.address)
  }, [assetOwner, session.wallet.address])

  const trimmed = name.trim()
  const validation = useMemo(() => (trimmed ? validateBnsName(trimmed) : null), [trimmed])
  const parsed = validation?.ok ? parseBnsName(trimmed) : null

  const availability = useAsync<NameAvailability | null>(
    validation?.ok ? () => model.controllers.registry.checkAvailability(trimmed) : null,
    [model, trimmed, validation?.ok],
  )

  const parentOverview = useAsync(
    parsed && !parsed.isTopLevel && parsed.parent
      ? () => model.repo.nameOverview(parsed.parent as string)
      : null,
    [model, parsed?.parent, parsed?.isTopLevel],
  )

  const ownerValid = isAddress(assetOwner)
  const isProxyRegistration =
    ownerValid &&
    session.wallet.address !== null &&
    assetOwner.toLowerCase() !== session.wallet.address.toLowerCase()

  const registrable = availability.status === 'ready' && availability.data?.registrable === true
  const formValid = Boolean(validation?.ok && ownerValid && registrable && duration > 0n)

  const registerForm: RegisterForm = {
    name: trimmed,
    assetOwner,
    durationSeconds: duration,
    gracePeriodSeconds: grace,
    renewable,
    transferable,
    allowDelegatedSubnames: allowSubnames,
  }

  return (
    <div>
      <h1 className="page-title">注册名称</h1>
      <p className="page-sub">
        顶级名称公开注册；二级名称需要父名称 effective owner 的钱包签名。注册当前不收取费用（value = 0）。
      </p>

      <div className="grid grid--2">
        <section className="card">
          <h2 className="card__title">
            <Plus /> 注册信息
          </h2>

          <Field
            label="名称"
            required
            error={validation && !validation.ok ? validation.message : null}
            help="小写字母、数字、- 和 .；最多一个 .（即顶级或二级名称）；不含 did:bns: 前缀"
          >
            <input
              type="text"
              className="mono"
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="alice 或 device.alice"
              autoComplete="off"
            />
          </Field>

          {trimmed && validation?.ok && /[A-Z]/.test(name) ? (
            <Note tone="warn">
              合约不自动转小写。
              <button type="button" className="btn btn--sm" onClick={() => setName(name.toLowerCase())}>
                转换为小写
              </button>
            </Note>
          ) : null}

          <Field
            label="Asset Owner"
            required
            error={assetOwner && !ownerValid ? '不是合法的 20 字节 EVM 地址' : null}
            help="名称资产记录中的地址，默认当前钱包；填他人地址即为代办注册（交易费由你承担，名称从第一天起属于对方）"
          >
            <input
              type="text"
              className="mono"
              value={assetOwner}
              onChange={(event) => setAssetOwner(event.target.value)}
              placeholder="0x…"
              autoComplete="off"
            />
          </Field>

          {isProxyRegistration ? (
            <Note tone="info">
              <b>代办注册：</b>名称将直接登记在 {shortAddress(assetOwner)} 名下。
              如需继续代办后续操作，请在注册后由对方授权 controller 规则（服务商模式，PRD 9.24）。
            </Note>
          ) : null}

          <Field label="注册时长" required>
            <div className="radio-row">
              {DURATION_OPTIONS.map((option) => (
                <span
                  key={option.label}
                  className={`radio-card ${duration === option.seconds ? 'is-active' : ''}`}
                  onClick={() => setDuration(option.seconds)}
                >
                  {option.label}
                </span>
              ))}
            </div>
          </Field>

          <Field label="宽限期（grace period）">
            <div className="radio-row">
              {GRACE_OPTIONS.map((option) => (
                <span
                  key={option.label}
                  className={`radio-card ${grace === option.seconds ? 'is-active' : ''}`}
                  onClick={() => setGrace(option.seconds)}
                >
                  {option.label}
                </span>
              ))}
            </div>
          </Field>

          <CheckRow checked={renewable} onChange={setRenewable} label="允许续期（renewable）" />
          <CheckRow
            checked={transferable}
            onChange={setTransferable}
            label="允许转移（transferable）"
            hint="当前合约的 transferName 未强制检查该 flag（PRD 6.4.2），它只影响派生字段 standard_transfer_enabled"
          />
          <CheckRow
            checked={allowSubnames}
            onChange={setAllowSubnames}
            label="允许委托子名称（allow delegated subnames）"
            hint="当前合约注册二级名称时不使用该 flag 鉴权，仍需父名称 owner 签名（PRD 6.4.3）"
          />

          <div className="divider" />
          <button
            type="button"
            className="btn btn--primary"
            disabled={!formValid || !session.writeGate.allowed}
            onClick={() => setDialogOpen(true)}
            style={{ width: '100%' }}
          >
            <BadgeCheck /> 预检并注册
          </button>
          {!session.writeGate.allowed ? (
            <Note tone="warn">{session.writeGate.reason}</Note>
          ) : null}
        </section>

        <div>
          <AvailabilityCard trimmedName={trimmed} validationOk={validation?.ok ?? false} availability={availability} />
          {parsed && !parsed.isTopLevel ? (
            <ParentCard parent={parsed.parent as string} parentOverview={parentOverview} />
          ) : null}
        </div>
      </div>

      {dialogOpen ? (
        <WriteDialog
          title={`注册 ${trimmed}`}
          icon={<Plus />}
          onClose={() => setDialogOpen(false)}
          formValid={formValid}
          form={
            <dl className="confirm-grid">
              <dt>名称</dt>
              <dd className="mono">{trimmed}</dd>
              <dt>Asset Owner</dt>
              <dd className="mono">
                {assetOwner}
                {isProxyRegistration ? '（代办注册）' : '（当前钱包）'}
              </dd>
              <dt>时长 / 宽限期</dt>
              <dd>
                {DURATION_OPTIONS.find((option) => option.seconds === duration)?.label} ·{' '}
                {GRACE_OPTIONS.find((option) => option.seconds === grace)?.label}
              </dd>
              <dt>标志</dt>
              <dd className="chips">
                <Pill tone={renewable ? 'ok' : 'muted'}>renewable</Pill>
                <Pill tone={transferable ? 'ok' : 'muted'}>transferable</Pill>
                <Pill tone={allowSubnames ? 'ok' : 'muted'}>delegated subnames</Pill>
              </dd>
              <dt>初始 Semantic Owner</dt>
              <dd>Unset（顶级回退到 asset owner；二级继承父名称 owner）</dd>
              <dt>initialPaymentTarget</dt>
              <dd style={{ color: 'var(--text-faint)' }}>
                固定 zero address —— 合约当前不读取该字段（PRD 6.4.9）
              </dd>
            </dl>
          }
          prepare={() => model.controllers.registry.prepareRegister(registerForm)}
          review={() =>
            parsed && !parsed.isTopLevel ? (
              <Note tone="info">
                二级名称注册：guard 使用父名称 <code>{parsed.parent}</code> 的 name_seq；
                授权路径为父名称 effective owner。
              </Note>
            ) : (
              <Note tone="info">顶级名称公开注册：无需授权声明，合约不使用 expectedNameSeq。</Note>
            )
          }
        />
      ) : null}
    </div>
  )
}

function AvailabilityCard({
  trimmedName,
  validationOk,
  availability,
}: {
  trimmedName: string
  validationOk: boolean
  availability: ReturnType<typeof useAsync<NameAvailability | null>>
}) {
  return (
    <section className="card">
      <h2 className="card__title">
        <Search /> 可用性
      </h2>
      {!trimmedName ? (
        <div className="empty">输入名称后自动检查</div>
      ) : !validationOk ? (
        <Note tone="warn">名称格式不满足合约规则</Note>
      ) : availability.status === 'loading' || availability.status === 'idle' ? (
        <div className="loading-row">
          <Spinner /> 查询投影…
        </div>
      ) : availability.status === 'error' ? (
        <Note tone="danger">可用性检查失败：{String(availability.error)}</Note>
      ) : availability.data ? (
        <>
          <div className="chips" style={{ marginBottom: 8 }}>
            {availability.data.registrable ? (
              <Pill tone="ok" dot>
                可以注册
              </Pill>
            ) : (
              <Pill tone="danger" dot>
                不可注册
              </Pill>
            )}
            {availability.data.overview ? (
              <Pill tone="neutral">
                当前状态：{NAME_STATUS_LABEL[availability.data.overview.state.status]}
              </Pill>
            ) : null}
          </div>
          <p style={{ fontSize: 12.5, color: 'var(--text-dim)', margin: 0 }}>{availability.data.reason}</p>
          {availability.data.overview ? (
            <p style={{ fontSize: 12, color: 'var(--text-faint)', marginTop: 6 }}>
              到期时间：{formatTime(availability.data.overview.state.expireAt)}
            </p>
          ) : (
            <Note tone="info">
              投影未找到该名称。如果它刚被他人注册，Indexer 可能尚未同步；提交时合约仍是最终裁决方。
            </Note>
          )}
        </>
      ) : null}
    </section>
  )
}

function ParentCard({
  parent,
  parentOverview,
}: {
  parent: string
  parentOverview: ReturnType<typeof useAsync>
}) {
  const data = parentOverview.data as import('../bns_model').NameOverview | null
  return (
    <section className="card">
      <h2 className="card__title">
        <CircleSlash /> 父名称 {parent}
      </h2>
      {parentOverview.status === 'loading' ? (
        <div className="loading-row">
          <Spinner /> 查询父名称…
        </div>
      ) : data ? (
        <>
          <dl className="kv kv--tight">
            <dt>状态</dt>
            <dd>
              <Pill tone={data.state.status === 'active' ? 'ok' : 'warn'}>
                {NAME_STATUS_LABEL[data.state.status]}
              </Pill>
              {data.state.status !== 'active' ? (
                <span style={{ color: 'var(--danger)', fontSize: 11.5, display: 'block' }}>
                  合约要求父名称 raw status 为 Active
                </span>
              ) : null}
            </dd>
            <dt>Effective Owner</dt>
            <dd className="mono">{data.state.effectiveOwner.value || 'Unset'}</dd>
            <dt>name_seq（guard）</dt>
            <dd className="mono">{data.state.nameSeq.toString()}</dd>
          </dl>
          <Note tone="warn">
            注册 <code>*.{parent}</code> 需要父名称 effective owner 的签名；
            allow_delegated_subnames 当前不参与链上鉴权（PRD 6.4.3）。
          </Note>
        </>
      ) : (
        <Note tone="danger">父名称不存在，无法注册二级名称。</Note>
      )}
    </section>
  )
}
