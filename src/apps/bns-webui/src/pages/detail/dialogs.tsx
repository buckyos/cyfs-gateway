/**
 * 名称域写操作对话框集（PRD 9.5–9.18）。
 *
 * 每个对话框只负责收集意图参数；预检/guard 重读/确认摘要/提交/进度
 * 全部走通用 WriteDialog（两步流程，PRD 8.5）。
 */

import {
  ArrowLeftRight,
  Ban,
  Coins,
  FileText,
  History,
  KeyRound,
  Link as LinkIcon,
  RotateCcw,
  Shield,
  Timer,
  User,
} from 'lucide-react'
import { useMemo, useState } from 'react'

import type { AuthorityKeyUpdateInput, ControllerRuleInput, NameAggregate, Principal } from '../../bns_model'
import {
  isAddress,
  isBytes32,
  MAX_INLINE_DOCUMENT,
  PERMISSION_PUBLISH_DOCUMENT,
  PERMISSION_REVOKE_DOCUMENT,
  PERMISSION_SET_ALIAS,
  PERMISSION_SET_NAMESPACE,
  PERMISSION_SET_PAYMENT,
  utf8ToBytes,
  validateBnsName,
  ZERO_BYTES32,
} from '../../bns_model'
import { useBnsModel, useSession } from '../../bns_model/react'
import { formatDurationSeconds, formatTime, principalText, shortAddress } from '../../ui/format'
import { CheckRow, Field, Note, Pill } from '../../ui/kit'
import { useAsync } from '../../ui/use_async'
import { DiffPair, WriteDialog } from '../../ui/write_dialog'

const DAY = 86_400n

// ---------------------------------------------------------------------------
// 9.5 续期：公共维护行为
// ---------------------------------------------------------------------------

export function RenewDialog({ aggregate, onClose }: { aggregate: NameAggregate; onClose: () => void }) {
  const model = useBnsModel()
  const session = useSession()
  const [duration, setDuration] = useState(365n * DAY)
  const state = aggregate.overview.data?.state ?? null

  const isOwner =
    state !== null &&
    session.wallet.address !== null &&
    ((state.effectiveOwner.kind === 'chain_account' &&
      state.effectiveOwner.value.toLowerCase() === session.wallet.address.toLowerCase()) ||
      state.assetOwner.toLowerCase() === session.wallet.address.toLowerCase())

  const blocked =
    state === null
      ? '名称不存在'
      : !state.renewable
        ? '该名称 renewable = false，不允许续期'
        : state.status === 'released' || state.status === 'tombstoned'
          ? '已释放或已永久停用的名称不能续期'
          : null

  return (
    <WriteDialog
      title={`为 ${aggregate.name} 续期`}
      icon={<RotateCcw />}
      onClose={onClose}
      formValid={blocked === null && duration > 0n}
      form={
        <>
          {!isOwner ? (
            <Note tone="info">
              <b>正在为他人名称续期。</b>
              任何账户都可以为任何名称续期——这是公共维护行为：续期注入的价值只会变成名称的有效时间，
              一次性、不可撤回，与调用者是否使用该名称无关。
            </Note>
          ) : null}
          {blocked ? <Note tone="danger">{blocked}</Note> : null}
          <Field label="续期时长" required>
            <div className="radio-row">
              {[
                { label: '180 天', value: 180n * DAY },
                { label: '1 年', value: 365n * DAY },
                { label: '2 年', value: 730n * DAY },
              ].map((option) => (
                <span
                  key={option.label}
                  className={`radio-card ${duration === option.value ? 'is-active' : ''}`}
                  onClick={() => setDuration(option.value)}
                >
                  {option.label}
                </span>
              ))}
            </div>
          </Field>
          <Note tone="info">
            当前续期只消耗 gas（value = 0，duration 为显式参数）。未来经济模型接入后，
            续期金额将按当时价格即时换算为有效期，本入口交互不变（PRD 16.4，未实现）。
          </Note>
        </>
      }
      prepare={() => model.controllers.name.prepare(model.controllers.name.buildRenew(aggregate.name, duration), { kind: 'public' })}
      review={() =>
        state ? (
          <>
            <DiffPair
              label="到期时间"
              before={formatTime(state.expireAt)}
              after={`${formatTime(state.expireAt + duration)}（估算：当前值 + ${formatDurationSeconds(duration)}）`}
            />
            <Note tone="info">
              任何账户都可代续期；续期只增加有效期、不可撤回。
              {!isOwner ? ' 你不是该名称的持有人，本次属于为他人续期。' : ''}
            </Note>
          </>
        ) : null
      }
    />
  )
}

// ---------------------------------------------------------------------------
// 9.6 转移名称
// ---------------------------------------------------------------------------

export function TransferDialog({ aggregate, onClose }: { aggregate: NameAggregate; onClose: () => void }) {
  const model = useBnsModel()
  const session = useSession()
  const [newOwner, setNewOwner] = useState('')
  const [semanticMode, setSemanticMode] = useState<'unset' | 'bns_name'>('unset')
  const [semanticName, setSemanticName] = useState('')
  const state = aggregate.overview.data?.state ?? null
  const isSecondLevel = aggregate.name.includes('.')

  const targetAuthority = useAsync(
    semanticMode === 'bns_name' && validateBnsName(semanticName.trim()).ok
      ? () => model.repo.authoritySet(semanticName.trim())
      : null,
    [model, semanticMode, semanticName],
  )

  const semanticOk =
    semanticMode === 'unset' ||
    (targetAuthority.status === 'ready' && (targetAuthority.data?.activeKeyCount ?? 0) > 0)

  const ownerValid = isAddress(newOwner)
  const sameAsCurrent =
    ownerValid && session.wallet.address !== null && newOwner.toLowerCase() === session.wallet.address.toLowerCase()

  const semanticOwner: Principal =
    semanticMode === 'unset' ? { kind: 'unset', value: '' } : { kind: 'bns_name', value: semanticName.trim() }

  return (
    <WriteDialog
      title={`转移 ${aggregate.name}`}
      icon={<ArrowLeftRight />}
      onClose={onClose}
      danger
      confirmText={aggregate.name}
      formValid={ownerValid && semanticOk}
      form={
        <>
          <Note tone="warn">
            这是 BNS 自定义转移，不是 ERC-721 transfer。交易会同时改变 asset owner 与 semantic owner。
            {state && !state.transferable
              ? ' 注意：该名称 transferable = false，但当前合约的 transferName 未强制该 flag（PRD 6.4.2）——这不是安全承诺。'
              : ''}
          </Note>
          <Field
            label="新 Asset Owner 地址"
            required
            error={newOwner && !ownerValid ? '不是合法的 20 字节 EVM 地址' : null}
          >
            <input
              type="text"
              className="mono"
              value={newOwner}
              onChange={(event) => setNewOwner(event.target.value)}
              placeholder="0x…"
              autoComplete="off"
            />
          </Field>
          {sameAsCurrent ? <Note tone="info">目标地址就是当前钱包地址：这是一次冗余转移。</Note> : null}
          <Field label="新 Semantic Owner" help="只允许 Unset 或 BNS Name；不允许把链账户编码为 semantic owner">
            <div className="radio-row">
              <span
                className={`radio-card ${semanticMode === 'unset' ? 'is-active' : ''}`}
                onClick={() => setSemanticMode('unset')}
              >
                Unset（顶级回退新 asset owner；二级继承父 owner）
              </span>
              <span
                className={`radio-card ${semanticMode === 'bns_name' ? 'is-active' : ''}`}
                onClick={() => setSemanticMode('bns_name')}
              >
                BNS Name
              </span>
            </div>
          </Field>
          {semanticMode === 'bns_name' ? (
            <Field
              label="Semantic Owner 名称"
              required
              error={
                semanticName && targetAuthority.status === 'ready' && !semanticOk
                  ? '目标名称没有 active authentication key，合约会拒绝'
                  : null
              }
            >
              <input
                type="text"
                className="mono"
                value={semanticName}
                onChange={(event) => setSemanticName(event.target.value)}
                placeholder="受让方的账号名称"
              />
            </Field>
          ) : null}
          {isSecondLevel && semanticMode === 'unset' ? (
            <Note tone="warn">
              <b>跨账号转移二级名称时保持 Unset：</b>受让方只得到持有权，
              控制权仍随父名称 owner（PRD 5.3 继承规则）。建议改为受让方的 BNS name
              （目标须 Active 且有 active authentication key）。
            </Note>
          ) : null}
        </>
      }
      prepare={() =>
        model.controllers.name.prepare(
          model.controllers.name.buildTransfer(aggregate.name, newOwner, { newSemanticOwner: semanticOwner }),
        )
      }
      review={() =>
        state ? (
          <>
            <DiffPair
              label="Asset Owner"
              before={<span className="mono">{shortAddress(state.assetOwner, 8, 6)}</span>}
              after={<span className="mono">{shortAddress(newOwner, 8, 6)}</span>}
            />
            <DiffPair
              label="Semantic Owner"
              before={principalText(state.semanticOwner)}
              after={semanticMode === 'unset' ? 'Unset' : semanticName.trim()}
            />
            <Note tone="warn">目标地址请与受让方逐字核对（原样展示，未做 checksum 换算）。</Note>
          </>
        ) : null
      }
    />
  )
}

// ---------------------------------------------------------------------------
// 9.7 Semantic Owner 管理
// ---------------------------------------------------------------------------

export function SemanticOwnerDialog({ aggregate, onClose }: { aggregate: NameAggregate; onClose: () => void }) {
  const model = useBnsModel()
  const [mode, setMode] = useState<'unset' | 'bns_name'>('unset')
  const [targetName, setTargetName] = useState('')
  const state = aggregate.overview.data?.state ?? null
  const isSecondLevel = aggregate.name.includes('.')

  const targetAuthority = useAsync(
    mode === 'bns_name' && validateBnsName(targetName.trim()).ok
      ? () => model.repo.authoritySet(targetName.trim())
      : null,
    [model, mode, targetName],
  )
  const targetOk =
    mode === 'unset' || (targetAuthority.status === 'ready' && (targetAuthority.data?.activeKeyCount ?? 0) > 0)

  const semanticOwner: Principal =
    mode === 'unset' ? { kind: 'unset', value: '' } : { kind: 'bns_name', value: targetName.trim() }

  return (
    <WriteDialog
      title={`设置 ${aggregate.name} 的 Semantic Owner`}
      icon={<User />}
      onClose={onClose}
      danger
      formValid={targetOk}
      form={
        <>
          <Field label="Owner 模式" required>
            <div className="radio-row">
              <span className={`radio-card ${mode === 'unset' ? 'is-active' : ''}`} onClick={() => setMode('unset')}>
                使用默认 Owner
                <span style={{ display: 'block', fontSize: 11, color: 'var(--text-faint)' }}>
                  {isSecondLevel ? '继承父名称 effective owner' : '回退到 asset owner'}
                </span>
              </span>
              <span
                className={`radio-card ${mode === 'bns_name' ? 'is-active' : ''}`}
                onClick={() => setMode('bns_name')}
              >
                使用 BNS Name
                <span style={{ display: 'block', fontSize: 11, color: 'var(--text-faint)' }}>
                  以该名称的 authority set 管理本名称
                </span>
              </span>
            </div>
          </Field>
          {mode === 'bns_name' ? (
            <>
              <Field
                label="目标 BNS 名称"
                required
                error={
                  targetName && targetAuthority.status === 'ready' && !targetOk
                    ? '目标名称 active key count = 0，合约会拒绝'
                    : null
                }
              >
                <input
                  type="text"
                  className="mono"
                  value={targetName}
                  onChange={(event) => setTargetName(event.target.value)}
                  placeholder="alice"
                />
              </Field>
              {targetAuthority.status === 'ready' && targetAuthority.data ? (
                <Note tone={targetOk ? 'ok' : 'danger'}>
                  目标 authority set：seq {targetAuthority.data.authoritySeq.toString()}，active key{' '}
                  {targetAuthority.data.activeKeyCount} 个。
                </Note>
              ) : null}
            </>
          ) : null}
        </>
      }
      prepare={() =>
        model.controllers.name.prepare(model.controllers.name.buildSetSemanticOwner(aggregate.name, semanticOwner))
      }
      review={() =>
        state ? (
          <DiffPair
            label="Semantic Owner"
            before={principalText(state.semanticOwner)}
            after={mode === 'unset' ? 'Unset（默认规则）' : targetName.trim()}
          />
        ) : null
      }
    />
  )
}

// ---------------------------------------------------------------------------
// 9.10 发布 / 更新文档（inline）
// ---------------------------------------------------------------------------

export function PublishDocumentDialog({
  aggregate,
  initialDocType = '',
  onClose,
}: {
  aggregate: NameAggregate
  initialDocType?: string
  onClose: () => void
}) {
  const model = useBnsModel()
  const [docType, setDocType] = useState(initialDocType)
  const [storage, setStorage] = useState<'inline' | 'uri'>('inline')
  const [content, setContent] = useState('')
  const [uri, setUri] = useState('')
  const [contentHash, setContentHash] = useState('')
  const [paymentTarget, setPaymentTarget] = useState('')

  const docTypeOk = /^[a-z0-9_-]{1,32}$/.test(docType.trim())
  const inlineBytes = useMemo(() => utf8ToBytes(content), [content])
  const inlineTooLarge = inlineBytes.length > MAX_INLINE_DOCUMENT
  const paymentOk = paymentTarget === '' || isAddress(paymentTarget)

  const formValid =
    docTypeOk &&
    paymentOk &&
    (storage === 'inline'
      ? content.length > 0 && !inlineTooLarge
      : uri.trim().length > 0 && isBytes32(contentHash))

  const currentVersion = aggregate.documents[docType.trim()]?.data?.state?.version ?? null

  return (
    <WriteDialog
      title={`发布文档 · ${aggregate.name}`}
      icon={<FileText />}
      onClose={onClose}
      wide
      formValid={formValid}
      form={
        <>
          <Field
            label="doc type"
            required
            error={docType && !docTypeOk ? '1–32 字节的小写字母、数字、- 或 _' : null}
            help={docType.trim() === 'owner' ? 'owner 文档按 Owner-only 处理，且影响 owner_document_version' : undefined}
          >
            <input
              type="text"
              className="mono"
              value={docType}
              onChange={(event) => setDocType(event.target.value)}
              placeholder="zone / owner / device / …"
            />
          </Field>
          <Field label="存储方式" required>
            <div className="radio-row">
              <span
                className={`radio-card ${storage === 'inline' ? 'is-active' : ''}`}
                onClick={() => setStorage('inline')}
              >
                Inline（≤ 4 KiB，content hash 自动计算）
              </span>
              <span className={`radio-card ${storage === 'uri' ? 'is-active' : ''}`} onClick={() => setStorage('uri')}>
                URI（content hash 由你提供并自负其责）
              </span>
            </div>
          </Field>
          {storage === 'inline' ? (
            <Field
              label={`文档内容（${inlineBytes.length} / ${MAX_INLINE_DOCUMENT} 字节）`}
              required
              error={inlineTooLarge ? `超过 ${MAX_INLINE_DOCUMENT} 字节上限，已在钱包请求前阻断` : null}
              help="content_hash = sha256(inline_document)，由页面自动计算，不可手填"
            >
              <textarea
                value={content}
                onChange={(event) => setContent(event.target.value)}
                placeholder='{"did":"did:bns:…", …}'
              />
            </Field>
          ) : (
            <>
              <Field label="URI" required>
                <input
                  type="text"
                  className="mono"
                  value={uri}
                  onChange={(event) => setUri(event.target.value)}
                  placeholder="https://… 或 cyfs://…"
                />
              </Field>
              <Field
                label="content hash（bytes32）"
                required
                error={contentHash && !isBytes32(contentHash) ? '需要 0x + 64 位十六进制' : null}
              >
                <input
                  type="text"
                  className="mono"
                  value={contentHash}
                  onChange={(event) => setContentHash(event.target.value)}
                  placeholder="0x…"
                />
              </Field>
            </>
          )}
          <Field
            label="payment target（可选）"
            error={!paymentOk ? '不是合法地址' : null}
            help="收款地址，写入文档状态；留空为 zero address"
          >
            <input
              type="text"
              className="mono"
              value={paymentTarget}
              onChange={(event) => setPaymentTarget(event.target.value)}
              placeholder="0x…（留空跳过）"
            />
          </Field>
          <Note tone="info">
            expectedVersion 将从 document.resolve 现读（从未发布时为 0）
            {currentVersion !== null ? `；当前版本 ${currentVersion}` : ''}。版本冲突不会自动覆盖。
          </Note>
        </>
      }
      prepare={async () => {
        const trimmedType = docType.trim()
        const intent =
          storage === 'inline'
            ? await model.controllers.name.buildPublishInlineDocument(aggregate.name, trimmedType, content, {
                paymentTarget: paymentTarget || undefined,
              })
            : await model.controllers.name.buildPublishUriDocument(aggregate.name, trimmedType, uri.trim(), contentHash)
        return model.controllers.name.prepare(intent)
      }}
      review={(prepared) =>
        prepared.intent.kind === 'publish_document' ? (
          <dl className="confirm-grid">
            <dt>expectedVersion</dt>
            <dd className="mono">{prepared.intent.expectedVersion.toString()}（现读）</dd>
            <dt>content hash</dt>
            <dd className="mono" style={{ overflowWrap: 'anywhere' }}>
              {prepared.intent.document.contentHash}
            </dd>
            <dt>storage</dt>
            <dd>{prepared.intent.document.storageType}</dd>
          </dl>
        ) : null
      }
    />
  )
}

// ---------------------------------------------------------------------------
// 9.11 撤销文档
// ---------------------------------------------------------------------------

export function RevokeDocumentDialog({
  aggregate,
  docType,
  onClose,
}: {
  aggregate: NameAggregate
  docType: string
  onClose: () => void
}) {
  const model = useBnsModel()
  const current = aggregate.documents[docType]?.data?.state ?? null

  return (
    <WriteDialog
      title={`撤销文档 ${aggregate.name} / ${docType}`}
      icon={<Ban />}
      onClose={onClose}
      danger
      confirmText={aggregate.name}
      form={
        <>
          <Note tone="danger">
            撤销不会删除历史版本，而是创建一个新的 <b>Revoked</b> 版本；
            payment target 与各 policy hash 在新版本中清零。
            {docType === 'owner' ? ' owner 文档撤销后 owner_document_version 指向新 revoked 版本。' : ''}
          </Note>
          <dl className="confirm-grid">
            <dt>当前版本</dt>
            <dd className="mono">{current?.version.toString() ?? '（现读）'}</dd>
            <dt>将生成</dt>
            <dd className="mono">
              {current ? `版本 ${(current.version + 1n).toString()}（Revoked）` : '当前版本 + 1（Revoked）'}
            </dd>
            <dt>reason hash</dt>
            <dd className="mono">{ZERO_BYTES32.slice(0, 18)}…（未提供）</dd>
          </dl>
        </>
      }
      prepare={async () =>
        model.controllers.name.prepare(await model.controllers.name.buildRevokeDocument(aggregate.name, docType))
      }
    />
  )
}

// ---------------------------------------------------------------------------
// 9.15 Payment Target
// ---------------------------------------------------------------------------

export function PaymentTargetDialog({
  aggregate,
  docType,
  onClose,
}: {
  aggregate: NameAggregate
  docType: string
  onClose: () => void
}) {
  const model = useBnsModel()
  const [target, setTarget] = useState('')
  const current = aggregate.documents[docType]?.data?.state ?? null
  const targetOk = isAddress(target)

  return (
    <WriteDialog
      title={`设置支付目标 · ${aggregate.name} / ${docType}`}
      icon={<Coins />}
      onClose={onClose}
      formValid={targetOk}
      form={
        <>
          <Note tone="info">
            本操作更新现有文档的 payment target：<b>不创建新版本</b>（version 不变），
            但会更新 document state hash 并使 name_seq 增加。文档必须已存在。
          </Note>
          <Field label="payment target 地址" required error={target && !targetOk ? '不是合法地址' : null}>
            <input
              type="text"
              className="mono"
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              placeholder="0x…"
            />
          </Field>
        </>
      }
      prepare={async () =>
        model.controllers.name.prepare(
          await model.controllers.name.buildSetPaymentTarget(aggregate.name, docType, target),
        )
      }
      review={() =>
        current ? (
          <DiffPair
            label="payment target"
            before={<span className="mono">{current.paymentTarget}</span>}
            after={<span className="mono">{target}</span>}
          />
        ) : null
      }
    />
  )
}

// ---------------------------------------------------------------------------
// 9.12 Authority Keys
// ---------------------------------------------------------------------------

export function AuthorityKeysDialog({ aggregate, onClose }: { aggregate: NameAggregate; onClose: () => void }) {
  const model = useBnsModel()
  const session = useSession()
  const [mode, setMode] = useState<'add_wallet' | 'revoke'>('add_wallet')
  const [kid, setKid] = useState('')
  const [purposeAuth, setPurposeAuth] = useState(true)
  const [purposeRecovery, setPurposeRecovery] = useState(false)
  const [purposeSign, setPurposeSign] = useState(false)

  const kidOk = isBytes32(kid)
  const walletAddress = session.wallet.address

  const buildUpdates = (): AuthorityKeyUpdateInput[] => {
    if (mode === 'revoke') {
      return [
        {
          active: false,
          key: {
            kid,
            verificationMethod: ZERO_BYTES32,
            keyData: new Uint8Array(0),
            purposes: 0,
            validFrom: 0n,
            validUntil: 0n,
            status: 'revoked',
            metadataHash: ZERO_BYTES32,
          },
        },
      ]
    }
    const keyData = walletAddress
      ? Uint8Array.from(
          (walletAddress.slice(2).match(/.{2}/g) ?? []).map((byte) => Number.parseInt(byte, 16)),
        )
      : new Uint8Array(0)
    return [
      {
        active: true,
        key: {
          kid,
          verificationMethod: ZERO_BYTES32,
          keyData,
          purposes: (purposeAuth ? 1 : 0) | (purposeRecovery ? 2 : 0) | (purposeSign ? 4 : 0),
          validFrom: 0n,
          validUntil: 0n,
          status: 'active',
          metadataHash: ZERO_BYTES32,
        },
      },
    ]
  }

  const randomKid = () => {
    const bytes = new Uint8Array(32)
    crypto.getRandomValues(bytes)
    setKid(`0x${[...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('')}`)
  }

  return (
    <WriteDialog
      title={`更新 Authority Keys · ${aggregate.name}`}
      icon={<KeyRound />}
      onClose={onClose}
      danger
      formValid={kidOk && (mode === 'revoke' || walletAddress !== null)}
      form={
        <>
          <Note tone="warn">
            bns-server 没有「列出全部 key」接口：批量替换前请确认 kid 无冲突。
            撤销 key 属于高风险操作；若该名称被其他名称用作 authority owner，
            不能撤销它的最后一个 active authentication key。
          </Note>
          <Field label="操作" required>
            <div className="radio-row">
              <span
                className={`radio-card ${mode === 'add_wallet' ? 'is-active' : ''}`}
                onClick={() => setMode('add_wallet')}
              >
                使用当前钱包作为 key
                <span style={{ display: 'block', fontSize: 11, color: 'var(--text-faint)' }}>
                  key data 自动编码为钱包 20 字节地址
                </span>
              </span>
              <span className={`radio-card ${mode === 'revoke' ? 'is-active' : ''}`} onClick={() => setMode('revoke')}>
                撤销指定 kid
              </span>
            </div>
          </Field>
          <Field
            label="kid（bytes32）"
            required
            error={kid && !kidOk ? '需要 0x + 64 位十六进制，且不得为全零' : null}
            help="链上 kid 是 bytes32。人类可读标签需按 keccak256(UTF-8(label)) 计算后填入——本原型不代算，可用随机生成"
          >
            <div style={{ display: 'flex', gap: 8 }}>
              <input
                type="text"
                className="mono"
                value={kid}
                onChange={(event) => setKid(event.target.value)}
                placeholder="0x…"
                style={{ flex: 1 }}
              />
              {mode === 'add_wallet' ? (
                <button type="button" className="btn btn--sm" onClick={randomKid}>
                  随机生成
                </button>
              ) : null}
            </div>
          </Field>
          {mode === 'add_wallet' ? (
            <>
              <CheckRow checked={purposeAuth} onChange={setPurposeAuth} label="Authentication（bit 1）" hint="唯一参与链上 msg.sender 验证的 purpose" />
              <CheckRow
                checked={purposeRecovery}
                onChange={setPurposeRecovery}
                label="Recovery（bit 2）"
                hint="当前不授予链上写权限（PRD 6.4.11），仅作元数据"
              />
              <CheckRow
                checked={purposeSign}
                onChange={setPurposeSign}
                label="Sign Document（bit 4）"
                hint="当前不授予链上写权限，供链下签发文档使用"
              />
            </>
          ) : null}
        </>
      }
      prepare={() =>
        model.controllers.name.prepare(model.controllers.name.buildUpdateAuthorityKeys(aggregate.name, buildUpdates()))
      }
      review={() => (
        <Note tone="info">
          提交后请以 authority.get_set 校验 seq / root / active key count，再按已知 kid 逐个复查。
        </Note>
      )}
    />
  )
}

// ---------------------------------------------------------------------------
// 9.13 Controller Policy（全量替换）
// ---------------------------------------------------------------------------

interface RuleDraft {
  principalKind: 'chain_account' | 'bns_name'
  principalValue: string
  docType: string
  permissions: number
  validUntilDays: string
}

export function ControllerPolicyDialog({
  aggregate,
  presetEmpty = false,
  onClose,
}: {
  aggregate: NameAggregate
  /** 接管场景（PRD 9.24）：预填「清空全部规则」。 */
  presetEmpty?: boolean
  onClose: () => void
}) {
  const model = useBnsModel()
  const [rules, setRules] = useState<RuleDraft[]>(
    presetEmpty
      ? []
      : [
          {
            principalKind: 'chain_account',
            principalValue: '',
            docType: '',
            permissions: PERMISSION_PUBLISH_DOCUMENT,
            validUntilDays: '',
          },
        ],
  )

  const rulesValid = rules.every((rule) => {
    const principalOk =
      rule.principalKind === 'chain_account'
        ? isAddress(rule.principalValue)
        : validateBnsName(rule.principalValue.trim()).ok
    const docTypeOk = rule.docType === '' || /^[a-z0-9_-]{1,32}$/.test(rule.docType)
    return principalOk && docTypeOk && rule.permissions > 0
  })

  const toInputs = (): ControllerRuleInput[] =>
    rules.map((rule) => ({
      controller:
        rule.principalKind === 'chain_account'
          ? { kind: 'chain_account', value: rule.principalValue }
          : { kind: 'bns_name', value: rule.principalValue.trim() },
      docType: rule.docType,
      permissions: rule.permissions,
      namespaceScopeHash: ZERO_BYTES32,
      validFrom: 0n,
      validUntil:
        rule.validUntilDays.trim() === ''
          ? 0n
          : BigInt(Math.floor(Date.now() / 1000)) + BigInt(rule.validUntilDays) * DAY,
      constraintHash: ZERO_BYTES32,
    }))

  const permissionBits: { bit: number; label: string }[] = [
    { bit: PERMISSION_PUBLISH_DOCUMENT, label: 'Publish Document' },
    { bit: PERMISSION_REVOKE_DOCUMENT, label: 'Revoke Document' },
    { bit: PERMISSION_SET_PAYMENT, label: 'Set Payment' },
    { bit: PERMISSION_SET_ALIAS, label: 'Set Alias' },
    { bit: PERMISSION_SET_NAMESPACE, label: 'Set Namespace' },
  ]

  return (
    <WriteDialog
      title={`替换 Controller 规则 · ${aggregate.name}`}
      icon={<Shield />}
      onClose={onClose}
      danger
      wide
      confirmText={aggregate.name}
      formValid={rulesValid}
      form={
        <>
          <Note tone="danger">
            <b>本次调用会替换全部现有规则。</b>
            bns-server 没有 controller 规则查询接口——页面无法展示当前规则明细，
            你必须重新填写完整规则集；提交空列表即收回所有授权。
          </Note>
          {rules.map((rule, index) => (
            <div key={index} className="card" style={{ background: 'var(--bg-raise)', marginBottom: 10 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                <b style={{ fontSize: 13 }}>规则 {index + 1}</b>
                <button
                  type="button"
                  className="btn btn--ghost btn--sm"
                  onClick={() => setRules(rules.filter((_, i) => i !== index))}
                >
                  删除
                </button>
              </div>
              <div className="grid grid--2">
                <Field label="Controller Principal" required>
                  <div style={{ display: 'flex', gap: 6 }}>
                    <select
                      value={rule.principalKind}
                      onChange={(event) =>
                        setRules(
                          rules.map((r, i) =>
                            i === index
                              ? { ...r, principalKind: event.target.value as RuleDraft['principalKind'] }
                              : r,
                          ),
                        )
                      }
                      style={{ width: 130 }}
                    >
                      <option value="chain_account">链账户</option>
                      <option value="bns_name">BNS 名称</option>
                    </select>
                    <input
                      type="text"
                      className="mono"
                      value={rule.principalValue}
                      onChange={(event) =>
                        setRules(rules.map((r, i) => (i === index ? { ...r, principalValue: event.target.value } : r)))
                      }
                      placeholder={rule.principalKind === 'chain_account' ? '0x…' : 'provider'}
                      style={{ flex: 1 }}
                    />
                  </div>
                </Field>
                <Field label="doc type（空 = wildcard）">
                  <input
                    type="text"
                    className="mono"
                    value={rule.docType}
                    onChange={(event) =>
                      setRules(rules.map((r, i) => (i === index ? { ...r, docType: event.target.value } : r)))
                    }
                    placeholder="zone（留空匹配全部）"
                  />
                </Field>
              </div>
              <Field label="权限">
                <div className="chips">
                  {permissionBits.map(({ bit, label }) => (
                    <span
                      key={bit}
                      className={`radio-card ${(rule.permissions & bit) !== 0 ? 'is-active' : ''}`}
                      style={{ padding: '4px 9px', fontSize: 11.5 }}
                      onClick={() =>
                        setRules(
                          rules.map((r, i) => (i === index ? { ...r, permissions: r.permissions ^ bit } : r)),
                        )
                      }
                    >
                      {label}
                    </span>
                  ))}
                </div>
              </Field>
              <Field label="有效期（天，空 = 不设截止）">
                <input
                  type="number"
                  value={rule.validUntilDays}
                  onChange={(event) =>
                    setRules(rules.map((r, i) => (i === index ? { ...r, validUntilDays: event.target.value } : r)))
                  }
                  placeholder="365"
                  min={1}
                />
              </Field>
              <div style={{ fontSize: 11.5, color: 'var(--text-faint)' }}>
                namespace scope hash / constraint hash 固定为 zero——当前仅作为链上元数据保存，
                合约授权逻辑不执行这两个约束（PRD 6.4.10）。
              </div>
            </div>
          ))}
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              type="button"
              className="btn btn--sm"
              onClick={() =>
                setRules([
                  ...rules,
                  {
                    principalKind: 'chain_account',
                    principalValue: '',
                    docType: '',
                    permissions: PERMISSION_PUBLISH_DOCUMENT,
                    validUntilDays: '',
                  },
                ])
              }
            >
              添加规则
            </button>
            <button
              type="button"
              className="btn btn--sm"
              onClick={() => {
                const blob = new Blob([JSON.stringify(rules, null, 2)], { type: 'application/json' })
                const url = URL.createObjectURL(blob)
                const anchor = document.createElement('a')
                anchor.href = url
                anchor.download = `${aggregate.name}-controller-rules.json`
                anchor.click()
                URL.revokeObjectURL(url)
              }}
            >
              导出本地 JSON
            </button>
          </div>
          {rules.length === 0 ? (
            <Note tone="warn">
              规则列表为空：提交后将清空该名称的全部 controller 授权（收回代办 / 请求秘钥）。
            </Note>
          ) : null}
        </>
      }
      prepare={() =>
        model.controllers.name.prepare(model.controllers.name.buildSetControllerPolicy(aggregate.name, toInputs()))
      }
      review={() => (
        <Note tone="warn">
          替换语义：链上只保留本次提交的 {rules.length} 条规则。policy hash 传 zero
          （当前合约不计算或验证 policy hash）。请自行保存规则 JSON 以备之后重建。
        </Note>
      )}
    />
  )
}

// ---------------------------------------------------------------------------
// 9.14 DID Alias
// ---------------------------------------------------------------------------

export function AliasDialog({ aggregate, onClose }: { aggregate: NameAggregate; onClose: () => void }) {
  const model = useBnsModel()
  const [kind, setKind] = useState<'none' | 'alias' | 'migrated_to' | 'canonical'>('alias')
  const [target, setTarget] = useState('')

  const targetOk = kind === 'none' || (target.startsWith('did:') && target.length > 4)

  return (
    <WriteDialog
      title={`设置 DID Alias · ${aggregate.name}`}
      icon={<LinkIcon />}
      onClose={onClose}
      danger
      formValid={targetOk}
      form={
        <>
          <Field label="Alias 类型" required>
            <div className="radio-row">
              {(['alias', 'migrated_to', 'canonical', 'none'] as const).map((option) => (
                <span
                  key={option}
                  className={`radio-card ${kind === option ? 'is-active' : ''}`}
                  onClick={() => setKind(option)}
                >
                  {option === 'none' ? 'None（清除）' : option}
                </span>
              ))}
            </div>
          </Field>
          {kind !== 'none' ? (
            <Field
              label="目标 DID"
              required
              error={target && !targetOk ? '必须以 did: 开头且长度大于 4' : null}
            >
              <input
                type="text"
                className="mono"
                value={target}
                onChange={(event) => setTarget(event.target.value)}
                placeholder="did:web:example.com / did:bns:other"
              />
            </Field>
          ) : null}
          <Note tone="info">
            读取现状：bns-server 没有独立的 alias 查询接口，alias 状态从 document.resolve
            或事件推断（PRD 9.14）。
          </Note>
        </>
      }
      prepare={() =>
        model.controllers.name.prepare(
          model.controllers.name.buildSetDidAlias(aggregate.name, kind === 'none' ? '' : target.trim(), kind),
        )
      }
    />
  )
}

// ---------------------------------------------------------------------------
// 9.8 Namespace 策略
// ---------------------------------------------------------------------------

export function NamespaceDialog({ aggregate, onClose }: { aggregate: NameAggregate; onClose: () => void }) {
  const model = useBnsModel()
  const state = aggregate.overview.data?.state ?? null
  const [allow, setAllow] = useState(state?.allowDelegatedSubnames ?? false)

  return (
    <WriteDialog
      title={`Namespace 策略 · ${aggregate.name}`}
      icon={<Shield />}
      onClose={onClose}
      form={
        <>
          <CheckRow
            checked={allow}
            onChange={setAllow}
            label="allow delegated subnames"
            hint="flag 会被保存与查询；当前 registerName 未用它做二级名称鉴权——开启后第三方仍不能直接注册子名称（PRD 6.4.3）"
          />
          <Note tone="info">namespace policy hash 本表单固定传 zero bytes32（高级用法请走原始参数工具）。</Note>
        </>
      }
      prepare={() =>
        model.controllers.name.prepare(model.controllers.name.buildNamespacePolicy(aggregate.name, allow))
      }
      review={() =>
        state ? (
          <DiffPair
            label="allow_delegated_subnames"
            before={state.allowDelegatedSubnames ? 'true' : 'false'}
            after={allow ? 'true' : 'false'}
          />
        ) : null
      }
    />
  )
}

// ---------------------------------------------------------------------------
// 9.16 吊销历史签发（Owner IAT Floor）
// ---------------------------------------------------------------------------

export function MinIatDialog({ aggregate, onClose }: { aggregate: NameAggregate; onClose: () => void }) {
  const model = useBnsModel()
  const state = aggregate.overview.data?.state ?? null
  const [localTime, setLocalTime] = useState(() => {
    const now = new Date()
    now.setMinutes(now.getMinutes() - now.getTimezoneOffset())
    return now.toISOString().slice(0, 16)
  })

  const newIat = useMemo(() => {
    const parsed = Date.parse(localTime)
    return Number.isNaN(parsed) ? null : BigInt(Math.floor(parsed / 1000))
  }, [localTime])

  const current = state?.minDocumentIat ?? 0n
  const increaseOk = newIat !== null && newIat > current

  return (
    <WriteDialog
      title={`吊销历史签发 · ${aggregate.name}`}
      icon={<History />}
      onClose={onClose}
      danger
      confirmText={aggregate.name}
      formValid={increaseOk}
      form={
        <>
          <Note tone="info">
            <b>场景：</b>设备丢失或私钥疑似泄露，但你还想继续使用该名称下的签发能力。
            选定一个时间后，该名称 owner 签发的、iat 早于该时间的链下文档
            （含未上链的二级名称 / 设备文档）一律视为无效；第三方校验方会在链上查到这个阈值。
            吊销后用当前私钥重新签发仍需要的文档即可恢复使用。
          </Note>
          <Field
            label="新的 IAT 下限（此时间之前签发的全部失效）"
            required
            error={newIat !== null && !increaseOk ? '新值必须大于当前值（只能增加，不能回退）' : null}
          >
            <input type="datetime-local" value={localTime} onChange={(event) => setLocalTime(event.target.value)} />
          </Field>
          <dl className="confirm-grid">
            <dt>当前 min_document_iat</dt>
            <dd>{current === 0n ? '未设置（0）' : formatTime(current)}</dd>
            <dt>新值</dt>
            <dd>{newIat !== null ? formatTime(newIat) : '—'}</dd>
          </dl>
        </>
      }
      prepare={() =>
        model.controllers.name.prepare(
          model.controllers.name.buildSetMinDocumentIat(aggregate.name, newIat ?? 0n),
        )
      }
      review={() => (
        <Note tone="danger">
          <b>不可回退。</b>阈值只能增加。此操作影响该 owner 签发的链下文档的验证语义：
          iat 早于阈值的文档将被判为无效；受影响的文档需要用当前私钥重新签发。
        </Note>
      )}
    />
  )
}

// ---------------------------------------------------------------------------
// 9.18 释放与永久 Tombstone
// ---------------------------------------------------------------------------

export function ReleaseDialog({
  aggregate,
  mode,
  onClose,
}: {
  aggregate: NameAggregate
  mode: 'release_after_grace' | 'tombstone_forever'
  onClose: () => void
}) {
  const model = useBnsModel()
  const state = aggregate.overview.data?.state ?? null
  const isTombstone = mode === 'tombstone_forever'

  return (
    <WriteDialog
      title={isTombstone ? `永久禁用 ${aggregate.name}` : `释放 ${aggregate.name}`}
      icon={<Timer />}
      onClose={onClose}
      danger
      confirmText={aggregate.name}
      acknowledge={isTombstone ? '我理解该名称将永久停用，包括我自己在内任何人都无法再注册或使用它' : null}
      form={
        <>
          {isTombstone ? (
            <Note tone="danger">
              <b>永久禁用（Tombstone）对所有人生效、包括 owner 本人，且不可逆。</b>
              典型动机：名称被盗用后的信用止损（彻底禁用以示负责）；或主体不再存续、
              名称在法律上无人继承，宣告其成为 dead name。
            </Note>
          ) : (
            <Note tone="warn">
              释放后名称立即离开 Active（写入 Released）。当前合约允许 Released 名称被重新注册，
              且不等待 grace、也不清理旧 authority / 文档 / policy / alias 存储（PRD 6.4.5 / 6.4.8）——
              本产品的普通注册流程会阻断这类名称，但其他客户端未必。
            </Note>
          )}
          {state ? (
            <dl className="confirm-grid">
              <dt>名称</dt>
              <dd className="mono">{aggregate.name}</dd>
              <dt>Asset Owner</dt>
              <dd className="mono">{state.assetOwner}</dd>
              <dt>Effective Owner</dt>
              <dd>{principalText(state.effectiveOwner)}</dd>
              <dt>提交后状态</dt>
              <dd>
                <Pill tone={isTombstone ? 'danger' : 'warn'}>{isTombstone ? 'Tombstoned' : 'Released'}</Pill>
              </dd>
            </dl>
          ) : null}
        </>
      }
      prepare={() => model.controllers.name.prepare(model.controllers.name.buildRelease(aggregate.name, mode))}
    />
  )
}
