/**
 * Controller / Alias 与支付 / Namespace / 活动记录 / 危险操作 tab。
 * （PRD 9.8 / 9.13 / 9.14 / 9.15 / 9.16 / 9.18 / 9.20 / 9.24）
 */

import {
  Activity,
  Ban,
  Coins,
  DoorOpen,
  History,
  Link as LinkIcon,
  Network,
  RefreshCw,
  Shield,
  Skull,
} from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

import { EVENT_TYPE_LABELS, type NameAggregate } from '../../bns_model'
import { useBnsModel, useSession } from '../../bns_model/react'
import { formatTime, isZeroHex, principalText, shortHash } from '../../ui/format'
import { CopyText, Note, Pill, RawDetails, Spinner } from '../../ui/kit'
import {
  AliasDialog,
  ControllerPolicyDialog,
  MinIatDialog,
  NamespaceDialog,
  PaymentTargetDialog,
  ReleaseDialog,
} from './dialogs'

// ---------------------------------------------------------------------------
// Controller tab
// ---------------------------------------------------------------------------

export function ControllerTab({ aggregate }: { aggregate: NameAggregate }) {
  const model = useBnsModel()
  const session = useSession()
  const [dialog, setDialog] = useState<'replace' | 'reclaim' | null>(null)

  useEffect(() => {
    if (aggregate.activity.status === 'idle') void model.controllers.name.loadActivity(aggregate.name)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [model, aggregate.name])

  const snapshot = aggregate.controllerPolicy.data ?? null
  const hasPolicyEvidence = snapshot?.policyHash !== null && snapshot !== null && !isZeroHex(snapshot.policyHash)
  const walletIsOwner = aggregate.authority?.canAttempt ?? false

  return (
    <div>
      <section className="card">
        <h2 className="card__title">
          <Shield /> Controller Policy
        </h2>
        {aggregate.controllerPolicy.status === 'loading' && !snapshot ? (
          <div className="loading-row">
            <Spinner /> 从事件回扫 policy 记录…
          </div>
        ) : snapshot ? (
          <>
            <dl className="kv kv--tight">
              <dt>policy hash</dt>
              <dd>
                {snapshot.policyHash ? (
                  <CopyText value={snapshot.policyHash} display={shortHash(snapshot.policyHash)} />
                ) : (
                  '未发现相关事件'
                )}
              </dd>
              <dt>最近更新</dt>
              <dd>
                {snapshot.updatedAtSeq !== null
                  ? `事件 #${snapshot.updatedAtSeq}（name_seq ${snapshot.updatedNameSeq}）`
                  : '—'}
              </dd>
              <dt>规则明细</dt>
              <dd style={{ color: 'var(--text-dim)' }}>{snapshot.note}</dd>
            </dl>
            {hasPolicyEvidence ? (
              <Note tone="warn">
                <b>可能存在代办 / controller 授权（推断）。</b>
                依据是事件中的非零 policy hash；bns-server 没有 controller.get_policy 查询接口，
                无法断言当前规则内容（PRD 9.24 的已知缺口）。
              </Note>
            ) : (
              <Note tone="info">未发现 controller policy 事件；这不能证明不存在授权，只是缺少证据。</Note>
            )}
          </>
        ) : null}
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 10 }}>
          <button type="button" className="btn" onClick={() => setDialog('replace')}>
            <Shield /> 替换全部规则（高级）
          </button>
          {hasPolicyEvidence && walletIsOwner ? (
            <button type="button" className="btn btn--danger" onClick={() => setDialog('reclaim')}>
              <DoorOpen /> 收回代办授权（清空规则）
            </button>
          ) : null}
        </div>
      </section>

      <section className="card">
        <h2 className="card__title">
          <DoorOpen /> 服务商模式与接管（PRD 9.24）
        </h2>
        <p style={{ fontSize: 12.5, color: 'var(--text-dim)', margin: '0 0 8px' }}>
          代办注册的服务商通过 controller 规则（产品语言：请求秘钥）为你继续代办操作。
          你始终是最大权限方：可以随时单方面收回授权，或换成另一家服务商。
          收回操作是「全量替换」语义——若还有其他 controller 授权，需要一并重新填写。
        </p>
        <Note tone="info">
          建议：当你的钱包已有可用 gas，尽早通知服务商并收回代办授权，改为自主管理（见
          <Link to="/security"> 安全中心</Link>）。
        </Note>
      </section>

      {dialog === 'replace' ? <ControllerPolicyDialog aggregate={aggregate} onClose={() => setDialog(null)} /> : null}
      {dialog === 'reclaim' ? (
        <ControllerPolicyDialog aggregate={aggregate} presetEmpty onClose={() => setDialog(null)} />
      ) : null}
      {!session.wallet.connected ? null : null}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Alias 与支付 tab
// ---------------------------------------------------------------------------

export function AliasPaymentTab({ aggregate }: { aggregate: NameAggregate }) {
  const model = useBnsModel()
  const [dialog, setDialog] = useState<'alias' | 'payment' | null>(null)
  const [payDocType, setPayDocType] = useState('payment')

  useEffect(() => {
    if (aggregate.activity.status === 'idle') void model.controllers.name.loadActivity(aggregate.name)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [model, aggregate.name])

  const alias = aggregate.alias.data ?? null
  const zoneDoc = aggregate.documents.zone?.data ?? null
  const docAlias = zoneDoc && zoneDoc.aliasKind !== 'none' ? zoneDoc : null

  return (
    <div>
      <section className="card">
        <h2 className="card__title">
          <LinkIcon /> DID Alias
        </h2>
        {docAlias ? (
          <dl className="kv kv--tight">
            <dt>kind</dt>
            <dd>
              <Pill tone="accent">{docAlias.aliasKind}</Pill>
            </dd>
            <dt>目标 DID</dt>
            <dd>
              <CopyText value={docAlias.aliasTargetDid} />
            </dd>
            <dt>数据来源</dt>
            <dd style={{ color: 'var(--text-faint)' }}>document.resolve（当前可查询文档携带）</dd>
          </dl>
        ) : alias ? (
          <dl className="kv kv--tight">
            <dt>kind</dt>
            <dd>
              <Pill tone="accent">{alias.kind}</Pill>
            </dd>
            <dt>目标 DID</dt>
            <dd>
              <CopyText value={alias.targetDid} />
            </dd>
            <dt>数据来源</dt>
            <dd style={{ color: 'var(--text-faint)' }}>
              事件回扫（seq #{alias.observedAtSeq?.toString() ?? '—'}）
            </dd>
          </dl>
        ) : (
          <div className="empty">当前可查询的文档 / 事件中未发现 alias</div>
        )}
        <Note tone="info">
          bns-server 没有独立的 alias 查询接口；以上状态基于当前可查询文档与事件得到，
          <b>不保证始终完整</b>（PRD 9.14）。
        </Note>
        <button type="button" className="btn" onClick={() => setDialog('alias')}>
          设置 / 清除 Alias
        </button>
      </section>

      <section className="card">
        <h2 className="card__title">
          <Coins /> 支付目标
        </h2>
        <p className="card__hint">
          payment target 挂在具体文档上（document state），更新不产生新版本（PRD 9.15）。
        </p>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 10 }}>
          <span style={{ fontSize: 12, color: 'var(--text-faint)' }}>doc type</span>
          <select
            value={payDocType}
            onChange={(event) => setPayDocType(event.target.value)}
            style={{
              background: 'var(--bg-raise)',
              color: 'var(--text)',
              border: '1px solid var(--line)',
              borderRadius: 7,
              padding: '5px 9px',
              fontSize: 12.5,
            }}
          >
            {aggregate.docTypes.map((entry) => (
              <option key={entry.docType} value={entry.docType}>
                {entry.docType}
              </option>
            ))}
          </select>
          <button
            type="button"
            className="btn btn--sm"
            onClick={() => void model.controllers.name.loadDocument(aggregate.name, payDocType)}
          >
            <RefreshCw /> 读取
          </button>
        </div>
        {(() => {
          const doc = aggregate.documents[payDocType]?.data
          if (!doc?.state) return <div className="empty">该 doc type 未发布，payment target 需要文档已存在</div>
          return (
            <dl className="kv kv--tight">
              <dt>payment target</dt>
              <dd className="mono">{isZeroHex(doc.state.paymentTarget) ? '未设置' : doc.state.paymentTarget}</dd>
              <dt>beneficiary</dt>
              <dd>{principalText(doc.state.beneficiary)}</dd>
              <dt>版本</dt>
              <dd className="mono">v{doc.state.version.toString()}（设置支付目标不会改变它）</dd>
            </dl>
          )
        })()}
        <button
          type="button"
          className="btn"
          style={{ marginTop: 8 }}
          disabled={!aggregate.documents[payDocType]?.data?.state}
          onClick={() => setDialog('payment')}
        >
          设置支付目标
        </button>
      </section>

      {dialog === 'alias' ? <AliasDialog aggregate={aggregate} onClose={() => setDialog(null)} /> : null}
      {dialog === 'payment' ? (
        <PaymentTargetDialog aggregate={aggregate} docType={payDocType} onClose={() => setDialog(null)} />
      ) : null}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Namespace tab
// ---------------------------------------------------------------------------

export function NamespaceTab({ aggregate }: { aggregate: NameAggregate }) {
  const [open, setOpen] = useState(false)
  const state = aggregate.overview.data?.state ?? null

  return (
    <div>
      <section className="card">
        <h2 className="card__title">
          <Network /> Namespace 策略
        </h2>
        {state ? (
          <dl className="kv kv--tight">
            <dt>allow delegated subnames</dt>
            <dd>
              <Pill tone={state.allowDelegatedSubnames ? 'ok' : 'muted'}>
                {state.allowDelegatedSubnames ? 'true' : 'false'}
              </Pill>
            </dd>
            <dt>namespace policy hash</dt>
            <dd className="mono">
              {isZeroHex(state.namespacePolicyHash) ? 'zero' : shortHash(state.namespacePolicyHash)}
            </dd>
          </dl>
        ) : (
          <Spinner />
        )}
        <Note tone="warn">
          该 flag 会被保存与查询，但当前 registerName <b>不使用它做二级名称鉴权</b>：
          无论开关如何，注册子名称仍需要父名称 effective owner 签名（PRD 6.4.3）。
        </Note>
        <button type="button" className="btn" onClick={() => setOpen(true)}>
          修改 Namespace 策略
        </button>
      </section>
      {open ? <NamespaceDialog aggregate={aggregate} onClose={() => setOpen(false)} /> : null}
    </div>
  )
}

// ---------------------------------------------------------------------------
// 活动记录 tab
// ---------------------------------------------------------------------------

export function ActivityTab({ aggregate }: { aggregate: NameAggregate }) {
  const model = useBnsModel()

  useEffect(() => {
    if (aggregate.activity.status === 'idle') void model.controllers.name.loadActivity(aggregate.name)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [model, aggregate.name])

  const scan = aggregate.activity.data ?? null

  return (
    <div>
      <section className="card">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
          <h2 className="card__title" style={{ margin: 0 }}>
            <Activity /> 活动记录
          </h2>
          <button
            type="button"
            className="btn btn--ghost btn--sm"
            style={{ marginLeft: 'auto' }}
            onClick={() => void model.controllers.name.loadActivity(aggregate.name)}
          >
            <RefreshCw /> 重新扫描
          </button>
        </div>
        {aggregate.activity.status === 'loading' && !scan ? (
          <div className="loading-row">
            <Spinner /> 客户端回扫事件（服务端无按名称过滤）…
          </div>
        ) : scan ? (
          <>
            {!scan.scanExhausted ? (
              <Note tone="warn">
                回扫达到页数上限，未覆盖全部历史：以下记录只到 seq #{scan.scannedDownToSeq?.toString() ?? '—'}，
                更早的事件请到事件浏览器手动翻页。
              </Note>
            ) : (
              <Note tone="info">已扫完当前日志中与该名称相关的全部事件（客户端过滤）。</Note>
            )}
            {scan.records.length === 0 ? (
              <div className="empty">扫描窗口内没有该名称的事件</div>
            ) : (
              scan.records.map((record) => (
                <div key={record.seq.toString()} className="event-line">
                  <span className="event-line__seq">#{record.seq.toString()}</span>
                  <div className="event-line__body">
                    <b>{EVENT_TYPE_LABELS[record.event.type]}</b>
                    <div className="event-line__meta">
                      {formatTime(record.observedAt)} · event hash {shortHash(record.eventHash, 5, 4)}
                    </div>
                    <RawDetails label="事件原始 JSON" value={record} />
                  </div>
                </div>
              ))
            )}
          </>
        ) : null}
      </section>
    </div>
  )
}

// ---------------------------------------------------------------------------
// 危险操作 tab
// ---------------------------------------------------------------------------

export function DangerTab({ aggregate }: { aggregate: NameAggregate }) {
  const [dialog, setDialog] = useState<'min_iat' | 'release' | 'tombstone' | null>(null)
  const state = aggregate.overview.data?.state ?? null

  return (
    <div>
      <Note tone="danger">
        以下操作均为高风险：需要 effective owner 授权、经过独立的二次确认，且都不可自动重试。
        安全中心提供面向场景的引导入口，但确认要求与此处完全一致（PRD 9.23）。
      </Note>

      <section className="card">
        <h2 className="card__title">
          <History /> 吊销历史签发（Owner IAT Floor）
        </h2>
        <p style={{ fontSize: 12.5, color: 'var(--text-dim)', margin: '0 0 8px' }}>
          设备丢失 / 私钥疑似泄露，但仍想继续使用名称时：把「某时间点之前签发的链下文档」全部作废，
          再用当前私钥重新签发。当前阈值：
          <b>{state ? (state.minDocumentIat === 0n ? ' 未设置' : ` ${formatTime(state.minDocumentIat)}`) : ' —'}</b>
          （owner_policy_seq {state?.ownerPolicySeq.toString() ?? '—'}）
        </p>
        <button type="button" className="btn" onClick={() => setDialog('min_iat')}>
          <History /> 提升 IAT 下限
        </button>
      </section>

      <section className="card">
        <h2 className="card__title">
          <Ban /> 释放（ReleaseAfterGrace）
        </h2>
        <p style={{ fontSize: 12.5, color: 'var(--text-dim)', margin: '0 0 8px' }}>
          主动放弃该名称。立即离开 Active、写入 Released；按当前合约它可能被重新注册，
          且旧 authority / 文档 / policy 状态不会被清理（PRD 6.4.5 / 6.4.8）。
        </p>
        <button type="button" className="btn btn--danger" onClick={() => setDialog('release')}>
          <Ban /> 释放名称
        </button>
      </section>

      <section className="card">
        <h2 className="card__title">
          <Skull /> 永久禁用（TombstoneForever）
        </h2>
        <p style={{ fontSize: 12.5, color: 'var(--text-dim)', margin: '0 0 8px' }}>
          与信用绑定的一次性决定：对所有人生效（包括你自己），永远无法重新注册。
          适用于被盗用后的信用止损，或实体消亡后的 dead name 宣告。
        </p>
        <button type="button" className="btn btn--danger" onClick={() => setDialog('tombstone')}>
          <Skull /> 永久禁用
        </button>
      </section>

      {dialog === 'min_iat' ? <MinIatDialog aggregate={aggregate} onClose={() => setDialog(null)} /> : null}
      {dialog === 'release' ? (
        <ReleaseDialog aggregate={aggregate} mode="release_after_grace" onClose={() => setDialog(null)} />
      ) : null}
      {dialog === 'tombstone' ? (
        <ReleaseDialog aggregate={aggregate} mode="tombstone_forever" onClose={() => setDialog(null)} />
      ) : null}
    </div>
  )
}
