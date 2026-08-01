/**
 * Owner 与 Authority tab（PRD 9.7 / 9.12 / 5.3 / 5.4）。
 */

import { KeyRound, Search, ShieldCheck, User } from 'lucide-react'
import { useEffect, useState } from 'react'

import type { NameAggregate } from '../../bns_model'
import { useBnsModel, useSession } from '../../bns_model/react'
import { formatTime, OWNER_SOURCE_LABEL, principalKindLabel, principalText, shortHash } from '../../ui/format'
import { CopyText, Note, Pill, Spinner } from '../../ui/kit'
import { AuthorityKeysDialog, SemanticOwnerDialog } from './dialogs'

export function OwnerAuthorityTab({ aggregate }: { aggregate: NameAggregate }) {
  const model = useBnsModel()
  const session = useSession()
  const [dialog, setDialog] = useState<'semantic' | 'keys' | null>(null)
  const [kidInput, setKidInput] = useState('')
  const [probing, setProbing] = useState(false)
  const [probeMessage, setProbeMessage] = useState<string | null>(null)

  useEffect(() => {
    void model.controllers.name.probeKnownKeys(aggregate.name)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [model, aggregate.name])

  const owner = aggregate.owner.data ?? null
  const state = aggregate.overview.data?.state ?? null
  const authoritySet = aggregate.authoritySet.data ?? null
  const probes = aggregate.authorityKeys.data ?? []
  const foundKeys = probes.filter((probe) => probe.key !== null)

  const probeKid = async () => {
    const kid = kidInput.trim()
    if (!kid) return
    setProbing(true)
    setProbeMessage(null)
    try {
      const key = await model.controllers.name.probeAuthorityKey(aggregate.name, kid)
      setProbeMessage(key ? '已找到该 kid 并加入本地已知列表。' : '该 kid 不存在（已记录探测结果）。')
      setKidInput('')
    } catch (error) {
      setProbeMessage(`探测失败：${error instanceof Error ? error.message : String(error)}`)
    } finally {
      setProbing(false)
    }
  }

  return (
    <div>
      <div className="grid grid--2">
        <section className="card">
          <h2 className="card__title">
            <User /> Owner 解析
          </h2>
          {owner && state ? (
            <>
              <dl className="kv kv--tight">
                <dt>Asset Owner</dt>
                <dd>
                  <CopyText value={state.assetOwner} />
                </dd>
                <dt>Semantic Owner</dt>
                <dd>
                  {principalText(state.semanticOwner)}
                  <Pill tone="muted" title="Semantic Owner 只允许 Unset 或 BNS Name">
                    {principalKindLabel(state.semanticOwner)}
                  </Pill>
                </dd>
                <dt>Effective Owner</dt>
                <dd>
                  <b>{principalText(owner.effectiveOwner)}</b>
                  <span style={{ color: 'var(--text-faint)', fontSize: 11.5, display: 'block' }}>
                    来源：{OWNER_SOURCE_LABEL[owner.source]}
                  </span>
                </dd>
                <dt>authority root / seq</dt>
                <dd className="mono">
                  {shortHash(owner.authorityRoot, 6, 4)} / {owner.authoritySeq.toString()}
                </dd>
              </dl>
              <div className="divider" />
              <button type="button" className="btn" onClick={() => setDialog('semantic')}>
                <User /> 设置 Semantic Owner
              </button>
            </>
          ) : (
            <div className="loading-row">
              <Spinner /> 解析 owner…
            </div>
          )}
        </section>

        <section className="card">
          <h2 className="card__title">
            <ShieldCheck /> 当前钱包的授权预检
          </h2>
          {!session.wallet.connected ? (
            <div className="empty">连接钱包后展示可用授权路径</div>
          ) : aggregate.authority ? (
            <>
              <div className="chips" style={{ marginBottom: 8 }}>
                {aggregate.authority.canAttempt ? (
                  <Pill tone="ok" dot>
                    存在可尝试的授权路径
                  </Pill>
                ) : (
                  <Pill tone="warn" dot>
                    未发现可用授权路径
                  </Pill>
                )}
                {aggregate.authority.manualOnly ? <Pill tone="neutral">仅剩手动 Controller 声明</Pill> : null}
              </div>
              <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12.5, color: 'var(--text-dim)' }}>
                {aggregate.authority.notes.map((note, index) => (
                  <li key={index} style={{ marginBottom: 4 }}>
                    {note}
                  </li>
                ))}
              </ul>
            </>
          ) : (
            <div className="loading-row">
              <Spinner /> 计算授权路径…
            </div>
          )}
        </section>
      </div>

      <div className="section-gap" />

      <section className="card">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', marginBottom: 8 }}>
          <h2 className="card__title" style={{ margin: 0 }}>
            <KeyRound /> Authority Set
          </h2>
          {authoritySet ? (
            <>
              <Pill tone="neutral">seq {authoritySet.authoritySeq.toString()}</Pill>
              <Pill tone={authoritySet.activeKeyCount > 0 ? 'ok' : 'muted'}>
                active key {authoritySet.activeKeyCount}
              </Pill>
              <span className="mono" style={{ fontSize: 11.5, color: 'var(--text-faint)' }}>
                root {shortHash(authoritySet.authorityRoot, 8, 6)}
              </span>
            </>
          ) : null}
          <button type="button" className="btn btn--sm" style={{ marginLeft: 'auto' }} onClick={() => setDialog('keys')}>
            更新 Authority Keys
          </button>
        </div>

        <Note tone="warn">
          当前服务仅支持按 kid 查询。下方列表由本地记录、用户输入和已知 key 组成，<b>可能不完整</b>
          {authoritySet && authoritySet.activeKeyCount > foundKeys.filter((p) => p.key?.status === 'active').length
            ? `——authority set 报告 ${authoritySet.activeKeyCount} 个 active key，本地仅探测到 ${
                foundKeys.filter((p) => p.key?.status === 'active').length
              } 个。`
            : '。'}
        </Note>

        {aggregate.authorityKeys.status === 'loading' && probes.length === 0 ? (
          <div className="loading-row">
            <Spinner /> 探测已知 kid…
          </div>
        ) : foundKeys.length > 0 ? (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>kid</th>
                  <th>状态</th>
                  <th>purposes</th>
                  <th>key data</th>
                  <th>有效期</th>
                  <th>来源</th>
                </tr>
              </thead>
              <tbody>
                {foundKeys.map((probe) => {
                  const key = probe.key
                  if (!key) return null
                  return (
                    <tr key={probe.kid}>
                      <td className="mono">{shortHash(key.kid, 6, 4)}</td>
                      <td>
                        <Pill tone={key.status === 'active' ? 'ok' : key.status === 'revoked' ? 'danger' : 'warn'}>
                          {key.status}
                        </Pill>
                        {key.usableNow ? <Pill tone="ok">窗口内</Pill> : null}
                      </td>
                      <td>
                        <span className="chips">
                          {key.purposeFlags.authentication ? <Pill tone="accent">Auth</Pill> : null}
                          {key.purposeFlags.recovery ? (
                            <Pill tone="muted" title="当前不授予链上写权限（PRD 6.4.11）">
                              Recovery
                            </Pill>
                          ) : null}
                          {key.purposeFlags.signDocument ? (
                            <Pill tone="muted" title="当前不授予链上写权限（PRD 6.4.11）">
                              SignDoc
                            </Pill>
                          ) : null}
                        </span>
                      </td>
                      <td className="mono">
                        {key.addressFromKeyData ? shortHash(key.addressFromKeyData, 6, 4) : `${key.keyData.length} bytes`}
                      </td>
                      <td style={{ fontSize: 11.5 }}>
                        {key.validFrom === 0n && key.validUntil === 0n
                          ? '不设限'
                          : `${formatTime(key.validFrom)} ~ ${formatTime(key.validUntil)}`}
                      </td>
                      <td style={{ fontSize: 11.5, color: 'var(--text-faint)' }}>
                        {probe.source === 'user_input' ? '手工输入' : probe.source === 'event_log' ? '事件' : '本地历史'}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty">本地没有已知 kid；在下方输入 kid 探测</div>
        )}

        <div style={{ display: 'flex', gap: 8, marginTop: 12, flexWrap: 'wrap' }}>
          <input
            type="text"
            className="mono"
            value={kidInput}
            onChange={(event) => setKidInput(event.target.value)}
            placeholder="输入 kid（bytes32）探测…"
            style={{
              flex: 1,
              minWidth: 240,
              background: 'var(--bg-raise)',
              border: '1px solid var(--line)',
              borderRadius: 8,
              color: 'var(--text)',
              padding: '7px 11px',
              fontSize: 12.5,
            }}
          />
          <button type="button" className="btn btn--sm" onClick={() => void probeKid()} disabled={probing}>
            {probing ? <Spinner /> : <Search />} 探测该 kid
          </button>
        </div>
        {probeMessage ? <div style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 6 }}>{probeMessage}</div> : null}
      </section>

      {dialog === 'semantic' ? <SemanticOwnerDialog aggregate={aggregate} onClose={() => setDialog(null)} /> : null}
      {dialog === 'keys' ? <AuthorityKeysDialog aggregate={aggregate} onClose={() => setDialog(null)} /> : null}
    </div>
  )
}
