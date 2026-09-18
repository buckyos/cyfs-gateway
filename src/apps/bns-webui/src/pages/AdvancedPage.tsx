/**
 * 高级工具（PRD 9.22 + 能力缺口清单）。
 *
 * - checkpoint 只读展示；publishLogCheckpoint 不进普通 UI（issuer 未与 msg.sender 绑定）；
 * - DID Resolver 手动查询；
 * - 服务端能力缺口对照表（模块如实表达，不用文案掩盖）。
 */

import { Database, Globe, ScrollText, Terminal } from 'lucide-react'
import { useEffect, useState } from 'react'

import { useBnsModel, useEvents } from '../bns_model/react'
import { formatTime, principalText, shortHash } from '../ui/format'
import { CopyText, Note, Spinner } from '../ui/kit'
import { DidResolverPanel } from './SearchPage'

const CAPABILITY_GAPS: { gap: string; handling: string }[] = [
  {
    gap: '没有「列出一个名称的全部 doc type」接口',
    handling: '文档入口 = 内置 6 个 + 本地历史 + 用户输入 + 事件发现，每项标注来源，不宣称完整',
  },
  {
    gap: '没有「列出全部 authority key」接口',
    handling: '仅按已知 kid 探测；页面显示 active_key_count 与探测条数的差异',
  },
  {
    gap: '没有 controller.get_policy（规则明细查询）',
    handling: '只展示事件里的 policy hash；替换表单要求重新填写完整规则；接管提示只能标注为推断',
  },
  {
    gap: '没有独立的 alias.get',
    handling: 'alias 从 document.resolve 或事件推断，标注数据来源',
  },
  {
    gap: 'events.list 无过滤、无「最新 N 条」',
    handling: '日志尾部用指数探测 + 二分定位；名称过滤是客户端回扫并如实透传是否扫完',
  },
  {
    gap: '没有同步高度 / 落后区块数接口',
    handling: '无法证明「已追到链 tip」；只能靠每笔交易的收敛期望判断',
  },
  {
    gap: 'name.query_by_addr 只按 asset_owner',
    handling: '资产页固定口径说明，不改写成「我能管理的名称」',
  },
  {
    gap: 'tx.query_state 无 revert reason',
    handling: '回退时优先展示提交前模拟错误，否则引导查看区块浏览器',
  },
]

export function AdvancedPage({ demoMode }: { demoMode: boolean }) {
  const model = useBnsModel()
  const events = useEvents()
  const [didInput, setDidInput] = useState('did:bns:alice')
  const [didQuery, setDidQuery] = useState<string | null>(null)

  useEffect(() => {
    void model.controllers.events.loadCheckpoint()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [model])

  const checkpoint = events.checkpoint.data ?? null

  return (
    <div>
      <h1 className="page-title">
        <Terminal style={{ width: 20, height: 20, color: 'var(--accent)' }} /> 高级工具
      </h1>
      <p className="page-sub">面向高级用户的只读工具与如实的能力缺口对照。</p>

      <section className="card">
        <h2 className="card__title">
          <ScrollText /> 最新 Log Checkpoint
        </h2>
        {events.checkpoint.status === 'loading' && !checkpoint ? (
          <div className="loading-row">
            <Spinner /> 查询 checkpoint.latest…
          </div>
        ) : checkpoint ? (
          <dl className="kv kv--tight">
            <dt>log root</dt>
            <dd>
              <CopyText value={checkpoint.logRoot} display={shortHash(checkpoint.logRoot, 10, 8)} />
            </dd>
            <dt>last seq</dt>
            <dd className="mono">{checkpoint.lastSeq.toString()}</dd>
            <dt>issued at</dt>
            <dd>{formatTime(checkpoint.issuedAt)}</dd>
            <dt>issuer</dt>
            <dd className="mono">{principalText(checkpoint.issuer)}</dd>
            <dt>external anchor</dt>
            <dd>
              <CopyText value={checkpoint.externalAnchor} display={shortHash(checkpoint.externalAnchor, 10, 8)} />
            </dd>
          </dl>
        ) : (
          <div className="empty">尚无 checkpoint</div>
        )}
        <Note tone="warn">
          publishLogCheckpoint 不在本界面开放：当前合约未把 issuer principal 与 msg.sender
          做身份绑定（PRD 6.4.6），协议运维入口需要独立的治理界面。
        </Note>
      </section>

      <section className="card">
        <h2 className="card__title">
          <Globe /> DID Resolver 手动查询
        </h2>
        <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
          <input
            type="text"
            className="mono"
            value={didInput}
            onChange={(event) => setDidInput(event.target.value)}
            placeholder="did:bns:alice"
            style={{
              flex: 1,
              background: 'var(--bg-raise)',
              border: '1px solid var(--line)',
              borderRadius: 8,
              color: 'var(--text)',
              padding: '7px 11px',
              fontSize: 12.5,
            }}
          />
          <button type="button" className="btn" onClick={() => setDidQuery(didInput.trim())}>
            解析
          </button>
        </div>
        {didQuery ? <DidResolverPanel did={didQuery} /> : null}
        <Note tone="info">
          历史（iat）查询当前返回 501 + historicalQuerySupported=false，属于能力缺口而非故障（PRD 9.21）。
        </Note>
      </section>

      <section className="card">
        <h2 className="card__title">
          <Database /> 服务端能力缺口（如实呈现）
        </h2>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>缺口</th>
                <th>本原型的处理</th>
              </tr>
            </thead>
            <tbody>
              {CAPABILITY_GAPS.map((row) => (
                <tr key={row.gap}>
                  <td>{row.gap}</td>
                  <td style={{ color: 'var(--text-dim)' }}>{row.handling}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {demoMode ? (
          <Note tone="info">
            演示模式的假 bns-server 同样只实现真实存在的 13 个 kRPC method，缺口行为与线上一致。
          </Note>
        ) : null}
      </section>
    </div>
  )
}
