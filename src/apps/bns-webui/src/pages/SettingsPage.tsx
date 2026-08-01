/**
 * 设置（PRD 7.2 #10）：部署配置与会话信息的只读展示 + 演示模式工具。
 *
 * 合约地址与投递模式是部署期配置，不允许终端用户在页面上修改（PRD 8.5 / README §3.36）。
 */

import { FlaskConical, Server, Settings, Wallet } from 'lucide-react'
import { useState } from 'react'

import { describeDeliveryMode } from '../bns_model'
import { useBnsModel, useSession } from '../bns_model/react'
import { requestRejectNext, rejectNextPending } from '../demo'
import { CopyText, Note, Pill } from '../ui/kit'

export function SettingsPage({ demoMode }: { demoMode: boolean }) {
  const model = useBnsModel()
  const session = useSession()
  const [rejectArmed, setRejectArmed] = useState(rejectNextPending())
  const info = session.systemInfo.data

  return (
    <div>
      <h1 className="page-title">
        <Settings style={{ width: 20, height: 20, color: 'var(--accent)' }} /> 设置
      </h1>
      <p className="page-sub">部署配置只读展示；合约地址与投递模式不允许在界面上修改。</p>

      <section className="card">
        <h2 className="card__title">
          <Server /> 服务与网络
        </h2>
        <dl className="kv">
          <dt>bns-server</dt>
          <dd className="mono">{model.config.serverUrl}</dd>
          <dt>kRPC 路径</dt>
          <dd className="mono">{model.config.rpcPath}</dd>
          <dt>chain ID（system.info）</dt>
          <dd className="mono">{info?.chainId ?? '—'}</dd>
          <dt>合约 Proxy（system.info）</dt>
          <dd>{info ? <CopyText value={info.contractAddress} /> : '—'}</dd>
          <dt>合约信任来源</dt>
          <dd>
            {model.config.contractTrust === 'pinned' ? (
              <>
                <Pill tone="ok">pinned</Pill>
                <span style={{ fontSize: 11.5, color: 'var(--text-faint)', display: 'block' }}>
                  与构建期锚点 {model.config.expectedContractAddress ?? '（未配置！）'} 逐字比对
                </span>
              </>
            ) : (
              <>
                <Pill tone="warn">server</Pill>
                <span style={{ fontSize: 11.5, color: 'var(--text-faint)', display: 'block' }}>
                  完全信任 system.info 返回的地址——仅限本地联调 / 演示；生产构建必须注入
                  VITE_BNS_CONTRACT_ADDRESS 使用 pinned 模式
                </span>
              </>
            )}
          </dd>
          <dt>交易投递</dt>
          <dd>
            <Pill tone={model.deliveryMode === 'wallet_direct' ? 'ok' : 'warn'}>{model.deliveryMode}</Pill>
            <span style={{ fontSize: 11.5, color: 'var(--text-faint)', display: 'block' }}>
              {describeDeliveryMode(model.deliveryMode)}
            </span>
          </dd>
          <dt>交易轮询节奏</dt>
          <dd style={{ fontSize: 12.5, color: 'var(--text-dim)' }}>
            前 30 秒每 2 秒 → 5 分钟内每 5 秒 → 之后每 15 秒（可停止）；
            投影超时阈值 {model.config.polling.indexerTimeoutMs / 1000} 秒
          </dd>
        </dl>
      </section>

      <section className="card">
        <h2 className="card__title">
          <Wallet /> 会话
        </h2>
        <dl className="kv">
          <dt>钱包</dt>
          <dd className="mono">
            {session.wallet.connected ? `${session.wallet.address}（chain ${session.wallet.chainId}）` : '未连接'}
          </dd>
          <dt>写闸门</dt>
          <dd>
            {session.writeGate.allowed ? (
              <Pill tone="ok" dot>
                允许写操作
              </Pill>
            ) : (
              <>
                <Pill tone="warn" dot>
                  只读
                </Pill>
                <span style={{ fontSize: 12, color: 'var(--text-dim)', display: 'block' }}>
                  {session.writeGate.reason}
                </span>
              </>
            )}
          </dd>
        </dl>
      </section>

      {demoMode ? (
        <section className="card">
          <h2 className="card__title">
            <FlaskConical /> 演示模式工具
          </h2>
          <Note tone="info">
            当前运行在演示模式：内置假 bns-server（13 个 kRPC method + DID Resolver）、
            演示钱包与演示 calldata 编码。写交易走完整的两阶段生命周期
            （链上确认约 1.3 秒，投影延迟约 2.2 秒，刻意保留 Indexing 窗口）。
            数据存于页面内存，刷新后重置为种子世界。
          </Note>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
            <button
              type="button"
              className="btn"
              disabled={rejectArmed}
              onClick={() => {
                requestRejectNext()
                setRejectArmed(true)
              }}
            >
              模拟下一笔交易被拒签
            </button>
            {rejectArmed ? <Pill tone="warn">已布防：下一笔签名将被拒绝</Pill> : null}
            <button type="button" className="btn btn--ghost" onClick={() => window.location.reload()}>
              重置演示世界（刷新页面）
            </button>
          </div>
          <Note tone="neutral">
            连接真实 bns-server：启动时设置 <code>VITE_BNS_SERVER_URL</code>（只读浏览），
            生产写路径还需注入 <code>VITE_BNS_CONTRACT_ADDRESS</code> 与真实钱包 / ABI 适配器。
          </Note>
        </section>
      ) : null}
    </div>
  )
}
