/**
 * 我买来的资产（PRD 9.3）：parent 不属于我的任何顶级名称的二级名称。
 *
 * 钱包维度的投资持有，不随账号切换过滤。
 * 「仅持有」条目（semantic owner 未设置 → 控制权仍随父名称 owner）必须显式提示。
 */

import { ArrowRight, Info, ShoppingBag } from 'lucide-react'
import { Link } from 'react-router-dom'

import { useSession } from '../bns_model/react'
import { isHoldOnly, useAccounts } from '../ui/account'
import { Note, Pill, Spinner } from '../ui/kit'
import { NameRow } from '../ui/name_list'

export function AcquiredPage() {
  const session = useSession()
  const { portfolio, acquired } = useAccounts()

  if (!session.wallet.connected) {
    return (
      <div>
        <h1 className="page-title">我买来的资产</h1>
        <Note tone="info">连接钱包后展示从他人处买入产权的名称（按钱包地址归组，跨账号）。</Note>
      </div>
    )
  }

  const holdOnlyCount = acquired.filter(isHoldOnly).length

  return (
    <div>
      <h1 className="page-title">我买来的资产</h1>
      <p className="page-sub">
        结构上不属于我的账号的持有名称（例：产权已转给我的 book.bob）。按钱包地址归组、不随账号切换。
        链上目前只有产权转移（transferName）一种机制——本页任何「买入」描述都不涉及链上撮合或支付。
      </p>

      {portfolio.page.status === 'loading' && acquired.length === 0 ? (
        <div className="loading-row">
          <Spinner /> 加载持有名称…
        </div>
      ) : acquired.length === 0 ? (
        <section className="card">
          <div className="empty">
            <ShoppingBag />
            <div>没有买来的资产</div>
          </div>
        </section>
      ) : (
        <>
          {holdOnlyCount > 0 ? (
            <Note tone="warn">
              <b>{holdOnlyCount} 项资产处于「仅持有」状态：</b>
              semantic owner 未设置时，按继承规则控制权仍在父名称 owner 手里（PRD 5.3）。
              正确做法是在转移交易中一并设置 semantic owner；事后补设需要现任 effective
              owner（即原父名称 owner）配合执行。
            </Note>
          ) : null}
          <section className="card">
            {acquired.map((entry) => {
              const holdOnly = isHoldOnly(entry)
              return (
                <div key={entry.name}>
                  <NameRow entry={entry} holdOnly={holdOnly} />
                  {holdOnly ? (
                    <div
                      style={{
                        margin: '0 0 8px',
                        padding: '6px 10px',
                        fontSize: 11.5,
                        color: 'var(--text-faint)',
                        display: 'flex',
                        alignItems: 'center',
                        gap: 8,
                        flexWrap: 'wrap',
                      }}
                    >
                      控制权仍在父名称 owner；要完全接管需由对方执行 setNameOwner。
                      <Link
                        to={`/name/${encodeURIComponent(entry.name)}?tab=owner`}
                        className="btn btn--ghost btn--sm"
                      >
                        查看 Owner 关系 <ArrowRight />
                      </Link>
                    </div>
                  ) : null}
                </div>
              )
            })}
          </section>
        </>
      )}

      <Note tone="info">
        <Info style={{ width: 13, height: 13 }} />
        分组按名称结构推导，不追溯取得方式；买来的<b>顶级名称</b>本身就是账号，会进入顶部账号切换器。
        「我买过的使用权」（公开购买收据）是未来预留能力，当前链上没有对应机制（PRD 16.4）。
        <span style={{ marginLeft: 6 }}>
          <Pill tone="muted">使用权收据 · 未实现</Pill>
        </span>
      </Note>
    </div>
  )
}
