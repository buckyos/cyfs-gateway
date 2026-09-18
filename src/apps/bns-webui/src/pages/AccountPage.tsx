/**
 * 我的账号（PRD 9.3）：当前账号视图 —— 账号信息与名下作品。
 *
 * 数据只来自 name.query_by_addr（按 asset_owner），前端按 5.1 规则分组；
 * 口径说明必须如实展示：该查询列不出通过 authority / controller / 继承可管理的名称。
 */

import { ArrowRight, Briefcase, Crown, DoorOpen, Info, Plus, RotateCcw } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'

import { isSettled } from '../bns_model'
import { useBnsModel, useNameAggregate, useSession, useTransactions } from '../bns_model/react'
import { useAccounts } from '../ui/account'
import { derivedStatusLabel, formatRelative, formatTime, isZeroHex } from '../ui/format'
import { Note, Pill, Spinner } from '../ui/kit'
import { NameRow } from '../ui/name_list'
import { RenewDialog } from './detail/dialogs'

export function AccountPage() {
  const session = useSession()
  const { portfolio, accounts, currentAccount, setCurrentAccount, works, acquired } = useAccounts()
  const model = useBnsModel()
  const navigate = useNavigate()
  const transactions = useTransactions()
  const [renewOpen, setRenewOpen] = useState(false)

  const accountAggregate = useNameAggregate(currentAccount ?? '')
  const accountEntry = accounts.find((entry) => entry.name === currentAccount) ?? null
  const accountOverview = accountEntry?.overview.data ?? null

  // 接管提示（PRD 9.24）：从事件推断是否仍存在代办授权。
  useEffect(() => {
    if (currentAccount) {
      void model.controllers.name.load(currentAccount)
      void model.controllers.name.loadActivity(currentAccount)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [model, currentAccount])

  const policyHash = accountAggregate.controllerPolicy.data?.policyHash ?? null
  const hasDelegationEvidence = policyHash !== null && !isZeroHex(policyHash)

  const pendingByName = useMemo(() => {
    const map = new Map<string, number>()
    for (const record of transactions.records) {
      if (!isSettled(record.stage) && !record.stopped) {
        map.set(record.target, (map.get(record.target) ?? 0) + 1)
      }
    }
    return map
  }, [transactions.records])

  if (!session.wallet.connected) {
    return (
      <div>
        <h1 className="page-title">我的账号</h1>
        <Note tone="info">连接钱包后，这里按「账号（一级名称）→ 名下作品」组织你的资产。</Note>
      </div>
    )
  }

  return (
    <div>
      <h1 className="page-title">
        我的账号
        {accounts.length > 1 ? (
          <span className="chips">
            {accounts.map((entry) => (
              <span
                key={entry.name}
                className={`radio-card ${entry.name === currentAccount ? 'is-active' : ''}`}
                onClick={() => setCurrentAccount(entry.name)}
              >
                <Crown style={{ width: 12, height: 12 }} /> {entry.name}
              </span>
            ))}
          </span>
        ) : null}
      </h1>
      <p className="page-sub">
        一级名称即账号。资产列表按当前钱包地址的 asset_owner 查询；
        不含通过 authority key、controller 规则或父名称继承可管理的名称——那些名称请从搜索进入。
      </p>

      {portfolio.page.status === 'loading' && portfolio.entries.length === 0 ? (
        <div className="loading-row">
          <Spinner /> 加载持有名称…
        </div>
      ) : accounts.length === 0 ? (
        <section className="card">
          <div className="empty">
            当前地址名下没有一级名称（账号）。
            {acquired.length > 0 ? ` 但持有 ${acquired.length} 项买来的资产，见「我买来的资产」。` : ''}
          </div>
          <Link to="/register" className="btn btn--primary" style={{ width: '100%' }}>
            <Plus /> 注册我的第一个账号
          </Link>
        </section>
      ) : (
        <>
          <section className="card">
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', marginBottom: 10 }}>
              <Crown style={{ width: 18, height: 18, color: 'var(--accent)' }} />
              <span className="mono" style={{ fontSize: 19, fontWeight: 700 }}>
                {currentAccount}
              </span>
              {accountOverview ? (
                <>
                  <Pill tone={derivedStatusLabel(accountOverview.derived).tone}>
                    {derivedStatusLabel(accountOverview.derived).text}
                  </Pill>
                  <span style={{ fontSize: 12, color: 'var(--text-faint)' }}>
                    到期 {formatTime(accountOverview.state.expireAt)}（{formatRelative(accountOverview.state.expireAt)}）
                  </span>
                </>
              ) : null}
              <span style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
                <button type="button" className="btn btn--sm" onClick={() => setRenewOpen(true)}>
                  <RotateCcw /> 续期
                </button>
                <button
                  type="button"
                  className="btn btn--sm"
                  onClick={() => navigate(`/name/${encodeURIComponent(currentAccount ?? '')}`)}
                >
                  账号详情 <ArrowRight />
                </button>
              </span>
            </div>

            {accountOverview && accountOverview.derived.secondsToExpire !== null &&
            accountOverview.derived.secondsToExpire < 60n * 86_400n ? (
              <Note tone="warn">
                账号有效期不足 60 天。续期是公共维护行为，任何账户都可以为它充值有效期（PRD 9.5）。
              </Note>
            ) : null}

            {hasDelegationEvidence ? (
              <Note tone="warn">
                <b>接管提示：</b>事件显示该账号可能仍存在代办（controller）授权。
                你的钱包已能自行发起交易，建议尽早通知服务商并收回代办授权，改为自主管理。
                <span style={{ display: 'block', marginTop: 6 }}>
                  <Link to={`/name/${encodeURIComponent(currentAccount ?? '')}?tab=controller`} className="btn btn--sm">
                    <DoorOpen /> 查看并收回授权
                  </Link>
                </span>
                <span style={{ display: 'block', marginTop: 4, fontSize: 11.5, color: 'var(--text-faint)' }}>
                  依据为事件中的非零 policy hash（推断，无法断言当前规则内容——服务端暂无查询接口）。
                </span>
              </Note>
            ) : null}
          </section>

          <section className="card">
            <h2 className="card__title">
              <Briefcase /> 当前账号的作品（{works.length}）
            </h2>
            <p className="card__hint">二级名称，parent 属于当前账号；随顶部账号切换过滤。</p>
            {works.length === 0 ? (
              <div className="empty">
                还没有作品。
                <div style={{ marginTop: 8 }}>
                  <Link
                    to={`/register?name=${encodeURIComponent(`.${currentAccount ?? ''}`)}`}
                    className="btn btn--sm"
                  >
                    <Plus /> 注册 *.{currentAccount}
                  </Link>
                </div>
              </div>
            ) : (
              works.map((entry) => (
                <NameRow key={entry.name} entry={entry} pendingTx={pendingByName.get(entry.name) ?? 0} />
              ))
            )}
          </section>

          {portfolio.hasMore ? (
            <button
              type="button"
              className="btn"
              style={{ width: '100%' }}
              onClick={() => void model.controllers.registry.loadMore()}
            >
              加载更多（cursor 分页）
            </button>
          ) : null}

          <Note tone="info">
            <Info style={{ width: 13, height: 13 }} /> {portfolio.scopeNote}
          </Note>
        </>
      )}

      {renewOpen && currentAccount ? (
        <RenewDialog aggregate={accountAggregate} onClose={() => setRenewOpen(false)} />
      ) : null}
    </div>
  )
}
