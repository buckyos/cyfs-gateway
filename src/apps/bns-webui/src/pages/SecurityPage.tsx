/**
 * 安全中心（PRD 9.23）：既有高危操作的场景化引导壳。
 *
 * 不新增任何合约操作；每张卡片先讲场景与后果，再进入名称详情页的具体流程。
 * 二次确认、guard、before/after 展示与直接入口完全一致，不因入口不同而减省。
 */

import { DoorOpen, History, ShieldAlert, Skull } from 'lucide-react'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'

import { useSession } from '../bns_model/react'
import { useAccounts } from '../ui/account'
import { Modal, Note } from '../ui/kit'

type Scene = 'revoke_iat' | 'tombstone' | 'reclaim'

const SCENES: {
  id: Scene
  icon: typeof History
  color: string
  bg: string
  title: string
  question: string
  body: string
  action: string
  targetTab: string
}[] = [
  {
    id: 'revoke_iat',
    icon: History,
    color: 'var(--warn)',
    bg: 'var(--warn-dim)',
    title: '设备丢失 / 私钥疑似泄露',
    question: '还想继续用这个名称，但要让旧签发全部失效？',
    body:
      '体系内大量二级名称（如设备名 laptop.alice）由 owner 私钥离线签发、默认不上链。' +
      '设备丢失后你说不出泄露私钥签过哪些文档，但说得出大概什么时候丢的——' +
      '所以吊销以「签发时间（IAT）」为阈值：早于该时间的链下签发一律失效，' +
      '之后用当前私钥重新签发仍需要的文档即可恢复使用。',
    action: '吊销历史签发',
    targetTab: 'danger',
  },
  {
    id: 'tombstone',
    icon: Skull,
    color: 'var(--danger)',
    bg: 'var(--danger-dim)',
    title: '名称被盗用，要彻底止损',
    question: '接受包括自己在内的所有人永远不能再用它？',
    body:
      '名称被盗用并产生大量不良行为后，彻底禁用它往往是对信用负责的选择——' +
      '代价是包括 owner 自己在内，谁都不能再使用它。公司等主体不再存续时，' +
      '也可以把一级名称 ban 掉，宣告它成为 dead name。这是与信用绑定的一次性决定，必须谨慎。',
    action: '永久禁用（Tombstone）',
    targetTab: 'danger',
  },
  {
    id: 'reclaim',
    icon: DoorOpen,
    color: 'var(--accent)',
    bg: 'var(--accent-dim)',
    title: '想收回代办授权',
    question: '已经有自己的 gas，改为自主管理？',
    body:
      '服务商代办注册时会写入以服务商为 principal 的 controller 规则（请求秘钥）。' +
      '你始终是最大权限方：可以随时单方面收回，也可以换成另一家服务商。' +
      '收回是「全量替换」语义——若还有其他授权，需要一并重新填写。',
    action: '接管（收回请求秘钥）',
    targetTab: 'controller',
  },
]

export function SecurityPage() {
  const session = useSession()
  const { accounts, works, acquired, currentAccount } = useAccounts()
  const navigate = useNavigate()
  const [pickerScene, setPickerScene] = useState<Scene | null>(null)

  const allMine = [...accounts, ...works, ...acquired]
  const scene = SCENES.find((item) => item.id === pickerScene) ?? null

  const goTo = (name: string, tab: string) => {
    setPickerScene(null)
    navigate(`/name/${encodeURIComponent(name)}?tab=${tab}`)
  }

  return (
    <div>
      <h1 className="page-title">
        <ShieldAlert style={{ width: 20, height: 20, color: 'var(--accent)' }} /> 安全中心
      </h1>
      <p className="page-sub">
        合约入口本身很简单，难的是「什么情况下该做什么」。先看场景与后果，再进入具体流程；
        所有操作仍是独立、显式确认的交易，这里没有任何「一键处理」。
      </p>

      <div className="grid grid--3">
        {SCENES.map((item) => {
          const Icon = item.icon
          return (
            <div key={item.id} className="scene-card">
              <div className="scene-card__icon" style={{ background: item.bg, color: item.color }}>
                <Icon />
              </div>
              <h3>{item.title}</h3>
              <p style={{ fontWeight: 600, color: 'var(--text)' }}>{item.question}</p>
              <p>{item.body}</p>
              <div className="scene-card__foot">
                <button
                  type="button"
                  className="btn"
                  style={{ width: '100%' }}
                  onClick={() => setPickerScene(item.id)}
                  disabled={!session.wallet.connected}
                >
                  {item.action}
                </button>
              </div>
            </div>
          )
        })}
      </div>

      {!session.wallet.connected ? (
        <Note tone="info">连接钱包后可从这里进入对应名称的操作流程。</Note>
      ) : null}

      <Note tone="warn">
        进入具体流程后，二次确认、guard 校验与 before/after 展示与「名称详情 → 危险操作」
        入口完全一致，不因从安全中心进入而减省（PRD 9.23）。
      </Note>

      {scene ? (
        <Modal title={`${scene.action} · 选择名称`} onClose={() => setPickerScene(null)}>
          {allMine.length === 0 ? (
            <div className="empty">当前钱包名下没有名称</div>
          ) : (
            <>
              <p style={{ fontSize: 12.5, color: 'var(--text-dim)', marginTop: 0 }}>
                {scene.id === 'revoke_iat'
                  ? '选择签发这些文档的 owner 名称（通常是你的账号，即一级名称）：'
                  : scene.id === 'reclaim'
                    ? '选择要收回代办授权的名称（通常是你的账号）：'
                    : '选择要永久禁用的名称：'}
              </p>
              {(scene.id === 'tombstone' ? allMine : accounts.length > 0 ? accounts : allMine).map((entry) => (
                <button
                  key={entry.name}
                  type="button"
                  className="btn"
                  style={{ width: '100%', justifyContent: 'flex-start', marginBottom: 8 }}
                  onClick={() => goTo(entry.name, scene.targetTab)}
                >
                  <span className="mono">{entry.name}</span>
                  {entry.name === currentAccount ? (
                    <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-faint)' }}>当前账号</span>
                  ) : null}
                </button>
              ))}
            </>
          )}
        </Modal>
      ) : null}
    </div>
  )
}
