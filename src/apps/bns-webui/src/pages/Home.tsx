import {
  ArrowRight,
  BookOpen,
  Check,
  Clock3,
  FilePlus2,
  Fingerprint,
  Layers3,
  Radio,
  Search,
  ShieldCheck,
  WalletCards,
} from 'lucide-react'
import { useNavigate } from 'react-router-dom'

import {
  Button,
  CopyValue,
  GlobalSearch,
  SectionHeading,
  StageIcon,
  StatusDot,
  Tag,
} from '../components'
import {
  events,
  names,
  proxyAddress,
  shortAddress,
  transactions,
  walletAddress,
} from '../data'
import { useAppState } from '../state'

export function HomePage() {
  const navigate = useNavigate()
  const { walletConnected, openWallet, openAction } = useAppState()

  return (
    <div className="page page--home">
      <section className="home-hero reveal">
        <div className="home-hero__copy">
          <span className="eyebrow">Bucky Name System · Beta2.2</span>
          <h1>
            一个名字，
            <br />
            <em>抵达你的世界。</em>
          </h1>
          <p>
            搜索、注册和管理去中心化名称。每一次写入都由你的钱包直接确认，每一项状态都从
            BNS 查询投影读取。
          </p>
          <GlobalSearch large />
          <div className="search-suggestions">
            <span>试试</span>
            {['alice', 'device.alice', 'did:bns:studio'].map((value) => (
              <button
                key={value}
                type="button"
                onClick={() =>
                  navigate(`/name/${value.replace(/^did:bns:/, '')}`)
                }
              >
                {value}
              </button>
            ))}
          </div>
        </div>

        <div className="registry-map" aria-label="BNS 读写拓扑示意图">
          <div className="registry-map__grid" />
          <span className="map-coordinate map-coordinate--a">47° 23′ N</span>
          <span className="map-coordinate map-coordinate--b">REGISTRY / 01</span>
          <div className="map-node map-node--wallet">
            <WalletCards size={17} />
            <span>钱包</span>
            <small>签名</small>
          </div>
          <div className="map-node map-node--proxy">
            <span className="map-node__orb">B</span>
            <span>BNS Proxy</span>
            <small>链上事实</small>
          </div>
          <div className="map-node map-node--indexer">
            <Layers3 size={17} />
            <span>Indexer</span>
            <small>查询投影</small>
          </div>
          <svg viewBox="0 0 460 300" aria-hidden="true">
            <path className="map-path map-path--write" d="M88 218 C155 218 156 115 230 115" />
            <path className="map-path map-path--read" d="M247 125 C290 176 324 197 390 196" />
            <circle className="map-pulse map-pulse--one" cx="145" cy="188" r="4" />
            <circle className="map-pulse map-pulse--two" cx="318" cy="177" r="4" />
          </svg>
          <div className="map-legend">
            <span><i className="legend-line legend-line--write" />写：钱包直达合约</span>
            <span><i className="legend-line legend-line--read" />读：Server 投影</span>
          </div>
        </div>
      </section>

      <section className="service-ledger reveal reveal--2">
        <div className="service-ledger__label">
          <Radio size={17} />
          <span>实时服务</span>
        </div>
        <div className="service-ledger__item">
          <span>BNS Server</span>
          <strong><StatusDot tone="success" pulse />Ready</strong>
        </div>
        <div className="service-ledger__item">
          <span>Chain ID</span>
          <strong>11155420</strong>
        </div>
        <div className="service-ledger__item service-ledger__item--proxy">
          <span>Canonical Proxy</span>
          <CopyValue value={proxyAddress} compact />
        </div>
        <div className="service-ledger__item">
          <span>Indexer</span>
          <strong className="warning-text"><StatusDot tone="warning" />~1 block</strong>
        </div>
      </section>

      <div className="home-columns">
        <section className="home-primary reveal reveal--3">
          <SectionHeading
            eyebrow="Your registry"
            title={walletConnected ? '我持有的名称' : '把你的名称带回家'}
            description={
              walletConnected
                ? '按当前钱包的 asset_owner 查询；不代表全部可管理名称。'
                : '连接钱包后查看持有名称、未完成交易和权限预检。'
            }
            action={
              walletConnected ? (
                <Button tone="ghost" size="sm" onClick={() => navigate('/names')}>
                  查看全部
                  <ArrowRight size={15} />
                </Button>
              ) : undefined
            }
          />

          {walletConnected ? (
            <div className="name-ledger">
              {names.map((name, index) => (
                <button
                  className="name-ledger__row"
                  key={name.name}
                  type="button"
                  onClick={() => navigate(`/name/${name.name}`)}
                >
                  <span className="name-index">
                    {String(index + 1).padStart(2, '0')}
                  </span>
                  <div className="name-identity">
                    <strong>{name.name}</strong>
                    <small>did:bns:{name.name}</small>
                  </div>
                  <Tag tone="success">Active</Tag>
                  <div className="name-expiry">
                    <span>有效期</span>
                    <strong>{name.derivedStatus.replace('有效 · ', '')}</strong>
                  </div>
                  <span className="row-arrow"><ArrowRight size={16} /></span>
                </button>
              ))}
            </div>
          ) : (
            <div className="connect-prompt">
              <div className="connect-prompt__visual">
                <span className="wallet-ring wallet-ring--one" />
                <span className="wallet-ring wallet-ring--two" />
                <WalletCards size={27} />
              </div>
              <div>
                <h3>连接钱包，继续管理</h3>
                <p>
                  BNS 不托管私钥。只有在你提交写操作时，钱包才会请求确认。
                </p>
                <Button tone="primary" icon={WalletCards} onClick={openWallet}>
                  选择钱包
                </Button>
              </div>
            </div>
          )}
        </section>

        <aside className="home-side reveal reveal--4">
          <SectionHeading
            eyebrow="Quick access"
            title="常用操作"
          />
          <div className="quick-actions">
            <button type="button" onClick={() => navigate('/register')}>
              <span className="quick-action__icon quick-action__icon--coral">
                <Fingerprint size={20} />
              </span>
              <span>
                <strong>注册名称</strong>
                <small>创建新的顶级或二级名称</small>
              </span>
              <ArrowRight size={16} />
            </button>
            <button
              type="button"
              onClick={() => openAction({ kind: 'publish', target: 'alice' })}
            >
              <span className="quick-action__icon quick-action__icon--green">
                <FilePlus2 size={20} />
              </span>
              <span>
                <strong>发布文档</strong>
                <small>Inline 或 URI，自动计算 Hash</small>
              </span>
              <ArrowRight size={16} />
            </button>
            <button type="button" onClick={() => navigate('/search?mode=did')}>
              <span className="quick-action__icon quick-action__icon--ink">
                <Search size={20} />
              </span>
              <span>
                <strong>DID Resolver</strong>
                <small>查看解析结果和原始 JSON</small>
              </span>
              <ArrowRight size={16} />
            </button>
          </div>
        </aside>
      </div>

      <div className="home-columns home-columns--bottom">
        <section className="transaction-snapshot reveal reveal--4">
          <SectionHeading
            eyebrow="Transaction flow"
            title="交易不是一个瞬间"
            description="链上成功后，仍需等待 Indexer 将事件投影为可查询状态。"
            action={
              <Button tone="ghost" size="sm" onClick={() => navigate('/transactions')}>
                交易中心
                <ArrowRight size={15} />
              </Button>
            }
          />
          <button
            className="featured-transaction"
            type="button"
            onClick={() =>
              openAction({ kind: 'transaction', transaction: transactions[0] })
            }
          >
            <div className="featured-transaction__top">
              <div>
                <strong>发布 zone 文档</strong>
                <span>alice · {shortAddress(transactions[0].hash)}</span>
              </div>
              <Tag tone="warning">正在索引</Tag>
            </div>
            <div className="tx-route">
              <div className="tx-route__step is-done">
                <StageIcon state="done" />
                <span>钱包确认</span>
              </div>
              <div className="tx-route__line is-done" />
              <div className="tx-route__step is-done">
                <StageIcon state="done" />
                <span>链上成功</span>
              </div>
              <div className="tx-route__line is-active" />
              <div className="tx-route__step is-active">
                <StageIcon state="active" />
                <span>等待投影</span>
              </div>
            </div>
            <span className="featured-transaction__meta">
              <Clock3 size={14} />
              区块 #18,492,120 · 已等待 18 秒
            </span>
          </button>
        </section>

        <section className="activity-snapshot reveal reveal--5">
          <SectionHeading
            eyebrow="Public activity"
            title="最新事件"
            action={
              <Button tone="ghost" size="sm" onClick={() => navigate('/events')}>
                浏览全部
              </Button>
            }
          />
          <div className="activity-list">
            {events.slice(0, 4).map((event) => (
              <button
                className="activity-row"
                key={event.seq}
                type="button"
                onClick={() => navigate(`/name/${event.name}`)}
              >
                <span className="activity-row__marker" />
                <div>
                  <strong>{event.name}</strong>
                  <small>{event.detail}</small>
                </div>
                <span>{event.observedAt}</span>
              </button>
            ))}
          </div>
        </section>
      </div>

      <footer className="protocol-footer">
        <div>
          <ShieldCheck size={18} />
          <span>所有写操作目标均为 Canonical BNS Proxy</span>
        </div>
        <span>Read projection · bns-server</span>
        <span>Protocol · Beta2.2</span>
      </footer>
    </div>
  )
}
