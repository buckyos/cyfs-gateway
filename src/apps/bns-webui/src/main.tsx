/**
 * 入口：组装 BnsModel 并挂载 React 应用。
 *
 * 两种运行模式：
 * - 真实模式（默认）：直连 `https://bns.buckyos.ai`，环境变量可覆盖部署参数。
 *   生产口径要求同时注入 `VITE_BNS_CONTRACT_ADDRESS` 作为比对锚点（contractTrust=pinned，
 *   PRD 8.1）；默认值已钉死当前 OP Mainnet 部署。
 *   真实模式当前未接入浏览器钱包适配器与 ABI codec，写入口会按 writeGate 显示只读原因。
 * - 演示模式（显式）：设置 `VITE_BNS_DEMO_MODE=true`，注入浏览器内假 bns-server、
 *   演示钱包与演示 codec。页面走的仍是真实 bns_model 管线，读写闭环完整可交互。
 */

import { createRoot } from 'react-dom/client'

import { App } from './App'
import { createBnsModel, type BnsModel } from './bns_model'
import { BnsModelProvider } from './bns_model/react'
import { createDemoSetup } from './demo'
import './styles.css'

const DEFAULT_BNS_SERVER_URL = 'https://bns.buckyos.ai'
const DEFAULT_BNS_CHAIN_ID = 10
const DEFAULT_BNS_CONTRACT_ADDRESS = '0x68aD9f8f551e2f9115B6b38d3D4CA02A847c43CC'

const demoMode = import.meta.env.VITE_BNS_DEMO_MODE === 'true'
const liveUrl = (import.meta.env.VITE_BNS_SERVER_URL as string | undefined) || DEFAULT_BNS_SERVER_URL
const pinnedContract =
  (import.meta.env.VITE_BNS_CONTRACT_ADDRESS as string | undefined) || DEFAULT_BNS_CONTRACT_ADDRESS
const expectedChainRaw = import.meta.env.VITE_BNS_CHAIN_ID as string | undefined

let model: BnsModel
if (demoMode) {
  const demo = createDemoSetup()
  model = createBnsModel(
    {
      serverUrl: 'http://demo.bns.local',
      contractTrust: 'server',
      // 演示的假链没有真实出块节奏，读缓存调短让写后收敛更快可见。
      readCacheTtlMs: 1_000,
    },
    demo.adapters,
  )
} else {
  model = createBnsModel({
    serverUrl: liveUrl,
    expectedChainId: expectedChainRaw ? Number(expectedChainRaw) : DEFAULT_BNS_CHAIN_ID,
    expectedContractAddress: pinnedContract,
    contractTrust: 'pinned',
  })
}

if (import.meta.env.DEV) {
  // 开发调试便利：控制台可直接观察 model 状态。
  ;(window as unknown as Record<string, unknown>).bnsModel = model
}

const root = document.getElementById('root')
if (!root) throw new Error('缺少 #root 挂载点')

createRoot(root).render(
  <BnsModelProvider model={model}>
    <App demoMode={demoMode} />
  </BnsModelProvider>,
)
