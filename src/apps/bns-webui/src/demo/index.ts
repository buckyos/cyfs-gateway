/**
 * 演示模式组装入口。
 *
 * 未配置 `VITE_BNS_SERVER_URL` 时，main.tsx 使用这里的适配器组建 BnsModel：
 * 页面消费的仍是真实 bns_model 管线，只是三个端口被换成浏览器内实现。
 */

import type { BnsModelAdapters } from '../bns_model'
import { createDemoCodec } from './codec'
import { createDemoFetch } from './server'
import { DemoWallet } from './wallet'
import { DEMO_ALICE_KID, DemoWorld } from './world'

export {
  DEMO_ALICE_KID,
  DEMO_CHAIN_ID,
  DEMO_CONTRACT_ADDRESS,
  DEMO_WALLET_ADDRESS,
  DemoWorld,
} from './world'
export { requestRejectNext, rejectNextPending, DemoWallet } from './wallet'

export interface DemoSetup {
  world: DemoWorld
  wallet: DemoWallet
  adapters: BnsModelAdapters
}

export function createDemoSetup(storageKeyPrefix = 'bns.webui'): DemoSetup {
  const world = new DemoWorld()
  const wallet = new DemoWallet(world)
  seedKnownKids(storageKeyPrefix)
  return {
    world,
    wallet,
    adapters: {
      wallet,
      calldata: createDemoCodec(),
      fetchImpl: createDemoFetch(world),
    },
  }
}

/**
 * 预置 alice 的已知 kid：bns-server 没有「列出全部 authority key」接口（PRD 9.12），
 * NameModel 只能探测本地记录过的 kid。演示模式里把 alice 的 key 当作
 * 「用户此前在本机验证过」的本地历史，让 BNS-name-owner 授权路径可演示。
 */
function seedKnownKids(prefix: string): void {
  try {
    const key = `${prefix}.kids.alice`
    const existing = window.localStorage.getItem(key)
    const kids: string[] = existing ? (JSON.parse(existing) as string[]) : []
    if (!kids.includes(DEMO_ALICE_KID)) {
      kids.push(DEMO_ALICE_KID)
      window.localStorage.setItem(key, JSON.stringify(kids))
    }
  } catch {
    // 存储不可用时跳过；只影响演示的授权路径展示。
  }
}
