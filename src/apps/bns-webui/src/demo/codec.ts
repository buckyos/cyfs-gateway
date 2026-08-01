/**
 * 演示 CalldataCodec：不做真实 ABI 编码。
 *
 * encode 把 WriteIntent 序列化成 JSON 再转 hex —— 假链（demo world）解开它
 * 就知道该应用哪种投影变化。生产实现应替换为 viem/ethers 适配器：
 * `encodeFunctionData({ abi: parseAbi(BNS_ABI_SOURCE), functionName, args: toAbiArgs(intent) })`
 * （见 bns_model/write/abi.ts 与 README §3.6）。
 */

import type { CalldataCodec, WriteIntent } from '../bns_model'
import { intentToJson, utf8ToHex } from './util'

export function createDemoCodec(): CalldataCodec {
  return {
    encode(intent: WriteIntent) {
      return utf8ToHex(intentToJson(intent))
    },
    decodeError(data: string) {
      // 演示链不会产生 revert data；保留原始值以便复制（PRD 12.4）。
      return { name: 'UndecodedRevert', args: [], raw: data }
    },
  }
}
