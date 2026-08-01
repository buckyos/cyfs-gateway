# bns_model 待办与待定设计

模块位置：`src/apps/bns-webui/src/bns_model/`，设计说明见同目录 `README.md`。

当前状态：`tsc -b` 通过；243 个单测 + 22 个线上契约测试（`pnpm test` / `pnpm run test:live`）全绿；
模块零第三方运行时依赖；**尚未接入任何页面**。

---

## A. 阻塞可用闭环（P0）

### A1. 原型页面仍在用演示数据

`src/pages/*.tsx`、`src/data.ts`、`src/state.tsx` 完全没接 bns_model，仍是硬编码的
`names` / `documents` / `transactions` / `events`。

接入顺序建议（每步都能独立跑起来）：

1. `main.tsx` 包 `BnsModelProvider`，首页服务状态条改读 `useSession()`；
2. 搜索 / 名称详情概览改读 `useNameDetail()`；
3. 我的名称改读 `usePortfolioSync()`；
4. 事件浏览器 / 交易中心；
5. 最后删 `src/data.ts`。

`src/state.tsx` 的 `AppStateProvider` 目前同时管 UI 态（抽屉、主题、toast）和交易列表，
交易那部分要迁到 `TxModel`，UI 态留在原处。

### A2. 缺 WalletPort 适配器

`ports.ts` 定义了接口，没有实现。需要：EIP-6963 多钱包发现 + EIP-1193 兼容入口 +
WalletConnect；`accountsChanged` / `chainChanged` 事件转成 `WalletAccountState`。
`capabilities()` 要如实上报 `signTransaction`（谎报会让用户走到一半才失败）。

### A3. 缺 CalldataCodec 适配器

需要引入 `viem`（当前 package.json 没有）。实现只有两个方法：

```ts
encode: (intent) => encodeFunctionData({
  abi: parseAbi(BNS_ABI_SOURCE),
  functionName: WRITE_INTENT_META[intent.kind].method,
  args: toAbiArgs(intent),
})
decodeError: (data) => decodeErrorResult({ abi: parseAbi(BNS_ABI_SOURCE), data })
```

**连带一个必须补的测试**：`write/abi.ts` 里的 human-readable ABI 目前只被「参数个数与
顺序和签名字符串一致」验证过，**没有人真正编码过一次**。签名字符串本身写错（字段顺序、
类型、struct 定义）现有测试抓不到。适配器落地后要加一组 encode → decode 往返用例，
最好再和 `src/apps/bns/out/Bns.sol/Bns.json` 里的 `methodIdentifiers` 对一遍 selector。

### A4. 中继模式下 gas 预检会误报（已知缺陷）

`write/write_flow.ts:147` 无条件调用 `wallet.estimateGas(request)`。但中继模式的前提
就是**钱包连不上这条链**，这一步必然失败，于是 `gasEstimate = null` 且
`simulationError` 被填成一条无意义的 `UnknownError`。

影响：不会构造出错误的交易（`ServerRelayDelivery` 在 deliver 时用 `tx.prepare` 的
gas，签名里的值是对的），但确认页会显示假的模拟错误。

修法：`TxDelivery` 增加 `estimate(request, context)`，直连走钱包、中继走
`tx.prepare` 的 `estimated_gas` / `gas_limit`；同时中继模式下明确标注
「无法做提交前 revert 模拟」，因为 `eth_call` 同样需要链连接。

---

## B. 测试缺口（P0/P1）

| 缺口 | 说明 |
| --- | --- |
| ABI 真编码往返 | 见 A3，当前最大的假阴性风险 |
| Controller 层 | `NameController` 的 13 个意图构造器、`RegistryController.resolveRegisterPath`（二级名称父授权推导）、`SessionController.bootstrap` 与钱包订阅、`EventsController` 都只被间接覆盖 |
| `react.tsx` hooks | 完全没测，需要 jsdom + `@testing-library/react` |
| 移动钱包往返恢复 | `TxModel.restore()` 有单测，但「跳转出去再回来」的完整链路没有 |
| 钱包换账户/换链中途打断 | `WriteFlow.submit` 的拦截有测试，但 `NameController.recomputeAuthority` 的作废时序没有 |

---

## C. 需要你拍板的设计问题

### C1. `contractTrust` 默认值

我把默认设成了 `'pinned'`：不配 `expectedContractAddress` 就一律只读。
理由是合约地址决定用户的签名打给谁，不该由终端用户填。

代价：任何没注入地址的部署（包括 dev）写操作直接被卡。
如果觉得太激进，改 `config.ts` 的 `DEFAULTS.contractTrust` 为 `'server'` 即可（一行）。

> 答：这个是页面部署的时候配置的，我们只需要方便页面在部署的时候能够很容易的配置就好了。


### C2. `deliveryMode` 该不该让用户选

现在只能在 `createBnsModel` 的部署配置里定。
另一种做法是在「高级工具/设置」页暴露开关，方便对着内网测试链联调。
倾向：**不暴露**——投递路径影响 gas/fee 的决定方，属于部署决策而非用户偏好。

> 答：这个是页面部署的时候配置的

### C3. Model 层里的中文文案

`models/session_model.ts`、`write/delivery.ts`、`write/authority.ts` 里
`writeGate.reason`、`readiness.reason/hint`、`assessment.notes` 都是硬编码中文。
Model 返回可展示文案在当前单语产品下最省事，但要做 i18n 就得改成
「错误码 + 参数」，文案挪到 View。要做的话越早越好，这些字符串已经被测试断言了。

> 答：应该支持i18n

### C4. 交易替换 / 加速 / 取消

完全没做。`tx.query_state` 的 `not_found` 有可能就是同 nonce 替换的结果，
但模块不保存 nonce、也不提供 replacement 关系。要做的话需要：
记录提交时的 nonce（直连模式钱包不给，只能事后查）、提供 speed-up/cancel 入口。

>答: 交易的高级功能主要靠钱包，bns-server只要能快速的解决把tx投递到测试链来缩短测试路径就好了

---

## D. 受服务端能力限制、只能如实呈现的部分

这些**不是 bug**，模块已经在数据结构上标注了来源与完整性，UI 必须照实展示，
不得用文案掩盖。若将来 bns-server 补了接口，这一节可以逐条消除。

| 缺口 | 模块现状 | 补齐条件 |
| --- | --- | --- |
| 无法列出一个名称的全部 doc type | `NameModel.docTypes` 每项带 `source`（builtin/本地历史/用户输入/事件发现） | server 增加 `document.list_types` |
| 无法列出全部 authority key | 只能按已知 kid 探测；`ReadRepository.discoverAuthorityKids` 是空实现（`read_repository.ts:385`），因为 `authority_keys_updated` 事件只带 seq/root，不带 kid | 事件补 kid 字段，或 server 增加列举接口 |
| 无 controller rule 明细 | `ControllerPolicySnapshot.rules` 恒为 null（`name_model.ts:40`），只给事件里的 policy_hash | server 增加 `controller.get_policy` |
| 无 `getAlias` | 从 `document.resolve` 或 `did_alias_set` 事件推断，带 `source` 标注 | server 暴露合约已有的 `getAlias` |
| `events.list` 无过滤 | 按名称的活动记录是客户端回扫，`ActivityScan.scanExhausted` 如实透传 | server 支持按 name/type 过滤 |
| 无同步高度 / 落后区块数 | 无法证明「已追到链 tip」，只能靠单笔交易的收敛期望 | server 暴露 indexer cursor |

合约侧的语义缺口（`initialPaymentTarget` 不生效、`transferable` 不影响 `transferName`、
`allow_delegated_subnames` 不参与鉴权、Released 重注册不清理旧状态、
`publishLogCheckpoint` 的 issuer 未绑定 msg.sender 等）已按 PRD 6.4 逐条落在
`write/intents.ts` 与 `controllers/registry_controller.ts` 的注释和默认值里，
不重复列。

---

## E. 工程细节（P2）

- **`InvalidMutation(bytes32 reason)` 文案映射表** 没建（PRD 12.4 要求版本化维护
  reason hash → 文案；未知 hash 只显示原始 bytes32，不猜测）。
- **`ReadRepository.cache` 与 `NameModel.store` 都是无上限 Map**，长会话浏览大量名称会
  持续增长。加 LRU 或按路由卸载即可。
- **fee 字段的 u128**：`tx.prepare` 的 `max_fee_per_gas` 在 Rust 侧是 u128，
  `mapPrepareTx` 用 u64 安全层校验，超过 2^53 会抛错而不是静默截断。
  当前链上费率远低于该值，属于「将来主网高费率时可能触发」。
- **`sessionToken` 无人设置**：`config.sessionToken` 一路传到 kRPC 的 `sys[1]`，
  但没有获取/刷新它的流程（PRD 13.4）。当前 server 也不校验。
- **`AddChainParams` 没有来源**：`SessionController.addServerChain` 要求调用方传入
  rpcUrls / nativeCurrency，但 `BnsModelConfig` 里没有这份部署配置。
- **fixture 会过期**：`__tests__/fixtures/live_responses.json` 抓自
  `https://bns.buckyos.io`（chain 31337 的 anvil）。链重置后 `pnpm run capture:fixtures`
  重抓；`live.test.ts` 依赖名称 `test-iobns-20260715-01` 存在，可用
  `BNS_LIVE_NAME` 覆盖。
