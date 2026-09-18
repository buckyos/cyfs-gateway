# bns_model 待办

模块位置：`src/apps/bns-webui/src/bns_model/`，设计说明见同目录 `README.md`。

当前状态：`tsc -b` 通过；243 个单测全绿，22 个线上契约测试默认 skip（`pnpm test` /
`pnpm run test:live`）；模块零第三方运行时依赖；**尚未接入任何页面**。

建议落地顺序（每步都能独立验证）：

```
A5 部署配置注入 → A6 文案 code 化 → A1 第 1–2 步（只读接入）
                → A2 + A3（打通写闭环）→ A4 → A1 剩余步骤
```

A6 必须排在 A1 前面：等 View 照着 Model 返回的中文成品句子写完再改 code，等于把 View 写两遍。

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

交易详情页要按 C 的口径做：加速 / 取消只引导用户去钱包，页面不提供自己的入口。

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

中继只是测试路径（见 C），但这条仍要修：每次测试都看到一条假的模拟错误，会掩盖真错误。

### A5. 部署期配置注入

口径已定：`contractTrust` 与 `deliveryMode` 都是**部署配置**，不进用户界面（见 C）。
真正缺的不是默认值，而是**把这些值送进 `createBnsModel` 的通道** —— `main.tsx` 现在
根本没建 model，任何部署都会落到 `expectedContractAddress: null` +
`contractTrust: 'pinned'`，也就是 `network = 'contract_unpinned'`、写操作全禁
（`models/session_model.ts:164`、`config.ts:108`）。

要求（用户口径）：部署的时候要很容易配置 —— **改一个文件就能换部署，不用重新构建**。

方案：运行期同源配置文件 + 构建期兜底。

1. `public/bns-webui.config.json`，随 `dist/` 一起发布，部署时直接改：

```jsonc
{
  "serverUrl": "https://bns.buckyos.io",
  "expectedChainId": 31337,
  "expectedContractAddress": "0x…",   // pinned 模式必填
  "contractTrust": "pinned",           // 本地联调可显式改 "server"
  "deliveryMode": "wallet_direct",     // 测试链没有浏览器可达 RPC 时改 "server_relay"
  "chainParams": {                     // 供 wallet_addEthereumChain
    "chainName": "BNS Devnet",
    "rpcUrls": ["http://127.0.0.1:8545"],
    "nativeCurrency": { "name": "Ether", "symbol": "ETH", "decimals": 18 }
  }
}
```

2. 新增 `src/deployment_config.ts`（**放 app 层，不进 bns_model**，模块要保持零环境依赖）：
   - `fetch(new URL('bns-webui.config.json', import.meta.env.BASE_URL), { cache: 'no-store' })`；
   - 404 / 网络失败回退到构建期 `import.meta.env.VITE_BNS_*`；两者都没有才判定配置缺失；
   - 逐字段校验：`serverUrl` 是绝对 URL、`expectedContractAddress` 过 `isAddress`、
     两个枚举只收已知值。**校验失败必须停在「配置错误」屏，不许静默降级** ——
     一个拼错的 `contractTrust` 把 pinned 变成 server，等于把写操作的信任锚点丢了。
3. `main.tsx`：`await loadDeploymentConfig()` → `createBnsModel` → `BnsModelProvider`；
   加载失败渲染配置错误页，不要让用户以为是 bns-server 挂了。
4. `chainParams` 顺带补上 `SessionController.addServerChain`
   （`controllers/session_controller.ts:107`）缺的那份 `AddChainParams`。

两条禁忌：

- 这份配置**不能**从 bns-server 的 kRPC 取。pin 的全部意义是「锚点由页面发布方控制」，
  锚点和被验证方同源就没有意义了（`config.ts:70` 的注释）。
- `sessionToken` 不放进这个文件。它是任何访客都能 GET 到的静态文件。

### A6. Model 层文案改「code + 参数」（i18n）

口径已定：要支持 i18n。现在 Model / Controller 直接返回中文成品句子，共约 100 处：

| 位置 | 产出 | 条数 |
| --- | --- | --- |
| `models/session_model.ts` | `writeGate.reason` 8、`configMismatch` 3、`assertWritable` 错误 2 | 13 |
| `write/authority.ts` | `assessment.notes` 14、`describeAuthorityPath` 5 | 19 |
| `write/intents.ts` | `WRITE_INTENT_META[*].label` | 15 |
| `models/events_model.ts` | `EVENT_TYPE_LABELS` | 14 |
| `models/tx_model.ts` | `progress.headline` | 9 |
| `controllers/registry_controller.ts` | `availability.reason` / 搜索分类 message 7、校验错误 4 | 11 |
| `write/write_flow.ts` | `describeExpectation` 6、写前拦截错误 7 | 13 |
| `write/delivery.ts` | `readiness.reason/hint` 4、`describeDeliveryMode` 2 | 6 |
| `infra/numeric.ts` | `formatDuration`（天 / 小时 / 分钟 / 秒） | 4 |
| `models/name_model.ts`、`models/portfolio_model.ts` | 数据完整性说明常量 | 2 |

改法：

- 新增 `MessageRef = { code: string; params?: Record<string, string | number> }`，
  上表字段的类型由 `string` 换成 `MessageRef` / `MessageRef[]`；
  语言包 `src/i18n/zh-CN.ts`、`en.ts` 放在 View 侧，Model 不 import 语言包。
- 大部分 code 现成：`NetworkStatus`、`WriteIntentKind`、事件 type、交易 stage
  本来就是枚举，直接当 key 用，不需要新造一套。
- `BnsError.message` 降级为开发者可读的英文 fallback，展示一律走 `code` + `detail` 查表。
  前置两件事：(a) 把 3 处字面量 code 收进常量表（`models/session_model.ts:148`、
  `controllers/name_controller.ts:483` 的 `INVALID_MUTATION` 目前不在任何表里、
  `controllers/registry_controller.ts:233`）；(b) 给 `infra/codec.ts` 的校验错误补齐
  上限值 / 实际值等插值参数，现在这些数字只存在于句子里。
- `formatDuration` 改成返回 `{ value, unit }` 或换 `Intl.RelativeTimeFormat`，
  单位不在 Model 里拼。
- 现有 14 处断言中文文案的测试要改成断言 code：`codec.test.ts:67`、
  `delivery.test.ts:217`、`numeric.test.ts:68-71`、`tx_center.test.ts:87,108`、
  `write_flow.test.ts:111,167,191,246,257,261`。
- `index.html` 的 `lang="zh-CN"` 与 description 跟着语言切换。

---

## B. 测试缺口（P0/P1）

| 缺口 | 说明 |
| --- | --- |
| ABI 真编码往返 | 见 A3，当前最大的假阴性风险 |
| Controller 层 | `NameController` 的 13 个意图构造器、`RegistryController.resolveRegisterPath`（二级名称父授权推导）、`SessionController.bootstrap` 与钱包订阅、`EventsController` 都只被间接覆盖 |
| `react.tsx` hooks | 完全没测，需要 jsdom + `@testing-library/react` |
| 移动钱包往返恢复 | `TxModel.restore()` 有单测，但「跳转出去再回来」的完整链路没有 |
| 钱包换账户/换链中途打断 | `WriteFlow.submit` 的拦截有测试，但 `NameController.recomputeAuthority` 的作废时序没有 |
| 语言包完整性 | A6 落地后要有「每个 code 在每个语言包都有条目」的断言，漏一条就红 |
| 部署配置校验 | A5 的 `loadDeploymentConfig`：缺文件回退、非法 `contractTrust` 不降级、地址非法即停 |

---

## C. 已定口径（不再讨论）

| 问题 | 结论 | 落点 |
| --- | --- | --- |
| `contractTrust` 默认值 | 保持 `pinned`。这是页面部署时配的，不由终端用户填；要做的是让部署时配起来足够容易 | A5 |
| `deliveryMode` 要不要给用户选 | 不暴露。同样是页面部署时配的 | A5 |
| Model 层的中文文案 | 支持 i18n，改「code + 参数」，文案挪到 View | A6 |
| 交易替换 / 加速 / 取消 | **不做**。交易的高级功能主要靠钱包；bns-server 的中继只承担一个职责——把 tx 快速投到测试链、缩短测试路径 | 见下 |

最后一条的连带结论：

- 不记录提交时的 nonce、不维护 replacement 关系。`tx.query_state` 返回 `not_found`
  时如实说明「可能已被替换或尚未广播」，现状已经是这样（`models/tx_model.ts:193`）。
- 交易详情页不提供加速 / 取消入口，只引导用户去钱包操作。
- `server_relay` 的定位由此固定为**测试路径**，不是产品写路径；不必为它补更多产品化能力，
  但 A4 那条假模拟错误要修。

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
  reason hash → 文案；未知 hash 只显示原始 bytes32，不猜测）。落地时直接按 A6 的
  `MessageRef` 形态做，别再新增一套中文常量。
- **`ReadRepository.cache` 与 `NameModel.store` 都是无上限 Map**，长会话浏览大量名称会
  持续增长。加 LRU 或按路由卸载即可。
- **fee 字段的 u128**：`tx.prepare` 的 `max_fee_per_gas` 在 Rust 侧是 u128，
  `mapPrepareTx` 用 u64 安全层校验，超过 2^53 会抛错而不是静默截断。
  当前链上费率远低于该值，属于「将来主网高费率时可能触发」。
- **`sessionToken` 无人设置**：`config.sessionToken` 一路传到 kRPC 的 `sys[1]`，
  但没有获取/刷新它的流程（PRD 13.4）。当前 server 也不校验。注意它不能进 A5 那份
  静态配置文件。
- **fixture 会过期**：`__tests__/fixtures/live_responses.json` 抓自
  `https://bns.buckyos.io`（chain 31337 的 anvil）。链重置后 `pnpm run capture:fixtures`
  重抓；`live.test.ts` 依赖名称 `test-iobns-20260715-01` 存在，可用
  `BNS_LIVE_NAME` 覆盖。
