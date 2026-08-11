# bns_model — BNS WebUI 前端数据层设计

按 MVC 组织的前端模块，统一收拢 BNS WebUI 所有的数据读写接口。

- **M（Model）**：可观察的领域状态 + 领域规则（`models/`、`types/`）
- **C（Controller）**：用例编排，View 唯一可以调用的入口（`controllers/`）
- **V（View）**：`src/pages/*`、`src/components.tsx` 等 React 组件，**不在本模块内**

接口口径来源：
- `doc/BNS/BNS-API.md`（kRPC 方法与数据结构）
- `doc/BNS/BNS-WebUI-PRD.md`（读写边界、交易状态机、能力缺口）
- `src/components/bns-server/src/lib.rs`、`src/components/bns-client/src/{rpc,model}.rs`
- `src/apps/bns/src/{IBns,BnsTypes}.sol`（写方法与 custom error）

---

## 1. 分层

```
View (React)
  │  只读 Model store（useSyncExternalStore），调用 Controller 方法
  ▼
Controller     session · registry · name · tx · events
  │  编排用例，把结果写回 Model
  ▼
Model          SessionModel · NameModel · PortfolioModel · TxModel · EventsModel
  │  读走 ReadRepository，写走 WriteFlow
  ▼
Service        BnsServerApi(kRPC) · DidResolverService · ReadRepository · mapper
  │
Ports          WalletPort · CalldataCodec · StoragePort（外部注入，模块本身零第三方依赖）
```

严格的单向依赖：View → Controller → Model → Service → Port。
反向只通过 Store 订阅通知，没有回调穿透。

### 目录

| 路径 | 职责 |
| --- | --- |
| `config.ts` | 端点、轮询节奏、部署期望配置 |
| `types/wire.ts` | 与 bns-server JSON **1:1** 的线上类型（snake_case、number、number[]） |
| `types/domain.ts` | 前端领域模型（camelCase、bigint、Uint8Array、派生字段） |
| `types/errors.ts` | `BnsError` 与四类失败的统一表达 |
| `infra/krpc.ts` | kRPC 传输 + BNS 信封解码 |
| `infra/numeric.ts` | u64 安全层 |
| `infra/codec.ts` | 名称/doc_type 校验、address/bytes32/label、inline SHA-256 |
| `infra/observable.ts` | `Store<T>`、`AsyncState<T>`、请求去重 |
| `services/bns_server_api.ts` | 13 个 kRPC method + `/health` 的 1:1 封装 |
| `services/did_resolver.ts` | `GET /1.0/identifiers/{did}` |
| `services/mapper.ts` | wire → domain，含状态派生 |
| `services/read_repository.ts` | 缓存、去重、缺失态翻译、服务端能力补齐 |
| `ports.ts` | 钱包 / ABI 编码 / 存储适配器接口 |
| `write/intents.ts` | 15 个写方法的领域意图 |
| `write/abi.ts` | 聚合 IBns ABI + Intent → ABI 位置参数 |
| `write/authority.ts` | `CallAuthority`、`MutationGuard`、授权预检 |
| `write/write_flow.ts` | 预检 → guard 重读 → calldata → 签名 → 投递 → 收敛判定 |
| `write/delivery.ts` | 两条投递路径（直连 / 服务端中继）及其前提与硬约束 |
| `models/*` | 五个可观察 Model |
| `controllers/*` | 五个 Controller |
| `react.tsx` | Provider + hooks（View 层唯一绑定点） |

---

## 2. 读写边界

| 行为 | 本模块的实现 | 禁止 |
| --- | --- | --- |
| 查询名称/owner/文档/authority/事件 | `ReadRepository` → `BnsServerApi` → `/kapi/bns` | 直接调合约 view |
| 提交写交易 | `WriteFlow.submit` → `TxDelivery`（默认直连钱包） | 默认路径下走 `tx.submit_raw` |
| 查询交易状态 | `tx.query_state` 轮询 | 只看钱包弹窗 |
| 判断“操作完成” | 交易成功 **且** 投影收敛 | 看到 receipt 就认为完成 |
| ABI 编码目标 | `system.info.contract_address`（与构建期锚点比对） | 只信构建期硬编码 / Facet 地址 |

`tx.submit_raw` 与 `tx.prepare` 被隔离在 `BnsServerApi.advanced` 命名空间，
业务代码只能通过 `ServerRelayDelivery` 这一个受控入口触达它们，
而该投递模式必须在配置里显式选择（见 §3.35）。直接在业务流程里引用 `advanced.*` 是设计错误。

---

## 3. 几个关键决定

### 3.1 wire 与 domain 分离

`types/wire.ts` 只描述服务端事实，不做任何加工；`types/domain.ts` 才是页面用的模型。
所有转换集中在 `services/mapper.ts`，它同时是 **u64 安全层的唯一入口**。

u64 在 JSON 里是 number，超过 `2^53-1` 会在 `JSON.parse` 阶段静默丢精度。
`u64FromWire` 的契约是**宁可报错也不静默舍入**：不是安全整数就抛
`BnsError(kind='numeric')`。已知限制：精度丢失发生在 parse 内部，事后只能发现、
无法还原，所以这属于“异常数据告警”，不是完整防线。

### 3.2 raw 状态与派生状态并列

合约不会因为时间流逝把 `status` 改成 `Expired`。`deriveNameStatus` 计算
`timeExpired` / `inGrace` / `secondsToExpire`，与 `raw` 一起放在 `DerivedNameStatus` 里，
**永远不覆盖 raw**。文档同理：`DocumentView` 同时给出 `rawStatus`（来自 `document.resolve`）
和 `derivedStatus`（与 DID Resolver 同口径，见 `deriveDocumentStatus`）。

### 3.3 四类失败必须区分

```
HTTP 非 2xx / 网络中断        → BnsError.kind = 'transport'
kRPC error（含 UnknownMethod）→ 'transport'（服务端仍返回 HTTP 200）
信封 ok:false                 → 'registry'，带业务 code
信封 ok:true, result:null     → 不是错误，callOptional 返回 null
```

其中 `NAME_NOT_FOUND` / `DOCUMENT_NOT_FOUND` 是**业务缺失态**，
`ReadRepository` 会把它们翻成 `null` / `status:'missing'`，其他错误照常抛。

### 3.35 交易投递：两条路径

写 BNS 需要三样东西：**calldata**、**签名**、**能把 raw tx 送进链节点的通道**。
前两样没有分歧（calldata 本模块生成，签名只能钱包做），分歧只在第三样。
完整推理见 [`write/delivery.ts`](write/delivery.ts) 顶部注释，这里是结论。

**模式 A `wallet_direct`（默认，唯一接线的产品路径）**

```
WebUI --calldata--> Wallet --eth_sendTransaction--> 钱包自己的 RPC --> BNS Proxy
```

WebUI 只需要知道 `chainId` + Proxy 地址，连节点地址都不用知道。
前提是**钱包为该 chainId 配了可用 RPC** —— 公链永远成立。

**模式 B `server_relay`（需显式开启）**

```
WebUI --tx.prepare--> bns-server          （拿 nonce / gasLimit / EIP-1559 fee）
WebUI --eth_signTransaction--> Wallet     （只签名，拿回 raw tx）
WebUI --tx.submit_raw--> bns-server --eth_sendRawTransaction--> 链节点
```

它解决的正是**测试链/私链没有浏览器可达 RPC**：anvil 常常只跑在开发机或 VM 内网，
bns-server 连得上、浏览器连不上。`tx.prepare` 的存在就是为此 —— 它替代了
「客户端自己查 nonce/gas/fee」，所以中继模式下 WebUI 不需要任何链 RPC。

**但它不是通用回退**，有一条硬约束：

> 中继需要一份**已签名的 raw tx**，拿到它只能靠 `eth_signTransaction`。
> 主流注入式钱包（MetaMask 等）**不实现这个方法**，它们只给 `eth_sendTransaction`。

所以中继只在这些场景可用：支持 `eth_signTransaction` 的钱包（Frame、部分硬件签名器、
部分 WalletConnect 对端）、浏览器之外的外部签名方（bns-client 的
`BnsEvmControllerClient` 走的就是这条，见 BNS-API.md §4.2）、e2e 工具。

因此模块的选择是：**默认直连；中继必须在配置里显式选，且先探测钱包能力**，
能力不足时在进入写表单阶段就给出可解释的拒绝 + 替代方案，而不是等弹钱包才失败。

```ts
createBnsModel({ serverUrl, deliveryMode: 'server_relay' })
// readiness.reason: 当前钱包不支持 eth_signTransaction……
// readiness.hint:   改用直连：让钱包 wallet_addEthereumChain 添加这条链……
```

**测试链其实还有第三个选项**，而且优先级更高：如果链节点**浏览器可达**
（网络可达 + CORS 允许），让钱包 `wallet_addEthereumChain` 加上这条链，
继续走直连（PRD 8.3）。只有节点仅 bns-server 可达时，中继才是唯一解。

优先级：**直连 > 加链后直连 > 中继**。

投递路径会写进 `PreparedWrite.summary.deliveryMode` 和 `TxRecord.deliveryMode`：
中继模式下广播方不是钱包、gas/fee 也不由钱包决定，用户有权在确认页看到这一点。

### 3.36 合约地址的信任来源

合约地址决定用户的签名打给谁，是安全关键参数，**不应该由终端用户在界面上填**。
模块用 `contractTrust` 表达这件事：

| 值 | 行为 | 用途 |
| --- | --- | --- |
| `pinned`（默认） | 必须配 `expectedContractAddress`，与 `system.info.contract_address` 逐字比对；缺失 → `contract_unpinned` 只读，不一致 → `config_mismatch` 只读 | 生产 |
| `server` | 完全信任 `system.info` | 本地联调 |

`pinned` **不等于**「只用写死的地址」——运行时地址仍然来自 `system.info`
（PRD 8.1 明确禁止仅依赖构建期常量），钉死的值只作为比对锚点。
这样即使 bns-server 被替换或劫持，也无法把用户的签名引到别的合约上。

```ts
createBnsModel({
  serverUrl: import.meta.env.VITE_BNS_SERVER_URL ?? 'https://bns.buckyos.ai',
  expectedContractAddress:
    import.meta.env.VITE_BNS_CONTRACT_ADDRESS ?? '0x68aD9f8f551e2f9115B6b38d3D4CA02A847c43CC',
  expectedChainId: Number(import.meta.env.VITE_BNS_CHAIN_ID ?? 10),
})
```

### 3.4 写操作强制两步

```ts
const intent   = nameCtrl.buildRenew('alice', 180n * 86400n)
const prepared = await nameCtrl.prepare(intent)   // 重读 guard、编码、estimateGas、算收敛期望
// → 这里展示 prepared.summary
//   （方法名 / Proxy / chainId / value=0 / authority / guard / deliveryMode）
//   以及 prepared.delivery.readiness —— 投递路径不可用时在这一步就该拦住
const record   = await nameCtrl.submit(prepared)  // 签名 + 投递 + 登记交易中心
```

`prepare` 里 guard 是**现读**的，因为用户在钱包确认框里停留的时间足够让 `name_seq` 过期。
如果 `estimateGas` 解出 `StaleNameSeq` / `StaleParentNameSeq` / `StaleDocumentVersion`，
`prepared.staleGuard = true`，`submit` 会直接拒绝——不自动重放，必须重读后由用户重新确认。

### 3.5 交易是两阶段的

```
awaiting_wallet → submitted → pending → chain_reverted        (失败，终态)
                                      ↘ indexing → completed  (成功，终态)
                                                 ↘ indexer_lagging
                            → not_found（不是失败）
```

`TxController` 按 PRD 节奏轮询（前 30s 每 2s，30s–5min 每 5s，之后 15s 并允许停止）。
`succeeded` 之后还要跑 `ConvergenceExpectation`——每个 intent 都带一个从提交前状态
算出的期望（`name_seq ≥ n+1`、`document version ≥ v+1`、`expire_at > 旧值` 等），
只有它满足才是 `completed`。超过 5 分钟仍未收敛显示“链上已成功，Indexer 尚未同步”，
**不显示失败**。

`not_found` 同理不是失败：可能是节点没见过、mempool 丢弃、同 nonce 替换或历史裁剪。

### 3.6 ABI 编码是端口，参数摆放是 Model

模块本身不依赖 viem/ethers。`write/abi.ts` 提供：
- `BNS_ABI_STRUCTS` / `BNS_WRITE_FUNCTIONS` / `BNS_ERRORS`：human-readable ABI，
  `viem` 的 `parseAbi` 可直接消费；
- `toAbiArgs(intent)`：把领域意图转成位置参数（含 enum 序号、Principal 的 bytes 形态、
  `storageType` 标签 → bytes32 等易错转换）。

于是适配器只剩一行：

```ts
const codec: CalldataCodec = {
  encode: (intent) => encodeFunctionData({
    abi: parseAbi(BNS_ABI_SOURCE),
    functionName: WRITE_INTENT_META[intent.kind].method,
    args: toAbiArgs(intent),
  }),
  decodeError: (data) => { /* decodeErrorResult */ },
}
model.setCalldataCodec(codec)
```

`Principal` 有两种形态，转换点只有 `toAbiPrincipal` 一处：
读投影里是字符串（chain account 是 `0x…`，bns name 是名称），
ABI 里是 bytes（20 字节裸地址 / 名称的 UTF-8 bytes）。

---

## 4. 服务端能力缺口（模块如实表达，不用文案掩盖）

| 缺口 | 本模块的处理 |
| --- | --- |
| 没有「列出一个名称的全部 doc type」 | `NameModel.docTypes` = 内置 6 个 + 本地历史 + 用户输入 + 事件发现，每项带 `source`，UI 必须提示不完整 |
| 没有「列出全部 authority key」 | 只能按已知 kid 探测（`AuthorityKeyProbe`）；UI 应对比 `authority_set.active_key_count` 与探测条数 |
| 没有 controller rule 明细查询 | `ControllerPolicySnapshot.rules` 恒为 `null`，只给事件里的 `policy_hash` + 说明 |
| 没有 `getAlias` | alias 从 `document.resolve` 或 `did_alias_set` 事件推断，带 `source` 标注 |
| `events.list` 无过滤、无「最新 N 条」 | `latestEventSeq()` 用指数探测 + 二分定位日志尾部（O(log n) 次请求）；按名称过滤是客户端回扫，`ActivityScan.scanExhausted` 如实透传 |
| 没有同步高度 / 落后区块数 | 无法证明“已追到链 tip”，只能靠收敛期望判断单笔交易 |
| `name.query_by_addr` 只按 asset_owner | `PortfolioModel.scopeNote` 固定文案，不允许被改写成“我能管理的名称” |

合约侧的语义缺口（`initialPaymentTarget` 不生效、`transferable` 不影响 `transferName`、
`allow_delegated_subnames` 不参与鉴权、Released 重注册不清理旧状态等）在
`write/intents.ts` 和 `registry_controller.ts` 的注释与默认值里逐条落实。

---

## 5. 接入方式

```tsx
// main.tsx
import { createBnsModel } from './bns_model'
import { BnsModelProvider } from './bns_model/react'

const model = createBnsModel({
  serverUrl: import.meta.env.VITE_BNS_SERVER_URL ?? 'https://bns.buckyos.ai',
  expectedChainId: Number(import.meta.env.VITE_BNS_CHAIN_ID ?? 10),
  expectedContractAddress:
    import.meta.env.VITE_BNS_CONTRACT_ADDRESS ?? '0x68aD9f8f551e2f9115B6b38d3D4CA02A847c43CC',
})

createRoot(root).render(
  <BnsModelProvider model={model}>
    <App />
  </BnsModelProvider>,
)
```

```tsx
// 页面里
const session = useSession()
const aggregate = useNameDetail('alice')     // 自动 load + 钱包变化后重算授权
const { controllers } = useBnsModel()

if (!session.writeGate.allowed) return <ReadOnlyNotice reason={session.writeGate.reason} />
```

`writeGate` 是**唯一**的写闸门，把「server 不可达 / ready=false / 合约未钉死 /
部署配置不一致 / 未连钱包 / 链不一致」全部阻断条件收敛成一个布尔 + 原因，
视图不需要自己拼判断。

钱包与 ABI 适配器可以后接：

```ts
model.setWallet(createEip6963Wallet())
model.setCalldataCodec(createViemCodec())
```

在两者注入之前，所有读页面完全可用，写入口按 `writeGate.reason` 显示为只读——
这正好对应当前原型没有钱包依赖的状态。

---

## 6. 测试

```bash
pnpm test           # 243 个单测，离线，全部基于线上抓回的真实报文
pnpm run test:live  # 22 个契约测试，直连 https://bns.buckyos.ai，只读
```

### 单测（`__tests__/*.test.ts`）

| 文件 | 覆盖 |
| --- | --- |
| `codec.test.ts` | 名称/doc_type 规则、bytes32 标签、地址、`content_hash = sha256(inline)` |
| `numeric.test.ts` | u64 安全层：拒绝 `2^53`、拒绝非整数、回写检查 |
| `krpc.test.ts` | 四类失败分支、seq 自增、session token、超时 |
| `bns_server_api.test.ts` | 13 个 method 名与 params 形状、参数校验必须 reject 而非同步抛 |
| `mapper.test.ts` | wire→domain、名称/文档状态派生、事件联合类型、AuthorityKeyView |
| `did_resolver.test.ts` | 200 / 404-missing / 404-notApplicable / 501 / 5xx、DID 的 URL 编码 |
| `abi.test.ts` | 15 个写方法的位置参数逐个对齐 IBns.sol 签名、Principal 两种形态 |
| `read_repository.test.ts` | 缺失态翻译、缓存/去重、日志尾部二分、活动回扫、文档历史链 |
| `write_flow.test.ts` | 写闸门七种阻断（含合约未钉死）、授权预检、guard 重读、提交前的账户/链校验 |
| `delivery.test.ts` | 两条投递路径、钱包能力探测、中继的 prepare→sign→submit 三步与链/合约二次核对 |
| `tx_center.test.ts` | 轮询节奏、两阶段状态机、收敛判定、bigint 本地恢复 |

fixture 是从线上 bns-server 抓回来的真实响应（`__tests__/fixtures/live_responses.json`），
**不要手工编辑**——手写报文会掩盖服务端的真实行为。刷新：

```bash
pnpm run capture:fixtures
```

### 契约测试（`live.test.ts`）

默认跳过，只在 `BNS_LIVE_URL` 存在时运行。它验证的是**服务端契约有没有变**
（方法名、信封形状、错误码、可空语义、DID Resolver 四种回答），不重复单测的业务逻辑。
全部只读，不含任何写操作。

### 测试实际抓到的问题

1. **DID Resolver 全线 400** —— `didResolverEndpoint` 用 `encodeURIComponent(did)`
   把冒号编成 `%3A`，而 bns-server 对**未解码**的 path 做 `strip_prefix` +
   `starts_with("did:")`。冒号在 path segment 里是合法 pchar，不该编码。
   单测发现不了（fixture 是 curl 抓的、路径正确），只有打真服务器才暴露。
2. **活动记录回扫重复计数** —— 最后一页窗口小于 `pageSize` 时按整页请求，
   会读回上一页扫过的 seq。修成按闭区间 `[from, cursor]` 算 limit 并过滤。
3. **501 被吞进 5xx** —— `parseDidResolution` 先判 `>= 500`，历史查询的能力缺口
   被误判成解析器故障。501 必须先判。
4. **参数校验同步抛出** —— `BnsServerApi` 的方法签名是 `Promise<T>` 但本地校验
   同步 throw，调用方的 `.catch()` / `Promise.all` 接不住。全部改成 `async`。

### 还没有测试的部分

Controller 层（`controllers/*`）目前只被 write_flow / tx_center 间接覆盖，
`NameController` 的意图构造器和 `RegistryController` 的注册路径推导还缺直接用例；
`react.tsx` 的 hooks 没有测试（需要 jsdom + @testing-library/react）。

---

## 7. 状态

- `tsc -b` 通过，模块零第三方运行时依赖（vitest 只是 devDependency）。
- 原型页面（`src/pages/*`、`src/data.ts`）尚未接入，仍在使用演示数据。
