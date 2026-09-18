# BNS WebUI Prototype

基于 `doc/BNS/BNS-WebUI-PRD.md`（v1.1，Beta2.2）的交互原型。

View 层直接接在 `src/bns_model`（MVC 的 M+C 层，见其 README）之上：
页面消费真实的 mapper / 写流程 / 交易状态机代码路径，不再使用独立的演示数据文件。

## Run

```bash
pnpm install
pnpm run dev        # http://localhost:5178/，默认直连 https://bns.buckyos.ai
pnpm run dev:demo   # http://localhost:5179/，显式启动浏览器内演示模式
pnpm run dev:live   # http://localhost:5179/，显式读取 .env.live（同样连接 bns.buckyos.ai）
pnpm run check      # tsc
pnpm test           # bns_model 单测（243 个，离线）
pnpm run seed:live  # ⚠ 会写测试链：用临时账号在 bns.buckyos.ai 留一组名称状态供 UI 走查
```

`seed:live`（`src/bns_model/__tests__/live_write.test.ts`）同时是 `write/abi.ts` 对真实合约的
契约验证：viem 临时密钥 + 中继投递（tx.prepare → 本地签名 → tx.submit_raw，PRD 8.5.3），
gas 从 anvil 默认 0 号账户（公开测试密钥）注资。场景：注册顶级名 → 发布 zone 文档 →
注册二级名 → 转移二级名（semantic 保持 Unset，制造「仅持有」）→ 无关账号公共续期。

## 两种运行模式

| 模式 | 触发条件 | 行为 |
| --- | --- | --- |
| 真实模式（默认） | 未设置 `VITE_BNS_DEMO_MODE=true` | 默认直连 `https://bns.buckyos.ai`，并钉死 OP Mainnet chain 10 与 Proxy `0x68aD…43CC`。`VITE_BNS_SERVER_URL`、`VITE_BNS_CONTRACT_ADDRESS` 和 `VITE_BNS_CHAIN_ID` 可在部署时覆盖。真实钱包（EIP-6963）与 ABI codec（viem）适配器尚未接线，写入口按 `writeGate.reason` 显示只读原因。 |
| 演示模式（显式） | 设置 `VITE_BNS_DEMO_MODE=true`（或运行 `pnpm run dev:demo`） | 注入浏览器内假 bns-server（13 个 kRPC method + `/health` + DID Resolver，报文与 wire 层 1:1）、演示钱包与演示 calldata codec。写交易走完整两阶段生命周期：链上确认约 1.3s、投影延迟约 2.2s，刻意保留 Indexing 窗口。世界数据存于页面内存，刷新重置；演示钱包的连接授权与本地交易记录存 localStorage。 |

## 目录

```
src/
  main.tsx            模式判定与 BnsModel 组装（DEV 下暴露 window.bnsModel 便于调试）
  App.tsx             路由（PRD 7.2 一级导航 + /name/:name 详情）
  styles.css          设计系统（深色 teal 主题，<960px 抽屉导航）
  demo/               演示模式适配器：world（假链+indexer 投影）/ server（fetchImpl）
                      / wallet（WalletPort）/ codec（JSON-hex calldata）
  ui/                 shell（顶部全局区+侧栏）、account（9.3 账号/资产分组）、
                      write_dialog（通用两步写流程）、tx（三段进度）、kit、format
  pages/              10 个一级页面 + NameDetailPage（8 tab）+ detail/（tab 与写对话框）
```

## 原型覆盖（对照 PRD）

- 账号与资产心智（5.1/9.3）：账号切换器、作品分组、买来的资产、「仅持有」提示、接管提示（9.24，事件推断并标注）
- 搜索四类分流与 DID Resolver 四种回答（9.2/9.21）
- 注册（9.4 P0）：可用性检查、Released 阻断、代办注册提示、二级名称父授权说明
- 名称详情 8 tab（7.3），raw 与派生状态并列（6.4.1/12.1）
- 全部 P0/P1 写操作对话框：续期（公共维护行为）、转移、semantic owner、文档发布/撤销/支付目标、
  authority keys、controller 全量替换、alias、namespace、min IAT、release/tombstone
- 通用写流程（8.5）：预检 → 确认摘要（方法/Proxy/chainId/value=0/授权/guard/投递路径/gas）→
  钱包 → 三段进度；stale guard 拒绝自动重放；高风险输入名称二次确认（13.3）
- 交易中心两阶段状态机（9.19）：not_found 不判失败、indexer 滞后不判失败、本地恢复轮询
- 事件浏览器（9.20）：日志尾部定位、客户端过滤如实标注、内外层 event_type 差异展示
- 安全中心场景卡（9.23）与高级工具（checkpoint 只读 + 能力缺口对照表）
- 服务端能力缺口全部如实呈现（bns_model README §4），不用文案掩盖

## 设置页演示工具

- 「模拟下一笔交易被拒签」：验证 wallet_rejected 路径
- 重置演示世界（刷新页面）
