# BNS WebUI Prototype

基于 `doc/BNS/BNS-WebUI-PRD.md` 的 Beta2.2 交互原型。

## Run

```bash
pnpm install
pnpm run dev
```

Vite 默认启动在 `http://localhost:5178/`。

## Prototype scope

- 首页、统一搜索与 DID Resolver
- 我持有的名称、名称详情与 8 个管理标签
- 顶级/二级名称注册向导
- 钱包连接、网络与 Proxy 校验展示
- 续期、转移、文档发布操作抽屉
- Wallet → Chain → Indexer 双阶段交易状态
- 交易中心、事件浏览器、高级工具与设置
- Desktop、tablet、mobile 响应式布局和深浅主题

当前版本使用明确标注的演示投影数据，便于在未启动 bns-server、链节点或钱包扩展时完整浏览原型。
