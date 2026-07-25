# BNS devtest Host 构建、VM 部署改造 TODO

> 状态：待实施  
> 记录日期：2026-07-25  
> 临时措施：当前 `sn` VM 已扩容到约 3 GiB；建议配置 2 CPU / 4 GiB 留出余量，
> 先保证当前测试继续推进。

## 1. 背景

web3-gateway devtest 的预期边界是：

- host 负责源码依赖安装、编译、校验和 staging 构造；
- VM 只接收构建产物，启动 Anvil，部署预编译合约并运行服务；
- VM 不应充当 Rust、Solidity 或前端构建机。

当前实现只对 Rust 二进制和配置满足这个边界。BNS 迁移到 Hardhat/UUPS/facet
部署后，host staging 仅复制以下内容：

- `package.json`、`package-lock.json`；
- `hardhat.config.ts`、`tsconfig.json`；
- `src/`、`hardhat-scripts/`。

staging 没有包含 Solidity 编译产物。VM 中的 `init_anvil.py` 因而会执行：

```text
npm ci
npm run compile
npm run deploy:local
```

这使 VM 同时承担 npm 依赖解析、Solidity via-IR 编译、facet 校验、bindings
生成和链上部署。

## 2. 已确认的故障

`sn` VM 使用 `ubuntu_basic` 模板，当前规格为 1 CPU / 1 GiB，且没有 swap。
执行 fresh install/start 时，内核两次将 `npm ci` 作为 OOM victim 杀死：

```text
Out of memory: Killed process ... (npm ci)
anon-rss: approximately 500 MiB
```

因为进程被内核直接发送 SIGKILL，`init_anvil.py` 最终只得到非零退出码，
`stdout`/`stderr` 可能均为空。故障发生时：

1. `init_anvil.py --fresh` 已经启动 Anvil；
2. `npm ci` 被 OOM killer 终止；
3. BNS proxy/facets 尚未部署；
4. `bns-deployment.json` 和 `dv-env.json` 尚未生成；
5. devtest 仍继续执行 systemd start 和健康检查；
6. `start.py` 报告 BNS contract 未部署，健康检查等待 90 秒后失败。

因此这里有两个独立问题：

- **P0：构建职责错误。** BNS 依赖安装和 Solidity 编译发生在资源受限的 VM。
- **P1：错误传播错误。** `init_anvil` 失败后 devtest 没有 fail-fast，继续执行后续命令。

这次故障与 facet 业务逻辑是否正确无关；它是 Hardhat/facet 部署迁移引入的构建和部署
边界回退。

## 3. 临时措施

在正式改造完成前，开发者可提高现有 Multipass VM 规格。当前约 3 GiB 已能解除
这次 `npm ci` 阻塞；以下建议配置使用 4 GiB 留出编译峰值余量：

```bash
multipass stop sn
multipass set local.sn.memory=4G
multipass set local.sn.cpus=2
multipass start sn
```

扩容后必须重新执行完整 fresh 初始化，不能复用 OOM 后留下的部分 `node_modules`
或半初始化 Anvil 状态：

```bash
multipass exec sn -- bash -lc \
  'cd /opt/web3-gateway && sudo /usr/local/bin/uv run ./init_anvil.py --fresh --install-foundry --configure-sn-bns-proxy'
```

临时扩容只用于解除当前测试阻塞，不视为本 TODO 的最终修复。

## 4. 目标架构

### 4.1 Host 构建阶段

host 的 `web3_gateway_staging.py build-all` 应完成：

1. 安装锁定版本的 BNS Node.js 依赖；
2. 使用锁定的 solc/Hardhat 配置编译所有 BNS contracts；
3. 执行 facet selector、重复 selector、runtime bytecode size 检查；
4. 执行 UUPS storage layout/upgrade compatibility 校验；
5. 生成 Rust ABI bindings，并验证仓库中的 committed bindings 未漂移；
6. 生成可独立部署的 BNS artifact bundle；
7. 将 bundle 与 Rust 二进制、配置和 seed 一并写入 staging；
8. 对 bundle 生成内容清单和哈希，staging 校验失败时禁止 push。

artifact bundle 至少应包含：

- BNS router implementation bytecode；
- ERC-1967 proxy 创建所需 bytecode 和 initializer calldata 描述；
- 每个 facet 的 creation/runtime bytecode；
- ABI；
- function selector → facet 映射；
- solc 版本、optimizer、via-IR、EVM version；
- storage layout/upgrade validation 元数据；
- artifact、selector manifest 和源码版本哈希。

### 4.2 VM 部署阶段

VM 中的 `init_anvil.py` 应只负责：

1. fresh/resume Anvil 生命周期；
2. 校验 artifact bundle 完整性和版本；
3. 使用 devtest deployer key 广播预编译部署交易；
4. 部署 router implementation、ERC-1967 proxy 和各 facets；
5. 调用 `addFacets`；
6. 逐项验证 proxy implementation、owner、selector 路由和链上 code hash；
7. 原子写入 `bns-deployment.json`、`dv-env.json` 和相关运行参数。

最终 VM 部署路径不得：

- 执行 `npm ci`；
- 执行 Hardhat build 或 solc；
- 生成或修改 ABI/bindings；
- 依赖 `node_modules`；
- 从 npm registry 下载构建依赖。

## 5. 部署器方案

需要在实施前确定预编译 artifact 的 VM 侧部署器。

### 方案 A：Rust 轻量部署器（推荐）

扩展现有 BNS EVM 基础设施或 `bns_dv`，增加只消费 artifact bundle 的
`deploy-local` 子命令：

- 支持 contract creation transaction；
- 支持代理 constructor/initializer 编码；
- 支持 facets 批量配置和链上验证；
- 复用现有 signer、nonce、receipt wait 和 JSON-RPC 实现；
- 不引入 Node.js/Hardhat 运行时依赖。

优点是跨平台、错误类型清晰，并与 VM 已部署的 Rust 二进制统一。需要补齐 creation
transaction、proxy 初始化和部署 manifest 解析能力。

### 方案 B：Host Hardhat 通过受控通道部署

host 完成编译后，通过 SSH tunnel 或专用受控 RPC 通道连接 VM Anvil，并执行
`deploy:local`；随后把 deployment metadata 写入 VM。

该方案改动较小，但会扩大 Anvil RPC 的编排和安全边界，并使 host/VM 状态协调更复杂。
不得简单将 Anvil 无保护地绑定到局域网 `0.0.0.0`。

### 不推荐：复制 `node_modules`

不应把 host 的 `node_modules` 直接复制到 VM：

- host 与 VM 可能是不同 OS/CPU/libc；
- Hardhat、EDR、esbuild、Solidity analyzer 含平台相关包；
- staging 体积和供应链面显著增加；
- VM 仍保留 Node/Hardhat 运行时耦合。

## 6. Fail-fast 与失败清理

- [ ] `init_anvil` 返回非零时，devtest 必须停止，不得执行 systemd start。
- [ ] systemd start 失败时，不得继续进入完整健康检查等待。
- [ ] 优先在 buckyos-devkit 中修复 `Workspace.run(..., check=False)` 的退出码传播。
- [ ] 若短期不能修改 devkit，将 fresh init、start、health gate 收敛到一个明确
  `set -e` 的 VM 侧包装脚本，并让 app command 只调用该脚本一次。
- [ ] `init_anvil.py` 的子命令错误应记录 return code；进程被 signal 杀死时应输出
  signal 名称/编号，并提示检查 OOM 日志。
- [ ] 若本轮 fresh 流程新启动了 Anvil，但部署失败，应停止该 Anvil 或写入明确的
  incomplete marker，禁止后续流程将其误判为可 resume 环境。
- [ ] 仅在完整部署和链上验证成功后原子替换 `bns-deployment.json`、`dv-env.json`。
- [ ] `start.py` 继续保留“目标地址必须有 code”的启动门禁。

## 7. Staging 修改

- [ ] 将 `copy_bns_source()` 改为构建并复制 artifact bundle；源码可作为调试材料保留，
  但不得成为 VM 启动依赖。
- [ ] `validate_complete_staging()` 校验 bundle 必需文件、manifest schema 和哈希。
- [ ] staging 中禁止出现 `node_modules/`、Hardhat cache 和临时 build-info。
- [ ] 将最终需要保留的精简 ABI/storage metadata 显式列入 allowlist。
- [ ] `build`/update 仅改 Rust 二进制时，不重复编译 BNS；BNS 输入有变化时
  `build-all` 必须重建 bundle。
- [ ] 为 bundle 增加确定性检查：相同源码、lockfile 和编译配置应产生相同内容哈希。

## 8. 测试计划

### 8.1 Host 构建

- [ ] staging 单元测试确认 BNS 编译和校验发生在 host。
- [ ] 修改任一 facet 源码后，bundle hash 和对应 bytecode hash 必须变化。
- [ ] selector 冲突、facet 超过 EIP-170、storage layout 不兼容时 build-all 失败。
- [ ] committed Rust bindings 与生成结果不一致时 build-all 失败。
- [ ] staging 不包含 `node_modules`、Hardhat cache 或 VM 运行态文件。

### 8.2 VM 部署

- [ ] 从没有 Node.js/npm 的干净 VM 成功部署 BNS。
- [ ] 在 1 GiB、无 swap 的 VM 上完成 artifact 校验和部署，证明 VM 不再承担编译。
- [ ] fresh 路径部署全部 facets，逐 selector 验证成功。
- [ ] resume 路径复用相同 deployment，不重复部署、不重置 indexer。
- [ ] artifact hash 损坏、selector manifest 不一致或任一部署交易回滚时立即失败。
- [ ] 部署失败后不存在可被 `start.py` 接受的部分 deployment metadata。

### 8.3 完整 devtest

- [ ] `web3-gateway.start` 中 init 失败时不启动 systemd unit。
- [ ] fresh install → BNS seed 4 笔交易 → SN/DNS/HTTPS 健康检查完整通过。
- [ ] 在 host 断网但 npm cache/构建产物已就绪的情况下，VM deploy 不访问公网。
- [ ] VM 中 `command -v node` 和 `command -v npm` 失败时，部署与服务启动仍成功。
- [ ] OOM、交易回滚、端口占用等失败场景均返回可靠的非零退出码。

## 9. 完成标准

- [ ] BNS Solidity 编译、facet 校验和 bindings 生成全部发生在 host。
- [ ] VM 部署输入是经过哈希校验的预编译 artifact bundle。
- [ ] `init_anvil.py` 不再执行或查找 npm/Node/Hardhat/solc。
- [ ] devtest app command 在首个失败步骤立即停止。
- [ ] 默认 1 GiB VM 可以完成部署和完整 web3-gateway 启动。
- [ ] fresh/resume、seed 幂等、BNS resolver 和 SN smoke tests 全部通过。
- [ ] 开发文档明确区分 host build、VM deploy 与 VM runtime 三个阶段。
