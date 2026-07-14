# BNS 合约字节码优化实验结论

## 1. 结论摘要

当前单体 `Bns` 无法通过局部调整常量、pure 函数、内部 storage struct 或 nested mapping，
下降到 EIP-170 的 24,576-byte runtime 上限以内。已验证方案的收益最多只有几十到一千余
bytes，距离可部署状态仍有约 15 KB 以上差距；部分方案还会增加字节码和运行时 gas。

因此停止继续进行局部 ABI/storage 微调，回退 Principal 内容寻址实验，正式转向：

- 保留一个 ERC-1967/UUPS proxy 和 canonical BNS address；
- 由轻量 Router 按 selector `delegatecall` 到多个业务子合约（facet）；
- 所有 facet 通过固定 storage layout 共享 proxy 状态；
- 保留跨 name、authority、document、event log 的单交易原子性；
- 使用 Hardhat 完成编译、测试、UUPS 校验、部署和尺寸检查；
- 仅在 Hardhat 不能完成必要分析时使用本机已有的 Foundry；
- 如需安装其他第三方工具，先停止实施并说明用途和安装方式。

详细字节码归因、功能消融和候选模块尺寸见
[`bns-contract-bytecode-splitting-analysis.md`](./bns-contract-bytecode-splitting-analysis.md)。

## 2. 根因判断

EVM 本身没有 Solidity `struct`、`string` 或 `bytes` 类型，也没有直接处理这些类型的
指令。复杂度来自 Solidity ABI coder：对嵌套动态 tuple/array 生成 calldata offset、长度、
边界校验、内存分配、storage/memory/calldata 拷贝以及返回值编码代码。

`viaIR` optimizer 会内联函数并合并公共 helper，因此不能按源码行数或单个 struct 直接
估算尺寸。一次 optimized IR 检查已经确认：

- `hashPrincipal((uint8,bytes))` 和 `internPrincipal((uint8,bytes))` 共用同一个
  `abi_decode_struct_Principal_calldata`；
- 只要 external ABI 仍接收 `Principal`，该 decoder 就不会消失；
- `getPrincipal` 的动态返回编码还会与合约中其他 `string/bytes` encoder 共享；
- 从大型 struct 中移除嵌套 Principal 只能减少部分调用点和 offset 处理，不能按出现次数
  成比例删除 coder。

需要区分两件事：仅在源码中声明或在 storage 中保存 `Principal` 不会自动产生 ABI coder；
是 external/public ABI 对该动态类型的输入和输出使 coder 保留在 runtime 中。

## 3. 已验证实验

所有数字均为 Solidity 0.8.24、`viaIR=true`、optimizer `runs=20` 下的 runtime bytecode。
不同历史源码形态不能直接混用基线，表中分别标明。

### 3.1 算法 library

历史单体 runtime 为 41,079 bytes。将 name/document-type 纯校验移到外部
`BnsValidation` library 后为 39,819 bytes，减少 1,260 bytes，但仍超限 15,243 bytes。

结论：算法 library 可以取得有限减码，但不足以解决部署问题，还会引入 library 地址链接、
部署顺序、部署记录和升级验证复杂度。

### 3.2 Storage 形状

以 39,819 bytes 为基线：

| 方案 | Runtime | 相对基线 |
| --- | ---: | ---: |
| `DocumentRef` 拆到平行 mapping | 40,082 | +263 |
| 仅压平三级 document mapping | 39,759 | -60 |
| 同时压平 document/current-version/authority mapping | 39,722 | -97 |

结论：平行 struct 需要额外 materialize 代码；nested mapping 改组合键只有约 0.24% 收益。
两者都不值得增加协议 key 规范、审计和调试成本，正式实现保持原 storage 表示。

### 3.3 Principal 固定宽度引用和内容寻址 registry

以恢复为单文件后的 40,512-byte 基线横向比较：

| 方案 | Runtime | 相对基线 |
| --- | ---: | ---: |
| 两字引用（kind + hash），不带 registry | 41,920 | +1,408 |
| 两字引用，仅保留最小纯校验 | 41,554 | +1,042 |
| 两字引用 + registry + 完整回查 | 45,008 | +4,496 |
| 单字 hash + registry + 完整回查 | 41,948 | +1,436 |

单字方案使用：

```solidity
principalHash = keccak256(abi.encode(kind, value));
```

它没有为 `bytes32(0)` 保留特殊语义；鉴权通过 hash 取回已 intern 的 Principal 后继续使用
原 Principal 比较逻辑；Indexer 不依赖额外事件，而是通过 `getPrincipal` 回查。该方案已贯通
Solidity、Rust ABI/client 和 Indexer，90 个 Solidity 测试以及相关 Rust 测试通过。

结论：方案在协议语义上可行，但 registry 写入、hash/intern/get 接口、storage 回查和动态
返回编码的成本超过 ABI/storage 简化收益，runtime 增加 1,436 bytes（3.54%）。如果唯一目标
是解决 EIP-170，应回退该方案。

### 3.4 常量和 helper

- private constant 通常在使用点折叠，不是主要体积来源；
- public constant 只增加小型 getter；
- 把少量 constant 或 pure helper 移到独立合约，收益不足以改变架构结论；
- post-solc 字节码重写会影响 jump、metadata、source map、合约验证和升级安全，不作为正式
  部署方案。

## 4. 功能归因

以 39,819-byte 历史分析基线做功能消融，各组共享 helper，节省值不可相加：

| 移除功能组 | 剩余 runtime | 节省 |
| --- | ---: | ---: |
| 名称生命周期整组 | 30,632 | 9,187 |
| register/apply/transfer | 31,195 | 8,624 |
| 文档相关接口 | 32,880 | 6,939 |
| 全部 read API | 34,359 | 5,460 |
| alias/payment | 35,679 | 4,140 |
| checkpoint | 38,552 | 1,267 |
| authority 对外接口 | 38,883 | 936 |

主要来源依次为：跨域原子编排和复杂 calldata、文档动态存储和 hash、rich view 返回编码、
owner/authority/controller 鉴权、全局 event log 及业务事件。

这也说明不能只拆成一个 Name 和一个 Document 子合约：完整名称生命周期切片约 26,595
bytes，已经超限；完整 document 切片约 24,194 bytes，只剩 382 bytes，缺少安全升级余量。

## 5. 正式拆分约束

拆分必须保持以下语义：

1. 用户只面对一个 proxy/canonical BNS address；
2. `msg.sender` 在 facet 中保持原调用者，不能用普通 external call 改变鉴权语义；
3. `address(this)` 仍为 proxy，保持 document hash 和 event domain separation；
4. `globalEventSeq/currentLogRoot` 在所有功能间共享并单调更新；
5. register、transfer、applyMutations 的跨域操作仍在同一交易中原子完成；
6. Indexer 继续监听同一个 proxy 地址；
7. selector 路由更新受 UUPS owner 控制，并校验 selector 冲突、facet code、manifest 和
   storage layout；
8. 每个 facet 不只要低于 24,576 bytes，还要保留后续升级余量。

## 6. 推荐初始边界

- Router/UUPS：初始化、升级授权、facet manifest 和 fallback delegatecall；
- Registration：`registerName`；
- Atomic Mutation：`applyMutations`、`transferName`，必要时继续拆分；
- Name：renew、set owner、release、namespace；
- Document：publish、revoke、controller policy、owner IAT；
- Authority：authority key 生命周期；
- Alias/Payment：alias、payment，可容纳 checkpoint；
- Resolver：链上必须保留的 read API；长期可把 rich aggregation 迁移到 BNSBackend/Indexer。

首轮实施优先建立共享 storage 和 Router，再迁移一个低耦合功能组验证 delegatecall、事件、
鉴权、UUPS 升级和 Hardhat 测试链路；验证通过后再迁移 register/apply/transfer 等高耦合入口。

## 7. 决策记录

- 局部 struct/storage 优化：停止；
- Principal registry：回退；
- nested mapping：保持；
- UUPS 根 proxy：保持；
- 正式方向：共享 storage 的 selector router + 业务 facet；
- 默认工具链：Hardhat；Foundry 仅作补充分析；新增第三方工具必须先获得确认。

## 8. 子合约拆分实施结果

上述决策已经按原 ABI 实施。当前生产合约在相同编译配置下的 runtime 为：

| 合约 | Runtime bytes | 距 24,576 上限余量 |
| --- | ---: | ---: |
| UUPS `Bns` Router | 4,562 | 20,014 |
| Resolver | 9,882 | 14,694 |
| Registration | 17,244 | 7,332 |
| Atomic Mutation | 19,145 | 5,431 |
| Name | 9,857 | 14,719 |
| Authority | 6,670 | 17,906 |
| Document | 13,835 | 10,741 |
| Alias/Payment | 10,321 | 14,255 |

Router 继续作为唯一的 UUPS implementation，通过命名 storage slot 保存 selector 表；所有
业务 facet 继承同一 `BnsCore` storage layout。聚合 `IBns` ABI 保持原业务调用和事件形状，
Rust `bns-evm` 改为从同步后的聚合 JSON ABI 生成绑定。

Hardhat 已完成编译、97 个 Solidity 测试、28 个 selector 的完整性/冲突检查、Router 与全部
facet 的递归 storage-layout 对比，以及 OpenZeppelin UUPS implementation validation；所有生产
implementation 都低于 EIP-170 上限。Rust 聚合 ABI 保留了原有 enum 类型，Indexer 会忽略同一
proxy 地址产生的 facet 管理事件。`bns-evm`、`bns-client`、`bns-indexer` 共 100 个非忽略
Rust 测试和全 workspace `cargo check` 通过；6 个依赖旧单体 `forge create` 的 Anvil e2e 仍为
ignore，需随非阻塞 DV 环境另行迁移。本轮不需要安装额外第三方工具。
