# BNS 合约字节码归因与拆分分析

> 状态：本文保留各轮归因过程和实验数据。Principal 内容寻址实验已决定回退，最终决策与
> 正式拆分约束见 [`bns-contract-bytecode-experiment-conclusions.md`](./bns-contract-bytecode-experiment-conclusions.md)。

## 1. 背景与结论

当前 `Bns` 在 Solidity `0.8.24`、`viaIR=true`、optimizer `runs=20` 下的
runtime bytecode 为 **39,819 bytes**，超过 EIP-170 的 **24,576 bytes** 上限
15,243 bytes。

现有实验已经将 name 和 document type 校验移动到外部 `BnsValidation`
library，runtime 从 41,079 bytes 降到 39,819 bytes。这个结果说明继续机械地把少量
pure 函数移到外部 library，无法解决整体超限问题，还会增加 library 链接、部署记录和
升级验证的复杂度。

主要结论是：

- 体积主体来自 BNS 业务逻辑和 Solidity 为复杂 ABI 生成的代码，不是 UUPS 框架；
- `registerName`、`applyMutations`、`transferName` 是跨 name、authority、document、
  policy 和 event log 的原子编排入口；
- `DocumentState`、`DocumentUpdate[]`、`AuthorityKeyUpdate[]`、
  `ControllerRule[]`、`ResolveResult` 等动态嵌套结构会产生大量 ABI 编解码代码；
- 单纯移走 read API 或单纯拆一个 document 合约都不足以解决问题；
- 如果内部存储形状优化不能带来显著收益，后续应采用共享 proxy 状态的业务 facet，
  而不是继续扩展外部算法 library。

## 2. 归因方法与限制

分析使用当前 Hardhat build-info 中的 deployed bytecode、source map 和 optimized IR，
并在内存中生成“保留或删除一组 external API”的编译变体。所有变体保持相同编译器、
optimizer、viaIR 和 EVM version。

source map 总体归因如下：

| 来源 | Runtime 大小 |
| --- | ---: |
| BNS 源码及映射到合约级的生成代码 | 35,110 bytes |
| 编译器生成、无法映射的代码 | 4,005 bytes |
| OpenZeppelin UUPS、Ownable 等 | 约 704 bytes |
| 合计 | 39,819 bytes |

viaIR 会内联函数、合并公共代码，并把一部分 ABI coder 映射到整个 contract 的源码范围，
因此不能把 source map 中某一行的字节数理解为该行独占的真实成本。下文的消融编译结果
比逐行归因更适合用于决定模块边界。

## 3. 功能消融结果

从完整合约删除某组 API 后的结果如下。各组共享内部 helper，节省值不可直接相加。

| 从完整合约移除 | 剩余 runtime | 节省 |
| --- | ---: | ---: |
| 名称生命周期整组 | 30,632 | 9,187 |
| `registerName + applyMutations + transferName` | 31,195 | 8,624 |
| 文档相关接口 | 32,880 | 6,939 |
| 全部 read API | 34,359 | 5,460 |
| alias/payment | 35,679 | 4,140 |
| checkpoint | 38,552 | 1,267 |
| authority 对外接口 | 38,883 | 936 |

主要体积来源依次是：

1. 跨域原子编排和复杂 calldata；
2. 文档版本存储、动态字段复制和 document state hash；
3. 大型 view 返回结构的 ABI 编码；
4. owner graph、authority key 和 controller policy 鉴权；
5. 统一 event log root 和各类业务事件。

public/private 常量不是主要问题。public 常量会生成很小的 getter，private 常量通常被
直接折叠进使用位置；把常量单独放进外部合约通常得不偿失。

## 4. 候选模块尺寸

下表通过仅保留对应 external API 得到。实验变体仍继承 UUPS 并保留当前 storage 声明，
因此对真正的 facet 来说是偏保守的估算。

| 候选功能切片 | Runtime | 距 EIP-170 上限 |
| --- | ---: | ---: |
| `registerName` | 18,232 | 6,344 |
| `applyMutations` | 14,189 | 10,387 |
| `registerName + applyMutations` | 22,993 | 1,583 |
| `transferName + applyMutations` | 20,003 | 4,573 |
| 常规 name 操作 | 9,956 | 14,620 |
| document mutation/policy | 14,820 | 9,756 |
| authority 模块 | 8,544 | 16,032 |
| alias/payment 模块 | 11,498 | 13,078 |
| resolver/read API | 10,898 | 13,678 |
| checkpoint 模块 | 4,615 | 19,961 |

完整的名称生命周期切片为 26,595 bytes，已经超过上限；完整 document 切片为
24,194 bytes，只剩 382 bytes。因此不能只拆成一个 Name 合约和一个 Document 合约。

单独保留 `transferName` 时，solc 0.8.24 viaIR 会在复杂 `DocumentUpdate[]` 路径触发
Yul stack-too-deep；与 `applyMutations` 同时保留时能够编译。后续拆分时应把
`transferName` 的文档更新和事件提交拆成更小的内部步骤，并把这个编译器行为纳入测试。

## 5. 推荐的长期架构

当前 BNS 的关键语义依赖一个 canonical address 和一份原子状态：

- 鉴权直接使用 `msg.sender`；
- document hash 和 event log root 使用 `address(this)` 做 domain separation；
- `globalEventSeq/currentLogRoot` 是全局单调序列；
- register、transfer、applyMutations 必须在同一交易中原子完成；
- Indexer 当前按单一合约地址监听事件。

因此，优先方案不是多个各自持有状态的独立 UUPS proxy，而是保留一个 ERC-1967/UUPS
入口，在 UUPS Router 后按 selector delegatecall 到共享 proxy storage 的业务 facet：

```text
ERC1967Proxy
  -> BnsRouter (UUPS owner、facet selector 路由)
       -> BnsRegistrationFacet
       -> BnsMutationFacet
       -> BnsNameFacet
       -> BnsDocumentFacet
       -> BnsAuthorityFacet
       -> BnsAliasPaymentFacet
       -> BnsResolverFacet

所有业务状态保存在 proxy 的固定 BnsStorage.Layout 中。
```

这个方案保留 UUPS 作为根 proxy 的升级机制，同时利用 facet 解决每个实现地址的
EIP-170 限制。它不是直接切换为标准 Diamond；facet 地址和 selector 的升级需要额外的
manifest、code hash、selector 冲突检查和存储兼容测试。

建议的初始边界是：

- Registration facet：`registerName`；
- Mutation facet：`applyMutations`、`transferName`；
- Name facet：renew、set owner、release、namespace；
- Document facet：publish、revoke、controller policy、min document IAT；
- Authority facet：authority key 生命周期；
- Alias/Payment facet：alias、payment，可合并小型 checkpoint；
- Resolver facet：全部 read API。

## 6. 存储形状替代路线

在实施 facet 前，验证了两项不改变外部 ABI 的存储实验：

1. 将 `DocumentRef` 从 `DocumentState` 的嵌套 storage struct 中拿出，使用相同 document
   key 存入平行 mapping；必要时进一步把 controller、beneficiary 或 policy 字段分组；
2. 将 `_documents[nameHash][docTypeHash][version]` 改为
   `_documents[keccak256(nameHash, docTypeHash, version)]` 形式的一级 mapping。

需要注意：内部 storage struct 的形状本身不会改变 external ABI。只要 external 函数仍然
接收 `DocumentRef`、`DocumentUpdate[]` 或返回完整 `DocumentState/ResolveResult`，对应的
ABI decoder/encoder 仍然存在。存储拆分只可能减少或增加 storage address 计算、动态字段
复制以及 materialize 代码，必须用实际 runtime bytecode 和测试结果判断。

多级 mapping 和组合键一级 mapping 都不可遍历。BNS 需要遍历的 name 和 authority key
仍必须保留 `_nameHashes`、`_authorityKeyIds` 等显式索引；组合键不会自动解决遍历问题。

### 6.1 实验结果

| 方案 | Runtime | 相对基线 |
| --- | ---: | ---: |
| 原始 nested struct + nested mapping | 39,819 | 基线 |
| `DocumentRef` 拆到平行 nested mapping | 40,082 | **增加 263** |
| 仅将三级 `_documents` 改为组合键一级 mapping | 39,759 | 减少 60 |
| 同时压平 document、current version、authority key mapping | 39,722 | 减少 97 |

`DocumentRef` 平行存储没有改变 external ABI。`resolveDocument` 和
`getDocumentVersion` 仍须返回完整 `DocumentState`，因此 decoder/encoder 没有减少，反而
新增了从 `StoredDocumentState + DocumentRef` 组装返回结构的 materialize 代码，最终体积
增加 263 bytes。更激进地把 controller、beneficiary、policy 拆成更多平行 mapping，预计
会继续增加 storage key 计算和 materialize 路径，不再保留该方案。

组合键一级 mapping 的实验使用固定宽度的 `bytes32 + bytes32 (+ uint64)` 生成 key，不存在
动态 `abi.encodePacked` 歧义。只压平最大的 document mapping 仅节省 60 bytes；把本合约中
其余 authority/current-version nested mapping 一并压平，总收益也只有 97 bytes，约占当前
runtime 的 0.24%。这不足以抵偿自定义 key 规范、状态迁移、链下调试和审计复杂度。

因此实验代码已经恢复，正式实现继续保持原来的 `DocumentState` 嵌套 `DocumentRef` 和
nested mapping。需要降低 ABI coder 时，应该改变 external API 的数据形状或拆分 selector/
facet，而不是只改变内部 storage 表示。

本轮采用的保留标准：

- external ABI 和事件语义不变；
- Solidity/Hardhat 测试全部通过；
- upgrade storage 方案明确；
- runtime 有足够显著的下降，而不是用更高 gas 和更复杂代码换取几十或几百 bytes；
- 若组合键 mapping 收益很低或为负，保持现有 nested mapping。

## 7. 复杂 ABI 清单

当前 ABI 共有 **26 个函数**直接使用 `tuple`、`tuple[]` 或返回复杂 tuple，涉及
**18 种 struct**。其中只有 `MutationGuard` 和 `OwnerPolicyUpdate` 是完全静态的；其余
16 种都直接或间接包含 `string`、`bytes`、动态数组或动态 Principal。

### 7.1 Struct 依赖

| Struct | 动态来源 | 主要使用位置 |
| --- | --- | --- |
| `Principal` | `bytes value` | 几乎所有 owner/controller 输入和返回值 |
| `CallAuthority` | 嵌套 `Principal actor` | 13 个 mutation API |
| `MutationGuard` | 无，静态 tuple | 13 个 mutation API |
| `AuthorityKey` | `bytes keyData` | authority 更新和查询 |
| `AuthorityKeyUpdate` | 嵌套 `AuthorityKey`，且作为数组元素 | register/apply/update authority |
| `AuthoritySetState` | `string name` | `getAuthoritySet` |
| `DocumentRef` | `string uri`、`bytes inlineDocument` | publish、batch、document 查询 |
| `DocumentUpdate` | string、DocumentRef、两个 Principal，且作为数组元素 | register/apply/transfer |
| `DocumentState` | 两个 string、DocumentRef、两个 Principal | document 查询、ResolveResult |
| `ControllerRule` | Principal、string，且作为数组元素 | register/set controller policy |
| `RegisterOptions` | Principal | register |
| `OwnerPolicyUpdate` | 无，静态 tuple | applyMutations |
| `NameState` | string、两个 Principal | queryNameState、ResolveResult |
| `OwnerResolution` | Principal | resolveOwner、ResolveResult |
| `ResolveResult` | 嵌套 NameState、DocumentState、OwnerResolution、Principal 和 string | resolveDocument |
| `AliasState` | 两个 string | getAlias |
| `PurchaseContext` | 两个 string、Principal | getPurchaseContext |
| `LogCheckpoint` | Principal | checkpoint 输入/输出 |

`Principal` 是传播最广的基础动态类型。它使 `CallAuthority` 成为动态二级 tuple，并进一步
进入 release、revoke、namespace 等本来只需要少量静态参数的接口。`DocumentUpdate[]`
则是单个元素最复杂的输入：每个元素包含 `string + DocumentRef(string+bytes) + 2 个
Principal(bytes) + 多个 policy hash`。

### 7.2 写接口

| 优先级 | ABI | 复杂输入 |
| --- | --- | --- |
| 极高 | `registerName` | RegisterOptions、AuthorityKeyUpdate[]、Principal、ControllerRule[]、DocumentUpdate[]、CallAuthority、MutationGuard |
| 极高 | `applyMutations` | AuthorityKeyUpdate[]、DocumentUpdate[]、OwnerPolicyUpdate、CallAuthority、MutationGuard |
| 极高 | `transferName` | Principal、DocumentUpdate[]、CallAuthority、MutationGuard |
| 极高 | `publishDocument` | DocumentRef、两个 Principal、CallAuthority、MutationGuard |
| 高 | `setControllerPolicy` | ControllerRule[]、CallAuthority、MutationGuard |
| 高 | `updateAuthorityKeys` | AuthorityKeyUpdate[]、CallAuthority、MutationGuard |
| 中 | `setNameOwner` | Principal、CallAuthority、MutationGuard |
| 中 | `setPaymentTarget` | Principal、CallAuthority、MutationGuard |
| 中 | `publishLogCheckpoint` | Principal 输入并返回 LogCheckpoint |
| 低但覆盖面广 | `releaseName`、`revokeDocument`、`setDidAlias`、`setMinDocumentIat`、`setNamespacePolicy` | 复杂性主要由公共 CallAuthority 带入；MutationGuard 本身是静态的 |

### 7.3 读接口

| 优先级 | ABI | 复杂返回值 |
| --- | --- | --- |
| 极高 | `resolveDocument` | 深度 3 的 ResolveResult，汇总 NameState、DocumentState、OwnerResolution、alias 和 proof root |
| 极高 | `getDocumentVersion` | DocumentState |
| 高 | `queryNameState` | NameState |
| 高 | `getPurchaseContext` | PurchaseContext |
| 中 | `resolveOwner` | OwnerResolution |
| 中 | `resolvePaymentTarget` | Principal + payment policy fields |
| 中 | `getAuthorityKey`、`getAuthoritySet`、`getAlias` | AuthorityKey、AuthoritySetState、AliasState |
| 低 | `latestCheckpoint` | LogCheckpoint |
| 可删除 helper | `chainAccountPrincipal`、`bnsNamePrincipal` | Principal |

删除全部 rich read API 的既有消融实验最多可直接减少 5,460 bytes。正式 BNSBackend 已经有
Indexer 投影，因此需要区分“链上合约必须提供的最小 view”和“只为客户端方便、可以由
Backend 聚合的 rich view”。

## 8. ABI 改造候选

### 8.1 第一优先：移除动态 CallAuthority.actor

当前合约不信任 `CallAuthority.actor`，最终身份必须等于 `msg.sender`。owner/controller
的预期 Principal 已经可以从 name state 或 controller rule 中得到，因此 caller 不需要再把
同一个 Principal 放进 calldata。

第一组低语义风险实验可以把：

```solidity
struct CallAuthority {
    AuthorityRole role;
    Principal actor;
    bytes32 kid;
}
```

改成静态参数：

```solidity
AuthorityRole role,
bytes32 kid
```

owner-only 接口甚至只需要 `bytes32 kid`；同时把大多数接口的 `MutationGuard` 改成单独的
`uint64 expectedNameSeq`，只有 subname registration 保留 `expectedParentNameSeq`。这个实验
不改变授权语义，却能从 13 个 mutation selector 中移除动态 Principal decoder。

### 8.2 第二优先：Principal 内容寻址 registry

不能把 `Principal.value` 本身统一截断为固定宽度：不同 kind 的值可能是 address、32-byte
标识符，也可能是较长的名称。可实验保留原始 `Principal { kind, bytes value }` 作为
registry value，而所有嵌入位置只保存一个内容寻址 hash：

```solidity
mapping(bytes32 => Principal) private _principals;
mapping(bytes32 => bool) private _knownPrincipal;

struct CallAuthority {
    AuthorityRole role;
    bytes32 actor;
    bytes32 kid;
}
```

同样将 `NameState.semanticOwner/effectiveOwner`、`DocumentState.controller/beneficiary`、
`ControllerRule.controller`、`RegisterOptions.initialSemanticOwner`、`DocumentUpdate` 中的两个
Principal、`OwnerResolution`、`ResolveResult`、`PurchaseContext` 和 `LogCheckpoint` 的 Principal
字段改为 `bytes32`。这样动态 `Principal` 不再逐层传播到 ABI；它和把 value 塞进
`bytes32` 是两种不同方案。

registry 至少需要三个职责不同的接口：

```solidity
function hashPrincipal(Principal calldata principal) external pure returns (bytes32);
function getPrincipal(bytes32 principalHash) external view returns (Principal memory);
function internPrincipal(Principal calldata principal) external returns (bytes32);
```

`pure/view` 接口都不能写 mapping，因此不能只增加一个“pure view”接口同时完成注册和查询。
业务调用只传 hash 前，合约必须已经知道对应 preimage；可使用单独的 permissionless、幂等
`internPrincipal`，或在业务入口附带一组需要原子注册的 Principal。后一种方式会把一部分动态
calldata 带回来，但仍可避免同一个 Principal 在多层 struct 中重复出现。

本轮实验采用最直接且唯一的 key 规则：
`keccak256(abi.encode(kind, value))`。不为 `Unset` 保留 `bytes32(0)`；Unset 也使用相同公式和
空 value 得到正常的非零 key。`bytes32(0)` 只是一个从未插入过的未知 key，`getPrincipal(0)`
会失败。当前 `ChainAccount` 校验同时接受 20 和 32-byte address 表示，因此两种原始 bytes 会
得到两个不同 key；这是按原始 Principal 内容寻址的预期结果，而不是在 hash 层做规范化。

首次 intern 会新增 mapping SSTORE 和动态 bytes 存储；后续业务写入只保存一个 slot。读取和
鉴权则会增加 registry SLOAD。它更适合会被多个 name/document/rule 重复引用的 Principal，
不适合每个 Principal 只出现一次的场景。本轮不增加 `PrincipalInterned` 事件；Indexer 在事件
或链上状态中看到未知 hash 时调用 `getPrincipal`，恢复后继续使用原有领域层 `Principal`。

当前合约尚未首次部署，因此本轮直接确定新的 storage layout，不处理旧 proxy 迁移。

#### 字节码原型结果

当前磁盘上的单文件 `Bns.sol` 在相同 Solidity 0.8.24、viaIR、runs=20 配置下为
**40,512 bytes**。这一基线与本文前面已拆出 `BnsValidation` 的 39,819-byte 历史实验不是
同一个源码形态，下面只做同基线横向比较：

| 原型 | Runtime | 相对 40,512-byte 基线 |
| --- | ---: | ---: |
| 嵌入处使用两字固定引用（kind + hash），不带 registry | 41,920 | +1,408 |
| 同上，但只保留最小纯校验，用于估算 ABI 改造上限 | 41,554 | +1,042 |
| 两字固定引用 + 原值 registry + hash/intern/get + 业务回查 | 45,008 | +4,496 |
| **单字 hash + 原值 registry + 完整业务回查** | **41,948** | **+1,436** |

最终单字版本已经完整实现，而不是只替换 ABI 的桩代码：所有嵌入字段、鉴权、owner graph、
document state hash、事件、Solidity 测试、Rust ABI adapter 和 Indexer 回查路径均已切换。90 个
Solidity 测试、`bns-evm`、`bns-client`、`bns-indexer` 测试和 workspace check 通过。

结果表明 viaIR 会共享不少原有动态 ABI helper；缩小 tuple 和 storage 的收益不足以抵销
`internPrincipal/getPrincipal/hashPrincipal`、registry 写入以及各业务路径的 storage 回查，最终
runtime 反而增加 **1,436 bytes（3.54%）**。因此该方案已经证明在语义上可行，但**不能用于
解决 EIP-170，单纯以减小字节码为目标时应回退**。如果 Principal 内容寻址对 Backend API、
去重存储或长期协议标识仍有独立价值，可以保留；否则 facet/selector 拆分和缩小 rich read
surface 仍是部署架构的主线。

当前 `AuthorityKey.keyData` 的认证实现最终也只接受 20/32-byte EVM 地址并与
`msg.sender` 比较。如果 V1 不需要在链上直接支持非 EVM 公钥，可以把它改为
`address signer`，使 AuthorityKey 和 AuthorityKeyUpdate[] 变成固定宽度。

### 8.3 第三优先：缩小链上 read surface

建议把 `resolveDocument` 的聚合语义移到 BNSBackend/Indexer。链上只保留面向其它合约的
最小查询，例如：

- name core：status、asset owner、owner ref、seq、expireAt；
- current document meta：version、status、contentHash、documentStateHash；
- authority auth：active key signer、purposes、validity；
- payment view：beneficiary ref、payment target、policy hashes。

不要在单次链上返回中重复 `name`、`docType`、NameState、DocumentState、OwnerResolution
和 alias。调用方已经提供 name/docType，Backend 也可以从事件投影组装完整 ResolveResult。

### 8.4 第四优先：拆掉通用 DocumentUpdate[]

`DocumentUpdate[]` 同时服务 register、transfer 和 applyMutations，导致每个入口都携带完整
document/payment/controller policy 能力。可考虑：

- 把普通 publish、owner recovery、transfer-with-documents 分成专用请求结构；
- 将 owner key rotation + owner document + min IAT 固化为专用原子入口；
- inline document 和 URI document 使用不同入口，使每个入口只包含一种动态 payload。

仅把 tuple 字段平铺成相同的 `string/bytes` 参数通常不会显著减少 bytecode；把 struct 改成
`bytes payload` 后再使用 `abi.decode`，编译器仍会生成相似 decoder。真正有效的方向是减少
动态字段、改成固定宽度 ID，或者减少单个 selector 支持的通用能力。

## 9. 建议实验顺序

1. ABI-A：删除 `CallAuthority.actor`，把 guard 拆成必要的静态参数；
2. ABI-B：删除两个 Principal helper，并将 rich read API 替换成最小 projection；
3. ABI-C：实验单字 Principal hash registry 和 `AuthorityKey.signer`；
4. ABI-D：将 register/apply/transfer 中的通用 DocumentUpdate[] 改为专用原子入口；
5. 每一步分别记录 runtime、initcode、ABI diff、89 个 Solidity 测试和 Rust ABI 绑定影响。
