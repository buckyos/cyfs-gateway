# 合约修改需求(评估版):用通用原子批量接口收敛强业务 combo

**提出方:** SN / cyfs-gateway 团队
**目标合约:** `Bns.sol`
**类型:** 接口收敛(含**删除**两个强业务 combo + 新增 1 个通用原子批量接口 + 合并创建接口)
**性质:** 破坏性变更,需合约先行、依赖项一次性跟进

> 本文取代早前仅新增 `publishDocuments` 的需求(那只是这里的一个子集)。

---

## 1. 目标

不止"加一个 `publishDocuments`",而是把"原子地组合多个操作"这件事收敛成**通用原语**,
从而**删除**强业务语义的 combo 接口:

- `bootstrapName`(L631)—— register + authorityKeys + semanticOwner + controllerPolicy + initialDocuments
- `rotateAuthorityAndOwnerDocument`(L911)—— updateAuthorityKeys + publishDocument(owner)

这两个本质都是"几个原语的原子组合"。与其为每种业务组合各开一个函数,不如提供
**一个原子批量原语**覆盖它们,以及未来任意组合。

---

## 2. 现状分解:原语 vs 组合

**原语(对已存在 name 的单步状态变更):**
`publishDocument` / `revokeDocument` / `updateAuthorityKeys` / `setControllerPolicy` /
`setNamespacePolicy` / `setDidAlias` / `setPaymentTarget` / setSemanticOwner

**创建(生命周期特例,name 尚不存在、需 bootstrap 鉴权、payable 收费):**
`registerName` / `bootstrapName`(后者 = 前者 + 初始配置)

**强业务 combo(本需求要删):**
`bootstrapName`、`rotateAuthorityAndOwnerDocument`

**核心技术约束 —— guard / nameSeq 顺序性:**
每笔外部写都带 `MutationGuard.expectedNameSeq`(L70),由 `_checkGuard`(L1639)校验,
成功后 `nameSeq` 自增。**两笔独立写无法同事务**:第二笔拿不到第一笔自增后的 seq。
combo 接口存在的根本原因就是绕开这一点(在一个函数体内"check 一次 guard、连续应用、整体回滚")。
任何替代方案都必须保留这一语义:**整批只校验一次 guard、要么全成功要么全回滚**。

---

## 3. 方案对比

### 方案 A:通用 `Op[]` 字节分发(最大通用)

```solidity
enum OpKind { PublishDocument, RevokeDocument, UpdateAuthorityKeys,
              SetControllerPolicy, SetNamespacePolicy, SetSemanticOwner,
              SetDidAlias, SetPaymentTarget }
struct Op { OpKind kind; bytes data; }   // data = 该 op 参数的 abi 编码(不含 name/authority/guard)

function applyOps(string name, Op[] ops, CallAuthority authority, MutationGuard guard)
    external payable returns (bytes[] results);
```

- **优点**:一个函数收敛全部组合,未来加组合零成本;删 `bootstrapName`(创建 op 入批)、`rotate*` 全覆盖。
- **缺点**:
  - `bytes` 分发**丢失 ABI 类型安全**,审计困难(审计方普遍排斥不透明 opcode 分发);解码 gas 高、报错定位差。
  - **indexer 受冲击大**:当前靠 `BnsCall::abi_decode`(bns-evm/src/lib.rs:34)逐函数解码 calldata 做事件补全。
    `Op[].data` 是嵌套 bytes,indexer 要再写一层二级解码,projection 复杂度上升。
  - 逐 op 鉴权(不同 op 权限不同,authority key 变更是 Owner-only)集中到一个分发器里,**安全风险集中**。
  - payable 跨 op 的 value 归属、返回值聚合都要额外约定。

### 方案 B(推荐):合并创建 + 一个**类型化**原子批量

不引入 bytes 分发,用强类型表达"已被证明需要的组合 = authority keys + 文档(+ 策略)"。

**B1. 把 `bootstrapName` 并入 `registerName`,删除 `bootstrapName`:**
```solidity
function registerName(
    string name, address assetOwner, RegisterOptions options,
    AuthorityKeyUpdate[] authorityUpdates,      // 原 bootstrap 能力
    Principal semanticOwnerAfterAuthority,      // 原 bootstrap 能力
    ControllerRule[] controllerPolicy, bytes32 controllerPolicyHash,  // 原 bootstrap 能力
    DocumentUpdate[] initialDocuments,
    CallAuthority authority, MutationGuard guard
) external payable returns (uint64 nameSeq, uint64 authoritySeq, bytes32 authorityRoot);
```
创建天生是特例(name 不存在、payable、authority 自举),保留显式、类型安全的单一创建入口;
原 `registerName` 只是它 authorityUpdates/policy 为空的退化调用 → 二合一,不丢能力。

**B2. 对已存在 name 新增一个类型化原子批量,删除 `rotateAuthorityAndOwnerDocument`:**
```solidity
/// 对已注册 name,在单事务内原子应用:authority key 变更 + 多文档发布。guard 仅校验一次。
function applyMutations(
    string name,
    AuthorityKeyUpdate[] authorityUpdates,   // 空 = 不动 authority
    DocumentUpdate[] documents,              // 空 = 不发布文档;>=1 时即"批量 publishDocuments"
    CallAuthority authority,
    MutationGuard guard
) external returns (uint64 authoritySeq, bytes32 authorityRoot, uint64[] documentVersions);
```
- `documents` only → 等价"批量 `publishDocuments`"(覆盖 zone+boot 的诉求);
- `authorityUpdates` + `documents=[owner]` → 等价 `rotateAuthorityAndOwnerDocument`;
- 复用既有 `DocumentUpdate`(L174)/`AuthorityKeyUpdate` 结构体,调用方零新结构。

**保留**:`publishDocument` / `updateAuthorityKeys` 等单步原语(它们不是"强业务",可作为
`applyMutations` 单元素的便捷封装继续存在,或一并下沉为 wrapper,二选一)。

### 方案 C:OZ 式 `multicall(bytes[])` —— 否决

通用 self-multicall 不解决 guard/nameSeq 顺序性(每个内层调用各自 `_checkGuard`、各自自增 seq,
调用方仍要预测批内 seq),反而把问题搬进了一个事务内。除非每个内层调用支持"跳过 guard"模式,
否则不可行;那样改造量不比方案 B 小,且仍是 bytes 分发的审计劣势。

---

## 4. 推荐

**采用方案 B。** 理由:

1. **达成用户目标**:`bootstrapName`、`rotateAuthorityAndOwnerDocument` 两个强业务 combo 都被删除。
2. **安全优先**:涉及 authority key 的写是高危面,类型化签名比 bytes 分发**可审计性强得多**,
   逐 op 鉴权按字段静态可见。
3. **覆盖真实需求**:今天实际存在的原子组合只有两类(创建+配置、keys+ownerDoc),
   demonstrated need 就是"authority keys + documents",类型化批量正好覆盖,不需要为不存在的
   组合需求提前付出 bytes 分发的代价。
4. **indexer 改动小**:仍是逐函数 `sol!` 解码,只是多/改几个具名函数,无需二级 bytes 解码。

**何时升级到方案 A**:当可组合的 op 种类显著增多、且确实出现"任意组合"的业务需求时,
再把 `applyMutations` 泛化为 `applyOps(Op[])`。届时已有的一次性迁移经验可复用。

> 净接口变化:删 `bootstrapName`(并入 `registerName`)、删 `rotateAuthorityAndOwnerDocument`、
> 新增 `applyMutations`。写接口数量不增反减,且 `publishDocuments` 不再需要单列。

---

## 5. 语义要求(对 `applyMutations` 与合并后的 `registerName`)

1. **原子性**:任一条目鉴权/应用失败 → 整笔 revert。
2. **Guard 一次**:整批只 `_checkGuard` 一次;调用方只提供一个 `expectedNameSeq`。
3. **逐条鉴权**:每个 `documents[i].docType` 按现有 `PERMISSION_PUBLISH_DOCUMENT` + controller policy
   规则鉴权;`authorityUpdates` 按现有 Owner-only 规则鉴权(与单步函数完全等价)。
4. **顺序**:若同批既改 authority 又发文档,需明确应用顺序(建议先 authority 后文档,
   与 `rotateAuthorityAndOwnerDocument` 现有语义一致)。
5. **事件**:每个子操作发出与对应单步函数**相同**的事件,使 indexer projection 复用现有路径
   (一笔 tx → 多个事件 + 一次 nameSeq 变更)。
6. **校验**:`authorityUpdates` 与 `documents` 不可同时为空;`documents` 内重复 docType 建议 revert;
   建议设条目上限防 gas 失控。

---

## 6. Blast radius / 一次性迁移清单(合约先行)

合约 ABI 变更会沿 `sol!` 绑定传导,需按序一次改完:

1. **合约**:实现 B1/B2,删除两个 combo。(内部机制已具备:`_registerNameHash` 已循环
   `_publishDocumentUpdateInternal`(L1270);`transferName` 已循环原子写(L787);`_checkGuard` 本就每笔一次。)
2. **bns-evm**:重新生成 `sol!` 绑定;更新 `decode_bns_call` / `BnsCall` 变体(bns-evm/src/lib.rs:34)。
3. **bns-indexer**:更新 `decoded_call_for_log` / projection 以认得新函数(sync.rs:215)。
   ✅ **历史兼容已不是问题**:目标链处于开发测试阶段、生产环境零部署(2026-06-27 确认),
   可直接硬删旧函数、随意重置测试链,**无需保留旧 ABI 历史解码器**。
4. **bns-client**:更新/替换 `bootstrap_name_call`、新增 `apply_mutations_call`;`BnsBootstrapNameReq` 等请求类型调整。
5. **SN 调用方**:
   - `cyfs-sn api/auth.rs:118` 的 `bootstrap_name` 调用切到合并后的 `register_name`。
   - `bind_zone_documents` 改用 `apply_mutations`(documents=[zone, boot]),写回**独立原子文档**,
     弃用"boot_jwt 内嵌 zone"(仅 DNS TXT 出口保留 JWT 紧凑序列化)。
   - 任何 key 轮换 + owner 文档流程改用 `apply_mutations`。
6. **低成本红利**:`rotateAuthorityAndOwnerDocument` 当前 Rust 侧**零调用**,删除无迁移负担。

---

## 7. 风险与确认项

- [x] 目标链是否 pre-launch? —— **已确认:开发测试阶段、生产零部署(2026-06-27)**。
      可硬删旧函数、可重置测试链,无历史回放负担。这是本次破坏性变更最大的前置顾虑,现已消除。
- [ ] `applyMutations` 是否需要也覆盖 `setControllerPolicy` / `setSemanticOwner`?
      (若 bootstrap 后还有"改策略+发文档"的原子需求,可把这两类也纳入 B2 的字段;
       否则保持最小集 authority+documents。)
- [ ] 合并后的 `registerName` 参数较多,需评估可读性 / 是否拆 struct 入参。
- [ ] payable 收费仅在创建路径,`applyMutations` 非 payable,确认无费用语义遗漏。
- [ ] 安全审计:逐 op 鉴权矩阵、批内顺序、guard-once + nameSeq 自增的不变量。
