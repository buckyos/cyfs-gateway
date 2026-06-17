# BNS 智能合约接口设计

本文基于 `认识BNS.md` 和 `BNS 去中心的名字系统.md`，把 BNS 的协议目标收敛成智能合约接口。

BNS 合约的职责不是保存所有 DID Document，也不是替代内容网络、支付合约、DNS、SN 或 Zone resolver。它只负责保存不可被中心化 provider 覆盖的全局事实：

- 名字是否存在、由谁拥有、是否过期、是否可转移。
- `did:bns:$name + doc_type` 当前版本是什么，历史版本是否有效或已吊销。
- 谁可以更新某个名字或某类文档。
- 名字是否迁移、别名指向哪里、旧状态如何追溯。
- 收款目标、收益策略和支付合约需要验证的 purchase context。

## 1. 设计边界

### 合约必须负责

- `did:bns:$name` 的全局名字资产状态。
- 名字资产 owner 与 BuckyOS 语义 owner/controller 的分离表达。
- DID Document 的 `doc_type` 版本状态、当前指针、吊销状态和历史 proof。
- Owner key 轮换、controller policy 更新、别名和迁移。
- 支付合约可查询的 beneficiary、payment target、split policy hash。
- 事件日志，供 resolver、indexer、钱包和客户端构造可验证历史。

### 合约不负责

- `did:dev` 自认证设备身份。`did:dev` 由设备公钥和 RTCP 握手证明；合约只可能通过某个 `did:bns` 文档间接引用它。
- 大型 DID Document、AppDoc、content meta、ZoneConfig、ObjId bytes 的默认托管。合约保存 `DocumentRef` 和 hash，文档本体通常由 Repo、Source、SN、Zone resolver、HTTPS 或缓存提供；如果调用者愿意承担 gas，也允许把文档原文 inline 到链上。
- 内容购买扣款和 receipt 发行。标准支付合约负责 `purchase(...)`，BNS 只提供当前 purchase context。
- DNS TXT、`.well-known`、SN、local cache 的可信化。它们只能作为候选 provider，最终必须回到 BNS 状态、签名和 hash 校验。
- 全文搜索、内容排名、信用评分、应用商店和索引推荐。

## 2. 合约分层

一个部署可以实现全部接口，但协议上按三个接口面理解：

```text
IBnsRegistry
  名字资产生命周期
  文档版本生命周期
  controller / alias / payment policy

IBnsResolverView
  resolveDid(did, doc_type)
  queryNameState / getDocumentVersion / getAlias
  供 resolver、钱包、客户端只读查询

IBnsPaymentView
  resolvePaymentTarget(...)
  getPurchaseContext(...)
  供标准支付合约购买内容、App、服务订阅时调用
```

`IBnsRegistry` 是唯一写入面；其它 view 都是从 registry 状态投影出来的只读接口。

## 3. 基础约定

### name 与 DID

合约入参使用不带 `did:bns:` 前缀的 canonical name：

```text
alice
jarvis.alice
book1.alice
filebrowser.buckyos
```

Resolver 层负责把 `did:bns:alice` 转成 `alice`。合约不接受 `did:web`；`did:web` 只能作为 discovery 入口，并通过文档签名或 BNS alias 绑定到 `did:bns`。

`did:dev` 不进入全局名字资产表。设备文档可由 `did:bns:ood1.alice` 的 `doc` 或 `service` 文档引用 `did:dev:<pkx>`。

### doc_type

`doc_type` 使用 canonical string 字面量，链上直接保存和传递短字符串，不做 `hash(lowercase(doc_type))` 转换。

第一版规则：

- 只接受 lower-case ASCII。
- 长度建议限制在 32 bytes 以内。
- 标准类型走 allow-list，扩展类型可通过治理或 registry 增加。
- 比较时按 byte exact match，不做大小写折叠。
- 具体 EVM 实现若需要进一步省 gas，可以在合约内部把标准字符串 intern 成小整数；协议 ABI 仍暴露 `string docType`，不要求调用方传 hash。

第一版保留这些标准类型：

| doc_type | 语义 |
| --- | --- |
| `owner` | OwnerConfig / global profile |
| `boot` | ZoneBootConfig |
| `zone` | ZoneConfig |
| `doc` | 通用 DID Document |
| `device` | DeviceConfig 或设备文档指针 |
| `service` | ServiceInfo |
| `agent` | AgentDocument |
| `app` | AppDoc |
| `content` | content meta |
| `payment` | 支付策略扩展文档 |

`info` 是运行时上报信息，默认不作为链上 `doc_type`。它应由 Zone resolver / system-config 提供，并由上级 `doc` / `device` / `zone` 文档授权。

### 版本

每个 `(name, docType)` 维护单调递增的 `version`。

- `version = 0` 表示不存在。
- 新发布文档必须指定 `expectedVersion`，防止并发覆盖。
- 历史版本不删除，只改变状态。
- 当前版本变化不会改写历史 receipt、历史签名、旧 ObjId 或旧 owner 状态。

## 4. 数据类型

以下是协议级 IDL。具体链实现可以映射成 Solidity、Move 或其它合约语言。

```solidity
enum NameStatus {
    Available,
    Active,
    Expired,
    Released,
    Tombstoned
}

enum DocumentStatus {
    Missing,
    Active,
    Revoked,
    Expired,
    Migrated,
    Tombstoned
}

enum AliasKind {
    Alias,
    MigratedTo,
    Canonical
}

enum ReleaseMode {
    ReleaseAfterGrace,
    TombstoneForever
}

enum PrincipalKind {
    ChainAddress,
    Did,
    PublicKey,
    Contract
}

struct Principal {
    PrincipalKind kind;
    bytes value;
}

struct DocumentRef {
    // inline, ipfs, cyfs, https, zone-resolver, source, repo 等，由 resolver 理解。
    bytes32 storageType;
    string uri;

    // 当 storageType = inline 时保存完整文档原文；其它形态必须为空。
    // 如果文档是 JSON，这里保存 canonical JSON 的 UTF-8 bytes。
    // 这是调用者主动选择的高 gas 模式，适合短 OwnerConfig、关键 tombstone 说明等。
    bytes inlineDocument;

    // 文档本体的内容 hash。provider 返回文档后必须匹配该 hash。
    // storageType = inline 时必须等于 hash(inlineDocument)。
    bytes32 contentHash;

    // 文档 schema / codec，例如 OwnerConfig v1、AppDoc v1。
    bytes32 schema;
    bytes32 codec;

    // 可选扩展，如压缩算法、mirror 列表、ObjId、版本策略等的 hash。
    bytes32 extraHash;
}

struct NameState {
    string name;
    address assetOwner;
    NameStatus status;

    uint64 registeredAt;
    uint64 expireAt;
    uint64 graceUntil;
    uint64 updatedAt;

    // 名字级别单调序号，owner、policy、alias、release 都会递增。
    uint64 nameSeq;

    // owner doc 的当前版本，便于 boot / wallet 快速读取 owner trust root。
    uint64 ownerDocumentVersion;

    bytes32 namespacePolicyHash;
    bytes32 paymentPolicyHash;

    // alias / migrated / canonical 关系的 hash，具体结构通过 getAlias 查询。
    bytes32 aliasStateHash;
}

struct DocumentState {
    string name;
    string docType;
    uint64 version;
    uint64 previousVersion;

    DocumentStatus status;
    DocumentRef document;

    Principal controller;
    Principal beneficiary;
    address paymentTarget;

    uint64 validFrom;
    uint64 expireAt;
    uint64 revokedAt;

    bytes32 controllerPolicyHash;
    bytes32 splitPolicyHash;
    bytes32 documentStateHash;
}

struct ControllerRule {
    Principal controller;

    // 空值表示适用于所有 doc_type；否则只适用于指定类型。
    string docType;

    // create/update/revoke/set_payment/set_alias/delegate 等位图。
    uint32 permissions;

    // 可选命名空间约束，例如 "*.alice" 或 "content.*.alice" 的 hash。
    bytes32 namespaceScopeHash;

    uint64 validFrom;
    uint64 validUntil;
    bytes32 constraintHash;
}

struct AuthProof {
    Principal signer;
    bytes signature;
    uint64 nonce;
    uint64 deadline;

    // 必须匹配更新前状态，不能由新 document 自己授权本次更新。
    uint64 expectedNameSeq;
    uint64 expectedDocumentVersion;
}

struct RegisterOptions {
    uint64 duration;
    uint64 gracePeriod;
    bool renewable;
    bool transferable;

    // 是否允许未上链子名字回落到父 Zone / Owner resolver。
    bool allowDelegatedSubnames;

    address initialPaymentTarget;
    bytes32 initialPaymentPolicyHash;
    bytes32 initialNamespacePolicyHash;
}

struct DocumentUpdate {
    string docType;
    DocumentRef document;
    Principal controller;
    Principal beneficiary;
    address paymentTarget;
    uint64 expireAt;
    bytes32 controllerPolicyHash;
    bytes32 splitPolicyHash;
}

struct ResolveResult {
    NameState nameState;
    DocumentState documentState;

    Principal verifiedOwner;
    Principal controller;
    bytes32 trustRoot;

    DocumentStatus status;
    AliasKind aliasKind;
    string aliasTargetDid;

    // 用于 resolver 输出 provider/cache/warning 前的链上 proof anchor。
    bytes32 proofRoot;
}

struct AliasState {
    string name;
    AliasKind kind;
    string targetDid;
    bytes32 proofHash;
    uint64 setAt;
    uint64 nameSeq;
}

struct PurchaseContext {
    string contentName;
    string docType;
    uint64 documentVersion;

    Principal beneficiary;
    address paymentTarget;
    bytes32 splitPolicyHash;
    bytes32 pricePolicyHash;
    bytes32 rightsPolicyHash;

    DocumentStatus status;
    bytes32 proofRoot;
}
```

## 5. 名字资产接口

### queryNameState

```solidity
function queryNameState(string calldata name)
    external view returns (NameState memory state);
```

回答“这个名字当前是否存在、由谁拥有、是否过期、是否允许后续更新”。

规则：

- `Available` 可以注册。
- `Active` 可以解析和更新。
- `Expired` 不能发布新文档，但历史仍可查询；是否能被别人注册取决于 `graceUntil` 和 tombstone 策略。
- `Released` 可以进入重新注册流程，但历史事件保留。
- `Tombstoned` 永久不可重新注册，只能查询历史。

### registerName

```solidity
function registerName(
    string calldata name,
    address assetOwner,
    RegisterOptions calldata options,
    DocumentUpdate[] calldata initialDocuments
) external payable returns (uint64 nameSeq);
```

注册全局名字。`initialDocuments` 建议至少包含 `owner` 文档，也可以同时提交 `boot`、`zone`、`app` 或 `content` 初始文档。

规则：

- 注册只接受 canonical name。
- 二级名字首次注册必须由它的一级名字资产 owner 调用。例如首次注册 `jarvis.alice` 时，调用方必须是 `alice` 的当前 `assetOwner`；后续转让、续期和文档更新按 `jarvis.alice` 自己的状态授权。
- 如果一级名字不存在、已过期、已释放或 tombstoned，则不能首次注册它下面的二级名字。
- 注册成功后 `assetOwner` 是链上名字资产 owner。
- `owner` 文档里的 owner/controller 是 BuckyOS 语义 owner，不要求等同于 `assetOwner`。
- 如果设置 `allowDelegatedSubnames = true`，未全局注册的子名字可以回落到父名字授权的 Zone resolver。
- exact global name 优先级永远高于 delegated subname。Zone resolver 不能覆盖已上链名字。

### renewName

```solidity
function renewName(string calldata name, uint64 duration)
    external payable returns (uint64 expireAt);
```

续期只改变名字资产状态，不改变任何 DID Document。

规则：

- 任何人都可以为名字续期付费。
- 短名字、高价值名字可以强制续期；长名字或 Zone 内子名字可由经济模型设置为无需续期。
- 过期不会抹除历史 proof。

### transferName

```solidity
function transferName(
    string calldata name,
    address newAssetOwner,
    DocumentUpdate[] calldata atomicDocumentUpdates,
    AuthProof calldata proof
) external returns (uint64 nameSeq);
```

转移名字资产 owner。内容版权出售、App 归属转移、组织接管等场景通常需要同时更新 `owner` / `content` / `app` / `payment` 文档，因此接口允许原子提交 `atomicDocumentUpdates`。

规则：

- 只改变 `assetOwner` 不等于改变 BuckyOS 语义 owner。
- 如果业务上需要把 `did:bns:book1.alice` 的收益和更新权交给新主体，必须同时发布新的 `content` 或 `owner` 文档。
- 原子更新的授权仍基于更新前状态。
- 历史 receipt 继续绑定旧版本 purchase context。

### releaseName

```solidity
function releaseName(
    string calldata name,
    ReleaseMode mode,
    bytes32 reasonHash,
    AuthProof calldata proof
) external returns (uint64 nameSeq);
```

释放或 tombstone 名字。

规则：

- `ReleaseAfterGrace` 允许名字进入释放/重新注册流程。
- `TombstoneForever` 表示名字永久不可再注册，适用于高风险、钓鱼、重大迁移或争议名字。
- release 不删除历史文档、事件和支付记录。

### setNamespacePolicy

```solidity
function setNamespacePolicy(
    string calldata name,
    bool allowDelegatedSubnames,
    bytes32 namespacePolicyHash,
    AuthProof calldata proof
) external returns (uint64 nameSeq);
```

更新子名字委托策略。

规则：

- exact global name 永远优先于 delegated subname。
- `allowDelegatedSubnames = true` 只表示 resolver 可以回落到父名字授权的 Zone / Owner resolver。
- 具体 Zone resolver endpoint 不直接写在这个接口里，而是通过 `owner` / `zone` / `service` 文档表达。
- 关闭委托不会删除历史解析记录，但会阻止未来未上链子名字继续回落。

## 6. DID 文档接口

### resolveDid

```solidity
function resolveDid(string calldata did, string calldata docType)
    external view returns (ResolveResult memory result);
```

链上只解析 `did:bns:$name`。`did:dev`、`did:web` 由 resolver 层处理。

规则：

- `did` 必须是 `did:bns:$name`。
- 如果 exact name active，返回该名字的指定 `docType` 当前版本。
- 如果 exact name 是 alias / migrated，返回 alias 状态和目标 DID，客户端不能静默改写历史记录。
- 如果 exact name 不存在且父名字允许 delegated subnames，返回 delegated proof anchor；具体文档由父 Zone resolver 提供。
- 返回结果不包含 provider/cache 状态；这些由链下 resolver 补充。

### getDocumentVersion

```solidity
function getDocumentVersion(
    string calldata name,
    string calldata docType,
    uint64 version
) external view returns (DocumentState memory state);
```

查询历史版本，用于验证旧签名、旧 receipt、旧 ObjId 和审计记录。

### publishDocument

```solidity
function publishDocument(
    string calldata name,
    string calldata docType,
    DocumentRef calldata document,
    Principal calldata controller,
    Principal calldata beneficiary,
    address paymentTarget,
    uint64 expireAt,
    bytes32 controllerPolicyHash,
    bytes32 splitPolicyHash,
    AuthProof calldata proof
) external returns (uint64 version);
```

发布某个 `doc_type` 的新当前版本。

授权规则：

- 必须先读取更新前的 `NameState` 和当前 `DocumentState`。
- `proof.signer` 必须是更新前状态授权的 `assetOwner`、owner controller 或该 `docType` 的 controller。
- `proof.expectedDocumentVersion` 必须等于当前版本。
- 新文档里的 owner/controller/payment 声明只能影响下一状态，不能授权本次更新。
- `document.contentHash` 是 resolver 验证文档本体的硬约束。
- `document.storageType = inline` 时，合约直接保存 `inlineDocument` 原文；这是高 gas 写入路径，但允许调用者用成本换取最强可用性。

完整 JSON document 保存规则：

- `publishDocument` 支持把完整 document 保存进 `DocumentRef.inlineDocument`。
- JSON document 必须先序列化成 canonical JSON 的 UTF-8 bytes，再作为 `inlineDocument` 提交。
- 合约不解析 JSON 字段，不根据 JSON 内容做授权判断，只把它作为可验证 bytes 保存。
- `document.contentHash` 必须等于 `hash(document.inlineDocument)`；resolver 读取链上 `inlineDocument` 后仍按同一 hash 验证。
- `document.uri` 在 `storageType = inline` 时应为空；需要链下 mirror 时放入 `extraHash` 指向的扩展结构或在文档内部声明。
- `document.codec` 应标记 JSON codec，`document.schema` 标记具体文档类型和版本，例如 OwnerConfig v1、AppDoc v1。

### revokeDocument

```solidity
function revokeDocument(
    string calldata name,
    string calldata docType,
    uint64 fromVersion,
    uint64 toVersion,
    bytes32 reasonHash,
    AuthProof calldata proof
) external returns (uint64 nameSeq);
```

吊销文档版本范围。

规则：

- 吊销不删除历史，只改变版本状态。
- 如果吊销当前版本，`resolveDid` 应返回 `Revoked`，除非同时发布了新的当前版本。
- `reasonHash` 指向链下说明、事故报告或治理决议。
- key 泄露时应吊销受影响版本，并发布新的 `owner` 或 controller policy。

### setControllerPolicy

```solidity
function setControllerPolicy(
    string calldata name,
    ControllerRule[] calldata rules,
    bytes32 policyHash,
    AuthProof calldata proof
) external returns (uint64 nameSeq);
```

更新名字级 controller policy。复杂 policy 可以放在链下文档，链上保存 `policyHash` 和事件。

规则：

- owner 不应每天使用最高权限 key 更新 AppDoc、content meta 或设备文档。
- `content-signer.alice` 这类子身份可以只被授权更新 `content`。
- `jarvis.alice` 可以只被授权更新 `agent`。
- policy 生效后只影响未来更新，不改写历史版本。

### changeOwnerKey

```solidity
function changeOwnerKey(
    string calldata name,
    DocumentRef calldata newOwnerDocument,
    ControllerRule[] calldata newControllerRules,
    AuthProof calldata proof
) external returns (uint64 ownerDocumentVersion);
```

轮换 owner key。它是 `owner` 文档更新的专用快捷接口，不等同于名字资产转让。

典型用途：

- 日常 key 轮换。
- 私钥泄露后的恢复。
- 从临时 key 迁移到硬件钱包或多签。
- 从单 key 迁移到 controller policy。

规则：

- 授权仍基于旧 owner / recovery policy。
- 成功后 `ownerDocumentVersion` 递增。
- 旧版本可被标记为 revoked，但历史签名仍可按当时状态解释。

### setDidAlias

```solidity
function setDidAlias(
    string calldata name,
    string calldata targetDid,
    AliasKind kind,
    bytes32 proofHash,
    AuthProof calldata proof
) external returns (uint64 nameSeq);
```

设置 alias、migration 或 canonical 关系。

规则：

- `setDidAlias` 不叫 rename，因为旧 DID 不能被直接替换。
- `MigratedTo` 表示新请求应优先使用目标 DID。
- 客户端可以提示用户迁移收藏、联系人、安装记录，但不能批量改写历史 receipt、历史签名和旧版本内容。
- 如果 `did:web` 要继承 BNS 信用，需要在 BNS 或 OwnerConfig 中声明绑定，并验证 Web host 返回文档与 BNS owner/controller 一致。

### getAlias

```solidity
function getAlias(string calldata name)
    external view returns (AliasState memory state);
```

查询 alias / migration / canonical 状态。客户端展示迁移提示、钱包确认支付对象、安装器处理旧 App DID 时都应显式读取该状态，而不是只取最终目标 DID。

### setPaymentTarget

```solidity
function setPaymentTarget(
    string calldata name,
    string calldata docType,
    address paymentTarget,
    Principal calldata beneficiary,
    bytes32 paymentPolicyHash,
    AuthProof calldata proof
) external returns (uint64 version);
```

更新收款目标或收益主体。也可以通过 `publishDocument` 更新，但支付路径需要一个明确接口，方便钱包和支付合约审计。

规则：

- `beneficiary` 是收益主体，不等于名字控制权 owner。
- `paymentTarget` 是链上实际收款地址，可以是普通地址、分账合约或 DAO treasury。
- 收款目标变更只影响之后的新购买。
- 历史支付和 receipt 仍按购买时的 purchase context 验证。

## 7. 支付合约查询接口

BNS 不扣款，不生成购买 receipt。标准支付合约在购买前查询 BNS，拿到当时的 purchase context。

### getPurchaseContext

```solidity
function getPurchaseContext(
    string calldata contentName,
    string calldata docType
) external view returns (PurchaseContext memory context);
```

标准支付合约调用流程：

```text
purchase(content_name, amount, indexer, recommendation_id):
  context = bns.getPurchaseContext(content_name, "content")
  assert context.status == Active
  assert amount matches price policy
  transfer token to context.paymentTarget or split targets
  emit receipt with content_name + documentVersion + proofRoot
```

购买 receipt 至少应记录：

- buyer。
- content_name。
- doc_type。
- BNS document version。
- paid amount / token。
- payment target。
- split policy hash。
- rights policy hash。
- tx hash / block number。

这样内容升级、版权转移、收款目标变化后，旧 receipt 仍能回到购买发生时的 BNS 状态。

### resolvePaymentTarget

```solidity
function resolvePaymentTarget(
    string calldata name,
    string calldata docType,
    uint64 version
) external view returns (
    Principal memory beneficiary,
    address paymentTarget,
    bytes32 splitPolicyHash,
    bytes32 proofRoot
);
```

用于审计历史 payment target，也用于支付合约在指定版本上做复核。

## 8. 事件

所有状态变化必须发事件。Resolver、indexer、钱包、Source 和支付合约通过事件构造可验证索引。

```solidity
event NameRegistered(
    string indexed name,
    address indexed assetOwner,
    uint64 expireAt,
    uint64 nameSeq
);

event NameRenewed(
    string indexed name,
    uint64 expireAt,
    uint64 nameSeq
);

event NameTransferred(
    string indexed name,
    address indexed oldAssetOwner,
    address indexed newAssetOwner,
    uint64 nameSeq
);

event NameReleased(
    string indexed name,
    ReleaseMode mode,
    bytes32 reasonHash,
    uint64 nameSeq
);

event DocumentPublished(
    string indexed name,
    string docType,
    uint64 indexed version,
    bytes32 contentHash,
    bytes32 documentStateHash
);

event DocumentRevoked(
    string indexed name,
    string docType,
    uint64 fromVersion,
    uint64 toVersion,
    bytes32 reasonHash
);

event ControllerPolicyUpdated(
    string indexed name,
    bytes32 policyHash,
    uint64 nameSeq
);

event NamespacePolicyUpdated(
    string indexed name,
    bool allowDelegatedSubnames,
    bytes32 namespacePolicyHash,
    uint64 nameSeq
);

event OwnerKeyChanged(
    string indexed name,
    uint64 ownerDocumentVersion,
    bytes32 ownerDocumentHash
);

event DidAliasSet(
    string indexed name,
    string targetDid,
    AliasKind kind,
    bytes32 proofHash,
    uint64 nameSeq
);

event PaymentTargetUpdated(
    string indexed name,
    string docType,
    address paymentTarget,
    bytes32 paymentPolicyHash,
    uint64 version
);
```

## 9. Resolver 映射规则

链下 resolver 的强验证路径应按以下顺序：

```text
resolve(did:bns:$name, doc_type):
  1. 查询 BNS exact name state。
  2. 如果 active，查询当前 doc_type 版本。
  3. 如果 DocumentRef 是 inline，直接读取 inlineDocument；如果 codec 是 JSON，则按 UTF-8 JSON 解码；否则从 DocumentRef 指定 provider 获取文档本体。
  4. 校验 hash(document) == contentHash。
  5. 校验文档签名是否回到 BNS owner/controller policy。
  6. 输出 document + verified_owner + controller + proof + provider/cache/warnings。
```

子名字回落规则：

```text
resolve(did:bns:cam01.alice, doc):
  1. 如果 cam01.alice 是 exact global name，使用链上状态。
  2. 如果不存在，查询父名字 alice。
  3. 如果 alice 允许 delegated subnames，按 alice 的 zone/owner 文档找到 Zone resolver。
  4. Zone resolver 返回 DeviceConfig / ServiceInfo。
  5. 用 alice 当前 owner/controller 验证返回文档。
```

DNS TXT、HTTPS、SN、Repo、Source、local cache 都可以参与第 3 步提供文档本体或候选 boot 材料，但不能跳过第 1、4、5 步。

## 10. 授权规则

所有写接口都遵循同一原则：

```text
authorize_update():
  current_name_state = load(name)
  current_document_state = load(name, doc_type)
  assert proof.expectedNameSeq == current_name_state.nameSeq
  assert proof.expectedDocumentVersion == current_document_state.version
  assert proof.signer is authorized by current state
  assert proof not expired and nonce not used
  apply update
```

关键约束：

- 授权依据必须来自更新前状态。
- 新提交文档不能授权本次提交。
- `assetOwner` 可以管理名字资产生命周期。
- `assetOwner` 直接发起交易时可以不携带签名；由代理、钱包 session 或链下 key 代签时必须携带 `AuthProof`。
- owner/controller policy 决定谁能更新具体 `doc_type`。
- payment target 可以由 owner 或被授权的 payment controller 更新。
- content/app/service 文档的更新权可以下放给特定子身份。
- release/tombstone/name transfer 属于高风险操作，默认需要 asset owner 或 recovery policy 授权。

## 11. 最小闭环接口

如果只保留第一版必须实现的接口，优先级如下：

```solidity
// name asset
queryNameState
registerName
renewName
transferName
releaseName
setNamespacePolicy

// document
resolveDid
getDocumentVersion
publishDocument
revokeDocument

// control
setControllerPolicy
changeOwnerKey
setDidAlias
getAlias
setPaymentTarget

// payment view
getPurchaseContext
resolvePaymentTarget
```

这组接口覆盖了两份 BNS 文档要求的最小协议闭环：

- 名字可以注册、拥有、续期、释放和转让。
- `did + doc_type` 可以解析到可验证文档。
- 文档可以更新、吊销、保留历史版本。
- owner key 和 controller policy 可以轮换。
- alias / migration 不破坏历史可信。
- 支付合约能绑定长期内容名和购买发生时的权益状态。
- Zone resolver、SN、DNS、HTTPS、Source、Repo 可以作为 provider，但不能获得最终控制权。

## 12. 第一版不解决的问题

- 具体定价、拍卖、短名保护、保留字和争议仲裁。
- Unicode 名字、同形字、大小写和多语言显示策略。第一版建议只接受 lower-case ASCII label。
- Ed25519 / secp256k1 / 多签 / 社交恢复的具体链上验签实现。接口保留 `Principal` 和 `AuthProof`，具体链可先只支持链原生账户和合约账户。
- 跨链名字同步和跨链支付。
- 隐私保护。BNS 是公开状态层，不应保存私有 profile 字段。
- 标准支付合约的完整 ABI、receipt NFT/SBT 形态和退款/托管规则。
- Source、indexer、review report、信用机构的业务协议。
