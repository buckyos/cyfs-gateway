# BNS 发布说明

## Beta 2.2：DID Resolver 文档版本语义修正

本次为 breaking change：BNS HTTP DID Resolver 的 `buckyos.documentVersion` 改为当前发布
文档的 `iat`，`didDocumentMetadata.versionId` 为同一值的字符串形式，与 name-client、
system-config 和 SN Resolver 一致。iat 统一通过 `name_client::document_iat` 提取（缺 `iat`
时可从 `exp - DEFAULT_EXPIRE_TIME` 推导）；无法取得时省略这两个字段，不回落到登记计数器。

BNS 自增登记号改放在可选字段 `buckyos.registryVersion` 中，为 0 时省略。WebUI 用它显示
登记版本和导航登记历史。旧客户端会忽略此未知字段，因此 bns-server 可以单独先发布，
无需与 buckyos-base 锁步升级。

bns-client 写路径 receipt 的 `document_version` 及 `STALE_DOCUMENT_VERSION` 检查继续采用
登记号语义，登记历史 API 的版本参数也保持不变。

### 升级操作与一次性影响

- 升级时清理 system-config 中 `resolver/cache/*` 前缀下的旧解析缓存，让后续解析重新填充。
  这是 system-config 的 KV 命名空间。旧 BNS 写入的 `state.document_version` 为登记号，
  无法通过 Zone Resolver 的 `document_version == document_iat` 检查。无需修改 buckyos 代码。
- 通过 `did:bns` 解析的已安装应用，在升级后首次检查时，版本值从登记号变为 iat，可能改变
  安装／升级指纹并提示一次“有更新”。这是本次语义修正的预期一次性影响。
