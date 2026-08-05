# bns_dv 与 SourceDAOBackend 链交互对比及优化建议

## 1. 文档目的

本文只比较两个 backend 与 EVM 链的交互方式，并给出 `bns_dv` 的 RPC/API 消耗优化建议。建议的边界是：

- 不修改 BNS 合约接口和链上业务语义；
- 不修改 BNS-Server 已公开的 kRPC 方法、请求和响应结构；
- 不修改名称、文档、权限、MutationGuard 等业务规则；
- 继续由 SQLite 投影承担业务读请求；
- 主要调整链 RPC provider、轮询调度、事件取数、交易状态查询和缓存；
- 对投影代码的改动只用于减少链读取，并要求优化前后投影结果一致。
- `BnsEvmControllerClient` 只属于本地测试路径：`smoke` 冒烟，以及测试脚本通过 `serve --config`/`--seed-config` 配合 Anvil 从零初始化完整 SN 集群；它不进入正式服务生命周期。本轮不修改 Controller，也不把它接入 `BnsChainClient`。

对比代码快照：

- `cyfs-gateway`: `4e1f391c95eb42803751d4a98a7ec2c958134ad8`
- `SourceDAOBackend`: `af0b1fff3b833acb15bfe1550e1d93437c68a07a`
- 分析日期：2026-08-05

这里的调用量是根据代码路径做的静态估算，不代表线上账单。上线改动前后通过现有 API 页面和 RPC 服务侧数据校准即可，不需要为此在代码中新增观测。

## 2. 结论摘要

`bns_dv` 的普通业务读已经走 SQLite 投影，这一点与 SourceDAOBackend 的方向一致。正式服务由 indexer 和 server handler 完成链交互，不使用 Controller。当前高消耗主要不在普通 BNS 查询，而在以下三个链交互路径：

1. **空闲轮询过密且每轮重复读取不变量。** 默认 `interval_ms=1000` 时，投影追平后每轮仍调用一次 `eth_chainId`、一次 `eth_blockNumber`、一次 `eth_getBlockByNumber`。约为 **259,200 次/天**。SourceDAOBackend 的链头轮询是每 15 秒一次、每次一次 `eth_getBlockByNumber("latest")`，约 **5,760 次/天**。
2. **事件投影先无条件读取交易，再按每条事件回读合约状态。** `bns-indexer` 对每个 registry event 都先进入 `decoded_call_for_log`；即使只有 authority/controller 事件真正使用 calldata，也会对几乎每笔有业务事件的交易调用 `eth_getTransactionByHash`。随后多数事件还会产生 1～2 次 `eth_call`，同一名称在同一交易内也可能被重复读取。
3. **客户端交易状态与链 RPC 一一放大。** 每次 `tx.query_state` 都需要两次上游 RPC：`eth_getTransactionReceipt` 加 `eth_blockNumber`，或者 `eth_getTransactionReceipt` 加 `eth_getTransactionByHash`。前端会按 2 秒、5 秒、15 秒分段持续轮询，多个用户或恢复出的历史未完成交易会线性放大上游消耗。

建议先做不改变投影语义的优化：

1. 首先在现有下层 crate `bns-evm` 中抽出一个长期存在的 `BnsChainClient`，由 `bns_dv` 创建单实例并注入 indexer 和 server；以后 `bns_dv` 进程内的链交互尽量集中在该实例中。
2. 参考 SourceDAOBackend，在 `BnsChainClient` 内把一次投影过程中的多次独立 latest `eth_call` 聚合为一次 Multicall；继续使用现有 RPC endpoint，聚合失败才回退到逐个 `eth_call`。
3. 再在 `BnsChainClient` 内缓存 chain ID、latest head、fee 和 receipt，并提供 singleflight。
4. 链错误处理直接采用 SourceDAOBackend 的简单规则：后台链操作失败后固定暂停 30 秒再重试；外部 API 触发的链操作失败则立即返回错误，由调用方重新请求。
5. 将同步器改成“backlog 连续处理、追平后按 `interval_ms` 休眠”；`interval_ms` 默认 15 秒。每个 backlog 分片默认处理 500 个 block，并可通过 `--max-block-span` 调整。
6. 只对确实需要 calldata 的事件读取交易，并在一个同步批次内去重 name/document/transaction 读取。
7. 最后再评估事件/calldata 优先投影等影响更大的方案。

`BnsChainClient` 收敛本身不改变调用量；在这个基础上完成 chain ID 缓存、状态感知调度以及 latest head/reorg 合并后，按 15 秒空闲间隔估算，后台空闲请求可从约 259,200 次/天下降到约 5,760 次/天，下降约 **97.8%**，同时不降低历史追赶速度。

## 3. 对比范围与公平性说明

SourceDAOBackend 可以作为 indexer 和 backend 读写隔离的基准，但不能直接认为它的所有链交互都优于 BNS：

- SourceDAOBackend 不为浏览器或 SN 提供 raw transaction relay，也不提供 backend 侧的实时交易状态接口；BNS 的 `tx.prepare`、`tx.submit_raw`、`tx.query_state` 是额外产品能力。
- BNS 保存游标 block hash 并主动检查 reorg；SourceDAOBackend 只保存下一个扫描块高，没有等价的 block hash/reorg 校验。优化时应保留 BNS 的正确性能力，不能直接删除重组检查。
- 两边在处理历史事件时，部分补充 `eth_call` 默认读 `latest`。对当前“最终状态投影”模型这是可接受的：无后续变更时 latest 即正确状态；有后续变更时，较早事件可能暂时读到未来状态，但继续追到后续事件后会再次收敛到同一正确最新状态。历史追赶期间 backend 本来也不适合承接写操作。

因此本文把问题拆为两部分：

- indexer 的固定后台消耗：可以直接参考 SourceDAOBackend；
- BNS 独有的交易服务消耗：保持 API 不变，在 server 内部做共享、缓存、合并和退避。

## 4. 当前链交互全景

### 4.1 bns_dv

长驻进程入口在 [`bns_dv.rs`](../../src/components/bns-server/src/bin/bns_dv.rs)。`serve` 同时启动：

- `BnsContractEventIndexer`：轮询链并写 SQLite；
- `BnsContractServerHandler`：普通读查 SQLite，交易相关接口直连链；

目前 indexer 和 server handler 分别创建自己的 `EthRpcClient`。虽然 `reqwest::Client` 在单个实例内能复用连接，但两者之间没有共享链头、chain ID、receipt 或 fee 数据。`BnsEvmControllerClient` 不属于正式服务运行时链访问模型，只在以下本地测试初始化路径使用：

- `smoke` 子命令执行跨分层冒烟；
- 测试脚本以 `serve --config`/`--seed-config` 进入 `run_on_init_txs`，配合 Anvil 从零构造并启动完整的本地 SN 集群。

这两条路径都属于测试基础设施，不是正式 CD 服务启动方式。它们应继续保持可用，但不纳入服务侧 `BnsChainClient` 的共享、缓存或调度改造；新增的 `serve --cluster` 也不得隐式触发本地初始化交易。

#### Indexer 每次 `sync_once`

代码位置：[`bns-indexer/src/sync.rs`](../../src/components/bns-indexer/src/sync.rs)。

| 阶段 | 当前 RPC | 触发频率 |
| --- | --- | --- |
| 校验网络 | `eth_chainId` | 每次 `sync_once` |
| 读取链头 | `eth_blockNumber` | 每次 `sync_once` |
| 检查 reorg | `eth_getBlockByNumber(cursor.block_number)` | 已有带 hash 游标时，每次 `sync_once`，即使链头没变 |
| 拉事件 | `eth_getLogs` | 有待同步区间时，每个最多 1000 block 的分片一次 |
| 解交易 calldata | `eth_getTransactionByHash` | 当前对每个 registry event 都尝试；同一 `sync_once` 内按 tx hash 去重 |
| 补名称状态 | `eth_call(queryNameState)` | 多数名称事件一次；文档、alias 等事件也会再次调用 |
| 补文档状态 | `eth_call(getDocumentVersion)` | document publish/revoke/payment 事件各一次 |
| 补 authority/alias/checkpoint | 对应 `eth_call` | 对应事件各一次 |
| 保存游标 hash | `eth_getBlockByNumber(to_block)` | 每个实际完成的同步分片一次 |

正常已有游标且投影追平时，一次循环固定是 3 次 RPC：

```text
eth_chainId
eth_blockNumber
eth_getBlockByNumber(cursor)
```

因此当前空闲日调用量近似为：

```text
3 * 86,400,000 / interval_ms
```

Rust 命令行缺省值和仓库内 `web3-gateway/start.py` 都是 1000 ms；正式线上实例如果由外部 cluster settings 覆盖，应先代入实际 `interval_ms`，再与 RPC 账单核对。

有新区间时，一次同步分片的基础调用量为：

```text
5 + T + C
```

其中：

- 5 = chain ID、链头、旧游标 hash、getLogs、新游标 hash；
- `T` = 该分片中包含 registry event 的不同交易数；
- `C` = 各事件触发的合约状态 `eth_call` 数。

例如同一笔注册交易产生 `NameRegistered` 和一个 `DocumentPublished` 时，当前路径通常至少增加一次 transaction lookup、一次名称读取、一次重复名称读取和一次文档读取。也就是说，该分片大致会产生 9 次 RPC，而不是只有链头和 `getLogs` 两次。

#### BNS-Server 方法

代码位置：[`bns-server/src/lib.rs`](../../src/components/bns-server/src/lib.rs)。

| BNS 方法 | 当前上游链 RPC | 单次调用量 |
| --- | --- | ---: |
| 普通名称、owner、authority、document、event 查询 | 无，读取 SQLite | 0 |
| `system.info` | `eth_chainId` | 1 |
| `tx.prepare` | chain ID、pending nonce、estimate gas、gas price、priority fee | 5 |
| `tx.submit_raw` | `eth_sendRawTransaction` | 1 |
| `tx.query_state`，未出 receipt | receipt + transaction by hash | 2 |
| `tx.query_state`，已有 receipt | receipt + latest block number | 2 |

`tx.prepare` 中的 chain ID 和 contract address 实际是进程级不变量，但现在每次都通过 `system_info()` 重新读链。fee 的两个读取也没有短 TTL 或按区块缓存。

`tx.query_state` 没有 receipt 缓存、pending/not-found 缓存或相同 tx hash 的并发合并。即使 receipt 已经确认，下一次查询仍重新读取 receipt 和链头。

#### 客户端对 `tx.query_state` 的放大

BNS WebUI 默认轮询策略位于 [`config.ts`](../../src/apps/bns-webui/src/bns_model/config.ts)：

- 前 30 秒：每 2 秒一次；
- 30 秒～5 分钟：每 5 秒一次；
- 之后：每 15 秒一次；
- `not_found` 和 `indexer_lagging` 不是终态，可持续轮询。

在 server 没有缓存的情况下，单笔交易仅前 30 秒约产生 15～16 次 BNS 查询，即约 30～32 次链 RPC；持续到 5 分钟约产生 138 次链 RPC；进入 tail 阶段后仍约为 8 次链 RPC/分钟。多个浏览器、多个本地恢复记录和 SN receipt waiter 会叠加。

SN 注册等待使用 500 ms 的默认 receipt 间隔。它通过 BNS-Server 查询时，一笔活跃注册最多可形成约 4 次上游链 RPC/秒。

### 4.2 SourceDAOBackend

主要链逻辑集中在 `/root/work/SourceDAOBackend/src/server/src/chain_client.rs`，HTTP handler 只访问 storage 或内存 status。

#### 启动阶段

- 创建一个长期存在的 Alloy `DynProvider`，所有合约实例共享该 provider；
- provider 配置最多 3 次重试、3 秒重试间隔；
- 一次性读取各子合约地址和 chain ID；
- token symbol/decimals 只在首次填充时逐项读取；
- 7 个 token/treasury 数值通过一次 Multicall 聚合读取，失败才降级为 7 次独立 `eth_call`。

#### 长驻阶段

- 链扫描追平后 sleep 15 秒；
- 一次 `eth_getBlockByNumber("latest")` 同时得到 block number 和 timestamp；
- 发现新区间后，用一次合并 address filter 的 `eth_getLogs` 读取所有关注合约的事件；
- 追赶历史区间时不 sleep，直到再次超过已知链头；
- 大部分事件直接使用 log 字段更新 storage；只有事件中缺少必要详情时才 `eth_call`；只有 `ProjectCreate` 等确实需要发送者信息时才读取 transaction；
- token/treasury 状态约每 60 秒用一次 Multicall 刷新；
- `/status`、`/contract/info`、`/contract/token` 等 HTTP API 返回内存状态，不把一次用户请求直接放大成一次链请求。

SourceDAOBackend 的静态空闲后台量约为：

```text
链头轮询：86400 / 15 = 5,760 次/天
token Multicall：最多约 86400 / 60 = 1,440 次/天
合计：约 7,200 次/天（不含启动和真实链事件）
```

## 5. 关键差异

| 维度 | bns_dv | SourceDAOBackend | 对 bns_dv 的影响 |
| --- | --- | --- | --- |
| provider 生命周期 | indexer、server 各自创建 client | 一个 provider clone 给所有合约实例 | `bns_dv` 内无法共享链头、fee、receipt 和限流状态 |
| chain ID | 每个 `sync_once`；`system.info`/`tx.prepare` 也会读取 | 启动时读取并缓存 | 纯固定消耗，且随 API 请求放大 |
| 空闲链头间隔 | 默认 1 秒 | 15 秒 | indexer 固定调用量相差 45 倍 |
| 链头信息 | `eth_blockNumber`，hash 另查 | 一次 latest block 同时拿 number/timestamp | BNS 每轮方法数更多 |
| 追赶调度 | 每个分片后仍 sleep `interval_ms` | 有 backlog 时连续扫描 | BNS 空闲过快、追赶反而被人为减速 |
| 失败调度 | 下一轮通常 1 秒后重试 | event 失败等 30 秒，provider 还有重试配置 | 限流/故障时 BNS 容易形成持续压力 |
| reorg | 每轮检查 cursor block hash | 无显式 hash 检查 | BNS 更正确，但检查频率不合理 |
| transaction lookup | 所有 registry event 都先尝试读取 tx | 只有确需 signer 等信息的事件才读取 | BNS 对普通事件产生额外请求 |
| 合约状态补读 | 多数事件 1～2 次，且同批次会重复读相同 name | 大部分直接用 event，少数补读 | BNS 请求量随事件数快速增长 |
| 批量读取 | 没有 JSON-RPC batch/Multicall | 7 个周期性 view call 用 Multicall | BNS 多个独立 `eth_call` 无法聚合 |
| 用户 API | tx/system/prepare 会同步打链 | handler 基本只读 DB/内存 | BNS 流量随在线用户和未完成交易数增长 |
| receipt 策略 | 每次查询重新读；无 singleflight/TTL | backend 不提供对应能力 | BNS 独有的主要活动流量源 |
| RPC 健壮性 | 自定义 reqwest client，无显式 timeout/retry/backoff | Alloy provider 有 retry；业务循环有较长退避 | 故障时既不稳定也不节流 |

## 6. 建议的目标链访问模型

在现有下层 crate `bns-evm` 内引入 `BnsChainClient`。它内部持有现有 `EthRpcClient` transport 和共享运行状态，只负责链交互，不承载 BNS 业务规则。

`bns_dv serve` 启动时创建一个 `Arc<BnsChainClient>`，注入：

- `BnsContractEventIndexer`；
- `BnsContractServerHandler`；
- 后续新增的、属于 `bns_dv` 进程内的链访问能力。

上述组件不再直接创建或长期持有各自的 `EthRpcClient`，而是通过同一个 `BnsChainClient` 访问链。为了不改变上下游依赖：

- `BnsChainClient` 放在 indexer/server 已经依赖的 `bns-evm`，不新增反向依赖或 crate 依赖环；
- 保留现有 public trait、构造入口和数据结构，新增注入构造入口供 `bns_dv` 使用；旧入口可内部创建独立 `BnsChainClient` 作为兼容包装；
- 不修改 `BnsEvmControllerClient` 及任何 controller 代码，不把 Controller 注入正式服务路径；`smoke` 和本地 SN 集群初始化路径保持独立；
- 不要求其他进程注入或共享 `bns_dv` 的内存实例；其他进程通过现有 BNS API 与 `bns_dv` 交互；
- 不修改 BNS-Server、BNS-Indexer、cyfs-sn、WebUI 的公开 API 和依赖方向。

建议维护以下状态：

- 启动时验证后的 `chain_id`、contract address；
- 最新链头 `{number, hash, parent_hash, fetched_at}`；
- 最近一次通过 reorg 校验的 cursor/head；
- 短 TTL fee suggestion；
- 按 tx hash 缓存的 receipt/pending/not-found 状态；
- 相同 key 并发请求的 singleflight；
- 后台同步状态，用于区分 backlog、idle 和错误后的固定 30 秒等待。

同时由该实例提供 Multicall 聚合入口：接收一组相互独立、使用同一 block tag 的合约只读调用，一次提交到目标链已有的 Multicall3，按原顺序解码结果；聚合失败时才退回现有逐个 `eth_call` 路径。

普通业务读仍然直接读取 SQLite，不经过该层。

## 7. 候选优化详细说明

本节说明各项候选改动的技术内容，不代表提交顺序。实际优先级、状态和“一项方案对应一次提交”的拆分见第 11 节。

### 7.1 统一 `BnsChainClient` 边界

第一步只做结构收敛，不同时加入缓存或改变 RPC 行为：

- 在 `bns-evm` 新增 `BnsChainClient`，内部委托现有 `EthRpcClient`；
- `bns_dv` 只创建一个实例；
- indexer/server 新增接收 `Arc<BnsChainClient>` 的构造入口；
- 现有构造入口和测试入口继续可用；
- 将 indexer/server 的直接 RPC 调用改为通过该实例；
- controller 代码以及本地测试初始化路径使用的 `EthRpcClient` 保持不动，不纳入服务侧共享实例。

这个提交的验收目标是“调用结果和调用次数完全不变，但链访问入口已经集中”，为后续把优化限制在 `BnsChainClient` 内创造条件。

### 7.2 用 Multicall 聚合顺序 `eth_call`

SourceDAOBackend 已经把 7 个顺序执行的 token/treasury view call 通过 Alloy provider 的 `multicall().add(...).aggregate()` 合成一次 `eth_call`，仅在聚合失败时回退为 7 次独立调用。这个优化的目标就是减少 RPC provider 统计的 `eth_call`/credit 消耗，而不只是减少 HTTP 往返。

`bns_dv` 可以采用同样方式：

- 在 `BnsChainClient` 内提供 Multicall3 聚合方法，indexer/server 不直接依赖具体 ABI 和地址处理；
- 使用现有 RPC endpoint、现有进程和目标链已有的 Multicall3，不新增服务、endpoint、合约部署或 Controller 依赖；
- 将同一投影过程或同步分片中相互独立、都读取 `latest` 的 name/document/authority/alias/checkpoint 调用收集后一次执行；
- 保持调用与返回值的稳定顺序，并分别使用原有 ABI 解码，业务结果不变；
- 聚合失败时回退到现有逐个 `eth_call`，保证兼容性，但回退只作为异常路径。

一组 `N` 个顺序 `eth_call` 在正常路径会变为 1 个 `eth_call`。这与 JSON-RPC batch 不同：batch 只减少 HTTP 往返，provider 仍可能逐个统计内部 method；Multicall3 在链上执行多个只读调用，对 RPC provider 表现为一次 `eth_call`。本方案不改变上下游接口和依赖方向，也不需要修改 controller。

### 7.3 状态感知的同步调度

把固定 `sync_once -> sleep(interval)` 改为：

1. 启动时校验一次 chain ID；连接重建、连续错误或低频安全审计时再复核，而不是每秒复核。
2. 有 backlog 时按 block range 连续处理，成功完成一个分片后立即处理下一个分片，不执行 idle sleep。
3. 每个 backlog 分片使用现有 `BnsIndexerSyncConfig.max_block_span`，默认值从 1000 调整为 500，并由 `bns_dv serve --max-block-span <n>` 覆盖。
4. 追平后按现有 `interval_ms` 进入 idle sleep，再读取一次 latest block header；`interval_ms` 默认值从 1000 ms 调整为 15000 ms，继续由现有 `--interval-ms` 覆盖。
5. 后台同步中的任意链操作失败时，本轮终止并固定暂停 30 秒，然后从持久化 cursor 重试；不设计多级指数退避或 jitter。

这样 `interval_ms` 只控制已经追平后的链头检查频率，不再限制历史追赶速度；`max_block_span` 只控制单次 backlog 请求和事务的规模。

### 7.4 合并链头读取并降低 reorg 检查频率

当前 `eth_blockNumber` 只给高度，随后还要查 block hash。建议以 latest block header 为主：

- `confirmations=0` 且 cursor 正好位于 head 时，latest header 的 hash 可同时完成链头读取和 cursor 校验；
- 链头没有变化时，不重复读取同一个 cursor block；
- 链头前进时，在处理新区间前校验一次必要 ancestor；
- 为防同高度 reorg，可额外做 30～60 秒一次的低频 hash 审计；
- 发生 reorg 后继续沿用当前 reset/replay 语义。

这不是删除 reorg 检测，而是把“每秒重复验证同一事实”改为“链头变化驱动 + 低频兜底”。

### 7.5 按调用来源统一链错误处理

直接采用 SourceDAOBackend 的固定策略，不在 `BnsChainClient` 内设计复杂的重试、指数退避、jitter 或调用方限流状态：

- 启动校验、indexer 等由 backend 自主管理的后台链操作发生任何错误时，结束本轮处理，固定暂停 30 秒后从持久化状态重试；
- `system.info`、`tx.prepare`、`tx.submit_raw`、`tx.query_state` 等由外部 API 请求触发的链操作发生错误时，立即把错误返回给调用方，不在请求生命周期内 sleep 或自动重试；
- 外部调用方沿用现有重试或重新发起请求的机制，backend 不替它延长单次请求；
- Multicall 聚合失败时仍可先走既定的逐个 `eth_call` 兼容回退；若回退也失败，则按上述后台/API 来源处理。

这使错误语义只保留“后台 30 秒后重试”和“外部请求立即失败”两种，不需要为不同 JSON-RPC 错误码维护不同退避阶梯。`eth_sendRawTransaction` 也不在 server 内自动重发，避免网络结果不确定时重复提交。

### 7.6 只在需要 calldata 时读取 transaction

当前调用顺序是先对每条 registry event 执行 `decoded_call_for_log`，再进入 `projection_for_record`。但 calldata 当前只被以下投影使用：

- `AuthorityKeysUpdated`：恢复 authority key updates；
- `ControllerPolicyUpdated`：恢复 controller rules。

应先识别 event 类型，只有这两类或以后明确需要 calldata 的类型才调用 `eth_getTransactionByHash`。这个改动不改变投影值，是低风险高收益项。

### 7.7 同一同步批次收集、去重后再读取

先解码整个 `eth_getLogs` 结果，建立需要补读的唯一 key 集合：

- transaction hash；
- name；
- `(name, doc_type, version)`；
- authority set、alias、checkpoint。

然后统一从 `latest` 读取并回填投影，避免同一交易的 `NameRegistered + DocumentPublished` 对同一 name 重复 `queryNameState`。

这里继续使用 `latest` 是有意选择，而不是待修复的历史精确性问题：

- 久远事件之后没有同类状态变更时，latest 就是该事件最终应投影的状态；
- 久远事件之后还有状态变更时，较早事件补读可能提前得到未来状态，但继续处理后续事件时会再次读到并收敛到相同的最新正确状态；
- event log 本身仍按真实事件顺序和内容持久化，latest 只用于补充当前状态投影；
- catch-up 未完成时 backend 不适合承接依赖最新 guard/state 的写操作，因此不要求暴露每个历史瞬间的可操作中间态。

收集、去重后的调用直接交给 7.2 的 Multicall 聚合入口。JSON-RPC batch 仍只作为减少 HTTP 往返的可选 transport 优化，不能替代 Multicall；调用量效果通过现有 API 页面和 RPC 服务侧数据验证，不在代码中新增统计。

### 7.8 `tx.query_state` 的 singleflight 与分状态缓存

在不修改 kRPC 行为和 controller 的前提下，在 server 使用的 `BnsChainClient` 内实现：

- 同一 tx hash 的并发查询合并为一个上游请求；
- receipt 一旦存在，缓存 receipt 的 status、block number、block hash；确认数用共享最新链头计算，不再每次重复读取 receipt 和 `eth_blockNumber`；
- 未确认 receipt 使用 1～2 秒短 TTL；pending/not-found 使用 2～5 秒 TTL；
- `eth_getTransactionByHash` 只用于区分 pending 和 not-found，可用比 receipt 更长的 10～30 秒 TTL；
- indexer 已观察到某 tx 的 log 时，可给状态缓存提供“该交易已成功进入某区块”的正向提示，但不能作为所有交易状态的唯一来源；
- reorg 发生时，失效受影响区块之后的 terminal receipt cache。

这样多个 WebUI/SN 同时查询一笔交易时，上游调用量由“客户端数 × 轮询次数 × 2”收敛为“每个 TTL 窗口最多一组读取”。WebUI、cyfs-sn 和 controller 代码均不需要修改。

### 7.9 `tx.prepare` 缓存不变量和 fee

保持 nonce 和 gas estimate 的实时性，但在 server 使用的 `BnsChainClient` 内减少其他调用：

- chain ID 和 contract address 使用启动时已验证的值；
- fee suggestion 按最新区块或 2～5 秒 TTL 缓存；
- 支持时可用一次 `eth_feeHistory` 生成 EIP-1559 建议，或用现有 transport 实现 JSON-RPC batch；
- `eth_getTransactionCount(from, "pending")` 对任意外部钱包仍按请求读取，不建议像托管 signer 一样长期缓存 nonce；
- `eth_estimateGas` 仍按 calldata 读取。

常规 `tx.prepare` 可从 5 次链 RPC 降为 2 次（fee cache 命中）或 3 次（需要刷新 fee），而不改变客户端签名参数结构。

### 7.10 事件/calldata 优先，缺失字段才回链

SourceDAOBackend 的主要节省来自“大部分事件直接更新 storage”。BNS 也可以逐事件迁移：

- NameRegistered/Renewed/Transferred/OwnerUpdated/Released 等先用 event 字段对本地状态应用 delta；
- alias、namespace、owner IAT floor、checkpoint 等 event 已携带主要变更值，优先直接投影；
- document 内容和 authority/controller 规则可从已签名交易 calldata 恢复，并用 event 中的 hash/root 校验；
- 只有 event 和 calldata 都不足以重建的字段才执行 latest `eth_call`。

这是影响范围最大、风险最高的候选项，会触及 projector，而不仅是 RPC 调度。必须以同一批历史区块同时跑旧、新 projector，对 SQLite 最终结果做逐字段 diff 后再切换。只有前述优化仍不能满足目标时才实施。

## 8. 不建议直接照搬 SourceDAOBackend 的部分

1. **不要删除 BNS reorg 检测。** SourceDAOBackend 没有同等级检测，这不是需要复制的差异。
2. **不要修改 controller，也不要把它引入正式服务路径。** `bns_dv` 的 Controller 只服务于 `smoke` 和基于 Anvil 的本地完整 SN 集群初始化；正式服务的链访问只由 indexer 和 server handler 完成。
3. **不要改变上下游依赖。** `BnsChainClient` 应放在现有公共下层并保留兼容入口，不能让 `bns-evm` 反向依赖 indexer/server，也不能要求调用方改变公开 API。
4. **不需要为历史补读引入 block tag。** 当前目标是最终最新状态投影，使用 latest 能在追赶结束后正确收敛，且改动更集中。
5. **不要为了减少 RPC 缓存任意钱包的 nonce。** SourceDAOBackend 不承担 relay；BNS `tx.prepare` 面对外部钱包时必须读取 pending nonce。
6. **不要用 JSON-RPC batch 代替 Multicall。** batch 内的子请求仍可能被 RPC provider 分别计数；Multicall 才是把多个 view call 合成一个 `eth_call` 的主要降耗路径。实际降幅通过现有 API 页面和 RPC 服务侧数据验证。
7. **不要只把 interval 调大。** 固定大间隔会同时拖慢历史追赶；正确方式是 backlog 与 idle 使用不同调度。

## 9. 建议的改动文件边界

第一项 `BnsChainClient` 收敛方案只应触及既有链交互和装配文件：

- `src/components/bns-evm/src/rpc.rs`
  - 保留底层 JSON-RPC transport；
- `src/components/bns-evm/src/lib.rs`
  - 导出新增 chain client module/type；
- `src/components/bns-evm/src/chain_client.rs`（建议新增）
  - `BnsChainClient`、共享链配置和后续运行态缓存的唯一归属；
- `src/components/bns-indexer/src/sync.rs`
  - 新增 chain client 注入入口，链调用改经 `BnsChainClient`；
- `src/components/bns-server/src/lib.rs`
  - 新增 chain client 注入入口，server 链调用改经 `BnsChainClient`；
- `src/components/bns-server/src/bin/bns_dv.rs`
  - 创建并装配唯一 `Arc<BnsChainClient>`。

第一阶段不需要修改：

- BNS Solidity 合约和 ABI；
- `BnsIndexerApi` 对外方法签名；
- `BnsEvmControllerClient` 及其他 controller 代码；
- 现有 crate 依赖方向和上下游公开构造/调用关系；
- BNS WebUI 轮询状态机；
- cyfs-sn 注册、DNS 和鉴权业务流程；
- SQLite 中名称、文档、权限等业务 schema。

如果实施 7.10 的事件 delta projector，会修改 `bns-indexer` 的投影实现，但其输入、输出和持久化业务语义必须保持不变，应作为独立后续改动。

## 10. 验证与验收建议

### 10.1 RPC 调用量测试

扩展现有 mock RPC 测试，至少钉死：

1. 已追平、链头不变的 N 次调度：chain ID 不随 N 重复，cursor block hash 不每轮重复读取。
2. 新区间出现：每个 range 只有一次 `eth_getLogs`；默认每次最多处理 500 个 block，`--max-block-span` 能覆盖该值，追赶期间不执行 idle sleep。
3. 同一组 N 个独立 view call 在 Multicall 正常路径只产生一次 `eth_call`，各项返回值与逐个调用一致；聚合失败时能回退到 N 次原有调用。
4. 普通 Name/Document 事件不会无条件触发 `eth_getTransactionByHash`；authority/controller 仍能正确恢复 calldata。
5. 同批次相同 name 和 document key 只补读一次。
6. 100 个并发 `tx.query_state(same_hash)` 在同一 TTL 窗口最多形成一组上游 receipt/transaction 请求。
7. terminal receipt 重复查询不再读取 receipt；确认数随共享 head 正确增加。
8. 后台链操作发生任意错误后固定等待 30 秒再重试；相同错误发生在外部 API 请求路径时立即返回，server 内不 sleep，也不重试该次失败的 RPC。
9. reorg 后 cursor reset、投影重放和 receipt cache 失效仍与当前语义一致。

### 10.2 投影一致性测试

- 用固定历史区块范围分别运行优化前后 indexer；
- 比较 names、documents、authority sets/keys、aliases、controller policies、events、checkpoint 和 cursor；
- 对 register、applyMutations、多文档、release、alias、authority/controller 更新分别覆盖；
- 增加“同一名称在多个历史块连续变化”的 catch-up 用例，验证较早事件即使从 latest 提前读到最终状态，完整追赶后的 SQLite 最终状态仍与链上 latest 一致。

### 10.3 线上验收数据

建议通过现有 API 页面和 RPC 服务侧数据，以 24 小时窗口观察：

- 无链活动时，后台链头请求接近 `86400 / idle_interval_seconds`，15 秒间隔约 5,760 次/天，而不是 259,200 次/天；
- `eth_chainId` 只在启动、低频审计或连接切换时出现；
- 没有新区间时不出现每秒 `eth_getBlockByNumber(cursor)`；
- 有 backlog 时按默认 500 block 分片连续处理；发生链错误后，相邻后台尝试之间约隔 30 秒；
- 可聚合的连续 view call 在正常路径按组表现为一次 `eth_call`，逐个 `eth_call` 只在 Multicall 回退路径出现；
- transaction lookup 数量接近真正需要 calldata/signer 的交易数，而不是所有 registry transaction 数；
- `tx.query_state` 上游请求量不随同一 tx 的并发客户端数线性增长；
- indexer lag、交易确认延迟和现有 API 错误率没有回归；
- reorg 测试仍能自动 reset/replay。

## 11. 优化实施方案

以下顺序同时表示实施优先级：越靠前优先级越高。在依赖关系允许的情况下，方案大致按改动影响范围和回归风险从小到大排列。`OPT-01` 虽涉及多个构造位置，但只做内部结构收敛、不改变行为，是所有后续方案的前置条件。

状态标记规则：

- `[TODO]`：尚未实现；
- `[DONE <full commit hash>]`：已经通过一次独立提交实现；
- 每个 `OPT` 必须对应且只对应一次提交；实现时不得顺带合入下一项方案；
- 当前代码快照中以下优化均未实现，因此全部标为 `[TODO]`。完成某项后，在本节把它更新为 `[DONE <full commit hash>]`。

### OPT-01 `[TODO]` 抽出并统一使用 `BnsChainClient`

- **提交：** 待实现，一次提交。
- **目标：** 在 `bns-evm` 新增单独的 `BnsChainClient` 实例，`bns_dv` 创建唯一 `Arc`，indexer 和 server 的所有直接链交互改经该实例。
- **影响：** 只调整内部链访问边界和构造装配；RPC 方法、次数、时序和返回值保持不变。
- **兼容：** 保留既有 public trait/构造入口；不改变 crate 依赖方向；不修改 `BnsEvmControllerClient`、cyfs-sn 或 WebUI，不把本地测试初始化使用的 Controller 接入服务侧共享实例。
- **验收：** 现有测试全部通过；mock RPC 调用序列与改造前一致；`bns_dv` 内 indexer/server 不再各自创建长期 `EthRpcClient`。

### OPT-02 `[TODO]` 用 Multicall 聚合顺序 `eth_call`

- **提交：** 待实现，一次提交。
- **目标：** 在 `BnsChainClient` 增加 Multicall3 聚合入口，把同一投影过程或同步分片内相互独立的 latest view call 收集后一次执行；失败才回退到逐个 `eth_call`。
- **影响：** 正常路径把一组 N 次 `eth_call` 降为 1 次，可直接大幅降低 RPC provider 的 `eth_call`/credit 消耗；继续使用现有 endpoint 和目标链能力，不新增运行服务、合约部署、上下游依赖或 Controller 改动。
- **验收：** mock 中 N 个可聚合读取只产生一次 `eth_call`，结果与原路径逐字段一致；Multicall 失败时可靠回退；通过现有 API 页面确认 `eth_call` 消耗下降。

### OPT-03 `[TODO]` 缓存链级不变量

- **提交：** 待实现，一次提交。
- **目标：** `chain_id` 和 contract address 在 `BnsChainClient` 启动时验证并缓存；只在连接切换、连续错误或低频安全审计时复核。
- **影响：** 删除每个 `sync_once` 和每个 `system.info`/`tx.prepare` 对 chain ID 的重复读取；对外返回值不变。
- **验收：** 空闲运行时不再每秒出现 `eth_chainId`；错误 endpoint/chain 仍能在启动或切换时被拒绝。

### OPT-04 `[TODO]` 按调用来源统一链错误处理

- **提交：** 待实现，一次提交。
- **目标：** 采用 SourceDAOBackend 的简单规则：启动校验、indexer 等后台链操作发生任意错误后固定暂停 30 秒再重试；外部 API 触发的链操作发生错误时立即返回，由外部调用方重新请求。
- **影响：** 不引入指数退避、jitter、按错误码区分的重试阶梯或请求内自动重试。正常成功路径不变；`eth_sendRawTransaction` 错误也直接返回，不在 server 内自动重发。
- **验收：** mock 任意后台 RPC 错误后，下一次尝试固定发生在 30 秒后并能从持久化状态继续；mock `system.info`、`tx.prepare`、`tx.submit_raw`、`tx.query_state` 链错误均立即返回，单次 API 请求内没有 sleep，也不重试该次失败的 RPC。

### OPT-05 `[TODO]` 改为 backlog/idle 分离的同步调度

- **提交：** 待实现，一次提交。
- **目标：** 有 backlog 时连续处理分片；追平后才按现有 `interval_ms` sleep，默认值改为 15000 ms。将现有 `max_block_span` 默认值从 1000 改为 500，并新增 `bns_dv serve --max-block-span <n>` 覆盖入口。
- **影响：** `interval_ms` 只控制 idle 链头检查；`max_block_span` 只控制单次 backlog 处理的区块长度。改变默认轮询间隔和分片大小，但不改变扫描边界、cursor、事件顺序或投影语义。
- **验收：** 默认配置下，无活动时每 15 秒检查一次链头；1501 个 block 的 backlog 按 500、500、500、1 连续处理且分片间不 sleep；显式 `--interval-ms` 和 `--max-block-span` 均生效；错误路径遵循 OPT-04 的固定 30 秒等待。

### OPT-06 `[TODO]` 合并 latest head 与 reorg 校验

- **提交：** 待实现，一次提交。
- **目标：** 缓存 latest header；链头不变时不重复读取同一 cursor block；链头变化时校验必要 ancestor，并保留低频同高度 reorg 审计。
- **影响：** 减少 `eth_blockNumber + eth_getBlockByNumber(cursor)` 的重复组合；保留现有 reset/replay 行为。
- **验收：** 15 秒 idle 配置下后台链头量接近 5,760 次/天；已有 reorg 测试继续通过；同高度 reorg 审计可触发 reset。

### OPT-07 `[TODO]` transaction lookup lazy 化

- **提交：** 待实现，一次提交。
- **目标：** 只有 `AuthorityKeysUpdated`、`ControllerPolicyUpdated` 等真正使用 calldata 的事件才调用 `eth_getTransactionByHash`。
- **影响：** 只删除未使用的链读取，不改变任何投影结果。
- **验收：** 普通 name/document 事件不产生 transaction lookup；authority/controller 投影与当前结果逐字段一致。

### OPT-08 `[TODO]` 缓存并合并 `tx.query_state`

- **提交：** 待实现，一次提交。
- **目标：** 在 `BnsChainClient` 对同一 tx hash 做 singleflight、receipt cache、pending/not-found 短 TTL；确认数由共享 head 计算。
- **影响：** kRPC、WebUI、cyfs-sn 和 controller 完全不改；短 TTL 内允许返回同一状态快照。
- **验收：** 100 个并发相同 tx 查询在一个 TTL 窗口只形成一组上游读取；reorg 能失效相关 receipt；状态机结果不变。

### OPT-09 `[TODO]` 缓存 `tx.prepare` 的不变量和 fee suggestion

- **提交：** 待实现，一次提交。
- **目标：** 使用已验证 chain/contract，fee 按 head 或 2～5 秒 TTL 缓存；pending nonce 和 gas estimate 仍逐请求读取。
- **影响：** 常规 prepare 从 5 次链 RPC 降到 2～3 次；不改变签名参数结构，不缓存任意钱包 nonce。
- **验收：** fee cache 命中/失效符合预期；连续外部钱包交易不发生 nonce 冲突；现有 prepare 测试通过。

### OPT-10 `[TODO]` 同步批次内去重 latest 状态补读

- **提交：** 待实现，一次提交。
- **目标：** 先收集完整日志分片，再按 transaction、name、document、authority、alias、checkpoint key 去重补读。
- **影响：** 会调整一个分片内的投影组织方式，但继续从 latest 补读，event 记录顺序和最终 SQLite 状态不变。
- **验收：** 同一交易的 NameRegistered/DocumentPublished 不重复读取同一 name；多历史变更完整追赶后最终状态与链上 latest 一致。

### OPT-11 `[TODO]` 事件/calldata 优先投影

- **提交：** 待实现，一次提交。
- **目标：** 对 event/calldata 已包含完整信息的状态直接投影，只有信息不足时才 latest `eth_call`。
- **影响：** 改动 projector，范围和回归风险最大；只有 OPT-01～OPT-10 后链 API 消耗仍不达标时才实施。
- **验收：** 固定历史区间的新旧 projector 最终 SQLite 逐字段一致；事件 hash/root 校验完整；所有业务 API 和 controller 保持不变。

### OPT-12 `[TODO]` CD 系统适配：原生支持 `--cluster`

- **提交：** 待实现，一次提交。
- **目标：** 为 `bns_dv serve` 新增 `--cluster` 选项。指定后由进程在启动时读取固定位置的 `/etc/cluster_config/cluster_config.json` 和 `/etc/security/security_config.json`，并映射成现有 `serve` 配置：`security.chain_rpc_url` 对应 `--rpc`，`apps.bns_dv.settings` 下的 `contract`、`chain_id`、`db`、`listen`、`start_block`、`confirmations`、`interval_ms` 分别对应现有同名命令行能力；可选 `max_block_span` 对应 OPT-05 新增的 `--max-block-span`，缺省时使用 500。
- **覆盖规则：** 先加载 cluster/security 配置，再合并本次显式指定的其他命令行参数；命令行参数优先，覆盖文件中的对应值。未指定 `--cluster` 时完全沿用当前命令行解析、必填项和默认值行为。
- **迁移边界：** 将当前 `start_bns_dv.ts` 中“读取和校验固定配置文件、转换为现有命令行参数”的能力下沉到 `bns_dv`；不新增另一套业务配置语义，不修改现有参数名称、Controller、链交互或上下游 API。`start_bns_dv.ts` 可在 CD 切换完成前保留为兼容入口；cluster/security 配置本身不提供 seed 或初始化交易，只有本地测试脚本显式传入 `--config`/`--seed-config` 时才进入既有初始化路径。
- **验收：** 仅指定 `--cluster` 可以按两个固定配置文件成功启动，且进程中不创建或调用 `BnsEvmControllerClient`；显式 `--rpc`、`--contract`、`--chain-id`、`--db`、`--listen`、`--start-block`、`--confirmations`、`--interval-ms`、`--max-block-span` 分别能覆盖文件值；缺失、类型错误和非法路径等配置继续启动失败并给出明确错误；不指定 `--cluster` 的现有启动命令以及测试脚本显式使用 `--config`/`--seed-config` 的本地集群初始化行为保持不变。
