# RTCP 新入站 Tunnel 替换旧 Tunnel TODO

状态：已完成（2026-07-24）

相关文档：

- [rtcp.md](rtcp.md)
- [rtcp_v2_review.md](rtcp_v2_review.md)
- [tunnel框架.md](../tunnel框架.md)

主要实现：

- `src/components/cyfs-gateway-lib/src/rtcp/rtcp.rs`

完成内容：

- `RTcpTunnel` 增加进程内唯一 `instance_id`。
- map API 明确拆分为 `register_outbound_if_absent`、`replace_authenticated_inbound` 和 `remove_if_current`。
- 入站替换在 map 临界区内同步标记旧实例 closed 并原子切换 current，锁外完成 waiter 清理和 transport shutdown。
- `run()` 可被 close 主动唤醒；自然退出同样进入幂等 close，Open/ROpen/Pong 和 pending HelloStream waiter 会快速释放。
- `ping`、`ping_rtt`、stream/datagram 创建、reconnect 和入站 Open/ROpen 处理均检查 closed 状态。
- 出站路径仍为 first-wins，但只在存活实例间生效：map 中的 closed 实例不参与复用，`create_tunnel` 会先 `remove_if_current` 再重新拨号，`register_outbound_if_absent` 也会替换已 closed 的旧值；入站完整认证和准入后的路径为 last-accepted-wins。

## 目标

为同一对 canonical device DID 定义明确且可并发验证的 Tunnel 冲突语义：

- 客户端主动建连路径继续复用本地已经存在的 Tunnel，不重复拨号。
- 服务端收到一条新的入站 Tunnel，且该连接已经完成身份验证、v2 key-confirmation、应用准入和设备文档提交后，新 Tunnel 必须替换相同 tunnel key 下的旧 Tunnel。
- 被替换的旧 Tunnel 必须关闭。
- 旧 Tunnel 随后退出读循环时，不得把已经替换进 map 的新 Tunnel 删除。

本文只定义 RTCP Stack 内的 Tunnel 仲裁和生命周期。私钥吊销、设备封禁、DID 文档换钥以及存量业务 stream 的强制撤销不在本任务范围内。

## 修复前问题

`RTcpInner::on_new_tunnel` 在新入站连接完成全部握手和准入后调用 `RTcpTunnelMap::on_new_tunnel`。当前 map 中只要已经存在相同 key，就拒绝并关闭新 Tunnel，旧 Tunnel 继续运行。

该行为存在以下问题：

1. 它与预期的服务端重连语义相反。服务端无法判断两个持有同一设备私钥的实例中哪一个是“旧设备”，应以最后完成全部认证和准入的连接作为当前连接。
2. NAT 半开、网络切换或客户端异常退出可能让旧 Tunnel 长时间留在 map 中，合法重连会持续被拒绝。
3. 当前注释以 AES-GCM `(key, nonce)` 重用为理由拒绝新连接，但这个理由不适用于 RTCP v2。每次握手双方都会生成新的 ephemeral X25519 密钥、nonce 和 challenge，成功的新握手拥有独立的会话密钥；原始 Hello 重放还会被 nonce cache 和 key-confirmation 拒绝。
4. 当前行为与 `doc/tunnel框架.md` 中“新入站 tunnel 命中相同 key 时，会替换旧 tunnel”的说明不一致。

## 规范语义

### 1. Tunnel identity

继续使用现有 canonical key 规则：

```text
direct:
<local_dev_did>_<remote_dev_did>

bootstrap:
<local_dev_did>_<remote_dev_did>|bootstrap=<bootstrap_url>
```

名字 DID 和 `did:dev` 如果解析到同一个设备公钥，就属于同一个 canonical device identity。目标 DID 的文本表示、名称解析缓存以及连接源 IP 都不改变 tunnel key。

### 2. 客户端出站路径

保持当前行为：

- `RTcpInner::create_tunnel` 在拨号前查询 `tunnel_map`。
- 已有相同 key 的 Tunnel 时直接复用。
- 并发创建发生竞速时，只保留先注册成功的本地 Tunnel，关闭本次多建出来的 Tunnel，并返回 map 中的现有 Tunnel。

本任务不得把客户端路径改成“每次请求都重建并替换”。名称 DID 与 `did:dev` 的合并应继续在客户端 canonicalization 阶段完成。

### 3. 服务端入站路径

服务端采用 **last accepted connection wins**：

```text
接收 TCP
  -> 验证 Hello / tunnel_token / nonce
  -> 完成 HelloAck / HelloAckConfirm key-confirmation
  -> listener.on_new_tunnel 准入成功
  -> verified device document 提交成功（如有）
  -> 构造新 RTcpTunnel
  -> 原子替换 tunnel_map 中相同 key 的当前 Tunnel
  -> 关闭被替换的旧 Tunnel
  -> 运行新 Tunnel
```

“新”按完成全部验证并执行 map 原子替换的顺序定义，不按 TCP accept 顺序、握手开始时间或源 IP 定义。

任何在身份验证、anti-replay、key-confirmation、listener 准入或设备文档提交阶段失败的连接都不得替换旧 Tunnel。这样未认证连接无法通过反复拨号踢掉合法 Tunnel。

如果新连接使用裸 `did:dev` 且不带 `device_doc_jwt`，`source_device_info` 可以是 `None`。是否允许这种连接替换已有的名字身份连接，由 `RTcpListener::on_new_tunnel` 的准入策略决定：listener 接受后参与正常替换；listener 拒绝则旧 Tunnel 保持不变。

### 4. 替换范围

替换动作关闭旧 RTCP 控制 Tunnel，并阻止该 Tunnel 再创建新的业务 stream/datagram。

已经脱离 Tunnel 控制循环、交给上层处理的存量业务 stream 是否继续存在，保持当前行为，不在本任务中扩展为全会话吊销。

## 实现要求

### 1. 为 Tunnel instance 提供稳定身份

同一个 tunnel key 会先后对应多个 `RTcpTunnel` instance，清理时必须区分具体 instance。可采用以下任一方式：

- 为每个 `RTcpTunnel` 分配唯一、仅用于进程内比较和日志的 `instance_id`。
- 使用一个每个 Tunnel 独有、clone 后共享的 `Arc` identity，并通过 `Arc::ptr_eq` 比较。
- 在 map entry 中维护 generation，并由运行任务持有自己的 generation。

不要用 tunnel key、remote DID 或 AES key 充当 instance identity。

### 2. 原子替换并返回旧 Tunnel

将当前“存在即返回 `Err`”的入站注册 API 改为原子替换 API，例如：

```rust
async fn replace_tunnel(
    &self,
    tunnel_key: &str,
    new_tunnel: RTcpTunnel,
) -> Option<RTcpTunnel>;
```

要求：

- 在一次 map mutex 临界区内完成 `insert`/replace。
- 返回被替换的旧 Tunnel；不存在时返回 `None`。
- map 锁释放后再执行旧 Tunnel 的异步 `close()`，不得持有 map mutex 等待网络 I/O。
- 日志明确区分首次注册和替换，至少包含 tunnel key；如果增加 instance ID，同时记录 old/new instance ID。

如果需要严格保证 map 切换后旧实例不能再发起新操作，可以把“标记 old closed”拆成无 await 的同步操作，在临界区内标记后完成替换，再在锁外 shutdown 写半边。不得因此在 mutex 内执行可能阻塞的 I/O。

### 3. 使用 compare-and-remove 清理

当前 `remove_tunnel(tunnel_key)` 会无条件删除 map entry。改为只允许当前运行实例删除自己，例如：

```rust
async fn remove_tunnel_if_current(
    &self,
    tunnel_key: &str,
    tunnel: &RTcpTunnel,
) -> bool;
```

语义：

- map 中的 value 与调用方 instance 相同时才删除并返回 `true`。
- key 已不存在或已经指向更新的 instance 时不删除并返回 `false`。
- 所有 `tunnel.run().await` 后的清理路径都使用这一接口。

这是本修复的必要条件。否则旧 Tunnel 被关闭并退出 `run()` 后，会通过相同 key 把新 Tunnel 从 map 中误删。

### 4. 保留出站竞速策略

`create_tunnel` 的 bootstrap 和 direct 出站竞速分支仍应保留“本地已有者优先”的语义。不要无差别地把所有 map 插入都改成 last-wins。

建议明确拆分 API，避免调用方混用：

```text
register_outbound_if_absent(...)
replace_authenticated_inbound(...)
remove_if_current(...)
```

具体命名可以按现有代码风格调整，但两种策略必须在类型或方法层面清晰可见。

### 5. 关闭后的旧 Tunnel 必须 fail fast

`RTcpTunnel::close()` 必须保持幂等，并在任何异步 shutdown 之前设置 closed 状态。所有仍可能持有旧 Tunnel clone 的调用方都应观察到该状态：

- `ping` / `ping_rtt` 对 closed Tunnel 返回 `BrokenPipe` 或等价错误，不能吞掉发送失败后返回成功。
- `request_open_stream` 及 datagram 创建路径在执行任何 Open/ROpen、创建 waiter 或发起 reconnect 前检查 closed 状态。
- 安全清理已有的 Open/ROpen/Pong waiters，使替换时正在等待旧 Tunnel 响应的调用尽快失败，而不是等待完整超时。
- 已经创建完成并交给上层的独立业务 stream 不在这里强制关闭。

### 6. 保留 v2 anti-replay

不得削弱以下检查：

- Hello JWT 签名、`aud`、`from`、`to` 和有效期校验。
- `(canonical_source_dev_did, nonce)` replay cache。
- HelloAck 对 initiator ephemeral key 的绑定。
- AEAD `HelloAckConfirm` challenge 校验。
- `RTcpListener::on_new_tunnel` 准入。
- verified device document freshness/CAS 提交。

相同 Hello token 的重放必须继续在进入 tunnel map 仲裁前失败。只有一次全新且完整通过认证的握手才能替换旧 Tunnel。

## 测试清单

- [x] map 单元测试：首次入站注册返回 `None`，map 指向新 Tunnel。
- [x] map 单元测试：第二个相同 key 的入站 Tunnel 原子替换第一个，并返回旧 Tunnel。
- [x] 清理竞态测试：旧 Tunnel 退出后调用 `remove_if_current`，不得删除新 Tunnel。
- [x] 正常清理测试：当前 Tunnel 退出后能够删除自己的 map entry。
- [x] 并发替换测试：多个已认证入站 Tunnel 并发注册时，map 始终只有一个 current instance，最后完成原子注册的 instance 留在 map 中。
- [x] 关闭测试：替换成功后旧 Tunnel 被标记为 closed，后续 ping/open/datagram 不再成功。
- [x] 准入测试：新连接在 `RTcpListener::on_new_tunnel` 被拒绝时，不替换、不关闭旧 Tunnel。
- [x] anti-replay 回归测试：重放相同 Hello/nonce 在 map 仲裁前被拒绝，不替换旧 Tunnel。
- [x] 集成测试：同一设备身份从不同 RTCP instance 建立第二条合法入站连接，新 Tunnel 可 ping/open，旧 Tunnel 退出且延迟清理不删除新 Tunnel。
- [x] 身份表达测试：名字 DID 连接与相同 canonical `did:dev` 连接发生入站冲突时，后完成准入的连接成为 current。
- [x] 身份降级策略测试：listener 允许裸 `did:dev` 时可以替换；listener 拒绝时保留旧名字身份 Tunnel。
- [x] 客户端回归测试：通过名字 DID 建立 Tunnel 后，再通过对应 `did:dev` 调用 `create_tunnel`，仍复用现有 Tunnel，不产生第二次拨号。
- [x] bootstrap 回归测试：不同 bootstrap URL 仍使用不同 key，不互相替换。

建议至少运行：

```bash
cd src
cargo test -p cyfs-gateway-lib rtcp::rtcp::tests -- --test-threads=1
cargo test -p cyfs-gateway-lib --lib -- --test-threads=1
```

验证结果（2026-07-24）：

- `cargo check -p cyfs-gateway-lib --lib`：通过。
- RTCP 测试模块：29 passed，0 failed。
- `cyfs-gateway-lib` 完整 lib 测试：345 passed，0 failed。
- 原有 stream/datagram 测试改用动态端口，避免完整测试中的固定端口冲突。

## 文档同步

- [x] 更新 `doc/rtcp/rtcp.md` §6.2/§14.1，删除“v2 下替换会重用同一 `(key, nonce)`”的过时说明。
- [x] 明确记录 last accepted connection wins、替换发生点和 compare-and-remove 清理约束。
- [x] 确认 `doc/tunnel框架.md` 的行为说明与代码一致。
- [x] 在 `doc/rtcp/rtcp_v2_review.md` 对应问题标记已修复并记录验证范围。

## 验收标准

- 同一 RTCP Stack 内，每个 tunnel key 任意时刻只有一个 current Tunnel。
- 客户端对同一 canonical target 的重复创建继续复用本地 Tunnel。
- 服务端只允许完整通过认证和准入的新入站 Tunnel 替换旧 Tunnel。
- 替换后旧 Tunnel 被关闭，新 Tunnel 保留在 map 中并可正常 ping/open。
- 旧 Tunnel 的延迟退出不会删除或影响新 Tunnel。
- 未认证、重放、key-confirmation 失败或 listener 拒绝的连接不能踢掉旧 Tunnel。
- 名字 DID 与对应 `did:dev` 使用相同 canonical key，并遵循同一替换规则。
- RTCP v2 的 anti-replay 和前向安全性质不因本修复退化。
