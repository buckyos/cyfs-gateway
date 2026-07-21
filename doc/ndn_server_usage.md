# CyfsDirServer 使用文档

> 说明:旧版 `NdnServer` / `NdnServerConfig` 已经在 `beta2.2` 中被移除,
> 当前 cyfs-gateway 中提供 `cyfs://` 语义(R-Link / O-Link)对外服务的
> 是 `CyfsDirServer`(配置中的 `type: cyfs-dir`)。本文档描述的是它的
> 实际实现。

实现位置:[src/components/cyfs-gateway-lib/src/server/cyfs_dir_server.rs](../src/components/cyfs-gateway-lib/src/server/cyfs_dir_server.rs)

注册位置:[src/apps/cyfs_gateway/src/lib.rs:91](../src/apps/cyfs_gateway/src/lib.rs#L91) / [:182](../src/apps/cyfs_gateway/src/lib.rs#L182)

## 概述

`CyfsDirServer` 是一个把 HTTP 请求映射到 `NamedDataMgr` 存储里 chunk /
named object 的服务器。它实现 `HttpServer` trait,可以挂在 cyfs-gateway
的 server 框架下。

它本身**不直接**实现 chunk 读写、inner-path 解析、`cyfs-*` 响应头那一套
逻辑,而是在请求进入前先跑一段 **process chain**,把"语义路径 → ObjId"
的解析做完之后,把改写过的请求**转交给内部的 `NdnDirServer`(来自
`ndn-toolkit`)** 去做实际的内容流式输出。

```
HTTP Request
     │
     ▼
┌──────────────────────┐
│  process chain       │  解析 path → ObjId / SidecarRecord
│  (可选, hook_point)  │  也可以 drop / reject / error / redirect
└──────────────────────┘
     │
     ▼  改写为 O-Link: <url_prefix>/<obj_id>{/@/<inner>?}
┌──────────────────────┐
│  NdnDirServer (内)   │  chunk 流、inner-path、cyfs-* headers、
│                      │  hostname-based O-Link、文件系统回退
└──────────────────────┘
```

## 配置

### 字段说明(`CyfsDirServerConfig`)

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | string | 服务器 ID |
| `type` | string | 必须为 `"cyfs-dir"` |
| `named_store_config_path` | string | `NamedDataMgr` 存储布局配置文件路径 |
| `http_backend_links` | map<string,string> | 远端存储节点的 HTTP base URL,key 是 store 项的 `device_did`;不在表里的 store 当作本地 store。读写都会走 HTTP backend |
| `signing_key_path` | string? | 用于签发 `PathObject` JWT 的 ed25519 PEM 私钥路径。不配置时 R-Link 响应里不会带 `cyfs-path-obj` |
| `signing_kid` | string? | 上述 key 的 kid |
| `semantic_root` | string? | 文件系统语义根。配置后,未被 chain 解析的 R-Link 会回退到本地文件系统;不配置则纯 chain 驱动,文件系统侧一律 404 |
| `url_prefix` | string | 转发到内层 `NdnDirServer` 之前要剥掉的 URL 前缀,如 `"/ndn"`。默认空 |
| `obj_id_in_host` | bool | 是否把 hostname 的首段 label 当作 `ObjId`(O-Link 主机名模式)。默认 false |
| `mode` | string? | 仅当 `semantic_root` 存在时生效的 scanner 持久化模式。可选 `"local-link"`(默认)、`"in-store"` |
| `scan_interval_secs` | u64 | 自动 objectify 扫描间隔(秒)。`0` 关闭扫描器,默认 60 |
| `hook_point` | object? | 可选的 process chain 配置,结构见 `ProcessChainConfigs` |

### YAML 示例

```yaml
servers:
  - id: cyfs_dir_1
    type: cyfs-dir
    named_store_config_path: /etc/buckyos/named_store.json
    url_prefix: /ndn
    obj_id_in_host: true

    # 可选:文件系统回退 + 自动 objectify
    semantic_root: /var/buckyos/dir
    mode: local-link
    scan_interval_secs: 60

    # 可选:R-Link path-obj JWT 签名
    signing_key_path: /etc/buckyos/keys/path_obj.pem
    signing_kid: path-obj-2026

    # 可选:远端存储节点 HTTP backend
    http_backend_links:
      did:bns:node-a: http://10.0.0.5:8080/ndn

    # 可选:进入内层之前先跑一段 process chain
    hook_point:
      chains:
        - id: resolve
          blocks:
            - id: main
              block: |
                # 把 /ndn/foo/bar 解析为某个已知 obj_id
                match REQ_path "^/ndn/foo/bar$" && \
                  set RESP_cyobj_id "5aSixgLwnWbmcSKvpiaLTqJzg7bxqoPYRCZSPu6Y6p5K";
```

### 纯 chain 驱动的最小配置

```yaml
- id: cyfs_dir_chain_only
  type: cyfs-dir
  named_store_config_path: /etc/buckyos/named_store.json
  url_prefix: /ndn
  hook_point: { ... }
```

不配置 `semantic_root` 时,内层只接受 chain 已经解析出来的 O-Link;
没解析出来的请求会落到 `NdnDirServer` 的文件系统回退路径,因为没有
`semantic_root` 所以一律 404。

## Process chain 契约

`hook_point` 配置的 chain 在请求被分发到内层之前执行。chain 拿到的是
标准的 HTTP `REQ_*` 环境(path / method / headers / …),可以通过
**两种**等价方式告诉服务器"这个语义路径解析到哪个对象":

### 方式 1:`RESP_cyobj_meta`(完整 sidecar)

设置环境变量 `RESP_cyobj_meta` 为一段 JSON 字符串,结构与 `NdnDirServer`
落地的 `<name>.cyobj` 文件一致:

```json
{
  "obj_type": "...",
  "obj_id": "5aSixgLwnWbmcSKvpiaLTqJzg7bxqoPYRCZSPu6Y6p5K",
  "obj_json": { ... },
  "path_obj_jwt": "eyJhbGciOi..."
}
```

服务器会:
1. 解析其中的 `obj_id`;
2. 把 `obj_json` 通过 `NamedDataMgr::put_object` 旁路写入 store
   (idempotent,如果已经存在则忽略错误);
3. 把请求 URI 改写为 O-Link 形式后转交给内层。

适合"对象内容由 chain 即时构造、还没在 store 里"的场景。

### 方式 2:`RESP_cyobj_id`(裸 ObjId)

设置 `RESP_cyobj_id` 为一个 `ObjId` 字符串。要求该对象**已经在 store
里**(否则内层会 404)。只做 URI 改写,不会触发 `put_object`。

适合"chain 只负责路由、对象本身已经入库"的场景。

### 没设置任何变量

服务器会让请求按原样穿过 chain,继续走内层 `NdnDirServer` 的常规解析:
- `obj_id_in_host = true` 时识别 hostname 中的 `ObjId`;
- 路径中的 `ObjId`(O-Link);
- 配置了 `semantic_root` 时,按文件系统回退解析 R-Link。

### 控制流

`drop` / `reject` / `error` 与 `ProcessChainHttpServer` 行为一致:

| 控制 | HTTP 响应 |
| --- | --- |
| `drop` | `200 OK`,空 body |
| `reject` | `403 Forbidden`,空 body |
| `error <msg>` | `502 Bad Gateway`,body 为 `<msg>` |
| `return ...` | 当前不用作路由指令,会被忽略 |

chain 内部抛出的执行错误会被映射成 `500 Internal Server Error`。

## URL 改写规则

chain 解析成功后,内部 URI 会被改写为:

```
<url_prefix>/<obj_id>{/@/<inner_path>}{?<query>}
```

- `url_prefix` 来自 server 配置(去掉首尾 `/`);
- `/@/` 之前的部分都被替换成 `obj_id`,`/@/` 之后的 inner path 完整保留;
- query string 原样保留。

例:
- 配置 `url_prefix: /ndn`,请求 `GET /ndn/foo/bar/@/content?x=1`,
  chain 设置 `RESP_cyobj_id = OBJ`,改写后内层看到的是
  `GET /ndn/OBJ/@/content?x=1`。

## 行为委托给内层 `NdnDirServer` 的部分

下面这些都不在 `CyfsDirServer` 自己的代码里,而是 `ndn-toolkit` 的
`NdnDirServer` 提供:

- chunk / chunk list / named object 的实际读取
- `inner_path`(`/@/...`)解析与对象内导航
- HTTP Range / 206 Partial Content
- `cyfs-obj-id` / `cyfs-root-obj-id` / `cyfs-obj-size` / `cyfs-path-obj`
  等响应头
- `obj_id_in_host = true` 时的 hostname O-Link
- 配置了 `semantic_root` 时的文件系统回退 + 自动 objectify scanner
  (`spawn_scanner`,按 `scan_interval_secs` 触发)
- HTTP 版本协商、HTTP/3 端口等

> 这些功能的具体细节请以 `ndn-toolkit` 中 `NdnDirServer` 的实现为准。
> 当 ACL / 权限字段加到 `.cyobj` sidecar 里时,会在 `ndn-toolkit` 先
> 落地,本服务器自动继承。

## Server context

`CyfsDirServer` 在带 `hook_point` 时需要一个 `CyfsDirServerContext`:

```rust
pub struct CyfsDirServerContext {
    pub server_mgr: ServerManagerWeakRef,
    pub global_process_chains: GlobalProcessChainsRef,
    pub js_externals: JsExternalsManagerRef,
    pub global_collection_manager: GlobalCollectionManagerRef,
}
```

cyfs-gateway 在
[`server_registry.rs`](../src/components/cyfs-gateway-app-lib/src/server_registry.rs)
的统一 registration 中为 `cyfs-dir` 绑定了 parser、factory 和 context builder，正常通过
yaml/json 加载配置时不需要手动构造。

## 注册到 ServerManager

应用初始化时通过一个完整 descriptor 一次性注册 parser、factory 和 context builder：

```rust
use cyfs_gateway_app_lib::{
    GatewayServerContextMode, GatewayServerRegistration, GatewayServerRegistryBuilder,
};
use cyfs_gateway_lib::CyfsDirServerFactory;
use cyfs_gateway_app_lib::CyfsDirServerConfigParser;

registry_builder.register(GatewayServerRegistration::new(
    "cyfs-dir",
    "my-module::cyfs-dir",
    Arc::new(CyfsDirServerConfigParser::new()),
    Arc::new(CyfsDirServerFactory::new()),
    GatewayServerContextMode::Required,
    |runtime| Ok(Some(Arc::new(CyfsDirServerContext::new(
        runtime.server_manager.clone(),
        runtime.global_process_chains.clone(),
        runtime.js_externals.clone(),
        runtime.global_collection_manager.clone(),
    )))),
))?;
```

默认的 9 种 Server 由 `register_default_gateway_servers(...)` 集中安装；两个 Gateway
二进制共享这份清单。自定义 profile 可以在 build 阶段向 builder 显式安装自己的完整
registration，registry build 后不可再修改。

## 错误处理

| 来源 | 状态码 |
| --- | --- |
| chain `drop` | 200 |
| chain `reject` | 403 |
| chain `error` | 502 |
| chain 执行异常 / 解析失败 | 500 |
| 内层 `NdnDirServer` 的常规结果 | 200 / 206 / 4xx / 5xx |

`RESP_cyobj_meta` 字段无效(JSON 格式错、`obj_id` 不合法等)会被当成
chain 执行异常,返回 500。

## 相关文档

- [DIR Server 使用文档](dir_server_usage.md) — 纯文件系统的 HTTP 静态服务器
- [Process Chain 核心模型](process_chain_core_model.md)
- [Process Chain Gateway 外部命令](process_chain_gateway_external_commands.md)
- [编写复杂的 process_chain](编写复杂的 process_chain.md)
