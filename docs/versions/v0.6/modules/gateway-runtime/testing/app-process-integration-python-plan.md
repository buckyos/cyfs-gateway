# cyfs_gateway App 进程级 Python 集成测试方案

## 元数据
- version: v0.6
- module: gateway-runtime
- stage: testing-plan
- status: draft
- scope: cyfs_gateway app process integration tests

## 定位
本文档整理 `cyfs_gateway` 真实 app 进程级集成测试方案。该方案不同于现有 Rust 集成测试：

- 不直接调用 `gateway_service_main()`。
- 不做纯 process-chain DSL 语义测试。
- 不使用 `cyfs_gateway debug` 作为主要验证入口。
- 通过 Python 编译并拉起真实 `cyfs_gateway` binary。
- 通过真实配置文件、真实进程、真实客户端请求验证行为。

现有 `src/apps/cyfs_gateway/tests/test_cyfs_gateway.rs` 继续作为库内集成 smoke。本文档描述新增的 Python app 级测试层。

## 目标
- 编译真实 `cyfs_gateway` app。
- 用 Python 生成临时配置并启动 `cyfs_gateway --config_file <path>`。
- 构造 HTTP、DNS、SOCKS、TCP、CLI 客户端请求验证运行时行为。
- 覆盖命令行、配置装载、配置合并、路径归一化、控制平面、网络转发和 process chain 规则在 gateway 中的实际效果。
- 所有 case 使用独立临时目录、独立 `BUCKYOS_ROOT` 和动态端口，避免本地与 CI 环境污染。

## 非目标
- 不替代 `cyfs-gateway-lib` 中 TCP/TLS/UDP/QUIC stack 的单元测试。
- 不单独验证 process-chain engine 的语法与执行语义。
- 不通过 debug 子命令检查内部变量或解释器细节。
- 不依赖固定端口。
- 不把未实现测试直接登记为正式通过的 `testplan.yaml` 步骤。

## 推荐目录
```text
tests/integration/cyfs_gateway_app/
  run.py
  cases/
    test_startup.py
    test_config_loading.py
    test_cli.py
    test_network_runtime.py
    test_process_chain_runtime.py
  lib/
    process.py
    config.py
    ports.py
    http_client.py
    dns_client.py
    socks_client.py
    cli.py
    assertions.py
  fixtures/
    minimal.yaml.tpl
    config_merge/
    process_chain_runtime.yaml.tpl
    local_dns.toml
    js_hook.js
```

## 统一执行流程
`run.py` 负责整体编排：

1. 执行 `cargo build -p cyfs_gateway`。
2. 定位 `src/target/debug/cyfs_gateway`。
3. 为每个 case 创建 `tempfile.TemporaryDirectory()`。
4. 分配动态端口并渲染配置模板。
5. 设置独立 `BUCKYOS_ROOT`。
6. 使用 `subprocess.Popen` 拉起真实 app。
7. 轮询 control server 或 TCP 端口确认 ready。
8. 执行客户端请求与 CLI 子命令。
9. 校验响应、输出、文件或 collection 状态。
10. 结束 case 时 terminate app，超时 kill。
11. case 失败时输出配置路径、stdout/stderr 路径和关键诊断信息。

进程启动示例：

```python
proc = subprocess.Popen(
    [bin_path, "--config_file", config_path],
    cwd=case_dir,
    env={**os.environ, "BUCKYOS_ROOT": buckyos_root},
    stdout=stdout_file,
    stderr=stderr_file,
)
```

## 基础设施要求
- `GatewayProcess` 必须提供 `start()`、`wait_ready()`、`stop()` 和失败诊断输出。
- readiness 不使用固定 `sleep`，应轮询 control API 或目标 TCP 端口。
- 所有端口由 Python 动态分配，并在配置模板中替换。
- 每个 case 的 `BUCKYOS_ROOT` 必须独立，隔离 token、sqlite、saved config、remote cache 和运行时数据。
- app stdout/stderr 必须落盘，失败时打印路径。
- Python runner 可不依赖 pytest，直接维护 case 列表并以退出码作为 harness 结果。

## Harness 接入建议
实现完成后，在 `docs/versions/v0.6/modules/gateway-runtime/testplan.yaml` 的 `integration` level 增加独立步骤：

```yaml
- id: gateway-runtime-app-process-integration
  name: 执行 cyfs_gateway app 进程级集成测试
  run: ["bash", "-lc", "python3 tests/integration/cyfs_gateway_app/run.py"]
```

保留现有 Rust 集成测试步骤，使两个验证层职责清晰：

- Rust integration：库内组装和低成本回归。
- Python app integration：真实 binary、真实 CLI、真实配置、真实客户端调用。

## Case 分组

### 1. App 启动与基础路由
#### `minimal_startup`
- 配置：app 内置 control server，加测试构造的 TCP stack、HTTP server、dir server。
- 操作：启动真实 `cyfs_gateway`。
- 验证：
  - control API ready。
  - HTTP `Host: dir.test` 返回目录文件内容。
  - 进程保持运行直到测试主动停止。

#### `invalid_config_exit`
- 配置：unknown stack protocol 或 unknown server type。
- 操作：启动 app。
- 验证：
  - 进程非 0 退出。
  - 输出包含 `unknown protocol`、`unknown server type` 或等价错误信息。

#### `buckyos_root_isolation`
- 配置：最小可启动配置。
- 操作：连续启动两个 case，各自使用不同 `BUCKYOS_ROOT`。
- 验证：
  - token、saved config、sqlite、cache 不串扰。

### 2. 配置装载与合并
#### `single_file_yaml_json_toml`
- 配置：分别生成 YAML、JSON、TOML 最小配置。
- 验证：三种格式均可启动并响应 control API。

#### `config_dir_root_includes`
- 配置：`root.yaml` include `10-base.yaml`、`20-routes.yaml`。
- 验证：
  - include 文件都参与合并。
  - 合并后的 stack/server 可以真实响应请求。

#### `config_dir_index_order`
- 配置：目录中存在 `base.10.yaml`、`override.20.yaml`。
- 验证：
  - 显式 index 控制 merge 顺序。
  - 后续标量覆盖前序标量。
  - 数组合并去重。

#### `relative_path_resolution`
- 配置：`root_path: ./www`、`js_externals: ./hook.js`。
- 操作：从不同 cwd 启动 app。
- 验证：相对路径按主配置文件所在目录解析。

#### `remote_include_and_cache`
- 配置：本地 Python HTTP server 提供 remote include。
- 验证：
  - 首次启动能下载 remote config。
  - remote server 不可用时可使用本地 cache。
- 备注：该 case 成本较高，可作为第二阶段。

### 3. CLI 行为
#### `cli_help_and_process_chain_docs`
- 命令：
  - `cyfs_gateway --help`
  - `cyfs_gateway process_chain`
  - `cyfs_gateway process_chain call-server`
- 验证：退出码为 0，输出包含预期命令或帮助内容。

#### `cli_gen_rtcp_key`
- 命令：`cyfs_gateway gen_rtcp_key -n test -p <temp_dir>`。
- 验证：
  - `device.key.pem` 存在。
  - `device.doc.json` 存在且可解析。

#### `cli_process_chain_docs_against_runtime_binary`
- 操作：启动 app 后执行不依赖 control token 的 CLI 子命令：
  - `cyfs_gateway process_chain call-server`
  - `cyfs_gateway process_chain --all`
- 验证：退出码为 0，输出包含 `call-server`、`proxy-protocol-probe` 等已注册命令文档。
- 说明：app 进程级测试配置不声明 `__control_server__`；控制面由 `cyfs_gateway` 内置 `gateway_control_server.yaml` 注入，测试通过默认控制端口访问。

#### `cli_control_plane_roundtrip`
- 状态：部分自动化。
- 目标命令：
  - `show config`：已覆盖，验证返回用户配置且不会泄漏内置 `__control_server__`。
  - `collection get/set-add/map-put/map-del`：暂缓自动化。
  - `reload`：CLI roundtrip 暂缓自动化。
- 说明：真实 control RPC `reload` 已由 `reload_runtime_workloads` 自动化覆盖；CLI collection/reload 以后在独立 root token 路径稳定后补充。

#### `multi_gateway_tunnel_protocols`
- 操作：
  - Python 同时拉起 remote/client 两个真实 `cyfs_gateway` app 进程。
  - remote gateway 暴露 HTTP、PROXY-aware HTTP、UDP 和 SOCKS stack。
  - client gateway 暴露本地入口，并通过 process chain 将客户端请求转发到 remote gateway。
- 配置约束：
  - control server stack/server 仍由 `cyfs_gateway` 内置配置注入。
  - 因同一测试进程内要同时启动两个 app，测试配置只覆盖已注入 `stacks.__control_server__.bind`，用于隔离 remote/client 控制端口；不复制或外部声明 control server 的 hook/server 定义。
- 已自动化的通信路径：
  - `tcp`：client HTTP server `forward "tcp://..."` 到 remote HTTP stack，断言 remote dir body。
  - `ptcp`：client TCP stack `forward "ptcp://${REQ.source_addr}/..."` 到 remote TCP stack，断言 PROXY v1 源端口被 remote HTTP post hook 保留。
  - `udp`：client UDP stack `forward "udp://..."` 到 remote UDP stack，再到 Python UDP echo，断言 datagram payload。
  - `socks`：client HTTP server `forward "socks://user:pass@remote_socks/target"`，remote SOCKS server 按 hook 返回 DIRECT，断言 remote dir body。
- 当前边界：
  - `tls` / `quic` forward tunnel 在 app 级端到端中依赖平台证书校验；临时自签证书不能作为稳定通信通过用例，需要后续引入可信证书夹具或测试专用 trust store。
  - `tun` 是 L3 overlay/虚拟网卡路径，需要宿主机网络权限、路由和 TUN 设备前置条件，不放入默认 Python app integration。

#### `rtcp_app_tunnel_roundtrip`
- 操作：
  - Python 先通过真实 `cyfs_gateway gen_rtcp_key` 为 remote/client 生成独立 RTCP device key 和 device doc。
  - Python 同时拉起 remote/client 两个真实 `cyfs_gateway` app 进程。
  - remote gateway 暴露 `remote_rtcp` RTCP stack，并将 RTCP tunnel stream 转发到同进程内的 `remote_http` TCP stack。
  - remote gateway 的 `remote_http` stack 通过 `http-probe && call-server ${REQ.dest_host}` 路由到 `rtcp-via.test` dir server。
  - client gateway 暴露本地 `client_http` TCP stack 和 `client_rtcp` RTCP stack；本地 HTTP server 使用 `forward "rtcp://<bootstrap>@<remote_device>/rtcp-via.test:80"` 访问 remote。
- 配置约束：
  - control server stack/server 仍由 `cyfs_gateway` 内置配置注入。
  - 因同一测试进程内要同时启动两个 app，测试配置只覆盖已注入 `stacks.__control_server__.bind`，用于隔离 remote/client 控制端口；不复制或外部声明 control server 的 hook/server 定义。
  - RTCP 设备材料全部由 case 临时目录生成，不依赖固定本机密钥或外部服务发现。
- 验证：
  - client 侧 Python HTTP 客户端访问 `rtcp-via.test`。
  - 请求经 client HTTP server -> client RTCP stack -> remote RTCP stack -> remote HTTP stack -> remote dir server。
  - 断言最终 HTTP 状态为 200，body 为 remote 端构造的 `REMOTE_RTCP`。

#### `reload_runtime_workloads`
- 操作：
  - 启动真实 app 并访问 initial 配置下的 HTTP 与 DNS 服务。
  - 改写同一个临时 `cyfs_gateway.yaml` 为 reloaded 配置。
  - 通过 control RPC `login` 获取 token，再调用 `reload`。
  - 使用 Python 客户端访问 reload 后的各类服务。
- 配置约束：测试构造的 `cyfs_gateway.yaml` 只包含业务配置，不包含 `__control_server__`；控制面使用 app 内置配置。
- 验证：
  - `dir.test`、`reload.test`、`complex.test` 返回 reload 后的新 dir 内容。
  - `complex.test` 的 forward、global chain、for、match-result、nested if、reload-only 分支均可处理请求。
  - gzip 响应内容更新且仍压缩。
  - DNS local record 更新。
  - SOCKS DIRECT/PROXY 两类路径仍可 echo。
  - 带 PROXY protocol v1 前缀的 HTTP 请求仍能命中 reload 后的 server。

### 4. 网络运行时行为
#### `http_host_routing`
- 配置：TCP stack `http-probe && call-server ${REQ.dest_host}`。
- 请求：不同 Host。
- 验证：路由到不同 server。

#### `http_rewrite_forward`
- 配置：server hook 中 rewrite path 后 forward 到 Python upstream。
- 请求：`/api/hello`。
- 验证：upstream 收到 `/hello`。

#### `http_gzip_static_dir`
- 配置：dir/http server 开启 gzip。
- 请求：
  - 带 `Accept-Encoding: gzip`。
  - 不带 gzip。
- 验证：压缩响应和原始响应均正确。

#### `dns_local_resolution`
- 配置：UDP DNS stack + `local_dns` server。
- 请求：Python DNS client 查询 A/AAAA/CNAME。
- 验证：返回记录符合 fixture。

#### `socks_direct_proxy_reject`
- 配置：SOCKS server hook 根据目标端口返回 `"DIRECT"`、`"PROXY"` 或 `reject`。
- 请求：Python SOCKS5 client。
- 验证：
  - DIRECT 连接 echo server 成功。
  - PROXY 命中 upstream socks。
  - reject 目标失败。

#### `proxy_protocol_probe`
- 配置：TCP stack 接收 PROXY protocol v1 前缀后继续执行 `http-probe && call-server ...`。
- 请求：Python TCP client 发送 PROXY protocol v1 前缀和 HTTP 请求。
- 验证：PROXY header 被栈级逻辑剥离，后续 HTTP 路由返回目标 dir server 内容。
- 说明：当前 TCP stack 在 process chain 前已自动解析 PROXY protocol；链内再执行 `proxy-protocol-probe` 会读不到 header。因此该 case 验证 gateway app 的实际栈级 PROXY protocol 行为，命令注册由 CLI 文档 case 覆盖。

#### `io_dump_frames`
- 配置：TCP stack 设置 `io_dump_file`。
- 请求：HTTP 请求。
- 验证：dump 文件产生可解码 frame，upload/download 包含请求和响应片段。

### 5. Process Chain 运行时 Case
这些 case 只验证 process chain 在 `cyfs_gateway` 真实运行时中的业务结果，不单独验证 DSL 解释器内部语义。

#### `pc_http_probe_call_server`
- 规则：
  ```text
  http-probe && call-server ${REQ.dest_host};
  reject;
  ```
- 请求：`Host: dir.test`。
- 验证：返回对应 dir server 文件内容。

#### `pc_forward_http`
- 规则：
  ```text
  starts-with ${REQ.path} "/forward" && forward "http://127.0.0.1:{{upstream_http_port}}";
  reject;
  ```
- 验证：Python upstream 被命中并返回请求信息。

#### `pc_rewrite_forward`
- 规则：
  ```text
  starts-with ${REQ.path} "/api/" && rewrite ${REQ.path} "/api/*" "/*" && forward "http://127.0.0.1:{{upstream_http_port}}";
  reject;
  ```
- 验证：upstream 看到改写后的 path。

#### `pc_return_forward`
- 规则：
  ```text
  starts-with ${REQ.path} "/return-forward" && return "forward http://127.0.0.1:{{upstream_http_port}}";
  reject;
  ```
- 验证：行为等价于 forward。

#### `pc_reject`
- 规则：
  ```text
  starts-with ${REQ.path} "/reject" && reject;
  call-server fallback_dir;
  ```
- 验证：客户端收到当前实现定义的失败表现。

#### `pc_post_hook_header`
- 规则：
  ```text
  map-add RESP x-pc-case post-hook;
  ```
- 验证：响应头包含 `x-pc-case: post-hook`。

#### `pc_global_process_chain_exec`
- 全局链：
  ```text
  starts-with ${REQ.path} "/shared" && call-server shared_dir;
  ```
- server hook：
  ```text
  exec --lib shared_router;
  call-server fallback_dir;
  ```
- 验证：`/shared` 命中 shared dir，其它路径命中 fallback。

#### `pc_collection_side_effect`
- 规则：
  ```text
  set-add test_set ${REQ.path};
  map-add test_map ${REQ.path} hit;
  call-server fallback_dir;
  ```
- 验证：请求后通过 CLI `collection get` 检查 set/map 内容。

#### `pc_if_elif_else_router`
- 规则：
  ```text
  if starts-with ${REQ.path} "/if/dir" then
      call-server dir_case;
  elif starts-with ${REQ.path} "/if/forward" then
      forward "http://127.0.0.1:{{upstream_http_port}}";
  elif starts-with ${REQ.path} "/if/reject" then
      reject;
  else
      call-server fallback_dir;
  end
  ```
- 验证：
  - `/if/dir` 返回 dir case。
  - `/if/forward` 命中 upstream。
  - `/if/reject` 失败。
  - 其它路径返回 fallback。

#### `pc_nested_if_router`
- 规则：外层判断 Host，内层判断 path。
- 示例行为：
  - `Host: complex.test` + `/admin/*` -> reject。
  - `Host: complex.test` + `/api/*` -> forward。
  - 其它 -> dir。
- 验证：通过不同 Host/path 请求观察最终路由。

#### `pc_for_collection_router`
- 配置：准备 collection 保存 allowlist 或候选路由。
- 规则：使用 `for` 遍历 collection，匹配后设置响应头或选择 server。
- 验证：只断言最终路由、响应头或 collection side effect，不断言循环变量内部细节。

#### `pc_match_result_ok_err`
- 规则：
  ```text
  match-result $(match ${REQ.path} "/mr/ok")
  ok(v)
      call-server ok_dir;
  err(e)
      call-server fallback_dir;
  end
  ```
- 验证：
  - `/mr/ok` 命中 ok dir。
  - 其它路径命中 fallback。

#### `pc_match_result_control`
- 规则：使用 `match-result` 包装可能返回 control 的命令，例如 `return "forward ..."` 或 `reject`。
- 验证：不同分支产生对应 forward/reject 可观察结果。

#### `pc_dns_resolve`
- 规则：
  ```text
  resolve ${REQ.name} ${REQ.record_type} local_dns && return;
  reject;
  ```
- 验证：DNS client 得到 local_dns 记录。

#### `pc_socks_direct_proxy_reject`
- 规则：
  ```text
  eq ${REQ.target.port} "{{echo_direct_port}}" && return "DIRECT";
  eq ${REQ.target.port} "{{echo_proxy_port}}" && return "PROXY";
  reject;
  ```
- 验证：DIRECT、PROXY、reject 三类行为。

## 观测点
每个 case 至少使用一个外部可观察结果作为断言依据：

- HTTP status、body、header。
- DNS response record。
- SOCKS5 connect 成功、失败或 echo 内容。
- Python upstream server 收到的 path、header、body。
- CLI 输出和退出码。
- collection 内容。
- dump 文件内容。
- app 进程退出码和 stdout/stderr。

## 稳定性约束
- 所有网络 case 使用 `127.0.0.1`。
- 所有测试单线程执行，避免端口和全局环境竞争。
- app 进程必须在 case teardown 中清理。
- 失败时保留 case 临时目录路径，便于复现。
- 对异步写文件和后台任务使用轮询等待，并设置超时。

## 待补充 Case 矩阵
本节记录对照当前 `cyfs_gateway` 源码注册能力后仍缺少的 app 进程级 case。未实现前不得把这些条目登记为 `testplan.yaml` 的必跑步骤；实现后再将对应 case 名加入 `run.py` 的 case 列表。

### P0 默认集成优先补充
这些 case 不需要特殊宿主机权限或外部服务，适合直接补进默认 Python app integration。

#### `config_local_include_merge_semantics`
- 覆盖能力：本地文件 include、本地目录 include、object 递归 merge、array 去重追加、标量覆盖。
- 配置：主配置 include `base.yaml`、`routes.yaml` 和一个 include 目录，分别声明 stack/server/global chain。
- 验证：
  - include 来源全部进入最终运行配置。
  - 当前配置覆盖 include 中的同名标量字段。
  - 数组字段合并后无重复项。
  - 合并出的 HTTP 路由可真实响应请求。

#### `config_relative_path_from_main_file`
- 覆盖能力：`path` 与 `*_path` 字段按主配置文件目录归一化。
- 配置：主配置与 include 文件分属不同目录，include 中声明 `root_path`、`file_path` 或 `key_path` 的相对路径。
- 操作：从 case 临时目录之外的 cwd 启动 app。
- 验证：相对路径仍按主配置文件目录解析，HTTP dir/local DNS/证书文件可以被找到。

#### `invalid_server_type_and_timer_timeout_exit`
- 覆盖能力：server parser 只接受已注册 server type；timer `timeout` 必须大于 0。
- 配置：
  - unknown server type。
  - `timers.<id>.timeout: 0`。
- 验证：app 启动失败并输出可定位错误，不进入 ready 状态。

#### `control_cli_rule_mutation_roundtrip`
- 覆盖能力：CLI/control 的 `add_rule`、`append_rule`、`insert_rule`、`move_rule`、`set_rule`、`remove_rule`。
- 操作：启动 app 后通过 CLI 修改 `stack:<id>:main` 或 `server:<id>:main` 的 hook block，再发起真实 HTTP 请求。
- 验证：
  - `show` 能看到变更后的规则。
  - 变更无需重启即可通过 control reload 或热更新路径生效。
  - `remove_rule` 后对应路由失效或回到 fallback。

#### `control_cli_router_roundtrip`
- 覆盖能力：CLI/control 的 `add_router` 与 `remove_router`。
- 操作：
  - 添加本地目录 target。
  - 添加 HTTP upstream target。
  - 分别覆盖 exact、prefix、wildcard、regex URI。
- 验证：每类 URI 都能路由到预期 target；删除后不再命中。

#### `control_cli_dispatch_roundtrip`
- 覆盖能力：CLI/control 的 `add_dispatch` 与 `remove_dispatch`。
- 操作：
  - TCP dispatch 到 Python echo/upstream。
  - UDP dispatch 到 Python UDP echo。
- 验证：添加后端口可转发，删除后连接或 datagram 不再成功。

#### `control_cli_collection_roundtrip`
- 覆盖能力：CLI/control 的 `collection list/get/set-add/set-del/map-put/map-del`。
- 配置：`memory_set` 和 `memory_map`。
- 验证：
  - `collection list` 返回两类 collection。
  - set add/delete 后内容变化可见。
  - map put/delete 支持普通字符串值和 `--json` 值。

#### `http_dir_server_options`
- 覆盖能力：`dir` server 的 `index_file`、`fallback_file`、`autoindex`、`etag`、`if_modified_since`。
- 验证：
  - 自定义 index 文件返回正确 body。
  - 缺失路径命中 fallback。
  - autoindex 开关表现符合当前实现。
  - ETag/If-Modified-Since 产生 200/304 等可观察结果。

#### `http_compression_options`
- 覆盖能力：HTTP server 的 `gzip`、`gzip_types`、`gzip_min_length`、`gzip_vary`、`gzip_disable`、`brotli`。
- 验证：
  - gzip 命中和未命中分支。
  - `Vary: Accept-Encoding` 行为。
  - 低于 min length 时不压缩。
  - brotli 在客户端声明 `br` 时返回 br 编码。

#### `gateway_external_commands_runtime`
- 覆盖能力：gateway 注册的外部 process-chain 命令，而不是 process-chain 内建语法。
- 命令范围：`error`、`redirect`、`set-stat`、`set-limit`、`in-time-range`、`num-cmp`、`parse-cookie`。
- 验证：
  - `error` 返回指定错误响应。
  - `redirect` 返回 3xx 与 Location。
  - `parse-cookie` 能从请求 header 提取值并影响路由或响应头。
  - `in-time-range`、`num-cmp` 通过构造固定输入触发正反两类分支。
  - `set-stat`、`set-limit` 至少验证命令可执行并不破坏请求链路。

### P1 默认集成第二批
这些 case 可以自动化，但需要额外测试夹具或更细的客户端实现。

#### `dns_negative_and_record_types`
- 覆盖能力：DNS server + `local_dns` 的 miss/reject、A/AAAA/CNAME 等记录类型。
- 验证：
  - 已存在记录返回正确 answers。
  - 未命中记录走 reject 或当前实现定义的错误响应。
  - 多记录响应数量与内容符合 fixture。

#### `socks_auth_domain_ipv6_and_rule_config`
- 覆盖能力：SOCKS5 认证失败、domain target、IPv6 target、`rule_config` 本地/远程规则文件。
- 验证：
  - 错误用户名/密码被拒绝。
  - domain target 能被转发或按规则拒绝。
  - IPv6 loopback target 在平台支持时可用。
  - 本地和远程 `rule_config` 能改变 DIRECT/PROXY/REJECT 决策。

#### `control_refresh_token_and_unauthorized`
- 覆盖能力：control server 的 `refresh_token`、无 token、非法 token、错误 sys 参数。
- 验证：
  - 无 token 调用受保护方法返回 unauthorized。
  - 登录 token 可 refresh。
  - 非法 token 不能访问 `reload`、`get_config` 等方法。

#### `show_connections_and_device_manager`
- 覆盖能力：`show_connections`、`show_connection_devices`、`device_manager` 顶层配置。
- 配置：启用 `device_manager`，并通过 HTTP/SOCKS/RTCP 请求产生连接记录。
- 验证：CLI 输出包含可解析连接信息；device manager 数据不会跨 `BUCKYOS_ROOT` 泄漏。

#### `persistent_collections_json_sqlite_text`
- 覆盖能力：`json_set`、`sqlite_set`、`text_set`、`json_map`、`sqlite_map`。
- 验证：
  - 文件型 collection 能加载 fixture。
  - 只读 collection 的写操作失败或被拒绝。
  - sqlite map/set 在 app 重启后保留数据。

#### `timer_process_chain_side_effect`
- 覆盖能力：顶层 `timers` 启动和周期执行 process chain。
- 配置：timer 写入 memory collection 或触发本地 HTTP side effect。
- 验证：在超时窗口内观察到 side effect；teardown 后不再继续执行。

#### `acme_response_challenge_server`
- 覆盖能力：`acme_response` server 注册与 HTTP challenge 响应。
- 配置：通过 HTTP stack 路由 `/.well-known/acme-challenge/...` 到 `acme_response`。
- 验证：命中 challenge path 和未命中 path 的响应符合当前实现。

### P2 专项夹具或权限前置
这些 case 对环境要求高，不进入默认 integration；实现时应单独声明 precondition，并用独立 harness step 或手动验收入口承载。

#### `tls_app_stack_smoke`
- 覆盖能力：app 级 `tls` stack、SNI、证书加载、HTTP server 分支。
- 前置：测试专用 CA/trust store 或客户端禁用校验策略必须稳定可控。
- 验证：HTTPS 请求通过 TLS stack 命中 `Host` 对应 HTTP server。
- 状态：已进入默认 Python integration，使用 self-cert `domain: "*"` 与客户端禁用校验策略做 app 级 smoke。

#### `quic_app_stack_smoke`
- 覆盖能力：app 级 `quic` stack、HTTP/3 server 分支、证书加载。
- 前置：测试专用证书与 QUIC/HTTP3 Python 或 Rust 客户端夹具。
- 验证：QUIC/HTTP3 请求返回目标 dir body；错误 SNI 或证书路径失败可定位。

#### `tun_l3_overlay_smoke`
- 覆盖能力：app 级 `tun` stack 的 L3 overlay 行为。
- 前置：Linux TUN 设备权限、路由、防火墙/MTU 配置和 cleanup 权限。
- 验证：虚拟 IP 层连通和 TCP/UDP 应用层连通。该 case 不承诺 L2 广播域、ARP/mDNS/NetBIOS 自动发现。

#### `cyfs_dir_process_chain_smoke`
- 覆盖能力：已注册的 `cyfs-dir` server。
- 前置：NamedDataMgr store fixture、named store config、可构造的 `.cyobj` meta 或 `ObjId`。
- 验证：process chain 设置 `RESP_cyobj_meta` 或 `RESP_cyobj_id` 后，HTTP 请求可由 `cyfs-dir` 返回对象内容；未设置时按 `semantic_root` fallback。

#### `sn_server_smoke`
- 覆盖能力：已注册的 `sn` server 与 sqlite DB factory。
- 前置：明确 SN 协议客户端夹具和临时 sqlite 数据目录。
- 验证：server 可启动，基础 bind/lookup/route 行为可由客户端观测。

#### `ip_region_map_collection_smoke`
- 覆盖能力：`ip_region_map` collection。
- 前置：稳定 xdb fixture 或可本地生成的小型 DB，避免远程下载。
- 验证：IP 查询返回预期 region；缺少 fixture 或 checksum 不匹配时启动失败可定位。

## 当前实现状态
- `tests/integration/cyfs_gateway_app/run.py` 已实现并接入统一 integration 入口。
- 已实现 app 启动、非法配置退出、YAML/JSON/TOML 配置装载、include/remote include cache、本地 include merge、相对路径、内置 control server 注入、control RPC reload、HTTP host 路由、rewrite/forward/return/reject、gzip/brotli、DNS、SOCKS DIRECT/PROXY/reject、PROXY protocol、io dump、CLI help/process-chain/show config/gen_rtcp_key。
- 已实现 multi-gateway app 进程级通信：两个真实 `cyfs_gateway` 进程之间通过 `tcp`、`ptcp`、`udp`、`socks`、`rtcp` tunnel/forward 路径传输请求，并由客户端访问验证 remote 工作负荷。
- 已实现 process chain runtime case：`call-server`、`forward`、`rewrite`、`rewrite-reg`、`return`、`reject`、`post_hook_point`、`global_process_chains`、collection side effect、`if/elif/else`、nested if、`for`、`match-result`、DNS `resolve`、SOCKS hook return。
- 已实现控制面 mutation：rule set/insert/append/move/add/remove、router exact/wildcard/regex add/remove、dispatch、collection set/map 操作、未授权 token 边界。
- 已实现 gateway 外部命令 app smoke：HTTP `error`/`redirect` 返回动作、`parse-cookie`、`num-cmp`。
- 已实现 P1/P2 默认可自足 case：DNS negative、SOCKS domain/auth failure、`acme_response` unknown token、timer side effect、`json_set` 跨重启持久化、TLS self-cert HTTP smoke。
- 暂缓自动化：CLI `collection`、`reload` roundtrip；真实 reload 行为已通过 control RPC 覆盖。
- 专项夹具缺口：QUIC/TUN app 级通信、`cyfs-dir`、`sn`、`ip_region_map`。这些 case 需要 QUIC/HTTP3 客户端、宿主机 TUN 权限、NamedDataMgr/SN 客户端或 xdb fixture，现阶段继续由库级测试和后续专项入口负责。

## 完成定义
- Python runner 能通过统一入口执行。
- app 级测试确实编译并启动 `cyfs_gateway` binary。
- 所有配置文件由测试生成，不依赖固定本机环境。
- 所有客户端调用由 Python 构造。
- process chain case 覆盖 `forward`、`call-server`、`rewrite`、`return`、`reject`、`post_hook_point`、`global_process_chains`、collection side effect、`if/elif/else`、`for` 和 `match-result` 在真实 gateway 中的行为。
- multi-gateway case 覆盖当前默认 app integration 可稳定构造的 `tcp`、`ptcp`、`udp`、`socks`、`rtcp` 通信路径；TLS 由 self-cert app smoke 覆盖；`quic`、`tun` 仍显式记录夹具缺口。
- 失败输出足够定位到配置、进程日志和具体请求。
