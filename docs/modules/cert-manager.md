# cert-manager

## 职责
负责网关进程内证书生命周期管理，包括 ACME 申请与续期、自签 fallback 证书、本地与动态服务端证书解析、tunnel 客户端证书装载，以及 `provider` / `solver` 的边界维护。

## provider 选择规则
- 每个证书 provider 只管理自己签发或装载的证书与状态，不共享证书所有权。
- 用户为某个证书需求显式指定 provider 时，运行时只能消费该 provider 管理的证书，不能从其他 provider 借用、回退或混用结果。
- fallback 只允许发生在文档明确声明的独立入口上，例如 `domain: "*"` 的 self-signed fallback；它不是“任意 provider 失败后自动切到别的 provider”。

## 主要路径
- `src/components/cyfs-acme/`
- `src/components/cyfs-gateway-lib/src/self_cert_mgr.rs`
- `src/components/cyfs-gateway-lib/src/tunnel_client_cert_manager.rs`
- `src/components/cyfs-gateway-lib/src/server/acme_http_challenge_server.rs`
- `src/components/cyfs-gateway-lib/src/stack/tls_cert_resolver.rs`
- `src/components/cyfs-gateway-lib/src/stack/tls_stack.rs`
- `src/components/cyfs-gateway-lib/src/stack/quic_stack.rs`
- `src/apps/cyfs_gateway/src/gateway.rs`
- `src/apps/cyfs_gateway/src/config_loader.rs`
- `src/apps/cyfs_gateway/src/acme_sn_provider.rs`

## 输入
- 顶层证书相关配置：`acme`、`tls_ca`、`stacks[].certs[]`、`tunnel_client_certs`
- 运行时 consumer 提交的服务端与 tunnel 客户端证书需求
- `http-01`、`dns-01`、`tls-alpn-01` challenge 暴露面与执行器

## 输出
- ACME account、order、challenge 与续期运行时
- 服务端 TLS/QUIC 的 SNI / ALPN 证书解析结果
- 本地自签 fallback 证书与缓存
- tunnel 客户端证书材料与状态

## 邻接边界
- `gateway-runtime` 负责创建和装配证书 manager、stack 与 server，不拥有证书生命周期语义。
- `runtime-configs` 负责提供证书相关默认值与打包输入，不拥有 provider、order 或 solver 的执行逻辑。
- `web-dashboard` 只消费外露状态，不定义证书生命周期模型。

## 验证面
- `tunnel_client_cert_manager` 的 snapshot、reload、校验逻辑单测
- TLS / QUIC stack 对 wildcard fallback、自签证书和 client auth 的 runnable tests
- gateway 集成测试对 `tunnel_client_certs`、控制平面装配和证书消费路径的验证

## 风险等级
Tier A：证书生命周期、challenge 暴露面、client auth 与配置兼容性变更都需要明确测试证据。
