---
module: gateway-runtime
submodule: http-upstreams
version: v0.6
status: approved
approved_by: user
approved_at: 2026-07-12T00:00:00+08:00
---

# HTTP Named Upstreams and Connection Reuse Design

## Metadata
- version: v0.6
- module: gateway-runtime
- submodule: http-upstreams
- stage: design
- status: approved

## Design Scope
This design covers `P-http-upstreams-1` and replaces the worktree's `hyper_util` pool with `sfo_http_pool::fixed::Client` while extending pooled HTTP/1 sessions to every stream URL supported by `forward` and `TunnelManager`.

## Overall Approach
Keep named-upstream parsing and execution in `http_server.rs`. Normalize each enabled upstream into a runtime endpoint and construct one fixed Client for it. The Client uses a `ForwardPoolHost` whose target contains the upstream name and full URL, plus a `ForwardPoolConnector` that establishes the underlying stream:

- `http`: DNS/TCP fallback, then `PooledHttpConnection::handshake`.
- `https`: DNS/TCP fallback, existing TLS/SNI policy, then the same handshake.
- other schemes: `TunnelManager::open_stream_by_url`, wrap with `TunnelStreamConnection`, then the same handshake.

The fixed Client owns the idle keepalive cache, idle timeout, reuse count, connection availability, and response-body lease lifecycle. Gateway code calls `acquire_stream()` before taking `req_slot`, disables the Client's own canceled-request retry, builds the origin-form request, and calls `ClientSendStream::send_request` only after acquisition succeeds. `keepalive` limits cached idle connections rather than active concurrency; the gateway sets the library's separate total-connection limit to `u16::MAX`, the practical unlimited value supported by the current API.

## Runtime Types
| type | responsibility |
|------|----------------|
| `ForwardPoolTarget` | Carries `upstream_name` and the full parsed transport URL without assuming a standard HTTP authority. |
| `ForwardPoolHost` | Implements fixed-client `Host` and returns the custom transport target without imposing standard authority validation on hostless tunnel URLs. |
| `ForwardPoolConnector` | Implements `Connector<BoxBody<Bytes, ServerError>>` and opens direct or tunnel-backed streams. |
| `PooledHttpClient` | Stores `fixed::Client` and the configured target URL for one named upstream. |
| `ResolvedForwardTarget` | Preserves both resolved URL and optional upstream name through direct execution. |

## Configuration
```yaml
upstreams:
  direct_api:
    url: "https://api.internal/"
    keepalive: 32
    keepalive_timeout: 60s
    keepalive_requests: 1000

  peer_api:
    url: "rtcp://peer/service"
    keepalive: 8
```

The containing HTTP server also accepts NGINX-compatible upstream TLS
verification controls:

```yaml
proxy_ssl_verify: true
proxy_ssl_trusted_certificate: "/etc/cyfs-gateway/upstream-ca.pem"
proxy_ssl_verify_depth: 1
```

- `proxy_ssl_verify` defaults to `false`, matching NGINX compatibility behavior.
- Enabling verification requires `proxy_ssl_trusted_certificate`.
- The trusted file may contain one or more PEM certificates.
- The common configuration normalization pass recognizes
  `proxy_ssl_trusted_certificate` as a path alias. Relative values are resolved
  from the main gateway configuration directory before server config
  deserialization; `http_server.rs` only opens the normalized value.
- `proxy_ssl_verify_depth` defaults to `1` and limits intermediate certificates.
- The upstream URL host remains the certificate name and SNI name.
- A single immutable rustls client configuration is built per HTTP server and is
  shared by pooled and direct HTTPS forwarding.

Validation rules:
- Name matches `^[A-Za-z_][A-Za-z0-9_-]{0,63}$`, contains no leading or trailing whitespace, and does not conflict with balance keywords. This prevents a name from also parsing as an absolute URL.
- URL parses successfully.
- `keepalive` is false/omitted, true, or an integer in `1..=u16::MAX`.
- Timeout and request limit require enabled keepalive.
- Timeout parses and request limit is positive.
- Keepalive does not reject a URL solely because its scheme is non-HTTP.
- HTTP/HTTPS URLs containing a fragment are rejected.

## Proxy-Pass URI Mapping
HTTP and HTTPS forwarding model a static NGINX `proxy_pass` inside an implicit
`location /`:

- A target with no explicit URI, such as `http://backend`, preserves the inbound
  path and query.
- A target with a URI replaces the implicit `/` location prefix. The target path
  and unmatched inbound path are concatenated exactly; no slash is inserted.
  Therefore `/api/` plus `/users` becomes `/api/users`, while `/api` plus
  `/users` becomes `/apiusers`, matching NGINX trailing-slash behavior.
- When the target specifies query arguments, they replace inbound arguments;
  otherwise inbound arguments are preserved.
- URL fragments are invalid because they are not HTTP request-target data.
- Non-HTTP tunnel URLs retain their existing behavior: the transport URL opens
  the stream and the inbound origin-form URI is sent over it.

## Proxy Host Semantics
- Request-header map mutations mark explicit process-chain Host additions,
  replacements, and removals in the request extensions.
- For HTTP and HTTPS targets, if the process chain leaves Host unchanged, set
  the forwarded Host to the parsed upstream authority. Include a non-default
  explicit port and bracket IPv6 literals.
- If the process chain adds, replaces, or removes Host, preserve that explicit
  mutation. This gives process-chain policy precedence over the proxy default.
- Direct and pooled forwarding share this normalization before their execution
  paths diverge.
- Non-HTTP tunnel targets retain the post-process-chain Host because a hostless
  transport URL may not have an HTTP authority to apply.

## Key Call Flow
1. Resolve an inline forward token to `ResolvedForwardTarget { url, upstream_name }`.
2. Join the incoming path/query to the upstream URL and filter hop-by-hop headers.
3. If the target has an enabled named pool, call `client.acquire_stream()` while `req_slot` is still populated.
4. On acquisition failure, return an error with the original request body intact.
5. On success, take the request, build an origin-form HTTP/1 request, and call `send_request`.
6. Map `ClientResponseBody` into the gateway body. The fixed Client retains the lease until EOS and evicts on error or early drop.
7. If no named pool applies, use the existing one-request-one-connection branch.

## Failure and Retry Semantics
- Connector failures occur before `req_slot.take()` and remain eligible for gateway next-upstream retry.
- Send failures happen after commitment and are not retried unless the existing buffered-request path explicitly permits replay.
- `.retry_canceled_requests(false)` prevents a hidden pool-level retry from competing with gateway policy.
- Direct connect/TLS failures retain their canonical `TunnelFailureReason` through an error source wrapper.
- Acquisition errors are classified before history writeback: connector and HTTP handshake failures retain the direct-path history behavior, while stale-connection and pool-internal failures return locally without marking the upstream URL unreachable.
- Tunnel open history continues to be written only by `TunnelManager`; the pooled HTTP layer does not duplicate non-HTTP success/failure writeback.
- As in the direct path, send-stage failures evict the affected connection but do not mark the tunnel URL unreachable.
- Pooled requests use the same scheme-specific HTTP version and `ServerErrorCode` behavior as the direct path.

## ForwardPlan Boundary
Named direct targets retain their upstream name in `ResolvedForwardTarget`. Group execution currently operates on resolved URLs and continues on the existing manual path so its body-buffering and candidate retry contract is unchanged. Extending named pool identity through serialized `ForwardPlan` is deferred rather than inferring identity by URL.

## Dependency and Lifecycle Decisions
- Add `sfo-http-pool = "0.1.1"`; do not use `hyper_util::legacy::Client` for pooling.
- Reuse existing Tokio, Hyper, rustls, and `TunnelStreamConnection` types.
- The fixed Client is dropped with `ProcessChainHttpServer`; no independent cleanup task is necessary for correctness.
- `keepalive_requests` is applied through `ClientBuilder::max_reuse_count`.
- `keepalive_timeout` is applied through `ClientBuilder::pool_idle_timeout`.
- `keepalive` is applied through `ClientBuilder::pool_max_idle` and controls only cached idle connections.
- `ClientBuilder::pool_max_connections(u16::MAX)` prevents the idle-cache setting from becoming an active-concurrency bottleneck; no user-facing active-connection limit is introduced by this change.

## Directly Mapped Change Items
| change_id | proposal_id | design coverage | scope paths |
|-----------|-------------|-----------------|-------------|
| P-http-upstreams-1 | gateway-runtime-http-upstreams | Configuration, path normalization, proxy Host precedence, runtime types, connector selection, acquire-before-consume flow, failure handling, and test plan. | `src/components/cyfs-gateway-lib/Cargo.toml`, `src/components/cyfs-gateway-lib/src/server/mod.rs`, `src/components/cyfs-gateway-lib/src/server/server.rs`, `src/components/cyfs-gateway-lib/src/server/http_server.rs` |

## Rejected Alternatives
- `hyper_util::client::legacy::Client`: does not satisfy the required library ownership.
- Direct `fixed::HttpPool`: exposes lower-level lease bookkeeping that fixed Client already implements.
- Built-in fixed `HttpHost`: assumes HTTP-style scheme/authority and is unsuitable for hostless tunnel URLs.
- URL-to-upstream reverse lookup: ambiguous when multiple names share one URL.

## Risks and Rollback
- Risk: custom Connector errors lose protocol classification. Mitigation: wrap canonical failure reason inside `io::Error` and recover it from the source chain.
- Risk: tunnel transport passes HTTP/1 over a stream that is not an HTTP URL. Mitigation: this is identical to the existing non-HTTP forward branch.
- Risk: verification enabled without usable trust anchors prevents server startup.
  Mitigation: validate the file and all PEM certificates while building the server.
- Rollback: disable keepalive or restore the existing one-request-one-connection execution path.

## Approval Record
- approver: user
- approval_date: 2026-07-12
- user_statement: "确定，自动处理后续步骤"
- amendment_date: 2026-07-13
- amendment_statement: "现将问题2，问题3修改，问题1等sfo-http-pool修改完成再说"
- keepalive_amendment_date: 2026-07-13
- keepalive_amendment_statement: "更新了sfo-http-pool，支持了keepalive逻辑，请修复问题1"
- tls_uri_amendment_date: 2026-07-14
- tls_uri_amendment_statement: "问题1，在http server中添加跟nginx类似的配置吧，代码中也实现nginx相同的功能；问题2，也实现跟nginx类似的url拼接方式；问题4，暂时不管"
- path_normalization_amendment_date: 2026-07-14
- path_normalization_amendment_statement: "不要在http_server.rs中补偿，可以在配置解析时补偿"
- proxy_host_amendment_date: 2026-07-14
- proxy_host_amendment_statement: "问题2，也改成默认是代理host吧，其它问题先不管了"
