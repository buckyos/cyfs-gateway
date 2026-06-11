---
module: gateway-runtime
version: v0.6
status: approved
approved_by: user
approved_at: 2026-06-11T23:55:57+08:00
approved_content_sha256: ee536cc030047b0bdec8f280e212e18db1f6c273a1e40de693b2d46caf0ad141
---

# gateway-runtime Proposal

## Metadata
- version: v0.6
- module: gateway-runtime
- stage: proposal
- status: approved
- approved_by: user
- approved_at: 2026-06-11T23:55:57+08:00

## Background and Goal
`gateway-runtime` owns gateway startup, config loading, stack and server registration, the built-in control plane, and integration behavior. The current built-in control server defaults to `127.0.0.1:13451`; tests that start more than one `cyfs_gateway` process need a stable way to assign a distinct control server port per instance.

The existing runtime can already override the injected internal stack through `stacks.__control_server__.bind`, but that is an internal stack key and is easy to miss. This proposal adds a user-facing top-level `control_port` setting so multi-instance tests and local development can avoid fixed-port conflicts without duplicating the built-in control server stack or server definitions.

This proposal also preserves the previously planned TCP/TLS/UDP/QUIC reuseport work for the module packet.

## Scope
### In Scope
- Add a top-level `control_port` config setting for the built-in control server port.
- Keep the default control server endpoint equivalent to `127.0.0.1:13451` when the new setting is absent.
- Map the setting to the injected `__control_server__` TCP stack bind address during config loading.
- Use the setting in tests that start multiple `cyfs_gateway` instances or otherwise need isolated control ports.
- Preserve the built-in control server stack/server definitions; user configs must not need to copy the hook point or server definition.
- Keep existing TCP/TLS/UDP/QUIC reuseport proposal items in this module packet.

### Out of Scope
- Do not expose a remote control-plane bind host in this change; the new setting controls the port only and remains loopback-bound.
- Do not change control-plane RPC methods, authentication, token behavior, or response schemas.
- Do not require existing configs to add the new setting.
- Do not remove the existing internal `stacks.__control_server__.bind` override path until compatibility is separately designed.
- Do not redesign stack, server, process-chain, RTCP, or TUN behavior.

### Adjacent Module Boundaries
- `gateway-runtime` owns config loading, built-in control server injection, and runtime startup behavior.
- `runtime-configs` owns shipped templates/default examples; design must decide whether any rootfs examples should show the new setting.
- `web-dashboard` consumes the control plane but does not define the runtime port setting in this proposal.

## Assumptions and Ambiguities
- The requested setting is for selecting the local control server port for test and local multi-instance startup, not for exposing the control server on a non-loopback interface.
- The external shape is the top-level runtime config field `control_port`, rather than a nested object or the internal `__control_server__` stack id.
- If both `control_port` and `stacks.__control_server__.bind` are present, design must define precedence or conflict handling before implementation.
- The exact YAML shape, parser location, and validation error messages belong in design.

## Constraints
- Default behavior must remain backward compatible: no setting means port `13451`.
- The control server must remain loopback-only unless a separate approved proposal expands the trust boundary.
- Port values must be validated before stack startup, with invalid or out-of-range values reported as config errors.
- Multi-instance tests must not duplicate the built-in control server hook/server definition.
- Config-template synchronization rules apply if shipped examples or templates expose the new setting.

## Requirement Challenge
| question | evaluation | risk_or_tradeoff | decision |
|----------|------------|------------------|----------|
| Should tests keep using `stacks.__control_server__.bind` instead of a new setting? | It already works, but it exposes an internal injected stack id and makes test configs depend on built-in wiring details. | Keeping only the internal override avoids code changes but leaves the recurring fixed-port problem easy to reintroduce. | Add a user-facing port setting while preserving the internal override path for compatibility. |
| Should the setting be nested or top-level? | The requested purpose is a simple global runtime startup knob used by tests and local multi-instance runs. | A nested object leaves more room for future control-plane settings but adds shape complexity that is not needed for port-only configuration. | Use top-level `control_port`. |
| Should the new setting accept a full bind address or only a port? | The user asked for a port, and remote control-plane exposure would alter the security boundary. | A full bind address is more flexible but risks accidental non-loopback control-plane exposure. | Support port-only in this change; keep loopback binding. |
| Should this be implemented directly from chat context? | The approved proposal currently excludes new user-visible config fields. | Direct implementation would bypass proposal/design admission. | Return to proposal first and record downstream design, implementation, and testing follow-up. |

## Large Module Submodule Decision
| submodule | new_or_existing | responsibility | proposal_packet | reason |
|-----------|-----------------|----------------|-----------------|--------|
| gateway-runtime/control-plane-config | existing module scope | Built-in control server startup configuration and multi-instance control port isolation | docs/versions/v0.6/modules/gateway-runtime/proposal.md | The change is a small config surface inside gateway runtime startup and does not justify a new direct submodule packet. |

## Trigger Matrix
| trigger_category | applies | evidence | required_checks | deferred_checks_and_reason |
|------------------|---------|----------|-----------------|----------------------------|
| contract/protocol | yes | Adds top-level runtime config key `control_port` for control server port. | Design must specify config shape, compatibility, conflict handling, and validation errors; tests must cover default and explicit port config. | owner: gateway-runtime design/testing; risk: config contract ambiguity; acceptance impact: implementation cannot be accepted without compatibility evidence |
| data/schema | no | No persisted data, database schema, migration, cache key, or serialized state shape changes are required. | none | none |
| security/privacy/permission | yes | The control server is an authenticated local control plane; changing its endpoint can affect access boundaries. | Design must state loopback-only binding and negative handling for attempts to configure a host or invalid port. | owner: gateway-runtime design/testing; risk: accidental control-plane exposure; acceptance impact: acceptance must reject missing loopback/negative validation |
| runtime/integration | yes | Startup binds the built-in `__control_server__` TCP stack and multi-instance tests need distinct ports. | DV or integration tests must start with an explicit control port and verify control RPC login/system info works. | owner: gateway-runtime testing; risk: multi-instance startup still races or binds the default port; acceptance impact: integration evidence is required |
| build/dependency/config/deployment | yes | Adds top-level `control_port` config key/default behavior and may affect shipped examples/templates. | Design must list touched config surfaces; implementation must update or justify rootfs/template docs and run relevant module tests. | owner: gateway-runtime design/testing; risk: template/docs drift; acceptance impact: config-template sync must be reviewed |
| ui/datamodel/workflow | no | No web dashboard UI state or frontend/backend dashboard data contract changes are requested. | none | none |
| harness/process | no | No harness scripts, rules, testplan schema, or CI entrypoint behavior changes are requested by this proposal. | none | none |

## High-Level Outcomes
- A config can select a non-default control server port for a `cyfs_gateway` instance without copying built-in control server definitions.
- Multiple gateway instances can run in tests with isolated control ports.
- Existing configs keep using `127.0.0.1:13451` by default.
- The control plane remains loopback-only and authenticated.

## Proposal Items
| proposal_id | change_id | outcome | success_evidence |
|-------------|-----------|---------|------------------|
| gateway-runtime-baseline | P-base-1 | Establish the `gateway-runtime` harness baseline module packet and validation entrypoints. | Maintain harness baseline docs, templates, and unified test entry itself. |
| gateway-runtime-tcp-reuseport | P-tcp-reuseport-1 | TCP stack uses external `sfo_reuseport::ServerRuntime` and `sfo_reuseport::TcpServer`, with `concurrency` interpreted as per-worker concurrency. | Modify `TcpStack`, `TcpStackFactory`, runtime factory registration, and focused tests. |
| gateway-runtime-tls-reuseport | P-tls-reuseport-1 | TLS stack uses external `sfo_reuseport::ServerRuntime` and `sfo_reuseport::TcpServer`, with `concurrency` interpreted as per-worker concurrency. | Modify `TlsStack`, `TlsStackFactory`, runtime factory registration, and focused tests. |
| gateway-runtime-udp-reuseport | P-udp-reuseport-1 | UDP stack uses external `sfo_reuseport::ServerRuntime` and `sfo_reuseport::UdpServer`, with `concurrency` interpreted as per-worker datagram handler concurrency. | Modify `UdpStack`, `UdpStackFactory`, runtime factory registration, and focused tests. |
| gateway-runtime-quic-reuseport | P-quic-reuseport-1 | QUIC stack uses external `sfo_reuseport::ServerRuntime` and `sfo_reuseport::QuicServer`, with `concurrency` interpreted as per-worker open connection limit. | Modify `QuicStack`, `QuicStackFactory`, runtime factory registration, and focused tests. |
| gateway-runtime-control-port-config | P-control-server-port-config-1 | Top-level `control_port` config can set the built-in control server port while preserving loopback binding and default port compatibility. | Design, implementation, and tests cover explicit port, default port, multi-instance startup, and invalid/conflicting config. |

## Success Criteria
- Top-level `control_port` can set the built-in control server port for one gateway instance.
- Two gateway instances in test can use different control ports and both answer control RPC requests.
- Absence of the new setting preserves the existing default port behavior.
- Invalid ports and unsafe host-style configuration are rejected before runtime bind attempts.
- Shipped config examples/templates are updated or explicitly documented as intentionally unchanged.

## Risks
- Introducing a new config key creates compatibility and documentation obligations.
- Ambiguous precedence between the new setting and `stacks.__control_server__.bind` could produce surprising startup behavior.
- Allowing a full bind address would expand the control-plane trust boundary, so this proposal keeps the setting port-only.
- Tests that allocate ports before process startup can still race with other processes; test design should use per-case allocation and clear diagnostics.

## Downstream Follow-Up
| stage | required_follow_up | reason |
|-------|--------------------|--------|
| design | Add `P-control-server-port-config-1` design coverage with config shape, precedence/conflict behavior, scope paths, validation, and template synchronization decision. | Implementation cannot start until the new config contract and affected paths are admitted. |
| testing | Add direct coverage for default port behavior, explicit control port behavior, invalid port handling, and multi-instance startup. | Triggered runtime/config/security checks require concrete validation. |
| implementation | Implement only after proposal/design approval and admission evidence for `P-control-server-port-config-1`. | Current approved design does not cover this new config field. |
| acceptance | Review docs, code defaults, templates, and test evidence for consistency. | Config-template sync and control-plane boundary risks need independent review. |

## Approval Record
- approver: user
- approval_date: 2026-06-11T23:55:57+08:00
- user_statement: "确定，自动处理后续步骤"
