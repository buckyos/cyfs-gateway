---
module: gateway-runtime
version: v0.6
status: approved
approved_by: auto-pipeline
approved_at: 2026-06-11T23:55:57+08:00
approved_content_sha256: 39282daa57e79fccde0e0819a028d807fe1aee62bd265ee3b750f92386f1d69c
---

# gateway-runtime Design

## Metadata
- version: v0.6
- module: gateway-runtime
- stage: design
- status: approved
- approved_by: auto-pipeline
- approved_at: 2026-06-11T23:55:57+08:00
- pipeline_launch: 用户要求“确定，自动处理后续步骤”

## Design Scope
This design adds implementation coverage for `P-control-server-port-config-1`: a top-level `control_port` config field that selects the built-in control server port while keeping the control server bound to loopback.

The existing TCP/TLS/UDP/QUIC reuseport design mappings remain in this module packet so earlier approved change ids continue to have direct mapping rows.

## Overall Approach
During config loading, `cyfs_gateway` continues to start from the embedded `gateway_control_server.yaml`, then merges the user config. After parameter substitution, the loader checks top-level `control_port`. When present, it validates the value as an integer TCP port in `1..=65535` and writes `stacks.__control_server__.bind = "127.0.0.1:<control_port>"` into the effective config before parsing stacks.

If `control_port` and `stacks.__control_server__.bind` are both present, `control_port` wins for the effective runtime bind. This keeps the user-facing global field authoritative while preserving the existing internal override for callers that have not migrated.

The user-visible config returned by control APIs may retain `control_port`, while existing hiding of the injected `__control_server__` stack/server remains unchanged.

## Simplicity Check
| decision | reused_component | new_abstraction | reason |
|----------|------------------|-----------------|--------|
| Apply `control_port` in config loading | Existing `serde_json::Value` merge and embedded control server config injection | none | A small helper around the existing raw config value is enough; no new config subsystem is needed. |
| Keep loopback host fixed | Existing built-in `__control_server__` TCP stack | none | The proposal approves port-only behavior and avoids expanding the control-plane trust boundary. |

## Current Structure
- `src/apps/cyfs_gateway/src/gateway.rs::load_user_config_from_file` loads user config, merges it onto `GATEWAY_CONTROL_SERVER_CONFIG`, applies params, and normalizes paths.
- The embedded control stack lives in `src/apps/cyfs_gateway/src/gateway_control_server.yaml` with default bind `127.0.0.1:13451`.
- Tests currently override `stacks.__control_server__.bind` directly when they need isolated control ports.
- `src/rootfs/etc/cyfs_gateway.yaml` is the shipped rootfs example/default config surface.

## Submodules
| submodule | type | responsibility | depends_on |
|-----------|------|----------------|------------|
| control-plane-config | runtime/config | Interpret top-level `control_port` and update the built-in control stack bind before stack parsing. | config loader, embedded control server config |
| control-plane-tests | testing | Validate default, explicit, invalid, and multi-instance control port behavior. | control-plane-config |
| reuseport-stack-listeners | runtime/stack | Existing TCP/TLS/UDP/QUIC reuseport listener design mappings. | sfo-reuseport |

## Boundary Rationale
`control_port` belongs in `gateway-runtime` because it affects how the runtime injects and starts the built-in control plane. It does not belong in `cyfs-gateway-lib` because the library only starts stacks from already-parsed stack configs, and it does not belong in `web-dashboard` because no frontend contract changes are required.

## Boundary Decision Matrix
| boundary | classification | business_responsibility | shared_logic_or_technical_area | decision |
|----------|----------------|-------------------------|--------------------------------|----------|
| control port config loading | technical area inside gateway-runtime | Start a gateway instance with an isolated local control endpoint. | Config merge and built-in control stack injection. | Keep in `src/apps/cyfs_gateway/src/gateway.rs`. |
| shipped config example | adjacent runtime-configs surface | Show supported startup config knobs. | Rootfs example/default config. | Update `src/rootfs/etc/cyfs_gateway.yaml` with commented `control_port`. |
| tests | validation area | Prove multi-instance and invalid config behavior. | Rust integration/DV tests. | Add or update tests under `src/apps/cyfs_gateway/tests/` in testing stage. |

## Dependency Graph
| source | depends_on | reason | cycle_check |
|--------|------------|--------|-------------|
| control-plane-config | embedded control server config | It rewrites the injected stack bind. | acyclic |
| control-plane-tests | control-plane-config | Tests exercise the new config behavior through runtime startup. | acyclic |
| rootfs config example | control-plane-config | Example documents the supported key. | acyclic |

## Key Call Flows
1. `gateway_service_main(config_file, params)` calls `load_config_from_file`.
2. `load_user_config_from_file` loads the user YAML/JSON/TOML directory.
3. The loader merges the user config onto `GATEWAY_CONTROL_SERVER_CONFIG`.
4. `apply_params_to_json` resolves params in the merged config.
5. `apply_control_port_config` reads top-level `control_port`; if present, it validates the port and writes `stacks.__control_server__.bind`.
6. `GatewayConfigParser::parse` parses the effective config and starts the control stack on the selected loopback port.

## Large Module Submodule Decision
| submodule | source_proposal | decision | design_packet | reason |
|-----------|-----------------|----------|---------------|--------|
| control-plane-config | P-control-server-port-config-1 | Keep inside existing `gateway-runtime` packet. | docs/versions/v0.6/modules/gateway-runtime/design.md | The change is a narrow config-loading behavior, not a new independent runtime subsystem. |

## Trigger Matrix
| trigger_category | applies | evidence | design_coverage | required_checks | deferred_checks_and_reason |
|------------------|---------|----------|-----------------|-----------------|----------------------------|
| contract/protocol | yes | Top-level config key `control_port` is added. | `Overall Approach`, `Interfaces and Dependencies` | Test explicit `control_port`, default behavior, and conflict behavior. | none |
| data/schema | no | No persisted data or database schema changes. | `Data and State` | none | none |
| security/privacy/permission | yes | Control server endpoint remains an authenticated local control plane. | `Overall Approach`, `Key Decisions` | Verify host stays `127.0.0.1`; reject invalid non-port values. | none |
| runtime/integration | yes | Startup bind of `__control_server__` changes when `control_port` is present. | `Key Call Flows`, `Implementation Order` | DV/integration test startup with explicit control port and control RPC. | none |
| build/dependency/config/deployment | yes | Rootfs config example gains `control_port`. | `Boundary Decision Matrix`, `Document Index` | Inspect/update `src/rootfs/etc/cyfs_gateway.yaml`; run relevant tests. | none |
| ui/datamodel/workflow | no | No web dashboard data model or UI workflow changes. | `Design Scope` | none | none |
| harness/process | no | No harness rule, script, schema, or CI behavior changes. | `Design Scope` | none | none |

## Directly Mapped Change Items
| change_id | proposal_id | design_coverage | scope_paths |
|-----------|-------------|-----------------|-------------|
| P-base-1 | gateway-runtime-baseline | `Document Index` and `Implementation Order` preserve the module baseline entrypoints and module packet wiring. | `docs/versions/v0.6/modules/gateway-runtime/testplan.yaml`, `harness/scripts/test-run.py`, `test-run.sh` |
| P-control-server-port-config-1 | gateway-runtime-control-port-config | `Overall Approach`, `Key Call Flows`, `Interfaces and Dependencies`, and `Key Decisions` cover top-level `control_port` config loading and loopback control bind behavior. | `src/apps/cyfs_gateway/src/gateway.rs`, `src/rootfs/etc/cyfs_gateway.yaml` |
| P-tcp-reuseport-1 | gateway-runtime-tcp-reuseport | Existing reuseport listener design covers TCP stack external `ServerRuntime` and `TcpServer` behavior. | `src/components/cyfs-gateway-lib/src/stack/tcp_stack.rs`, `src/apps/cyfs_gateway/src/lib.rs` |
| P-tls-reuseport-1 | gateway-runtime-tls-reuseport | Existing reuseport listener design covers TLS stack external `ServerRuntime` and `TcpServer` behavior. | `src/components/cyfs-gateway-lib/src/stack/tls_stack.rs`, `src/apps/cyfs_gateway/src/lib.rs` |
| P-udp-reuseport-1 | gateway-runtime-udp-reuseport | Existing reuseport listener design covers UDP stack external `ServerRuntime` and `UdpServer` behavior. | `src/components/cyfs-gateway-lib/src/stack/udp_stack.rs`, `src/apps/cyfs_gateway/src/lib.rs` |
| P-quic-reuseport-1 | gateway-runtime-quic-reuseport | Existing reuseport listener design covers QUIC stack external `ServerRuntime` and `QuicServer` behavior. | `src/components/cyfs-gateway-lib/src/stack/quic_stack.rs`, `src/apps/cyfs_gateway/src/lib.rs` |

## Implementation Order
| step | change_id | action | output |
|------|-----------|--------|--------|
| 1 | P-control-server-port-config-1 | Add config-loading helper in `gateway.rs` that validates and applies `control_port`. | Effective config rewrites `__control_server__` bind to `127.0.0.1:<port>`. |
| 2 | P-control-server-port-config-1 | Update rootfs example with commented `control_port`. | Template/example documents the supported field without changing default behavior. |
| 3 | P-control-server-port-config-1 | Add testing-stage cases for explicit, invalid, and multi-instance ports. | Test evidence for triggered checks. |

## Key Decisions
- `control_port` is a top-level field.
- `control_port` accepts integer ports and numeric strings after params are applied.
- Valid range is `1..=65535`; `0`, negative values, non-numeric strings, arrays, and objects are invalid.
- Runtime bind is always `127.0.0.1:<control_port>`.
- If `control_port` and `stacks.__control_server__.bind` are both present, `control_port` wins.
- Existing configs with no `control_port` keep the embedded default `127.0.0.1:13451`.

## Data and State
No durable data, database, token, certificate, cache, or serialized state changes are required. The effective in-memory config gains/retains `control_port` and updates the injected control stack bind before parsing.

## Interfaces and Dependencies
- Config interface: top-level `control_port: <u16-compatible value>`.
- Internal effective config: `stacks.__control_server__.bind` is set to `127.0.0.1:<control_port>` when `control_port` exists.
- Existing control RPC, login token, and server implementation remain unchanged.
- Dependency on `runtime-configs`: `src/rootfs/etc/cyfs_gateway.yaml` must document the new field or explicitly omit it; this design chooses to document it as a commented example.

## Document Index
| path | purpose |
|------|---------|
| `docs/versions/v0.6/modules/gateway-runtime/proposal.md` | Approved requirement baseline for `P-control-server-port-config-1`. |
| `docs/versions/v0.6/modules/gateway-runtime/design.md` | This design and implementation admission mapping. |
| `docs/versions/v0.6/modules/gateway-runtime/testing.md` | Testing-stage coverage to be updated after implementation. |
| `docs/versions/v0.6/modules/gateway-runtime/testplan.yaml` | Unified test entry to be updated if new test commands are added. |
| `src/apps/cyfs_gateway/src/gateway.rs` | Config loading and built-in control server injection. |
| `src/rootfs/etc/cyfs_gateway.yaml` | Shipped rootfs config example/default surface. |

## Risks and Rollback
- Risk: invalid precedence between `control_port` and internal bind could surprise tests. Mitigation: `control_port` explicitly wins and tests cover it.
- Risk: accepting a host would expand the control-plane trust boundary. Mitigation: only port values are accepted and host remains loopback.
- Risk: port allocation races in tests. Mitigation: tests allocate ports per case and report selected ports.
- Rollback: remove `control_port` helper and rootfs example line; existing internal `stacks.__control_server__.bind` override remains available.

## Approval Record
Auto-pipeline confirmed this design after `doc-structure-check.py --docs design` passed. Launch evidence is recorded in `harness/pipeline-plan.md`.
