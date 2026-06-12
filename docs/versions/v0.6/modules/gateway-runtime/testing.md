---
module: gateway-runtime
version: v0.6
status: approved
approved_by: auto-pipeline
approved_at: 2026-06-12T10:58:43+08:00
approved_content_sha256: fc2deef8409dc0f1b327876b06fa68d0a61f3baebce3f9e8542eeed58b7b8e69
---

# gateway-runtime Testing

## Metadata
- version: v0.6
- module: gateway-runtime
- stage: testing
- status: approved
- approved_by: auto-pipeline
- approved_at: 2026-06-11T23:55:57+08:00

## Test Document Index
| document | purpose | scope |
|----------|---------|-------|
| `docs/versions/v0.6/modules/gateway-runtime/testplan.yaml` | Unified runnable test entry. | unit, dv, integration |
| `docs/versions/v0.6/modules/gateway-runtime/testing/app-process-integration-python-plan.md` | App-process integration case matrix. | real `cyfs_gateway` binary and multi-gateway flows |

## Unified Test Entry
- Unit: `python3 ./harness/scripts/test-run.py gateway-runtime unit`
- DV: `python3 ./harness/scripts/test-run.py gateway-runtime dv`
- Integration: `python3 ./harness/scripts/test-run.py gateway-runtime integration`
- All: `python3 ./harness/scripts/test-run.py gateway-runtime all`

## Submodule Tests
| submodule | responsibility | validation_ids | files |
|-----------|----------------|----------------|-------|
| control-plane-config | Validate top-level `control_port` parsing and effective loopback bind rewrite. | unit.gateway-runtime-control-port-config | `src/apps/cyfs_gateway/src/gateway.rs` |
| control-plane-runtime | Validate assembled control plane still starts and serves RPC. | dv.gateway-runtime-dv, integration.gateway-runtime-integration | `src/apps/cyfs_gateway/tests/test_control_server.rs`, `src/apps/cyfs_gateway/tests/test_cyfs_gateway.rs` |
| multi-gateway-app-process | Validate multiple app processes use isolated control ports. | integration.gateway-runtime-app-process-integration | `tests/integration/cyfs_gateway_app/run.py` |
| reuseport-stack-listeners | Preserve existing TCP/TLS/UDP/QUIC reuseport focused tests. | unit.gateway-runtime-tcp-stack, unit.gateway-runtime-tls-stack, unit.gateway-runtime-udp-stack, unit.gateway-runtime-quic-stack | `src/components/cyfs-gateway-lib/src/stack/*.rs` |
| test-server-helper | Validate `test_server` can serve through `cyfs_gateway_lib::Runner` without missing Tokio local context. | integration.gateway-runtime-test-server-local-runner | `src/apps/test_server/src/main.rs` |

## Module-Level Tests
| validation_id | level | command | expected_result |
|---------------|-------|---------|-----------------|
| unit.gateway-runtime-control-port-config | unit | `cd src && cargo test -p cyfs_gateway test_apply_control_port_config -- --test-threads=1` | default, explicit numeric, explicit string, and invalid `control_port` cases behave as designed |
| dv.gateway-runtime-dv | dv | `cd src && cargo test -p cyfs_gateway --test test_control_server -- --test-threads=1` | control server assembly and RPC smoke pass |
| integration.gateway-runtime-integration | integration | `cd src && cargo test -p cyfs_gateway --test test_cyfs_gateway -- --test-threads=1` | full runtime test starts with top-level `control_port` and control RPC succeeds |
| integration.gateway-runtime-app-process-integration | integration | `python3 tests/integration/cyfs_gateway_app/run.py` | multi-gateway app-process configs use top-level `control_port` and avoid control port collisions |
| integration.gateway-runtime-test-server-local-runner | integration | `cd src && cargo build -p test_server --bin test_server`, then run `target/debug/test_server` with `TEST_SERVER_PORT=<free_port>` and one HTTP request to `/server/` | `test_server` accepts the request and does not panic from `spawn_local` outside a `LocalSet` |

## External Interface Tests
| interface | responsibility | positive_case | negative_or_boundary_case | validation_id |
|-----------|----------------|---------------|---------------------------|---------------|
| `control_port` config key | Select built-in control server port. | `control_port: <free_port>` rewrites bind to `127.0.0.1:<free_port>`. | `0`, out-of-range numbers, non-numeric strings, and objects are rejected. | unit.gateway-runtime-control-port-config |
| Control HTTP API | Verify selected control port is reachable. | login/system info through selected control endpoint. | unauthorized/invalid token behavior remains covered by control-plane DV. | dv.gateway-runtime-dv |
| Multi-instance config | Run multiple gateway processes without fixed control-port collision. | remote/client app configs use distinct `control_port` values. | process startup failure reports selected port in test diagnostics. | integration.gateway-runtime-app-process-integration |
| `test_server` helper HTTP endpoint | Verify helper runtime supplies Tokio local task context for `Runner`. | request to `/server/` returns helper response. | pre-fix reproduction records missing `LocalSet` panic or an infeasibility reason. | integration.gateway-runtime-test-server-local-runner |

## Direct Change Coverage
| change_id | design_source | validation_id | testplan_level | testplan_step_id | gap | gap_manual_reason |
|-----------|---------------|---------------|----------------|------------------|-----|-------------------|
| P-base-1 | `design.md` Directly Mapped Change Items | unit.gateway-runtime-unit | unit | gateway-runtime-unit | no | none |
| P-control-server-port-config-1 | `design.md` Directly Mapped Change Items and Trigger Matrix | unit.gateway-runtime-control-port-config | unit | gateway-runtime-control-port-config | no | none |
| P-test-server-local-runner-1 | `design.md` Directly Mapped Change Items and Trigger Matrix | integration.gateway-runtime-test-server-local-runner | integration | gateway-runtime-test-server-local-runner | no | none |
| P-tcp-reuseport-1 | `design.md` Directly Mapped Change Items | unit.gateway-runtime-tcp-stack | unit | gateway-runtime-tcp-stack | no | none |
| P-tls-reuseport-1 | `design.md` Directly Mapped Change Items | unit.gateway-runtime-tls-stack | unit | gateway-runtime-tls-stack | no | none |
| P-udp-reuseport-1 | `design.md` Directly Mapped Change Items | unit.gateway-runtime-udp-stack | unit | gateway-runtime-udp-stack | no | none |
| P-quic-reuseport-1 | `design.md` Directly Mapped Change Items | unit.gateway-runtime-quic-stack | unit | gateway-runtime-quic-stack | no | none |

## Case-Type Coverage
| change_id | case_type | required | validation_id | status | gap_manual_reason |
|-----------|-----------|----------|---------------|--------|-------------------|
| P-control-server-port-config-1 | normal | yes | unit.gateway-runtime-control-port-config | covered | none |
| P-control-server-port-config-1 | boundary | yes | unit.gateway-runtime-control-port-config | covered | none |
| P-control-server-port-config-1 | negative | yes | unit.gateway-runtime-control-port-config | covered | none |
| P-control-server-port-config-1 | error | yes | unit.gateway-runtime-control-port-config | covered | none |
| P-control-server-port-config-1 | compatibility | yes | unit.gateway-runtime-control-port-config | covered | none |
| P-control-server-port-config-1 | lifecycle | yes | integration.gateway-runtime-integration | covered | none |
| P-control-server-port-config-1 | cross-module | yes | integration.gateway-runtime-app-process-integration | covered | none |
| P-test-server-local-runner-1 | normal | yes | integration.gateway-runtime-test-server-local-runner | covered | none |
| P-test-server-local-runner-1 | boundary | no | integration.gateway-runtime-test-server-local-runner | covered | Port selection boundary is unchanged and already delegated to existing `TEST_SERVER_PORT` parsing. |
| P-test-server-local-runner-1 | negative | no | integration.gateway-runtime-test-server-local-runner | covered | The bug is a runtime-context panic; no new input validation or denial path is introduced. |
| P-test-server-local-runner-1 | error | yes | integration.gateway-runtime-test-server-local-runner | covered | Pre-fix missing-local-context panic is the error path. |
| P-test-server-local-runner-1 | compatibility | yes | integration.gateway-runtime-test-server-local-runner | covered | Binary port configuration and HTTP routes remain unchanged. |
| P-test-server-local-runner-1 | lifecycle | yes | integration.gateway-runtime-test-server-local-runner | covered | The smoke starts the helper process, sends a request, and terminates it. |
| P-test-server-local-runner-1 | cross-module | yes | integration.gateway-runtime-test-server-local-runner | covered | Covers `test_server` consuming `cyfs_gateway_lib::Runner`. |

## Validation Rationale
Unit tests are sufficient for parser-level validation and precedence because `control_port` is applied before stack parsing. Runtime integration is still required because the change affects actual startup bind behavior. The app-process Python suite is the relevant multi-instance validation because it starts multiple real `cyfs_gateway` processes with separate control ports.

The `test_server` helper fix is best validated as a focused process smoke because the failure occurs only when `cyfs_gateway_lib::Runner` handles a request from a binary without a Tokio local task context.

## Definition of Done
- [ ] `gateway-runtime-control-port-config` unit step passes.
- [ ] `gateway-runtime-integration` passes or any failure is recorded with owner, risk, and acceptance impact.
- [ ] `gateway-runtime-app-process-integration` passes or any failure is recorded with owner, risk, and acceptance impact.
- [ ] `gateway-runtime-test-server-local-runner` passes or any failure is recorded with owner, risk, and acceptance impact.
- [ ] Testing evidence is written under `harness/evidence/test-runs/`.
- [ ] Scope checks and any failures are reported in the final acceptance evidence.

## Approval Record
Auto-pipeline confirmed this testing document after `doc-structure-check.py --docs testing` and `testing-coverage-check.py --skip-test-run-check` passed. Launch evidence is recorded in `harness/pipeline-plan.md`.
