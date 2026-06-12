# Pipeline Plan

## Trigger
- Approved proposal: docs/versions/v0.6/modules/gateway-runtime/proposal.md
- User launch confirmed: yes
- Per-stage user confirmation: not required; user said "确定，自动处理后续步骤"; for `dir-server-range`, user confirmed continuation with "确认"
- Auto-confirm completed document stages: yes
- Version: v0.6
- Module(s): gateway-runtime
- change_id values: P-control-server-port-config-1, P-test-server-local-runner-1, P-dir-server-range-1

## Stage Graph
| task_id | stage | status | responsibility | scope | parent_task | depends_on | output | done_condition |
|---------|-------|--------|----------------|-------|-------------|------------|--------|----------------|
| D-control-port | design | complete | Define `control_port` config shape, runtime wiring, validation, scope paths, and trigger coverage. | docs/versions/v0.6/modules/gateway-runtime/design.md | pipeline | proposal approval | approved design.md | design doc structure and schema checks pass |
| I-control-port | implementation | blocked | Implement top-level `control_port` handling and default compatibility. | production code and admission evidence | pipeline | D-control-port | code changes and admission evidence | schema/admission checks passed; implementation scope check is blocked by mixed worktree changes |
| T-control-port | testing | complete | Add and run tests for default, explicit, invalid, and multi-instance control ports. | testing artifacts and test code | pipeline | I-control-port | updated testing evidence and runnable test results | relevant gateway-runtime tests passed; red-green pre-fix artifact remains a testing evidence gap |
| A-control-port | acceptance | complete | Audit proposal, design, implementation, tests, and evidence for `control_port`. | docs/versions/v0.6/reviews/ | pipeline | T-control-port | docs/versions/v0.6/reviews/gateway-runtime-control-port-config-20260612.md | report concludes needs changes |
| D-test-server-local-runner | design | complete | Define helper app runtime wrapper, scope path, and local task context behavior. | docs/versions/v0.6/modules/gateway-runtime/design.md | pipeline | proposal approval | approved design.md | design doc structure and schema checks pass |
| I-test-server-local-runner | implementation | complete | Wrap `test_server` `Runner` execution in a Tokio current-thread `LocalSet`. | production code and admission evidence | pipeline | D-test-server-local-runner | code changes and admission evidence | schema/admission checks pass; implementation scope check records combined-diff limitation |
| T-test-server-local-runner | testing | complete | Run focused process smoke for `test_server` request handling without `spawn_local` panic. | testing evidence | pipeline | I-test-server-local-runner | runnable test result artifact | focused manual smoke passed; machine-written test-run artifact remains a gap |
| A-test-server-local-runner | acceptance | complete | Audit docs, code, and evidence for `P-test-server-local-runner-1`. | docs/versions/v0.6/reviews/ | pipeline | T-test-server-local-runner | docs/versions/v0.6/reviews/gateway-runtime-test-server-local-runner-20260612.md | report concludes needs changes |
| D-dir-server-range | design | complete | Define `DirServer` single Range parsing, 206/416 response shape, scope path, and rollback. | docs/versions/v0.6/modules/gateway-runtime/dir-server-range/design.md | pipeline | dir-server-range proposal approval | approved design.md | design doc structure and schema checks pass |
| I-dir-server-range | implementation | complete | Fix `DirServer` Range parsing and invalid Range response handling. | production code and admission evidence | pipeline | D-dir-server-range | code changes and admission evidence | schema/admission checks passed; implementation scope check is blocked by mixed worktree and cross-stage docs in the same diff |
| T-dir-server-range | testing | complete | Add and run focused regression tests for exact, open-ended, suffix, malformed, out-of-bounds, and multi-range Range behavior. | test code, testing artifacts, and runnable evidence | pipeline | I-dir-server-range | tests and evidence | focused regression and dir_server tests passed; parent unit artifact includes DirServer step pass but fails later in unrelated QUIC step |
| A-dir-server-range | acceptance | pending | Audit proposal, design, implementation, tests, and evidence for `P-dir-server-range-1`. | docs/versions/v0.6/reviews/ | pipeline | T-dir-server-range | docs/versions/v0.6/reviews/gateway-runtime-dir-server-range-20260612.md | report concludes accepted or routes concrete fixes |

## Return Routing
- Proposal issue: return to proposal and re-approve before continuing.
- Design issue: return to D-control-port.
- Implementation issue: return to I-control-port after design/admission coverage is corrected.
- Testing issue: return to T-control-port.
- Acceptance issue: route to the owning earlier stage named by the acceptance finding.

## Exit Condition
- [x] `P-control-server-port-config-1` has approved design coverage.
- [x] Implementation admission passed for `P-control-server-port-config-1`.
- [x] `control_port` implementation is complete.
- [x] Required tests and evidence exist.
- [x] Acceptance report is complete.
- [ ] Acceptance concluded `accepted`.
- [x] `P-test-server-local-runner-1` has approved design coverage.
- [x] Implementation admission passed for `P-test-server-local-runner-1`.
- [x] `test_server` LocalSet implementation is complete.
- [x] Focused `test_server` smoke evidence exists.
- [x] `P-dir-server-range-1` has approved design coverage.
- [x] Implementation admission passed for `P-dir-server-range-1`.
- [x] `DirServer` Range implementation is complete.
- [x] Focused Range regression evidence exists.
- [ ] DirServer Range acceptance report is complete.
