# Pipeline Plan

## Trigger
- Approved proposal: docs/versions/v0.6/modules/gateway-runtime/proposal.md
- User launch confirmed: yes
- Per-stage user confirmation: not required; user said "确定，自动处理后续步骤"
- Auto-confirm completed document stages: yes
- Version: v0.6
- Module(s): gateway-runtime
- change_id values: P-control-server-port-config-1, P-test-server-local-runner-1

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
