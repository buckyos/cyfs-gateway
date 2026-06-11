# Pipeline Submodule Task

## Task Identity
- Task ID:
- Stage:
- Responsibility:
- Version:
- Module:
- Submodule:
- change_id:
- Parent Task:
- Depends On:
- Owner:

## Goal
- Complete the named stage for this direct submodule only.

## Scope Boundary
- In scope:
- Out of scope:
- Shared topics handled elsewhere:

## Inputs
- Proposal excerpts:
- Design references:
- Testing references or generated test evidence:
- Upstream outputs:

## Admission Checks
- [ ] Required upstream artifacts exist
- [ ] Required upstream approvals exist
- [ ] If per-stage user confirmation is skipped, the pipeline plan records explicit user auto-pipeline authorization
- [ ] The pipeline plan task status was updated to `confirmed` or `complete` before dependent tasks continue
- [ ] If this task produces a stage document and auto-confirmation is enabled, the document front matter was updated to `status: approved`, `approved_by: auto-pipeline`, `approved_at`, and `approved_content_sha256`
- [ ] Scope stays inside this direct submodule
- [ ] Scope stays inside the named stage unless the user explicitly requested cross-stage synchronization
- [ ] For single-stage tasks, `stage-scope-check.py --stage <stage>` passed for the current diff (implementation runs add `--change-id <change_id>` per admitted id so the diff is bound to the design Scope Paths)
- [ ] For implementation: proposal and design inputs for this submodule are approved
- [ ] For implementation: active `version`, `module`, submodule, and `change_id` are explicit
- [ ] For implementation: `schema-check.py --submodule <submodule>` passed for the submodule packet
- [ ] For implementation: `harness/evidence/admission/<task-id>.md` contains required admission evidence
- [ ] For implementation: `admission-check.py --submodule <submodule> --evidence-file harness/evidence/admission/<task-id>.md` passed for every admitted `change_id`
- [ ] For implementation: the approved submodule doc inspection and coverage judgment are recorded in the admission evidence file

## Implementation Admission Evidence
| evidence_item | source | status | notes |
|---------------|--------|--------|-------|
| proposal_read | `<submodule>/proposal.md` section/table | pass/fail | cite admitted `change_id` and relevant proposal coverage |
| design_read | `<submodule>/design.md` section/table | pass/fail | cite admitted `change_id` and relevant design coverage |
| change_scope_matches_request | user request + proposal/design mapping | pass/fail | explain why the admitted scope covers this submodule task |
| active_module_resolved | submodule packet path | pass/fail | version/module/submodule |
| no_chat_only_evidence | versioned docs and inspected code | pass/fail | confirm no oral/chat-only requirement is used as admission evidence |

## Required Outputs
- Output file(s):
- Evidence:

## Allowed Changes
- Can modify:
- Must not modify:

Stage-task defaults:
- Proposal can modify: `<submodule>/proposal.md` only
- Design can modify: `<submodule>/design.md` and required long-lived boundary sync only
- Implementation can modify: production code, required non-test runtime/build resources, and task admission evidence under `harness/evidence/admission/` only
- Testing can modify: test code, test fixtures, test runners, unified test entrypoint wiring, and optional `<submodule>/testing.md` / `<submodule>/testplan.yaml` only
- Acceptance can modify: review reports and generated acceptance rules/expected-result evidence only
- Cross-stage edits require explicit user instruction naming the extra stage(s) or asking for cross-stage synchronization

## Done Condition
- [ ] Submodule output is complete
- [ ] For testing: submodule tests are reachable through `harness/scripts/test-run.py <module>/<submodule> all` or the repository's documented submodule equivalent
- [ ] For acceptance: submodule test design adequacy was reviewed, including relevant normal, boundary, negative, error, compatibility, lifecycle, and cross-module cases
- [ ] For acceptance: incomplete, ambiguous, unreasonable, stale, or non-runnable submodule test coverage was routed back to testing
- [ ] No out-of-scope files were changed
- [ ] Stage scope check passed when applicable
- [ ] Handover data for the next dependent task exists

## Failure Handling
- If the issue is shared or upstream, return it instead of solving it inside this submodule task.
- Record:
  - issue id
  - return stage
  - return target task
  - expected upstream fix
