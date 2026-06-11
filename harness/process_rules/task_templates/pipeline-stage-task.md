# Pipeline Stage Task

## Task Identity
- Task ID:
- Stage: design / implementation / testing / acceptance
- Responsibility:
- Scope:
- Version:
- Module:
- Submodule:
- change_id:
- Parent Task:
- Depends On:
- Owner:

## Goal
- Describe the single stage outcome this task must complete.

## Inputs
- Proposal inputs:
- Upstream task outputs:
- Relevant docs:
- Relevant code:
- Constraints:

## Admission Checks
- [ ] For implementation-like scopes: `harness/rules/task-entry-gate-rules.md` was applied before any code, test, build, or resource edit
- [ ] Required upstream artifacts exist
- [ ] Required upstream approvals exist
- [ ] If per-stage user confirmation is skipped, the pipeline plan records explicit user auto-pipeline authorization
- [ ] The pipeline plan task status was updated to `confirmed` or `complete` before dependent tasks continue
- [ ] If this task produces a stage document and auto-confirmation is enabled, the document front matter was updated to `status: approved`, `approved_by: auto-pipeline`, `approved_at`, and `approved_content_sha256`
- [ ] Scope does not cross into another stage
- [ ] If scope crosses into another stage, the user explicitly requested those stages or cross-stage synchronization
- [ ] For single-stage tasks, `stage-scope-check.py --stage <stage>` passed for the current diff (implementation runs add `--change-id <change_id>` per admitted id so the diff is bound to the design Scope Paths)
- [ ] For implementation: `proposal.md` and `design.md` are both `approved`
- [ ] For implementation: active `version`, `module`, and `change_id` are explicit
- [ ] For implementation in a direct submodule packet: active `submodule` is explicit
- [ ] For implementation: `schema-check.py` passed for the active module packet
- [ ] For implementation: `harness/evidence/admission/<task-id>.md` contains required admission evidence
- [ ] For implementation: `admission-check.py --evidence-file harness/evidence/admission/<task-id>.md` passed for every admitted `change_id`
- [ ] For implementation in a direct submodule packet: both checks passed with `--submodule <submodule>`
- [ ] For implementation: approved-doc inspection and task coverage judgment are recorded in the admission evidence file
- [ ] For cross-module implementation: each affected module passed admission independently
- [ ] For cross-submodule implementation: each affected submodule packet passed admission independently
- [ ] For implementation: code edits started only after `admission-check.py` passed with the admission evidence file

## Allowed Changes
- Can modify:
- Must not modify:

## Implementation Admission Evidence
| evidence_item | source | status | notes |
|---------------|--------|--------|-------|
| proposal_read | `proposal.md` section/table | pass/fail | cite admitted `change_id` and relevant proposal coverage |
| design_read | `design.md` section/table | pass/fail | cite admitted `change_id` and relevant design coverage |
| change_scope_matches_request | user request + proposal/design mapping | pass/fail | explain why the admitted scope covers this task |
| active_module_resolved | module packet path | pass/fail | version/module/submodule if applicable |
| no_chat_only_evidence | versioned docs and inspected code | pass/fail | confirm no oral/chat-only requirement is used as admission evidence |

Stage-task defaults:
- Proposal can modify: `proposal.md` in the active module or submodule packet only
- Design can modify: `design.md`, `design/`, direct submodule packet design files, and required long-lived boundary sync only
- Implementation can modify: production code, required non-test runtime/build resources, and task admission evidence under `harness/evidence/admission/` only
- Testing can modify: test code, test fixtures, test runners, unified test entrypoint wiring, and optional testing artifacts only
- Acceptance can modify: review reports and generated acceptance rules/expected-result evidence only
- Downstream follow-up from an upstream change is recorded as a return route unless cross-stage synchronization was explicitly requested

## Required Outputs
- Output 1:
- Output 2:

## Done Condition
- [ ] Required output exists
- [ ] For testing: every generated or changed automated test is reachable through `harness/scripts/test-run.py`
- [ ] For acceptance: test design adequacy was reviewed, including relevant normal, boundary, negative, error, compatibility, lifecycle, and cross-module cases
- [ ] For acceptance: incomplete, ambiguous, unreasonable, stale, or non-runnable test coverage was routed back to testing
- [ ] Scope boundary respected
- [ ] Stage scope check passed when applicable
- [ ] Dependencies satisfied
- [ ] Evidence attached

## Failure Handling
- If blocked by an upstream issue, do not patch outside scope.
- Record:
  - blocking issue
  - suspected owning stage
  - return target
  - evidence
