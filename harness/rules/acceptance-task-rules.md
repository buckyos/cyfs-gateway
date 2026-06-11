# Acceptance Task Rules

## Goal
- Define how acceptance evaluates evidence and records outcomes.

## Scope
- optional `acceptance.md`
- review reports under `docs/versions/<version>/reviews/`

## Required Inputs
- `proposal.md`
- `design.md` and `design/`
- testing implementation, test fixtures, test runners, and optional `testing.md`, `testing/`, or `testplan.yaml`
- direct submodule packets under `docs/versions/<version>/modules/<module>/<submodule>/` when the work is split by submodule
- optional `acceptance.md`
- long-lived module docs
- implementation
- test code
- test results
- optional git diff/status evidence when useful for locating changed files
- `harness/rules/acceptance-review-rules.md`

## Acceptance Rule
- Acceptance evaluates consistency across the entire evidence chain.
- Acceptance MUST apply `harness/rules/acceptance-review-rules.md` and judge whether the documents' described behavior is implemented and internally coherent.
- Git diff/status output is not the acceptance standard. Diff noise, unrelated churn, or `git diff --check` output should not decide acceptance unless it exposes a document inconsistency, document-to-implementation mismatch, missing approved behavior, or logical defect.
- Acceptance MUST check consistency between proposal, design, code implementation, and test implementation.
- If consistency problems exist, the approved `proposal.md` is authoritative.
- Subject to satisfying the approved proposal, acceptance MUST route non-requirement fixes through design -> implementation/code -> testing implementation.
- Optional testing documents MUST conform to design documents; code MUST conform to design; tests MUST verify proposal/design/code behavior.
- Acceptance MUST write a standalone review report instead of editing implementation or stage docs.
- Acceptance MUST NOT directly edit `proposal.md`, `design.md`, `design/`, `testing.md`, `testing/`, `testplan.yaml`, code, or test code unless the user explicitly requested a separate cross-stage update task.
- Acceptance MUST identify the owning stage for each blocking mismatch.
- Acceptance MUST verify that the reviewed change maps back to direct proposal and design items, not only to module-overview or baseline text.
- Acceptance MUST verify that reviewed implementation changes map to stable `change_id` values across proposal and design, and that testing implementation covers those `change_id` values or records an explicit gap.
- Acceptance MUST verify every module needed as evidence for accepted behavior has approved, directly mapped proposal/design coverage and post-implementation testing evidence.
- Acceptance MUST verify every direct submodule packet needed as evidence for accepted behavior has approved, directly mapped proposal/design coverage and post-implementation testing evidence.
- Acceptance MUST verify completed testing work includes `testplan.yaml`, unless a repo-local versioned exception records the reason, owner, risk, and acceptance impact.
- Acceptance MUST verify that post-implementation test design is reasonable for proposal/design/code behavior and covers normal, boundary, negative, error, compatibility, lifecycle, and cross-module cases where applicable.
- Acceptance MUST verify that test design and test implementation coverage map to reviewed `change_id` values, or that explicit gaps are recorded with a reason.
- Acceptance MUST verify that automated test evidence is reachable through the unified test entrypoint `harness/scripts/test-run.py`, and that whole-project tests can be invoked through `test-run.py all all`.
- Acceptance MUST cite machine-written run artifacts as execution evidence: `harness/evidence/test-runs/*.json` for test runs and `harness/evidence/quality-runs/*.json` for quality gates; claimed runs without an artifact are missing evidence.
- Acceptance MUST run `uv run --active python ./harness/scripts/quality-check.py` and treat failing or unrun configured quality gates as blocking; see `harness/rules/quality-gate-rules.md`.
- Acceptance MUST verify red-green regression evidence for reviewed bugfix work: a regression test bound to the bugfix `change_id` with a failing pre-fix run artifact or a recorded concrete infeasibility reason.
- Acceptance MUST verify the implementation diff was bound to the admitted design Scope Paths via `stage-scope-check.py --stage implementation --change-id ...`.
- Acceptance MUST treat missing or ambiguous active module / `change_id` evidence as a blocking admission failure.
- Acceptance MUST treat missing or ambiguous active submodule evidence as a blocking admission failure when the change belongs to a direct submodule packet.
- Acceptance MUST NOT mark the work as passed when required evidence is missing.
- Acceptance MUST NOT mark the work as passed only because tests passed.
- Acceptance MUST generate or finalize acceptance rules and expected results from `proposal.md`, `design.md`, implementation, and testing implementation before judging pass/fail.
- Acceptance MUST run `uv run --active python ./harness/scripts/acceptance-report-check.py <report>` before marking the report complete.
- An `accepted` conclusion is invalid when `acceptance-report-check.py` fails.

## Failure Handling
- proposal mismatch: return to proposal
- proposal-to-design mismatch: return to design unless the proposal itself is ambiguous or contradictory
- design-to-code mismatch: return to implementation/code
- missing, invalid, incomplete, ambiguous, stale, or unreasonable test design / test implementation coverage: return to testing
- test evidence not reachable through the unified test entrypoint: return to testing
- document-to-code mismatch: return to implementation/code
- implementation defect: return to implementation
- logic or consistency finding: return to the owning stage named by the finding
- non-requirement findings: repeat design -> implementation -> testing implementation, then rerun acceptance
- more than 5 unsuccessful iterations for the same unresolved issue: stop and report the issue to the user
