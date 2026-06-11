# Acceptance Review Gate

## Goal
- Define acceptance as an evidence-chain and consistency review.
- Acceptance confirms that the behavior described by the approved documents is implemented, that the documents agree with each other and with the implementation, and that no document or implementation logic defect invalidates the result.
- Git diff output is optional scoping evidence. It is not the acceptance standard, and diff-only cleanliness problems do not block acceptance unless they reveal a document inconsistency, document-to-implementation mismatch, missing approved behavior, or logical defect.

## Required Audits
Acceptance MUST perform:
- document coverage audit for every behavior, non-goal, constraint, and acceptance boundary described by the approved documents
- document consistency audit across proposal, design, optional testing artifacts, generated acceptance rules, expected results, and long-lived module docs
- implementation consistency audit between the approved proposal/design documents and the delivered implementation/test evidence
- test design adequacy audit for whether post-implementation tests reasonably cover proposal/design/code behavior, including normal, boundary, negative, error, compatibility, lifecycle, and cross-module cases where applicable
- logic audit for contradictions, impossible states, missing cases, invalid assumptions, or other reasoning defects in documents or implementation
- trigger matrix authenticity audit: for the reviewed change, verify that `applies: no` rows cite evidence that exists and actually supports non-applicability, and that `applies: yes` rows have their required checks present in the test or review evidence; template-like, copy-pasted, or unverifiable trigger evidence is a finding against the owning document stage

## Optional Diff Commands
When useful for locating changed files or implementation evidence, run and record:
- `git status --short`
- `git diff --stat`
- `git diff --name-status`
- `git diff --check`

These commands are evidence discovery tools only. Their output is not a pass/fail criterion by itself.

For public symbol, API, codec, or wire-format migrations, also run a targeted search such as:
- `rg "old_symbol|old_encoding|old_method"`

## Required Harness Commands
For every module needed as evidence for accepted behavior, run and record:
- `uv run --active python ./harness/scripts/schema-check.py --version <version> --module <module>`
- `uv run --active python ./harness/scripts/admission-check.py --version <version> --module <module> --change-id <change_id> --evidence-file harness/evidence/admission/<task-id>.md`
- the relevant generated test commands through `uv run --active python ./harness/scripts/test-run.py <module> <level-or-all>`

For every direct submodule packet needed as evidence for accepted behavior, run the same commands with `--submodule <submodule>`.

For whole-project evidence or final pipeline acceptance, run and record:
- `uv run --active python ./harness/scripts/test-run.py all all`
- the project-root shortcut with no arguments, for example `test-run.bat` or `./test-run.sh`, unless the current platform cannot execute that format

For code-level quality evidence, run and record:
- `uv run --active python ./harness/scripts/quality-check.py` (per `harness/rules/quality-gate-rules.md`; required whenever `harness/quality-gates.yaml` declares at least one gate)

For single-stage tasks, run and record:
- `uv run --active python ./harness/scripts/stage-scope-check.py --stage <stage> --version <version> --module <module>` (plus `--submodule <submodule>` for submodule packets; implementation-stage runs additionally pass `--change-id <change_id>` per admitted id so the diff is bound to the design Scope Paths)

For the acceptance report, run and record before completion:
- `uv run --active python ./harness/scripts/acceptance-report-check.py <report>`

Test and quality execution evidence MUST be the machine-written run artifacts (`harness/evidence/test-runs/*.json` from `test-run.py`, `harness/evidence/quality-runs/*.json` from `quality-check.py`): cite the artifact paths in the report. Pasted or summarized command output without a matching artifact is not execution evidence, and `acceptance-report-check.py` re-verifies that the referenced artifacts exist, passed, and are fresh.

If a test layer is manual, disabled, or deferred, the acceptance report MUST cite the generated test evidence and any optional testing document or `testplan.yaml` reason.

## Evidence Scope Audit
Acceptance MUST identify the documents, code paths, tests, and results used as evidence for each approved behavior.

Changed-file classification is optional and only supports evidence discovery. Do not reject acceptance merely because the working tree contains unrelated churn, formatting changes, generated files, or other diff noise. Reject only when the reviewed evidence shows:
- an approved document behavior is not implemented
- documents disagree with each other
- documents and implementation disagree
- a document contains a logical contradiction, unsupported assumption, or impossible requirement
- implementation contains a logical correctness, compatibility, lifecycle, state, or error-handling defect relevant to the accepted behavior

## Cross-Module Admission Audit
- Acceptance MUST NOT check only the current module or declared `change_id`.
- Every evidence-bearing module MUST have approved proposal/design coverage and post-implementation test evidence.
- Every evidence-bearing module MUST have a direct `change_id` mapping across proposal and design, plus generated test coverage or an explicit testing gap.
- Every automated test used as acceptance evidence MUST be reachable through the unified test entrypoint.
- The project-root test shortcut MUST delegate to the unified test entrypoint and must not maintain a separate test list.
- Evidence spanning multiple modules MUST pass schema and admission checks independently for each affected module packet.
- Evidence spanning multiple submodule packets MUST pass schema and admission checks independently for each affected submodule packet.
- If the implementation evidence for an accepted behavior depends on a module with draft, missing, ambiguous, or non-covering proposal/design documents or missing test evidence, acceptance MUST fail even when workspace tests pass.

## Test Design Adequacy Audit
Acceptance MUST review the post-implementation test design before marking work accepted:
- each approved behavior, constraint, non-goal, acceptance boundary, and implemented `change_id` MUST map to concrete test evidence or an explicit gap
- normal success paths, boundary values, negative inputs, error paths, compatibility or migration behavior, lifecycle/state transitions, concurrency or retry behavior, and cross-module effects MUST be covered when relevant to the proposal/design/code
- completed testing work MUST include `testplan.yaml` unless a repo-local versioned exception records reason, owner, risk, and acceptance impact
- bugfix work MUST show red-green regression evidence: a regression test bound to the bugfix `change_id` that reproduced the defect (a failing pre-fix run artifact, or a recorded concrete reason why reproduction was not feasible) and passes after the fix; happy-path-only validation of a bugfix is a test design gap
- optional `testing.md`, `testing/`, and required `testplan.yaml` must agree with the delivered test implementation and command evidence when present
- tests that only prove the happy path are insufficient when the proposal/design/code creates meaningful edge, failure, compatibility, or integration risk
- broad assertions, smoke-only tests, or unregistered tests do not count as complete coverage unless the acceptance report records why deeper validation is not applicable

If the test design is incomplete, unreasonable, ambiguous, stale relative to delivered code, or not reachable through the unified test entrypoint, acceptance MUST fail and return work to the testing stage to supplement test design, test implementation, metadata, and runnable evidence before acceptance is retried.

## Implementation Logic Checklist
Acceptance MUST review the implementation evidence for correctness risks beyond test pass/fail:
- public API, enum, codec, or wire-format changes
- downstream semantic changes, compatibility shims, or migration behavior that is missing from design coverage or post-implementation test evidence
- language-level invariant violations, such as inconsistent `Eq` and `Hash` behavior in Rust
- concurrency, state-machine, resource-release, lifecycle, retry, or cancellation defects
- error-path gaps and fallback behavior
- risks that tests do not cover but that are logically inferable from the code

## Document Timing Consistency
- Approval staleness is checked mechanically: every approved document records `approved_content_sha256`, and `schema-check.py` fails when the current content no longer matches it. A failing hash means the document changed after approval and needs re-approval before its content counts as approved evidence.
- Downstream `design.md` approval metadata MUST NOT predate new proposal coverage it claims to implement.
- Optional testing artifacts created before the final implementation MUST be regenerated or explicitly revalidated against the delivered code.
- If approved documents receive new substantive content, acceptance MUST require re-approval; the re-approval updates `approved_content_sha256` in the same edit.
- Acceptance MUST fail when approval state exists but the approved content does not directly cover the reviewed evidence.

## Acceptance Must Fail If
- any approved behavior, constraint, non-goal, or acceptance boundary described by the documents is not implemented or cannot be verified
- any required evidence module lacks approved proposal/design coverage or post-implementation test evidence
- a single-stage task fails `stage-scope-check.py --stage <stage>`
- public API, codec, wire format, or runtime semantics changed without direct design coverage and generated test coverage or an explicit gap
- test design or test implementation does not reasonably cover the proposal/design/code behavior and relevant normal, boundary, negative, error, compatibility, lifecycle, or cross-module cases
- required test evidence is ambiguous, stale, unregistered with the unified test entrypoint, or not mapped to the reviewed `change_id` values
- required test or quality execution evidence lacks a matching machine-written run artifact, or the referenced artifact is missing, failing, or stale
- `harness/quality-gates.yaml` declares gates but no fresh passing quality run artifact exists, or the config file itself is missing
- a reviewed bugfix lacks red-green regression evidence for its `change_id` and no concrete infeasibility reason is recorded
- the implementation diff was not bound to the admitted design Scope Paths (`stage-scope-check.py --stage implementation --change-id ...` missing or failing)
- completed testing work lacks `testplan.yaml` and no repo-local versioned exception records reason, owner, risk, and acceptance impact
- trigger matrix evidence for the reviewed change is template-like, copy-pasted, unverifiable, or contradicted by the inspected code
- stage documents contradict each other, or downstream documents silently narrow or expand approved proposal intent
- documents and implementation describe different behavior
- any document or implementation contains a plausible correctness, compatibility, governance, or logical defect
- the same non-requirement issue remains unresolved after more than 5 design -> implementation -> testing iterations

## Report Format
- Findings MUST appear first in the acceptance report and be sorted by severity.
- Test success is supporting evidence only; it does not automatically mean accepted.
- Any High finding MUST produce a `rejected` or `needs changes` conclusion.
- The report MUST include generated acceptance rules, expected results, document coverage, consistency findings, implementation evidence, test design adequacy, harness command results, test evidence, optional diff summaries if used, iteration count, and unresolved risks.
- The iteration count is defined mechanically, not from memory: for each blocking issue id, count the recorded acceptance returns for that issue id in `harness/pipeline-plan.md` (pipeline work) or the prior acceptance reports under `docs/versions/<version>/reviews/` that name the same issue id (non-pipeline work), plus the current run. When the count for one unresolved issue exceeds 5, stop and report the issue to the user instead of looping again.
- `acceptance-report-check.py` MUST fail the report when these required fields are missing, placeholder-only, or incompatible with an `accepted` conclusion.
