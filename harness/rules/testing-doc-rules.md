# Testing Document Rules

## Goal
- Define optional persistent testing artifacts and the required post-implementation testing responsibilities.

## Scope
- `docs/versions/<version>/modules/<module>/testing.md`
- `docs/versions/<version>/modules/<module>/testing/`
- `docs/versions/<version>/modules/<module>/<submodule>/testing.md` when a large module is split into direct submodule packets
- `docs/versions/<version>/modules/<module>/testplan.yaml`
- `docs/versions/<version>/modules/<module>/<submodule>/testplan.yaml` when a large module is split into direct submodule packets

## Metadata For Optional Testing Documents
- `module`
- `version`
- `status`
- `approved_by`
- `approved_at`

## Required Content
- test cases designed after implementation from proposal, design, and delivered code
- submodule test coverage mapped to design and implementation
- module-level verification
- external interface verification
- validation rationale that ties checks to concrete behaviors, risks, or success criteria
- coverage rationale for relevant normal, boundary, negative, error, compatibility, lifecycle, and cross-module cases
- case-type coverage table for normal, boundary, negative, error, compatibility, lifecycle, and cross-module coverage for each tested `change_id`
- definition of done
- stable test entrypoints aligned with `testplan.yaml` for completed testing work
- direct change coverage for implemented work
- stable `change_id` values matching proposal and design items
- explicit gap records where direct validation does not yet exist
- large-module submodule test documentation when design uses direct submodules

## Guardrails
- Testing must operationalize approved proposal/design intent against the delivered implementation.
- Optional testing documents that use approval metadata follow the same approval authority rule: agents MUST NOT set `status: approved` on their own initiative; user approvals require a filled `## Approval Record`, and auto-pipeline approvals require `harness/pipeline-plan.md` launch evidence.
- Testing tasks run after implementation completes and MUST inspect `proposal.md`, `design.md`, and the delivered code before designing test cases.
- Testing tasks are single-stage by default and MUST NOT edit `proposal.md`, `design.md`, `design/`, acceptance artifacts, or production code unless the user explicitly requested those additional stages.
- Testing tasks may modify test code, test fixtures, test runners, and optional testing artifacts.
- Testing tasks may modify unified test entrypoint wiring when needed to register the generated tests.
- Testing tasks must not rewrite proposal, design, or production implementation artifacts.
- If proposal/design split a large module into direct submodules and optional testing artifacts are generated, those artifacts MUST mirror that split using submodule packets under the large module directory, such as `docs/versions/<version>/modules/<module>/<submodule>/testing.md` and `testplan.yaml`, not `testing/<submodule>/`.
- Human-authored testing docs MUST stay under 1000 lines each. Any testing document that would exceed 1000 lines MUST be split by submodule, responsibility, validation layer, or interface boundary and the test document index MUST be updated.
- Every implemented change MUST have direct validation coverage or an explicit gap.
- Every completed testing task MUST generate or update `testplan.yaml` unless a repo-local versioned rule explicitly disables machine-readable test metadata for the current module and the testing task records that exception.
- Every implemented `change_id` MUST map to a validation id and a generated test implementation or `testplan.yaml` step unless the validation path is explicitly `manual` or `disabled`.
- Every implemented `change_id` MUST have `## Case-Type Coverage` rows for normal, boundary, negative, error, compatibility, lifecycle, and cross-module coverage. Each non-covered, manual, disabled, or not-applicable row MUST include a concrete reason.
- Every generated or changed automated test MUST be reachable through `harness/scripts/test-run.py`.
- Testing is not complete until `uv run --active python ./harness/scripts/test-run.py <module> all` reaches the module tests and `uv run --active python ./harness/scripts/test-run.py all all` reaches all project tests registered with the harness.
- Test execution evidence is the machine-written run artifact under `harness/evidence/test-runs/` that `test-run.py` produces; cite the artifact path in testing evidence instead of pasting command output. Claimed runs without an artifact do not count.
- For bugfix work, testing MUST produce a regression test bound to the bugfix `change_id` that reproduces the defect before the fix and passes after it (red-green). Record the failing pre-fix run artifact when reproduction is feasible; when it is not (for example the fix landed before testing started, or the defect needs an unavailable environment), record the concrete reason in the testing evidence instead. A bugfix validated only by happy-path tests is incomplete testing.
- Case-type exemptions are tighter for triggered categories: when the proposal/design trigger matrix marks a category as `applies: yes`, the corresponding case-type rows (for example negative/error for security triggers, compatibility for data/contract triggers) may be `manual`, `disabled`, or not-covered only with a recorded owner, risk, and acceptance impact, not just a free-text reason.
- Validation paths MUST prove a named behavior or risk; do not add unrelated checks as evidence.
- If acceptance returns a testing gap, the testing stage must supplement the test design, test implementation, metadata when used, and unified-entrypoint runnable evidence for the missing case types before acceptance is retried.
- If a layer is `manual` or `disabled`, the reason MUST appear in generated test evidence and optional testing metadata when present.
- If a testing task discovers an upstream design or implementation problem, return work to the owning design or implementation stage instead of widening test scope silently.
- If a testing change implies acceptance updates, record the downstream follow-up unless the user explicitly requested cross-stage synchronization.
- Before testing completion, run `uv run --active python ./harness/scripts/doc-structure-check.py --version <version> --module <module> --docs testing` and `uv run --active python ./harness/scripts/testing-coverage-check.py --version <version> --module <module>`.
- Use `testing-coverage-check.py --allow-missing-testplan` only when a repo-local versioned rule explicitly permits the exception and the testing evidence records the reason, owner, risk, and acceptance impact.
