# Implementation Admission Rules

## Goal
- Define the hard prerequisites for starting implementation or bugfix work.
- This rule is reached only after `task-entry-gate-rules.md` classifies the task and requires implementation admission.

## Scope
- implementation tasks
- bugfix tasks
- production code changes for a versioned module

## Required Inputs
- `docs/versions/<version>/modules/<module>/proposal.md`
- `docs/versions/<version>/modules/<module>/design.md`
- `harness/evidence/admission/<task-id>.md`
- Or, for a direct submodule packet under a large module:
  - `docs/versions/<version>/modules/<module>/<submodule>/proposal.md`
  - `docs/versions/<version>/modules/<module>/<submodule>/design.md`

## Admission Rule
- Implementation admission MUST be evaluated before editing production code, build files, or resources.
- Implementation MUST NOT start unless all required inputs exist.
- Implementation MUST NOT start unless proposal and design documents have `status: approved`.
- Approved status alone does NOT satisfy implementation admission; implementation and bugfix tasks MUST read the approved proposal/design docs and confirm they contain task-relevant coverage for the current change.
- The read-and-coverage confirmation MUST be recorded in `harness/evidence/admission/<task-id>.md` under `## Implementation Admission Evidence`; chat-only claims or final-answer statements do not satisfy this requirement.
- The admission evidence table MUST include `proposal_read`, `design_read`, `change_scope_matches_request`, `active_module_resolved`, and `no_chat_only_evidence`, each with `status` set to `pass`, a concrete source, and task-specific notes.
- The evidence file name MUST be `harness/evidence/admission/<YYYYMMDD>-<task-slug>.md` with today's date; reusing an earlier task's evidence file fails admission.
- The evidence file MUST bind to the exact approved document content: `## Document Binding` records the LF-normalized sha256 of the packet's `proposal.md` and `design.md` (use `admission-check.py --print-doc-hashes`), and `## Coverage Quotes` records, per admitted `change_id`, a verbatim quote of the covering proposal row and design row. `admission-check.py` re-verifies both against the current documents and fails closed on mismatch.
- If a bound document changes after the evidence was written, the evidence is stale: re-read the changed document and regenerate the evidence before continuing.
- A passing `admission-check.py` run writes the admission stamp `harness/evidence/admission/<task-id>.<module>[.<submodule>].stamp.json`; `edit-guard.py` requires a valid stamp before production-code edits and re-verifies the bound document hashes on every edit. Never hand-write or edit a stamp file.
- Bugfix tasks follow the same rule unless the repository publishes an explicit exception path.
- Bugfix tasks additionally require red-green regression evidence: before or alongside the fix, the testing stage MUST produce a regression test bound to the bugfix `change_id` that reproduces the defect (a failing run recorded in a `harness/evidence/test-runs/` artifact, or a recorded concrete reason why pre-fix reproduction is not feasible) and passes after the fix. A bugfix whose tests only exercise the happy path does not satisfy this rule.
- Implementation MUST NOT start unless the active `version`, `module`, and concrete `change_id` values are known.
- If implementation targets a direct submodule packet, implementation MUST NOT start unless the active `submodule` is also known.
- Implementation MUST NOT start unless each `change_id` maps through the exact required traceability locations:
  - `proposal.md` `## Proposal Items` table, `change_id` column
  - `design.md` `## Directly Mapped Change Items` table, `change_id` column
- If the request affects multiple modules, each affected module MUST pass admission separately.
- If the request affects multiple direct submodules, each affected submodule packet MUST pass admission separately.
- Implementation MUST run `schema-check.py` and `admission-check.py --evidence-file harness/evidence/admission/<task-id>.md` successfully before code edits.
- For direct submodule packets, implementation MUST run those checks with `--submodule <submodule>`.
- If approved docs do not yet contain the current change's required content, implementation MUST stop and return work to the owning upstream doc stage before coding starts.
- Code modification may begin only after `admission-check.py` passes with the task evidence file.
- Module-level baseline docs, package overviews, historical notes, or oral explanation do not count as sufficient implementation admission.
- If direct mapping is missing, the default path is to return work upstream, not to implement first and document later.

## Allowed Changes
- production code
- required non-test runtime/build resources
- task admission evidence under `harness/evidence/admission/`

## Execution Guardrails
- Implement the minimum production code needed to satisfy the approved proposal, design, and current request.
- Keep every changed production path inside the admitted design `Scope Paths`. Before completion, run `uv run --active python ./harness/scripts/stage-scope-check.py --stage implementation --version <version> --module <module> --change-id <change_id>` (repeat `--change-id` per admitted id; add `--submodule <submodule>` for submodule packets); an out-of-scope diff is a task failure.
- If the implementation legitimately needs paths outside the admitted Scope Paths, that is missing design coverage: return to the design stage to extend the `Scope Paths` mapping (and re-run admission), or split the extra paths into their own admitted task. Do not widen the diff silently.
- Leave test implementation for the post-implementation testing stage unless the user explicitly requested a combined implementation/testing task.
- Touch only files and lines required by the admitted task.
- Match surrounding style, naming, and structure.
- Do not refactor, reformat, rewrite comments, rename symbols, or clean adjacent code unless the admitted task requires it.
- Do not add unrequested features, options, extension points, configuration, or defensive handling for scenarios ruled out by approved docs or reachable code paths.
- Remove only unused imports, variables, functions, or files made unused by the current change.
- If unrelated dead code or defects are noticed, record them as residual risk or follow-up instead of repairing them in the implementation task.
- Every changed line MUST be traceable in acceptance evidence to the current task's approved docs, requested behavior, or required verification.
- Every changed line MUST be traceable in acceptance evidence to at least one admitted `change_id`.

## Forbidden Changes
- `proposal.md`
- `design.md`
- `design/`
- `testing.md`
- `testing/`
- `testplan.yaml`
- `acceptance.md`
- test code and test fixtures, unless the user explicitly requested a combined implementation/testing task

## Verification Default
- Repositories may choose a strict default where implementation does not proactively run validation commands.
- In that mode, tests run only when:
  - the user explicitly requests validation
  - debugging needs fresh evidence
  - task docs or repo-local rules explicitly require validation
- "quick sanity check", "minimal self-test", and similar habitual reasons are not valid exceptions.

## Rust Formatting Default
- For Rust repositories, agents MUST NOT automatically run `cargo fmt`.
- `cargo fmt` may run only when the user explicitly requests formatting or repo-local rules explicitly require it for the current task.

## Return Routing
- Missing or draft proposal: return to proposal task
- Missing or draft design: return to design task
- Missing direct proposal mapping: return to proposal task
- Missing direct design mapping or changed boundaries/interfaces: return to design task
- Missing active module or `change_id`: return to proposal or design task
- Missing active submodule for work that belongs to a direct submodule packet: return to proposal or design task
- Missing or failing admission evidence file: return to implementation admission setup before code edits
- Implementation diff outside the admitted design Scope Paths: return to design to extend the `Scope Paths` mapping, or split the out-of-scope edits into their own admitted task
- Failed schema or admission checker: return to the owning document stage named by the checker output
- Approved proposal/design docs exist but do not yet cover the current task in enough detail: return to the owning proposal/design task to supplement docs first
- Upstream contradiction discovered during implementation: return to the owning upstream stage instead of patching docs in place

## Examples

`change_id` quality:
- GOOD: `CHG-login-rate-limit`, `CHG-cfg-reload-sighup` — each names one concrete behavior or contract.
- BAD: `misc`, `bugfix`, `module-update`, `cleanup` — too broad; `admission-check.py` rejects them.

Admission evidence: see `harness/evidence/admission-evidence.template.md` for the required shape. A valid file is dated today, binds the packet's `proposal.md` / `design.md` hashes, and quotes the covering mapping rows verbatim. Filling the table with `pass` without reading the documents does not work: the hashes and quotes are re-verified against the current document content.
