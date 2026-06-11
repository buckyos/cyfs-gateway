# Task Entry Gate Rules

## Goal
- Prevent implementation, bugfix, optimization, and refactor requests from bypassing versioned document admission and moving directly into code changes.

## Priority
- This is the highest-priority entry rule for task classification and implementation admission.
- Apply this rule before reading task-type process rules or editing any repository artifact.

## Scope
- requests involving code
- requests involving tests
- requests involving runtime behavior
- requests involving UI behavior
- requests involving build behavior
- bugfix, optimization, refactor, and implementation requests

## Stage Write-Scope Rule
- When the user explicitly enters one stage, that stage is the only write scope by default.
- Proposal-stage tasks MUST modify only `proposal.md` files in the active module or submodule packet.
- Design-stage tasks MUST modify only `design.md`, `design/`, direct submodule packet design files, and required long-lived boundary sync.
- Testing-stage tasks MUST modify only test code, test fixtures, test runners, and optional testing artifacts such as `testing.md`, `testing/`, `testplan.yaml`, and direct submodule packet testing files.
- Implementation-stage tasks MUST modify only production code, required non-test runtime/build resources, and the task admission evidence file under `harness/evidence/admission/` after implementation admission passes.
- Acceptance-stage tasks MUST audit evidence, generate or finalize acceptance rules and expected results, and write review reports only.
- A task MUST NOT edit multiple stage artifact groups unless the user explicitly names the stages or explicitly asks for cross-stage synchronization.
- "Explicitly" means the user's own words, not an inference: a multi-stage task MUST record the user's verbatim authorizing statement in its evidence file or produced report. If no quotable statement exists, the task is single-stage.
- Changing an upstream document does not automatically authorize downstream document edits. If downstream artifacts need updates, record the return route or follow-up unless the user explicitly requested those downstream edits.
- Before finishing a single-stage task, run `uv run --active python ./harness/scripts/stage-scope-check.py --stage <stage> --version <version> --module <module>` (plus `--submodule <submodule>` for submodule packets) and treat any out-of-stage diff as a task failure. Proposal, design, and testing runs refuse to start without `--version` and `--module`, so another module's documents can never pass the check.
- Implementation-stage scope checks additionally require `--change-id <change_id>` (repeatable): the checker loads the admitted design `Scope Paths` entries and fails when any changed production path falls outside them, so every changed line is mechanically bound to its admitted `change_id`.
- When the working tree contains unrelated changes from other tasks, run the scope check against committed work with `--base <ref>` instead of accepting a noisy worktree; the default mode checks the whole worktree and will correctly flag mixed-task diffs.

## Approval Authority Rule
- Agents MUST NOT set `status: approved`, or fill `approved_by` / `approved_at`, on any stage document on their own initiative.
- Document-stage tasks deliver `status: draft` by default; finishing a proposal, design, or testing task does NOT approve the document.
- The draft -> approved transition is allowed only when:
  - the user explicitly approves the document, in which case the same edit MUST fill `## Approval Record` with `approver`, `approval_date`, and a verbatim `user_statement` quoting the user's approval instruction, and `approver` MUST match front matter `approved_by`; or
  - auto-pipeline mode auto-confirms a completed stage with `approved_by: auto-pipeline`, which is valid only while `harness/pipeline-plan.md` records explicit user launch evidence.
- Inferred approval, user silence, "the user seemed satisfied", or chat-only statements are NOT approval; leave the document `draft` and ask the user instead.
- The same edit that applies an approval MUST record front matter `approved_content_sha256`, generated via `schema-check.py --print-approval-hash <doc>`. The hash covers the document content excluding the approval fields themselves, so any later content edit makes the approval stale and `schema-check.py` / `admission-check.py` fail closed until the document is re-approved.
- `schema-check.py` and `admission-check.py` fail closed on approved documents with missing approval provenance: agent-like `approved_by` values, a missing or placeholder `## Approval Record`, a missing or mismatched `approved_content_sha256`, or `approved_by: auto-pipeline` without recorded pipeline launch evidence.
- Editing approval front matter, `## Approval Record`, or `approved_content_sha256` to make a check pass without a real user approval instruction is a task failure, not a workaround.

## Requirement And Scope Classification Rule
- A request that adds, removes, narrows, widens, or reclassifies goals, scope, non-goals, obligations, supported behavior, unsupported behavior, acceptance boundaries, or success evidence MUST default to proposal stage.
- Requirement language such as "does not need", "no longer needs", "should not provide", "must provide", "support", "do not support", or equivalent terms MUST be treated as proposal-stage language by default.
- Do not reinterpret a requirement/scope request as "make the whole packet consistent" unless the user explicitly asks to update downstream documents or asks for cross-stage synchronization.
- In a proposal-stage task, update `proposal.md`, fill the `## Requirement Challenge` and `## Trigger Matrix` evidence, and record downstream design/implementation/testing/acceptance follow-up there when needed. Do not edit `design.md`, testing artifacts, acceptance artifacts, code, or test code unless the user explicitly requested those stages in the same task.
- Before proposal-stage completion, run `uv run --active python ./harness/scripts/doc-structure-check.py --version <version> --module <module> --docs proposal` and treat missing challenge or trigger evidence as task failure.

## Task Entry Gate Rule
- When the user request touches code, tests, runtime behavior, UI behavior, build behavior, bugfixes, optimization, or refactoring, the default path is not immediate code modification.
- The first task step MUST locate the current versioned module packet.
- The task MUST identify the active `version`, `module`, and one or more concrete `change_id` values.
- If the active packet is a direct submodule under a large module, the task MUST also identify the active `submodule`.
- If the request affects multiple modules, repeat the gate and admission check for each affected module packet.
- If the request affects multiple direct submodules, repeat the gate and admission check for each affected submodule packet.
- Before any implementation path starts, the task MUST read:
  - `proposal.md`
  - `design.md`
- Before implementation admission passes, the task MUST create `harness/evidence/admission/<task-id>.md` with a `## Implementation Admission Evidence` table recording `proposal_read`, `design_read`, `change_scope_matches_request`, `active_module_resolved`, and `no_chat_only_evidence`, each with `status` set to `pass`, a concrete source, and task-specific notes.
- `<task-id>` MUST have the form `<YYYYMMDD>-<task-slug>` where `<YYYYMMDD>` is today's date and `<task-slug>` is a short stable name for the task; `admission-check.py` rejects malformed or future-dated names. Do not reuse a previous task's evidence file.
- The evidence file MUST also contain `## Document Binding` with the LF-normalized sha256 of the packet's `proposal.md` and `design.md` (generate via `admission-check.py --print-doc-hashes`), and `## Coverage Quotes` with one `### Quote: proposal.md <change_id>` and one `### Quote: design.md <change_id>` block per admitted `change_id`, quoting the covering row or sentence verbatim from the current document.
- `admission-check.py` re-verifies the hashes and quotes against the current documents and fails closed on any mismatch, so the evidence cannot be written without reading the documents, cannot be reused after a document changes, and becomes invalid if a document is edited after admission.
- On success, `admission-check.py` writes a machine-readable admission stamp (`harness/evidence/admission/<task-id>.<module>.stamp.json`) recording the bound document hashes and the admitted design `Scope Paths`. The `edit-guard.py` hook blocks production-code edits unless a today-dated stamp is still valid (the recorded hashes must match the current documents) and the edited path falls inside the stamped Scope Paths. Do not hand-write or edit stamp files; only a passing `admission-check.py` run may produce them.
- Before implementation admission passes, the task MUST run:
  - `uv run --active python ./harness/scripts/schema-check.py --version <version> --module <module>`
  - `uv run --active python ./harness/scripts/admission-check.py --version <version> --module <module> --change-id <change_id> --evidence-file harness/evidence/admission/<task-id>.md`
- For direct submodule packets, pass `--submodule <submodule>` to both checks.
- Before document reading and direct mapping judgment are complete, the task MUST NOT edit:
  - code files
  - build files
  - resource files
- If any required proposal/design document is missing, is not `approved`, or does not directly cover the current user request, the task MUST return to the corresponding document stage.
- Code modification may begin only after `admission-check.py` passes with the task evidence file.

## Default Stage Classification Rule
- When the user has not explicitly said to enter the proposal, design, testing, or acceptance stage, classify the task by its likely artifact changes.
- If the request is a requirement, scope, non-goal, supported/unsupported behavior, or acceptance-boundary change, classify it as proposal stage before considering downstream consistency work.
- If the request would lead to code changes, the task MUST run the implementation admission check first.
- If the admission check fails, the current task is automatically classified as the earliest missing document stage.
- If the active module cannot be determined without guessing, return to proposal or design.
- If the active direct submodule cannot be determined without guessing, return to proposal or design.
- If no concrete `change_id` maps to the request, return to proposal or design based on the missing coverage.
- A concrete `change_id` maps to the request only when it appears in the required `change_id` column of the proposal and design mapping tables.
- User oral requirements, chat context, old implementation, module overviews, and historical notes MUST NOT be treated as admission evidence.
- If the request has multiple plausible meanings and the ambiguity affects scope, behavior, risk, or validation, route to proposal or the owning upstream document stage instead of silently choosing an interpretation.
- "Read code first and then decide" permits code inspection only; it does not permit code edits.
- If code inspection reveals a document gap, the task MUST stop the code path and return to the owning document stage.

## Return Routing
- Missing or unapproved `proposal.md`: return to proposal stage.
- Missing direct proposal coverage: return to proposal stage.
- Missing or unapproved `design.md`: return to design stage.
- Missing direct design coverage, boundary coverage, or interface coverage: return to design stage.

## Examples

Classification:
- "登录接口偶尔报 500，修一下" — bugfix, so it is implementation-shaped: run the entry gate and admission first; do not start editing code, even though the fix looks small.
- "这个模块不再需要支持匿名访问" — requirement language ("不再需要"): proposal stage by default; edit only `proposal.md` and record downstream follow-up there.
- "更新一下 design.md，把新的子模块边界写进去" — the user explicitly named the design stage: design write scope only.
- "看看这段代码为什么慢" — inspection only: reading code is allowed, editing is not; if a fix is then requested, run the entry gate.

Admission outcome:
- PASS: `proposal.md` and `design.md` are approved with valid provenance, `CHG-login-rate-limit` appears in both mapping tables, today's evidence file binds the doc hashes and quotes the covering rows, and `admission-check.py` exits 0.
- FAIL: the docs are approved but contain nothing about rate limiting — coverage is missing, so the task returns to proposal/design; "the user told me in chat" does not substitute.
- FAIL: the evidence file was created yesterday for another task, or a doc was edited after the evidence was written — the hash binding rejects it; regenerate the evidence.
