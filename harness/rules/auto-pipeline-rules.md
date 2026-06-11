# Auto Pipeline Rules

## Goal
- Define the repository's fully automatic downstream workflow after explicit user launch and proposal approval.
- Make stage planning, child-task execution, return-routing, and exit conditions explicit.

## Trigger
- This rule is inactive unless the user explicitly asks to enter it.
- Entry signal: user explicitly asks to enable, launch, run, or enter the automatic pipeline
- Required prerequisite: `proposal.md` exists and `status: approved`
- `proposal.md` approval alone does not enter auto-pipeline mode
- Optional launch command or workflow entry:

## User Authorization Precedence
- Explicit user instructions have highest priority for entering auto-pipeline mode, requested pipeline scope, and whether per-stage user confirmation is required.
- If the user explicitly asks auto-pipeline mode to handle all subsequent stages or the whole downstream workflow, the pipeline MUST NOT stop after each stage to ask for separate user confirmation before continuing.
- That launch instruction authorizes downstream design, implementation, post-implementation testing, and acceptance execution according to the pipeline plan.
- When a document-producing stage completes, the pipeline MUST auto-confirm that stage by updating the produced stage document front matter to:
  - `status: approved`
  - `approved_by: auto-pipeline`
  - `approved_at: <current timestamp>`
  - `approved_content_sha256: <hash from schema-check.py --print-approval-hash>`
- Auto-confirmation happens only after that stage's declared done criteria and required checks pass.
- `approved_by: auto-pipeline` is valid only while `harness/pipeline-plan.md` records a non-empty `User launch confirmed:` value under `## Trigger`; `schema-check.py` and `admission-check.py` fail approved documents that claim auto-pipeline approval without that launch evidence.
- Outside an explicitly launched pipeline, the normal approval authority rule applies: agents MUST NOT set `status: approved` themselves, and user approvals require a filled `## Approval Record`.
- After each child task completes, the pipeline MUST update the pipeline plan task status to `confirmed` or `complete` before continuing to dependent tasks.
- The pipeline MUST run `uv run --active python ./harness/scripts/pipeline-plan-check.py harness/pipeline-plan.md` before downstream execution, and MUST run `uv run --active python ./harness/scripts/pipeline-plan-check.py harness/pipeline-plan.md --require-complete` before final completion.
- Implementation completion MUST be recorded in the pipeline plan and implementation evidence, and final acceptance MUST be recorded in the pipeline plan and acceptance report.
- This authorization does not waive proposal authority, stage write scopes, `stage-scope-check.py`, implementation admission, schema checks, admission checks, required validation, or final acceptance.

## Acceptance Baseline
- Final acceptance baseline: approved `proposal.md`
- Downstream artifacts (`design.md`, optional testing artifacts, optional acceptance artifacts, implementation, and tests) may refine execution detail but MUST NOT contradict, narrow, or silently expand the proposal.
- When downstream artifacts or code disagree, fixes MUST preserve the approved proposal and route non-requirement defects through design -> implementation/code -> testing implementation.
- Code MUST conform to design, and tests MUST verify proposal/design/code behavior.

## Stage Responsibilities
- Proposal responsibility:
  - define the approved baseline of goals, scope, non-goals, and constraints
- Pipeline planning responsibility:
  - plan stage tasks, dependencies, outputs, and done conditions before execution starts
- Design responsibility:
  - convert the approved proposal into submodules, dependencies, key call flows, exported interfaces, external dependencies, and implementation order
  - keep module and submodule dependencies acyclic
  - split submodules by business logic first, extract shared implementation logic into shared submodules, and isolate clear technical areas such as HTTP interfaces or persistence/database access
- Testing responsibility:
  - after implementation completes, design test cases from proposal, design, and delivered code, then generate test implementation and runnable evidence
- Implementation responsibility:
  - deliver the smallest production code changes that satisfy approved proposal and design inputs
- Acceptance responsibility:
  - generate or finalize acceptance rules and expected results, independently evaluate evidence consistency and logic, then return non-requirement failures through design -> implementation -> testing

## Pipeline Planning Rule
- Before execution starts, the pipeline MUST create a plan for:
  - design tasks
  - implementation tasks
  - testing tasks
  - acceptance tasks
- The planner MUST declare:
  - task ids
  - stage
  - responsibility
  - scope
  - dependencies
  - outputs
  - done conditions

## Implementation Admission Rule
- The task entry gate still applies inside the pipeline: implementation tasks MUST classify scope and run admission before editing production code, build files, or resources.
- No implementation task may start unless:
  - `proposal.md` exists and `status: approved`
  - `design.md` exists and `status: approved`
- Implementation tasks MUST read those approved proposal/design docs and confirm they cover the current task before coding.
- Implementation tasks MUST record that confirmation in `harness/evidence/admission/<task-id>.md`, and `admission-check.py` MUST validate it with `--evidence-file`.
- Implementation tasks MUST identify explicit `version`, `module`, and `change_id` values before coding.
- Implementation tasks for direct submodule packets MUST also identify explicit `submodule`.
- Implementation tasks MUST pass `schema-check.py` and `admission-check.py` for each affected module packet.
- Implementation tasks MUST pass `admission-check.py --evidence-file harness/evidence/admission/<task-id>.md` for each affected module packet.
- Implementation tasks for direct submodule packets MUST pass those checks with `--submodule <submodule>`.
- Cross-module implementation tasks MUST pass admission independently for every affected module.
- Cross-submodule implementation tasks MUST pass admission independently for every affected submodule packet.
- If approved proposal/design docs are incomplete for the current task, the pipeline MUST return to the owning doc stage to supplement them before implementation resumes.
- Bugfix tasks follow the same rule unless the repository publishes a narrower exception path.
- If any prerequisite is missing or not approved, the task MUST return to the owning upstream stage.

## Stage Execution Rule
- Each stage MUST execute as an independent child task.
- Each stage child task MUST keep writes inside that stage's artifact group unless the user explicitly requested cross-stage synchronization for that task.
- Each single-stage child task MUST run `stage-scope-check.py --stage <stage> --version <version> --module <module>` (plus `--submodule <submodule>` for submodule packets) before completion and fail on out-of-stage diffs.
- Upstream-stage changes MUST NOT automatically edit downstream-stage artifacts. If a downstream artifact becomes stale, the pipeline MUST create or reopen the downstream stage task instead of silently bundling the edit into the upstream task.
- If a stage contains direct submodules, the pipeline MUST create independent child tasks for those submodules or record a concrete merged-task reason in the pipeline plan.
- Each child task MUST have:
  - one owner
  - one clear output
  - explicit file or scope boundary
  - explicit dependencies
  - observable done criteria
- `pipeline-plan-check.py` MUST fail a plan that omits design, implementation, testing, or acceptance tasks, lacks dependencies or done conditions, lacks explicit user launch evidence, or leaves dependency-ready tasks without `confirmed` / `complete` status when `--require-complete` is used.

## Recommended Stage Order
1. Design planning and design tasks
2. Implementation tasks
3. Testing planning and testing implementation tasks
4. Acceptance task

## Recursive Submodule Rule
- If `proposal.md` and `design.md` define direct submodules, the pipeline MUST create submodule packets under the large module directory and mirror them in:
  - design child tasks
  - testing child tasks
  - implementation child tasks where ownership can be separated safely
- Independent submodule proposal and design artifacts MUST live in the submodule packet, such as `docs/versions/<version>/modules/<module>/<submodule>/proposal.md`, not under `design/<submodule>/`. Optional post-implementation testing artifacts MUST live in the same packet when generated.
- Shared cross-cutting topics may be separate child tasks if they have clear boundaries.

## Acceptance Task Rule
- Final acceptance MUST compare delivered results back to the approved `proposal.md`.
- Final acceptance MUST generate or finalize acceptance rules and expected results from proposal, design, implementation, and testing implementation.
- Final acceptance MUST check consistency between proposal, design, implementation, testing implementation, and results.
- Final acceptance MUST audit whether test design is reasonable and covers normal, boundary, negative, error, compatibility, lifecycle, and cross-module cases where applicable.
- Final acceptance MUST apply `harness/rules/acceptance-review-rules.md`.
- Git diff/status output may be used to locate evidence, but it is not the final acceptance standard.
- Final acceptance MUST audit admission for every module needed as evidence for the accepted behavior.
- If consistency problems exist, final acceptance MUST use the approved `proposal.md` as the authority and route non-requirement fixes through design -> implementation/code -> testing implementation.
- Acceptance MUST inspect supporting evidence from:
  - `design.md` and `design/`
  - test implementation, fixtures, runners, and optional testing metadata
  - direct submodule packets when the accepted work is split by submodule
  - implementation
  - test code
  - test results
- Acceptance MUST output:
  - findings first, sorted by severity
  - accepted, rejected, or needs changes conclusion
  - evidence summary
  - mismatch list
  - document and implementation logic findings
  - return-routing decision

## Return Routing Rule
- If acceptance fails, the pipeline MUST return work to the correct earlier stage instead of exiting.
- If acceptance finds incomplete, ambiguous, unreasonable, stale, or non-runnable test design / test implementation coverage, the pipeline MUST return to the testing stage to supplement tests and evidence before rerunning acceptance.
- Non-requirement acceptance failures MUST repeat design -> implementation -> testing, then rerun acceptance.
- If the same unresolved issue remains after more than 5 unsuccessful iterations, the pipeline MUST stop and report the issue to the user.
- The iteration counter lives in the pipeline plan: every failed acceptance run MUST append a return record (blocking issue id, owning stage, target task, reason, expected fix output), and the iteration count for an issue is the number of return records with the same blocking issue id. Do not track the count from memory or chat context.
- `pipeline-plan-check.py --require-complete` MUST fail if final exit-condition checkboxes are not complete.

Minimum return categories:
- proposal issue
- design issue
- testing implementation issue
- implementation issue

For each failed acceptance run, record:
- blocking issue id
- owning stage
- target task to reopen or recreate
- reason for return
- expected fix output

## Exit Condition
- The pipeline MUST continue until:
  - proposal-defined outcomes are satisfied
  - blocking issues are closed
  - required tests and evidence exist
  - final acceptance passes

## Guardrails
- The pipeline MUST NOT skip planning and jump straight into implementation.
- The pipeline MUST NOT treat draft or missing design artifacts as implementation-ready.
- The pipeline MUST NOT treat missing post-implementation test evidence as acceptance-ready.
- The pipeline MUST NOT treat one failed acceptance as terminal completion.
- The pipeline MUST NOT let downstream documents override proposal intent.
- The pipeline MUST record the ownership or validation boundary for every child task in the pipeline plan; unnecessary task depth is rejected by acceptance when it creates unclear ownership or evidence.

## Suggested Companion Files
- `harness/pipeline-plan.md` or equivalent generated plan artifact
- child task template
- acceptance report template
- trigger rules
