# Schema Validation Rules

## Goal
- Define the machine-checkable structure for module packets, rule files, and validation metadata.
- Make implementation admission fail closed when required fields, approval state, or change-level traceability are missing.

## Scope
- `docs/versions/<version>/modules/<module>/proposal.md`
- `docs/versions/<version>/modules/<module>/design.md`
- optional `docs/versions/<version>/modules/<module>/testing.md`
- `docs/versions/<version>/modules/<module>/testplan.yaml` for completed testing work, unless a repo-local versioned exception explicitly allows missing machine-readable test metadata
- `docs/versions/<version>/modules/<module>/<submodule>/proposal.md` and sibling stage files when a large module uses direct submodule packets
- `harness/scripts/schema-check.py`
- `harness/scripts/admission-check.py`
- `harness/scripts/stage-scope-check.py`
- `harness/scripts/doc-structure-check.py`
- `harness/scripts/testing-coverage-check.py`
- `harness/scripts/acceptance-report-check.py`
- `harness/scripts/pipeline-plan-check.py`

## Required Front Matter
`proposal.md` and `design.md` MUST contain YAML-style front matter. Optional `testing.md` MUST use the same metadata when generated:

```yaml
module: <module>
version: <version>
status: draft | approved | rejected | superseded
approved_by: <person-or-process>
approved_at: <iso-8601-date-or-datetime>
approved_content_sha256: <hash-from-schema-check-print-approval-hash>
```

`approved_content_sha256` is required whenever `status: approved`: it is the sha256 of the LF-normalized document content excluding the approval front matter fields and the `## Approval Record` section, generated via `schema-check.py --print-approval-hash <doc>`. It binds the approval to the exact approved content, so any later substantive edit invalidates the approval until the document is re-approved.

Direct submodule packet docs MAY also include:

```yaml
submodule: <submodule>
```

Implementation admission accepts only `status: approved`.

## Approval Provenance Schema
- Agents MUST NOT set `status: approved` or fill `approved_by` / `approved_at` on their own initiative; document-stage tasks end at `status: draft`.
- An approved document MUST carry verifiable approval provenance in one of exactly two forms:
  - User approval: front matter `approved_by` names the user, and the document contains a `## Approval Record` section with non-placeholder `approver`, `approval_date`, and `user_statement` fields, where `approver` matches `approved_by` and `user_statement` quotes the user's approval instruction verbatim.
  - Auto-pipeline approval: front matter `approved_by: auto-pipeline`, valid only while `harness/pipeline-plan.md` exists and records a non-empty `User launch confirmed:` value under `## Trigger`.
- Agent-like `approved_by` values (for example `agent`, `assistant`, `claude`, `ai`, `self`, `auto`, `bot`) MUST fail validation.
- Every approved document MUST carry a matching `approved_content_sha256`; both approval paths (user and auto-pipeline) record it in the same edit that applies the approval.
- `schema-check.py` and `admission-check.py` MUST fail closed on approved documents whose approval provenance is missing, placeholder-only, inconsistent with front matter, or whose `approved_content_sha256` is missing or does not match the current document content (stale approval).

## Change Traceability Schema
- Every implementation-ready change MUST have one stable `change_id`.
- `change_id` values MUST be specific enough to name one behavior, contract, or implementation unit. Do not use broad IDs such as `misc`, `cleanup`, `all`, `module`, or `bugfix`.
- The same `change_id` MUST appear in these exact locations:
  - `proposal.md` section `## Proposal Items`, column `change_id`; the same row MUST include non-empty `proposal_id`, `Outcome`, and `Success Evidence`.
  - `design.md` section `## Directly Mapped Change Items`, column `change_id`; the same row MUST include non-empty `proposal_id`, `Design Coverage`, and `Scope Paths`.
- Post-implementation testing evidence MUST also reference the same `change_id`; `testing.md` / `testplan.yaml` MUST include the `change_id` for completed testing work, but those files are not implementation-admission prerequisites.
- `change_id` text in comments, prose, unrelated tables, historical notes, or module overviews MUST NOT satisfy admission.
- A broad module overview, historical note, or oral explanation MUST NOT satisfy this schema.

## Active Module Resolution
- A task MUST name the active `version`, `module`, and one or more `change_id` values before implementation admission can pass.
- If the active packet is a direct submodule under a large module, the task MUST also name the active `submodule`.
- If the request affects multiple modules, admission MUST be evaluated independently for each affected module packet.
- If the request affects multiple direct submodules, admission MUST be evaluated independently for each affected submodule packet with `--submodule <submodule>`.
- If the active module cannot be determined from repository paths, module docs, or the user's explicit request, route to proposal or design instead of selecting a convenient module.

## Testplan Schema
For completed testing work, `testplan.yaml` MUST exist and include the structure below unless a repo-local versioned rule explicitly permits missing machine-readable test metadata for the current module. `schema-check.py` validates `testplan.yaml` when present; `testing-coverage-check.py` enforces that completed testing has testplan mapping unless run with an explicit `--allow-missing-testplan` exception.

```yaml
schema_version: 1
version: <version>
module: <module>
submodule: <submodule> # optional; required only when the repository chooses explicit submodule metadata
levels:
  unit|dv|integration:
    mode: enabled | manual | disabled
    summary: <text>
    test_targets: []
    preconditions:
      tools: []
      env: []
      services: []
      notes: []
    steps:
      - id: <stable-id>
        name: <text>
        change_ids: [<change-id>]
        run: [<command>, <arg>]
```

Rules:
- `enabled` levels MUST have at least one step.
- Each enabled step MUST define `id`, `name`, `change_ids`, and `run`.
- Step ids MUST be unique within the module packet.
- `manual` and `disabled` levels MUST include `change_ids` and a reason in generated test evidence and optional `testing.md` / `testplan.yaml` when present.
- Unknown test levels MUST fail validation.

## Checker Contract
- `harness/scripts/schema-check.py` validates mandatory proposal/design packet structure, approval provenance for approved documents, and optional testplan shape for module packets and, with `--submodule <submodule>`, direct submodule packets.
- `harness/scripts/admission-check.py` validates implementation admission for explicit `version`, `module`, optional `submodule`, and `change_id` values, including the mandatory proposal/design traceability positions above and the approval provenance of every required approved document.
- `harness/scripts/admission-check.py` MUST also validate `--evidence-file harness/evidence/admission/<task-id>.md`, including proposal/design reading evidence, direct task coverage judgment, active module resolution, and rejection of chat-only evidence.
- `harness/scripts/admission-check.py` MUST validate the evidence file name as `<YYYYMMDD>-<task-slug>.md` with a valid non-future date, verify `## Document Binding` sha256 hashes against the current LF-normalized `proposal.md` / `design.md` content, and verify that every `## Coverage Quotes` block appears verbatim in the named document and contains the admitted `change_id`; any mismatch fails closed.
- On success, `harness/scripts/admission-check.py` MUST write the admission stamp `harness/evidence/admission/<task-id>.<module>[.<submodule>].stamp.json` recording the bound document hashes and the admitted design `Scope Paths`; `harness/scripts/edit-guard.py` MUST refuse production-code edits without a valid today-dated stamp and MUST reject paths outside the stamped Scope Paths.
- `harness/scripts/schema-check.py --print-approval-hash <doc>` MUST print the `approved_content_sha256` value for a document so approvals can record it mechanically.
- `harness/scripts/stage-scope-check.py` validates that the current diff stays inside one declared stage artifact group.
- For the implementation stage, `harness/scripts/stage-scope-check.py` MUST require `--version`, `--module`, and at least one `--change-id`, load the admitted design `Scope Paths`, and fail when any changed production path (other than the task's own admission evidence) falls outside them.
- `harness/scripts/doc-structure-check.py` validates proposal requirement challenge records, proposal/design trigger matrices, design boundary decision matrices, acyclic dependency graph, testing case-type coverage, and mandatory document sections/tables.
- `harness/scripts/testing-coverage-check.py` validates direct `change_id` coverage, explicit gap reasons, testplan mapping, case-type coverage, and unified test entrypoint reachability.
- `harness/scripts/test-run.py` MUST write a machine-readable run artifact to `harness/evidence/test-runs/` for every real run, recording each executed command, its exit code, and the git state; those artifacts are the only valid test execution evidence for acceptance.
- `harness/scripts/quality-check.py` MUST run the gates declared in `harness/quality-gates.yaml`, fail closed when the config is missing or any gate fails, and write a run artifact to `harness/evidence/quality-runs/`.
- `harness/scripts/acceptance-report-check.py` validates acceptance reports and fails accepted reports with blocking findings, missing command evidence, missing consistency evidence, failing generated acceptance rules, or inadequate test design evidence.
- `harness/scripts/acceptance-report-check.py` MUST also re-verify execution evidence: every referenced run artifact must exist and parse, and an `accepted` conclusion requires a referenced fresh passing whole-project test run artifact plus, when quality gates are configured, a referenced fresh passing quality run artifact.
- `harness/scripts/pipeline-plan-check.py` validates auto-pipeline launch evidence, stage graph dependencies, task statuses, and exit-condition completion evidence.
- These scripts MUST exit non-zero on missing mandatory files, missing approval metadata, missing or invalid approval provenance, missing direct proposal/design traceability, ambiguous active module, malformed optional test metadata, or out-of-stage diffs.
- Stage scope checks MUST exit non-zero when a proposal task changes anything except `proposal.md`, when a design task changes non-design artifacts, when a testing task changes non-testing artifacts, when an acceptance task changes anything except review reports and optional packet `acceptance.md`, or when an implementation task changes stage documents or any `harness/` path other than its own admission evidence — including `harness/scripts/`, `harness/rules/`, `harness/pipeline-plan.md`, and trigger rules, so checkers cannot be weakened from inside an implementation task.
- Stage scope checks for proposal, design, and testing MUST require the active `--version` and `--module` (and `--submodule` for submodule packets) and refuse to run without them.
- Passing checker output is necessary but not sufficient for implementation: agents must still read the approved docs and keep edits inside the admitted scope.
