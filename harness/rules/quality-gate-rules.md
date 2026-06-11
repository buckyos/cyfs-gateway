# Quality Gate Rules

## Goal
- Make code-level quality checks (build, lint, typecheck, format checks) a declared, mechanical gate instead of reviewer goodwill.
- Make quality-gate evidence verifiable: gates run through one checker that writes machine-readable run artifacts.

## Scope
- `harness/quality-gates.yaml`
- `harness/scripts/quality-check.py`
- `harness/evidence/quality-runs/`

## Configuration Rule
- The repository MUST declare its mechanical quality gates in `harness/quality-gates.yaml`.
- Each gate MUST have a stable `id` and a non-interactive, deterministic `run` command list with a meaningful exit code.
- A missing `harness/quality-gates.yaml` fails closed: `quality-check.py` exits non-zero until the file exists.
- An explicitly empty `gates: []` list is allowed but is a versioned, reviewable decision; record the reason as a comment next to it.
- Choosing, adding, or removing gates is a harness/process change: it belongs to a harness governance task, not to an implementation task. `stage-scope-check.py` rejects implementation-stage edits to `harness/quality-gates.yaml`.

## Execution Rule
- Run gates through `uv run --active python ./harness/scripts/quality-check.py`; do not run "equivalent" ad hoc commands as gate evidence.
- `quality-check.py` writes a run artifact to `harness/evidence/quality-runs/<timestamp>-quality.json` recording each gate's command, exit code, and duration; that artifact is the only valid quality-gate evidence.
- Acceptance MUST run the quality gates when `harness/quality-gates.yaml` declares at least one gate, and the acceptance report MUST cite the resulting run artifact path.
- `acceptance-report-check.py` fails an `accepted` conclusion when gates are configured but no referenced fresh passing quality run artifact exists, or when `harness/quality-gates.yaml` is missing.
- CI runs `quality-check.py` via `harness/ci/harness-checks.yml`, so failing gates block merges independently of agent behavior.

## Guardrails
- Quality gates supplement tests; passing gates is necessary supporting evidence, not an acceptance conclusion by itself.
- Do not weaken, skip, or conditionally bypass a failing gate to make a task pass; a failing gate routes the work back to the implementation stage (or to a harness governance task when the gate itself is wrong).
- Keep gates fast enough to run at acceptance time; long-running validation belongs in test levels under `test-run.py`, not in quality gates.
