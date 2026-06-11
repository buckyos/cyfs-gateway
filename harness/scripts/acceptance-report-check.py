#!/usr/bin/env python3
"""Validate that an acceptance report contains enforceable review evidence.

Beyond report structure, this checker re-verifies execution evidence: accepted
reports must reference machine-written run artifacts (test-run.py writes
harness/evidence/test-runs/*.json; quality-check.py writes
harness/evidence/quality-runs/*.json), and the checker validates that those
artifacts exist, passed, and are fresh. Pasted command output alone is not
acceptance evidence.
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
from pathlib import Path


TABLE_SEPARATOR_RE = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$")
EMPTY_VALUES = {"", "-", "n/a", "na", "none", "tbd", "todo", "pending"}
BLOCKING_EVIDENCE_STATUSES = {"missing", "inconsistent", "logically invalid"}
BLOCKING_TEST_STATUSES = {"gap", "stale", "not runnable"}
BLOCKING_RULE_STATUSES = {"fail", "gap"}
HIGH_SEVERITIES = {"critical", "high"}
ALLOWED_SEVERITIES = {"none", "low", "medium", "high", "critical"}
REQUIRED_COMMAND_LABELS = (
    "schema-check.py",
    "admission-check.py",
    "stage-scope-check.py",
    "test-run.py <module> all",
    "test-run.py all all",
    "quality-check.py",
)
RUN_ARTIFACT_RE = re.compile(
    r"harness/evidence/(test-runs|quality-runs)/[A-Za-z0-9+_.-]+\.json"
)
RUN_ARTIFACT_SCHEMA = 1
QUALITY_GATES_CONFIG = "harness/quality-gates.yaml"


def fail(message: str) -> None:
    print(f"acceptance-report-check: {message}", file=sys.stderr)
    raise SystemExit(1)


def read_text(path: Path) -> str:
    if not path.exists():
        fail(f"missing required file: {path}")
    return path.read_text(encoding="utf-8")


def normalize_column(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")


def split_table_row(line: str) -> list[str]:
    parts = [part.strip() for part in line.strip().split("|")]
    if parts and parts[0] == "":
        parts = parts[1:]
    if parts and parts[-1] == "":
        parts = parts[:-1]
    return parts


def non_empty(value: str) -> bool:
    return value.strip().lower() not in EMPTY_VALUES


def section_body(text: str, heading: str, path: Path) -> str:
    match = re.search(rf"(?m)^##\s+{re.escape(heading)}\s*$", text)
    if not match:
        fail(f"{path} missing required section: ## {heading}")
    next_heading = re.search(r"(?m)^##\s+", text[match.end() :])
    end = match.end() + next_heading.start() if next_heading else len(text)
    return text[match.end() : end]


def table_rows(text: str, heading: str, path: Path) -> list[dict[str, str]]:
    body = section_body(text, heading, path)
    lines = body.splitlines()
    table_start = None
    for index, line in enumerate(lines):
        if "|" in line and index + 1 < len(lines) and TABLE_SEPARATOR_RE.match(lines[index + 1]):
            table_start = index
            break
    if table_start is None:
        fail(f"{path} section ## {heading} missing required table")
    headers = [normalize_column(cell) for cell in split_table_row(lines[table_start])]
    rows: list[dict[str, str]] = []
    for line in lines[table_start + 2 :]:
        if not line.strip() or not line.lstrip().startswith("|"):
            break
        values = split_table_row(line)
        rows.append({header: values[pos].strip() if pos < len(values) else "" for pos, header in enumerate(headers)})
    if not rows:
        fail(f"{path} section ## {heading} has no data rows")
    return rows


def require_columns(path: Path, heading: str, rows: list[dict[str, str]], columns: tuple[str, ...]) -> None:
    missing = sorted(set(columns) - set(rows[0]))
    if missing:
        fail(f"{path} ## {heading} missing columns: {', '.join(missing)}")


def conclusion(text: str, path: Path) -> str:
    body = section_body(text, "Conclusion", path).lower()
    if re.search(r"accepted\s*/\s*rejected\s*/\s*needs changes:\s*accepted\b", body):
        return "accepted"
    if re.search(r"accepted\s*/\s*rejected\s*/\s*needs changes:\s*rejected\b", body):
        return "rejected"
    if re.search(r"accepted\s*/\s*rejected\s*/\s*needs changes:\s*needs changes\b", body):
        return "needs changes"
    fail(f"{path} Conclusion must explicitly select accepted, rejected, or needs changes")


def check_nonempty_rows(path: Path, heading: str, rows: list[dict[str, str]], skip: set[str] | None = None) -> None:
    skip = skip or set()
    for index, row in enumerate(rows, start=1):
        for column, value in row.items():
            if column in skip:
                continue
            if not non_empty(value):
                fail(f"{path} ## {heading} row {index} column {column} is empty placeholder content")


def load_run_artifact(root: Path, rel_path: str) -> dict[str, object]:
    artifact_path = root / rel_path
    if not artifact_path.is_file():
        fail(f"referenced run artifact does not exist: {rel_path}")
    try:
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        fail(f"referenced run artifact is not valid JSON: {rel_path}: {error}")
    if not isinstance(artifact, dict) or artifact.get("schema") != RUN_ARTIFACT_SCHEMA:
        fail(f"referenced run artifact has an unsupported schema: {rel_path}")
    return artifact


def artifact_is_fresh(artifact: dict[str, object], max_age_hours: float) -> bool:
    finished = artifact.get("finished_at")
    if not isinstance(finished, str):
        return False
    try:
        finished_at = datetime.datetime.fromisoformat(finished)
    except ValueError:
        return False
    if finished_at.tzinfo is None:
        finished_at = finished_at.replace(tzinfo=datetime.timezone.utc)
    age = datetime.datetime.now(datetime.timezone.utc) - finished_at
    return datetime.timedelta(0) <= age <= datetime.timedelta(hours=max_age_hours)


def quality_gates_configured(root: Path) -> bool | None:
    """Return True/False for configured/empty gates, or None when the config is missing."""
    config = root / QUALITY_GATES_CONFIG
    if not config.is_file():
        return None
    text = config.read_text(encoding="utf-8")
    if re.search(r"(?m)^gates:\s*\[\s*\]\s*$", text):
        return False
    gates_line = re.search(r"(?m)^gates:\s*$", text)
    if not gates_line:
        return None
    return bool(re.search(r"(?m)^\s*-\s*id:\s*\S+", text[gates_line.end() :]))


def check_run_artifacts(path: Path, text: str, root: Path, max_age_hours: float, result: str) -> None:
    referenced_paths = sorted(set(match.group(0) for match in RUN_ARTIFACT_RE.finditer(text)))
    artifacts = {rel: load_run_artifact(root, rel) for rel in referenced_paths}

    if result != "accepted":
        return

    test_run_ok = False
    for rel, artifact in artifacts.items():
        if "/test-runs/" not in rel:
            continue
        if (
            artifact.get("requested_module") == "all"
            and artifact.get("requested_level") == "all"
            and artifact.get("exit_code") == 0
            and artifact_is_fresh(artifact, max_age_hours)
        ):
            test_run_ok = True
    if not test_run_ok:
        fail(
            f"{path} accepted conclusion requires a referenced fresh passing whole-project "
            "test run artifact (harness/evidence/test-runs/*.json with requested module/level "
            "'all all', exit code 0, finished within "
            f"{max_age_hours:g}h); rerun test-run.py all all and cite the artifact"
        )

    configured = quality_gates_configured(root)
    if configured is None:
        fail(
            f"{path} accepted conclusion requires {QUALITY_GATES_CONFIG} to exist; declare "
            "the repository quality gates or an explicitly empty gates list"
        )
    if configured:
        quality_ok = any(
            artifact.get("exit_code") == 0 and artifact_is_fresh(artifact, max_age_hours)
            for rel, artifact in artifacts.items()
            if "/quality-runs/" in rel
        )
        if not quality_ok:
            fail(
                f"{path} accepted conclusion requires a referenced fresh passing quality run "
                "artifact (harness/evidence/quality-runs/*.json, exit code 0); rerun "
                "quality-check.py and cite the artifact"
            )


def check_report(path: Path, text: str, root: Path, max_age_hours: float) -> None:
    result = conclusion(text, path)

    findings = table_rows(text, "Findings", path)
    require_columns(path, "Findings", findings, ("id", "severity", "stage", "evidence", "problem", "fail_condition_hit"))
    # severity legitimately uses the value "none" for no-finding rows; its
    # validity is checked against ALLOWED_SEVERITIES below instead.
    check_nonempty_rows(path, "Findings", findings, skip={"fail_condition_hit", "severity"})
    for index, row in enumerate(findings, start=1):
        severity = row.get("severity", "").strip().lower()
        if severity not in ALLOWED_SEVERITIES:
            fail(f"{path} Findings row {index} has invalid severity: {row.get('severity')}")
        if result == "accepted" and severity in HIGH_SEVERITIES:
            fail(f"{path} accepted conclusion cannot contain {severity} findings")
        if result == "accepted" and non_empty(row.get("fail_condition_hit", "")):
            fail(f"{path} accepted conclusion cannot cite a fail condition in Findings row {index}")

    coverage = table_rows(text, "Evidence Coverage", path)
    require_columns(
        path,
        "Evidence Coverage",
        coverage,
        ("documented_item", "source_document", "implementation_evidence", "test_result_evidence", "status"),
    )
    check_nonempty_rows(path, "Evidence Coverage", coverage)
    if result == "accepted":
        for row in coverage:
            if row.get("status", "").strip().lower() in BLOCKING_EVIDENCE_STATUSES:
                fail(f"{path} accepted conclusion has blocking evidence status: {row.get('status')}")

    adequacy = table_rows(text, "Test Design Adequacy", path)
    require_columns(
        path,
        "Test Design Adequacy",
        adequacy,
        ("behavior_risk_change_id", "required_case_types", "test_design_evidence", "runnable_test_evidence", "status"),
    )
    check_nonempty_rows(path, "Test Design Adequacy", adequacy)
    if result == "accepted":
        for row in adequacy:
            if row.get("status", "").strip().lower() in BLOCKING_TEST_STATUSES:
                fail(f"{path} accepted conclusion has blocking test design status: {row.get('status')}")

    rules = table_rows(text, "Generated Acceptance Rules", path)
    require_columns(path, "Generated Acceptance Rules", rules, ("rule_id", "source", "expected_result", "evidence_required", "status"))
    check_nonempty_rows(path, "Generated Acceptance Rules", rules)
    if result == "accepted":
        for row in rules:
            if row.get("status", "").strip().lower() in BLOCKING_RULE_STATUSES:
                fail(f"{path} accepted conclusion has failing acceptance rule: {row.get('rule_id')}")

    command_body = section_body(text, "Required Command Evidence", path)
    for label in REQUIRED_COMMAND_LABELS:
        pattern = rf"(?im)^\s*-\s+.*{re.escape(label)}.*:\s*(.+)$"
        match = re.search(pattern, command_body)
        if not match or not non_empty(match.group(1)):
            fail(f"{path} Required Command Evidence missing result for {label}")

    summary_body = section_body(text, "Consistency Summary", path)
    for label in (
        "Proposal authority check",
        "Proposal vs design",
        "Design vs implementation",
        "Test design adequacy",
        "change_id traceability",
        "Document logic review",
        "Implementation logic review",
    ):
        pattern = rf"(?im)^\s*-\s+{re.escape(label)}:\s*(.+)$"
        match = re.search(pattern, summary_body)
        if not match or not non_empty(match.group(1)):
            fail(f"{path} Consistency Summary missing evidence for {label}")

    follow_up = section_body(text, "Follow-Up Tasks", path)
    iteration = re.search(r"(?im)^\s*-\s+Iteration count:\s*(\d+)\s*$", follow_up)
    if not iteration:
        fail(f"{path} Follow-Up Tasks must include numeric Iteration count")
    if int(iteration.group(1)) > 5 and result == "accepted":
        fail(f"{path} accepted conclusion cannot exceed 5 unresolved iterations")

    check_run_artifacts(path, text, root, max_age_hours, result)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report")
    parser.add_argument("--root", default=".")
    parser.add_argument(
        "--max-age-hours",
        type=float,
        default=24,
        help="maximum age of referenced run artifacts accepted as fresh evidence",
    )
    args = parser.parse_args()

    path = Path(args.report)
    check_report(path, read_text(path), Path(args.root), args.max_age_hours)
    print("acceptance-report-check: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
