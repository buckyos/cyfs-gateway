#!/usr/bin/env python3
"""Validate auto-pipeline plan structure and task status evidence."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


TABLE_SEPARATOR_RE = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$")
EMPTY_VALUES = {"", "-", "n/a", "na", "none", "tbd", "todo"}
ALLOWED_STATUSES = {"pending", "running", "confirmed", "complete", "blocked", "returned"}


def fail(message: str) -> None:
    print(f"pipeline-plan-check: {message}", file=sys.stderr)
    raise SystemExit(1)


def normalize_column(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")


def non_empty(value: str) -> bool:
    return value.strip().lower() not in EMPTY_VALUES


def split_table_row(line: str) -> list[str]:
    parts = [part.strip() for part in line.strip().split("|")]
    if parts and parts[0] == "":
        parts = parts[1:]
    if parts and parts[-1] == "":
        parts = parts[:-1]
    return parts


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
    return rows


def require_columns(path: Path, heading: str, rows: list[dict[str, str]], columns: tuple[str, ...]) -> None:
    if not rows:
        fail(f"{path} ## {heading} has no data rows")
    missing = sorted(set(columns) - set(rows[0]))
    if missing:
        fail(f"{path} ## {heading} missing columns: {', '.join(missing)}")


def check_trigger(text: str, path: Path) -> None:
    body = section_body(text, "Trigger", path)
    required = (
        "Approved proposal",
        "User launch confirmed",
        "Per-stage user confirmation",
        "Auto-confirm completed document stages",
        "Version",
        "Module(s)",
        "change_id values",
    )
    for label in required:
        match = re.search(rf"(?im)^\s*-\s+{re.escape(label)}:\s*(.+)$", body)
        if not match or not non_empty(match.group(1)):
            fail(f"{path} Trigger missing value for {label}")
    launch = re.search(r"(?im)^\s*-\s+User launch confirmed:\s*(.+)$", body)
    if launch and launch.group(1).strip().lower() not in {"yes", "true", "confirmed"}:
        fail(f"{path} auto-pipeline plan requires explicit user launch confirmation")


def check_stage_graph(text: str, path: Path, require_complete: bool) -> None:
    rows = table_rows(text, "Stage Graph", path)
    require_columns(
        path,
        "Stage Graph",
        rows,
        ("task_id", "stage", "status", "responsibility", "scope", "parent_task", "depends_on", "output", "done_condition"),
    )
    seen_stages: set[str] = set()
    for index, row in enumerate(rows, start=1):
        for column in ("task_id", "stage", "status", "responsibility", "scope", "depends_on", "output", "done_condition"):
            if not non_empty(row.get(column, "")):
                fail(f"{path} ## Stage Graph row {index} column {column} is empty")
        status = row.get("status", "").strip().lower()
        if status not in ALLOWED_STATUSES:
            fail(f"{path} ## Stage Graph row {index} invalid status: {status}")
        if require_complete and status not in {"confirmed", "complete"}:
            fail(f"{path} ## Stage Graph row {index} must be confirmed or complete before dependents continue")
        seen_stages.add(row.get("stage", "").strip().lower())
    missing = {"design", "implementation", "testing", "acceptance"} - seen_stages
    if missing:
        fail(f"{path} ## Stage Graph missing stages: {', '.join(sorted(missing))}")


def check_exit_condition(text: str, path: Path, require_complete: bool) -> None:
    body = section_body(text, "Exit Condition", path)
    items = re.findall(r"(?m)^\s*-\s+\[([ xX])\]\s+(.+)$", body)
    if not items:
        fail(f"{path} Exit Condition must contain checkbox items")
    if require_complete:
        unchecked = [label for mark, label in items if mark.strip().lower() != "x"]
        if unchecked:
            fail(f"{path} Exit Condition has unchecked items: {', '.join(unchecked)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("plan")
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args()

    path = Path(args.plan)
    if not path.exists():
        fail(f"missing required file: {path}")
    text = path.read_text(encoding="utf-8")
    check_trigger(text, path)
    check_stage_graph(text, path, args.require_complete)
    check_exit_condition(text, path, args.require_complete)
    print("pipeline-plan-check: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
