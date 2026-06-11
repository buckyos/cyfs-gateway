#!/usr/bin/env python3
"""Validate Harness Engineering module packet document structure."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


MAX_HUMAN_DOC_LINES = 1000
TABLE_SEPARATOR_RE = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$")
EMPTY_VALUES = {"", "-", "n/a", "na", "none", "tbd", "todo"}

REQUIRED_SECTIONS = {
    "proposal.md": (
        "Background and Goal",
        "Scope",
        "Assumptions and Ambiguities",
        "Constraints",
        "Requirement Challenge",
        "Large Module Submodule Decision",
        "Trigger Matrix",
        "High-Level Outcomes",
        "Proposal Items",
        "Success Criteria",
        "Risks",
        "Downstream Follow-Up",
    ),
    "design.md": (
        "Design Scope",
        "Overall Approach",
        "Simplicity Check",
        "Current Structure",
        "Submodules",
        "Boundary Rationale",
        "Boundary Decision Matrix",
        "Dependency Graph",
        "Key Call Flows",
        "Large Module Submodule Decision",
        "Trigger Matrix",
        "Directly Mapped Change Items",
        "Implementation Order",
        "Key Decisions",
        "Data and State",
        "Interfaces and Dependencies",
        "Document Index",
        "Risks and Rollback",
    ),
    "testing.md": (
        "Test Document Index",
        "Unified Test Entry",
        "Submodule Tests",
        "Module-Level Tests",
        "External Interface Tests",
        "Direct Change Coverage",
        "Case-Type Coverage",
        "Validation Rationale",
        "Definition of Done",
    ),
}

REQUIRED_TABLE_COLUMNS = {
    ("proposal.md", "Proposal Items"): ("proposal_id", "change_id", "outcome", "success_evidence"),
    ("proposal.md", "Requirement Challenge"): (
        "question",
        "evaluation",
        "risk_or_tradeoff",
        "decision",
    ),
    ("proposal.md", "Large Module Submodule Decision"): (
        "submodule",
        "new_or_existing",
        "responsibility",
        "proposal_packet",
        "reason",
    ),
    ("proposal.md", "Trigger Matrix"): (
        "trigger_category",
        "applies",
        "evidence",
        "required_checks",
        "deferred_checks_and_reason",
    ),
    ("design.md", "Submodules"): ("submodule", "type", "responsibility", "depends_on"),
    ("design.md", "Boundary Decision Matrix"): (
        "boundary",
        "classification",
        "business_responsibility",
        "shared_logic_or_technical_area",
        "decision",
    ),
    ("design.md", "Dependency Graph"): ("source", "depends_on", "reason", "cycle_check"),
    ("design.md", "Large Module Submodule Decision"): (
        "submodule",
        "source_proposal",
        "decision",
        "design_packet",
        "reason",
    ),
    ("design.md", "Trigger Matrix"): (
        "trigger_category",
        "applies",
        "evidence",
        "design_coverage",
        "required_checks",
        "deferred_checks_and_reason",
    ),
    ("design.md", "Directly Mapped Change Items"): (
        "change_id",
        "proposal_id",
        "design_coverage",
        "scope_paths",
    ),
    ("testing.md", "Direct Change Coverage"): (
        "change_id",
        "design_source",
        "validation_id",
        "testplan_level",
        "testplan_step_id",
        "gap",
        "gap_manual_reason",
    ),
    ("testing.md", "Case-Type Coverage"): (
        "change_id",
        "case_type",
        "required",
        "validation_id",
        "status",
        "gap_manual_reason",
    ),
}

TRIGGER_CATEGORIES = {
    "contract/protocol",
    "data/schema",
    "security/privacy/permission",
    "runtime/integration",
    "build/dependency/config/deployment",
    "ui/datamodel/workflow",
    "harness/process",
}
CASE_TYPES = {"normal", "boundary", "negative", "error", "compatibility", "lifecycle", "cross-module"}


def fail(message: str) -> None:
    print(f"doc-structure-check: {message}", file=sys.stderr)
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


def section_body(text: str, heading: str, path: Path) -> str:
    pattern = re.compile(rf"(?m)^##\s+{re.escape(heading)}\s*$")
    match = pattern.search(text)
    if not match:
        fail(f"{path} missing required section: ## {heading}")
    next_heading = re.search(r"(?m)^##\s+", text[match.end() :])
    end = match.end() + next_heading.start() if next_heading else len(text)
    return text[match.end() : end]


def table_after_heading(text: str, heading: str, path: Path) -> list[dict[str, str]]:
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
        row = {header: values[pos].strip() if pos < len(values) else "" for pos, header in enumerate(headers)}
        rows.append(row)
    if not rows:
        fail(f"{path} section ## {heading} has no data rows")
    return rows


def non_empty(value: str) -> bool:
    return value.strip().lower() not in EMPTY_VALUES


def check_line_count(path: Path, max_lines: int) -> None:
    line_count = len(read_text(path).splitlines())
    if line_count > max_lines:
        fail(f"{path} has {line_count} lines; split docs above {max_lines} lines")


def check_sections(path: Path, text: str) -> None:
    for heading in REQUIRED_SECTIONS[path.name]:
        section_body(text, heading, path)


def check_tables(path: Path, text: str) -> None:
    for (name, heading), columns in REQUIRED_TABLE_COLUMNS.items():
        if name != path.name:
            continue
        rows = table_after_heading(text, heading, path)
        available = set(rows[0])
        missing = [column for column in columns if column not in available]
        if missing:
            fail(f"{path} ## {heading} missing columns: {', '.join(missing)}")
        for index, row in enumerate(rows, start=1):
            if all(not non_empty(value) for value in row.values()):
                fail(f"{path} ## {heading} row {index} is empty placeholder content")
            for column in columns:
                if column in {
                    "depends_on",
                    "gap_manual_reason",
                    "deferred_checks_and_reason",
                    "required_checks",
                    "testplan_step_id",
                }:
                    continue
                if not non_empty(row.get(column, "")):
                    fail(f"{path} ## {heading} row {index} column {column} is empty placeholder content")


def split_dependencies(value: str) -> list[str]:
    if not non_empty(value):
        return []
    if value.strip().lower() in {"none", "no", "n/a", "na"}:
        return []
    parts = re.split(r"[,;/]+|\band\b", value)
    return [part.strip().strip("`") for part in parts if non_empty(part)]


def check_dependency_graph(path: Path, text: str) -> None:
    rows = table_after_heading(text, "Dependency Graph", path)
    graph: dict[str, set[str]] = {}
    for row in rows:
        source = row.get("source", "").strip().strip("`")
        if not non_empty(source):
            continue
        graph.setdefault(source, set())
        for dependency in split_dependencies(row.get("depends_on", "")):
            graph[source].add(dependency)
            graph.setdefault(dependency, set())

    visiting: set[str] = set()
    visited: set[str] = set()
    stack: list[str] = []

    def visit(node: str) -> None:
        if node in visited:
            return
        if node in visiting:
            cycle = " -> ".join([*stack, node])
            fail(f"{path} dependency graph contains a cycle: {cycle}")
        visiting.add(node)
        stack.append(node)
        for dependency in sorted(graph.get(node, ())):
            visit(dependency)
        stack.pop()
        visiting.remove(node)
        visited.add(node)

    for node in sorted(graph):
        visit(node)


def check_trigger_matrix(path: Path, text: str) -> None:
    if path.name not in {"proposal.md", "design.md"}:
        return
    rows = table_after_heading(text, "Trigger Matrix", path)
    seen: set[str] = set()
    for index, row in enumerate(rows, start=1):
        category = row.get("trigger_category", "").strip().lower()
        applies = row.get("applies", "").strip().lower()
        seen.add(category)
        if category not in TRIGGER_CATEGORIES:
            fail(f"{path} ## Trigger Matrix row {index} has unknown trigger category: {category}")
        if applies not in {"yes", "no"}:
            fail(f"{path} ## Trigger Matrix row {index} Applies must be yes or no")
        if not non_empty(row.get("evidence", "")):
            fail(f"{path} ## Trigger Matrix row {index} must include evidence")
        if applies == "yes" and not non_empty(row.get("required_checks", "")):
            fail(f"{path} ## Trigger Matrix row {index} applies=yes requires checks")
        deferred = row.get("deferred_checks_and_reason", "")
        if non_empty(deferred) and not re.search(r"(?i)\b(owner|risk|acceptance)\b", deferred):
            fail(f"{path} ## Trigger Matrix row {index} deferred checks must include owner, risk, or acceptance impact")
    missing = sorted(TRIGGER_CATEGORIES - seen)
    if missing:
        fail(f"{path} ## Trigger Matrix missing categories: {', '.join(missing)}")


def check_case_type_coverage(path: Path, text: str) -> None:
    if path.name != "testing.md":
        return
    rows = table_after_heading(text, "Case-Type Coverage", path)
    seen: set[str] = set()
    for index, row in enumerate(rows, start=1):
        case_type = row.get("case_type", "").strip().lower()
        required = row.get("required", "").strip().lower()
        status = row.get("status", "").strip().lower()
        seen.add(case_type)
        if case_type not in CASE_TYPES:
            fail(f"{path} ## Case-Type Coverage row {index} has unknown case_type: {case_type}")
        if required not in {"yes", "no"}:
            fail(f"{path} ## Case-Type Coverage row {index} Required must be yes or no")
        if status not in {"covered", "gap", "manual", "disabled", "not-applicable"}:
            fail(f"{path} ## Case-Type Coverage row {index} has invalid status: {status}")
        if required == "yes" and status == "not-applicable":
            fail(f"{path} ## Case-Type Coverage row {index} cannot mark required coverage not-applicable")
        if status in {"gap", "manual", "disabled", "not-applicable"} and not non_empty(row.get("gap_manual_reason", "")):
            fail(f"{path} ## Case-Type Coverage row {index} requires Gap / Manual Reason")
    missing = sorted(CASE_TYPES - seen)
    if missing:
        fail(f"{path} ## Case-Type Coverage missing case types: {', '.join(missing)}")


def check_submodule_doc_placement(packet: Path) -> None:
    for folder_name in ("design", "testing"):
        folder = packet / folder_name
        if not folder.exists():
            continue
        for name in ("proposal.md", "design.md", "testing.md", "testplan.yaml"):
            matches = sorted(folder.rglob(name))
            if matches:
                rendered = ", ".join(str(path) for path in matches[:5])
                fail(f"submodule packet docs belong directly under the submodule packet, not {folder_name}/: {rendered}")


def check_doc(path: Path, max_lines: int) -> None:
    text = read_text(path)
    check_line_count(path, max_lines)
    check_sections(path, text)
    check_tables(path, text)
    if path.name == "design.md":
        check_dependency_graph(path, text)
    check_trigger_matrix(path, text)
    check_case_type_coverage(path, text)
    if path.name == "testing.md" and "harness/scripts/test-run.py" not in text:
        fail(f"{path} must reference the unified test entrypoint")


def packet_path(root: Path, version: str, module: str, submodule: str | None) -> Path:
    packet = root / "docs" / "versions" / version / "modules" / module
    if submodule:
        packet = packet / submodule
    return packet


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--version", required=True)
    parser.add_argument("--module", required=True)
    parser.add_argument("--submodule")
    parser.add_argument("--max-lines", type=int, default=MAX_HUMAN_DOC_LINES)
    parser.add_argument(
        "--docs",
        choices=("all", "mandatory", "proposal", "design", "testing"),
        default="all",
    )
    args = parser.parse_args()

    packet = packet_path(Path(args.root), args.version, args.module, args.submodule)
    if args.docs in {"all", "mandatory", "proposal"}:
        check_doc(packet / "proposal.md", args.max_lines)
    if args.docs in {"all", "mandatory", "design"}:
        check_doc(packet / "design.md", args.max_lines)
    if args.docs in {"all", "testing"}:
        testing = packet / "testing.md"
        if testing.exists():
            check_doc(testing, args.max_lines)
        elif args.docs == "testing":
            fail(f"missing required file: {testing}")

    check_submodule_doc_placement(packet)
    print("doc-structure-check: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
