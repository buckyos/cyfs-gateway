#!/usr/bin/env python3
"""Check implementation admission for explicit module/change ids.

The checker verifies mandatory proposal/design structure, approval state,
direct change traceability, and task-level admission evidence that records
the required document-reading and coverage judgment before code edits.

Evidence files are bound to the exact approved document content: they must
record LF-normalized sha256 hashes of proposal.md/design.md and verbatim
coverage quotes that the checker re-verifies against the current documents,
so stale or fabricated evidence fails closed.

On success the checker writes a machine-readable admission stamp
(`harness/evidence/admission/<task-id>.<module>[.<submodule>].stamp.json`)
recording the bound document hashes and the admitted design Scope Paths.
edit-guard.py validates that stamp before allowing production-code edits, and
stage-scope-check.py uses the same Scope Paths to reject out-of-scope diffs.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import re
import sys
from pathlib import Path


FORBIDDEN_BROAD_IDS = {"all", "any", "bugfix", "change", "cleanup", "misc", "module", "refactor", "task"}
REQUIRED_DOCS = ("proposal.md", "design.md")
APPROVAL_DOCS = ("proposal.md", "design.md")
TABLE_SEPARATOR_RE = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$")
REQUIRED_EVIDENCE_ITEMS = (
    "proposal_read",
    "design_read",
    "change_scope_matches_request",
    "active_module_resolved",
    "no_chat_only_evidence",
)
EMPTY_VALUES = {"", "-", "n/a", "na", "none", "tbd", "todo", "pending", '""', "''"}
PIPELINE_APPROVER = "auto-pipeline"
FORBIDDEN_APPROVERS = {
    "agent", "assistant", "ai", "bot", "llm", "model", "self", "auto",
    "claude", "codex", "copilot", "cursor", "gemini", "gpt",
}
APPROVAL_RECORD_FIELDS = ("approver", "approval_date", "user_statement")
APPROVAL_FRONT_MATTER_FIELDS = ("status", "approved_by", "approved_at", "approved_content_sha256")
EVIDENCE_FILENAME_RE = re.compile(r"^(\d{4})(\d{2})(\d{2})-[A-Za-z0-9][A-Za-z0-9_.-]*\.md$")
MIN_QUOTE_CHARS = 20
STAMP_SCHEMA = 1


def fail(message: str) -> None:
    print(f"admission-check: {message}", file=sys.stderr)
    raise SystemExit(1)


def read_text(path: Path) -> str:
    if not path.exists():
        fail(f"missing required file: {path}")
    return path.read_text(encoding="utf-8")


def front_matter(text: str, path: Path) -> dict[str, str]:
    if not text.startswith("---\n"):
        fail(f"missing front matter: {path}")
    end = text.find("\n---", 4)
    if end == -1:
        fail(f"unterminated front matter: {path}")
    data: dict[str, str] = {}
    for line in text[4:end].splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip()
    return data


def validate_change_id(change_id: str) -> None:
    if change_id.lower() in FORBIDDEN_BROAD_IDS:
        fail(f"change_id is too broad: {change_id}")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{2,63}", change_id):
        fail(f"change_id must be a stable 3-64 character id: {change_id}")


def approval_record_fields(text: str, path: Path) -> dict[str, str]:
    match = re.search(r"(?m)^##\s+Approval Record\s*$", text)
    if not match:
        fail(f"{path} is approved but missing required section: ## Approval Record")
    next_heading = re.search(r"(?m)^##\s+", text[match.end() :])
    end = match.end() + next_heading.start() if next_heading else len(text)
    fields: dict[str, str] = {}
    for line in text[match.end() : end].splitlines():
        item = re.match(r"^\s*-\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$", line)
        if item:
            fields[item.group(1).strip()] = item.group(2).strip()
    return fields


def approval_content_sha256(text: str) -> str:
    """Hash the approvable document content, excluding the approval fields themselves.

    LF-normalize, drop the approval-related front matter lines, drop the
    `## Approval Record` section, and hash the rest. Applying an approval does
    not change this hash, but any later content edit does, so a stale approval
    fails closed until the document is re-approved.
    """
    text = text.replace("\r\n", "\n")
    if text.startswith("---\n"):
        end = text.find("\n---", 4)
        if end != -1:
            kept = [
                line
                for line in text[4:end].splitlines()
                if line.split(":", 1)[0].strip() not in APPROVAL_FRONT_MATTER_FIELDS
            ]
            text = "---\n" + "\n".join(kept) + text[end:]
    match = re.search(r"(?m)^##\s+Approval Record\s*$", text)
    if match:
        next_heading = re.search(r"(?m)^##\s+", text[match.end() :])
        section_end = match.end() + next_heading.start() if next_heading else len(text)
        text = text[: match.start()] + text[section_end:]
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def require_approval_content_hash(path: Path, text: str, data: dict[str, str]) -> None:
    recorded = data.get("approved_content_sha256", "").strip().lower()
    if not has_value(recorded):
        fail(
            f"{path} is approved but front matter is missing approved_content_sha256; "
            "generate it via schema-check.py --print-approval-hash and record it in the "
            "same edit that applies the approval"
        )
    actual = approval_content_sha256(text)
    if recorded != actual:
        fail(
            f"{path} approved_content_sha256 does not match the current document content: "
            f"the document changed after approval, so the approval is stale; "
            f"re-approve the document (current hash {actual})"
        )


def require_approval_provenance(root: Path, path: Path, text: str, data: dict[str, str]) -> None:
    approved_by = data.get("approved_by", "").strip()
    require_approval_content_hash(path, text, data)

    if approved_by == PIPELINE_APPROVER:
        plan = root / "harness" / "pipeline-plan.md"
        if not plan.exists():
            fail(
                f"{path} is approved by {PIPELINE_APPROVER} but {plan} is missing; "
                "auto-pipeline approval requires recorded launch evidence"
            )
        launch = re.search(r"(?mi)^\s*-\s*User launch confirmed:\s*(.+)$", plan.read_text(encoding="utf-8"))
        if not launch or not has_value(launch.group(1)):
            fail(
                f"{path} is approved by {PIPELINE_APPROVER} but {plan} does not record "
                "a non-empty 'User launch confirmed:' value under ## Trigger"
            )
        return

    if approved_by.lower() in FORBIDDEN_APPROVERS:
        fail(
            f"{path} approved_by '{approved_by}' looks like an agent self-approval; "
            "only the user or auto-pipeline (after explicit launch) may approve"
        )

    record = approval_record_fields(text, path)
    missing = [field for field in APPROVAL_RECORD_FIELDS if not has_value(record.get(field, ""))]
    if missing:
        fail(f"{path} ## Approval Record has missing or placeholder fields: {', '.join(missing)}")
    if record["approver"].strip() != approved_by:
        fail(
            f"{path} ## Approval Record approver '{record['approver'].strip()}' "
            f"does not match front matter approved_by '{approved_by}'"
        )


def require_approved(root: Path, path: Path, module: str, version: str, submodule: str | None = None) -> None:
    text = read_text(path)
    data = front_matter(text, path)
    if data.get("module") != module:
        fail(f"{path} module mismatch: expected {module}, got {data.get('module', '<missing>')}")
    if data.get("version") != version:
        fail(f"{path} version mismatch: expected {version}, got {data.get('version', '<missing>')}")
    if submodule and data.get("submodule") not in {None, "", submodule}:
        fail(f"{path} submodule mismatch: expected {submodule}, got {data.get('submodule')}")
    if data.get("status") != "approved":
        fail(f"{path} is not approved")
    if not has_value(data.get("approved_by", "")) or not has_value(data.get("approved_at", "")):
        fail(f"{path} approval metadata is incomplete")
    require_approval_provenance(root, path, text, data)


def normalize_column(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")


def split_table_row(line: str) -> list[str]:
    parts = [part.strip() for part in line.strip().split("|")]
    if parts and parts[0] == "":
        parts = parts[1:]
    if parts and parts[-1] == "":
        parts = parts[:-1]
    return parts


def table_rows_after_heading(text: str, heading: str, path: Path) -> list[dict[str, str]]:
    heading_pattern = re.compile(rf"(?m)^##\s+{re.escape(heading)}\s*$")
    match = heading_pattern.search(text)
    if not match:
        fail(f"{path} missing required section: ## {heading}")

    lines = text[match.end() :].splitlines()
    table_start = None
    for index, line in enumerate(lines):
        if re.match(r"^##\s+", line):
            break
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


def require_table_change(
    path: Path,
    text: str,
    heading: str,
    change_id: str,
    required_columns: tuple[str, ...],
    required_values: tuple[str, ...],
) -> dict[str, str]:
    rows = table_rows_after_heading(text, heading, path)
    available_columns = set(rows[0])
    missing_columns = [column for column in required_columns if column not in available_columns]
    if missing_columns:
        fail(f"{path} ## {heading} missing columns: {', '.join(missing_columns)}")

    matches = [row for row in rows if row.get("change_id") == change_id]
    if not matches:
        fail(f"change_id {change_id} missing from {path} ## {heading} change_id column")
    if len(matches) > 1:
        fail(f"change_id {change_id} appears multiple times in {path} ## {heading}")

    row = matches[0]
    empty_values = [column for column in required_values if not row.get(column)]
    if empty_values:
        fail(f"change_id {change_id} in {path} ## {heading} has empty fields: {', '.join(empty_values)}")
    return row


def section_body(text: str, heading: str, path: Path) -> str:
    match = re.search(rf"(?m)^##\s+{re.escape(heading)}\s*$", text)
    if not match:
        fail(f"{path} missing required section: ## {heading}")
    next_heading = re.search(r"(?m)^##\s+", text[match.end() :])
    end = match.end() + next_heading.start() if next_heading else len(text)
    return text[match.end() : end]


def table_rows_in_section(text: str, heading: str, path: Path) -> list[dict[str, str]]:
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


def has_value(value: str) -> bool:
    return value.strip().lower() not in EMPTY_VALUES


def normalize_ws(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def lf_sha256(path: Path) -> str:
    text = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def validate_evidence_filename(path: Path) -> None:
    match = EVIDENCE_FILENAME_RE.match(path.name)
    if not match:
        fail(
            f"evidence file name must match <YYYYMMDD>-<task-slug>.md: {path.name}"
        )
    try:
        stamp = datetime.date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
    except ValueError:
        fail(f"evidence file name has an invalid date: {path.name}")
    if stamp > datetime.date.today():
        fail(f"evidence file name is dated in the future: {path.name}")


def validate_document_binding(text: str, path: Path, expected_docs: dict[str, Path]) -> None:
    rows = table_rows_in_section(text, "Document Binding", path)
    available = set(rows[0])
    if not {"doc", "sha256"} <= available:
        fail(f"{path} ## Document Binding must have doc and sha256 columns")
    recorded = {row.get("doc", "").strip(): row.get("sha256", "").strip().lower() for row in rows}
    for rel_path, doc_path in expected_docs.items():
        if rel_path not in recorded:
            fail(f"{path} ## Document Binding missing row for {rel_path}")
        actual = lf_sha256(doc_path)
        if recorded[rel_path] != actual:
            fail(
                f"{path} ## Document Binding hash mismatch for {rel_path}: "
                f"evidence was created against different document content; "
                f"re-read the document and regenerate the evidence "
                f"(current sha256 {actual})"
            )


def quote_block(text: str, leaf: str, change_id: str, path: Path) -> str:
    heading = re.search(
        rf"(?m)^###\s+Quote:\s+{re.escape(leaf)}\s+{re.escape(change_id)}\s*$", text
    )
    if not heading:
        fail(f"{path} missing section: ### Quote: {leaf} {change_id}")
    lines: list[str] = []
    for line in text[heading.end() :].splitlines():
        stripped = line.strip()
        if not stripped:
            if lines:
                break
            continue
        if stripped.startswith(">"):
            lines.append(stripped.lstrip(">").strip())
            continue
        break
    return "\n".join(lines)


def validate_coverage_quotes(
    text: str, path: Path, change_ids: list[str], doc_texts: dict[str, str]
) -> None:
    for change_id in change_ids:
        for leaf, doc_text in doc_texts.items():
            quote = normalize_ws(quote_block(text, leaf, change_id, path))
            if len(quote) < MIN_QUOTE_CHARS:
                fail(
                    f"{path} quote for {leaf} {change_id} is too short; "
                    f"quote the verbatim coverage row or sentence (>= {MIN_QUOTE_CHARS} chars)"
                )
            if change_id not in quote:
                fail(f"{path} quote for {leaf} {change_id} does not contain the change_id")
            if quote not in normalize_ws(doc_text):
                fail(
                    f"{path} quote for {leaf} {change_id} does not appear verbatim in {leaf}; "
                    "quotes must be copied from the current approved document"
                )


def validate_admission_evidence(path: Path, change_ids: list[str]) -> None:
    text = read_text(path)
    rows = table_rows_in_section(text, "Implementation Admission Evidence", path)
    available = set(rows[0])
    required_columns = {"evidence_item", "source", "status", "notes"}
    missing_columns = sorted(required_columns - available)
    if missing_columns:
        fail(f"{path} ## Implementation Admission Evidence missing columns: {', '.join(missing_columns)}")

    by_item = {row.get("evidence_item", "").strip(): row for row in rows if row.get("evidence_item", "").strip()}
    missing_items = [item for item in REQUIRED_EVIDENCE_ITEMS if item not in by_item]
    if missing_items:
        fail(f"{path} missing admission evidence items: {', '.join(missing_items)}")

    for item in REQUIRED_EVIDENCE_ITEMS:
        row = by_item[item]
        if row.get("status", "").strip().lower() != "pass":
            fail(f"{path} admission evidence item {item} must have status pass")
        if not has_value(row.get("source", "")):
            fail(f"{path} admission evidence item {item} must name a source")
        if not has_value(row.get("notes", "")):
            fail(f"{path} admission evidence item {item} must include notes")

    text_lower = text.lower()
    for change_id in change_ids:
        if change_id.lower() not in text_lower:
            fail(f"{path} must cite admitted change_id: {change_id}")


def parse_scope_paths(cell: str) -> list[str]:
    """Parse a design Scope Paths cell into repo-relative path entries.

    Entries are the backtick-wrapped tokens in the cell; without backticks the
    cell is split on commas. Each entry is a path prefix or fnmatch glob
    relative to the repository root.
    """
    entries = [match.group(1) for match in re.finditer(r"`([^`]+)`", cell)]
    if not entries:
        entries = cell.split(",")
    normalized: list[str] = []
    for entry in entries:
        cleaned = entry.strip().replace("\\", "/").strip("/")
        if cleaned and cleaned not in normalized:
            normalized.append(cleaned)
    return normalized


def write_admission_stamp(
    root: Path,
    evidence_path: Path,
    packet: Path,
    packet_rel: str,
    args: argparse.Namespace,
    scope_paths: list[str],
) -> Path:
    stamp_name = evidence_path.stem + "." + args.module
    if args.submodule:
        stamp_name += "." + args.submodule
    stamp_path = evidence_path.parent / (stamp_name + ".stamp.json")
    try:
        evidence_rel = evidence_path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        evidence_rel = evidence_path.as_posix()
    stamp = {
        "schema": STAMP_SCHEMA,
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "evidence_file": evidence_rel,
        "version": args.version,
        "module": args.module,
        "submodule": args.submodule,
        "change_ids": list(args.change_ids),
        "doc_hashes": {f"{packet_rel}/{name}": lf_sha256(packet / name) for name in REQUIRED_DOCS},
        "scope_paths": scope_paths,
    }
    stamp_path.write_text(json.dumps(stamp, indent=2) + "\n", encoding="utf-8")
    return stamp_path


def yaml_list_contains(block: str, key: str, value: str) -> bool:
    inline = re.search(rf"(?m)^\s*{re.escape(key)}:\s*\[([^\]]*)\]\s*$", block)
    if inline:
        values = [item.strip().strip("\"'") for item in inline.group(1).split(",")]
        return value in values

    multiline = re.search(rf"(?ms)^\s*{re.escape(key)}:\s*\n((?:\s+-\s*[^\n]+\n?)+)", block)
    if multiline:
        values = [line.split("-", 1)[1].strip().strip("\"'") for line in multiline.group(1).splitlines()]
        return value in values
    return False


def extract_level_block(text: str, level: str) -> str:
    match = re.search(rf"(?m)^  {re.escape(level)}:\s*$", text)
    if not match:
        return ""
    next_level = re.search(r"(?m)^  [A-Za-z0-9_-]+:\s*$", text[match.end() :])
    end = match.end() + next_level.start() if next_level else len(text)
    return text[match.end() : end]


def extract_step_block(level_block: str, step_id: str) -> str:
    match = re.search(rf"(?m)^      - id:\s*{re.escape(step_id)}\s*$", level_block)
    if not match:
        return ""
    next_step = re.search(r"(?m)^      - id:\s*[A-Za-z0-9_.-]+\s*$", level_block[match.end() :])
    end = match.end() + next_step.start() if next_step else len(level_block)
    return level_block[match.start() : end]


def require_testplan_mapping(path: Path, text: str, change_id: str, testing_row: dict[str, str]) -> None:
    level = testing_row.get("testplan_level", "").strip()
    step_id = testing_row.get("testplan_step_id", "").strip()
    gap = testing_row.get("gap", "").strip().lower()
    gap_reason = testing_row.get("gap_manual_reason", "").strip()

    if not level:
        fail(f"change_id {change_id} in testing.md must declare testplan_level")
    level_block = extract_level_block(text, level)
    if not level_block:
        fail(f"change_id {change_id} references missing testplan level: {level}")

    if level in {"manual", "disabled"} or gap in {"yes", "manual", "disabled"}:
        if not gap_reason:
            fail(f"change_id {change_id} declares a gap/manual path without a reason in testing.md")
        if not yaml_list_contains(level_block, "change_ids", change_id):
            fail(f"change_id {change_id} must appear in testplan.yaml level {level} change_ids")
        return

    if not step_id:
        fail(f"change_id {change_id} in testing.md must declare testplan_step_id")
    step_block = extract_step_block(level_block, step_id)
    if not step_block:
        fail(f"change_id {change_id} references missing testplan step: {level}/{step_id}")
    if not yaml_list_contains(step_block, "change_ids", change_id):
        fail(f"change_id {change_id} must appear in testplan.yaml step {level}/{step_id} change_ids")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--version", required=True)
    parser.add_argument("--module", required=True)
    parser.add_argument("--submodule")
    parser.add_argument("--change-id", action="append", dest="change_ids")
    parser.add_argument(
        "--evidence-file",
        help="task evidence file containing ## Implementation Admission Evidence",
    )
    parser.add_argument(
        "--print-doc-hashes",
        action="store_true",
        help="print the LF-normalized sha256 hashes needed for ## Document Binding and exit",
    )
    args = parser.parse_args()

    root = Path(args.root)
    packet = root / "docs" / "versions" / args.version / "modules" / args.module
    packet_rel = f"docs/versions/{args.version}/modules/{args.module}"
    if args.submodule:
        packet = packet / args.submodule
        packet_rel = f"{packet_rel}/{args.submodule}"
    for name in REQUIRED_DOCS:
        if not (packet / name).exists():
            fail(f"missing required file: {packet / name}")

    if args.print_doc_hashes:
        for name in REQUIRED_DOCS:
            print(f"| {packet_rel}/{name} | {lf_sha256(packet / name)} |")
        return 0

    if not args.change_ids:
        fail("--change-id is required")
    if not args.evidence_file:
        fail("--evidence-file is required")
    for name in APPROVAL_DOCS:
        require_approved(root, packet / name, args.module, args.version, args.submodule)

    docs = {name: read_text(packet / name) for name in REQUIRED_DOCS}
    scope_paths: list[str] = []
    for change_id in args.change_ids:
        validate_change_id(change_id)
        require_table_change(
            packet / "proposal.md",
            docs["proposal.md"],
            "Proposal Items",
            change_id,
            ("proposal_id", "change_id", "outcome", "success_evidence"),
            ("proposal_id", "outcome", "success_evidence"),
        )
        design_row = require_table_change(
            packet / "design.md",
            docs["design.md"],
            "Directly Mapped Change Items",
            change_id,
            ("change_id", "proposal_id", "design_coverage", "scope_paths"),
            ("proposal_id", "design_coverage", "scope_paths"),
        )
        entries = parse_scope_paths(design_row.get("scope_paths", ""))
        if not entries:
            fail(
                f"change_id {change_id} has no parsable Scope Paths entries in design.md; "
                "record concrete repo-relative paths or globs (backtick-wrapped) so the "
                "implementation diff can be scoped mechanically"
            )
        for entry in entries:
            if entry not in scope_paths:
                scope_paths.append(entry)

    evidence_path = Path(args.evidence_file)
    if not evidence_path.is_absolute():
        evidence_path = Path(args.root) / evidence_path
    validate_evidence_filename(evidence_path)
    validate_admission_evidence(evidence_path, args.change_ids)
    evidence_text = read_text(evidence_path)
    validate_document_binding(
        evidence_text,
        evidence_path,
        {f"{packet_rel}/{name}": packet / name for name in REQUIRED_DOCS},
    )
    validate_coverage_quotes(evidence_text, evidence_path, args.change_ids, docs)
    stamp_path = write_admission_stamp(root, evidence_path, packet, packet_rel, args, scope_paths)
    print("admission-check: passed")
    print("implementation admission evidence: passed")
    print(f"admission stamp written: {stamp_path}")
    print(f"admitted scope paths: {', '.join(scope_paths)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
