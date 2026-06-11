#!/usr/bin/env python3
"""Validate the generated Harness Engineering module packet shape.

This template intentionally uses only the Python standard library. Adapt paths
or stricter YAML parsing after the target repository chooses its dependencies.
Only proposal.md and design.md are mandatory implementation-admission inputs.
testplan.yaml is validated when present; testing-coverage-check.py enforces it
for completed testing work.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path


REQUIRED_FRONT_MATTER = ("module", "version", "status", "approved_by", "approved_at")
APPROVAL_FRONT_MATTER_FIELDS = ("status", "approved_by", "approved_at", "approved_content_sha256")
ALLOWED_LEVELS = {"unit", "dv", "integration"}
ALLOWED_MODES = {"enabled", "manual", "disabled"}
PIPELINE_APPROVER = "auto-pipeline"
FORBIDDEN_APPROVERS = {
    "agent", "assistant", "ai", "bot", "llm", "model", "self", "auto",
    "claude", "codex", "copilot", "cursor", "gemini", "gpt",
}
APPROVAL_RECORD_FIELDS = ("approver", "approval_date", "user_statement")
PLACEHOLDER_VALUES = {"", "-", "n/a", "na", "none", "tbd", "todo", "pending", '""', "''"}


def fail(message: str) -> None:
    print(f"schema-check: {message}", file=sys.stderr)
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


def has_value(value: str) -> bool:
    return value.strip().strip('"').strip("'").lower() not in PLACEHOLDER_VALUES


def approval_record_fields(text: str, path: Path) -> dict[str, str]:
    match = re.search(r"(?m)^##\s+Approval Record\s*$", text)
    if not match:
        fail(f"{path} is approved but missing required section: ## Approval Record")
    next_heading = re.search(r"(?m)^##\s+", text[match.end() :])
    end = match.end() + next_heading.start() if next_heading else len(text)
    body = text[match.end() : end]
    fields: dict[str, str] = {}
    for line in body.splitlines():
        item = re.match(r"^\s*-\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$", line)
        if item:
            fields[item.group(1).strip()] = item.group(2).strip()
    return fields


def validate_pipeline_launch_evidence(root: Path, path: Path) -> None:
    plan = root / "harness" / "pipeline-plan.md"
    if not plan.exists():
        fail(
            f"{path} is approved by {PIPELINE_APPROVER} but {plan} is missing; "
            "auto-pipeline approval requires recorded launch evidence"
        )
    text = plan.read_text(encoding="utf-8")
    launch = re.search(r"(?mi)^\s*-\s*User launch confirmed:\s*(.+)$", text)
    if not launch or not has_value(launch.group(1)):
        fail(
            f"{path} is approved by {PIPELINE_APPROVER} but {plan} does not record "
            "a non-empty 'User launch confirmed:' value under ## Trigger"
        )


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


def validate_approval_content_hash(path: Path, text: str, data: dict[str, str]) -> None:
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


def validate_approval_provenance(root: Path, path: Path, text: str, data: dict[str, str]) -> None:
    if data.get("status") != "approved":
        return
    approved_by = data.get("approved_by", "").strip()
    approved_at = data.get("approved_at", "").strip()
    if not has_value(approved_by) or not has_value(approved_at):
        fail(f"{path} is approved but approved_by/approved_at are empty")
    validate_approval_content_hash(path, text, data)

    if approved_by == PIPELINE_APPROVER:
        validate_pipeline_launch_evidence(root, path)
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


def validate_doc(root: Path, path: Path, module: str, version: str, submodule: str | None = None) -> None:
    text = read_text(path)
    data = front_matter(text, path)
    missing = [field for field in REQUIRED_FRONT_MATTER if field not in data]
    if missing:
        fail(f"{path} missing front matter fields: {', '.join(missing)}")
    if data["module"] != module:
        fail(f"{path} module mismatch: expected {module}, got {data['module']}")
    if data["version"] != version:
        fail(f"{path} version mismatch: expected {version}, got {data['version']}")
    if submodule and data.get("submodule") not in {None, "", submodule}:
        fail(f"{path} submodule mismatch: expected {submodule}, got {data['submodule']}")
    validate_approval_provenance(root, path, text, data)


def extract_level_blocks(text: str) -> dict[str, str]:
    match = re.search(r"(?m)^levels:\s*$", text)
    if not match:
        fail("testplan.yaml missing levels")
    levels_text = text[match.end() :]
    starts = list(re.finditer(r"(?m)^  ([A-Za-z0-9_-]+):\s*$", levels_text))
    blocks: dict[str, str] = {}
    for index, start in enumerate(starts):
        level = start.group(1)
        end = starts[index + 1].start() if index + 1 < len(starts) else len(levels_text)
        blocks[level] = levels_text[start.end() : end]
    return blocks


def validate_testplan(path: Path, module: str, version: str, submodule: str | None = None) -> None:
    text = read_text(path)
    for key, value in (("schema_version", "1"), ("version", version), ("module", module)):
        if not re.search(rf"(?m)^{re.escape(key)}:\s*{re.escape(value)}\s*$", text):
            fail(f"{path} missing or mismatched {key}: {value}")
    if submodule and re.search(r"(?m)^submodule:\s*\S+", text):
        if not re.search(rf"(?m)^submodule:\s*{re.escape(submodule)}\s*$", text):
            fail(f"{path} submodule mismatch: expected {submodule}")

    blocks = extract_level_blocks(text)
    unknown = set(blocks) - ALLOWED_LEVELS
    if unknown:
        fail(f"{path} has unknown test levels: {', '.join(sorted(unknown))}")

    step_ids: set[str] = set()
    for level in sorted(ALLOWED_LEVELS):
        if level not in blocks:
            fail(f"{path} missing test level: {level}")
        block = blocks[level]
        mode_match = re.search(r"(?m)^    mode:\s*([A-Za-z0-9_-]+)\s*$", block)
        if not mode_match:
            fail(f"{path} level {level} missing mode")
        mode = mode_match.group(1)
        if mode not in ALLOWED_MODES:
            fail(f"{path} level {level} has invalid mode: {mode}")

        ids = re.findall(r"(?m)^      - id:\s*([A-Za-z0-9_.-]+)\s*$", block)
        if mode == "enabled" and not ids:
            fail(f"{path} enabled level {level} has no steps")
        if mode in {"manual", "disabled"} and not re.search(r"(?mi)reason:\s*\S+", block):
            fail(f"{path} {mode} level {level} missing reason")
        for step_id in ids:
            if step_id in step_ids:
                fail(f"{path} duplicate step id: {step_id}")
            step_ids.add(step_id)
            step_pattern = (
                rf"(?ms)^      - id:\s*{re.escape(step_id)}\s*$"
                rf".*?^        name:\s*\S+"
                rf".*?^        change_ids:\s*\[.+\]\s*$"
                rf".*?^        run:\s*\[.+\]\s*$"
            )
            if not re.search(step_pattern, block):
                fail(f"{path} step {step_id} must define name, change_ids, and run")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--version")
    parser.add_argument("--module")
    parser.add_argument("--submodule")
    parser.add_argument(
        "--print-approval-hash",
        metavar="DOC",
        help="print the approved_content_sha256 value for one document and exit",
    )
    args = parser.parse_args()

    if args.print_approval_hash:
        doc = Path(args.print_approval_hash)
        print(approval_content_sha256(read_text(doc)))
        return 0

    if not (args.version and args.module):
        fail("--version and --module are required")

    root = Path(args.root)
    packet = root / "docs" / "versions" / args.version / "modules" / args.module
    if args.submodule:
        packet = packet / args.submodule
    for name in ("proposal.md", "design.md"):
        validate_doc(root, packet / name, args.module, args.version, args.submodule)
    optional_testing = packet / "testing.md"
    if optional_testing.exists():
        validate_doc(root, optional_testing, args.module, args.version, args.submodule)
    optional_testplan = packet / "testplan.yaml"
    if optional_testplan.exists():
        validate_testplan(optional_testplan, args.module, args.version, args.submodule)
    print("schema-check: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
