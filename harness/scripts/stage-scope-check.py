#!/usr/bin/env python3
"""Validate that the current diff stays inside one Harness stage scope.

This checker is intentionally conservative and dependency-free. It is meant to
catch accidental cross-stage edits such as a proposal task also changing
design.md, testing.md, testplan.yaml, or acceptance artifacts.

For the implementation stage, passing --version/--module/--change-id binds the
diff to the admitted design Scope Paths: every changed production path must
match one of the `Scope Paths` entries recorded for the admitted change_id
rows in design.md `## Directly Mapped Change Items`. This turns change-level
traceability from a review-time prose rule into a mechanical gate.
"""

from __future__ import annotations

import argparse
import fnmatch
import re
import subprocess
import sys
from pathlib import Path


STAGES = {"proposal", "design", "testing", "implementation", "acceptance"}
MODULE_DOCS = {"proposal.md", "design.md", "testing.md", "testplan.yaml", "acceptance.md"}
TABLE_SEPARATOR_RE = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$")


def fail(message: str) -> None:
    print(f"stage-scope-check: {message}", file=sys.stderr)
    raise SystemExit(1)


def git(args: list[str], root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
        )
    except FileNotFoundError:
        fail("git executable not found")
    except subprocess.CalledProcessError as error:
        stderr = error.stderr.decode("utf-8", errors="replace").strip()
        fail(stderr or f"git {' '.join(args)} failed")
    return result.stdout.decode("utf-8", errors="replace")


def normalize(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def parse_status_z(output: str) -> list[str]:
    changed: list[str] = []
    records = [record for record in output.split("\0") if record]
    index = 0
    while index < len(records):
        record = records[index]
        if len(record) < 4:
            fail(f"unexpected git status record: {record!r}")
        status = record[:2]
        path = record[3:]
        changed.append(normalize(path))
        index += 1
        if "R" in status or "C" in status:
            if index >= len(records):
                fail(f"rename/copy status missing old path for: {path}")
            changed.append(normalize(records[index]))
            index += 1
    return changed


def parse_diff_name_status_z(output: str) -> list[str]:
    changed: list[str] = []
    records = [record for record in output.split("\0") if record]
    index = 0
    while index < len(records):
        status = records[index]
        index += 1
        if not status:
            continue
        if status[0] in {"R", "C"}:
            if index + 1 >= len(records):
                fail(f"rename/copy diff status missing path data: {status}")
            old_path = records[index]
            new_path = records[index + 1]
            changed.extend([normalize(old_path), normalize(new_path)])
            index += 2
        else:
            if index >= len(records):
                fail(f"diff status missing path data: {status}")
            changed.append(normalize(records[index]))
            index += 1
    return changed


def changed_paths(root: Path, base: str | None, include_untracked: bool) -> list[str]:
    if base:
        output = git(["diff", "--name-status", "-z", f"{base}...HEAD"], root)
        return sorted(set(parse_diff_name_status_z(output)))

    args = ["status", "--porcelain=v1", "-z"]
    if include_untracked:
        args.append("--untracked-files=all")
    else:
        args.append("--untracked-files=no")
    output = git(args, root)
    return sorted(set(parse_status_z(output)))


def packet_parts(path: str) -> tuple[str, str, str] | None:
    parts = path.split("/")
    if len(parts) < 6:
        return None
    if parts[0] != "docs" or parts[1] != "versions" or parts[3] != "modules":
        return None
    version = parts[2]
    module = parts[4]
    relative = "/".join(parts[5:])
    return version, module, relative


def active_packet(path: str, version: str | None, module: str | None, submodule: str | None = None) -> tuple[str, str, str] | None:
    packet = packet_parts(path)
    if packet is None:
        return None
    packet_version, packet_module, relative = packet
    if version and packet_version != version:
        return None
    if module and packet_module != module:
        return None
    if submodule and relative != submodule and not relative.startswith(f"{submodule}/"):
        return None
    return packet_version, packet_module, relative


def is_module_boundary_sync(path: str, module: str | None) -> bool:
    if not path.startswith("docs/modules/") or not path.endswith(".md"):
        return False
    if module is None:
        return True
    return path == f"docs/modules/{module}.md"


def is_review_report(path: str) -> bool:
    if path.startswith("docs/reviews/") and path.endswith(".md"):
        return True
    parts = path.split("/")
    return (
        len(parts) >= 5
        and parts[0] == "docs"
        and parts[1] == "versions"
        and parts[3] == "reviews"
        and path.endswith(".md")
    )


def is_stage_doc_path(path: str) -> bool:
    packet = packet_parts(path)
    if packet is None:
        return False
    relative = packet[2]
    leaf = relative.rsplit("/", 1)[-1]
    return (
        leaf in MODULE_DOCS
        or relative.startswith("design/")
        or relative.startswith("testing/")
    )


def is_test_artifact(path: str) -> bool:
    parts = path.split("/")
    leaf = parts[-1].lower()
    return (
        "tests" in parts
        or "test" in parts
        or "__tests__" in parts
        or leaf.startswith("test_")
        or leaf.endswith("_test.py")
        or ".test." in leaf
        or ".spec." in leaf
        or leaf.endswith("_test.rs")
        or leaf.endswith("_tests.rs")
        or leaf in {"test.rs", "tests.rs"}
    )


def normalize_column(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")


def split_table_row(line: str) -> list[str]:
    parts = [part.strip() for part in line.strip().split("|")]
    if parts and parts[0] == "":
        parts = parts[1:]
    if parts and parts[-1] == "":
        parts = parts[:-1]
    return parts


def parse_scope_paths(cell: str) -> list[str]:
    entries = [match.group(1) for match in re.finditer(r"`([^`]+)`", cell)]
    if not entries:
        entries = cell.split(",")
    normalized: list[str] = []
    for entry in entries:
        cleaned = entry.strip().replace("\\", "/").strip("/")
        if cleaned and cleaned not in normalized:
            normalized.append(cleaned)
    return normalized


def design_scope_paths(root: Path, version: str, module: str, submodule: str | None, change_ids: list[str]) -> list[str]:
    design = root / "docs" / "versions" / version / "modules" / module
    if submodule:
        design = design / submodule
    design = design / "design.md"
    if not design.exists():
        fail(f"missing design document for scope binding: {design}")
    text = design.read_text(encoding="utf-8")

    heading = re.search(r"(?m)^##\s+Directly Mapped Change Items\s*$", text)
    if not heading:
        fail(f"{design} missing required section: ## Directly Mapped Change Items")
    lines = text[heading.end() :].splitlines()
    table_start = None
    for index, line in enumerate(lines):
        if re.match(r"^##\s+", line):
            break
        if "|" in line and index + 1 < len(lines) and TABLE_SEPARATOR_RE.match(lines[index + 1]):
            table_start = index
            break
    if table_start is None:
        fail(f"{design} ## Directly Mapped Change Items missing required table")

    headers = [normalize_column(cell) for cell in split_table_row(lines[table_start])]
    rows: list[dict[str, str]] = []
    for line in lines[table_start + 2 :]:
        if not line.strip() or not line.lstrip().startswith("|"):
            break
        values = split_table_row(line)
        rows.append({header: values[pos].strip() if pos < len(values) else "" for pos, header in enumerate(headers)})

    scope_paths: list[str] = []
    for change_id in change_ids:
        matches = [row for row in rows if row.get("change_id") == change_id]
        if not matches:
            fail(f"change_id {change_id} missing from {design} ## Directly Mapped Change Items")
        entries = parse_scope_paths(matches[0].get("scope_paths", ""))
        if not entries:
            fail(f"change_id {change_id} has no parsable Scope Paths entries in {design}")
        for entry in entries:
            if entry not in scope_paths:
                scope_paths.append(entry)
    return scope_paths


def in_scope_paths(path: str, scope_paths: list[str]) -> bool:
    for entry in scope_paths:
        if path == entry or path.startswith(entry + "/"):
            return True
        if fnmatch.fnmatch(path, entry):
            return True
    return False


def allowed_for_stage(path: str, stage: str, version: str | None, module: str | None, submodule: str | None = None) -> bool:
    packet = active_packet(path, version, module, submodule)
    relative = packet[2] if packet is not None else ""
    leaf = relative.rsplit("/", 1)[-1]

    if stage == "proposal":
        return packet is not None and leaf == "proposal.md"

    if stage == "design":
        if packet is not None and (leaf == "design.md" or relative.startswith("design/")):
            return True
        return is_module_boundary_sync(path, module)

    if stage == "testing":
        if packet is not None and (
            leaf == "testing.md"
            or leaf == "testplan.yaml"
            or relative.startswith("testing/")
        ):
            return True
        return is_test_artifact(path)

    if stage == "acceptance":
        if packet is not None and leaf == "acceptance.md":
            return True
        return is_review_report(path)

    if stage == "implementation":
        if is_stage_doc_path(path) or is_review_report(path) or is_module_boundary_sync(path, module):
            return False
        if is_test_artifact(path):
            return False
        if path == "AGENTS.md":
            return False
        # Implementation may write only its own admission evidence inside harness/;
        # rules, scripts, checkers, hooks, trigger rules, and pipeline plans are
        # governance surfaces that implementation tasks must not modify.
        if path.startswith("harness/") and not path.startswith("harness/evidence/"):
            return False
        return True

    fail(f"unknown stage: {stage}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--stage", required=True, choices=sorted(STAGES))
    parser.add_argument("--version")
    parser.add_argument("--module")
    parser.add_argument("--submodule")
    parser.add_argument(
        "--change-id",
        action="append",
        dest="change_ids",
        help="implementation stage: bind the diff to these admitted change_id Scope Paths from design.md",
    )
    parser.add_argument("--base", help="compare committed changes from <base>...HEAD instead of the working tree")
    parser.add_argument("--ignore-untracked", action="store_true")
    args = parser.parse_args()

    if args.stage in {"proposal", "design", "testing"} and not (args.version and args.module):
        fail(
            f"--version and --module are required for the {args.stage} stage; "
            "without them any module's documents would pass the scope check"
        )
    if args.change_ids and args.stage != "implementation":
        fail("--change-id applies only to the implementation stage")
    if args.stage == "implementation" and not args.change_ids:
        fail(
            "--version, --module, and --change-id are required for the implementation stage; "
            "without them the diff cannot be bound to the admitted design Scope Paths"
        )
    if args.stage == "implementation" and not (args.version and args.module):
        fail("--version and --module are required for the implementation stage")

    root = Path(args.root)
    scope_paths: list[str] = []
    if args.stage == "implementation":
        scope_paths = design_scope_paths(root, args.version, args.module, args.submodule, args.change_ids)

    paths = changed_paths(root, args.base, include_untracked=not args.ignore_untracked)
    if not paths:
        print("stage-scope-check: no changed files")
        return 0

    violations: list[str] = []
    out_of_scope: list[str] = []
    for path in paths:
        if not allowed_for_stage(path, args.stage, args.version, args.module, args.submodule):
            violations.append(path)
            continue
        if (
            args.stage == "implementation"
            and not path.startswith("harness/evidence/")
            and not in_scope_paths(path, scope_paths)
        ):
            out_of_scope.append(path)
    if violations or out_of_scope:
        if violations:
            print(f"stage-scope-check: {args.stage} stage scope violation", file=sys.stderr)
            for path in violations:
                print(f"  - {path}", file=sys.stderr)
        if out_of_scope:
            print(
                "stage-scope-check: changed paths outside the admitted design Scope Paths "
                f"({', '.join(scope_paths)}); extend design coverage or split the task",
                file=sys.stderr,
            )
            for path in out_of_scope:
                print(f"  - {path}", file=sys.stderr)
        raise SystemExit(1)

    print(f"stage-scope-check: passed ({args.stage}, {len(paths)} changed path(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
