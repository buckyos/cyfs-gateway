#!/usr/bin/env python3
"""Run every repo-wide harness check in one command.

This is the single enforcement entrypoint for CI and the pre-commit hook, so
the always-true harness invariants do not depend on an agent remembering to
run individual checkers:

- `harness-self-check.py` validates scaffold completeness.
- `schema-check.py` validates every discovered module and submodule packet,
  including approval provenance for approved documents.

Stage- and task-specific checks (admission evidence, stage scope, acceptance
reports, pipeline plans) still run inside their owning tasks; they need task
context this driver does not have.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def run(cmd: list[str]) -> bool:
    print(f"check-all: running {' '.join(cmd)}")
    return subprocess.run(cmd).returncode == 0


def discover_packets(root: Path) -> list[tuple[str, str, str | None]]:
    packets: list[tuple[str, str, str | None]] = []
    versions = root / "docs" / "versions"
    if not versions.is_dir():
        return packets
    for proposal in sorted(versions.glob("*/modules/*/proposal.md")):
        version, module = proposal.parts[-4], proposal.parts[-2]
        if module.startswith("_"):
            continue
        packets.append((version, module, None))
    for proposal in sorted(versions.glob("*/modules/*/*/proposal.md")):
        version, module, submodule = proposal.parts[-5], proposal.parts[-3], proposal.parts[-2]
        if module.startswith("_") or submodule.startswith("_"):
            continue
        packets.append((version, module, submodule))
    return packets


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    args = parser.parse_args()

    root = Path(args.root)
    scripts = root / "harness" / "scripts"
    failed = 0

    self_check = scripts / "harness-self-check.py"
    if self_check.exists():
        if not run([sys.executable, str(self_check), "--root", str(root)]):
            failed += 1
    else:
        print(f"check-all: missing {self_check}", file=sys.stderr)
        failed += 1

    packets = discover_packets(root)
    if not packets:
        print("check-all: no module packets discovered under docs/versions/")
    for version, module, submodule in packets:
        cmd = [
            sys.executable,
            str(scripts / "schema-check.py"),
            "--root",
            str(root),
            "--version",
            version,
            "--module",
            module,
        ]
        if submodule:
            cmd += ["--submodule", submodule]
        if not run(cmd):
            failed += 1

    if failed:
        print(f"check-all: FAILED ({failed} check(s) failed)", file=sys.stderr)
        return 1
    print("check-all: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
