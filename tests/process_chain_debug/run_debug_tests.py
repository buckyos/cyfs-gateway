#!/usr/bin/env -S uv run
"""
Process chain debug test runner.

Runs cyfs_gateway debug subcommand against req_file test cases,
using a specific cyfs-gateway config. Each test case is a JSON
req_file that defines input collections, target chain id, and
expected output variables.

Usage:
    uv run run_debug_tests.py [--binary PATH] [--config PATH]

Binary default: ../../src/rootfs/bin/cyfs-gateway/cyfs_gateway
Config default: config.yaml (in this directory)
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


# Default paths relative to this script's directory
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent
DEFAULT_BINARY = PROJECT_ROOT / "src" / "rootfs" / "bin" / "cyfs-gateway" / "cyfs_gateway"
DEFAULT_CONFIG = SCRIPT_DIR / "config.yaml"


def run_debug(binary: Path, config: Path, req_file: Path, rule_id: str | None = None) -> dict:
    """Run cyfs_gateway debug and return parsed JSON result."""
    cmd = [
        str(binary),
        "debug",
        "--config_file", str(config),
        "--req_file", str(req_file),
    ]
    if rule_id:
        cmd.extend(["--id", rule_id])

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"cyfs_gateway debug failed (exit {result.returncode})\n"
            f"stderr: {result.stderr}\nstdout: {result.stdout}"
        )

    print(result.stdout)

    # Output may contain echo/stdout before the final JSON result.
    # Extract the top-level JSON object (first { to matching final }).
    out = result.stdout.strip()
    start = out.find("{")
    if start < 0:
        raise RuntimeError("No JSON object in cyfs_gateway debug output")
    json_str = out[start:].strip()
    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Failed to parse debug output as JSON: {e}\nOutput: {result.stdout}")


def test_case(
    binary: Path,
    config: Path,
    req_file: Path,
    name: str,
    assertions: list[callable] | None = None,
) -> bool:
    """
    Run a single test case. Returns True if pass, False if fail.
    assertions: list of (result) -> (passed: bool, message: str)
    """
    try:
        result = run_debug(binary, config, req_file)
    except Exception as e:
        print(f"  FAIL {name}: {e}")
        return False

    if assertions:
        for fn in assertions:
            passed, msg = fn(result)
            if not passed:
                print(f"  FAIL {name}: {msg}")
                return False

    print(f"  PASS {name}")
    return True


def main():
    parser = argparse.ArgumentParser(description="Run process chain debug tests")
    parser.add_argument(
        "--binary",
        type=Path,
        default=DEFAULT_BINARY,
        help="Path to cyfs_gateway binary",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG,
        help="Path to cyfs-gateway config file",
    )
    parser.add_argument(
        "--req-dir",
        type=Path,
        default=SCRIPT_DIR,
        help="Directory containing req_*.json files",
    )
    args = parser.parse_args()

    if not args.binary.exists():
        print(f"Error: binary not found: {args.binary}")
        print("Build with: cd src && cargo build -p cyfs_gateway")
        sys.exit(1)

    if not args.config.exists():
        print(f"Error: config not found: {args.config}")
        sys.exit(1)

    req_files = sorted(args.req_dir.glob("req_*.json"))
    if not req_files:
        print(f"No req_*.json files in {args.req_dir}")
        sys.exit(1)

    print(f"Binary: {args.binary}")
    print(f"Config: {args.config}")
    print(f"Test cases: {len(req_files)}")
    print()

    passed = 0
    failed = 0

    for req_file in req_files:
        name = req_file.stem
        assertions = None

        if name == "req_global_chain":
            def check_debug_ran(result):
                out = result.get("output", {}).get("REQ", {})
                if isinstance(out, dict) and out.get("debug_ran") == "true":
                    return True, ""
                return False, f"expected REQ.debug_ran='true', got {out}"

            assertions = [check_debug_ran]

        elif name == "req_echo_and_return":
            def check_control_accept(result):
                ctrl = result.get("control_result", {})
                if ctrl.get("type") == "control" and ctrl.get("action") == "return":
                    return True, ""
                return False, f"expected control return, got {ctrl}"

            assertions = [check_control_accept]

        if test_case(args.binary, args.config, req_file, name, assertions):
            passed += 1
        else:
            failed += 1

    print()
    print(f"Result: {passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
