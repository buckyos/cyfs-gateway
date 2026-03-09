#!/usr/bin/env python3
"""
Process chain debug tests for buckyos real config.

Runs cyfs_gateway debug against req_*.json in this directory,
using tests/buckyos/cyfs_gateway.yaml (includes boot, node, post, user).

Usage:
    python run_debug_tests.py [--binary PATH] [--config PATH]
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent
DEFAULT_BINARY = PROJECT_ROOT / "src" / "rootfs" / "bin" / "cyfs-gateway" / "cyfs_gateway"
DEFAULT_CONFIG = SCRIPT_DIR / "cyfs_gateway.yaml"


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
    assertions: list | None = None,
    verbose: bool = False,
) -> bool:
    """Run a single test case. Returns True if pass, False if fail."""
    try:
        result = run_debug(binary, config, req_file)
    except Exception as e:
        print(f"  FAIL {name}: {e}")
        return False

    if verbose:
        print(json.dumps(result, indent=2, ensure_ascii=False))

    if assertions:
        for fn in assertions:
            passed, msg = fn(result)
            if not passed:
                print(f"  FAIL {name}: {msg}")
                return False

    print(f"  PASS {name}")
    return True


def main():
    parser = argparse.ArgumentParser(description="Run buckyos process chain debug tests")
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--req-dir", type=Path, default=SCRIPT_DIR)
    parser.add_argument("-v", "--verbose", action="store_true", help="Print full result JSON")
    args = parser.parse_args()

    if not args.binary.exists():
        print(f"Error: binary not found: {args.binary}")
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
    print(f"Test cases: {len(req_files)}\n")

    passed = 0
    failed = 0

    for req_file in req_files:
        name = req_file.stem
        assertions = None

        if name == "req_stack_node_rtcp":
            def check_forward_return(result):
                ctrl = result.get("control_result", {})
                if ctrl.get("type") != "control":
                    return False, f"expected control result, got {ctrl}"
                val = ctrl.get("value", "")
                action = ctrl.get("action", "")
                if action == "return" and "tcp://" in val and "192.168.1.100" in val:
                    return True, ""
                if action == "return" and val == "":
                    return True, ""
                return False, f"expected forward tcp url or passthrough, got {ctrl}"

            assertions = [check_forward_return]

        elif name == "req_server_node_gateway":
            def check_forward_system_config(result):
                ctrl = result.get("control_result", {})
                if ctrl.get("type") != "control":
                    return False, f"expected control result, got {ctrl}"
                val = ctrl.get("value", "")
                action = ctrl.get("action", "")
                if action == "return" and "127.0.0.1:3200" in val:
                    return True, ""
                if action == "return" and val == "":
                    return True, ""
                return False, f"expected forward to 3200 or passthrough, got {ctrl}"

            assertions = [check_forward_system_config]

        elif name == "req_stack_zone_gateway_http":
            def check_forward_to_service(result):
                ctrl = result.get("control_result", {})
                if ctrl.get("type") != "control" or ctrl.get("action") != "exit":
                    return False, f"expected control exit, got {ctrl}"
                val = str(ctrl.get("value", ""))
                if "forward" in val and ("127.0.0.1:10162" in val or "127.0.0.1:10163" in val):
                    return True, ""
                return False, f"expected forward to service upstream, got {val}"

            assertions = [check_forward_to_service]

        if test_case(args.binary, args.config, req_file, name, assertions, args.verbose):
            passed += 1
        else:
            failed += 1

    print(f"\nResult: {passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
