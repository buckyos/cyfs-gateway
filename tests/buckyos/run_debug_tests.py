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

        def control_matches(action_set, expected_substring=None, exact_value=None):
            def _check(result):
                ctrl = result.get("control_result", {})
                if ctrl.get("type") != "control":
                    return False, f"expected control result, got {ctrl}"
                action = ctrl.get("action", "")
                value = str(ctrl.get("value", ""))
                if action not in action_set:
                    return False, f"expected action in {sorted(action_set)}, got {ctrl}"
                if expected_substring is not None and expected_substring not in value:
                    return False, f"expected value containing '{expected_substring}', got {ctrl}"
                if exact_value is not None and value != exact_value:
                    return False, f"expected value '{exact_value}', got {ctrl}"
                return True, ""

            return _check

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

        elif name == "req_app_public_ok":
            assertions = [control_matches({"return", "exit"}, expected_substring="127.0.0.1:10161")]

        elif name == "req_app_private_no_cookie_fail":
            assertions = [control_matches({"return"}, expected_substring="/oauth/login?redirect_url=")]

        elif name == "req_app_private_cookie_wrong_appid_fail":
            assertions = [control_matches({"return"}, expected_substring="/oauth/login?redirect_url=")]

        elif name == "req_server_node_gateway":
            assertions = [control_matches({"return", "exit"}, expected_substring="127.0.0.1:10160")]

        elif name == "req_service_by_kapi_ok":
            assertions = [control_matches({"return", "exit"}, expected_substring="127.0.0.1:10165")]

        elif name == "req_service_by_host_prefix_ok":
            assertions = [control_matches({"return", "exit"}, expected_substring="127.0.0.1:10262")]

        elif name == "req_service_by_root_host_ok":
            assertions = [control_matches({"return", "exit"}, expected_substring="127.0.0.1:10262")]

        elif name == "req_service_blocked_by_app_fail":
            assertions = [control_matches({"exit"}, exact_value="reject")]

        elif name == "req_stack_zone_gateway_http":
            def check_forward_to_service(result):
                ctrl = result.get("control_result", {})
                if ctrl.get("type") != "control" or ctrl.get("action") != "return":
                    return False, f"expected control return, got {ctrl}"
                val = str(ctrl.get("value", ""))
                if val == "server node_gateway":
                    return True, ""
                return False, f"expected return server node_gateway, got {val}"

            assertions = [check_forward_to_service]

        if test_case(args.binary, args.config, req_file, name, assertions, args.verbose):
            passed += 1
        else:
            failed += 1

    print(f"\nResult: {passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
