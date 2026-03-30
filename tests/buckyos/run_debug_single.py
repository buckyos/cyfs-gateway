#!/usr/bin/env -S uv run
"""
Run a single process chain debug test (manual / ad-hoc).

Usage:
    uv run run_debug_single.py REQ_FILE [--id RULE_ID] [--config PATH] [--repeat N]

Examples:
    uv run run_debug_single.py req_stack_node_rtcp.json
    uv run run_debug_single.py req_server_node_gateway.json --id server:node_gateway:main
    uv run run_debug_single.py req_zone_http_selector.json --config cyfs_gateway.yaml
    uv run run_debug_single.py req_stack_zone_gateway_http.json --repeat 3
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


def main():
    parser = argparse.ArgumentParser(description="Run single process chain debug")
    parser.add_argument("req_file", type=Path, help="Request JSON file (e.g. req_xxx.json)")
    parser.add_argument("--id", "-i", help="Rule id override (otherwise use id from req_file)")
    parser.add_argument("--config", "-c", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--binary", "-b", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--repeat", "-r", type=int, default=1, help="Repeat count in one debug process")
    args = parser.parse_args()

    req_path = args.req_file if args.req_file.is_absolute() else SCRIPT_DIR / args.req_file
    if not req_path.exists():
        print(f"Error: req_file not found: {req_path}")
        sys.exit(1)
    if not args.binary.exists():
        print(f"Error: binary not found: {args.binary}")
        sys.exit(1)
    if not args.config.exists():
        print(f"Error: config not found: {args.config}")
        sys.exit(1)
    if args.repeat <= 0:
        print("Error: --repeat must be greater than 0")
        sys.exit(1)

    cmd = [
        str(args.binary),
        "debug",
        "--config_file", str(args.config),
        "--req_file", str(req_path),
        
    ]
    if args.id:
        cmd.extend(["--id", args.id])
    if args.repeat != 1:
        cmd.extend(["--repeat", str(args.repeat)])

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
    )

    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        print(result.stdout)
        sys.exit(result.returncode)

    # Print full output (echo + JSON)
    print(result.stdout)


if __name__ == "__main__":
    main()
