#!/usr/bin/env -S uv run

import subprocess
import sys
from pathlib import Path


def main() -> int:
    args = sys.argv
    print(f"args: {args}")

    current_dir = Path(__file__).resolve().parent
    config_file = current_dir / "web3_gateway.yaml"
    cmd = [str(current_dir / "web3_gateway"), "--config_file", str(config_file)]
    if "debug" in args:
        cmd.append("--debug")

    result = subprocess.run(cmd)
    if result.returncode == 0:
        print("web3_gateway service started")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
