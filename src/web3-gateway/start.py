#!/usr/bin/env -S uv run

import subprocess
import sys
import time
from pathlib import Path

MAX_START_ATTEMPTS = 30
STARTUP_STABLE_SECONDS = 5
RETRY_DELAY_SECONDS = 2


def main() -> int:
    args = sys.argv[1:]

    current_dir = Path(__file__).resolve().parent
    config_file = current_dir / "web3_gateway.yaml"
    cmd = [str(current_dir / "web3_gateway"), "--config_file", str(config_file)]
    if "debug" in args:
        cmd.append("--debug")

    for attempt in range(MAX_START_ATTEMPTS):
        started_at = time.monotonic()
        result = subprocess.run(cmd)
        elapsed = time.monotonic() - started_at
        if "debug" in args or elapsed >= STARTUP_STABLE_SECONDS:
            return result.returncode
        if attempt == MAX_START_ATTEMPTS - 1:
            return result.returncode
        time.sleep(RETRY_DELAY_SECONDS)

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
