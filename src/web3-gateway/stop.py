#!/usr/bin/env -S uv run

import subprocess


if __name__ == "__main__":
    raise SystemExit(subprocess.run(["killall", "web3_gateway"]).returncode)
