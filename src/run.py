#!/usr/bin/env -S uv run

import subprocess
import sys
from pathlib import Path


def main() -> int:
    config_file = sys.argv[1] if len(sys.argv) > 1 else "cyfs_gateway.json"
    rootfs_dir = Path(__file__).resolve().parent / "rootfs"
    config_path = rootfs_dir / "etc" / config_file

    print(f"run cyfs_gateway --config_file {config_path}")
    return subprocess.run(
        ["bin/cyfs_gateway/cyfs_gateway", "--config_file", str(config_path)],
        cwd=rootfs_dir,
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
