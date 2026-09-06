#!/usr/bin/env -S uv run

import os
import shutil
import subprocess
import sys
from pathlib import Path


DEVKIT_SPEC = "buckyos-devkit @ git+https://github.com/buckyos/buckyos-devkit.git@main"


def _command_names(command: str) -> list[str]:
    if os.name == "nt":
        return [f"{command}.exe", f"{command}.cmd", f"{command}.bat", command]
    return [command]


def _find_command(command: str) -> str | None:
    for name in _command_names(command):
        path = shutil.which(name)
        if path is not None:
            return path

    bin_dir = Path(sys.executable).parent
    for name in _command_names(command):
        candidate = bin_dir / name
        if candidate.exists():
            return str(candidate)

    return None


def main() -> int:
    build_executable = _find_command("buckyos-build")
    if build_executable is None:
        print("buckyos-build not found in the current environment")
        print("Install buckyos-devkit first, or use the repo uv runtime:")
        print("  cd src && uv run ./build.py [args]")
        print(f'  python3 -m pip install -U "{DEVKIT_SPEC}"')
        return 1

    result = subprocess.run([build_executable] + sys.argv[1:], env=os.environ.copy()).returncode
    if result != 0:
        print(f"buckyos-build failed with return code {result}")
        return result

    update_executable = _find_command("buckyos-update")
    if update_executable is None:
        print("buckyos-update not found in the current environment")
        print(f'Please ensure "{DEVKIT_SPEC}" is installed correctly.')
        return 1

    result = subprocess.run([update_executable], env=os.environ.copy()).returncode
    if result != 0:
        print(f"buckyos-update failed with return code {result}")
        return result

    print("buckyos-build and buckyos-update completed successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

