#!/usr/bin/env -S uv run

import subprocess

sn_server = "root@sn.buckyos.ai"


def main() -> int:
    result = subprocess.run(["scp", "./web3_gateway", f"{sn_server}:/opt/web3_bridge/web3_gateway"])
    if result.returncode != 0:
        return result.returncode

    return subprocess.run(
        ["ssh", sn_server, "chmod +x /opt/web3_bridge/web3_gateway"],
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())







