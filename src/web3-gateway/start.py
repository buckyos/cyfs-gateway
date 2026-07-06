#!/usr/bin/env -S uv run

import signal
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

MAX_START_ATTEMPTS = 30
STARTUP_STABLE_SECONDS = 5
RETRY_DELAY_SECONDS = 2
BNS_HEALTH_TIMEOUT_SECONDS = 30
BNS_HEALTH_INTERVAL_SECONDS = 0.5
PROCESS_STOP_TIMEOUT_SECONDS = 10

BNS_RPC_ENDPOINT = "http://127.0.0.1:8545"
BNS_CONTRACT_ADDRESS = "0x8464135c8F25Da09e49BC8782676a84730C318bC"
BNS_CHAIN_ID = "31337"
BNS_LISTEN = "127.0.0.1:18080"
BNS_SERVER_URL = "http://127.0.0.1:18080"
BNS_INDEXER_DB = "bns_indexer.sqlite"
BNS_START_BLOCK = "0"
BNS_CONFIRMATIONS = "0"
BNS_INTERVAL_MS = "1000"

children: list[subprocess.Popen] = []


def terminate_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=PROCESS_STOP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def signal_handler(signum: int, _frame) -> None:
    for process in list(children):
        terminate_process(process)
    raise SystemExit(128 + signum)


def run_child(cmd: list[str], cwd: Path) -> int:
    process = subprocess.Popen(cmd, cwd=cwd)
    children.append(process)
    try:
        return process.wait()
    finally:
        if process in children:
            children.remove(process)


BNS_SEED_CONFIG_FILE = "bns_dv_seed.yaml"


def start_bns_server(current_dir: Path) -> subprocess.Popen:
    cmd = [
        str(current_dir / "bns_dv"),
        "serve",
        "--rpc",
        BNS_RPC_ENDPOINT,
        "--contract",
        BNS_CONTRACT_ADDRESS,
        "--chain-id",
        BNS_CHAIN_ID,
        "--db",
        str(current_dir / BNS_INDEXER_DB),
        "--listen",
        BNS_LISTEN,
        "--start-block",
        BNS_START_BLOCK,
        "--confirmations",
        BNS_CONFIRMATIONS,
        "--interval-ms",
        BNS_INTERVAL_MS,
    ]
    # 部署目录带 BNS 种子（make_sn_config.ts --seed-v2 产物）时交给 bns_dv
    # 幂等重放（if_exists=apply_mutations），把种子用户的权威文档上链。
    seed_config = current_dir / BNS_SEED_CONFIG_FILE
    if seed_config.exists():
        cmd += ["--seed-config", str(seed_config)]
    process = subprocess.Popen(cmd, cwd=current_dir)
    children.append(process)
    try:
        wait_for_bns_server(process)
        return process
    except Exception:
        if process in children:
            children.remove(process)
        terminate_process(process)
        raise


def wait_for_bns_server(process: subprocess.Popen) -> None:
    health_url = f"{BNS_SERVER_URL}/health"
    deadline = time.monotonic() + BNS_HEALTH_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"bns_dv exited during startup with code {process.returncode}")
        try:
            with urlopen(health_url, timeout=2) as response:
                if response.status == 200 and response.read().decode("utf-8").strip() == "ok":
                    return
        except (URLError, OSError):
            pass
        time.sleep(BNS_HEALTH_INTERVAL_SECONDS)
    raise RuntimeError(f"bns_dv did not become healthy at {health_url}")


def main() -> int:
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    args = sys.argv[1:]

    current_dir = Path(__file__).resolve().parent
    bns_process = start_bns_server(current_dir)
    config_file = current_dir / "web3_gateway.yaml"
    cmd = [str(current_dir / "web3_gateway"), "--config_file", str(config_file)]
    if "debug" in args:
        cmd.append("--debug")

    try:
        for attempt in range(MAX_START_ATTEMPTS):
            if bns_process.poll() is not None:
                return bns_process.returncode or 1
            started_at = time.monotonic()
            returncode = run_child(cmd, current_dir)
            elapsed = time.monotonic() - started_at
            if "debug" in args or elapsed >= STARTUP_STABLE_SECONDS:
                return returncode
            if attempt == MAX_START_ATTEMPTS - 1:
                return returncode
            time.sleep(RETRY_DELAY_SECONDS)
    finally:
        if bns_process in children:
            children.remove(bns_process)
        terminate_process(bns_process)

    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as err:
        print(f"start.py error: {err}", file=sys.stderr)
        for process in list(children):
            terminate_process(process)
        raise SystemExit(1)
