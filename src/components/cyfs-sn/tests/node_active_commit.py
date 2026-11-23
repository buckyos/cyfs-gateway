"""Node Active commits (buckyos node_daemon) against this repository's SN, without live services.

The SN is unchanged: its SQLite databases, kRPC over HTTP and DNS over UDP. BNS is in
memory, the DNS outside the SN is simulated by node_daemon's test, which also answers the
SN's DoH query for `_pkx`.

Run with buckyos next to cyfs-gateway:
    python3 src/components/cyfs-sn/tests/node_active_commit.py
CARGO_TARGET_DIR and the repositories' .cargo/config.toml apply as usual.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

root = Path(__file__).resolve().parents[4]
buckyos = root.parent / "buckyos" / "src"
gateway = root / "src"


def build(cwd, *args):
    output = subprocess.run(
        ["cargo", "test", "--no-run", "--message-format=json", *args],
        cwd=cwd, check=True, stdout=subprocess.PIPE, text=True)
    executables = {}
    for line in output.stdout.splitlines():
        item = json.loads(line)
        if item.get("reason") == "compiler-artifact" and item.get("executable"):
            executables[item["target"]["name"]] = item["executable"]
    return executables


node = build(buckyos, "-p", "node_daemon")["node_daemon"]
sn = build(gateway, "-p", "cyfs-sn", "--test", "node_active_commit")["node_active_commit"]

with tempfile.TemporaryDirectory(prefix="node-active-sn-") as temp:
    fixture = Path(temp) / "fixture.json"
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        doh = f"http://127.0.0.1:{probe.getsockname()[1]}/resolve"
    env = dict(os.environ, NODE_ACTIVE_SN_FIXTURE=str(fixture), NODE_ACTIVE_DOH=doh)
    with (Path(temp) / "sn.log").open("w+") as log:
        server = subprocess.Popen(
            [sn, "serve_node_active_commit_fixture", "--ignored", "--nocapture"],
            env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 60
            while not fixture.exists():
                if server.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("SN fixture did not become ready")
                time.sleep(0.1)
            subprocess.run(
                [node, "commits_against_an_unchanged_sn", "--ignored", "--nocapture"],
                env=env, check=True, timeout=900)
        except BaseException:
            log.flush()
            log.seek(0)
            print(log.read())
            raise
        finally:
            Path(str(fixture) + ".stop").touch()
            try:
                server.wait(timeout=30)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
    if server.returncode:
        raise RuntimeError("SN fixture failed")
