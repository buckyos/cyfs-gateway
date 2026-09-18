"""Run Node Active -> projected BNS HTTP -> NameClient -> Relay without live writes."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import tomllib
import urllib.request

root = Path(__file__).resolve().parents[4]
buckyos = root.parent / "buckyos" / "src"
gateway = root / "src"

with tempfile.TemporaryDirectory(prefix="bns-node-active-") as temp:
    fixture = Path(temp) / "active.json"
    env = dict(os.environ, BUCKYOS_ACTIVE_FIXTURE=str(fixture))
    config = Path(temp) / "local-base.toml"
    base = root.parent / "buckyos-base" / "src"
    patches = ['[patch."https://github.com/buckyos/buckyos-base.git"]']
    for manifest in sorted(base.glob("*/Cargo.toml")):
        package = tomllib.loads(manifest.read_text()).get("package")
        if package:
            patches.append(json.dumps(package["name"]) + " = { path = " + json.dumps(str(manifest.parent)) + " }")
    config.write_text("\n".join(patches))

    def build(cwd, *args):
        output = subprocess.run(
            ["cargo", "test", "--offline", "--config", str(config),
             "--no-run", "--message-format=json", *args],
            cwd=cwd, env=env, check=True, stdout=subprocess.PIPE, text=True)
        executables = {}
        for line in output.stdout.splitlines():
            item = json.loads(line)
            if item.get("reason") == "compiler-artifact" and item.get("executable"):
                executables[item["target"]["name"]] = item["executable"]
        return executables

    node = build(buckyos, "-p", "node_daemon")["node_daemon"]
    binaries = build(gateway, "-p", "bns-server", "-p", "cyfs-gateway-lib", "--lib")
    subprocess.run([node, "active_server::tests::", "--test-threads=1"], env=env, check=True)
    subprocess.run([node, "export_node_active_authority_fixture", "--ignored"], env=env, check=True)
    subprocess.run([binaries["bns_server"], "--test-threads=1"], env=env, check=True)
    with (Path(temp) / "resolver.log").open("w+") as log:
        server = subprocess.Popen(
            [binaries["bns_server"], "serve_node_active_authority_fixture", "--ignored", "--nocapture"],
            env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 30
            while not Path(str(fixture) + ".url").exists():
                if server.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("BNS fixture server did not become ready")
                time.sleep(0.1)
            url = Path(str(fixture) + ".url").read_text()
            with urllib.request.urlopen(url + "/1.0/identifiers/did:bns:ood1.alice", timeout=10) as response:
                envelope = json.load(response)
                assert envelope["didDocument"] == json.loads(fixture.read_text())["device_jwt"]
                print("Device authority metadata:", envelope["didDocumentMetadata"], flush=True)
            subprocess.run(
                [binaries["cyfs_gateway_lib"], "relay_node_active_bns_authority_current", "--ignored", "--nocapture"],
                env=env, check=True, timeout=30)
        finally:
            Path(str(fixture) + ".stop").touch()
            try:
                server.wait(timeout=15)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
            log.seek(0)
            print(log.read())
        if server.returncode:
            raise RuntimeError("BNS fixture server failed")
