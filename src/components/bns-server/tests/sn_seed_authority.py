import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.request

root = Path(__file__).resolve().parents[4]
gateway = root / "src"

with tempfile.TemporaryDirectory(prefix="bns-sn-seed-") as temp:
    fixture = Path(temp) / "seed.json"
    env = dict(os.environ, BUCKYOS_SN_SEED_FIXTURE=str(fixture),
               BUCKYOS_ACTIVE_FIXTURE=str(fixture))
    subprocess.run(
        [env.get("DENO_BIN", "deno"), "test", "-A", "--filter",
         "BNS seed publishes full device documents separately from TXT mini JWTs",
         "make_sn_config_test.ts"],
        cwd=gateway, env=env, check=True)
    expected = json.loads(fixture.read_text())
    slots = {document["doc_type"]: document["content"]
             for document in expected["documents"] if document["name"] == "alice"}
    assert slots["ood1"] == expected["device_jwt"]
    assert slots["zone"] == expected["zone_jwt"]

    output = subprocess.run(
        ["cargo", "test", "--locked", "--release", "--no-run", "--message-format=json",
         "-p", "bns-server", "-p", "cyfs-gateway-lib", "--lib"],
        cwd=gateway, env=env, check=True, stdout=subprocess.PIPE, text=True)
    binaries = {}
    for line in output.stdout.splitlines():
        item = json.loads(line)
        if item.get("reason") == "compiler-artifact" and item.get("executable"):
            binaries[item["target"]["name"]] = item["executable"]

    with (Path(temp) / "resolver.log").open("w+") as log:
        server = subprocess.Popen(
            [binaries["bns_server"], "serve_node_active_authority_fixture",
             "--ignored", "--nocapture"],
            env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 30
            while not Path(str(fixture) + ".url").exists():
                if server.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("BNS seed fixture server did not become ready")
                time.sleep(0.1)
            url = Path(str(fixture) + ".url").read_text()
            with urllib.request.urlopen(
                url + "/1.0/identifiers/did:bns:ood1.alice", timeout=10,
            ) as response:
                envelope = json.load(response)
                assert envelope["didDocument"] == expected["device_jwt"]
                metadata = envelope["didDocumentMetadata"]["buckyos"]
                assert metadata["sourceName"] == "alice"
                assert metadata["sourceDocType"] == "ood1"
                assert metadata["sourceContentHash"].removeprefix("0x") == hashlib.sha256(
                    expected["device_jwt"].encode()).hexdigest()
                assert metadata["registryVersion"] == 10
                assert metadata["documentStatus"] == "active"
                print("Generated seed authority metadata:", metadata, flush=True)
            subprocess.run(
                [binaries["cyfs_gateway_lib"], "relay_node_active_bns_authority_current",
                 "--ignored", "--nocapture"],
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
            raise RuntimeError("BNS seed fixture server failed")
