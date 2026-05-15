from __future__ import annotations

import ssl
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyfs_gateway_performance.image import image_build_plan, push_plan, write_image_context
from cyfs_gateway_performance.profile import load_profile
from cyfs_gateway_performance.target import run_container_commands
from cyfs_gateway_performance.workload import _http_request, endpoint_for
from cyfs_gateway_performance.model import ScenarioPlan


PROFILE = Path(__file__).resolve().parents[1] / "profiles" / "performance.yaml"


class ImageHttpsStaticTests(unittest.TestCase):
    def test_nginx_context_contains_static_reverse_proxy_and_https_assets(self) -> None:
        plan = load_profile(PROFILE)
        with tempfile.TemporaryDirectory() as temp:
            metadata = write_image_context(plan, "nginx", Path(temp))
            dockerfile = Path(metadata["dockerfile"])
            config_dir = dockerfile.parent / "generated"
            nginx_conf = (config_dir / "default.conf").read_text(encoding="utf-8")

            self.assertIn("listen 80;", nginx_conf)
            self.assertIn("listen 443 ssl;", nginx_conf)
            self.assertIn("root /etc/cyfs-perf/static;", nginx_conf)
            self.assertIn("location /proxy/", nginx_conf)
            self.assertIn("proxy_pass http://127.0.0.1:8080;", nginx_conf)
            self.assertIn("ssl_certificate /etc/cyfs-perf/tls.crt;", nginx_conf)
            self.assertTrue((config_dir / "static" / "index.html").exists())
            self.assertEqual(metadata["tls"]["cert_path"], str(config_dir / "tls.crt"))

            _, commands = image_build_plan(plan, "nginx", Path(temp))
            self.assertTrue(any(command.command[:2] == ("openssl", "req") for command in commands))
            self.assertIn(("docker", "build", "-t", plan.images["nginx"].image_ref), [command.command[:4] for command in commands])
            self.assertIn("EXPOSE 80 443 9080 9443 8080 9000", dockerfile.read_text(encoding="utf-8"))

            push_commands = push_plan(plan, "nginx")
            self.assertEqual(len(push_commands), 1)
            self.assertEqual(push_commands[-1].command, ("docker", "push", plan.images["nginx"].image_ref))

    def test_cyfs_gateway_context_routes_static_reverse_proxy_and_https(self) -> None:
        plan = load_profile(PROFILE)
        with tempfile.TemporaryDirectory() as temp:
            metadata = write_image_context(plan, "cyfs_gateway", Path(temp))
            gateway_yaml = (Path(metadata["dockerfile"]).parent / "generated" / "gateway.yaml").read_text(
                encoding="utf-8"
            )

            self.assertIn("bind: 0.0.0.0:80", gateway_yaml)
            self.assertIn("bind: 0.0.0.0:443", gateway_yaml)
            self.assertIn("protocol: tls", gateway_yaml)
            self.assertIn("cert_path: /etc/cyfs-perf/tls.crt", gateway_yaml)
            self.assertIn('starts-with ${REQ.path} "/proxy/"', gateway_yaml)
            self.assertIn("forward http://127.0.0.1:8080;", gateway_yaml)
            self.assertIn("call-server perf_static_files;", gateway_yaml)
            self.assertIn("root_path: /etc/cyfs-perf/static", gateway_yaml)

    def test_target_run_maps_https_ports(self) -> None:
        plan = load_profile(PROFILE)
        commands = run_container_commands(plan)
        rendered = [" ".join(command.command) for command in commands]

        self.assertTrue(any("-p 18080:80 -p 18443:443" in command for command in rendered))
        self.assertTrue(any("-p 28080:80 -p 28443:443" in command for command in rendered))

    def test_https_workload_uses_unverified_client_context(self) -> None:
        scenario = ScenarioPlan("nginx", "static_http_file", "https", 1, "/index.html")
        self.assertEqual(endpoint_for(scenario), ("127.0.0.1", 18443, True))

        class FakeResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return b"ok"

        with mock.patch("urllib.request.urlopen", return_value=FakeResponse()) as urlopen:
            _http_request("https://127.0.0.1:18443/index.html", 1)

        context = urlopen.call_args.kwargs["context"]
        self.assertIsInstance(context, ssl.SSLContext)
        self.assertFalse(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)


if __name__ == "__main__":
    unittest.main()
