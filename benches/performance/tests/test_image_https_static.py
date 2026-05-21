from __future__ import annotations

import json
import ssl
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyfs_gateway_performance.image import (
    FIXTURE_CARGO_TOML,
    FIXTURE_MAIN_RS,
    REUSEPORT_STATIC_CARGO_TOML,
    REUSEPORT_STATIC_MAIN_RS,
    image_build_plan,
    push_plan,
    write_image_context,
)
from cyfs_gateway_performance.profile import load_profile
from cyfs_gateway_performance.target import run_container_commands
from cyfs_gateway_performance.workload import _http_request, _stream_request, endpoint_for, stream_tls_server_name
from cyfs_gateway_performance.model import ScenarioPlan


PROFILE = Path(__file__).resolve().parents[1] / "profiles" / "performance.yaml"


class ImageHttpsStaticTests(unittest.TestCase):
    def _generated_cmd(self, dockerfile_text: str) -> list[str]:
        for line in dockerfile_text.splitlines():
            if line.startswith("CMD "):
                return json.loads(line.removeprefix("CMD "))
        self.fail("generated Dockerfile did not contain CMD")

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
            dockerfile_text = dockerfile.read_text(encoding="utf-8")
            self.assertIn("ENV HYPER_STATIC_PORT=10080", dockerfile_text)
            self.assertIn("ENV REUSEPORT_STATIC_PORT=10081", dockerfile_text)
            self.assertIn("ENV REUSEPORT_STATIC_ENABLED=1", dockerfile_text)
            self.assertIn("ENV REUSEPORT_STATIC_RUNTIME=tokio", dockerfile_text)
            self.assertIn("ENV STATIC_ROOT=/etc/cyfs-perf/static", dockerfile_text)
            self.assertIn("cyfs-perf-reuseport-static-fixture", dockerfile_text)
            cmd = self._generated_cmd(dockerfile_text)
            self.assertEqual(cmd[:2], ["/bin/sh", "-c"])
            self.assertIn("if [ x$REUSEPORT_STATIC_ENABLED = x1 ]; then cyfs-perf-reuseport-static-fixture & fi;", cmd[2])
            self.assertIn("exec nginx -g 'daemon off;'", cmd[2])
            self.assertIn("EXPOSE 80 443 9080 9443 8080 9000 10080 10081", dockerfile_text)
            self.assertEqual(metadata["packaged_reverse_proxy_fixture"]["ports"]["hyper_static"], 10080)
            self.assertEqual(metadata["packaged_reuseport_static_fixture"]["ports"]["reuseport_static"], 10081)
            self.assertTrue(metadata["packaged_reuseport_static_fixture"]["enabled"])
            self.assertEqual(metadata["packaged_reuseport_static_fixture"]["threads"], "available_parallelism")
            self.assertEqual(metadata["packaged_reuseport_static_fixture"]["runtime"], "tokio")

            push_commands = push_plan(plan, "nginx")
            self.assertEqual(len(push_commands), 1)
            self.assertEqual(push_commands[-1].command, ("docker", "push", plan.images["nginx"].image_ref))

    def test_push_plan_is_empty_when_registry_push_is_disabled(self) -> None:
        plan = replace(load_profile(PROFILE), registry_push=False)

        self.assertEqual(push_plan(plan, "nginx"), [])

    def test_hyper_static_fixture_uses_openat_and_dirserver_style_body_policy(self) -> None:
        self.assertIn('name = "cyfs-perf-reuseport-static-fixture"', REUSEPORT_STATIC_CARGO_TOML)
        self.assertIn('socket2 = "0.6"', REUSEPORT_STATIC_CARGO_TOML)
        self.assertIn('tokio-uring = "0.5"', REUSEPORT_STATIC_CARGO_TOML)
        self.assertIn("socket.set_reuse_port(true)?", REUSEPORT_STATIC_MAIN_RS)
        self.assertIn("tokio::runtime::Builder::new_current_thread()", REUSEPORT_STATIC_MAIN_RS)
        self.assertIn('env::var("REUSEPORT_STATIC_RUNTIME")', REUSEPORT_STATIC_MAIN_RS)
        self.assertIn("tokio_uring::start(async move", REUSEPORT_STATIC_MAIN_RS)
        self.assertIn("tokio_uring::fs::File::from_std(file)", REUSEPORT_STATIC_MAIN_RS)
        self.assertIn("file.read_at(buffer, offset).await", REUSEPORT_STATIC_MAIN_RS)
        self.assertIn("stream.write_all(buffer.slice(..bytes_read)).await", REUSEPORT_STATIC_MAIN_RS)
        self.assertIn("stream_file_with_tokio_uring(stream, opened.file, content_length).await", REUSEPORT_STATIC_MAIN_RS)
        self.assertNotIn("read_file_with_tokio_uring", REUSEPORT_STATIC_MAIN_RS)
        self.assertNotIn("uring_binary_response", REUSEPORT_STATIC_MAIN_RS)
        self.assertIn("thread::available_parallelism()", REUSEPORT_STATIC_MAIN_RS)
        self.assertIn('env::var("REUSEPORT_STATIC_THREADS")', REUSEPORT_STATIC_MAIN_RS)
        self.assertIn("tokio::spawn(async move", REUSEPORT_STATIC_MAIN_RS)
        self.assertIn("TokioTcpListener::from_std(std_listener)?", REUSEPORT_STATIC_MAIN_RS)
        self.assertNotIn("load_static_files", FIXTURE_MAIN_RS)
        self.assertNotIn("tokio::fs::read(&file_path).await", FIXTURE_MAIN_RS)
        self.assertNotIn("tokio::fs::File::open(&file_path).await", FIXTURE_MAIN_RS)
        self.assertNotIn("tokio_uring", FIXTURE_MAIN_RS)
        self.assertNotIn("tokio-uring", FIXTURE_CARGO_TOML)
        self.assertNotIn("tokio-stream", FIXTURE_CARGO_TOML)
        self.assertNotIn("HashMap", FIXTURE_MAIN_RS)
        self.assertNotIn("HyperStaticCache", FIXTURE_MAIN_RS)
        self.assertNotIn("cached_static_body", FIXTURE_MAIN_RS)
        self.assertNotIn("insert_cached_static_body", FIXTURE_MAIN_RS)
        self.assertIn("libc::SYS_openat2", FIXTURE_MAIN_RS)
        self.assertIn("root_dir_file.as_raw_fd()", FIXTURE_MAIN_RS)
        self.assertIn("tokio::fs::File::from_std(file)", FIXTURE_MAIN_RS)
        self.assertIn("HYPER_STATIC_SMALL_FILE_INLINE_LIMIT", FIXTURE_MAIN_RS)
        self.assertIn("HYPER_STATIC_MIN_STREAM_BUFFER_SIZE", FIXTURE_MAIN_RS)
        self.assertIn("HYPER_STATIC_MAX_STREAM_BUFFER_SIZE", FIXTURE_MAIN_RS)
        self.assertIn("file.read_to_end(&mut body).await?", FIXTURE_MAIN_RS)
        self.assertIn("ReaderStream::with_capacity(file, hyper_static_stream_buffer_size(content_length))", FIXTURE_MAIN_RS)
        self.assertIn("libc::SYS_openat2", REUSEPORT_STATIC_MAIN_RS)
        self.assertIn("root_dir_file.as_raw_fd()", REUSEPORT_STATIC_MAIN_RS)
        self.assertIn("tokio::fs::File::from_std(opened.file)", REUSEPORT_STATIC_MAIN_RS)

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
            self.assertIn("etag: true", gateway_yaml)
            self.assertNotIn("open_file_cache:", gateway_yaml)
            self.assertNotIn("open_file_cache_min_uses:", gateway_yaml)
            dockerfile_text = Path(metadata["dockerfile"]).read_text(encoding="utf-8")
            cmd = self._generated_cmd(dockerfile_text)
            self.assertEqual(cmd[:2], ["/bin/sh", "-c"])
            self.assertIn("if [ x$REUSEPORT_STATIC_ENABLED = x1 ]; then cyfs-perf-reuseport-static-fixture & fi;", cmd[2])
            self.assertIn("exec cyfs_gateway --config_file /etc/cyfs-perf/gateway.yaml", cmd[2])

    def test_target_run_maps_https_ports(self) -> None:
        plan = load_profile(PROFILE)
        commands = run_container_commands(plan)
        rendered = [" ".join(command.command) for command in commands]

        self.assertTrue(any("-p 18080:80 -p 18443:443" in command for command in rendered))
        self.assertTrue(any("-p 28080:80 -p 28443:443" in command for command in rendered))
        self.assertTrue(any("-p 18180:10080" in command for command in rendered))
        self.assertTrue(any("-p 28180:10080" in command for command in rendered))
        self.assertFalse(any("--security-opt seccomp=unconfined" in command for command in rendered))

    def test_https_workload_uses_unverified_client_context(self) -> None:
        scenario = ScenarioPlan("nginx", "static_http_file", "https", 1, "/index.html")
        self.assertEqual(endpoint_for(scenario), ("127.0.0.1", 18443, True))
        self.assertEqual(
            endpoint_for(ScenarioPlan("nginx_hyper", "static_http_file", "http", 1, "/index.html")),
            ("127.0.0.1", 18180, False),
        )
        self.assertEqual(
            endpoint_for(ScenarioPlan("nginx_reuseport_static", "static_http_file", "http", 1, "/index.html")),
            ("127.0.0.1", 18181, False),
        )

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

    def test_stream_tls_workload_uses_profile_common_name_for_sni(self) -> None:
        plan = load_profile(PROFILE)
        self.assertEqual(stream_tls_server_name(plan), "perf.local")

        class FakeSocket:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def settimeout(self, _timeout):
                pass

            def sendall(self, _payload):
                pass

            def recv(self, _size):
                return b"cyfs-performance-stream-payload"

            def close(self):
                pass

        class FakeContext:
            def wrap_socket(self, raw, server_hostname=None):
                self.raw = raw
                self.server_hostname = server_hostname
                return raw

        context = FakeContext()
        raw = FakeSocket()
        with mock.patch("socket.create_connection", return_value=raw), mock.patch(
            "ssl._create_unverified_context",
            return_value=context,
        ):
            _stream_request("127.0.0.1", 29443, 1, True, stream_tls_server_name(plan))

        self.assertEqual(context.server_hostname, "perf.local")


if __name__ == "__main__":
    unittest.main()
