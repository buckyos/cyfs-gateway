from __future__ import annotations

import contextlib
import csv
import io
import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyfs_gateway_performance import cli
from cyfs_gateway_performance.executor import CommandResult, write_command_log
from cyfs_gateway_performance.image import cyfs_gateway_source, source_build_commands, write_image_context
from cyfs_gateway_performance.metrics import container_name_for_candidate, run_with_resource_metrics
from cyfs_gateway_performance.model import CommandPlan, ConfigError, ScenarioPlan
from cyfs_gateway_performance.profile import load_profile
from cyfs_gateway_performance.report import build_result, write_reports
from cyfs_gateway_performance.scenario import expand_scenarios
from cyfs_gateway_performance.target import container_readiness_commands, preflight, pull_commands, run_container_commands
from cyfs_gateway_performance.workload import endpoint_for, run_fixed_rate_workload


PROFILE = Path(__file__).resolve().parents[1] / "profiles" / "performance.yaml"


class RuntimeBehaviorTests(unittest.TestCase):
    def _command_result(self, command, returncode: int) -> CommandResult:
        return CommandResult(
            description=command.description,
            command=list(command.command),
            cwd=command.cwd,
            returncode=returncode,
            stdout="",
            stderr="",
            started_at=1.0,
            ended_at=1.1,
        )

    def test_command_result_and_log_include_readable_times(self) -> None:
        command = CommandPlan("test command", ("echo", "ok"))
        result = self._command_result(command, 0)
        result_dict = result.as_dict()

        self.assertIn("started_at_text", result_dict)
        self.assertIn("ended_at_text", result_dict)
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch("cyfs_gateway_performance.executor.current_time_text", return_value="2026-05-19T12:00:00+08:00"):
                log_path = write_command_log(Path(temp), "command.log", result)
            log = Path(log_path).read_text(encoding="utf-8")

        self.assertIn("log_written_at: 2026-05-19T12:00:00+08:00", log)
        self.assertIn("started_at:", log)
        self.assertIn("ended_at:", log)

    def test_stream_context_ports_and_candidate_endpoints_are_wired(self) -> None:
        plan = load_profile(PROFILE)
        with tempfile.TemporaryDirectory() as temp:
            nginx = write_image_context(plan, "nginx", Path(temp))
            cyfs = write_image_context(plan, "cyfs_gateway", Path(temp))
            nginx_dir = Path(nginx["dockerfile"]).parent / "generated"
            cyfs_dir = Path(cyfs["dockerfile"]).parent / "generated"

            nginx_conf = (nginx_dir / "nginx.conf").read_text(encoding="utf-8")
            gateway_yaml = (cyfs_dir / "gateway.yaml").read_text(encoding="utf-8")

        self.assertIn("listen 9080;", nginx_conf)
        self.assertIn("listen 9443 ssl;", nginx_conf)
        self.assertIn("proxy_pass 127.0.0.1:10080;", nginx_conf)
        self.assertIn("bind: 0.0.0.0:9080", gateway_yaml)
        self.assertIn("bind: 0.0.0.0:9443", gateway_yaml)
        self.assertIn('return "forward tcp:///127.0.0.1:10080";', gateway_yaml)

        rendered = [" ".join(command.command) for command in run_container_commands(plan)]
        self.assertTrue(any("-p 19080:9080 -p 19443:9443" in command for command in rendered))
        self.assertTrue(any("-p 29080:9080 -p 29443:9443" in command for command in rendered))
        self.assertTrue(any("-p 18180:10080" in command for command in rendered))
        self.assertTrue(any("-p 28180:10080" in command for command in rendered))
        self.assertTrue(any("-p 18181:10081" in command for command in rendered))
        self.assertTrue(any("-p 28181:10081" in command for command in rendered))
        self.assertTrue(any("-e REUSEPORT_STATIC_RUNTIME=tokio" in command for command in rendered))
        self.assertTrue(any("-e REUSEPORT_STATIC_ENABLED=1" in command for command in rendered))
        self.assertFalse(any("--security-opt seccomp=unconfined" in command for command in rendered))
        self.assertEqual(
            endpoint_for(ScenarioPlan("nginx", "stream_reverse_proxy", "http", 1, "/index.html")),
            ("127.0.0.1", 19080, False),
        )
        self.assertEqual(
            endpoint_for(ScenarioPlan("cyfs_gateway", "stream_reverse_proxy", "https", 1, "/payload.bin")),
            ("127.0.0.1", 29443, True),
        )
        self.assertEqual(
            endpoint_for(ScenarioPlan("nginx_hyper", "static_http_file", "http", 1, "/payload.bin")),
            ("127.0.0.1", 18180, False),
        )
        self.assertEqual(
            endpoint_for(ScenarioPlan("cyfs_gateway_hyper", "static_http_file", "http", 1, "/payload.bin")),
            ("127.0.0.1", 28180, False),
        )
        self.assertEqual(
            endpoint_for(ScenarioPlan("nginx_reuseport_static", "static_http_file", "http", 1, "/payload.bin")),
            ("127.0.0.1", 18181, False),
        )
        self.assertEqual(
            endpoint_for(ScenarioPlan("cyfs_gateway_reuseport_static", "static_http_file", "http", 1, "/payload.bin")),
            ("127.0.0.1", 28181, False),
        )
        self.assertEqual(container_name_for_candidate("nginx_hyper"), "cyfs-perf-nginx")
        self.assertEqual(container_name_for_candidate("cyfs_gateway_hyper"), "cyfs-perf-cyfs_gateway")
        self.assertEqual(container_name_for_candidate("nginx_reuseport_static"), "cyfs-perf-nginx")
        self.assertEqual(container_name_for_candidate("cyfs_gateway_reuseport_static"), "cyfs-perf-cyfs_gateway")

    def test_tokio_uring_reuseport_static_adds_docker_seccomp_unconfined(self) -> None:
        text = PROFILE.read_text(encoding="utf-8").replace("runtime: tokio", "runtime: tokio_uring")
        with tempfile.TemporaryDirectory() as temp:
            profile = Path(temp) / "profile.yaml"
            profile.write_text(text, encoding="utf-8")
            plan = load_profile(profile)
            rendered = [" ".join(command.command) for command in run_container_commands(plan)]

        self.assertTrue(any("--security-opt seccomp=unconfined" in command for command in rendered))

    def test_tokio_custom_reuseport_static_keeps_default_docker_seccomp(self) -> None:
        text = PROFILE.read_text(encoding="utf-8").replace("runtime: tokio", "runtime: tokio_custom")
        with tempfile.TemporaryDirectory() as temp:
            profile = Path(temp) / "profile.yaml"
            profile.write_text(text, encoding="utf-8")
            plan = load_profile(profile)
            rendered = [" ".join(command.command) for command in run_container_commands(plan)]

        self.assertTrue(any("-e REUSEPORT_STATIC_RUNTIME=tokio_custom" in command for command in rendered))
        self.assertFalse(any("--security-opt seccomp=unconfined" in command for command in rendered))

    def test_disabled_tokio_uring_reuseport_static_keeps_default_docker_seccomp(self) -> None:
        text = PROFILE.read_text(encoding="utf-8").replace("enabled: true", "enabled: false", 1)
        text = text.replace("runtime: tokio", "runtime: tokio_uring")
        with tempfile.TemporaryDirectory() as temp:
            profile = Path(temp) / "profile.yaml"
            profile.write_text(text, encoding="utf-8")
            plan = load_profile(profile)
            rendered = [" ".join(command.command) for command in run_container_commands(plan)]

        self.assertFalse(any("--security-opt seccomp=unconfined" in command for command in rendered))

    def test_fixed_rate_workload_uses_warmup_and_measured_windows(self) -> None:
        plan = load_profile(PROFILE)
        plan = replace(plan, load=replace(plan.load, duration_seconds=1, warmup_seconds=1, concurrency=2, rates=(2,)))
        scenario = ScenarioPlan("nginx", "static_http_file", "http", 2, "/index.html")

        def fake_run(command, **kwargs):
            if command[1] == "attack":
                return mock.Mock(returncode=0, stdout=b"vegeta-binary-results", stderr=b"")
            return mock.Mock(
                returncode=0,
                stdout=b'{"code":200,"latency":3000000}\n{"code":200,"latency":3000000}\n',
                stderr=b"",
            )

        with mock.patch("cyfs_gateway_performance.workload.ensure_vegeta", return_value=(Path("/tmp/vegeta"), {})), mock.patch(
            "cyfs_gateway_performance.workload.subprocess.run",
            side_effect=fake_run,
        ) as run_command:
            result = run_fixed_rate_workload(plan, scenario)

        attack_commands = [call.args[0] for call in run_command.call_args_list if call.args[0][1] == "attack"]
        self.assertEqual(len(attack_commands), 2)
        self.assertIn("-rate", attack_commands[0])
        self.assertIn("2/s", attack_commands[0])
        self.assertIn("-workers", attack_commands[0])
        self.assertIn("2", attack_commands[0])
        self.assertIn("-keepalive=false", attack_commands[0])
        self.assertIn("-max-body", attack_commands[0])
        self.assertIn("0", attack_commands[0])
        self.assertEqual(result["warmup_attempted"], 2)
        self.assertEqual(result["warmup_actual_attempted"], 2)
        self.assertEqual(result["attempted"], 2)
        self.assertEqual(result["actual_attempted"], 2)
        self.assertEqual(result["warmup_success"], 2)
        self.assertEqual(result["success"], 2)
        self.assertEqual(result["latency_ms"]["avg"], 3.0)
        self.assertEqual(result["concurrency"], 2)
        self.assertEqual(result["connection_reuse"], "new_connection")
        self.assertEqual(result["engine"], "vegeta")

    def test_https_fixed_rate_workload_uses_vegeta_with_sni_connect_mapping(self) -> None:
        plan = load_profile(PROFILE)
        plan = replace(plan, load=replace(plan.load, duration_seconds=1, warmup_seconds=0, concurrency=1, rates=(1,)))
        scenario = ScenarioPlan("cyfs_gateway", "stream_reverse_proxy", "https", 1, "/payload.bin")

        def fake_run(command, **kwargs):
            if command[1] == "attack":
                return mock.Mock(returncode=0, stdout=b"vegeta-binary-results", stderr=b"")
            return mock.Mock(returncode=0, stdout=b'{"code":200,"latency":4000000}\n', stderr=b"")

        with mock.patch("cyfs_gateway_performance.workload.ensure_vegeta", return_value=(Path("/tmp/vegeta"), {})), mock.patch(
            "cyfs_gateway_performance.workload.subprocess.run",
            side_effect=fake_run,
        ) as run_command:
            result = run_fixed_rate_workload(plan, scenario)

        attack_commands = [call.args[0] for call in run_command.call_args_list if call.args[0][1] == "attack"]
        self.assertEqual(len(attack_commands), 1)
        self.assertIn("-insecure", attack_commands[0])
        self.assertIn("-connect-to", attack_commands[0])
        self.assertIn("perf.local:29443:127.0.0.1:29443", attack_commands[0])
        self.assertIn(b"GET https://perf.local:29443/payload.bin\n", run_command.call_args_list[0].kwargs["input"])
        self.assertEqual(result["engine"], "vegeta")
        self.assertEqual(result["success"], 1)

    def test_profile_expands_connection_reuse_modes_in_scenario_matrix(self) -> None:
        plan = load_profile(PROFILE)
        scenarios = expand_scenarios(plan)
        reuse_modes = {scenario.connection_reuse for scenario in scenarios}
        equivalent = [
            scenario
            for scenario in scenarios
            if scenario.candidate == "nginx"
            and scenario.scenario == "static_http_file"
            and scenario.protocol == "http"
            and scenario.payload == "/index.html"
            and scenario.rate == 100
        ]

        self.assertEqual(
            set(plan.candidates),
            {
                "nginx",
                "cyfs_gateway",
                "nginx_hyper",
                "cyfs_gateway_hyper",
                "nginx_reuseport_static",
                "cyfs_gateway_reuseport_static",
            },
        )
        self.assertEqual(plan.load.connection_reuse_modes, ("new_connection", "reuse_connection"))
        self.assertEqual(reuse_modes, {"new_connection", "reuse_connection"})
        self.assertEqual({scenario.connection_reuse for scenario in equivalent}, {"new_connection", "reuse_connection"})
        self.assertEqual(
            {
                scenario.payload
                for scenario in scenarios
                if scenario.candidate == "nginx"
                and scenario.scenario == "http_reverse_proxy"
                and scenario.protocol == "http"
                and scenario.rate == 100
                and scenario.connection_reuse == "new_connection"
            },
            {"/proxy/payload"},
        )
        self.assertEqual(
            {
                (scenario.protocol, scenario.payload)
                for scenario in scenarios
                if scenario.candidate == "nginx"
                and scenario.scenario == "stream_reverse_proxy"
                and scenario.rate == 100
                and scenario.connection_reuse == "new_connection"
            },
            {
                ("http", "/index.html"),
                ("http", "/payload.bin"),
                ("https", "/index.html"),
                ("https", "/payload.bin"),
            },
        )

        hyper_static = [
            scenario
            for scenario in scenarios
            if scenario.candidate in {
                "nginx_hyper",
                "cyfs_gateway_hyper",
                "nginx_reuseport_static",
                "cyfs_gateway_reuseport_static",
            }
        ]
        self.assertTrue(hyper_static)
        self.assertEqual({scenario.scenario for scenario in hyper_static}, {"static_http_file"})
        self.assertEqual({scenario.protocol for scenario in hyper_static}, {"http"})

    def test_profile_candidates_filter_scenario_matrix_and_deployment(self) -> None:
        plan = replace(load_profile(PROFILE), candidates=("nginx_hyper",))
        scenarios = expand_scenarios(plan)

        self.assertTrue(scenarios)
        self.assertEqual({scenario.candidate for scenario in scenarios}, {"nginx_hyper"})
        self.assertEqual({scenario.scenario for scenario in scenarios}, {"static_http_file"})
        self.assertEqual({scenario.protocol for scenario in scenarios}, {"http"})

        pull_rendered = [" ".join(command.command) for command in pull_commands(plan)]
        run_rendered = [" ".join(command.command) for command in run_container_commands(plan)]
        readiness_rendered = [" ".join(command.command) for command in container_readiness_commands(plan)]

        self.assertTrue(any(plan.images["nginx"].image_ref in command for command in pull_rendered))
        self.assertFalse(any(plan.images["cyfs_gateway"].image_ref in command for command in pull_rendered))
        self.assertTrue(any("--name cyfs-perf-nginx" in command for command in run_rendered))
        self.assertFalse(any("--name cyfs-perf-cyfs_gateway" in command for command in run_rendered))
        self.assertEqual(readiness_rendered, ["docker inspect --format {{.State.Running}} cyfs-perf-nginx"])

    def test_reuseport_static_fixture_can_be_disabled(self) -> None:
        text = PROFILE.read_text(encoding="utf-8").replace("enabled: true", "enabled: false", 1)
        with tempfile.TemporaryDirectory() as temp:
            profile = Path(temp) / "profile.yaml"
            profile.write_text(text, encoding="utf-8")
            plan = load_profile(profile)
            scenarios = expand_scenarios(plan)
            metadata = write_image_context(plan, "nginx", Path(temp))
            dockerfile_text = Path(metadata["dockerfile"]).read_text(encoding="utf-8")

        self.assertFalse(plan.upstream["reuseport_static_fixture"]["enabled"])
        self.assertFalse(metadata["packaged_reuseport_static_fixture"]["enabled"])
        self.assertIn("ENV REUSEPORT_STATIC_ENABLED=0", dockerfile_text)
        self.assertFalse(
            any(
                scenario.candidate in {"nginx_reuseport_static", "cyfs_gateway_reuseport_static"}
                for scenario in scenarios
            )
        )

    def test_pull_policy_never_skips_target_pull_commands(self) -> None:
        plan = replace(load_profile(PROFILE), registry_pull_policy="never")

        self.assertEqual(pull_commands(plan), [])

    def test_profile_rejects_unknown_pull_policy(self) -> None:
        text = PROFILE.read_text(encoding="utf-8").replace("pull_policy: always", "pull_policy: sometimes")
        with tempfile.TemporaryDirectory() as temp:
            profile = Path(temp) / "profile.yaml"
            profile.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(ConfigError, "registry.pull_policy"):
                load_profile(profile)

    def test_profile_rejects_unknown_candidate(self) -> None:
        text = PROFILE.read_text(encoding="utf-8").replace("- cyfs_gateway_hyper", "- cyfs_gateay_hyper")
        with tempfile.TemporaryDirectory() as temp:
            profile = Path(temp) / "profile.yaml"
            profile.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(ConfigError, "unknown candidate"):
                load_profile(profile)

    def test_profile_rejects_unknown_connection_reuse_mode(self) -> None:
        text = PROFILE.read_text(encoding="utf-8").replace("- reuse_connection", "- multiplex_everything")
        with tempfile.TemporaryDirectory() as temp:
            profile = Path(temp) / "profile.yaml"
            profile.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(ConfigError, "connection_reuse_modes"):
                load_profile(profile)

    def test_profile_accepts_configured_reuseport_static_threads(self) -> None:
        text = PROFILE.read_text(encoding="utf-8").replace("# threads: 8", "threads: 6")
        with tempfile.TemporaryDirectory() as temp:
            profile = Path(temp) / "profile.yaml"
            profile.write_text(text, encoding="utf-8")
            plan = load_profile(profile)
            metadata = write_image_context(plan, "nginx", Path(temp))
            dockerfile_text = Path(metadata["dockerfile"]).read_text(encoding="utf-8")

        self.assertEqual(plan.upstream["reuseport_static_fixture"]["threads"], 6)
        self.assertEqual(metadata["packaged_reuseport_static_fixture"]["threads"], 6)
        self.assertIn("ENV REUSEPORT_STATIC_THREADS=6", dockerfile_text)
        rendered = [" ".join(command.command) for command in run_container_commands(plan)]
        self.assertTrue(any("-e REUSEPORT_STATIC_THREADS=6" in command for command in rendered))

    def test_profile_accepts_configured_reuseport_static_tokio_uring_runtime(self) -> None:
        text = PROFILE.read_text(encoding="utf-8").replace("runtime: tokio", "runtime: tokio_uring")
        with tempfile.TemporaryDirectory() as temp:
            profile = Path(temp) / "profile.yaml"
            profile.write_text(text, encoding="utf-8")
            plan = load_profile(profile)
            metadata = write_image_context(plan, "nginx", Path(temp))
            dockerfile_text = Path(metadata["dockerfile"]).read_text(encoding="utf-8")

        self.assertEqual(plan.upstream["reuseport_static_fixture"]["runtime"], "tokio_uring")
        self.assertEqual(metadata["packaged_reuseport_static_fixture"]["runtime"], "tokio_uring")
        self.assertIn("ENV REUSEPORT_STATIC_RUNTIME=tokio_uring", dockerfile_text)

    def test_profile_accepts_configured_reuseport_static_tokio_custom_runtime(self) -> None:
        text = PROFILE.read_text(encoding="utf-8").replace("runtime: tokio", "runtime: tokio_custom")
        with tempfile.TemporaryDirectory() as temp:
            profile = Path(temp) / "profile.yaml"
            profile.write_text(text, encoding="utf-8")
            plan = load_profile(profile)
            metadata = write_image_context(plan, "nginx", Path(temp))
            dockerfile_text = Path(metadata["dockerfile"]).read_text(encoding="utf-8")

        self.assertEqual(plan.upstream["reuseport_static_fixture"]["runtime"], "tokio_custom")
        self.assertEqual(metadata["packaged_reuseport_static_fixture"]["runtime"], "tokio_custom")
        self.assertIn("ENV REUSEPORT_STATIC_RUNTIME=tokio_custom", dockerfile_text)

    def test_profile_rejects_invalid_reuseport_static_runtime(self) -> None:
        text = PROFILE.read_text(encoding="utf-8").replace("runtime: tokio", "runtime: async_everything")
        with tempfile.TemporaryDirectory() as temp:
            profile = Path(temp) / "profile.yaml"
            profile.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(ConfigError, "reuseport_static_fixture.runtime"):
                load_profile(profile)

    def test_profile_rejects_invalid_reuseport_static_threads(self) -> None:
        text = PROFILE.read_text(encoding="utf-8").replace("# threads: 8", "threads: 0")
        with tempfile.TemporaryDirectory() as temp:
            profile = Path(temp) / "profile.yaml"
            profile.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(ConfigError, "reuseport_static_fixture.threads"):
                load_profile(profile)

    def test_reuse_connection_workload_sets_vegeta_keepalive(self) -> None:
        plan = load_profile(PROFILE)
        plan = replace(plan, load=replace(plan.load, duration_seconds=1, warmup_seconds=0, concurrency=2, rates=(4,)))
        scenario = ScenarioPlan("nginx", "stream_reverse_proxy", "https", 4, "/payload.bin", None, "reuse_connection")

        def fake_run(command, **kwargs):
            if command[1] == "attack":
                return mock.Mock(returncode=0, stdout=b"vegeta-binary-results", stderr=b"")
            return mock.Mock(
                returncode=0,
                stdout=b'{"code":200,"latency":3000000}\n{"code":200,"latency":3000000}\n',
                stderr=b"",
            )

        with mock.patch("cyfs_gateway_performance.workload.ensure_vegeta", return_value=(Path("/tmp/vegeta"), {})), mock.patch(
            "cyfs_gateway_performance.workload.subprocess.run",
            side_effect=fake_run,
        ) as run_command:
            result = run_fixed_rate_workload(plan, scenario)

        attack_commands = [call.args[0] for call in run_command.call_args_list if call.args[0][1] == "attack"]
        self.assertEqual(len(attack_commands), 1)
        self.assertIn("-keepalive=true", attack_commands[0])
        self.assertIn("-insecure", attack_commands[0])
        self.assertIn("perf.local:19443:127.0.0.1:19443", attack_commands[0])
        self.assertEqual(result["engine"], "vegeta")
        self.assertEqual(result["connection_reuse"], "reuse_connection")

    def test_resource_metrics_samples_during_measured_window(self) -> None:
        plan = load_profile(PROFILE)
        scenario = ScenarioPlan("nginx", "static_http_file", "http", 1, "/index.html")

        def workload() -> dict:
            return {
                "started_at": 100.0,
                "measured_started_at": 100.0,
                "ended_at": 101.0,
                "success": 1,
                "errors": 0,
            }

        sample = {
            "samples": [{"returncode": 0, "stdout": "12.50%|64MiB / 1GiB"}],
            "sampling": "docker-stats",
            "cpu_percent_avg": 12.5,
            "memory_bytes_avg": 64 * 1024 * 1024,
        }
        with mock.patch("cyfs_gateway_performance.metrics.time.time", return_value=100.5), mock.patch(
            "cyfs_gateway_performance.metrics._sample_resource_metrics",
            return_value=sample,
        ):
            request_metrics, resource_metrics = run_with_resource_metrics(plan, scenario, workload)

        self.assertEqual(request_metrics["success"], 1)
        self.assertEqual(resource_metrics["sampling"], "docker-stats-window")
        self.assertEqual(resource_metrics["cpu_percent_avg"], 12.5)
        self.assertEqual(resource_metrics["memory_bytes_avg"], 64 * 1024 * 1024)
        self.assertEqual(len(resource_metrics["samples"]), 1)
        self.assertNotIn("process_sample", resource_metrics["samples"][0])
        self.assertNotIn("process_cpu_percent_avg", resource_metrics)
        self.assertNotIn("process_rss_kib_avg", resource_metrics)

    def test_ssh_preflight_uses_remote_commands(self) -> None:
        plan = load_profile(PROFILE)
        ssh_plan = plan.__class__(
            **{**plan.__dict__, "target": plan.target.__class__("ssh", "perf-host", True, "ubuntu", 2222)}
        )

        def fake_run(command, timeout=None):
            stdout = "ID=ubuntu\n" if command.description == "read os release" else "{}"
            return mock.Mock(ok=True, stdout=stdout)

        with mock.patch("cyfs_gateway_performance.target.run_command", side_effect=fake_run) as run_command:
            result = preflight(ssh_plan)

        self.assertTrue(result["can_run_benchmark"])
        self.assertFalse(result["can_run_local_dv"])
        self.assertEqual(result["docker"], "remote-docker")
        self.assertEqual(run_command.call_args_list[0].args[0].command[:4], ("ssh", "-p", "2222", "ubuntu@perf-host"))

    def test_preflight_accepts_debian_targets(self) -> None:
        plan = load_profile(PROFILE)
        ssh_plan = plan.__class__(
            **{**plan.__dict__, "target": plan.target.__class__("ssh", "perf-host", True, "ubuntu", 2222)}
        )

        def fake_run(command, timeout=None):
            stdout = 'ID=debian\nPRETTY_NAME="Debian GNU/Linux 12"\n' if command.description == "read os release" else "{}"
            return mock.Mock(ok=True, stdout=stdout)

        with mock.patch("cyfs_gateway_performance.target.run_command", side_effect=fake_run):
            result = preflight(ssh_plan)

        self.assertTrue(result["can_run_benchmark"])
        self.assertFalse(result["ubuntu_detected"])
        self.assertTrue(result["debian_detected"])
        self.assertTrue(result["supported_os_detected"])
        self.assertFalse(result["unsupported_os"])

    def test_preflight_rejects_non_ubuntu_debian_targets(self) -> None:
        plan = load_profile(PROFILE)
        ssh_plan = plan.__class__(
            **{**plan.__dict__, "target": plan.target.__class__("ssh", "perf-host", True, "ubuntu", 2222)}
        )

        def fake_run(command, timeout=None):
            stdout = 'ID=fedora\nPRETTY_NAME="Fedora Linux"\n' if command.description == "read os release" else "{}"
            return mock.Mock(ok=True, stdout=stdout)

        with mock.patch("cyfs_gateway_performance.target.run_command", side_effect=fake_run):
            result = preflight(ssh_plan)

        self.assertFalse(result["can_run_benchmark"])
        self.assertTrue(result["unsupported_os"])
        self.assertIn("only supports Ubuntu or Debian", result["unsupported_os_error"])
        self.assertIn("Fedora Linux", result["unsupported_os_error"])

    def test_preflight_rejects_derivative_os_id_like_targets(self) -> None:
        plan = load_profile(PROFILE)
        ssh_plan = plan.__class__(
            **{**plan.__dict__, "target": plan.target.__class__("ssh", "perf-host", True, "ubuntu", 2222)}
        )

        def fake_run(command, timeout=None):
            stdout = 'ID=linuxmint\nID_LIKE="ubuntu debian"\nPRETTY_NAME="Linux Mint"\n' if command.description == "read os release" else "{}"
            return mock.Mock(ok=True, stdout=stdout)

        with mock.patch("cyfs_gateway_performance.target.run_command", side_effect=fake_run):
            result = preflight(ssh_plan)

        self.assertFalse(result["supported_os_detected"])
        self.assertTrue(result["unsupported_os"])
        self.assertIn("Linux Mint", result["unsupported_os_error"])

    def test_run_reports_user_error_for_unsupported_target_os(self) -> None:
        plan = load_profile(PROFILE)
        with tempfile.TemporaryDirectory() as temp:
            plan = replace(plan, output={**plan.output, "directory": temp})
            preflight_result = {
                "target_mode": "local",
                "target_host": "127.0.0.1",
                "platform": "test",
                "os_release_available": True,
                "os_id": "fedora",
                "os_id_like": [],
                "os_pretty_name": "Fedora Linux",
                "ubuntu_detected": False,
                "debian_detected": False,
                "supported_os_detected": False,
                "docker": "docker",
                "can_run_local_dv": False,
                "can_run_benchmark": False,
                "unsupported_os": True,
                "unsupported_os_error": "unsupported target OS: performance-test only supports Ubuntu or Debian; detected Fedora Linux",
            }
            with mock.patch("cyfs_gateway_performance.cli.load_profile", return_value=plan), mock.patch(
                "cyfs_gateway_performance.cli.preflight",
                return_value=preflight_result,
            ), mock.patch("cyfs_gateway_performance.cli.target_metadata", return_value={}):
                stdout = io.StringIO()
                stderr = io.StringIO()
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    rc = cli.main(["run", "--profile", str(PROFILE)])
                result_json_exists = (Path(temp) / "result.json").exists()

        self.assertEqual(rc, cli.EXIT_CONFIG)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("configuration error: unsupported target OS", stderr.getvalue())
        self.assertIn("only supports Ubuntu or Debian", stderr.getvalue())
        self.assertTrue(result_json_exists)

    def test_build_image_command_builds_nginx_then_cyfs_gateway(self) -> None:
        plan = load_profile(PROFILE)

        def fake_build(_plan, _output, image_key):
            return {"image": image_key, "status": "built"}

        with tempfile.TemporaryDirectory() as temp:
            plan = replace(plan, output={**plan.output, "directory": temp})
            with mock.patch(
                "cyfs_gateway_performance.cli.load_profile",
                return_value=plan,
            ), mock.patch(
                "cyfs_gateway_performance.cli._build_image_from_plan",
                side_effect=fake_build,
            ) as build_image:
                stdout = io.StringIO()
                stderr = io.StringIO()
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    rc = cli.main(["build-image", "--profile", str(PROFILE)])
                    aggregate = Path(temp) / "build-image-plan.json"
                    aggregate_exists = aggregate.exists()

        self.assertEqual(rc, 0)
        self.assertEqual([call.args[2] for call in build_image.call_args_list], ["nginx", "cyfs_gateway"])
        self.assertTrue(aggregate_exists)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("summary: status=built", stderr.getvalue())
        self.assertIn("build-image-plan.json", stderr.getvalue())

    def test_cyfs_gateway_source_build_uses_isolated_target_dir(self) -> None:
        plan = load_profile(PROFILE)
        with tempfile.TemporaryDirectory() as temp:
            context = Path(temp) / "docker" / "cyfs_gateway"
            commands = source_build_commands(plan, context)

        command = commands[0].command
        self.assertIn("--release", command)
        self.assertIn("--target", command)
        self.assertEqual(command[command.index("--target") + 1], cyfs_gateway_source(plan)["target"])
        self.assertIn("--target-dir", command)
        target_dir = command[command.index("--target-dir") + 1]
        self.assertTrue(target_dir.endswith("cargo-target/cyfs_gateway"))
        self.assertNotIn("/src/target", target_dir)
        self.assertNotIn("docker/cyfs_gateway/cargo-target", target_dir)

    def test_cyfs_gateway_source_build_logs_command_line(self) -> None:
        plan = load_profile(PROFILE)
        inspect_result = {
            "command": ["docker", "image", "inspect", plan.images["cyfs_gateway"].image_ref],
            "description": "inspect existing cyfs_gateway image",
            "returncode": 1,
        }
        source_result = {
            "command": ["cargo", "build"],
            "description": "build cyfs_gateway from current source",
            "returncode": 0,
        }
        build_result = {
            "command": ["docker", "build"],
            "description": "build cyfs_gateway image",
            "returncode": 0,
        }
        push_result = {
            "command": ["docker", "push", plan.images["cyfs_gateway"].image_ref],
            "description": "push cyfs_gateway image",
            "returncode": 0,
        }

        with tempfile.TemporaryDirectory() as temp, mock.patch(
            "cyfs_gateway_performance.cli._remove_existing_image",
            return_value=[inspect_result],
        ), mock.patch(
            "cyfs_gateway_performance.cli._run_commands",
            side_effect=[[source_result], [build_result], [push_result]],
        ):
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                metadata = cli._build_image_from_plan(plan, Path(temp), "cyfs_gateway")

        self.assertEqual(metadata["status"], "pushed")
        log = stderr.getvalue()
        self.assertIn("cyfs_gateway source build command: cargo build", log)
        self.assertIn("--manifest-path", log)
        self.assertIn("--package cyfs_gateway", log)
        self.assertIn("--target-dir", log)
        self.assertIn("cyfs_gateway compiled binary path:", log)
        self.assertIn("cyfs_gateway packaged binary path:", log)

    def test_profile_output_path_is_absolute_for_source_build_and_package_steps(self) -> None:
        plan = load_profile(PROFILE)
        with tempfile.TemporaryDirectory() as temp:
            relative_output = "relative-results"
            profile_path = Path(temp) / "profiles" / "custom.yaml"
            plan = replace(plan, profile_path=profile_path, output={**plan.output, "directory": relative_output})
            output = cli._profile_output(plan)
            context = output / "docker" / "cyfs_gateway"
            build_command = source_build_commands(plan, context)[0].command
            package_command = cli.image_build_plan(plan, "cyfs_gateway", output)[1][-2].command

        target_dir = Path(build_command[build_command.index("--target-dir") + 1])
        packaged_from = Path(package_command[-2])
        self.assertTrue(output.is_absolute())
        self.assertEqual(output, (profile_path.parent / relative_output).resolve())
        self.assertTrue(target_dir.is_absolute())
        self.assertTrue(packaged_from.is_absolute())
        self.assertTrue(packaged_from.is_relative_to(target_dir))

    def test_default_profile_output_is_relative_to_profile_directory(self) -> None:
        plan = load_profile(PROFILE)
        expected = (PROFILE.parent / "../results/latest").resolve()

        self.assertEqual(cli._profile_output(plan), expected)

    def test_build_commands_accept_output_cli_argument(self) -> None:
        plan = load_profile(PROFILE)
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "cli-output"
            with mock.patch(
                "cyfs_gateway_performance.cli.load_profile",
                return_value=plan,
            ), mock.patch(
                "cyfs_gateway_performance.cli._build_image_from_plan",
                return_value={"image": "nginx", "status": "built"},
            ) as build_image:
                stdout = io.StringIO()
                stderr = io.StringIO()
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    rc = cli.main(["build-nginx-image", "--profile", str(PROFILE), "--output", str(output)])

        self.assertEqual(rc, 0)
        self.assertEqual(build_image.call_args.args[1], output.resolve())
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("loading profile:", stderr.getvalue())

    def test_unknown_cli_argument_is_rejected(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            cli.main(["build-image", "--profile", str(PROFILE), "--unknown", "ignored"])

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("unrecognized arguments: --unknown ignored", stderr.getvalue())

    def test_container_readiness_inspects_running_state(self) -> None:
        plan = load_profile(PROFILE)
        commands = container_readiness_commands(plan)

        rendered = [" ".join(command.command) for command in commands]
        self.assertIn("docker inspect --format {{.State.Running}} cyfs-perf-nginx", rendered)
        self.assertIn("docker inspect --format {{.State.Running}} cyfs-perf-cyfs_gateway", rendered)

    def test_build_image_from_plan_pushes_successful_build_when_enabled(self) -> None:
        plan = load_profile(PROFILE)
        inspect_result = {
            "command": ["docker", "image", "inspect", plan.images["nginx"].image_ref],
            "description": "inspect existing nginx image",
            "returncode": 1,
        }
        build_result = {
            "command": ["docker", "build"],
            "description": "build nginx image",
            "returncode": 0,
        }
        push_result = {
            "command": ["docker", "push", plan.images["nginx"].image_ref],
            "description": "push nginx image",
            "returncode": 0,
        }

        with tempfile.TemporaryDirectory() as temp, mock.patch(
            "cyfs_gateway_performance.cli._remove_existing_image",
            return_value=[inspect_result],
        ), mock.patch(
            "cyfs_gateway_performance.cli._run_commands",
            side_effect=[[build_result], [push_result]],
        ) as run_commands:
            metadata = cli._build_image_from_plan(plan, Path(temp), "nginx")

        self.assertEqual(metadata["status"], "pushed")
        self.assertEqual(run_commands.call_count, 2)
        push_commands = run_commands.call_args_list[1].args[0]
        self.assertEqual(push_commands[-1].command, ("docker", "push", plan.images["nginx"].image_ref))
        self.assertEqual(metadata["push_results"][0]["description"], "push nginx image")

    def test_build_image_from_plan_skips_push_when_disabled(self) -> None:
        plan = replace(load_profile(PROFILE), registry_push=False)
        inspect_result = {
            "command": ["docker", "image", "inspect", plan.images["nginx"].image_ref],
            "description": "inspect existing nginx image",
            "returncode": 1,
        }
        build_result_data = {
            "command": ["docker", "build"],
            "description": "build nginx image",
            "returncode": 0,
        }

        with tempfile.TemporaryDirectory() as temp, mock.patch(
            "cyfs_gateway_performance.cli._remove_existing_image",
            return_value=[inspect_result],
        ), mock.patch(
            "cyfs_gateway_performance.cli._run_commands",
            return_value=[build_result_data],
        ) as run_commands:
            metadata = cli._build_image_from_plan(plan, Path(temp), "nginx")

        self.assertEqual(metadata["status"], "built")
        self.assertEqual(run_commands.call_count, 1)
        self.assertEqual(metadata["push_skipped"], "registry.push is false")

    def test_push_image_command_skips_when_push_disabled(self) -> None:
        plan = replace(load_profile(PROFILE), registry_push=False)
        with tempfile.TemporaryDirectory() as temp:
            plan = replace(plan, output={**plan.output, "directory": temp})
            with mock.patch("cyfs_gateway_performance.cli.load_profile", return_value=plan), mock.patch(
                "cyfs_gateway_performance.cli._run_commands"
            ) as run_commands:
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    rc = cli.main(["push-image", "--profile", str(PROFILE), "--image", "nginx"])
            metadata = json.loads((Path(temp) / "nginx-push-plan.json").read_text(encoding="utf-8"))

        self.assertEqual(rc, 0)
        run_commands.assert_not_called()
        self.assertEqual(metadata["status"], "skipped")
        self.assertEqual(metadata["push_skipped"], "registry.push is false")
        self.assertIn("image push skipped", stderr.getvalue())

    def test_result_records_registry_push_and_pull_policy(self) -> None:
        plan = replace(load_profile(PROFILE), registry_push=False, registry_pull_policy="never")
        result = build_result(plan, [], "completed", evidence={})

        self.assertEqual(result["registry"]["push"], False)
        self.assertEqual(result["registry"]["pull_policy"], "never")

    def test_build_image_removes_existing_target_image_before_build(self) -> None:
        plan = load_profile(PROFILE)
        build_result = {
            "command": ["docker", "build"],
            "description": "build nginx image",
            "returncode": 0,
        }
        push_result = {
            "command": ["docker", "push", plan.images["nginx"].image_ref],
            "description": "push nginx image",
            "returncode": 0,
        }

        def fake_run(command, timeout=None):
            return self._command_result(command, 0)

        with tempfile.TemporaryDirectory() as temp, mock.patch(
            "cyfs_gateway_performance.cli.run_command",
            side_effect=fake_run,
        ) as run_command, mock.patch(
            "cyfs_gateway_performance.cli._run_commands",
            side_effect=[[build_result], [push_result]],
        ):
            metadata = cli._build_image_from_plan(plan, Path(temp), "nginx")

        self.assertEqual(metadata["status"], "pushed")
        self.assertEqual(
            run_command.call_args_list[0].args[0].command,
            ("docker", "image", "inspect", plan.images["nginx"].image_ref),
        )
        self.assertEqual(
            run_command.call_args_list[1].args[0].command,
            ("docker", "image", "rm", "-f", plan.images["nginx"].image_ref),
        )
        self.assertEqual(
            [item["description"] for item in metadata["command_results"][:3]],
            ["inspect existing nginx image", "remove existing nginx image", "build nginx image"],
        )

    def test_build_image_continues_when_target_image_does_not_exist(self) -> None:
        plan = load_profile(PROFILE)
        build_result = {
            "command": ["docker", "build"],
            "description": "build nginx image",
            "returncode": 0,
        }
        push_result = {
            "command": ["docker", "push", plan.images["nginx"].image_ref],
            "description": "push nginx image",
            "returncode": 0,
        }

        def fake_run(command, timeout=None):
            return self._command_result(command, 1)

        with tempfile.TemporaryDirectory() as temp, mock.patch(
            "cyfs_gateway_performance.cli.run_command",
            side_effect=fake_run,
        ) as run_command, mock.patch(
            "cyfs_gateway_performance.cli._run_commands",
            side_effect=[[build_result], [push_result]],
        ):
            metadata = cli._build_image_from_plan(plan, Path(temp), "nginx")

        self.assertEqual(metadata["status"], "pushed")
        self.assertEqual(len(run_command.call_args_list), 1)
        self.assertEqual(metadata["command_results"][0]["description"], "inspect existing nginx image")

    def test_markdown_report_groups_equivalent_candidates_for_comparison(self) -> None:
        result = {
            "status": "completed",
            "profile": str(PROFILE),
            "results": [
                {
                    "candidate": "nginx",
                    "scenario": "static_http_file",
                    "protocol": "http",
                    "stream_mode": None,
                    "payload": "/index.html",
                    "connection_reuse": "new_connection",
                    "rate": 100,
                    "requests": {"success": 10, "latency_ms": {"avg": 1.1}},
                    "resources": {"cpu_percent_avg": 2.0, "memory_bytes_avg": 100},
                },
                {
                    "candidate": "nginx",
                    "scenario": "http_reverse_proxy",
                    "protocol": "http",
                    "stream_mode": None,
                    "payload": "/proxy/payload",
                    "connection_reuse": "new_connection",
                    "rate": 100,
                    "requests": {"success": 20, "latency_ms": {"avg": 2.2}},
                    "resources": {"cpu_percent_avg": 3.0, "memory_bytes_avg": 200},
                },
                {
                    "candidate": "cyfs_gateway",
                    "scenario": "static_http_file",
                    "protocol": "http",
                    "stream_mode": None,
                    "payload": "/index.html",
                    "connection_reuse": "new_connection",
                    "rate": 100,
                    "requests": {"success": 11, "latency_ms": {"avg": 1.2}},
                    "resources": {"cpu_percent_avg": 2.1, "memory_bytes_avg": 101},
                },
                {
                    "candidate": "cyfs_gateway",
                    "scenario": "http_reverse_proxy",
                    "protocol": "http",
                    "stream_mode": None,
                    "payload": "/proxy/payload",
                    "connection_reuse": "new_connection",
                    "rate": 100,
                    "requests": {"success": 21, "latency_ms": {"avg": 2.3}},
                    "resources": {"cpu_percent_avg": 3.1, "memory_bytes_avg": 201},
                },
            ],
        }

        with tempfile.TemporaryDirectory() as temp:
            outputs = write_reports(result, Path(temp))
            summary = Path(outputs["markdown"]).read_text(encoding="utf-8")

        static_nginx = summary.index("| static_http_file | http |  | /index.html | new_connection | 100 | nginx |")
        static_cyfs = summary.index("| static_http_file | http |  | /index.html | new_connection | 100 | cyfs_gateway |")
        proxy_nginx = summary.index("| http_reverse_proxy | http |  | /proxy/payload | new_connection | 100 | nginx |")
        proxy_cyfs = summary.index("| http_reverse_proxy | http |  | /proxy/payload | new_connection | 100 | cyfs_gateway |")
        self.assertLess(proxy_nginx, proxy_cyfs)
        self.assertLess(proxy_cyfs, static_nginx)
        self.assertLess(static_nginx, static_cyfs)

    def test_reports_include_generated_time_in_json_markdown_and_csv(self) -> None:
        result = {
            "status": "completed",
            "profile": str(PROFILE),
            "results": [
                {
                    "candidate": "nginx",
                    "scenario": "static_http_file",
                    "protocol": "http",
                    "stream_mode": None,
                    "payload": "/index.html",
                    "connection_reuse": "new_connection",
                    "rate": 100,
                    "requests": {"success": 10, "latency_ms": {"avg": 1.1}},
                    "resources": {"cpu_percent_avg": 2.0, "memory_bytes_avg": 100},
                },
            ],
        }

        with tempfile.TemporaryDirectory() as temp:
            with mock.patch("cyfs_gateway_performance.report.current_time_text", return_value="2026-05-19T12:00:00+08:00"):
                outputs = write_reports(result, Path(temp), csv_enabled=True)
            result_json = json.loads(Path(outputs["json"]).read_text(encoding="utf-8"))
            summary = Path(outputs["markdown"]).read_text(encoding="utf-8")
            with Path(outputs["csv"]).open(encoding="utf-8", newline="") as handle:
                csv_rows = list(csv.DictReader(handle))

        self.assertEqual(result_json["generated_at"], "2026-05-19T12:00:00+08:00")
        self.assertIn("- generated_at: 2026-05-19T12:00:00+08:00", summary)
        self.assertEqual(csv_rows[0]["generated_at"], "2026-05-19T12:00:00+08:00")

    def test_markdown_report_appends_when_summary_already_exists(self) -> None:
        first = {
            "status": "completed",
            "profile": str(PROFILE),
            "results": [
                {
                    "candidate": "nginx",
                    "scenario": "static_http_file",
                    "protocol": "http",
                    "stream_mode": None,
                    "payload": "/index.html",
                    "connection_reuse": "new_connection",
                    "rate": 100,
                    "requests": {"success": 10, "latency_ms": {"avg": 1.1}},
                    "resources": {"cpu_percent_avg": 2.0, "memory_bytes_avg": 100},
                },
            ],
        }
        second = {
            "status": "environment-deferred",
            "profile": str(PROFILE),
            "results": [
                {
                    "candidate": "cyfs_gateway",
                    "scenario": "static_http_file",
                    "protocol": "http",
                    "stream_mode": None,
                    "payload": "/index.html",
                    "connection_reuse": "new_connection",
                    "rate": 200,
                    "requests": {"success": 11, "latency_ms": {"avg": 1.2}},
                    "resources": {"cpu_percent_avg": 2.1, "memory_bytes_avg": 101},
                },
            ],
        }

        with tempfile.TemporaryDirectory() as temp:
            outputs = write_reports(first, Path(temp))
            write_reports(second, Path(temp))
            summary = Path(outputs["markdown"]).read_text(encoding="utf-8")

        self.assertEqual(summary.count("# Performance Benchmark Summary"), 2)
        self.assertIn("- status: completed", summary)
        self.assertIn("- status: environment-deferred", summary)
        self.assertLess(summary.index("- status: completed"), summary.index("- status: environment-deferred"))
        self.assertIn("\n---\n\n# Performance Benchmark Summary", summary)


if __name__ == "__main__":
    unittest.main()
