from __future__ import annotations

import platform
import shlex
import shutil
from pathlib import Path

from .executor import run_command
from .model import BenchmarkPlan, CommandPlan


SUPPORTED_OS_IDS = {"ubuntu", "debian"}


def _parse_os_release(text: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key] = value.strip().strip('"').strip("'")
    return data


def _os_release_metadata(text: str) -> dict:
    data = _parse_os_release(text)
    os_id = data.get("ID", "").lower()
    os_id_like = tuple(part.lower() for part in data.get("ID_LIKE", "").split() if part)
    ubuntu_detected = os_id == "ubuntu"
    debian_detected = os_id == "debian"
    supported_os_detected = os_id in SUPPORTED_OS_IDS
    return {
        "os_id": os_id,
        "os_id_like": list(os_id_like),
        "os_pretty_name": data.get("PRETTY_NAME", ""),
        "ubuntu_detected": ubuntu_detected,
        "debian_detected": debian_detected,
        "supported_os_detected": supported_os_detected,
    }


def preflight(plan: BenchmarkPlan) -> dict:
    if plan.target.mode == "ssh":
        os_result = run_command(target_command(plan, "read os release", ("cat", "/etc/os-release")), timeout=30)
        docker_result = run_command(target_command(plan, "docker version", ("docker", "version", "--format", "{{json .}}")), timeout=30)
        os_text = os_result.stdout
        os_release_available = os_result.ok
        docker_path = "remote-docker" if docker_result.ok else None
    else:
        os_release = Path("/etc/os-release")
        os_text = os_release.read_text(encoding="utf-8", errors="replace") if os_release.exists() else ""
        os_release_available = os_release.exists()
        docker_path = shutil.which("docker")
    os_metadata = _os_release_metadata(os_text)
    supported_os = os_metadata["supported_os_detected"]
    unsupported_os = plan.target.ubuntu_required and os_release_available and not supported_os
    can_run = (not plan.target.ubuntu_required or supported_os) and bool(docker_path)
    unsupported_os_error = ""
    if unsupported_os:
        detected = os_metadata["os_pretty_name"] or os_metadata["os_id"] or "unknown"
        unsupported_os_error = (
            "unsupported target OS: performance-test only supports Ubuntu or Debian; "
            f"detected {detected}"
        )
    return {
        "target_mode": plan.target.mode,
        "target_host": plan.target.host,
        "platform": platform.platform(),
        "os_release_available": os_release_available,
        **os_metadata,
        "docker": docker_path,
        "can_run_local_dv": plan.target.mode == "local" and can_run,
        "can_run_benchmark": can_run,
        "unsupported_os": unsupported_os,
        "unsupported_os_error": unsupported_os_error,
    }


def deployment_plan(plan: BenchmarkPlan) -> list[CommandPlan]:
    network = str(((plan.generated_config.get("docker") or {}) or {}).get("network") or "cyfs-perf-local")
    commands = [CommandPlan("create benchmark network", ("docker", "network", "create", network))]
    for image in plan.images.values():
        commands.append(CommandPlan(f"pull {image.key} image", ("docker", "pull", image.image_ref)))
        commands.append(
            CommandPlan(
                f"run {image.key} container",
                (
                    "docker",
                    "run",
                    "--rm",
                    "--network",
                    network,
                    "--name",
                    f"cyfs-perf-{image.key}",
                    image.image_ref,
                ),
            )
        )
    commands.append(CommandPlan("remove benchmark network", ("docker", "network", "rm", network)))
    return commands


def target_command(plan: BenchmarkPlan, description: str, command: tuple[str, ...]) -> CommandPlan:
    if plan.target.mode == "ssh":
        destination = f"{plan.target.user}@{plan.target.host}" if plan.target.user else plan.target.host
        ssh_command = ["ssh"]
        if plan.target.port:
            ssh_command.extend(["-p", str(plan.target.port)])
        ssh_command.extend([destination, " ".join(shlex.quote(part) for part in command)])
        return CommandPlan(description, tuple(ssh_command))
    return CommandPlan(description, command)


def target_metadata(plan: BenchmarkPlan) -> dict:
    commands = [
        target_command(plan, "read os release", ("cat", "/etc/os-release")),
        target_command(plan, "docker version", ("docker", "version", "--format", "{{json .}}")),
        target_command(plan, "kernel version", ("uname", "-a")),
        target_command(plan, "cpu info", ("sh", "-c", "lscpu || true")),
        target_command(plan, "memory info", ("sh", "-c", "free -b || true")),
    ]
    results = [run_command(command, timeout=30).as_dict() for command in commands]
    os_text = next((item["stdout"] for item in results if item["description"] == "read os release"), "")
    os_metadata = _os_release_metadata(os_text)
    return {
        "target_mode": plan.target.mode,
        "target_host": plan.target.host,
        "commands": results,
        **os_metadata,
        "docker_available": any(item["description"] == "docker version" and item["returncode"] == 0 for item in results),
    }


def docker_network_name(plan: BenchmarkPlan) -> str:
    return str(((plan.generated_config.get("docker") or {}) or {}).get("network") or "cyfs-perf-local")


def docker_env_args(plan: BenchmarkPlan, image_key: str) -> tuple[str, ...]:
    docker_cfg = (plan.generated_config.get("docker") or {}) if isinstance(plan.generated_config, dict) else {}
    env_cfg = docker_cfg.get(f"{image_key}_env") or {}
    if not isinstance(env_cfg, dict):
        return ()

    args: list[str] = []
    for key in sorted(env_cfg):
        value = env_cfg[key]
        if value is None:
            continue
        args.extend(["-e", f"{key}={value}"])
    return tuple(args)


def reuseport_static_config(plan: BenchmarkPlan) -> dict:
    fixture = plan.upstream.get("reuseport_static_fixture") if isinstance(plan.upstream, dict) else None
    return fixture if isinstance(fixture, dict) else {}


def reuseport_static_env_args(plan: BenchmarkPlan) -> tuple[str, ...]:
    fixture = reuseport_static_config(plan)
    enabled = 1 if fixture.get("enabled", False) else 0
    runtime = fixture.get("runtime") if fixture.get("runtime") in {"tokio", "tokio_uring"} else "tokio"
    port = int(fixture.get("port") or 10081)
    args = [
        "-e",
        f"REUSEPORT_STATIC_ENABLED={enabled}",
        "-e",
        f"REUSEPORT_STATIC_RUNTIME={runtime}",
        "-e",
        f"REUSEPORT_STATIC_PORT={port}",
    ]
    threads = fixture.get("threads")
    if isinstance(threads, int) and threads > 0:
        args.extend(["-e", f"REUSEPORT_STATIC_THREADS={threads}"])
    return tuple(args)


def reuseport_static_needs_io_uring(plan: BenchmarkPlan) -> bool:
    fixture = reuseport_static_config(plan)
    return bool(fixture.get("enabled", False)) and fixture.get("runtime") == "tokio_uring"


def docker_security_args(plan: BenchmarkPlan) -> tuple[str, ...]:
    if reuseport_static_needs_io_uring(plan):
        return ("--security-opt", "seccomp=unconfined")
    return ()


def image_keys_for_candidates(plan: BenchmarkPlan) -> tuple[str, ...]:
    wanted = {
        "nginx"
        if candidate in {"nginx_hyper", "nginx_reuseport_static"}
        else "cyfs_gateway"
        if candidate in {"cyfs_gateway_hyper", "cyfs_gateway_reuseport_static"}
        else candidate
        for candidate in plan.candidates
    }
    return tuple(image_key for image_key in plan.images if image_key in wanted)


def pull_commands(plan: BenchmarkPlan) -> list[CommandPlan]:
    if plan.registry_pull_policy == "never":
        return []
    return [
        target_command(plan, f"pull {plan.images[image_key].key} image", ("docker", "pull", plan.images[image_key].image_ref))
        for image_key in image_keys_for_candidates(plan)
    ]


def cleanup_commands(plan: BenchmarkPlan) -> list[CommandPlan]:
    network = docker_network_name(plan)
    commands = []
    for image_key in image_keys_for_candidates(plan):
        image = plan.images[image_key]
        commands.append(target_command(plan, f"remove {image.key} container", ("docker", "rm", "-f", f"cyfs-perf-{image.key}")))
    commands.append(target_command(plan, "remove benchmark network", ("docker", "network", "rm", network)))
    return commands


def run_container_commands(plan: BenchmarkPlan) -> list[CommandPlan]:
    network = docker_network_name(plan)
    commands = [target_command(plan, "create benchmark network", ("docker", "network", "create", network))]
    image_keys = image_keys_for_candidates(plan)
    if "nginx" in image_keys:
        commands.append(
            target_command(
                plan,
                "run nginx container",
                (
                    "docker",
                    "run",
                    "-d",
                    "--network",
                    network,
                    "--name",
                    "cyfs-perf-nginx",
                    "-p",
                    "18080:80",
                    "-p",
                    "18443:443",
                    "-p",
                    "19080:9080",
                    "-p",
                    "19443:9443",
                    "-p",
                    "18180:10080",
                    "-p",
                    "18181:10081",
                    *docker_security_args(plan),
                    *reuseport_static_env_args(plan),
                    *docker_env_args(plan, "nginx"),
                    plan.images["nginx"].image_ref,
                ),
            )
        )
    if "cyfs_gateway" in image_keys:
        commands.append(
            target_command(
                plan,
                "run cyfs_gateway container",
                (
                    "docker",
                    "run",
                    "-d",
                    "--network",
                    network,
                    "--name",
                    "cyfs-perf-cyfs_gateway",
                    "-p",
                    "28080:80",
                    "-p",
                    "28443:443",
                    "-p",
                    "29080:9080",
                    "-p",
                    "29443:9443",
                    "-p",
                    "28180:10080",
                    "-p",
                    "28181:10081",
                    *docker_security_args(plan),
                    *reuseport_static_env_args(plan),
                    *docker_env_args(plan, "cyfs_gateway"),
                    plan.images["cyfs_gateway"].image_ref,
                ),
            )
        )
    return commands


def container_logs_commands(plan: BenchmarkPlan) -> list[CommandPlan]:
    return [
        target_command(plan, f"logs {plan.images[image_key].key} container", ("docker", "logs", f"cyfs-perf-{plan.images[image_key].key}"))
        for image_key in image_keys_for_candidates(plan)
    ]


def container_readiness_commands(plan: BenchmarkPlan) -> list[CommandPlan]:
    return [
        target_command(
            plan,
            f"inspect {plan.images[image_key].key} container running",
            ("docker", "inspect", "--format", "{{.State.Running}}", f"cyfs-perf-{plan.images[image_key].key}"),
        )
        for image_key in image_keys_for_candidates(plan)
    ]
