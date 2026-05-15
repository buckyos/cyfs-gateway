from __future__ import annotations

import threading
import time
from collections.abc import Callable

from .executor import run_command
from .model import BenchmarkPlan, ScenarioPlan
from .target import target_command


def _parse_size(value: str) -> int:
    units = {
        "KiB": 1024,
        "MiB": 1024**2,
        "GiB": 1024**3,
        "kB": 1000,
        "MB": 1000**2,
        "GB": 1000**3,
        "B": 1,
    }
    value = value.strip()
    for unit, multiplier in units.items():
        if value.endswith(unit):
            return int(float(value[: -len(unit)].strip()) * multiplier)
    return int(float(value))


def _sample_resource_metrics(plan: BenchmarkPlan, scenario: ScenarioPlan) -> dict:
    if not plan.metrics.get("collect_docker_stats", True):
        return {"samples": [], "sampling": "disabled", "cpu_percent_avg": 0.0, "memory_bytes_avg": 0}
    container = f"cyfs-perf-{scenario.candidate}"
    command = target_command(
        plan,
        f"docker stats {container}",
        ("docker", "stats", "--no-stream", "--format", "{{.CPUPerc}}|{{.MemUsage}}", container),
    )
    result = run_command(command, timeout=15)
    sample = result.as_dict()
    if not result.ok:
        return {
            "samples": [sample],
            "sampling": "docker-stats-failed",
            "cpu_percent_avg": 0.0,
            "memory_bytes_avg": 0,
        }
    stdout = result.stdout.strip()
    cpu = 0.0
    memory = 0
    if "|" in stdout:
        cpu_text, memory_text = stdout.split("|", 1)
        cpu = float(cpu_text.strip().rstrip("%"))
        memory = _parse_size(memory_text.split("/", 1)[0].strip())
    return {
        "samples": [sample],
        "sampling": "docker-stats",
        "cpu_percent_avg": round(cpu, 3),
        "memory_bytes_avg": memory,
    }


def collect_resource_metrics(plan: BenchmarkPlan, scenario: ScenarioPlan) -> dict:
    return _sample_resource_metrics(plan, scenario)


def run_with_resource_metrics(
    plan: BenchmarkPlan,
    scenario: ScenarioPlan,
    workload: Callable[[], dict],
) -> tuple[dict, dict]:
    if not plan.metrics.get("collect_docker_stats", True):
        return workload(), {"samples": [], "sampling": "disabled", "cpu_percent_avg": 0.0, "memory_bytes_avg": 0}

    interval = float(plan.metrics.get("resource_sample_interval_seconds") or 1)
    if interval <= 0:
        interval = 1.0
    stop = threading.Event()
    samples: list[dict] = []

    def sample_loop() -> None:
        while not stop.is_set():
            sampled_at = time.time()
            sample = _sample_resource_metrics(plan, scenario)
            for item in sample.get("samples", []):
                item["sampled_at"] = sampled_at
                samples.append(item)
            stop.wait(interval)

    thread = threading.Thread(target=sample_loop, name=f"resource-sampler-{scenario.candidate}", daemon=True)
    thread.start()
    try:
        request_metrics = workload()
    finally:
        stop.set()
        thread.join(timeout=max(1.0, interval + 1.0))

    measured_start = request_metrics.get("measured_started_at", request_metrics.get("started_at", 0))
    measured_end = request_metrics.get("ended_at", time.time())
    window_samples = [
        item for item in samples if measured_start <= float(item.get("sampled_at", 0)) <= measured_end
    ]
    cpu_values = []
    memory_values = []
    for item in window_samples:
        stdout = str(item.get("stdout") or "").strip()
        if "|" not in stdout or int(item.get("returncode", 1)) != 0:
            continue
        cpu_text, memory_text = stdout.split("|", 1)
        try:
            cpu_values.append(float(cpu_text.strip().rstrip("%")))
            memory_values.append(_parse_size(memory_text.split("/", 1)[0].strip()))
        except ValueError:
            continue

    resource_metrics = {
        "samples": window_samples,
        "sampling": "docker-stats-window" if window_samples else "docker-stats-window-empty",
        "sample_interval_seconds": interval,
        "window_started_at": measured_start,
        "window_ended_at": measured_end,
        "cpu_percent_avg": round(sum(cpu_values) / len(cpu_values), 3) if cpu_values else 0.0,
        "memory_bytes_avg": int(sum(memory_values) / len(memory_values)) if memory_values else 0,
    }
    return request_metrics, resource_metrics
