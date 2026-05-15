from __future__ import annotations

import socket
import ssl
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

from .model import BenchmarkPlan, ScenarioPlan


def endpoint_for(scenario: ScenarioPlan, host: str = "127.0.0.1") -> tuple[str, int, bool]:
    if scenario.scenario == "stream_reverse_proxy":
        if scenario.candidate == "nginx":
            return host, 19443 if scenario.stream_mode == "tcp_tls" else 19080, scenario.stream_mode == "tcp_tls"
        return host, 29443 if scenario.stream_mode == "tcp_tls" else 29080, scenario.stream_mode == "tcp_tls"
    if scenario.protocol == "https":
        if scenario.candidate == "nginx":
            return host, 18443, True
        return host, 28443, True
    if scenario.candidate == "nginx":
        return host, 18080, False
    return host, 28080, False


def _percentile(values: list[float], percentile: int) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((percentile / 100) * (len(ordered) - 1))))
    return ordered[index]


def _http_request(url: str, timeout: int) -> None:
    request = urllib.request.Request(url, method="GET")
    context = ssl._create_unverified_context() if url.startswith("https://") else None
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        response.read()
        if response.status < 200 or response.status >= 300:
            raise RuntimeError(f"HTTP status {response.status}")


def _stream_request(host: str, port: int, timeout: int, tls: bool) -> None:
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        sock = ssl._create_unverified_context().wrap_socket(raw, server_hostname=host) if tls else raw
        with sock:
            sock.settimeout(timeout)
            payload = b"cyfs-performance-stream-payload"
            sock.sendall(payload)
            received = sock.recv(len(payload))
            if received != payload:
                raise RuntimeError("stream echo payload mismatch")
    finally:
        raw.close()


def _run_one(plan: BenchmarkPlan, scenario: ScenarioPlan, host: str, port: int, tls: bool) -> tuple[bool, float, str | None]:
    request_started = time.time()
    try:
        if scenario.scenario == "stream_reverse_proxy":
            _stream_request(host, port, plan.load.timeout_seconds, tls)
        else:
            scheme = "https" if scenario.protocol == "https" or tls else "http"
            _http_request(f"{scheme}://{host}:{port}{scenario.payload}", plan.load.timeout_seconds)
        return True, (time.time() - request_started) * 1000.0, None
    except (OSError, ssl.SSLError, urllib.error.URLError, RuntimeError) as exc:
        return False, 0.0, exc.__class__.__name__


def run_fixed_rate_workload(plan: BenchmarkPlan, scenario: ScenarioPlan) -> dict:
    endpoint_host = "127.0.0.1" if plan.target.mode == "local" else plan.target.host
    host, port, tls = endpoint_for(scenario, endpoint_host)
    warmup_attempts = scenario.rate * plan.load.warmup_seconds
    measured_attempts = scenario.rate * plan.load.duration_seconds
    attempts = max(1, warmup_attempts + measured_attempts)
    interval = 1.0 / max(1, scenario.rate)
    latencies: list[float] = []
    errors: dict[str, int] = {}
    success = 0
    warmup_success = 0
    warmup_errors: dict[str, int] = {}
    started = time.time()
    measured_started = started + (warmup_attempts * interval)
    futures = {}

    with ThreadPoolExecutor(max_workers=max(1, plan.load.concurrency)) as executor:
        for index in range(attempts):
            due = started + (index * interval)
            now = time.time()
            if due > now:
                time.sleep(due - now)
            future = executor.submit(_run_one, plan, scenario, host, port, tls)
            futures[future] = index >= warmup_attempts

        for future in as_completed(futures):
            measured = futures[future]
            ok, latency_ms, error = future.result()
            if measured:
                if ok:
                    latencies.append(latency_ms)
                    success += 1
                else:
                    key = error or "Error"
                    errors[key] = errors.get(key, 0) + 1
            elif ok:
                warmup_success += 1
            else:
                key = error or "Error"
                warmup_errors[key] = warmup_errors.get(key, 0) + 1

    ended = time.time()
    return {
        "attempted": measured_attempts,
        "warmup_attempted": warmup_attempts,
        "warmup_success": warmup_success,
        "warmup_errors": sum(warmup_errors.values()),
        "warmup_error_categories": warmup_errors,
        "success": success,
        "errors": sum(errors.values()),
        "error_categories": errors,
        "started_at": started,
        "measured_started_at": measured_started,
        "ended_at": ended,
        "target_rate_per_second": scenario.rate,
        "concurrency": plan.load.concurrency,
        "duration_seconds": round(ended - started, 3),
        "measured_duration_seconds": plan.load.duration_seconds,
        "latency_ms": {
            "avg": round(sum(latencies) / len(latencies), 3) if latencies else 0.0,
            "p50": round(_percentile(latencies, 50), 3),
            "p90": round(_percentile(latencies, 90), 3),
            "p95": round(_percentile(latencies, 95), 3),
            "p99": round(_percentile(latencies, 99), 3),
        },
    }
