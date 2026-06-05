from __future__ import annotations

import socket
import ssl
import subprocess
import time
import urllib.request

from .model import BenchmarkPlan, ScenarioPlan
from .vegeta import VegetaUnavailable, ensure_vegeta


def endpoint_for(scenario: ScenarioPlan, host: str = "127.0.0.1") -> tuple[str, int, bool]:
    if scenario.candidate == "nginx_hyper":
        return host, 18180, False
    if scenario.candidate == "cyfs_gateway_hyper":
        return host, 28180, False
    if scenario.candidate == "nginx_reuseport_static":
        return host, 18181, False
    if scenario.candidate == "cyfs_gateway_reuseport_static":
        return host, 28181, False
    if scenario.candidate == "nginx_reuseport_dirserver":
        return host, 18182, False
    if scenario.candidate == "cyfs_gateway_reuseport_dirserver":
        return host, 28182, False
    if scenario.scenario == "stream_reverse_proxy":
        tls = scenario.protocol == "https"
        if scenario.candidate == "nginx":
            return host, 19443 if tls else 19080, tls
        return host, 29443 if tls else 29080, tls
    if scenario.protocol == "https":
        if scenario.candidate == "nginx":
            return host, 18443, True
        return host, 28443, True
    if scenario.candidate == "nginx":
        return host, 18080, False
    return host, 28080, False


def stream_tls_server_name(plan: BenchmarkPlan) -> str:
    tls = (plan.generated_config.get("tls") or {}) if isinstance(plan.generated_config, dict) else {}
    return str(tls.get("common_name") or "perf.local")


def tls_server_name(plan: BenchmarkPlan) -> str:
    return stream_tls_server_name(plan)


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


def _read_until_header_end(reader) -> tuple[bytes, bytes]:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = reader.read(1)
        if not chunk:
            raise RuntimeError("HTTP response closed before headers")
        data.extend(chunk)
        if len(data) > 1024 * 1024:
            raise RuntimeError("HTTP response headers too large")
    split_at = data.index(b"\r\n\r\n") + 4
    return bytes(data[:split_at]), bytes(data[split_at:])


def _parse_http_response(headers: bytes) -> tuple[int, int | None, bool]:
    text = headers.decode("iso-8859-1", errors="replace")
    lines = text.split("\r\n")
    parts = lines[0].split()
    if len(parts) < 2 or not parts[1].isdigit():
        raise RuntimeError("invalid HTTP response status line")
    status = int(parts[1])
    content_length: int | None = None
    close_after_response = False
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        header = name.strip().lower()
        if header == "content-length":
            content_length = int(value.strip())
        elif header == "connection" and value.strip().lower() == "close":
            close_after_response = True
    return status, content_length, close_after_response


def _read_http_body(reader, buffered: bytes, content_length: int | None) -> None:
    if content_length is None:
        while reader.read(64 * 1024):
            pass
        return
    remaining = content_length - len(buffered)
    while remaining > 0:
        chunk = reader.read(min(remaining, 64 * 1024))
        if not chunk:
            raise RuntimeError("HTTP response closed before body completed")
        remaining -= len(chunk)


def _http_endpoint_request(
    host: str,
    port: int,
    path: str,
    timeout: int,
    tls: bool,
    server_name: str,
) -> None:
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        sock = ssl._create_unverified_context().wrap_socket(raw, server_hostname=server_name) if tls else raw
        with sock:
            sock.settimeout(timeout)
            reader = sock.makefile("rb")
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {server_name}\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode("ascii")
            sock.sendall(request)
            headers, buffered = _read_until_header_end(reader)
            status, content_length, _ = _parse_http_response(headers)
            _read_http_body(reader, buffered, content_length)
            if status < 200 or status >= 300:
                raise RuntimeError(f"HTTP status {status}")
    finally:
        raw.close()


def _stream_request(host: str, port: int, timeout: int, tls: bool, server_name: str | None = None) -> None:
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        sock = ssl._create_unverified_context().wrap_socket(raw, server_hostname=server_name or host) if tls else raw
        with sock:
            sock.settimeout(timeout)
            payload = b"cyfs-performance-stream-payload"
            sock.sendall(payload)
            received = sock.recv(len(payload))
            if received != payload:
                raise RuntimeError("stream echo payload mismatch")
    finally:
        raw.close()


def _latency_ms(value) -> float:
    if isinstance(value, (int, float)):
        return float(value) / 1_000_000.0
    if isinstance(value, str):
        try:
            return float(value) / 1_000_000.0
        except ValueError:
            return 0.0
    return 0.0


def _run_vegeta_attack(
    vegeta: str,
    plan: BenchmarkPlan,
    scenario: ScenarioPlan,
    url: str,
    duration_seconds: int,
    connect_to: str | None = None,
) -> tuple[list[float], dict[str, int], int, dict]:
    if duration_seconds <= 0:
        return [], {}, 0, {"attack": None, "encode": None}

    target = f"GET {url}\n".encode("utf-8")
    attack_command = [
        vegeta,
        "attack",
        "-rate",
        f"{scenario.rate}/s",
        "-duration",
        f"{duration_seconds}s",
        "-timeout",
        f"{plan.load.timeout_seconds}s",
        "-workers",
        str(max(1, plan.load.concurrency)),
        f"-keepalive={'true' if scenario.connection_reuse == 'reuse_connection' else 'false'}",
        "-max-body",
        "0",
    ]
    if scenario.protocol == "https":
        attack_command.append("-insecure")
    if connect_to:
        attack_command.extend(["-connect-to", connect_to])

    started = time.time()
    attack = subprocess.run(attack_command, input=target, capture_output=True, check=False)
    attack_ended = time.time()
    if attack.returncode != 0:
        raise RuntimeError(attack.stderr.decode("utf-8", errors="replace") or "vegeta attack failed")

    encode_command = [vegeta, "encode", "-to=json"]
    encode = subprocess.run(encode_command, input=attack.stdout, capture_output=True, check=False)
    if encode.returncode != 0:
        raise RuntimeError(encode.stderr.decode("utf-8", errors="replace") or "vegeta encode failed")

    latencies: list[float] = []
    errors: dict[str, int] = {}
    actual_attempted = 0
    for line in encode.stdout.decode("utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        actual_attempted += 1
        item = json_loads(line)
        code = int(item.get("code") or 0)
        error = str(item.get("error") or "")
        if error:
            errors[error] = errors.get(error, 0) + 1
        elif code < 200 or code >= 300:
            key = f"HTTP_{code}"
            errors[key] = errors.get(key, 0) + 1
        else:
            latencies.append(_latency_ms(item.get("latency")))

    return latencies, errors, actual_attempted, {
        "attack": {
            "command": attack_command,
            "returncode": attack.returncode,
            "stderr": attack.stderr.decode("utf-8", errors="replace"),
            "started_at": started,
            "ended_at": attack_ended,
        },
        "encode": {
            "command": encode_command,
            "returncode": encode.returncode,
            "stderr": encode.stderr.decode("utf-8", errors="replace"),
        },
    }


def json_loads(line: str) -> dict:
    import json

    loaded = json.loads(line)
    if not isinstance(loaded, dict):
        raise RuntimeError("vegeta encode produced a non-object JSON row")
    return loaded


def _run_vegeta_http_workload(plan: BenchmarkPlan, scenario: ScenarioPlan, host: str, port: int, tls: bool) -> dict:
    planned_warmup = scenario.rate * plan.load.warmup_seconds
    planned_measured = scenario.rate * plan.load.duration_seconds
    scheme = "https" if scenario.protocol == "https" or tls else "http"
    url_host = tls_server_name(plan) if scheme == "https" else host
    url = f"{scheme}://{url_host}:{port}{scenario.payload}"
    connect_to = f"{url_host}:{port}:{host}:{port}" if url_host != host else None
    started = time.time()
    measured_started = started
    warmup_success = 0
    warmup_errors: dict[str, int] = {}
    warmup_actual = 0
    command_evidence: dict[str, dict | None] = {}
    vegeta_metadata: dict = {}

    try:
        vegeta_path, vegeta_metadata = ensure_vegeta()
        if plan.load.warmup_seconds:
            warmup_latencies, warmup_errors, warmup_actual, warmup_command = _run_vegeta_attack(
                str(vegeta_path),
                plan,
                scenario,
                url,
                plan.load.warmup_seconds,
                connect_to,
            )
            warmup_success = len(warmup_latencies)
            command_evidence["warmup"] = warmup_command
        measured_started = time.time()
        latencies, errors, actual_attempted, measured_command = _run_vegeta_attack(
            str(vegeta_path),
            plan,
            scenario,
            url,
            plan.load.duration_seconds,
            connect_to,
        )
        command_evidence["measured"] = measured_command
    except (OSError, RuntimeError, VegetaUnavailable) as exc:
        ended = time.time()
        return {
            "attempted": planned_measured,
            "actual_attempted": 0,
            "warmup_attempted": planned_warmup,
            "warmup_actual_attempted": warmup_actual,
            "warmup_success": warmup_success,
            "warmup_errors": sum(warmup_errors.values()),
            "warmup_error_categories": warmup_errors,
            "success": 0,
            "errors": planned_measured,
            "error_categories": {exc.__class__.__name__: planned_measured},
            "started_at": started,
            "measured_started_at": measured_started,
            "ended_at": ended,
            "target_rate_per_second": scenario.rate,
            "actual_rate_per_second": 0.0,
            "concurrency": plan.load.concurrency,
            "connection_reuse": scenario.connection_reuse,
            "engine": "vegeta",
            "vegeta": vegeta_metadata,
            "vegeta_commands": command_evidence,
            "duration_seconds": round(ended - started, 3),
            "measured_duration_seconds": plan.load.duration_seconds,
            "latency_ms": {"avg": 0.0, "p50": 0.0, "p90": 0.0, "p95": 0.0, "p99": 0.0},
        }

    ended = time.time()
    attack_window = measured_command.get("attack") or {}
    measured_elapsed = max(
        0.001,
        float(attack_window.get("ended_at") or ended) - float(attack_window.get("started_at") or measured_started),
    )
    return {
        "attempted": planned_measured,
        "actual_attempted": actual_attempted,
        "warmup_attempted": planned_warmup,
        "warmup_actual_attempted": warmup_actual,
        "warmup_success": warmup_success,
        "warmup_errors": sum(warmup_errors.values()),
        "warmup_error_categories": warmup_errors,
        "success": len(latencies),
        "errors": sum(errors.values()),
        "error_categories": errors,
        "started_at": started,
        "measured_started_at": measured_started,
        "ended_at": ended,
        "target_rate_per_second": scenario.rate,
        "actual_rate_per_second": round(actual_attempted / measured_elapsed, 3),
        "concurrency": plan.load.concurrency,
        "connection_reuse": scenario.connection_reuse,
        "engine": "vegeta",
        "vegeta": vegeta_metadata,
        "vegeta_commands": command_evidence,
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


def run_fixed_rate_workload(plan: BenchmarkPlan, scenario: ScenarioPlan) -> dict:
    endpoint_host = "127.0.0.1" if plan.target.mode == "local" else plan.target.host
    host, port, tls = endpoint_for(scenario, endpoint_host)
    if scenario.protocol in {"http", "https"}:
        return _run_vegeta_http_workload(plan, scenario, host, port, tls)
    raise RuntimeError(f"unsupported non-HTTP workload protocol for vegeta runner: {scenario.protocol}")
