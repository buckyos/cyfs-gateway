from __future__ import annotations

import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.client import HTTPConnection, HTTPException, HTTPSConnection
from queue import Empty, Queue

from .model import BenchmarkPlan, ScenarioPlan
from .vegeta import VegetaUnavailable, ensure_vegeta


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


def stream_tls_server_name(plan: BenchmarkPlan) -> str:
    tls = (plan.generated_config.get("tls") or {}) if isinstance(plan.generated_config, dict) else {}
    return str(tls.get("common_name") or "perf.local")


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


class _ReusableConnection:
    def __init__(self, plan: BenchmarkPlan, scenario: ScenarioPlan, host: str, port: int, tls: bool) -> None:
        self.plan = plan
        self.scenario = scenario
        self.host = host
        self.port = port
        self.tls = tls
        self.server_name = stream_tls_server_name(plan)
        self._http: HTTPConnection | HTTPSConnection | None = None
        self._stream: socket.socket | None = None

    def close(self) -> None:
        if self._http is not None:
            self._http.close()
            self._http = None
        if self._stream is not None:
            self._stream.close()
            self._stream = None

    def request(self) -> None:
        try:
            if self.scenario.scenario == "stream_reverse_proxy":
                self._stream_request()
            else:
                self._http_request()
        except Exception:
            self.close()
            raise

    def _http_request(self) -> None:
        if self._http is None:
            timeout = self.plan.load.timeout_seconds
            if self.scenario.protocol == "https" or self.tls:
                context = ssl._create_unverified_context()
                self._http = HTTPSConnection(self.host, self.port, timeout=timeout, context=context)
            else:
                self._http = HTTPConnection(self.host, self.port, timeout=timeout)
        self._http.request("GET", self.scenario.payload)
        response = self._http.getresponse()
        response.read()
        if response.status < 200 or response.status >= 300:
            raise RuntimeError(f"HTTP status {response.status}")
        if response.getheader("connection", "").lower() == "close":
            self.close()

    def _stream_request(self) -> None:
        if self._stream is None:
            raw = socket.create_connection((self.host, self.port), timeout=self.plan.load.timeout_seconds)
            self._stream = (
                ssl._create_unverified_context().wrap_socket(raw, server_hostname=self.server_name) if self.tls else raw
            )
            self._stream.settimeout(self.plan.load.timeout_seconds)
        payload = b"cyfs-performance-stream-payload"
        self._stream.sendall(payload)
        received = self._stream.recv(len(payload))
        if received != payload:
            raise RuntimeError("stream echo payload mismatch")


def _run_one(plan: BenchmarkPlan, scenario: ScenarioPlan, host: str, port: int, tls: bool) -> tuple[bool, float, str | None]:
    request_started = time.time()
    try:
        if scenario.scenario == "stream_reverse_proxy":
            _stream_request(host, port, plan.load.timeout_seconds, tls, stream_tls_server_name(plan))
        else:
            scheme = "https" if scenario.protocol == "https" or tls else "http"
            _http_request(f"{scheme}://{host}:{port}{scenario.payload}", plan.load.timeout_seconds)
        return True, (time.time() - request_started) * 1000.0, None
    except (OSError, ssl.SSLError, urllib.error.URLError, RuntimeError) as exc:
        return False, 0.0, exc.__class__.__name__


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
    ]
    if scenario.protocol == "https":
        attack_command.append("-insecure")

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
    url = f"{scheme}://{host}:{port}{scenario.payload}"
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


def _run_reused_connections(
    plan: BenchmarkPlan,
    scenario: ScenarioPlan,
    host: str,
    port: int,
    tls: bool,
    attempts: int,
    warmup_attempts: int,
    interval: float,
    started: float,
) -> tuple[list[float], int, dict[str, int], int, dict[str, int]]:
    work: Queue[tuple[int, float, bool]] = Queue()
    for index in range(attempts):
        work.put((index, started + (index * interval), index >= warmup_attempts))

    latencies: list[float] = []
    errors: dict[str, int] = {}
    warmup_success = 0
    warmup_errors: dict[str, int] = {}

    def worker() -> tuple[list[float], int, dict[str, int], dict[str, int]]:
        session = _ReusableConnection(plan, scenario, host, port, tls)
        local_latencies: list[float] = []
        local_warmup_success = 0
        local_errors: dict[str, int] = {}
        local_warmup_errors: dict[str, int] = {}
        try:
            while True:
                try:
                    _, due, measured = work.get_nowait()
                except Empty:
                    break
                now = time.time()
                if due > now:
                    time.sleep(due - now)
                request_started = time.time()
                try:
                    session.request()
                    latency_ms = (time.time() - request_started) * 1000.0
                    if measured:
                        local_latencies.append(latency_ms)
                    else:
                        local_warmup_success += 1
                except (OSError, ssl.SSLError, urllib.error.URLError, HTTPException, RuntimeError) as exc:
                    target = local_errors if measured else local_warmup_errors
                    key = exc.__class__.__name__
                    target[key] = target.get(key, 0) + 1
                finally:
                    work.task_done()
        finally:
            session.close()
        return local_latencies, local_warmup_success, local_errors, local_warmup_errors

    with ThreadPoolExecutor(max_workers=max(1, plan.load.concurrency)) as executor:
        futures = [executor.submit(worker) for _ in range(max(1, plan.load.concurrency))]
        for future in as_completed(futures):
            worker_latencies, worker_warmup_success, worker_errors, worker_warmup_errors = future.result()
            latencies.extend(worker_latencies)
            warmup_success += worker_warmup_success
            for key, value in worker_errors.items():
                errors[key] = errors.get(key, 0) + value
            for key, value in worker_warmup_errors.items():
                warmup_errors[key] = warmup_errors.get(key, 0) + value

    return latencies, warmup_success, errors, sum(warmup_errors.values()), warmup_errors


def run_fixed_rate_workload(plan: BenchmarkPlan, scenario: ScenarioPlan) -> dict:
    endpoint_host = "127.0.0.1" if plan.target.mode == "local" else plan.target.host
    host, port, tls = endpoint_for(scenario, endpoint_host)
    if scenario.scenario != "stream_reverse_proxy":
        return _run_vegeta_http_workload(plan, scenario, host, port, tls)
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
    if scenario.connection_reuse == "reuse_connection":
        latencies, warmup_success, errors, warmup_error_count, warmup_errors = _run_reused_connections(
            plan,
            scenario,
            host,
            port,
            tls,
            attempts,
            warmup_attempts,
            interval,
            started,
        )
        success = len(latencies)
    else:
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
        warmup_error_count = sum(warmup_errors.values())

    ended = time.time()
    actual_attempted = success + sum(errors.values())
    measured_elapsed = max(0.001, ended - measured_started)
    return {
        "attempted": measured_attempts,
        "actual_attempted": actual_attempted,
        "warmup_attempted": warmup_attempts,
        "warmup_actual_attempted": warmup_success + warmup_error_count,
        "warmup_success": warmup_success,
        "warmup_errors": warmup_error_count,
        "warmup_error_categories": warmup_errors,
        "success": success,
        "errors": sum(errors.values()),
        "error_categories": errors,
        "started_at": started,
        "measured_started_at": measured_started,
        "ended_at": ended,
        "target_rate_per_second": scenario.rate,
        "actual_rate_per_second": round(actual_attempted / measured_elapsed, 3),
        "concurrency": plan.load.concurrency,
        "connection_reuse": scenario.connection_reuse,
        "engine": "builtin-stream",
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
