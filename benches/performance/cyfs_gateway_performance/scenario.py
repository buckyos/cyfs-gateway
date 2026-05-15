from __future__ import annotations

from .model import BenchmarkPlan, ConfigError, ScenarioPlan


CANDIDATES = ("nginx", "cyfs_gateway")


def expand_scenarios(plan: BenchmarkPlan) -> list[ScenarioPlan]:
    protocols = [name for name, enabled in plan.protocols.items() if enabled and name in {"http", "https"}]
    if not protocols:
        raise ConfigError("protocols must enable http or https")

    scenarios: list[tuple[str, list[str], list[str | None]]] = []
    static = plan.scenarios.get("static_http_file") or {}
    if static.get("enabled", False):
        paths = static.get("paths") or ["/"]
        scenarios.append(("static_http_file", [str(path) for path in paths], [None]))
    proxy = plan.scenarios.get("http_reverse_proxy") or {}
    if proxy.get("enabled", False):
        scenarios.append(("http_reverse_proxy", [str(proxy.get("path") or "/")], [None]))
    stream = plan.scenarios.get("stream_reverse_proxy") or {}
    if stream.get("enabled", False):
        modes = [str(mode) for mode in stream.get("modes", ["tcp", "tcp_tls"])]
        scenarios.append(("stream_reverse_proxy", ["stream"], modes))
    if not scenarios:
        raise ConfigError("at least one required scenario must be enabled")

    result: list[ScenarioPlan] = []
    for candidate in CANDIDATES:
        for scenario, payloads, stream_modes in scenarios:
            scenario_protocols = protocols if scenario != "stream_reverse_proxy" else ["tcp"]
            for protocol in scenario_protocols:
                for payload in payloads:
                    for mode in stream_modes:
                        for rate in plan.load.rates:
                            result.append(ScenarioPlan(candidate, scenario, protocol, rate, payload, mode))
    return result
