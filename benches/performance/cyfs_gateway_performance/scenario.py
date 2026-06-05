from __future__ import annotations

from .model import BenchmarkPlan, ConfigError, ScenarioPlan


HYPER_STATIC_CANDIDATES = ("nginx_hyper", "cyfs_gateway_hyper")
REUSEPORT_STATIC_CANDIDATES = ("nginx_reuseport_static", "cyfs_gateway_reuseport_static")
REUSEPORT_DIRSERVER_CANDIDATES = ("nginx_reuseport_dirserver", "cyfs_gateway_reuseport_dirserver")


def reuseport_static_enabled(plan: BenchmarkPlan) -> bool:
    fixture = plan.upstream.get("reuseport_static_fixture") if isinstance(plan.upstream, dict) else None
    if not isinstance(fixture, dict):
        return False
    return bool(fixture.get("enabled", False))


def reuseport_dirserver_enabled(plan: BenchmarkPlan) -> bool:
    fixture = plan.upstream.get("reuseport_dirserver_fixture") if isinstance(plan.upstream, dict) else None
    if not isinstance(fixture, dict):
        return False
    return bool(fixture.get("enabled", False))


def _scenario_paths(config: dict, default: str) -> list[str]:
    paths = config.get("paths")
    if isinstance(paths, list) and paths:
        return [str(path) for path in paths]
    return [str(config.get("path") or default)]


def expand_scenarios(plan: BenchmarkPlan) -> list[ScenarioPlan]:
    protocols = [name for name, enabled in plan.protocols.items() if enabled and name in {"http", "https"}]
    if not protocols:
        raise ConfigError("protocols must enable http or https")

    scenarios: list[tuple[str, list[str], list[str | None]]] = []
    static = plan.scenarios.get("static_http_file") or {}
    if static.get("enabled", False):
        scenarios.append(("static_http_file", _scenario_paths(static, "/"), [None]))
    proxy = plan.scenarios.get("http_reverse_proxy") or {}
    if proxy.get("enabled", False):
        scenarios.append(("http_reverse_proxy", _scenario_paths(proxy, "/proxy/payload"), [None]))
    stream = plan.scenarios.get("stream_reverse_proxy") or {}
    if stream.get("enabled", False):
        scenarios.append(("stream_reverse_proxy", _scenario_paths(stream, "/index.html"), [None]))
    if not scenarios:
        raise ConfigError("at least one required scenario must be enabled")

    result: list[ScenarioPlan] = []
    reuseport_enabled = reuseport_static_enabled(plan)
    dirserver_enabled = reuseport_dirserver_enabled(plan)
    for candidate in plan.candidates:
        if candidate in REUSEPORT_STATIC_CANDIDATES and not reuseport_enabled:
            continue
        if candidate in REUSEPORT_DIRSERVER_CANDIDATES and not dirserver_enabled:
            continue
        for scenario, payloads, stream_modes in scenarios:
            scenario_protocols = protocols
            if candidate in HYPER_STATIC_CANDIDATES or candidate in REUSEPORT_STATIC_CANDIDATES or candidate in REUSEPORT_DIRSERVER_CANDIDATES:
                if scenario != "static_http_file":
                    continue
                scenario_protocols = [protocol for protocol in scenario_protocols if protocol == "http"]
            for protocol in scenario_protocols:
                for payload in payloads:
                    for mode in stream_modes:
                        for rate in plan.load.rates:
                            for reuse_mode in plan.load.connection_reuse_modes:
                                result.append(ScenarioPlan(candidate, scenario, protocol, rate, payload, mode, reuse_mode))
    if not result:
        raise ConfigError("configured candidates, protocols, and scenarios produced no benchmark cases")
    return result
