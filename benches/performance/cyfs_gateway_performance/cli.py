from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path

from .executor import current_time_text, run_command, write_command_log
from .image import (
    cyfs_gateway_binary_metadata,
    fixture_binary_metadata,
    image_build_plan,
    push_plan,
    reuseport_static_binary_metadata,
    source_build_commands,
    write_image_context,
)
from .metrics import run_with_resource_metrics
from .model import CommandPlan, ConfigError
from .profile import load_profile
from .report import build_result, write_reports
from .scenario import expand_scenarios
from .target import (
    cleanup_commands,
    container_logs_commands,
    container_readiness_commands,
    image_keys_for_candidates,
    local_image_check_commands,
    preflight,
    pull_commands,
    run_container_commands,
    target_metadata,
)
from .workload import run_fixed_rate_workload


EXIT_CONFIG = 2
EXIT_EXECUTION = 3


def _log(message: str) -> None:
    print(f"[performance {current_time_text()}] {message}", file=sys.stderr, flush=True)


def _command_line(command: CommandPlan) -> str:
    return shlex.join(command.command)


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--profile", required=True)
    parser.add_argument("--output")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cyfs-gateway-performance")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("build-image", "build-nginx-image", "build-cyfs-gateway-image", "run"):
        _add_common(sub.add_parser(name))
    push = sub.add_parser("push-image")
    _add_common(push)
    push.add_argument("--image", choices=("nginx", "cyfs_gateway"), required=True)
    report = sub.add_parser("report")
    report.add_argument("--profile", required=True)
    report.add_argument("--output")
    report.add_argument("--input", required=True)
    return parser


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = dict(data)
    data.setdefault("generated_at", current_time_text())
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def _command_failed_status(plan, results: list[dict]) -> str:
    if plan.registry_allow_deferral:
        return "environment-deferred"
    return "failed"


def _log_summary(status: str | None = None, *, outputs: dict | None = None, artifact: Path | None = None) -> None:
    parts = []
    if status is not None:
        parts.append(f"status={status}")
    if artifact is not None:
        parts.append(f"artifact={artifact}")
    if outputs:
        parts.extend(f"{name}={path}" for name, path in sorted(outputs.items()))
    _log("summary: " + " ".join(parts))


def _run_commands(commands, output: Path, *, timeout: int | None = None) -> list[dict]:
    evidence = []
    for index, command in enumerate(commands, start=1):
        _log(f"step {index}/{len(commands)} start: {command.description}")
        result = run_command(command, timeout=timeout)
        item = result.as_dict()
        item["log"] = write_command_log(output / "logs", f"{index:02d}-{command.description.replace(' ', '-')}.log", result)
        evidence.append(item)
        _log(
            "step {}/{} done: {} returncode={} duration={}s log={}".format(
                index,
                len(commands),
                command.description,
                item["returncode"],
                item["duration_seconds"],
                item["log"],
            )
        )
        if not result.ok:
            _log(f"step {index}/{len(commands)} failed; remaining commands skipped")
            break
    return evidence


def _run_all_commands(commands, output: Path, *, timeout: int | None = None) -> list[dict]:
    evidence = []
    for index, command in enumerate(commands, start=1):
        _log(f"step {index}/{len(commands)} start: {command.description}")
        result = run_command(command, timeout=timeout)
        item = result.as_dict()
        item["log"] = write_command_log(output / "logs", f"{index:02d}-{command.description.replace(' ', '-')}.log", result)
        evidence.append(item)
        _log(
            "step {}/{} done: {} returncode={} duration={}s log={}".format(
                index,
                len(commands),
                command.description,
                item["returncode"],
                item["duration_seconds"],
                item["log"],
            )
        )
    return evidence


def _run_single_command(command: CommandPlan, output: Path, log_name: str, *, timeout: int | None = None) -> dict:
    _log(f"step start: {command.description}")
    result = run_command(command, timeout=timeout)
    item = result.as_dict()
    item["log"] = write_command_log(output / "logs", log_name, result)
    _log(
        "step done: {} returncode={} duration={}s log={}".format(
            command.description,
            item["returncode"],
            item["duration_seconds"],
            item["log"],
        )
    )
    return item


def _remove_existing_image(plan, output: Path, image_key: str) -> list[dict]:
    image_ref = plan.images[image_key].image_ref
    inspect = CommandPlan(f"inspect existing {image_key} image", ("docker", "image", "inspect", image_ref))
    inspect_result = _run_single_command(
        inspect,
        output,
        f"00-inspect-existing-{image_key}-image.log",
        timeout=30,
    )
    evidence = [inspect_result]
    if inspect_result["returncode"] != 0:
        _log(f"existing {image_key} image not found; removal skipped")
        return evidence

    remove = CommandPlan(f"remove existing {image_key} image", ("docker", "image", "rm", "-f", image_ref))
    remove_result = _run_single_command(
        remove,
        output,
        f"00-remove-existing-{image_key}-image.log",
        timeout=120,
    )
    evidence.append(remove_result)
    return evidence


def _profile_output(plan, override: str | None = None) -> Path:
    if override:
        output = Path(override)
        return output.resolve()
    directory = plan.output.get("directory")
    if not isinstance(directory, str) or not directory:
        raise ConfigError("profile.output.directory is required")
    output = Path(directory)
    if not output.is_absolute():
        output = plan.profile_path.parent / output
    return output.resolve()


def _build_image_from_plan(plan, output: Path, image_key: str) -> dict:
    _log(f"build {image_key} image output: {output}")
    evidence: list[dict] = []
    cleanup_evidence = _remove_existing_image(plan, output, image_key)
    if cleanup_evidence[-1]["description"].startswith("remove existing ") and cleanup_evidence[-1]["returncode"] != 0:
        metadata = {
            "image": image_key,
            "image_ref": plan.images[image_key].image_ref,
            "status": _command_failed_status(plan, cleanup_evidence),
            "commands": [item["command"] for item in cleanup_evidence],
            "command_results": cleanup_evidence,
        }
        artifact = output / f"{image_key}-build-plan.json"
        _write_json(artifact, metadata)
        _log(f"build {image_key} image failed while removing existing target image")
        _log_summary(metadata["status"], artifact=artifact)
        return metadata
    evidence.extend(cleanup_evidence)
    if image_key == "cyfs_gateway":
        _log("writing cyfs_gateway Docker context")
        metadata = write_image_context(plan, image_key, output)
        context = Path(metadata["dockerfile"]).parent
        source_commands = source_build_commands(plan, context)
        for command in source_commands:
            _log(f"cyfs_gateway source build command: {_command_line(command)}")
        _log("building cyfs_gateway from current source")
        evidence.extend(_run_commands(source_commands, output, timeout=3600))
        if evidence and evidence[-1]["returncode"] != 0:
            _log("cyfs_gateway source build failed")
            metadata["status"] = _command_failed_status(plan, evidence)
            metadata["commands"] = [item["command"] for item in evidence]
            metadata["command_results"] = evidence
            artifact = output / f"{image_key}-build-plan.json"
            _write_json(artifact, metadata)
            _log_summary(metadata["status"], artifact=artifact)
            return metadata
        source_metadata = cyfs_gateway_binary_metadata(plan, context)
        _log(f"cyfs_gateway compiled binary path: {source_metadata['expected_binary']}")
        _log(f"cyfs_gateway packaged binary path: {source_metadata['packaged_binary']}")
    else:
        _log(f"writing {image_key} Docker context")
        metadata = write_image_context(plan, image_key, output)
    _, commands = image_build_plan(plan, image_key, output)
    _log(f"running {len(commands)} image build command(s)")
    evidence.extend(_run_commands(commands, output, timeout=3600))
    context = Path(metadata["dockerfile"]).parent
    metadata["packaged_reverse_proxy_fixture"].update(fixture_binary_metadata(context))
    metadata["packaged_reuseport_static_fixture"].update(reuseport_static_binary_metadata(context))
    if image_key == "cyfs_gateway":
        metadata["source_build"] = cyfs_gateway_binary_metadata(plan, Path(metadata["dockerfile"]).parent)
    metadata["commands"] = [item["command"] for item in evidence]
    status = "built" if evidence and evidence[-1]["returncode"] == 0 else _command_failed_status(plan, evidence)
    push_evidence: list[dict] = []
    if status == "built" and plan.registry_push:
        _log(f"pushing {image_key} image to configured registry")
        push_commands = push_plan(plan, image_key)
        push_evidence = _run_commands(push_commands, output, timeout=120)
        metadata["push_commands"] = [item["command"] for item in push_evidence]
        metadata["push_results"] = push_evidence
        status = "pushed" if push_evidence and push_evidence[-1]["returncode"] == 0 else _command_failed_status(plan, push_evidence)
    elif not plan.registry_push:
        metadata["push_skipped"] = "registry.push is false"
    metadata["status"] = status
    metadata["command_results"] = evidence
    artifact = output / f"{image_key}-build-plan.json"
    _write_json(artifact, metadata)
    _log(f"build {image_key} image finished with status={status}")
    _log_summary(status, artifact=artifact)
    return metadata


def _build_image(args: argparse.Namespace, image_key: str) -> int:
    _log(f"loading profile: {args.profile}")
    plan = load_profile(args.profile)
    output = _profile_output(plan, args.output)
    metadata = _build_image_from_plan(plan, output, image_key)
    status = metadata["status"]
    return 0 if status in {"built", "pushed", "environment-deferred"} else EXIT_EXECUTION


def _build_images(args: argparse.Namespace) -> int:
    _log(f"loading profile: {args.profile}")
    plan = load_profile(args.profile)
    output = _profile_output(plan, args.output)
    images = {}
    status = "built"
    for image_key in ("nginx", "cyfs_gateway"):
        metadata = _build_image_from_plan(plan, output, image_key)
        images[image_key] = metadata
        if metadata["status"] == "failed":
            status = "failed"
            break
        if metadata["status"] == "environment-deferred":
            status = "environment-deferred"
        elif metadata["status"] == "pushed" and status == "built":
            status = "pushed"
    result = {"status": status, "images": images}
    artifact = output / "build-image-plan.json"
    _write_json(artifact, result)
    _log(f"build all images finished with status={status}")
    _log_summary(status, artifact=artifact)
    return 0 if status in {"built", "pushed", "environment-deferred"} else EXIT_EXECUTION


def _push_image(args: argparse.Namespace) -> int:
    _log(f"loading profile: {args.profile}")
    plan = load_profile(args.profile)
    output = _profile_output(plan, args.output)
    _log(f"push {args.image} image output: {output}")
    commands = push_plan(plan, args.image)
    if commands:
        _log(f"running {len(commands)} image push command(s)")
        evidence = _run_commands(commands, output, timeout=120)
        status = "pushed" if evidence and evidence[-1]["returncode"] == 0 else _command_failed_status(plan, evidence)
        push_skipped = None
    else:
        _log("image push skipped because registry.push is false")
        evidence = []
        status = "skipped"
        push_skipped = "registry.push is false"
    metadata = {
        "image": args.image,
        "image_ref": plan.images[args.image].image_ref,
        "status": status,
        "commands": [list(item.command) for item in commands],
        "command_results": evidence,
    }
    if push_skipped:
        metadata["push_skipped"] = push_skipped
    artifact = output / f"{args.image}-push-plan.json"
    _write_json(artifact, metadata)
    _log(f"push {args.image} image finished with status={status}")
    _log_summary(status, artifact=artifact)
    return 0 if status in {"pushed", "skipped", "environment-deferred"} else EXIT_EXECUTION


def _run(args: argparse.Namespace) -> int:
    _log(f"loading profile: {args.profile}")
    plan = load_profile(args.profile)
    output = _profile_output(plan, args.output)
    _log(f"benchmark output: {output}")
    scenarios = expand_scenarios(plan)
    _log(f"expanded {len(scenarios)} benchmark scenario(s)")
    _log("running target preflight")
    target = preflight(plan)
    _log(
        "preflight result: mode={} host={} os_id={} ubuntu_detected={} debian_detected={} docker={} can_run_benchmark={}".format(
            target["target_mode"],
            target["target_host"],
            target["os_id"] or "",
            target["ubuntu_detected"],
            target["debian_detected"],
            target["docker"] or "",
            target["can_run_benchmark"],
        )
    )
    evidence = {
        "preflight": target,
        "target_metadata": target_metadata(plan),
        "pull": [],
        "deploy": [],
        "readiness": [],
        "container_logs": [],
        "cleanup": [],
        "deferrals": [],
        "registry": {
            "push": plan.registry_push,
            "pull_policy": plan.registry_pull_policy,
            "allow_deferral": plan.registry_allow_deferral,
        },
    }
    if target["unsupported_os"]:
        message = target["unsupported_os_error"]
        _log(message)
        evidence["deferrals"].append(message)
        status = "failed"
        result = build_result(plan, scenarios, status, evidence, rows=[])
        outputs = write_reports(result, output, csv_enabled=bool((plan.output.get("formats") or {}).get("csv", False)))
        _log(f"reports written: {outputs}")
        _log_summary(status, outputs=outputs)
        print(f"configuration error: {message}", file=sys.stderr)
        return EXIT_CONFIG
    if not target["can_run_benchmark"]:
        _log("benchmark target environment unavailable; writing deferred report")
        evidence["deferrals"].append("benchmark target environment is unavailable or lacks Docker")
        status = "environment-deferred"
        result = build_result(plan, scenarios, status, evidence, rows=[])
        outputs = write_reports(result, output, csv_enabled=bool((plan.output.get("formats") or {}).get("csv", False)))
        _log(f"reports written: {outputs}")
        _log_summary(status, outputs=outputs)
        return 0 if plan.registry_allow_deferral else EXIT_EXECUTION

    try:
        _log("cleanup before deployment")
        evidence["cleanup"].extend(_run_all_commands(cleanup_commands(plan), output, timeout=60))
        pull_plan = pull_commands(plan)
        if pull_plan:
            _log("pulling benchmark images")
            evidence["pull"].extend(_run_commands(pull_plan, output, timeout=120))
        else:
            _log("image pull skipped because registry.pull_policy is never")
            evidence["pull_skipped"] = {
                "reason": "registry.pull_policy is never",
                "image_refs": [plan.images[image_key].image_ref for image_key in image_keys_for_candidates(plan)],
            }
            _log("checking required local benchmark images")
            evidence["local_images"] = _run_all_commands(local_image_check_commands(plan), output, timeout=30)
            missing_local_images = [item for item in evidence["local_images"] if item["returncode"] != 0]
            if missing_local_images:
                _log("one or more local benchmark images are missing; writing failed report")
                status = "failed"
                result = build_result(plan, scenarios, status, evidence, rows=[])
                outputs = write_reports(
                    result,
                    output,
                    csv_enabled=bool((plan.output.get("formats") or {}).get("csv", False)),
                )
                _log(f"reports written: {outputs}")
                _log_summary(status, outputs=outputs)
                return EXIT_EXECUTION
        if evidence["pull"] and evidence["pull"][-1]["returncode"] != 0:
            _log("image pull failed; writing deferred or failed report")
            evidence["deferrals"].append("configured registry image pull failed")
            status = "environment-deferred" if plan.registry_allow_deferral else "failed"
            result = build_result(plan, scenarios, status, evidence, rows=[])
            outputs = write_reports(result, output, csv_enabled=bool((plan.output.get("formats") or {}).get("csv", False)))
            _log(f"reports written: {outputs}")
            _log_summary(status, outputs=outputs)
            return 0 if plan.registry_allow_deferral else EXIT_EXECUTION

        _log("deploying benchmark containers")
        evidence["deploy"].extend(_run_commands(run_container_commands(plan), output, timeout=120))
        if evidence["deploy"] and evidence["deploy"][-1]["returncode"] != 0:
            _log("container deployment failed; writing failed report")
            status = "failed"
            result = build_result(plan, scenarios, status, evidence, rows=[])
            outputs = write_reports(result, output, csv_enabled=bool((plan.output.get("formats") or {}).get("csv", False)))
            _log(f"reports written: {outputs}")
            _log_summary(status, outputs=outputs)
            return EXIT_EXECUTION

        _log("checking benchmark containers are still running")
        evidence["readiness"].extend(_run_all_commands(container_readiness_commands(plan), output, timeout=30))
        not_running = [
            item
            for item in evidence["readiness"]
            if item["returncode"] != 0 or str(item.get("stdout") or "").strip().lower() != "true"
        ]
        if not_running:
            _log("one or more benchmark containers exited after deployment; collecting logs")
            evidence["container_logs"].extend(_run_all_commands(container_logs_commands(plan), output, timeout=60))
            status = "failed"
            result = build_result(plan, scenarios, status, evidence, rows=[])
            outputs = write_reports(result, output, csv_enabled=bool((plan.output.get("formats") or {}).get("csv", False)))
            _log(f"reports written: {outputs}")
            _log_summary(status, outputs=outputs)
            return EXIT_EXECUTION

        rows = []
        for index, scenario in enumerate(scenarios, start=1):
            _log(
                "scenario {}/{} start: candidate={} scenario={} protocol={} stream_mode={} connection_reuse={} rate={} payload={}".format(
                    index,
                    len(scenarios),
                    scenario.candidate,
                    scenario.scenario,
                    scenario.protocol,
                    scenario.stream_mode or "",
                    scenario.connection_reuse,
                    scenario.rate,
                    scenario.payload,
                )
            )
            request_metrics, resource_metrics = run_with_resource_metrics(
                plan,
                scenario,
                lambda scenario=scenario: run_fixed_rate_workload(plan, scenario),
            )
            _log(
                "scenario {}/{} workload done: success={} errors={} duration={}s".format(
                    index,
                    len(scenarios),
                    request_metrics["success"],
                    request_metrics["errors"],
                    request_metrics["duration_seconds"],
                )
            )
            _log(
                "scenario {}/{} metrics done: sampling={} cpu_avg={} memory_avg={}".format(
                    index,
                    len(scenarios),
                    resource_metrics["sampling"],
                    resource_metrics["cpu_percent_avg"],
                    resource_metrics["memory_bytes_avg"],
                )
            )
            rows.append(
                {
                    "candidate": scenario.candidate,
                    "scenario": scenario.scenario,
                    "protocol": scenario.protocol,
                    "stream_mode": scenario.stream_mode,
                    "connection_reuse": scenario.connection_reuse,
                    "rate": scenario.rate,
                    "payload": scenario.payload,
                    "requests": request_metrics,
                    "resources": resource_metrics,
                }
            )
        _log("collecting container logs")
        evidence["container_logs"].extend(_run_all_commands(container_logs_commands(plan), output, timeout=60))
        status = "completed"
        result = build_result(plan, scenarios, status, evidence, rows=rows)
    finally:
        _log("cleanup after benchmark")
        evidence["cleanup"].extend(_run_all_commands(cleanup_commands(plan), output, timeout=60))

    outputs = write_reports(result, output, csv_enabled=bool((plan.output.get("formats") or {}).get("csv", False)))
    _log(f"reports written: {outputs}")
    _log_summary(status, outputs=outputs)
    return 0 if status in {"completed", "environment-deferred"} else EXIT_EXECUTION


def _report(args: argparse.Namespace) -> int:
    _log(f"loading profile: {args.profile}")
    plan = load_profile(args.profile)
    _log(f"loading result input: {args.input}")
    result = json.loads(Path(args.input).read_text(encoding="utf-8"))
    output = _profile_output(plan, args.output)
    outputs = write_reports(result, output, csv_enabled=bool((plan.output.get("formats") or {}).get("csv", False)))
    _log(f"reports written: {outputs}")
    _log_summary(outputs=outputs)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "build-image":
            return _build_images(args)
        if args.command == "build-nginx-image":
            return _build_image(args, "nginx")
        if args.command == "build-cyfs-gateway-image":
            return _build_image(args, "cyfs_gateway")
        if args.command == "push-image":
            return _push_image(args)
        if args.command == "run":
            return _run(args)
        if args.command == "report":
            return _report(args)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except OSError as exc:
        print(f"execution error: {exc}", file=sys.stderr)
        return EXIT_EXECUTION
    return 1
