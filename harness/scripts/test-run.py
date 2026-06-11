#!/usr/bin/env python3

import argparse
import datetime
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_VERSION = "v0.6"
RUN_ARTIFACT_SCHEMA = 1
ALLOWED_LEVELS = ("unit", "dv", "integration")
LEVEL_CHOICES = (*ALLOWED_LEVELS, "all")
ALLOWED_MODES = {"enabled", "manual", "disabled"}
ALLOWED_ROOT_KEYS = {"schema_version", "version", "module", "defaults", "levels"}
ALLOWED_DEFAULT_KEYS = {"workdir", "timeout_sec", "env"}
ALLOWED_LEVEL_KEYS = {"mode", "summary", "test_targets", "preconditions", "steps"}
ALLOWED_PRECONDITION_KEYS = {"tools", "env", "services", "notes"}
ALLOWED_STEP_KEYS = {"id", "name", "run", "workdir", "timeout_sec", "env", "change_ids"}
RUN_STEPS: list[dict[str, object]] = []


def git_state() -> tuple[str | None, bool | None]:
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None, None
    if head.returncode != 0 or status.returncode != 0:
        return None, None
    return head.stdout.strip(), bool(status.stdout.strip())


def write_run_artifact(
    requested_module: str,
    requested_level: str,
    requested_version: str,
    started_at: str,
    exit_code: int,
    error: str | None = None,
) -> None:
    artifact_dir = REPO_ROOT / "harness" / "evidence" / "test-runs"
    try:
        artifact_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        slug_module = requested_module.replace("/", "+")
        artifact_path = artifact_dir / f"{timestamp}-{slug_module}-{requested_level}.json"
        head, dirty = git_state()
        artifact: dict[str, object] = {
            "schema": RUN_ARTIFACT_SCHEMA,
            "version": requested_version,
            "requested_module": requested_module,
            "requested_level": requested_level,
            "started_at": started_at,
            "finished_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "git_head": head,
            "worktree_dirty": dirty,
            "steps": RUN_STEPS,
            "exit_code": exit_code,
        }
        if error:
            artifact["error"] = error
        artifact_path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
        print(f"[test-run] run artifact written: {artifact_path.relative_to(REPO_ROOT)}")
    except OSError as exc:
        print(f"[test-run] warning: failed to write run artifact: {exc}", file=sys.stderr)


def load_testplan(module: str, version: str) -> tuple[dict, Path]:
    testplan_path = (
        REPO_ROOT / "docs" / "versions" / version / "modules" / module / "testplan.yaml"
    )
    if not testplan_path.exists():
        raise FileNotFoundError(f"missing testplan: {testplan_path}")

    with testplan_path.open("r", encoding="utf-8") as fh:
        plan = yaml.safe_load(fh) or {}

    if not isinstance(plan, dict):
        raise ValueError(f"invalid testplan format: {testplan_path}")
    return plan, testplan_path


def _unknown_keys(actual: dict, allowed: set[str]) -> list[str]:
    return sorted(set(actual.keys()) - allowed)


def _require_list_of_strings(value: object, field_name: str) -> None:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{field_name} must be a list of strings")


def validate_testplan(plan: dict, module: str, version: str, path: Path) -> None:
    unknown_root = _unknown_keys(plan, ALLOWED_ROOT_KEYS)
    if unknown_root:
        raise ValueError(f"{path}: unknown top-level keys: {', '.join(unknown_root)}")

    if plan.get("schema_version") != 1:
        raise ValueError(f"{path}: schema_version must be 1")

    if plan.get("module") != module:
        raise ValueError(f"{path}: module mismatch, expected '{module}'")

    if plan.get("version") != version:
        raise ValueError(f"{path}: version mismatch, expected '{version}'")

    defaults = plan.get("defaults")
    if not isinstance(defaults, dict):
        raise ValueError(f"{path}: defaults must be an object")

    unknown_default = _unknown_keys(defaults, ALLOWED_DEFAULT_KEYS)
    if unknown_default:
        raise ValueError(f"{path}: unknown defaults keys: {', '.join(unknown_default)}")

    env = defaults.get("env", {})
    if not isinstance(env, dict):
        raise ValueError(f"{path}: defaults.env must be an object")

    workdir = defaults.get("workdir", ".")
    if not isinstance(workdir, str):
        raise ValueError(f"{path}: defaults.workdir must be a string")

    timeout_sec = defaults.get("timeout_sec", 600)
    if not isinstance(timeout_sec, int):
        raise ValueError(f"{path}: defaults.timeout_sec must be an integer")

    levels = plan.get("levels")
    if not isinstance(levels, dict):
        raise ValueError(f"{path}: levels must be an object")

    unknown_levels = sorted(set(levels.keys()) - set(ALLOWED_LEVELS))
    if unknown_levels:
        raise ValueError(f"{path}: unknown levels: {', '.join(unknown_levels)}")

    missing_levels = [level for level in ALLOWED_LEVELS if level not in levels]
    if missing_levels:
        raise ValueError(f"{path}: missing levels: {', '.join(missing_levels)}")

    for level_name in ALLOWED_LEVELS:
        level_plan = levels.get(level_name)
        if not isinstance(level_plan, dict):
            raise ValueError(f"{path}: levels.{level_name} must be an object")

        unknown_level = _unknown_keys(level_plan, ALLOWED_LEVEL_KEYS)
        if unknown_level:
            raise ValueError(
                f"{path}: unknown keys in levels.{level_name}: {', '.join(unknown_level)}"
            )

        mode = level_plan.get("mode")
        if mode not in ALLOWED_MODES:
            raise ValueError(
                f"{path}: levels.{level_name}.mode must be one of {sorted(ALLOWED_MODES)}"
            )

        summary = level_plan.get("summary")
        if not isinstance(summary, str) or not summary.strip():
            raise ValueError(f"{path}: levels.{level_name}.summary must be a non-empty string")

        _require_list_of_strings(
            level_plan.get("test_targets", []), f"{path}: levels.{level_name}.test_targets"
        )
        if mode == "enabled" and not level_plan.get("test_targets"):
            raise ValueError(
                f"{path}: levels.{level_name}.test_targets must not be empty when enabled"
            )

        preconditions = level_plan.get("preconditions")
        if not isinstance(preconditions, dict):
            raise ValueError(f"{path}: levels.{level_name}.preconditions must be an object")

        unknown_preconditions = _unknown_keys(preconditions, ALLOWED_PRECONDITION_KEYS)
        if unknown_preconditions:
            raise ValueError(
                f"{path}: unknown keys in levels.{level_name}.preconditions: "
                f"{', '.join(unknown_preconditions)}"
            )

        for field in ("tools", "env", "services", "notes"):
            _require_list_of_strings(
                preconditions.get(field, []),
                f"{path}: levels.{level_name}.preconditions.{field}",
            )

        notes = preconditions.get("notes", [])
        if mode in {"manual", "disabled"} and not notes:
            raise ValueError(
                f"{path}: levels.{level_name}.preconditions.notes must explain why {mode}"
            )

        steps = level_plan.get("steps", [])
        if steps is None:
            steps = []

        if not isinstance(steps, list):
            raise ValueError(f"{path}: levels.{level_name}.steps must be a list")

        if mode == "enabled" and not steps:
            raise ValueError(f"{path}: levels.{level_name}.steps must not be empty when enabled")

        for index, step in enumerate(steps):
            if not isinstance(step, dict):
                raise ValueError(f"{path}: levels.{level_name}.steps[{index}] must be an object")

            unknown_step = _unknown_keys(step, ALLOWED_STEP_KEYS)
            if unknown_step:
                raise ValueError(
                    f"{path}: unknown keys in levels.{level_name}.steps[{index}]: "
                    f"{', '.join(unknown_step)}"
                )

            for required in ("id", "name", "run"):
                if required not in step:
                    raise ValueError(
                        f"{path}: levels.{level_name}.steps[{index}] missing '{required}'"
                    )

            if not isinstance(step["id"], str) or not step["id"].strip():
                raise ValueError(f"{path}: levels.{level_name}.steps[{index}].id must be set")

            if not isinstance(step["name"], str) or not step["name"].strip():
                raise ValueError(f"{path}: levels.{level_name}.steps[{index}].name must be set")

            run = step["run"]
            if not isinstance(run, list) or not run or any(not isinstance(item, str) for item in run):
                raise ValueError(
                    f"{path}: levels.{level_name}.steps[{index}].run must be a non-empty string list"
                )

            if "workdir" in step and not isinstance(step["workdir"], str):
                raise ValueError(
                    f"{path}: levels.{level_name}.steps[{index}].workdir must be a string"
                )

            if "timeout_sec" in step and not isinstance(step["timeout_sec"], int):
                raise ValueError(
                    f"{path}: levels.{level_name}.steps[{index}].timeout_sec must be an integer"
                )

            if "env" in step and not isinstance(step["env"], dict):
                raise ValueError(f"{path}: levels.{level_name}.steps[{index}].env must be an object")


def resolve_env(defaults: dict, step: dict) -> dict:
    env = os.environ.copy()
    env.update(defaults.get("env") or {})
    env.update(step.get("env") or {})
    return env


def resolve_workdir(defaults: dict, step: dict) -> Path:
    raw = step.get("workdir", defaults.get("workdir", "."))
    return (REPO_ROOT / raw).resolve()


def resolve_timeout(defaults: dict, step: dict) -> int:
    return int(step.get("timeout_sec", defaults.get("timeout_sec", 600)))


def run_level(module: str, level: str, version: str) -> int:
    plan, testplan_path = load_testplan(module, version)
    validate_testplan(plan, module, version, testplan_path)
    defaults = plan.get("defaults") or {}
    levels = plan.get("levels") or {}
    level_plan = levels.get(level)

    if not level_plan:
        raise KeyError(f"level '{level}' not found in {testplan_path}")

    mode = level_plan.get("mode", "enabled")
    if mode != "enabled":
        print(f"[test-run] {module}:{level} is {mode}; nothing to run")
        return 0

    steps = level_plan.get("steps") or []
    if not steps:
        raise ValueError(f"level '{level}' has no steps in {testplan_path}")

    print(f"[test-run] module={module} version={version} level={level}")
    print(f"[test-run] plan={testplan_path.relative_to(REPO_ROOT)}")

    for step in steps:
        run = step.get("run")
        if not isinstance(run, list) or not run:
            raise ValueError(f"step '{step.get('id', '<unknown>')}' has invalid run command")

        step_name = step.get("name", step.get("id", "unnamed-step"))
        workdir = resolve_workdir(defaults, step)
        timeout = resolve_timeout(defaults, step)
        env = resolve_env(defaults, step)

        print(f"[test-run] step={step_name}")
        print(f"[test-run] workdir={workdir}")
        print(f"[test-run] timeout_sec={timeout}")
        print(f"[test-run] cmd={' '.join(run)}")

        step_start = time.monotonic()
        try:
            completed = subprocess.run(
                run,
                cwd=workdir,
                env=env,
                timeout=timeout,
                check=False,
            )
            return_code = completed.returncode
        except subprocess.TimeoutExpired:
            return_code = 124
            print(
                f"[test-run] step timed out: {step_name} (timeout_sec={timeout})",
                file=sys.stderr,
            )
        RUN_STEPS.append(
            {
                "module": module,
                "level": level,
                "id": step.get("id"),
                "name": step_name,
                "command": run,
                "workdir": str(workdir),
                "timeout_sec": timeout,
                "change_ids": step.get("change_ids", []),
                "exit_code": return_code,
                "duration_s": round(time.monotonic() - step_start, 3),
            }
        )
        if return_code != 0:
            print(
                f"[test-run] step failed: {step_name} (exit={return_code})",
                file=sys.stderr,
            )
            return return_code

    print(f"[test-run] level passed: {module}:{level}")
    return 0


def discover_modules(version: str) -> list[str]:
    modules_root = REPO_ROOT / "docs" / "versions" / version / "modules"
    if not modules_root.exists():
        raise FileNotFoundError(f"missing modules directory: {modules_root}")
    modules = []
    for child in sorted(modules_root.iterdir()):
        if child.name.startswith("_") or not child.is_dir():
            continue
        if (child / "testplan.yaml").exists():
            modules.append(child.name)
    if not modules:
        raise FileNotFoundError(f"no module testplans found under {modules_root}")
    return modules


def run_module(module: str, level: str, version: str) -> int:
    levels = ALLOWED_LEVELS if level == "all" else (level,)
    for current_level in levels:
        result = run_level(module, current_level, version)
        if result != 0:
            return result
    return 0


def run_selection(module: str, level: str, version: str) -> int:
    modules = discover_modules(version) if module == "all" else [module]
    for current_module in modules:
        result = run_module(current_module, level, version)
        if result != 0:
            return result
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a module test level from docs/versions/<version>/modules/<module>/testplan.yaml"
    )
    parser.add_argument("module", help="module name, or 'all'")
    parser.add_argument("level", choices=LEVEL_CHOICES, help="test level, or 'all'")
    parser.add_argument(
        "--version",
        default=DEFAULT_VERSION,
        help=f"docs version to load (default: {DEFAULT_VERSION})",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    started_at = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    try:
        result = run_selection(args.module, args.level, args.version)
    except Exception as exc:  # pragma: no cover
        print(f"[test-run] error: {exc}", file=sys.stderr)
        write_run_artifact(args.module, args.level, args.version, started_at, 2, str(exc))
        return 2
    write_run_artifact(args.module, args.level, args.version, started_at, result)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
