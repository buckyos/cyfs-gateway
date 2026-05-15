from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .model import BenchmarkPlan, ConfigError, ImageConfig, LoadConfig, TargetConfig


try:
    import yaml  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - exercised when PyYAML is absent.
    yaml = None


def _load_yaml(text: str) -> dict[str, Any]:
    if yaml is not None:
        loaded = yaml.safe_load(text)
        if not isinstance(loaded, dict):
            raise ConfigError("profile must contain a YAML mapping")
        return loaded
    # The default profile stays JSON-compatible apart from YAML comments.
    loaded = json.loads("\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#")))
    if not isinstance(loaded, dict):
        raise ConfigError("profile must contain a mapping")
    return loaded


def _required_map(parent: dict[str, Any], key: str) -> dict[str, Any]:
    value = parent.get(key)
    if not isinstance(value, dict):
        raise ConfigError(f"profile.{key} must be a mapping")
    return value


def _required_int(parent: dict[str, Any], key: str, minimum: int = 0) -> int:
    value = parent.get(key)
    if not isinstance(value, int) or value < minimum:
        raise ConfigError(f"{key} must be an integer >= {minimum}")
    return value


def _image(key: str, data: dict[str, Any]) -> ImageConfig:
    image_ref = data.get("image_ref")
    if not isinstance(image_ref, str) or not image_ref:
        raise ConfigError(f"images.{key}.image_ref is required")
    if ":" not in image_ref or "/" not in image_ref:
        raise ConfigError(f"images.{key}.image_ref must be a full registry image reference")
    return ImageConfig(key=key, image_ref=image_ref)


def load_profile(path: str | Path) -> BenchmarkPlan:
    profile_path = Path(path).resolve()
    data = _load_yaml(profile_path.read_text(encoding="utf-8"))
    target = _required_map(data, "target")
    mode = target.get("mode")
    if mode not in {"local", "ssh"}:
        raise ConfigError("target.mode must be local or ssh")
    host = str(target.get("host") or "127.0.0.1")
    user = target.get("user")
    if user is not None and not isinstance(user, str):
        raise ConfigError("target.user must be a string when provided")
    port = target.get("port")
    if port is not None and (not isinstance(port, int) or port <= 0):
        raise ConfigError("target.port must be a positive integer when provided")

    registry = _required_map(data, "registry")

    images_data = _required_map(data, "images")
    images = {
        "nginx": _image("nginx", _required_map(images_data, "nginx")),
        "cyfs_gateway": _image("cyfs_gateway", _required_map(images_data, "cyfs_gateway")),
    }

    load = _required_map(data, "load")
    rates = load.get("rates")
    if not isinstance(rates, list) or not rates or not all(isinstance(rate, int) and rate > 0 for rate in rates):
        raise ConfigError("load.rates must be a non-empty list of positive fixed rates")
    duration = _required_int(load, "duration_seconds", 1)
    warmup = _required_int(load, "warmup_seconds", 0)
    if warmup >= duration:
        raise ConfigError("load.warmup_seconds must be lower than duration_seconds")

    generated_config = dict(data.get("generated_config") or {})
    generated_config["_raw_images"] = images_data

    return BenchmarkPlan(
        version=str(data.get("version") or "v0.6"),
        name=str(data.get("name") or profile_path.stem),
        profile_path=profile_path,
        target=TargetConfig(
            mode=mode,
            host=host,
            ubuntu_required=bool(target.get("ubuntu_required", True)),
            user=user,
            port=port,
        ),
        registry_push=bool(registry.get("push", True)),
        registry_allow_deferral=bool(registry.get("allow_deferral", False)),
        images=images,
        scenarios=_required_map(data, "scenarios"),
        protocols=_required_map(data, "protocols"),
        generated_config=generated_config,
        upstream=dict(data.get("upstream") or {}),
        load=LoadConfig(
            duration_seconds=duration,
            warmup_seconds=warmup,
            concurrency=_required_int(load, "concurrency", 1),
            rates=tuple(rates),
            timeout_seconds=_required_int(load, "timeout_seconds", 1),
        ),
        metrics=dict(data.get("metrics") or {}),
        output=dict(data.get("output") or {}),
    )
