from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class ImageConfig:
    key: str
    image_ref: str


@dataclass(frozen=True)
class TargetConfig:
    mode: str
    host: str
    ubuntu_required: bool
    user: str | None = None
    port: int | None = None


@dataclass(frozen=True)
class LoadConfig:
    duration_seconds: int
    warmup_seconds: int
    concurrency: int
    rates: tuple[int, ...]
    connection_reuse_modes: tuple[str, ...]
    timeout_seconds: int


@dataclass(frozen=True)
class BenchmarkPlan:
    version: str
    name: str
    profile_path: Path
    target: TargetConfig
    registry_push: bool
    registry_pull_policy: str
    registry_allow_deferral: bool
    images: dict[str, ImageConfig]
    candidates: tuple[str, ...]
    scenarios: dict
    protocols: dict
    generated_config: dict
    upstream: dict
    load: LoadConfig
    metrics: dict
    output: dict


@dataclass(frozen=True)
class ScenarioPlan:
    candidate: str
    scenario: str
    protocol: str
    rate: int
    payload: str
    stream_mode: str | None = None
    connection_reuse: str = "new_connection"


@dataclass(frozen=True)
class CommandPlan:
    description: str
    command: tuple[str, ...]
    cwd: str | None = None
