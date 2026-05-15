from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .model import CommandPlan


@dataclass(frozen=True)
class CommandResult:
    description: str
    command: list[str]
    cwd: str | None
    returncode: int
    stdout: str
    stderr: str
    started_at: float
    ended_at: float

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def as_dict(self) -> dict:
        return {
            "description": self.description,
            "command": self.command,
            "cwd": self.cwd,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_seconds": round(self.ended_at - self.started_at, 3),
        }


def run_command(command: CommandPlan, *, cwd: Path | None = None, timeout: int | None = None) -> CommandResult:
    started = time.time()
    effective_cwd = Path(command.cwd) if command.cwd else cwd
    try:
        completed = subprocess.run(
            command.command,
            cwd=effective_cwd,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        ended = time.time()
        return CommandResult(
            description=command.description,
            command=list(command.command),
            cwd=str(effective_cwd) if effective_cwd else None,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            started_at=started,
            ended_at=ended,
        )
    except FileNotFoundError as exc:
        ended = time.time()
        return CommandResult(
            description=command.description,
            command=list(command.command),
            cwd=str(effective_cwd) if effective_cwd else None,
            returncode=127,
            stdout="",
            stderr=str(exc),
            started_at=started,
            ended_at=ended,
        )
    except subprocess.TimeoutExpired as exc:
        ended = time.time()
        return CommandResult(
            description=command.description,
            command=list(command.command),
            cwd=str(effective_cwd) if effective_cwd else None,
            returncode=124,
            stdout=exc.stdout or "",
            stderr=exc.stderr or f"command timed out after {timeout} seconds",
            started_at=started,
            ended_at=ended,
        )


def write_command_log(output: Path, name: str, result: CommandResult) -> str:
    output.mkdir(parents=True, exist_ok=True)
    path = output / name
    body = [
        f"description: {result.description}",
        f"command: {' '.join(result.command)}",
        f"cwd: {result.cwd or ''}",
        f"returncode: {result.returncode}",
        "",
        "stdout:",
        result.stdout,
        "",
        "stderr:",
        result.stderr,
        "",
    ]
    path.write_text("\n".join(body), encoding="utf-8")
    return str(path)
