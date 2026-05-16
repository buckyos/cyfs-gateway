from __future__ import annotations

import csv
import json
from pathlib import Path

from .image import cyfs_gateway_source
from .model import BenchmarkPlan, ScenarioPlan
from .target import preflight


_CANDIDATE_ORDER = {"nginx": 0, "cyfs_gateway": 1}


def _comparison_key(row: dict) -> tuple:
    return (
        str(row.get("scenario") or ""),
        str(row.get("protocol") or ""),
        str(row.get("stream_mode") or ""),
        str(row.get("payload") or ""),
        str(row.get("connection_reuse") or ""),
        int(row.get("rate") or 0),
        _CANDIDATE_ORDER.get(str(row.get("candidate") or ""), 99),
        str(row.get("candidate") or ""),
    )


def build_result(
    plan: BenchmarkPlan,
    scenarios: list[ScenarioPlan],
    status: str,
    evidence: dict | None = None,
    rows: list[dict] | None = None,
) -> dict:
    return {
        "version": plan.version,
        "profile": str(plan.profile_path),
        "name": plan.name,
        "status": status,
        "evidence": evidence or {},
        "target": preflight(plan),
        "images": {key: image.__dict__ for key, image in plan.images.items()},
        "source_build": {
            "required": True,
            "metadata": cyfs_gateway_source(plan),
            "command": [
                "cargo",
                "build",
                "--manifest-path",
                cyfs_gateway_source(plan)["cargo_manifest"],
                "--package",
                cyfs_gateway_source(plan)["package"],
            ],
        },
        "results": rows if rows is not None else [],
    }


def write_reports(result: dict, output: Path, csv_enabled: bool = False) -> dict[str, str]:
    output.mkdir(parents=True, exist_ok=True)
    result_path = output / "result.json"
    summary_path = output / "summary.md"
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    lines = [
        "# Performance Benchmark Summary",
        "",
        f"- status: {result['status']}",
        f"- profile: {result['profile']}",
        f"- result rows: {len(result['results'])}",
        "",
        "| scenario | protocol | stream_mode | payload | connection_reuse | rate | candidate | engine | attempted | actual attempted | actual rate | success | avg latency ms | cpu avg | memory avg |",
        "|----------|----------|-------------|---------|------------------|------|-----------|--------|-----------|------------------|-------------|---------|----------------|---------|------------|",
    ]
    for row in sorted(result["results"], key=_comparison_key):
        requests = row.get("requests") or {}
        resources = row.get("resources") or {}
        latency = requests.get("latency_ms") or {}
        lines.append(
            "| {scenario} | {protocol} | {stream_mode} | {payload} | {connection_reuse} | {rate} | {candidate} | {engine} | {attempted} | {actual_attempted} | {actual_rate} | {success} | {latency} | {cpu} | {memory} |".format(
                scenario=row["scenario"],
                protocol=row["protocol"],
                stream_mode=row["stream_mode"] or "",
                payload=row.get("payload") or "",
                connection_reuse=row.get("connection_reuse") or "",
                rate=row["rate"],
                candidate=row["candidate"],
                engine=requests.get("engine", "builtin"),
                attempted=requests.get("attempted", 0),
                actual_attempted=requests.get("actual_attempted", requests.get("attempted", 0)),
                actual_rate=requests.get("actual_rate_per_second", 0.0),
                success=requests.get("success", 0),
                latency=latency.get("avg", 0.0),
                cpu=resources.get("cpu_percent_avg", 0.0),
                memory=resources.get("memory_bytes_avg", 0),
            )
        )
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    outputs = {"json": str(result_path), "markdown": str(summary_path)}
    if csv_enabled:
        csv_path = output / "result.csv"
        with csv_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "candidate",
                    "scenario",
                    "protocol",
                    "stream_mode",
                    "connection_reuse",
                    "rate",
                    "engine",
                    "attempted",
                    "actual_attempted",
                    "actual_rate_per_second",
                    "success",
                ],
            )
            writer.writeheader()
            for row in result["results"]:
                writer.writerow(
                    {
                        "candidate": row["candidate"],
                        "scenario": row["scenario"],
                        "protocol": row["protocol"],
                        "stream_mode": row["stream_mode"] or "",
                        "connection_reuse": row.get("connection_reuse") or "",
                        "rate": row["rate"],
                        "engine": row["requests"].get("engine", "builtin"),
                        "attempted": row["requests"].get("attempted", 0),
                        "actual_attempted": row["requests"].get(
                            "actual_attempted",
                            row["requests"].get("attempted", 0),
                        ),
                        "actual_rate_per_second": row["requests"].get("actual_rate_per_second", 0.0),
                        "success": row["requests"]["success"],
                    }
                )
        outputs["csv"] = str(csv_path)
    return outputs
