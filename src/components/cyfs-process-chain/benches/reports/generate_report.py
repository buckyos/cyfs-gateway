#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


GROUP_TYPE = {
    "parse_only": "T0",
    "link_only": "T1",
    "prepare_exec_only": "T2",
    "execute_api_hot": "T3",
    "execute_fork_hot": "T4",
    "js_register_only": "T5",
    "js_execute_hot": "T5",
}

GROUP_ORDER = {
    "phase1/parse_only": 0,
    "phase1/link_only": 1,
    "phase1/prepare_exec_only": 2,
    "phase1/execute_api_hot": 3,
    "phase1/execute_fork_hot": 4,
    "phase2/execute_fork_hot": 5,
    "phase3/execute_fork_hot": 6,
    "phase3/js_register_only": 7,
    "phase3/js_execute_hot": 8,
}

SCALE_ORDER = {
    "S": 0,
    "M": 1,
    "L": 2,
    None: 9,
    "": 9,
}

CASE_ORDER = {
    "empty_return": 0,
    "var_read_flat": 1,
    "var_read_path": 2,
    "list_path_read": 3,
    "route_prefix_pipeline": 4,
    "host_classify_pipeline": 5,
    "uri_query_pipeline": 6,
    "match_capture_pipeline": 7,
    "first_ok_first_success": 8,
    "first_ok_success": 9,
    "first_ok_last_success": 10,
    "first_ok_all_fail": 11,
    "case_when_pipeline": 12,
    "if_elif_pipeline": 13,
    "match_result_flow": 14,
    "literal_and_access": 15,
    "invoke_helper_return": 16,
    "capture_status_value": 17,
    "js_register_bool": 18,
    "js_execute_bool": 19,
    "js_execute_map_result": 20,
    "js_execute_set_result": 21,
}

CASE_NOTES = {
    "empty_return": "runtime floor",
    "var_read_flat": "flat env lookup",
    "var_read_path": "nested map path traversal",
    "list_path_read": "list index path traversal",
    "route_prefix_pipeline": "path strip + split + access",
    "host_classify_pipeline": "authority parse + host classify",
    "uri_query_pipeline": "parse-uri + parse-query + build-uri",
    "match_capture_pipeline": "match capture + named capture reads",
    "first_ok_first_success": "first-ok with first branch success",
    "first_ok_success": "first-ok with middle branch success",
    "first_ok_last_success": "first-ok with last branch success",
    "first_ok_all_fail": "first-ok with all branches failing",
    "case_when_pipeline": "case when branch fan-out",
    "if_elif_pipeline": "if/elif branch fan-out",
    "match_result_flow": "match-result branch scope restore",
    "literal_and_access": "literal creation + structured access",
    "invoke_helper_return": "helper invoke + payload access",
    "capture_status_value": "capture value + status bookkeeping",
    "js_register_bool": "JS external registration cold path",
    "js_execute_bool": "minimal JS bool call",
    "js_execute_map_result": "JS typed map wrapper conversion",
    "js_execute_set_result": "JS typed set wrapper conversion",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a managed cyfs-process-chain benchmark report from Criterion outputs."
    )
    parser.add_argument(
        "--baseline-name",
        required=True,
        help="Logical baseline name for this report, e.g. main-local",
    )
    parser.add_argument(
        "--compare-to",
        help="Optional baseline name used by an intentional comparison run. When set, change %% is read from Criterion change outputs.",
    )
    parser.add_argument(
        "--benchmark-command",
        required=True,
        help="The exact benchmark command used for the run.",
    )
    parser.add_argument(
        "--criterion-root",
        type=Path,
        help="Criterion output root. Defaults to <repo>/src/target/criterion.",
    )
    parser.add_argument(
        "--reports-root",
        type=Path,
        help="Report output root. Defaults to <repo>/src/components/cyfs-process-chain/benches/reports.",
    )
    return parser.parse_args()


def run_command(args: list[str], cwd: Path | None = None) -> str:
    result = subprocess.run(
        args,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def try_run_command(args: list[str], cwd: Path | None = None) -> str | None:
    try:
        return run_command(args, cwd=cwd)
    except Exception:
        return None


def repo_root() -> Path:
    root = run_command(["git", "rev-parse", "--show-toplevel"])
    return Path(root)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def infer_group_kind(group_id: str) -> str:
    return group_id.split("/", 1)[1]


def infer_type(group_id: str) -> str:
    return GROUP_TYPE.get(infer_group_kind(group_id), "unknown")


def sort_key(row: dict[str, Any]) -> tuple[int, int, int, str]:
    return (
        GROUP_ORDER.get(row["group_id"], 99),
        CASE_ORDER.get(row["case"], 99),
        SCALE_ORDER.get(row["scale"], 99),
        row["full_id"],
    )


def collect_rows(criterion_root: Path, include_change: bool) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for benchmark_path in criterion_root.rglob("new/benchmark.json"):
        estimates_path = benchmark_path.with_name("estimates.json")
        if not estimates_path.exists():
            continue

        benchmark = load_json(benchmark_path)
        estimates = load_json(estimates_path)
        scale_root = benchmark_path.parent.parent
        change_path = scale_root / "change" / "estimates.json"

        median_ns = float(estimates["median"]["point_estimate"])
        mean_ns = float(estimates["mean"]["point_estimate"])
        ops_per_sec = 1_000_000_000.0 / median_ns if median_ns > 0 else None
        change_pct = None
        if include_change and change_path.exists():
            change = load_json(change_path)
            change_pct = float(change["median"]["point_estimate"]) * 100.0

        row = {
            "group_id": benchmark["group_id"],
            "group_kind": infer_group_kind(benchmark["group_id"]),
            "case": benchmark.get("function_id") or benchmark["full_id"],
            "scale": benchmark.get("value_str") or "",
            "type": infer_type(benchmark["group_id"]),
            "full_id": benchmark["full_id"],
            "directory_name": benchmark["directory_name"],
            "median_ns": median_ns,
            "mean_ns": mean_ns,
            "ops_per_sec": ops_per_sec,
            "change_pct": change_pct,
            "note": CASE_NOTES.get(benchmark.get("function_id") or "", ""),
        }
        rows.append(row)

    rows.sort(key=sort_key)
    return rows


def format_ns(ns_value: float) -> str:
    if ns_value >= 1_000_000.0:
        return f"{ns_value / 1_000_000.0:.2f} ms"
    if ns_value >= 1_000.0:
        return f"{ns_value / 1_000.0:.2f} us"
    return f"{ns_value:.2f} ns"


def format_table_ns(ns_value: float) -> str:
    return f"{ns_value:.2f}"


def format_ops(ops_value: float | None) -> str:
    if ops_value is None:
        return "n/a"
    return f"{ops_value:,.0f}"


def format_change(change_pct: float | None, report_mode: str) -> str:
    if change_pct is None:
        return "baseline" if report_mode == "baseline" else "n/a"
    sign = "+" if change_pct > 0 else ""
    return f"{sign}{change_pct:.2f}%"


def summarize_hotspots(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hot_groups = {"execute_api_hot", "execute_fork_hot", "js_execute_hot"}
    hot_rows = [row for row in rows if row["group_kind"] in hot_groups]
    hot_rows.sort(key=lambda row: row["median_ns"], reverse=True)
    return hot_rows[:5]


def summarize_scale_growth(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}
    for row in rows:
        key = (row["group_id"], row["case"])
        grouped.setdefault(key, {})[row["scale"]] = row

    growth_rows = []
    for (group_id, case), scales in grouped.items():
        if "S" not in scales or "L" not in scales:
            continue
        small = scales["S"]["median_ns"]
        large = scales["L"]["median_ns"]
        if small <= 0:
            continue
        growth_rows.append(
            {
                "group_id": group_id,
                "case": case,
                "small_ns": small,
                "large_ns": large,
                "ratio": large / small,
            }
        )

    growth_rows.sort(key=lambda row: row["ratio"], reverse=True)
    return growth_rows[:5]


def summarize_changes(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    change_rows = [row for row in rows if row["change_pct"] is not None]
    regressions = sorted(change_rows, key=lambda row: row["change_pct"], reverse=True)[:5]
    improvements = sorted(change_rows, key=lambda row: row["change_pct"])[:5]
    return regressions, improvements


def build_machine_info(repo: Path) -> dict[str, str]:
    uname = try_run_command(["uname", "-srmo"], cwd=repo) or "unknown"
    lscpu = try_run_command(["lscpu"], cwd=repo)
    memory = try_run_command(["free", "-h"], cwd=repo)

    cpu_model = "unknown"
    cpu_count = "unknown"
    hypervisor = "unknown"
    if lscpu:
        for line in lscpu.splitlines():
            if line.startswith("Model name:"):
                cpu_model = line.split(":", 1)[1].strip()
            elif line.startswith("CPU(s):"):
                cpu_count = line.split(":", 1)[1].strip()
            elif line.startswith("Hypervisor vendor:"):
                hypervisor = line.split(":", 1)[1].strip()

    memory_total = "unknown"
    if memory:
        for line in memory.splitlines():
            if line.startswith("Mem:"):
                parts = line.split()
                if len(parts) >= 2:
                    memory_total = parts[1]
                break

    return {
        "uname": uname,
        "cpu_model": cpu_model,
        "cpu_count": cpu_count,
        "memory_total": memory_total,
        "hypervisor": hypervisor,
    }


def build_git_info(repo: Path) -> dict[str, str]:
    commit = run_command(["git", "rev-parse", "HEAD"], cwd=repo)
    short_commit = run_command(["git", "rev-parse", "--short", "HEAD"], cwd=repo)
    branch = run_command(["git", "branch", "--show-current"], cwd=repo)
    commit_line = run_command(
        ["git", "show", "-s", "--format=%cI %h %s", "HEAD"],
        cwd=repo,
    )
    return {
        "commit": commit,
        "short_commit": short_commit,
        "branch": branch,
        "commit_line": commit_line,
    }


def build_rust_info(repo: Path) -> dict[str, str]:
    rustc = run_command(["rustc", "-V"], cwd=repo / "src")
    rustc_verbose = run_command(["rustc", "-Vv"], cwd=repo / "src")
    return {
        "rustc": rustc,
        "rustc_verbose": rustc_verbose,
    }


def build_markdown(
    report_meta: dict[str, Any],
    rows: list[dict[str, Any]],
    hotspots: list[dict[str, Any]],
    scale_growth: list[dict[str, Any]],
    regressions: list[dict[str, Any]],
    improvements: list[dict[str, Any]],
) -> str:
    lines: list[str] = []
    lines.append("# cyfs-process-chain Benchmark Report")
    lines.append("")
    lines.append("## Metadata")
    lines.append("")
    lines.append(f"- generated_at: `{report_meta['generated_at']}`")
    lines.append(f"- report_mode: `{report_meta['report_mode']}`")
    lines.append(f"- baseline_name: `{report_meta['baseline_name']}`")
    if report_meta["compare_to"]:
        lines.append(f"- compare_to: `{report_meta['compare_to']}`")
    lines.append(f"- git_commit: `{report_meta['git']['commit']}`")
    lines.append(f"- git_branch: `{report_meta['git']['branch']}`")
    lines.append(f"- git_summary: `{report_meta['git']['commit_line']}`")
    lines.append(f"- rustc: `{report_meta['rust']['rustc']}`")
    lines.append(f"- machine_os: `{report_meta['machine']['uname']}`")
    lines.append(f"- machine_cpu: `{report_meta['machine']['cpu_model']}`")
    lines.append(f"- machine_cpus: `{report_meta['machine']['cpu_count']}`")
    lines.append(f"- machine_memory: `{report_meta['machine']['memory_total']}`")
    lines.append(f"- machine_hypervisor: `{report_meta['machine']['hypervisor']}`")
    lines.append(f"- benchmark_command: `{report_meta['benchmark_command']}`")
    lines.append(f"- criterion_root: `{report_meta['criterion_root']}`")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- benchmark_count: `{len(rows)}`")
    if hotspots:
        lines.append("- hottest hot-path cases:")
        for row in hotspots:
            lines.append(
                f"  - `{row['full_id']}`: `{format_ns(row['median_ns'])}`"
            )
    if scale_growth:
        lines.append("- largest S->L growth:")
        for row in scale_growth:
            lines.append(
                f"  - `{row['group_id']}/{row['case']}`: `x{row['ratio']:.2f}` "
                f"(`{format_ns(row['small_ns'])}` -> `{format_ns(row['large_ns'])}`)"
            )
    if report_meta["report_mode"] == "compare":
        if regressions:
            lines.append("- largest regressions:")
            for row in regressions:
                lines.append(
                    f"  - `{row['full_id']}`: `{format_change(row['change_pct'], 'compare')}`"
                )
        if improvements:
            lines.append("- largest improvements:")
            for row in improvements:
                lines.append(
                    f"  - `{row['full_id']}`: `{format_change(row['change_pct'], 'compare')}`"
                )
    lines.append("")

    grouped_rows: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped_rows.setdefault(row["group_id"], []).append(row)

    lines.append("## Results")
    lines.append("")
    for group_id in sorted(grouped_rows, key=lambda item: GROUP_ORDER.get(item, 99)):
        lines.append(f"### {group_id}")
        lines.append("")
        lines.append("| case | type | scale | median ns/op | ops/sec | change % | notes |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- |")
        for row in grouped_rows[group_id]:
            lines.append(
                "| "
                + " | ".join(
                    [
                        f"`{row['case']}`",
                        row["type"],
                        row["scale"] or "-",
                        format_table_ns(row["median_ns"]),
                        format_ops(row["ops_per_sec"]),
                        format_change(row["change_pct"], report_meta["report_mode"]),
                        row["note"] or "-",
                    ]
                )
                + " |"
            )
        lines.append("")

    return "\n".join(lines).strip() + "\n"


def load_manifest(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def write_manifest(path: Path, entries: list[dict[str, Any]]) -> None:
    path.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")


def write_index(path: Path, manifest: list[dict[str, Any]]) -> None:
    lines = [
        "# cyfs-process-chain Benchmark Reports",
        "",
        "| generated_at | mode | baseline | branch | commit | top hotspot | report |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]

    sorted_entries = sorted(
        manifest,
        key=lambda entry: entry["generated_at"],
        reverse=True,
    )
    for entry in sorted_entries:
        hotspot = entry.get("top_hotspot_full_id", "-")
        hotspot_ns = entry.get("top_hotspot_median_ns")
        hotspot_text = hotspot
        if hotspot_ns is not None:
            hotspot_text = f"`{hotspot}` ({format_ns(hotspot_ns)})"
        report_rel = entry["report_path"]
        report_name = Path(report_rel).name
        lines.append(
            "| "
            + " | ".join(
                [
                    entry["generated_at"],
                    entry["report_mode"],
                    entry["baseline_name"],
                    entry["branch"],
                    entry["short_commit"],
                    hotspot_text,
                    f"[{report_name}]({report_rel})",
                ]
            )
            + " |"
        )

    path.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    repo = repo_root()
    criterion_root = args.criterion_root or repo / "src" / "target" / "criterion"
    reports_root = args.reports_root or (
        repo / "src" / "components" / "cyfs-process-chain" / "benches" / "reports"
    )
    records_root = reports_root / "records"
    manifest_path = reports_root / "manifest.json"
    index_path = reports_root / "INDEX.md"

    if not criterion_root.exists():
        raise SystemExit(f"criterion root does not exist: {criterion_root}")

    report_mode = "compare" if args.compare_to else "baseline"
    rows = collect_rows(criterion_root, include_change=bool(args.compare_to))
    if not rows:
        raise SystemExit(f"no benchmark rows found under {criterion_root}")

    git = build_git_info(repo)
    rust = build_rust_info(repo)
    machine = build_machine_info(repo)
    generated_at = datetime.now().astimezone().isoformat(timespec="seconds")
    file_stamp = datetime.now().astimezone().strftime("%Y%m%dT%H%M%S%z")
    file_base = f"{file_stamp}__{args.baseline_name}__{git['short_commit']}"

    hotspots = summarize_hotspots(rows)
    scale_growth = summarize_scale_growth(rows)
    regressions, improvements = summarize_changes(rows)

    report_meta = {
        "generated_at": generated_at,
        "report_mode": report_mode,
        "baseline_name": args.baseline_name,
        "compare_to": args.compare_to,
        "benchmark_command": args.benchmark_command,
        "criterion_root": str(criterion_root.relative_to(repo)),
        "git": git,
        "rust": rust,
        "machine": machine,
    }

    snapshot = {
        "report": report_meta,
        "rows": rows,
        "summary": {
            "hotspots": hotspots,
            "scale_growth": scale_growth,
            "regressions": regressions,
            "improvements": improvements,
        },
    }

    records_root.mkdir(parents=True, exist_ok=True)
    report_path = records_root / f"{file_base}.md"
    snapshot_path = records_root / f"{file_base}.json"

    report_path.write_text(
        build_markdown(
            report_meta=report_meta,
            rows=rows,
            hotspots=hotspots,
            scale_growth=scale_growth,
            regressions=regressions,
            improvements=improvements,
        ),
        encoding="utf-8",
    )
    snapshot_path.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")

    manifest = load_manifest(manifest_path)
    manifest.append(
        {
            "generated_at": generated_at,
            "report_mode": report_mode,
            "baseline_name": args.baseline_name,
            "compare_to": args.compare_to,
            "branch": git["branch"],
            "commit": git["commit"],
            "short_commit": git["short_commit"],
            "report_path": str(report_path.relative_to(reports_root)),
            "snapshot_path": str(snapshot_path.relative_to(reports_root)),
            "benchmark_count": len(rows),
            "top_hotspot_full_id": hotspots[0]["full_id"] if hotspots else None,
            "top_hotspot_median_ns": hotspots[0]["median_ns"] if hotspots else None,
        }
    )
    write_manifest(manifest_path, manifest)
    write_index(index_path, manifest)

    print(f"generated report: {report_path}")
    print(f"generated snapshot: {snapshot_path}")
    print(f"updated index: {index_path}")
    print(f"updated manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
