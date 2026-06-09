# cyfs-gateway performance-test

`performance-test` is the repository-local benchmark module for comparing
`cyfs_gateway` with nginx under the same Docker-based workload plan.

The module lives under `benches/performance/` and is implemented as an
independent Python package named `cyfs_gateway_performance`.

## Scope

- Build self-contained nginx and `cyfs_gateway` test images.
- Build the `cyfs_gateway` test binary from the current repository source.
- Push configured image refs and make the benchmark target pull those refs.
- Run local or SSH-targeted Ubuntu/Debian Docker benchmarks.
- Cover static HTTP files, HTTP reverse proxy, and stream reverse proxy
  scenarios with fixed-rate workloads.
- Write machine-readable and human-readable comparison reports.

This module does not tune `cyfs_gateway`, change production runtime
configuration, define production SLOs, or provide a CI performance gate.

## Requirements

- Python 3.10 or newer.
- Python dependencies declared in `pyproject.toml`.
- `vegeta` for HTTP/HTTPS fixed-rate load. The runner first uses
  `CYFS_VEGETA_PATH` or `PATH`, then downloads the latest matching release from
  `https://github.com/tsenart/vegeta` into a local cache when missing.
- Ubuntu or Debian target host for benchmark runs.
- Docker CLI and Docker daemon on the benchmark target.
- Rust/cargo build environment for `cyfs_gateway` image builds.
- Registry access for image push/pull when `registry.push` is enabled.
- SSH only when `target.mode: ssh` is used.

The default profile allows environment deferral for registry or Docker
availability so local development can still produce auditable deferred reports.

## Profile

The default benchmark profile is:

```text
benches/performance/profiles/performance.yaml
```

The same profile is used for image build, image push, target pull, deployment,
workload planning, metrics collection, and report metadata. Important fields:

- `target`: local or SSH Ubuntu/Debian target.
- `registry`: push/pull behavior and environment deferral policy.
- `images`: full nginx and `cyfs_gateway` image refs.
- `generated_config`: generated test assets and Docker network settings.
- `scenarios`: enabled static file, HTTP proxy, and stream proxy cases.
- `protocols`: HTTP and HTTPS switches for HTTP-style scenarios.
- `load`: fixed-rate workload duration, warmup, concurrency, rates, and
  connection reuse modes.
- `metrics`: resource sampling and latency percentiles.
- `output`: result directory and report formats. Relative directories are
  resolved from the profile file's directory.

Before running against a real registry, replace the example image refs in the
profile with refs that the build host can push and the target host can pull.

## Running

From the repository root, run the package through uv:

```bash
uv run --project benches/performance cyfs-gateway-performance build-image \
  --profile benches/performance/profiles/performance.yaml
```

Build only one candidate image:

```bash
uv run --project benches/performance cyfs-gateway-performance build-nginx-image \
  --profile benches/performance/profiles/performance.yaml

uv run --project benches/performance cyfs-gateway-performance build-cyfs-gateway-image \
  --profile benches/performance/profiles/performance.yaml
```

Push an already-built image ref:

```bash
uv run --project benches/performance cyfs-gateway-performance push-image \
  --profile benches/performance/profiles/performance.yaml \
  --image nginx
```

Run the benchmark:

```bash
uv run --project benches/performance cyfs-gateway-performance run \
  --profile benches/performance/profiles/performance.yaml
```

Regenerate reports from an existing result:

```bash
uv run --project benches/performance cyfs-gateway-performance report \
  --profile benches/performance/profiles/performance.yaml \
  --input benches/performance/results/latest/result.json
```

## Outputs

The output directory contains command evidence and benchmark artifacts such as:

- `result.json`: primary machine-readable benchmark result.
- `summary.md`: human-readable comparison summary.
- `result.csv`: optional trend collection output when enabled.
- `*-build-plan.json`: image build metadata and command evidence.
- `*-push-plan.json`: image push metadata and command evidence.
- `logs/`: stdout/stderr logs for executed commands.

The report records profile path, target metadata, image refs, source build
metadata, request metrics, latency statistics, actual attempted request count,
actual request rate, CPU samples, memory samples, and deferral reasons when the
environment cannot complete a real run.

## Validation

Run unit coverage through the harness entrypoint:

```bash
uv run python3 ./harness/scripts/test-run.py performance-test unit
```

Run the local Docker DV path when the host has the required Ubuntu/Debian, Docker,
cargo, registry, and port environment:

```bash
uv run python3 ./harness/scripts/test-run.py performance-test dv
```

SSH remote benchmark validation is manual because credentials, Docker
permissions, registry access, and target machine load are environment-specific.

## Operational Notes

- The benchmark uses fixed configured rate tiers; it does not search for max
  throughput automatically.
- HTTP/HTTPS load, including stream TCP/TLS ports carrying HTTP static-file
  requests, uses `vegeta attack` and records response latency from
  `vegeta encode -to=json`.
- Set `CYFS_VEGETA_CACHE` to choose the auto-download cache directory, or
  `CYFS_VEGETA_PATH` to force a specific binary.
- nginx and `cyfs_gateway` must use the same profile, payloads, durations,
  warmup, concurrency, connection reuse mode, target host, and image refs for a
  valid comparison.
- Generated images are test images only, not production release artifacts.
- Successful or failed runs attempt to clean up containers and the benchmark
  Docker network created by this module.
