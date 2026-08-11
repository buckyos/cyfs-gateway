# cyfs-process-chain Benchmark Reports

This directory stores managed benchmark reports for `process_chain_runtime`.

The goal is to keep every formal run in a stable, reviewable form with:

- report timestamp
- git branch and commit
- benchmark command
- machine and toolchain metadata
- per-case metrics snapshot

Directory layout:

- `generate_report.py`: turns Criterion output under `src/target/criterion/` into a versioned report entry
- `records/*.md`: human-readable benchmark reports
- `records/*.json`: machine-readable metric snapshots for later diffing
- `manifest.json`: append-only report registry used to build the index
- `INDEX.md`: time-ordered report list

Baseline report example:

```bash
cd /home/bucky/work/cyfs-gateway
python3 src/components/cyfs-process-chain/benches/reports/generate_report.py \
  --baseline-name main-local \
  --benchmark-command 'CARGO_INCREMENTAL=0 cargo bench -p cyfs-process-chain --bench process_chain_runtime -- --save-baseline main-local'
```

Compare report example:

```bash
cd /home/bucky/work/cyfs-gateway
python3 src/components/cyfs-process-chain/benches/reports/generate_report.py \
  --baseline-name main-local \
  --compare-to main-local \
  --benchmark-command 'CARGO_INCREMENTAL=0 cargo bench -p cyfs-process-chain --bench process_chain_runtime -- --baseline main-local'
```

Notes:

- `--baseline-name` is the logical baseline label recorded in the report.
- `--compare-to` should only be passed for an intentional compare run. Without it, the report is treated as a baseline snapshot and `change %` is not read from Criterion.
- Reports are written under `records/` with a sortable timestamp prefix so timeline browsing stays simple.
