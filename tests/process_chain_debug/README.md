# Process Chain Debug Tests

Python-based test suite for the `cyfs_gateway debug` subcommand. Runs process chain rules in isolation with mock input, without loading stacks or servers.

## Prerequisites

- cyfs_gateway binary built at `src/rootfs/bin/cyfs-gateway/cyfs_gateway`
- `uv`
- Python 3.11+

## Usage

From project root:

```bash
uv run tests/process_chain_debug/run_debug_tests.py
```

Or from this directory:

```bash
uv run ./run_debug_tests.py
```

### Options

- `--binary PATH` – Path to cyfs_gateway binary (default: `../../src/rootfs/bin/cyfs-gateway/cyfs_gateway`)
- `--config PATH` – Path to gateway config YAML (default: `config.yaml` in this dir)
- `--req-dir PATH` – Directory with `req_*.json` files (default: this dir)

## Structure

- `config.yaml` – Minimal gateway config (global_process_chains only, no stacks/servers)
- `req_*.json` – Test case request files (input collections, chain id, output vars)
- `run_debug_tests.py` – Test runner

## Adding Test Cases

1. Add a `req_*.json` file:

```json
{
  "input": {
    "REQ": { "target_host": "example.com", "path": "/" }
  },
  "id": "chain_id_from_config",
  "output": ["REQ"]
}
```

2. Add the chain to `config.yaml` if needed.
3. Optionally add assertions in `run_debug_tests.py` for the new case.
