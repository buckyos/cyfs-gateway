# Generated SN seed authority regression

Prerequisites: Python 3.10+, Cargo/Rust, and Deno 2.9.2. The generator uses
`src/deno.json` to resolve `buckyos/provision` from the published SDK's `main`.
No Python packages, live BNS service, chain, or VM are required.

Run from the repository root, keeping scratch files under the project's `.work`.
The example below uses the canonical multi-repository workspace's parent directory;
a standalone checkout can use its own `.work/tmp` instead:

```bash
mkdir -p ../.work/tmp
export TMPDIR="$(cd .. && pwd)/.work/tmp"
python3 -m unittest discover -s src/components/bns-server/tests -p test_cargo_lockfile.py -v
(cd src && deno test -A make_sn_config_test.ts)
python3 src/components/bns-server/tests/sn_seed_authority.py
```

The integration loads the actual generated seed documents into an isolated BNS
projection, checks the HTTP device-slot metadata, and requires RTCP
`MethodAuthorityCurrent`. It does not submit transactions or establish a live
SN tunnel.

A fresh checkout has no tracked `src/Cargo.lock`. The integration generates one
only when missing, then compiles with `--locked`. An existing lockfile is not
refreshed, removed, or replaced; an outdated resolution fails instead of silently
changing dependencies. Git dependency declarations continue to use `main`.

The integration defaults to the `release` Cargo profile. Set
`BUCKYOS_SN_SEED_CARGO_PROFILE=test` to reuse the ordinary Cargo test cache.
The Rust CI workflow runs these regressions before its build and full test suite,
so its clean checkout exercises lockfile bootstrap and reuses the test profile.
