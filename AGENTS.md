# Agent Guide (cyfs-gateway)

This file is for autonomous coding agents working in this repository.

Repository layout
- Rust workspace root: `src/` (Cargo workspace in `src/Cargo.toml`)
- Main service app: `src/apps/cyfs_gateway/` (crate `cyfs_gateway`)
- Core library: `src/components/cyfs-gateway-lib/` (crate `cyfs-gateway-lib`)
- Other Rust components: `src/components/*`
- Web dashboard (Vite/React): `src/apps/cyfs_gateway/web/`
- Gateway runtime configs/templates: `src/rootfs/etc/` and `src/rootfs/etc/cyfs_gateway/server_templates/`

Cursor/Copilot rules
- No `.cursorrules`, no `.cursor/rules/`, and no `.github/copilot-instructions.md` found in this repo.

Commands

Rust (run from repo root)
```bash
cd src
```

Build
- CI uses: `cargo build --verbose` (see `.github/workflows/rust.yml`)
```bash
cd src && cargo build --verbose
```

Test
- CI uses single-threaded tests: `cargo test -- --test-threads=1` (see `.github/workflows/rust.yml`)
```bash
cd src && cargo test -- --test-threads=1
```

Run a single test (recommended patterns)
- One integration test file (crate `cyfs_gateway`):
```bash
cd src && cargo test -p cyfs_gateway --test test_control_server
```
- One test function by substring (fast triage; add `-- --exact` when needed):
```bash
cd src && cargo test -p cyfs_gateway test_login -- --nocapture
```
- Documented examples for `cyfs-gateway-lib`:
  - `cd src && cargo test --package cyfs-gateway-lib --lib server::dir_server` (see `doc/dir_server_usage.md`)
  - `cd src && cargo test --package cyfs-gateway-lib ndn_server` (see `doc/ndn_server_usage.md`)
  - `cd src && cargo test --package cyfs-gateway-lib json_collection` (see `doc/json_collection_usage.md`)

Release/packaging build (CI)
- Release workflows install `buckyos-devkit` then run `buckyos-build` in `./src`:
  - Linux: `.github/workflows/build-linux.yml`
  - macOS: `.github/workflows/build-macos.yml` (uses `sudo`)
  - Windows: `.github/workflows/build-windows.yml`
- Web3 gateway packaging: `.github/workflows/build_web3.yml` (`buckyos-build --app=web3-gateway`)

Lint/format
- No canonical lint/format command is wired in CI and no repo-level formatter configs were found.
- If you need formatting locally, default tooling is acceptable:
```bash
cd src && cargo fmt
cd src && cargo clippy
```
Treat these as optional unless a PR/CI starts enforcing them.

Web dashboard (Vite)
```bash
cd src/apps/cyfs_gateway/web
npm i
npm run dev
npm run build
```
Source: `src/apps/cyfs_gateway/web/package.json` and `src/apps/cyfs_gateway/web/README.md`.

Code style guidelines

General
- Prefer small, localized changes; avoid refactors mixed into bugfixes.
- Keep edits consistent with the file/module you touch (this repo is mixed-style).

Rust conventions (dominant codebase)
- Formatting: assume default `rustfmt` (no `rustfmt.toml` detected).
- Imports: usually grouped `std` then external crates then `crate::...`/local, with blank lines between groups.
  - Example: `src/components/cyfs-dns/src/dns_server.rs`
- Naming:
  - Types/enums/traits: `PascalCase`
  - Functions/modules/files: `snake_case`
  - Keyword collisions sometimes use suffix underscore in filenames (e.g. `type_.rs`, `match_.rs` in process-chain).
- Async/runtime:
  - Tokio is the standard runtime (`tokio = { features = ["full"] }` in `src/Cargo.toml`).
  - Long-running listeners typically run in `tokio::spawn` loops.
- Result/error types:
  - Common patterns are `anyhow::Result<T>` for app-level flows and crate-specific `*Result<T>` aliases.
    - Examples: `anyhow::Result` in `src/apps/cyfs_gateway/src/lib.rs`, `TunnelResult` in `src/components/cyfs-gateway-lib/src/lib.rs`.
  - Typed errors often use `thiserror` enums with `String` payloads.
    - Example: `src/components/cyfs-socks/src/error.rs`
  - When converting errors, prefer adding context:
    - `map_err(|e| ... )?` and existing macros are used heavily.
    - Examples: `server_err!(...)` / `into_server_err!(...)` in `src/components/cyfs-dns/src/lib.rs`.
- Logging:
  - Use `log` macros (`debug!`, `info!`, `warn!`, `error!`, `trace!`).
  - Import style varies (`use log::*` vs `use log::{info, warn}`); follow the file.
- Tests:
  - `#[tokio::test]` is common for async tests.
  - Use `-- --test-threads=1` when tests are flaky or share ports/state (matches CI).

TypeScript/TSX (web dashboard)
- Tooling: Vite; no lint/format/typecheck scripts are currently defined in `web/package.json`.
- Imports:
  - Alias `@` maps to `./src` (see `src/apps/cyfs_gateway/web/vite.config.ts`).
- Types:
  - Type strictness is mixed; some files allow `any` (e.g. `src/apps/cyfs_gateway/web/src/app/pages/Overview.tsx`).
  - Prefer adding types when touching code, but do not churn formatting across unrelated files.

Config and port binding (practical note)
- Many listening addresses are config-driven via `bind:` fields in YAML/JSON under `src/rootfs/etc/`.
- Examples:
  - `src/apps/cyfs_gateway/src/gateway_control_server.yaml` binds `127.0.0.1:13451`.
  - `src/rootfs/etc/boot_gateway.yaml` defines multiple stacks with `bind: 0.0.0.0:<port>`.
- When adding tests that bind ports, prefer ephemeral ports (`127.0.0.1:0`) or isolate with `--test-threads=1`.

Where to look first
- Service entrypoint: `src/apps/cyfs_gateway/src/main.rs` and `src/apps/cyfs_gateway/src/lib.rs`
- Stack/server implementations: `src/components/cyfs-gateway-lib/src/stack/` and `src/components/cyfs-gateway-lib/src/server/`
- Process-chain docs: `doc/reference.md` (large command reference)
