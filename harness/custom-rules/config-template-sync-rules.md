# Config Template Sync Rules

## Goal
- Keep runtime configuration examples, rootfs defaults, and user-facing config templates synchronized when supported config behavior changes.

## Scope
- `src/rootfs/etc/`
- bundled YAML/JSON/TOML examples
- Web console or control-plane config schemas when they expose the same setting
- module docs that define runtime-config behavior

## Rule
- Config field additions, removals, default changes, type changes, or semantic changes MUST first be covered by the owning module packet.
- Implementation MUST update every shipped template or generated default that represents the changed config contract.
- If a config behavior is intentionally supported only in code and not in a shipped template, the design or testing artifact MUST state why.
- Acceptance MUST compare docs, code defaults, shipped templates, and tests for the changed config behavior.

## Validation
- Run the relevant module tests through `harness/scripts/test-run.py`.
- For config changes, also inspect or test the rootfs/template files named by the design.
