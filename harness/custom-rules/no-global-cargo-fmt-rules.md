# No Global Cargo Fmt Rules

## Goal
- Prevent repository-wide formatting churn from obscuring scoped code changes.

## Rule
- Agents MUST NOT run global Rust formatting commands at any time.
- Forbidden commands include, but are not limited to:
  - `cargo fmt`
  - `cargo fmt --all`
  - `cd src && cargo fmt`
  - `rustup run <toolchain> cargo fmt`
- This rule applies even when implementation, testing, acceptance, or cleanup work is in progress.

## Allowed Formatting Scope
- File- or range-scoped formatting may be used only when the user explicitly requests it and the command can be limited to the files changed by the current task.
- If a tool or script would invoke global `cargo fmt` implicitly, do not run that tool until the formatting behavior is disabled or the user changes this rule.

## Review Expectation
- Formatting-only diffs outside the current task scope are not acceptable harness evidence.
- If existing code is unformatted, leave it unchanged unless the user explicitly starts a dedicated scoped formatting task.
