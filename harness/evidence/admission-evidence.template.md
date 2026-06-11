# Task <task-id> Admission Evidence

<!--
File name contract: harness/evidence/admission/<YYYYMMDD>-<task-slug>.md
- <YYYYMMDD> is today's date; admission-check.py rejects malformed or future dates.
- Generate the ## Document Binding hashes with:
  uv run --active python ./harness/scripts/admission-check.py --version <version> --module <module> [--submodule <submodule>] --print-doc-hashes
- Quotes must be copied verbatim from the current approved documents; admission-check.py
  re-verifies hashes and quotes against the documents, so editing a document after writing
  this file invalidates the evidence.
- A passing admission-check.py run writes <task-id>.<module>[.<submodule>].stamp.json next
  to this file. Never create or edit stamp files by hand; edit-guard.py validates the stamp
  (and its design Scope Paths) before allowing production-code edits.
-->

## Implementation Admission Evidence
| evidence_item | source | status | notes |
|---------------|--------|--------|-------|
| proposal_read | docs/versions/<version>/modules/<module>/proposal.md | pass | task-specific note on what was read |
| design_read | docs/versions/<version>/modules/<module>/design.md | pass | task-specific note on what was read |
| change_scope_matches_request | proposal <proposal_id> / design <change_id> | pass | why the admitted change covers the current request |
| active_module_resolved | docs/versions/<version>/modules/<module> | pass | how the active module was resolved |
| no_chat_only_evidence | versioned docs only | pass | confirm no chat-only assumptions were used |

## Document Binding
| doc | sha256 |
|-----|--------|
| docs/versions/<version>/modules/<module>/proposal.md | <64-hex LF-normalized sha256> |
| docs/versions/<version>/modules/<module>/design.md | <64-hex LF-normalized sha256> |

## Coverage Quotes

### Quote: proposal.md <change_id>
> | <proposal_id> | <change_id> | <outcome> | <success evidence> |

### Quote: design.md <change_id>
> | <change_id> | <proposal_id> | <design coverage> | <scope paths> |
