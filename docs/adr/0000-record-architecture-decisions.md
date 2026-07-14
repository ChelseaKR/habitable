# 0000. Govern the architecture decision log

Status: Accepted (2026-07-14)

## Context

Habitable adopted architecture decision records in ADR 0001 before the portfolio established a
canonical 0000 governance record. The log also acquired two accepted records numbered 0008. The
timestamp trust/readiness decision landed first; authenticated case-bound sync landed afterward.
Ambiguous numbers make durable citations unreliable in a project whose credibility depends on a
reviewable design history.

## Decision

This record is the canonical governance entry for `docs/adr/`. ADR 0001 remains the original
decision to adopt the practice rather than being rewritten out of history. Accepted records are
append-only; a later record explicitly supersedes an earlier decision when necessary.

ADR filenames use `NNNN-kebab-title.md` and new records use `docs/adr/template.md`. Existing
chronology is preserved: timestamp integrity/trust/readiness remains ADR 0008, and the later
authenticated case-bound sync decision becomes ADR 0009. Future records continue sequentially.

## Consequences

- Every ADR citation resolves to one decision.
- The original adoption record and the reasons in every accepted ADR remain intact.
- Mechanical portfolio checks can distinguish the canonical log from ordinary design notes.
