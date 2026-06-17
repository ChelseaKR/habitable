# 1. Record architecture decisions

Status: Accepted (2026-06-17)

## Context

habitable makes consequential, hard-to-reverse design choices — the evidence
model, the CRDT, the timestamping approach, the threat model — and the project is
alpha and concept-stage. Decisions made now will be questioned later, by
contributors, by auditors, and possibly in a courtroom where the design itself is
the thing under scrutiny. We need a durable, plain-text record of *why* each
significant choice was made, not just *what* the code does.

## Decision

We will record architecture decisions using Architecture Decision Records (ADRs)
in the lightweight format described by Michael Nygard: each ADR has a Title, a
Status, a Context, a Decision, and Consequences.

ADRs live in `docs/adr/`, are numbered sequentially (`NNNN-short-title.md`), and
are immutable once Accepted: a decision that is later reversed gets a new ADR that
supersedes the old one, rather than an edit in place. The history is the point.

## Consequences

- A reader can reconstruct the reasoning behind the architecture from version
  control alone, without interviewing the original author.
- Superseding rather than editing keeps an honest trail of how thinking changed,
  which matters for a tool whose credibility rests on transparency.
- There is a small per-decision cost to writing an ADR; we accept it for choices
  that are architecturally significant and skip it for routine ones.
