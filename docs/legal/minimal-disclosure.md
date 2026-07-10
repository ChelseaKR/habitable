<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Minimal-disclosure export scoping (item R-35)

> **This is not legal advice.** This is **educational background** on what a habitable evidence
> packet contains and, just as importantly, what it deliberately leaves out — so an attorney or
> advocate can respond to an over-broad discovery demand from an informed position. It is not a
> brief, not a script for your court, and the disclosure decision in any real matter is a legal
> one for a licensed attorney in your jurisdiction.

Discovery cuts both ways. If a tenant or union produces a packet, opposing counsel may try to
demand *more* — the whole vault, every issue, every other tenant's matter. The answer is not to
hide anything; it is that **the export is scoped by design, and that scope is stated on the
record inside the packet itself.** A produced packet is a narrow, self-documenting disclosure,
not a data dump, and it says so in writing.

## What a packet contains

A packet is assembled for **one scope**: a single issue, or one unit. Within that scope it
carries only:

- **Shared, sanitized copies** of the media for the in-scope issue(s) — location (GPS) metadata
  stripped from every shared copy, so the images do not reveal where the tenant lives.
- **A filtered timeline and issue record** — only the timeline entries and issues that fall
  within the export scope. Other issues in the same vault are not included.
- **The chain-of-custody proof** for the included items — exported in **identity-stripped** form
  (a hash-linked integrity proof), not the identities of who did what, unless custody-identity
  export is explicitly enabled.
- **Trusted timestamps** (RFC 3161 tokens) over the content hashes of the included items.
- **Disclosures** — a short, plain-language, localized statement (in `packet.html` and
  `packet.pdf`, and machine-readably in `bundle.json`) of what the packet reveals and what it
  omits, including the scope statement described below.

## What a packet does *not* contain

By construction, a packet excludes:

- **Other issues in the same vault.** An issue-scoped export carries that issue's captures,
  timeline, and custody records only — captures from other issues are not exported, and neither
  are their timeline entries.
- **Other tenants' or other members' matters.** Nothing outside the exported scope leaves the
  vault. A union's whole vault is never produced by exporting one packet.
- **Items captured before a `since` cutoff**, when the export sets one — those are excluded and
  the exclusion is stated explicitly.
- **Custody identities**, unless custody-identity export is deliberately enabled. The default
  custody proof is identity-stripped.
- **Location metadata**, unless the sealed originals are deliberately embedded
  (`include_originals`). Shared copies are location-stripped; embedding originals is a
  higher-disclosure choice and is flagged in the disclosures when made.
- **Drafts and sync/custody records not pertaining to the included items.**

These exclusions are not implicit. Each packet emits a machine-readable **`scope`** object in
`bundle.json` with a `statement` (e.g. *"Scope: issue &lt;id&gt; only — captures, timeline
entries, and custody records from other issues in this vault are not included"* or *"Scope: the
whole unit …"*) and an **`exclusions`** array naming what is left out (vault contents outside the
scope; pre-`since` items). The same statement is rendered, localized, in the human-readable
`packet.html` and `packet.pdf`, and is repeated in the packet's `disclosures` list. See
[`../bundle-schema.md`](../bundle-schema.md) for the field contract.

## Why the export is designed to be minimal

- **Privacy of the protected user.** Location stripping and issue scoping keep a produced packet
  from revealing where a tenant lives or what unrelated matters they may have documented.
- **Protecting third parties.** A union vault may hold many tenants' issues. Scoping means one
  member's production never sweeps in another's.
- **A defensible, on-the-record boundary.** Because the scope and exclusions are written into the
  signed bundle and the rendered packet, the minimal-disclosure nature of the production is
  itself part of the evidence, not an unrecorded assertion made later.

## Responding to an over-broad discovery demand

- **Produce the scoped packet, and point to its own scope statement.** The packet documents, in
  writing, that it is limited to the issue or unit at hand and that other vault contents are not
  included.
- **Meet a demand for "the whole vault" with the scope boundary, not a data dump.** An
  over-broad demand can expose other tenants and unrelated matters; the export is built precisely
  so that boundary is stated and honored.
- **Seek a protective order where appropriate.** Discuss with co-counsel whether a protective
  order should govern any production, and tailor scope (issue vs. unit, and any `since` cutoff)
  to what the matter actually requires.
- **Remember whose call it is.** The tool makes the export minimal and self-documenting; the
  **disclosure decision — what to produce, and on what terms — is a legal one** for the attorney
  in the matter, under the rules of the relevant jurisdiction. habitable makes no admissibility
  or discovery-scope guarantee.

## Related material

- [`foundation-guidance.md`](./foundation-guidance.md) — the *Discovery caution* section, and the
  authenticity-vs-condition framing for introducing a packet.
- [`../bundle-schema.md`](../bundle-schema.md) and
  [`../packet-bundle.schema.json`](../packet-bundle.schema.json) — the `scope` field contract.
- [`../privacy.md`](../privacy.md) — location stripping and the shared-copy/original distinction.
