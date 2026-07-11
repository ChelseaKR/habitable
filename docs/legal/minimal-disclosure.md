<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Minimal-disclosure export scoping (item R-35)

> **This is not legal advice.** This is **educational background** on what a habitable evidence
> packet contains and, just as importantly, what it deliberately leaves out — so an attorney or
> advocate can respond to an over-broad discovery demand from an informed position. It is not a
> brief, not a script for your court, and the disclosure decision in any real matter is a legal
> one for a licensed attorney in your jurisdiction.

Discovery cuts both ways. If a tenant or union produces a packet, opposing counsel may try to
demand *more* — the whole vault, every issue, every other tenant's matter. The disclosure decision
belongs with counsel, not the tool.

> **Current safety status:** new packet-v3 exports support the **whole unit only**. Requests using
> `--issue` or `--since` fail before staging or replacing output. Packet v3 represents custody as
> one complete hash-linked chain; filtering `items`, `issues`, and `timeline` while exporting that
> chain can still reveal excluded capture and timeline identifiers. Habitable will not call a
> truncated chain complete or publish a narrower disclosure statement until a new packet version
> defines a scoped, rehashed custody-view contract.

## What a packet contains

A currently supported packet is assembled for the **whole unit recorded in that case vault**. It
carries:

- **Shared, sanitized copies** of the media for the in-scope issue(s) — location (GPS) metadata
  stripped from every shared copy, so the images do not reveal where the tenant lives.
- **The unit's timeline and issue records** — every issue, timeline entry, and capture in the
  case is included.
- **The complete chain-of-custody proof** — exported in **identity-stripped** form
  (a hash-linked integrity proof), not the identities of who did what, unless custody-identity
  export is explicitly enabled.
- **Trusted timestamps** (RFC 3161 tokens) over the content hashes of the included items.
- **Disclosures** — a short, plain-language, localized statement (in `packet.html` and
  `packet.pdf`, and machine-readably in `bundle.json`) of what the packet reveals and what it
  omits, including the scope statement described below.

## What a packet does *not* contain

By construction, a currently supported packet excludes:

- **Other tenants' or other members' matters.** Nothing outside the exported scope leaves the
  case vault. Keep unrelated people or units in separate case vaults; a whole-unit export includes
  every issue in the opened case.
- **Custody identities**, unless custody-identity export is deliberately enabled. The default
  custody proof is identity-stripped.
- **Location metadata**, unless the sealed originals are deliberately embedded
  (`include_originals`). Shared copies are location-stripped; embedding originals is a
  higher-disclosure choice and is flagged in the disclosures when made.
- **Clear custody identities and vault-only private custody details.** The complete public proof
  still exposes its opaque item identifiers, actions, commitments, hashes, and ordering.

Each supported packet emits a machine-readable **`scope`** object stating that it covers the whole
unit. The older issue/date field shapes remain documented so historical packets keep verifying;
their presence in the schema is not a claim that new scoped exports are enabled. See
[`../bundle-schema.md`](../bundle-schema.md) for the compatibility contract.

## Why the export is designed to be minimal

- **Privacy of the protected user.** Shared-copy location stripping and optional withholding of
  originals reduce disclosure inside a whole-unit packet.
- **Protecting third parties.** Use separate case vaults for separate people or units. Current
  packet scoping is not a substitute for that separation.
- **An honest boundary.** The packet says it contains the whole unit; the tool does not promise a
  narrower boundary that its custody representation cannot honor.

## Responding to an over-broad discovery demand

- **Do not use `--issue` or `--since` as a production strategy today.** Those requests are blocked,
  and bypassing the guard would recreate the disclosure defect.
- **Review the whole-unit packet before producing it.** If that scope is too broad, stop and seek
  case-specific legal advice rather than exporting and manually deleting custody records.
- **Seek a protective order where appropriate.** Discuss with co-counsel whether a protective
  order should govern any production and whether the currently available whole-unit artifact is
  appropriate at all.
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
