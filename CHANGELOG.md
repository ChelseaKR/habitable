# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/). The **packet format** and the
**verification protocol** are versioned independently (see `docs/evidence-method.md`).

## [Unreleased]

### Fixed

- **Verifier subset now imports on Python < 3.14 again.** Three multi-type `except`
  clauses in the Apache-2.0 verification subset (`verify.py`, `tsa.py`, `exif.py`)
  used the PEP 758 parenthesis-free form, a `SyntaxError` before Python 3.14 — which
  contradicted the 0.2.0 note that the subset is portable for legal-aid embedders.
  The root cause is that the ruff formatter targets `py314` and strips the
  parentheses, so the clauses now reference a **named exception tuple** (e.g.
  `except _SIGNATURE_READ_ERRORS:`), which is formatter-stable and portable. A new
  guard test (`test_verifier_subset_avoids_py314_only_except_syntax`) fails the gate
  if the 3.14-only form is reintroduced.

### Added

- **Packet "what this proves — and what it does not" disclosure.** Every exported
  `packet.html` and `packet.pdf` now carries a plain-language, localized (EN/ES)
  statement of the upper-bound timestamp semantics and the limits of the evidence
  (it does not prove authorship, depiction, the underlying condition, or
  admissibility), with how to verify. Single source in `src/habitable/disclosure.py`
  so the HTML and PDF cannot drift. (Recipient personas: housing-court clerk,
  opposing counsel.)
- **Recipient-facing disclosures.** Packets now carry a localized (EN/ES) "what
  this packet discloses" note (shared copies have location removed; sealed
  originals, when embedded, retain full metadata), and the machine-readable
  `disclosures` list is included in the signed `bundle.json` (schema documented).
- **`habitable verify --json`.** A structured verification report (overall verdict
  plus per-item content hash, timestamp, custody, fixity, and notes) for scripts,
  downstream integrators, and screen-reader users.
- **`habitable verify --trusted-cert PEM`** (repeatable). Anchors each RFC 3161
  timestamp to a TSA root certificate the verifier trusts, so a court or auditor can
  assert the authority chain rather than only the token signature.
- **Multiple-authority timestamp redundancy by default.** Capture now stamps every
  configured timestamp authority (the default config ships more than one), recording
  the primary token in `timestamp` and independent tokens over the same content hash
  in `additional_timestamps`. The verifier checks all of them, reports
  `verified_authorities` per item (and in `verify --json`), and counts an item as
  timestamped if at least one authority verifies — so no packet's proof rests on a
  single TSA. Additive and backward-compatible: existing single-authority packets
  verify exactly as before.

- **Synthetic-persona research and derived backlog** in `docs/research/`
  (`synthetic-personas-feedback.md`, `execution-log.md`): a broad persona study,
  interviews, and a prioritized list of remediations/expansions checked against the
  project's invariants.
- **Reviewer & integrator documentation** realizing backlog items from that study:
  a standalone cryptographic design spec (`docs/crypto-spec.md`), a verifier
  decision table + independent cross-check procedure
  (`docs/verifier-decision-table.md`), a documented, versioned packet/bundle format
  (`docs/bundle-schema.md` + `docs/packet-bundle.schema.json`), a verifier-embedding
  cookbook (`docs/embedding-the-verifier.md`), and a "how to attack a packet"
  red-team document (`docs/audits/packet-attack-redteam.md`).
- **Legal-scaffolding docs** (`docs/legal/`): tenant/custodian declaration
  templates, foundation guidance for counsel, and California-scoped evidence notes
  (all explicitly not legal advice).
- **Adoption kit** (`docs/adoption/`): a train-the-trainer workshop guide, printable
  EN/ES quick-starts, and a board-level risk/benefit briefing.
- **Community, sustainability & ops docs**: a funder impact brief
  (`docs/funding-impact-brief.md`), a newcomer/good-first-issues guide
  (`docs/good-first-issues.md`), a localization-contributor guide
  (`docs/localization-guide.md`), a union key-custody playbook
  (`docs/key-custody-playbook.md`), and relay operator self-audit + observability
  docs (`docs/relay-operator-self-audit.md`, `docs/relay-observability-matrix.md`).

## [0.2.0] — 2026-06-17

Alpha hardening and reviewer-handoff release. Still alpha — do not rely on it for a
real legal matter yet. This release closes out the maintainer-only "Phase 0" work:
durable proofs, a frozen threat-model baseline, automated assurance, and the
materials an external auditor, accessibility tester, or pilot partner needs.

### Added

- **Archive (re-)timestamping.** `habitable retimestamp` re-stamps each capture's
  most recent token before the issuing authority's certificate or hash algorithm
  ages out (RFC 4998-style chaining). Existence stays anchored at the primary
  token's time; packets carry `archive_timestamps` per item and the standalone
  verifier walks the chain, failing closed on any break. (`tsa.retimestamp`,
  `tsa.verify_archive_chain`, `capture.retimestamp_all`.)
- **Vault key lifecycle.** `habitable key rotate | backup | restore` — passphrase
  rotation and an independent-passphrase recovery blob, with a non-technical-organizer
  walkthrough in `docs/key-management.md`.
- **Backward-compatibility guard.** A versioned packet/protocol contract in the
  verifier plus a committed golden-packet corpus, so every format version ever
  emitted must keep verifying and a newer-than-supported packet is rejected cleanly,
  never mis-verified.
- **Assurance automation.** A verifier fuzz/property harness; a scheduled,
  network-gated public-TSA integration job (DigiCert + FreeTSA); and a signed
  build-provenance + CycloneDX SBOM release pipeline.
- **Invariant guard tests.** `tests/test_guards.py` and hardened sync tests pin two
  promises: no plaintext (note text, image bytes, or a sender identity) reaches a
  relay or on-disk mailbox, and importing `habitable.verify` pulls in only the
  Apache-2.0 verification subset — no AGPL-only/heavy modules.
- **Frozen threat-model baseline B1.** A content-pinned (`SHA-256`) freeze of the
  threat model for external review, with a section-by-section re-review and an
  append-only baseline trail (`docs/audits/threat-model-baseline.md`, tag
  `threat-model-baseline-B1`).
- **Reviewer/pilot handoff docs.** `docs/audits/onboarding.md`, a DPIA-style
  `docs/privacy.md`, `docs/sustainability.md` (incl. bus-factor minimum), and a
  multi-year `ROADMAP.md`.
- **Accessibility.** Automated keyboard-navigation and 320 px reflow checks added to
  the a11y gate.

### Changed

- The verification subset (`verify`/`tsa`/`exif`) now writes its multi-type `except`
  clauses with explicit parentheses — behaviour-identical, but valid on every
  Python 3 and unambiguous to auditors and legal-aid embedders of the Apache-2.0
  verifier (no reliance on the PEP 758 syntax that 3.14 newly accepts).
- `docs/governance.md` "Releases" reconciled with the actual signed/provenanced
  pipeline.

### Fixed

- **RFC 3161 interoperability with real public authorities.** The client now reads
  `PKIStatus` whether rendered as an int or a name, follows the token's own digest
  algorithm instead of assuming SHA-256, and dispatches signature verification for
  both RSA (PKCS#1 v1.5) and ECDSA — verified against DigiCert and FreeTSA.
- Two verifier robustness bugs found by the fuzz harness: invalid-UTF-8 bundle bytes
  and a malformed custody chain are now clean rejections, never a crash.

### Security

- **Custody-actor identity and tenant filename no longer leak into exported packets.**
  The importing peer's fingerprint (`details.from`) and the original source filename
  (`details.source`) were being carried in the signed, shared `bundle.json`,
  weakening the "exports name no one" guarantee. They now live in a **vault-only
  `private_details`** field that is never hashed and never exported, while the union
  keeps them for its own audit. Previously-produced packets still verify unchanged.
  Regression-guarded by `tests/test_guards.py`.

## [0.1.0] — 2026-06-17

First public release. Alpha — a working reference implementation; do not rely on
it for real legal matters yet. It pairs the evidence spine with a local app,
accessibility gates, mobile/PWA install, an optional relay deploy, and a static
preview site.

### Added — app, accessibility, and operations

- **Local app.** `habitable app` runs a loopback-only HTTP server that holds the
  unlocked vault and serves an accessible, bilingual (English/Spanish) web client —
  capture, timeline, status, resolve, and export-and-verify over a small JSON API;
  nothing leaves the device. Installable PWA (manifest, maskable/Apple icons, and
  an offline service worker that is network-only for `/api/`).
- **axe-core accessibility gate.** A real WCAG scan of the running app in English
  and Spanish (Playwright/Chromium), blocking on any moderate/serious/critical
  violation, in a dedicated `a11y` CI workflow and `make a11y`; the app reports
  **zero** violations. Manual NVDA/VoiceOver/keyboard/zoom protocol documented in
  `docs/accessibility/manual-testing.md`.
- **Accessible HTML packet.** Every export also produces `packet.html` — a
  self-contained WCAG 2.2 AA rendering that passes the same axe gate — alongside a
  PDF that declares its language, sets `DisplayDocTitle`, and carries a navigable
  outline; all bundle-derived text is escaped before rendering.
- **Configurable packet templates** (per-jurisdiction wording, presentation only).
- **Optional relay deploy.** A dependency-free, non-root, read-only container and a
  one-command `docker compose` for the ciphertext-only sync relay
  (`docs/relay-deploy.md`).
- **Docs & preview.** Setup guide, mobile guide, and a static landing page with a
  live sample packet (GitHub Pages).

### Limitations

A *recorded* human screen-reader pass (protocol shipped), a fully tagged PDF/UA
structure tree (not available in reportlab's open-source API — the HTML packet is
the accessible rendering until then), and signed native app-store binaries (the
installable PWA covers mobile today) remain — see the ACR and the build plan.

### Added — evidence core

- **Evidence core.** Streaming SHA-256 fixity and an append-only, hash-linked
  chain of custody whose entry hashes commit to *salted actor commitments*, so an
  exported chain verifies as intact without revealing who viewed or copied an
  item. Tamper, deletion, and reordering are all detectable.
- **Trusted timestamping.** Real RFC 3161 (a local issuer for offline use/tests
  and an HTTP client for production) plus a clearly non-production offline dev
  TSA. The verifier enforces digest binding, validates the CMS signature and
  certificate chain, and detects `genTime` tampering.
- **Encryption.** ChaCha20-Poly1305 vault encryption under a scrypt-wrapped data
  key (cheap passphrase rotation and encrypted recovery backups), Ed25519 device
  identity, and an X25519 sealed box for end-to-end sync.
- **Offline-first model.** A CRDT case document (LWW registers, an OR-Set of
  issues, append-only timeline/captures) with commutative, associative,
  idempotent merge.
- **Vault + capture.** Encrypted on-disk case vault with fixity re-checked on
  read; capture pipeline that hashes, seals, and records custody offline, then
  obtains a trusted timestamp when online (queuing otherwise).
- **Packet + verify.** Deterministic signed `bundle.json`, location-stripped
  shared media, and an accessible paginated PDF; a standalone verifier
  (additionally Apache-2.0) that re-derives hashes, validates tokens and the
  producer signature, and walks custody.
- **Sync + relay.** End-to-end-encrypted peer-to-peer sync over a shared
  directory or an optional ciphertext-only relay.
- **CLI.** `habitable init|id|issue|capture|timeline|status|resolve|export|verify|sync|relay|demo`,
  plus `python -m habitable`.
- **Engineering.** uv project on Python 3.14; `ruff` + `mypy --strict`; pytest
  with property-based and tamper-detection tests (`make verify` green, ~85%
  coverage); SHA-pinned GitHub Actions, CodeQL, Dependabot, `pip-audit`.

[Unreleased]: https://github.com/ChelseaKR/habitable/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ChelseaKR/habitable/releases/tag/v0.1.0
