# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/). The **packet format** and the
**verification protocol** are versioned independently (see `docs/evidence-method.md`).

## [Unreleased]

### Added

- **Local app (Phase 4, in progress).** `habitable app` runs a loopback-only HTTP
  server that holds the unlocked vault and serves an accessible, bilingual
  (English/Spanish) web client — capture, timeline, status, and export-and-verify
  over a small JSON API; nothing leaves the device. EN/ES string parity and
  structural accessibility (lang, skip link, labelled controls, landmarks, alt
  text, no positive tabindex) are enforced by tests; an installable PWA manifest
  and a service worker (network-only for `/api/`) are included.
- **Configurable packet templates.** Per-jurisdiction header/footer wording
  (presentation only — it never changes how a packet verifies).
- **Setup guide.** `docs/setup-guide.md` — "set up your union in an afternoon".
- **Resolve in the app.** A "resolve awaiting timestamps" action (and `/api/resolve`)
  so items captured offline can be timestamped from the UI when back online.
- **PDF accessibility (toward PDF/UA).** Packet PDFs now declare their language
  and set `DisplayDocTitle`, so viewers show the document title, not the file name.
- **More gates.** Tests for the app's PWA installability (manifest, icons,
  service worker that is network-only for `/api/`) and the PDF accessibility
  markers; a `make a11y` target. 87 tests total, `make verify` green.

### Note

A full WCAG 2.2 AA audit (automated axe/pa11y + manual NVDA/VoiceOver review wired
as a merge gate), a fully tagged (PDF/UA structure tree) packet, and native mobile
packaging are still ahead — see the ACR and the build plan.

## [0.1.0] — 2026-06-17

First working reference implementation of the evidence spine. Alpha,
concept-stage: do not rely on it for real legal matters yet.

### Added

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
