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
- **axe-core accessibility gate.** A real WCAG scan of the running app in English
  and Spanish (via Playwright/Chromium), blocking on any moderate/serious/critical
  violation, wired into a dedicated `a11y` CI workflow and `make a11y`; the app
  reports **zero** violations. A manual NVDA/VoiceOver/keyboard/zoom protocol is
  documented in `docs/accessibility/manual-testing.md`.
- **Accessible HTML packet.** Every export now also produces `packet.html` — a
  self-contained WCAG 2.2 AA rendering (landmarks, one `h1`, a captioned appendix
  table with header scopes, meaningful image `alt`, document language) that passes
  the same axe gate. It is the accessible human-readable view alongside the PDF.
- **PDF accessibility.** Packet PDFs declare their (configured) language, set
  `DisplayDocTitle`, and carry a navigable outline/bookmarks; all bundle-derived
  text is escaped before rendering.
- **Mobile / PWA.** PNG icons (192/512) plus a maskable icon and an Apple touch
  icon, Apple/standalone meta tags, and a service worker that precaches the shell
  and falls back offline; install guidance in `docs/mobile.md`. Installability is
  test-gated.

### Note

A *recorded* human screen-reader pass (protocol shipped), a fully tagged PDF/UA
structure tree (not available in reportlab's open-source API — the HTML packet is
the accessible rendering until then), and signed native app-store binaries (the
installable PWA covers mobile today) remain — see the ACR and the build plan.

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
