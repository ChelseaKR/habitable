<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# habitable — roadmap

**v0.1.0 (alpha) is shipped and public.** The evidence spine, encryption, offline-first
sync, the accessible bilingual app, the export packets, and the optional relay all work
and are tested (see `CHANGELOG.md`). This document is the path from a working
reference implementation to something a tenant union can *rely on* — and an honest
account of what is deliberately left undone.

It is a working document, not a promise. Dates are horizons for a small volunteer
effort and will move; the *ordering* and the *exit criteria* matter more than the
calendar. Decisions of consequence are recorded as ADRs in `docs/adr/`.

> **Alpha caveat.** Until the v1.0 gate below is met, do not rely on habitable for
> real legal matters. See *Honest limits* in the [README](README.md).

## Contents

- [Vision & north star](#vision--north-star)
- [Guiding principles](#guiding-principles)
- [Releases & versioning](#releases--versioning)
- [The v1.0 gate (when "alpha" comes off)](#the-v10-gate-when-alpha-comes-off)
- [Release horizons](#release-horizons)
- [Workstreams](#workstreams)
  - [A. Evidence & cryptographic assurance](#a-evidence--cryptographic-assurance)
  - [B. Accessibility, localization & inclusive design](#b-accessibility-localization--inclusive-design)
  - [C. Apps, sync & platform](#c-apps-sync--platform)
  - [D. Governance, community, partnerships & sustainability](#d-governance-community-partnerships--sustainability)
- [Risks & mitigations](#risks--mitigations)
- [Measuring progress without surveillance](#measuring-progress-without-surveillance)
- [Non-goals](#non-goals)
- [How this roadmap is maintained](#how-this-roadmap-is-maintained)

## Vision & north star

A tenant — or their union — can document a habitability problem on the only device they
have, offline, and later hand a court or inspector a packet that the *other side* can
verify hasn't been altered, **without anyone but the keyholders ever being able to read
the tenant's data, and without trusting this project to do so.** The north-star metric is
not downloads; it is: *a tenant won, or was protected, partly because the record held up —
and nothing leaked in the process.*

## Guiding principles

These are invariants. No item on this roadmap may violate them; an item that requires
violating one is the wrong item.

1. **No server-side personal data, ever.** No cloud of cases, no accounts, nothing to
   subpoena from the project.
2. **No telemetry, no analytics.** The tool measures nothing about its users (this
   constrains how we measure our own progress — see below, and we accept that).
3. **No central authority over a union's records.** Forking or self-hosting changes
   nothing about who can read the data: only the keyholders.
4. **Tamper-evidence is mandatory.** The verifier must never accept altered evidence as
   intact, and must never reject sound evidence.
5. **The adversary is a retaliating landlord** with resources and motive. Defaults assume
   that.
6. **Say what it does not do.** Honesty about limits is a feature; overclaiming in a
   courtroom fails the people relying on the tool.
7. **Accessibility and bilingual reach are not optional.** A tool a disabled or
   Spanish-speaking tenant cannot operate has failed at its purpose.

## Releases & versioning

- **SemVer** for the package. The **packet format** and the **verification protocol** are
  versioned *independently*, and the contract is: **old packets keep verifying.** A change
  that could break verification of an existing packet is a protocol major bump with a
  migration note, never a silent change.
- A release is tagged, has a `CHANGELOG.md` entry, and passes the full gate (`make verify`
  + the `a11y` browser gate + CodeQL). **Signed releases and build provenance** are
  planned (see workstream A) — today actions are SHA-pinned and dependencies locked, but
  release artifacts are not yet signed.

## The v1.0 gate (when "alpha" comes off)

v1.0 is not a feature count; it is a trust threshold. **All** of the following must be
true and documented before the "alpha — do not rely on this" caveat is removed:

- [ ] An **independent security review and cryptographic review** completed, with findings
      remediated or formally accepted (workstream A).
- [ ] A **recorded human screen-reader pass** (NVDA + VoiceOver) at WCAG 2.2 AA with no
      open moderate-or-worse finding (workstream B).
- [ ] At least **one real tenant-union or legal-aid pilot** completed, with written
      outcomes — including whether a produced packet was usable in its intended forum
      (workstream D).
- [ ] The **threat model independently reviewed** and its residual risks re-confirmed
      (workstream D), including a lawyer's read of the "not legal advice / no admissibility
      guarantee" framing.
- [ ] **Signed releases + build provenance** in place (workstream A).
- [ ] Recovery, key-rotation, and multi-device flows documented and tested for a
      non-technical organizer (workstream C).

Until every box is checked, the project stays pre-1.0 and the caveat stays.

## Release horizons

Targets for a small volunteer/solo effort, anchored at **mid-2026 = v0.1.0**. Expect slip.

| Release | Horizon | Theme | Headline goals |
| --- | --- | --- | --- |
| **v0.1.x** | H2 2026 | Alpha hardening | Real public-TSA integration tests; fix anything pilots-prep surfaces; first recorded keyboard/AT spot-checks |
| **v0.2** | late 2026 | Assurance groundwork | Verifier fuzzing; archive/re-timestamping; signed releases + provenance; SECURITY disclosure maturity |
| **v0.3** | early 2027 | Accessible packet + platform spike | PDF/UA path decided & started; native-packaging spike (engine-on-device); jurisdiction template library |
| **v0.5 (beta)** | mid 2027 | Pilot-ready | Security/crypto audit underway; recorded AT pass; 1–2 union/legal-aid pilots running; multi-device + recovery UX |
| **v1.0** | ~2028 | Trustworthy | The [v1.0 gate](#the-v10-gate-when-alpha-comes-off) met; "alpha" caveat removed |
| **v2.x+** | beyond | Reach & resilience | More languages/jurisdictions; metadata-resistant sync; broader interop; shared governance |

## Workstreams

Each item lists an **objective** and, where useful, an **exit criterion / trigger**. Items
marked *shipped* are in v0.1.0 and listed only for context.

### A. Evidence & cryptographic assurance

The courtroom rests on this; it gets the most scrutiny.

- *Shipped:* SHA-256 fixity, RFC 3161 timestamps (local issuer + HTTP client + offline dev
  TSA), hash-linked custody with salted actor commitments, the standalone verifier,
  SHA-pinned CI, CodeQL, `pip-audit`, Dependabot.
- **Continuous real public-TSA integration.** *Objective:* prove tokens from real
  authorities (e.g. FreeTSA, DigiCert) verify end to end, not just the local issuer.
  *Exit:* a scheduled, network-gated CI job stamps and verifies against ≥2 public TSAs and
  is green.
- **Archive / re-timestamping.** *Objective:* keep old packets verifiable after a TSA
  signing cert expires. *Exit:* `habitable` can re-timestamp an existing token and the
  verifier accepts the archive chain; covered by a test with an expired-cert fixture.
- **Multiple-authority redundancy by default.** *Objective:* no packet's proof rests on a
  single TSA. *Exit:* capture can stamp against N configured authorities and the verifier
  reports per-authority status.
- **Fuzz & property-harden the verifier.** *Objective:* the verifier never accepts altered
  evidence and never crashes on hostile input. *Exit:* a fuzzing target over packets/tokens
  runs in CI with no accept-on-tamper and no crash.
- **Signed releases + build provenance (SLSA).** *Objective:* a downloader can verify a
  release was built from this source. *Exit:* tagged releases ship signatures + provenance
  attestations, documented in `docs/`.
- **Reproducible builds.** *Objective:* the same source yields the same artifacts. *Exit:*
  a documented, verified reproducible build of the wheel + relay image.
- **Independent security & cryptographic review.** *Objective:* an outside expert audits
  the crypto (vault, sealed-box sync, custody commitments) and the verifier. *Trigger:*
  before v0.5/beta and a precondition of v1.0; findings remediated or formally accepted in
  `docs/audits/`.

### B. Accessibility, localization & inclusive design

- *Shipped:* WCAG-targeted bilingual (EN/ES) app gated by **axe-core** (EN+ES, zero
  violations) plus structural, **keyboard-navigation**, and **320px-reflow** tests; an
  accessible `packet.html`; a PDF with language + DisplayDocTitle + outline; a documented
  manual-testing protocol.
- **Recorded human screen-reader pass.** *Objective:* confirm the app is *usable* with AT,
  which automation can't certify. *Exit:* a dated NVDA + VoiceOver pass per
  `docs/accessibility/manual-testing.md` recorded in `docs/audits/`, no open moderate+
  finding; repeated each release (gate item for v1.0).
- **Fully tagged PDF/UA packet.** *Objective:* a structure-tagged, screen-reader-navigable
  PDF. *Constraint:* reportlab's open-source API has no marked-content, so decide between a
  tagging-capable toolchain and treating the accessible `packet.html` as the conformant
  rendering. *Exit:* either a veraPDF-clean PDF/UA file, or a documented ADR adopting the
  HTML packet as the accessible artifact with the PDF as a print convenience.
- **Languages beyond EN/ES.** *Objective:* serve more communities. *Exit:* a documented
  localization-contributor process and ≥1 added language with string parity enforced (the
  i18n parity test already guards this).
- **Plain-language & cognitive review.** *Objective:* usable under stress and across
  reading levels. *Exit:* a reviewed plain-language pass of UI copy and the setup guide.
- **Low-end-device performance.** *Objective:* capture/seal/hash feel instant on an old
  phone. *Exit:* a documented latency budget for the local path, checked on a low-end
  target.

### C. Apps, sync & platform

- *Shipped:* CLI; loopback app server; installable PWA (manifest, maskable/Apple icons,
  offline service worker); offline-first CRDT sync over a shared directory or the optional
  ciphertext-only relay; minimal jurisdiction packet templates.
- **Native mobile packaging.** *Objective:* a home-screen app that carries the engine
  on-device (it's local-first — not a wrapper around a hosted site). *Exit:* a spike with
  BeeWare/Briefcase or Tauri embedding the loopback API the PWA already speaks; then a
  documented build. *Note:* signed App Store / Play Store binaries need platform accounts
  and keys and may remain out of scope; **Add-to-Home-Screen PWA install works today.**
- **Desktop packaging.** *Objective:* a one-click desktop app for organizers. *Exit:* a
  packaged build (e.g. Briefcase/Tauri) that launches the app with no terminal.
- **Multi-device & key lifecycle UX.** *Objective:* a non-technical organizer can add a
  device, back up, rotate, and recover keys safely. *Exit:* tested flows + docs; recovery
  with a lost passphrase is impossible *by design* and clearly communicated.
- **Merge/conflict surfacing.** *Objective:* make CRDT convergence legible (who changed
  what, when) without exposing it as data loss. *Exit:* a review view in the app.
- **Metadata-resistant sync (relay).** *Objective:* shrink what even a relay can observe
  (who syncs with whom, when, sizes). *Exit:* an evaluated option (padding, batching, or an
  onion/transport layer) with the residual exposure documented in the threat model.
- **Jurisdiction template library.** *Objective:* packets that match local expectations
  without touching the verification protocol. *Exit:* a community-contributable set of
  presentation-only templates (the config surface exists; this grows it).
- **Data portability / interop.** *Objective:* a union can take its data and a legal-aid
  tool can ingest a packet. *Exit:* documented portable formats; the structured bundle is
  already plain, verifiable data.

### D. Governance, community, partnerships & sustainability

- **Tenant-union & legal-aid pilots.** *Objective:* validate the tool in the real
  power-imbalance it's built for. *Exit:* ≥1 pilot with written outcomes, including whether
  a packet was usable in its forum and what broke (gate item for v1.0).
- **Contributor growth & onboarding.** *Objective:* lower the bus-factor. *Exit:* a "good
  first issue" set, an onboarding path beyond `CONTRIBUTING.md`, and ≥1 sustained outside
  contributor.
- **Shared governance.** *Objective:* move from benevolent-maintainer toward shared
  stewardship as contributors arrive. *Trigger:* sustained contributors → adopt a documented
  decision process and `MAINTAINERS`/`GOVERNANCE` evolution in `docs/governance.md`.
- **Sustainability without strings.** *Objective:* keep the project running with **no paid
  infrastructure and no vendor lock-in.** *Exit:* a funding approach (grants/mutual-aid)
  that never introduces a server holding tenant data or a dependency on a single vendor.
- **Threat-model evolution.** *Objective:* keep the adversary model current. *Exit:* a
  scheduled re-review of `docs/threat-model.md` each release with sign-off.
- **Disclosure maturity.** *Objective:* a trustworthy security front door. *Exit:* a tested
  coordinated-disclosure flow and published advisories where relevant.
- **Education.** *Objective:* organizers can self-serve. *Exit:* the "set up your union in
  an afternoon" guide kept current; short task walkthroughs.

## Risks & mitigations

| Risk | Mitigation |
| --- | --- |
| Users treat a timestamp as proof of *more* than it shows (authorship, depiction) | The verifier and docs state the upper-bound semantics; packets and the README repeat it; *Honest limits* is prominent |
| Someone relies on it for a real case before it's audited | The alpha caveat is everywhere; v1.0 gate requires audit + pilot before the caveat is removed |
| Maintainer bus-factor (single steward) | Contributor onboarding, ADRs capturing rationale, shared-governance trigger, reproducible builds |
| A dependency or cryptographic primitive is compromised | Pinned/locked deps, `pip-audit` + CodeQL, well-reviewed primitives via `cryptography`, planned external review and provenance |
| Relay metadata exposes who-syncs-with-whom | Documented in the threat model; pure peer-to-peer needs no relay; metadata-resistance workstream |
| Overreach into legal advice | Explicit non-goal; framing reviewed by a lawyer as a v1.0 gate item |

## Measuring progress without surveillance

The tool collects **no usage data** — by principle — so progress is measured by *artifacts
and outcomes*, never by watching users:

- Audits **completed** (security, cryptographic, threat-model) and findings closed.
- Recorded **AT passes** with no open moderate+ findings.
- **Pilots** run and their written outcomes.
- **Languages** shipped (with enforced string parity) and jurisdiction templates added.
- **Verifier robustness**: fuzzing green; cross-checks against general-purpose RFC 3161 /
  hashing tools.
- **Reproducible, signed** releases.

If a metric would require instrumenting users, it is the wrong metric.

## Observability

Per the portfolio **OBSERVABILITY-STANDARD** (which is tiered by deployment shape). This
records habitable's *values*; the gates themselves live in the standard.

- **CLI / library surface — Tier C.** OTel tracing/metrics/SLOs are **N/A: no network
  surface** (offline-first, local-only). Opt-in `--log-format json` is future work.
- **Optional sync relay (`src/habitable/relay.py`) — Tier A**, with deliberate
  N/A-with-reason carve-outs driven by two hard project rules — *no telemetry / no
  phone-home* and a *dependency-free relay image* (stdlib only, small attack surface):

| Control (standard §) | habitable value |
| --- | --- |
| Structured JSON logs (§3) | **Implemented**, stdlib `logging` (no structlog dep). One JSON object per line: `ts`, `level`, `msg`, `request_id`, `method`, `path`, `status`, `latency_ms`. Per-request access log is opt-in (`HABITABLE_RELAY_LOG=json`), off by default. |
| **PII/secrets-in-logs gate (§3, never N/A)** | **Enforced.** Logs are metadata-only: no bodies, no keys, no peer IPs, and the room id is redacted to the route template `/rooms/{room}`. Pinned by `tests/test_relay.py` (`test_access_log_never_leaks_room_id_key_or_payload`) and the E2E-encryption guard in `tests/test_sync.py`. |
| `/livez` + `/readyz` (§6) | **Implemented.** `/livez` → 200 (no dep calls); `/readyz` fails **closed** (503) when the in-memory store is unhealthy; existing `/healthz` kept for aggregate counts. Probes excluded from the access log. |
| OTel traces (§1), RED/USE metrics (§2), SLOs (§4), burn-rate alerts (§5), collector/LGTM compose (§7) | **N/A-with-reason:** the relay must stay dependency-free and telemetry-free; adding OTel/OTLP exporters would contradict the *no phone-home* rule and enlarge the attack surface of a component whose whole point is that it can observe as little as possible. Trace correlation fields are omitted for the same reason. |

## Non-goals

habitable will deliberately **never**:

- Host tenants' data, photos, or cases on a server the project controls.
- Run a central account system or any authority that can read or revoke a union's records.
- Add analytics, telemetry, or "anonymous" usage reporting.
- Promise admissibility or any court outcome, or become a substitute for legal advice.
- Weaken tamper-evidence or end-to-end encryption for convenience.

## How this roadmap is maintained

This file is revisited at each release and whenever a workstream item ships or a decision
changes. Significant decisions get an ADR in `docs/adr/`. Anything here that turns out to
violate a guiding principle is removed, not finessed. Progress is reflected in
`CHANGELOG.md`; this document is the *why* and the *next*, not the change log.
