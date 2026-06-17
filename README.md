# habitable — court-ready habitability evidence for tenant unions, offline and encrypted

> A privacy-first, offline-capable tool that lets tenants and their unions document repair and
> habitability problems as evidence that holds up: dated photos, condition notes, and a timeline,
> each captured with a trusted timestamp, a content hash, and a chain of custody, then assembled into
> a packet a tenant can hand to a court or a housing inspector. Everything is local-first and
> end-to-end encrypted; organizers sync directly between devices without a central server. The threat
> model assumes a landlord who retaliates, so there is no server-side personal data, no central
> authority over a union's records, and no third party who can be subpoenaed for what the union holds.
> The union owns its data.

**Status:** working reference implementation · **alpha** — the evidence core, CLI, peer-to-peer
sync, standalone verifier, and an accessible bilingual (EN/ES) installable web app are implemented
and tested on Python 3.14 (`make verify` green; the app is gated by a real `axe-core` scan in both
languages). A recorded human screen-reader pass and signed native app-store binaries remain, so
**do not rely on this for real legal matters yet** ·
independent personal open-source project · AGPL-3.0 ·
unaffiliated with any employer or client; contains no proprietary or client material; not a
government system and not built for a government customer.

**Why this domain.** A tenant withholding rent or fighting an eviction over a broken heater needs
proof, and proof is exactly what the housing-power imbalance denies them: the landlord controls the
property, the maintenance records, and often the only timeline anyone wrote down. Tenants take phone
photos, but a bare JPEG with editable EXIF data is weak evidence and a date a landlord's lawyer will
contest. Existing apps that promise to fix this usually do it by uploading every tenant's photos and
home address to a company's cloud, which creates a single honeypot and a single party to be
pressured, breached, or subpoenaed. habitable inverts that. The evidence lives on the tenant's
device, encrypted; trusted timestamps and content hashes make tampering detectable; and unions sync
peer to peer so no company sits between a tenant and their own records. It is the privacy and
local-first sibling to the civic-data projects in this portfolio, and it carries their discipline on
auditability, accessibility, and saying plainly what the tool does not do.

---

## What it does

- **Captures** a habitability issue as a structured record: photos and short video, a condition note,
  a category (heat, mold, pests, water, electrical, structural), the affected room, and a timeline of
  observations as the problem persists or recurs.
- **Makes each capture evidence-grade.** At capture the tool computes a content hash (SHA-256) of the
  original media, seals the original file unmodified, and writes an append-only chain-of-custody
  entry — all instantly and fully offline. It then obtains a **trusted timestamp** (RFC 3161) over
  that hash as soon as the device has connectivity, showing the item as *awaiting-timestamp* until the
  signed token is attached. EXIF is handled explicitly: the original (including its embedded capture
  time and any GPS) is retained sealed for evidentiary integrity, while any copy a tenant chooses to
  share can have location stripped.
- **Logs a timeline** per issue: repair requests sent, landlord responses or silence, inspections,
  and worsening conditions, each entry timestamped and hashed so the sequence is tamper-evident.
- **Syncs peer to peer.** An organizer and the tenants on a case keep records in step over
  end-to-end-encrypted, direct device-to-device sync using a CRDT, so two people editing the same
  case offline merge cleanly when they reconnect. No server holds the plaintext, and no server is
  required at all.
- **Exports a packet.** One command assembles a paginated, court-and-inspector-ready PDF (or a
  structured bundle) for an issue or a whole unit: the photos, the timeline, and an **evidence
  appendix** listing every item's hash, timestamp token, and a custody-integrity proof — the chain is
  shown to be intact without exporting who viewed or copied each item — so the recipient can verify
  nothing was altered after the fact.

```console
$ habitable export --unit "4B" --since 2026-01-01 --out 4B-packet.pdf
habitable: unit 4B — 3 issues, 27 captures, 14 timeline entries
           all 27 media items: content hash present, RFC 3161 timestamp verified
           chain of custody: intact (no gaps, no out-of-order entries)
           evidence appendix: hashes + timestamp tokens + custody proof (chain verified; identities not exported)
           location data: stripped from shared copies; originals sealed in case vault
$ habitable verify 4B-packet.pdf
habitable: 27/27 items verify against their sealed originals and timestamp tokens — packet intact
```

The verification command is the point: a packet is not "trust me," it is a set of claims a third
party can independently check against the timestamp authority and the hashes.

---

## Try it

Requires [uv](https://docs.astral.sh/uv/); the right Python (3.14) is fetched automatically.

```console
$ uv sync                 # create the env and install habitable + dev tools
$ uv run habitable demo   # capture → seal+hash → RFC 3161 → packet → verify, on synthetic data, offline
$ make verify             # the full gate: ruff + mypy --strict + pytest (property-based + tamper-detection)
```

`habitable demo` fabricates a couple of photos with embedded location, captures them as evidence,
builds a packet (location stripped from the shared copies), and independently verifies it — with no
network and no real tenant data. From there: `uv run habitable --help`.

**Just want to look?** There is deliberately no hosted app (it runs on `localhost` so your case never
leaves the device), but a static **[landing page + live sample packet](https://chelseakr.github.io/habitable/)**
shows what it produces. To document a real case on a phone, see [`docs/mobile.md`](docs/mobile.md);
to run the optional sync relay, see [`docs/relay-deploy.md`](docs/relay-deploy.md).

## Screenshots

| The local app (English / Español) | An exported, verifiable packet |
| --- | --- |
| ![The habitable local web app showing case status, issues, and an add-issue form](site/img/app-en.png) | ![An accessible habitability evidence packet with an issue, a captured photo, and an evidence appendix table](site/img/packet.png) |

The app is bilingual (EN/ES), accessible (WCAG 2.2 AA, axe-gated), and runs entirely on your device.
Every export ships an accessible `packet.html`, a paginated PDF, and a verifiable `bundle.json`.

---

## Hard rules (enforced, not aspirational)

1. **No server-side personal data, ever.** There is no central database of tenants, addresses,
   photos, or cases. Plaintext never leaves a device unencrypted. The only optional network
   components are a sync relay that sees ciphertext alone and a public timestamp authority that sees
   a hash, never the file. A relay still observes connection *metadata* — which peers connect, when,
   and roughly how much moves — even though it can read none of the contents; the mitigations are a
   no-log, self-hostable relay and pure peer-to-peer sync with no relay at all, detailed in
   `docs/threat-model.md`. Nothing the project operates can be subpoenaed for a tenant's contents,
   because it never holds them.
2. **No central authority over a union's records.** Each union holds its own keys and its own data;
   the project ships no account system, no admin who can read or revoke a union's evidence, and no
   hosted service that owns the records. Forking the code or running the relay yourself changes
   nothing about who can read the data: still no one but the keyholders.
3. **Tamper-evidence is mandatory, not optional.** Every captured item gets a content hash at capture
   and a trusted timestamp as soon as the device has connectivity, and every record is in an
   append-only, hash-linked log. The export refuses to present an item as evidence if its hash,
   timestamp, or custody chain does not verify; it surfaces the gap instead of hiding it.
4. **Originals are sealed; sharing is a deliberate, minimizing act.** The original media is preserved
   byte-for-byte for integrity. Any shared or exported copy strips location by default, and the user
   is shown exactly what a packet will disclose before it is produced. The tool never silently
   publishes a home's coordinates.
5. **Retaliation is the threat model.** Defaults assume an adversary with resources and motive: data
   at rest is encrypted, the app can be opened to a duress-safe state that hides case contents — a
   mitigation with documented limits, not a guarantee against a coercing or forensic adversary — and
   the tool collects no analytics and phones no home. The union decides what to disclose and to whom,
   documented in `docs/threat-model.md`.

---

## Honest limits — what habitable does not do

Being precise about the boundaries is part of being credible; a tool that overpromises in a courtroom
fails the people relying on it.

- **Not legal advice, and no guarantee of admissibility.** habitable produces well-documented
  evidence. Whether a court or agency admits it, or how much weight it carries, is a legal question
  this tool cannot answer.
- **It cannot manufacture a case the facts do not support.** Tamper-evidence shows an item was not
  altered after capture, and a timestamp bounds when it existed; neither proves the underlying
  condition was as a tenant describes. The tool strengthens true records, it does not create them.
- **It hosts nothing.** There is no account, no cloud of cases, and no operator who can read, produce,
  or revoke a union's data — which also means a lost key with no backup means lost data (see
  *Recoverability*).
- **A relay sees metadata, not contents.** A sync relay, if used, reads only ciphertext but can still
  observe who syncs with whom and when; pure peer-to-peer sync avoids even that.
- **A timestamp authority sees a hash, not the file** — and an RFC 3161 token bounds *when* content
  existed, not *who* created it or *what* it depicts.
- **Duress and forensic limits.** The duress-safe state hides case contents but is not a guarantee
  against a sufficiently capable coercing or forensic adversary.

The full threat model and the mitigation for each limit live in `docs/threat-model.md`.

---

## Architecture

```
habitable/
├── README.md
├── src/habitable/
│   ├── capture.py                 # media intake → hash → RFC 3161 timestamp → seal original
│   ├── evidence.py                # content hashing, fixity checks, chain-of-custody log
│   ├── exif.py                    # explicit EXIF handling: seal original, strip shared copies
│   ├── model.py                   # CRDT document model for cases/issues/timeline (offline-first)
│   ├── crypto.py                  # local encryption at rest; E2E sync keys; key backup/rotation
│   ├── sync.py                    # peer-to-peer encrypted sync; relay client sees ciphertext only
│   ├── packet.py                  # assemble court/inspector PDF + evidence appendix
│   ├── verify.py                  # independent verification of hashes, timestamps, custody
│   └── config.py                  # timestamp authorities, sync peers, policy as versioned files
├── app/                           # local-first client (PWA / desktop): capture, review, export
├── relay/                         # optional ciphertext-only sync relay (encrypted deltas + metadata, never contents)
├── tests/
│   ├── fixtures/                  # sample cases, tampered items, broken chains for verify tests
│   └── ...                        # unit, property-based, and tamper-detection tests
├── docs/                          # ARCHITECTURE, threat-model.md, privacy.md, sustainability.md, evidence-method.md, governance.md, ADRs, audits/ (+ onboarding, baseline), accessibility/, recruitment/ (call for reviewers)
└── pyproject.toml
```

The data model is a CRDT document per case, stored encrypted on each device, so the app is fully
usable with no network and two organizers editing the same case offline converge without conflict
when they sync. Capture is a pipeline: media in, original sealed and hashed, a timestamp token
fetched over the hash, a custody entry appended. Sync moves encrypted deltas directly between peers
or through a relay that only ever sees ciphertext, so adding a relay adds availability without adding
a party that can read anything. Verification is a separate module with no dependency on the rest, so a
court or an opposing party can check a packet with a small, auditable tool.

---

## The evidence engine (the part a courtroom rests on)

A photo is only as good as the answer to "how do we know it wasn't edited, and that it was taken
when you say?" habitable is built so those answers are independently checkable rather than asserted.

- **Fixity at capture.** The moment media is captured or imported, the original bytes are hashed
  (SHA-256) and written to a sealed case vault that the app treats as immutable. Any later read
  re-checks the hash, so silent corruption or tampering shows up as a failed fixity check, not a
  quietly altered exhibit.
- **Trusted timestamps.** The hash — never the photo — is sent to an **RFC 3161** timestamp
  authority, which returns a signed token proving the content existed *no later than* that time: an
  upper bound on when it was created, so an item cannot have been fabricated or edited after the fact
  without detection. Capture never blocks on the network: offline, the item is hashed and sealed
  instantly and the request is queued, the item showing an *awaiting-timestamp* status until
  connectivity lets the token be fetched and attached. Multiple authorities can be configured so the
  proof does not rest on one party, and the tokens travel inside the packet for offline verification.
- **Chain of custody.** Every action on an item — captured, viewed, copied for sharing, included in a
  packet — is an entry in an append-only, hash-linked log. A break or reordering in the chain is
  detectable, and the export reports it rather than presenting a compromised item as clean.
- **EXIF handled on purpose.** The sealed original keeps its embedded capture time and any GPS,
  because that metadata is part of the evidentiary record. Shared and exported copies strip location
  by default so producing a packet does not leak where a tenant lives, and the tool shows precisely
  which metadata each output retains or removes.
- **Independently verifiable.** `habitable verify` re-derives every hash, validates each timestamp
  token's signature and its full certificate chain back to a trusted RFC 3161 authority, and walks
  the custody chain — using only the packet and the sealed originals, with no access to the union's
  other data. Because a TSA's signing certificate eventually expires, long-held packets can be
  re-timestamped (an archive timestamp over the existing token) so old evidence keeps verifying. The
  verification tool is small and auditable on its own, so a skeptic can confirm a packet without
  trusting this project.

---

## Quality attributes (engineered for, not assumed)

Each decision below answers to a specific quality attribute, grouped into clusters for readability.
An evidence tool under an adversarial threat model lives or dies on integrity, confidentiality, and
verifiability, so those clusters carry the most weight.

### Integrity, evidence, and trust in the record
**Correctness** and **accuracy** — captures preserve original bytes and metadata; the timeline
records what happened in the order it happened. **Precision** and **fidelity** — originals are sealed
byte-for-byte with no re-encoding; hashes pin exact content and timestamps pin exact time. **Integrity**
— content hashing plus append-only, hash-linked custody makes any alteration detectable. **Auditability**
— every item carries its hash, timestamp token, and a verifiable custody-integrity proof, while the
full who-did-what trail stays in the union's vault rather than being exported.
**Provability** — a packet's claims are checkable against an external timestamp authority, not taken on
faith. **Traceability** — capture → seal → custody entries → packet item is recorded end to end.
**Determinability** and **predictability** — verification of the same packet yields the same verdict on
any machine. **Repeatability** and **reproducibility** — `habitable verify` reproduces fixity and
timestamp checks deterministically; packet assembly is deterministic for a given case state.
**Relevance** and **effectiveness** — the packet contains what a court or inspector actually needs to
act, measured against documented evidentiary requirements, not padded.

### Privacy, security, accountability, autonomy
**Confidentiality** and **securability** — end-to-end encryption at rest and in sync; the relay and the
timestamp authority see ciphertext or a bare hash, never contents; no analytics, no telemetry.
**Integrity** (supply chain) — pinned, hashed dependencies; signed releases; GitHub Actions pinned to
commit SHAs with build-provenance attestations.
**Vulnerability** management — pip-audit, gitleaks, and CodeQL in CI; a published threat model and
SECURITY policy with a disclosure path. **Accountability** — append-only custody logs and committed
`docs/audits/` record who did what to the data, while no outside party can read the data itself.
**Credibility** and **transparency** — the README states plainly what the tool is *not* (see *Honest
limits — what habitable does not do*) and how each guarantee is enforced, rather than asking for trust.
**Autonomy** — each union holds its own keys and records; there is no operator who can revoke, read, or
seize them.

### Usability, learnability, reach
**Accessibility** — WCAG 2.2 AA enforced as a merge gate; capture, timeline, and review are fully
keyboard and screen-reader operable, and any visual status has a text equivalent. **Usability** and
**convenience** — capture an issue in a few taps; export a packet in one command; no account to create
under stress. **Learnability**, **familiarity**, and **intuitiveness** — a photo-and-note flow people
already know from a camera roll, with the evidence machinery handled underneath. **Interactivity** and
**responsiveness** — capture and review work instantly on-device with no network wait. **Discoverability**
— a guided first case and an in-app explanation of what makes a strong record. **Demonstrability** —
`make demo` walks a sample case from capture to verified packet with no real tenant data.
**Understandability** — each item shows its evidence status (hashed, timestamped, custody intact) in
plain words. **Seamlessness** — capture, sync, and export operate on one local document.
**Localizability** — all strings in per-language bundles; Spanish ships in v1 given the communities
served. **Mobility** and **ubiquity** — mobile-first and installable as a PWA, because the documentation
happens in the apartment, often on the only device a tenant has.

### Dependability, resilience, safety
**Dependability** and **reliability** — the app is fully functional offline; loss of network never
blocks capturing evidence. **Availability** — there is no central service whose downtime stops a tenant;
the relay is optional and replaceable. **Fault-tolerance**, **resilience**, **robustness**, and
**survivability** — CRDT merges tolerate concurrent offline edits; a corrupted item is flagged by fixity
rather than crashing the case; data survives the loss of any one device through peer sync and
encrypted backup. **Recoverability** — an encrypted backup plus a recovered key restores a union's full
case set; a re-synced peer rebuilds local state. **Degradability** and **failure transparency** — a
missing timestamp token or a broken chain is shown as a degraded evidence status, never silently passed
as clean. **Redundancy** — multiple sync peers and configurable multiple timestamp authorities remove
single points of failure. **Stability** and **durability** — sealed originals are immutable; semver on
the packet format and verification protocol. **Safety** — the duress-safe open state (with the limits set
out in the hard rules and *Honest limits*) and location-stripped sharing reduce harm to the tenant; the
tool frames outputs as documentation, never as legal advice or a promise of a court outcome.

### Performance, scale, cost
**Efficiency** — hashing and sync deltas are incremental; the app does not re-process sealed media.
**Scalability** and **elasticity** — sync is peer to peer with no central bottleneck; a relay, if used,
forwards ciphertext and scales to zero between sessions. **Timeliness** — capture, hashing, and sealing
complete within a perceptible moment with no network in the loop, and the RFC 3161 token is fetched
asynchronously once the device is online; latency budgets for the local path are asserted in CI.
**Affordability** — the tool is free, runs on a tenant's existing phone, uses free public timestamp
authorities, and needs no paid infrastructure, because the people using it have none to spare. **Process capabilities** and
**producibility** — `make verify` reproduces the full gate; a release is one tagged, signed command.

### Maintainability, evolvability, modularity
**Maintainability**, **modifiability**, and **evolvability** — small modules behind interfaces; ruff +
mypy strict; the timestamp-authority and sync-transport layers are pluggable. **Extensibility** and
**flexibility** — new issue categories, export templates, and timestamp authorities plug in without
touching the evidence core. **Adaptability** — the packet template adapts to a jurisdiction's
expectations through config, with the verification protocol unchanged. **Modularity**, **composability**,
and **orthogonality** — capture, evidence, crypto, sync, packet, and verify are independent layers, and
verify depends on none of the others. **Simplicity** — local files and a CRDT, no server, no account
system. **Reusability** — the evidence and verify modules are importable and could harden capture in
another local-first tool. **Analyzability** — typed, documented, with an architecture and threat-model
doc. **Configurability**, **customizability**, and **tailorability** — one config sets authorities, sync
peers, sharing policy, and language. **Upgradability** — pinned dependencies with a documented bump path;
the packet format is versioned so old packets still verify.

### Operability, serviceability, sustainability
**Operability** and **manageability** — the optional relay ships with a runbook and a health endpoint; an
organizer needs none of it to work. **Administrability** — there is nothing to administer centrally;
policy is committed config a union edits for itself. **Observability** — on-device logs of capture and
sync events, kept local and never exfiltrated; the relay logs only ciphertext-passthrough metrics.
**Debuggability** — a case can be traced from capture through custody to packet under a debug flag,
without exposing plaintext off-device. **Serviceability / supportability** and **repairability** — issue
templates and a "reproduce on sample data" path; most fixes are template or config edits, and the
verification tool stands alone for support. **Deployability** and **installability** — `pipx install` for
the CLI, an installable app build, and an optional one-command relay deploy. **Agility** — a CI smoke
suite on every PR. **Autonomy**, **self-sustainability**, and **sustainability** — no paid dependency and
no service to fund, so a union keeps the tool working with no budget and no vendor.

### Compatibility, interoperability, standards, verification
**Compatibility** and **interoperability** — RFC 3161 timestamps and SHA-256 hashes are standard and
verifiable with off-the-shelf tools; packets are PDF plus a structured machine-readable bundle.
**Interchangeability** — timestamp authorities and sync transports swap without touching callers; a
packet verifies with the bundled tool or with general-purpose RFC 3161 and hashing utilities.
**Standards compliance** — RFC 3161 trusted timestamping, WCAG 2.2 AA, semver, conventional commits, SPDX
headers, and the AGPL-3.0 source obligation. **Inspectability** — hashes, tokens, and custody logs are
viewable and independently checkable. **Composability** — the structured bundle is plain data a legal-aid
tool could ingest. **Testability** — fixtures of clean, tampered, and chain-broken cases make the
evidence and verify paths unit-testable; verification attributes (provability, repeatability,
reproducibility, traceability, demonstrability) are covered above and exercised by the verify tool itself.

### Distribution, portability, installation
**Distributability** — the client ships as an installable app and PyPI package; the relay as a container
image. **Portability** — the local-first client runs on Android, iOS (PWA), and desktop, and the data is
portable encrypted files a union can move or back up anywhere. **Installability** — one command for the
CLI and a documented app install; the relay is optional and self-hostable. **Deployability** — committed
IaC stands up a relay for a union that wants one, and nothing breaks for unions that run pure peer to
peer.

---

## Accessibility and Section 508 conformance

habitable targets **WCAG 2.2 Level AA** and conformance with the **Revised Section 508 Standards**
(36 CFR Part 1194), which incorporate WCAG 2.0 A/AA by reference for web content and add the functional
performance criteria of Chapter 3. A tenant-union tool is not federal ICT, so Section 508 is not legally
required here. Building to it anyway is a values position and a practical one: disabled tenants face
housing discrimination and habitability harms at high rates, and a tool meant to give tenants power that
a disabled tenant cannot operate has failed at its purpose. Conforming to the standard governments audit
to also makes the packets and the app usable to the legal-aid workers and inspectors who receive them.

- A committed **Accessibility Conformance Report (ACR)** using the **VPAT 2.5 (Rev 508)** template lives
  at `docs/accessibility/ACR.md`, with tables for the WCAG 2.x A/AA success criteria, the Revised 508
  software (Chapter 5) and support-documentation (Chapter 6) criteria, and the **Functional Performance
  Criteria** (use without vision, with limited vision, without hearing, with limited reach and strength,
  with limited cognition).
- Every visual evidence-status indicator has a **text equivalent**: an item's hashed, timestamped, and
  custody-intact state is announced in words, never signaled by color or an icon alone. The case timeline
  and the review list are operable by keyboard and screen reader, and the exported PDF packet is tagged
  for accessibility with a text layer so a screen-reader user can read the evidence appendix.
- The app passes automated checks (axe) **and** manual screen-reader review (NVDA, VoiceOver); capture
  works without precise pointer control, and time limits are avoidable so a tenant documenting under
  stress is not rushed.
- Accessibility is a **merge-blocking CI gate**; a regression fails the build. The ACR is regenerated and
  re-committed on each release, the same audit-as-artifact discipline as the evidence method.

---

## Build plan

Phases 1–3 are **implemented** at the library + CLI level and covered by tests; Phase 4 (the
installable end-user app and localization) is the remaining work. For the strategic, multi-year
view beyond these phases — assurance, accessibility, platform, governance, and the v1.0 gate —
see **[`ROADMAP.md`](ROADMAP.md)**.

- **Phase 1 — capture and evidence core.** ✅ Media capture, content hashing, sealed originals, the
  append-only custody log, and explicit EXIF handling. Local encrypted storage. Definition of done: an
  issue can be captured offline and an item's fixity and metadata handling verified locally.
- **Phase 2 — timestamps, packets, and verification.** ✅ RFC 3161 timestamping over hashes; the
  court/inspector PDF with an evidence appendix; the standalone `verify` tool. Tamper-detection tests
  against fixtures of altered and chain-broken items.
- **Phase 3 — local-first sync.** ✅ The CRDT case model, end-to-end-encrypted peer-to-peer sync, the
  optional ciphertext-only relay, and encrypted backup with key rotation. Concurrent-offline-edit
  convergence tested (property-based).
- **Phase 4 — accessible app and generalize.** Mostly done: an accessible, bilingual (EN/ES) web app
  (`habitable app`) gated by a real **axe-core** scan in both languages plus structural + i18n-parity
  tests (✅); an **installable PWA** with PNG/maskable icons, Apple touch icon, and an offline service
  worker (✅, see `docs/mobile.md`); an **accessible `packet.html`** rendering that passes the same axe
  gate, alongside a PDF that declares its language and carries a navigable outline (✅); configurable
  packet templates (✅), the threat-model doc (✅), the setup guide (✅), and a documented manual
  screen-reader protocol (✅ `docs/accessibility/manual-testing.md`). **Remaining:** a *recorded* human
  NVDA/VoiceOver pass; a fully tagged **PDF/UA** structure tree (not available in reportlab's
  open-source API — the HTML packet is the accessible rendering until then); and signed native
  app-store binaries (the PWA covers mobile install today).

---

## Engineering and open-source practices

pytest plus property-based and tamper-detection tests for the evidence, crypto, sync, and verify paths;
ruff + mypy strict in CI; verification and packet assembly are deterministic and reproducible; `make
verify` reproduces the full gate end to end. The repo ships LICENSE (AGPL-3.0), NOTICE (independence
statement), CODE_OF_CONDUCT, CONTRIBUTING, SECURITY with a coordinated-disclosure path, a semver policy
covering the packet format and verification protocol, ADRs, a committed `docs/threat-model.md`, and
committed `docs/audits/`. Conventional commits; GitHub Actions pinned to commit SHAs with
build-provenance attestations; signed releases; Dependabot.

**Why AGPL-3.0.** This tool guards people under threat of retaliation, and the credible promise is that
no operator can quietly read or weaken the data. AGPL closes the hosted-service loophole: anyone who runs
a modified relay or a hosted variant for others must publish their changes, so a fork that secretly adds a
data-exfiltration path or a backdoored timestamp flow cannot be offered as a service to others without
that operator becoming obligated to publish its modified source. That legal lever is distinct from — and
additional to — the technical integrity the hashes, timestamps, and standalone verifier already provide.
For a privacy-critical tool the copyleft is part of the safety case, not just a license preference.

The bundled `verify` tool is the one component people may want to embed and redistribute widely. It is
offered under an additional permission (GPLv3 §7) that also licenses it under the permissive Apache-2.0,
so a court, a legal-aid group, or an opposing party can embed verification in their own software and ship
it without the AGPL reaching their code. The grant lives in the verify source headers and the LICENSE,
and NOTICE points to it. (Merely *running* the verifier never triggers copyleft in any case — the
exception is about embedding and redistribution.)

---

## Get involved — the project needs outside eyes

habitable stays labelled **alpha** until independent reviewers have checked its claims —
that is the whole bargain of a *verify, don't trust* tool, and it is the current priority.
If you can help, the **[call for reviewers](docs/recruitment/README.md)** has scoped briefs,
the funding paths, and one-click intake for each role:

- **[Security + cryptographic auditor](docs/recruitment/role-auditor.md)** — with an
  [audit-funding playbook](docs/recruitment/audit-funding.md) (grant / pro-bono / paid).
- **[Accessibility tester](docs/recruitment/role-accessibility-tester.md)** who uses
  assistive technology, for a recorded NVDA + VoiceOver pass (paid/stipended).
- **[Housing/tenant lawyer](docs/recruitment/role-legal-reviewer.md)** and a
  **[tenant-union / legal-aid pilot partner](docs/recruitment/role-pilot-partner.md)**
  (currently scoped to California).

Offers go through the [reviewer intake form](https://github.com/ChelseaKR/habitable/issues/new?template=reviewer-intake.yml);
**security vulnerabilities** go privately through [`SECURITY.md`](SECURITY.md), never a public issue.

## Definition of done

A tenant can capture a moldy bathroom offline; the photo is sealed and hashed at capture and timestamped
as soon as a device is online; an organizer on another phone syncs the case end to end encrypted with no
server; the union exports a
paginated packet with an evidence appendix for unit 4B; and a recipient runs `habitable verify` to confirm
every item is intact against its sealed original and timestamp token — with no personal data on any server
and every CI gate, including the accessibility gate, green.
