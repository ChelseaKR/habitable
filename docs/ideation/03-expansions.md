<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Expansions (2026-07-01)

Net-new capability, organized in three horizons. Each is distinct from the `E-##`
expansions in
[`docs/research/synthetic-personas-feedback.md`](../research/synthetic-personas-feedback.md);
where an idea deepens an existing `E-##`, the ID is cited and the *new* substance is what
matters. Effort tiers **S/M/L/XL** as in [`02-large-scale-fixes.md`](02-large-scale-fixes.md).

Format per item: pitch · impact · shape of the work · effort · risks/dependencies ·
excellence bar.

---

## Horizon 1 — deepen the core

### EXP-01 — External anchoring to close the hostile-keyholder gap

**Pitch.** Publish only custody-chain *head hashes* (never contents) to a public,
append-only anchor, so a hostile keyholder can no longer rewrite the local chain
undetected.

**Impact.** `threat-model.md` §5 admits its sharpest limit: the custody log is
tamper-*evident* but "does not prevent the holder of the vault key from discarding the
whole log and writing a new internally-consistent one before any external party has seen
the head hash." That is the one gap a landlord's lawyer can exploit against a self-held
record. Anchoring the head hash externally (a second timestamp over the head, an
OpenTimestamps commitment, or a public transparency log) converts "trust the tenant kept
the chain honest" into "the head existed by time T, so the chain can't have been rebuilt
after T." Highest evidentiary value of any expansion here.

**Shape of the work.** The pieces mostly exist: `tsa.retimestamp` already stamps over
arbitrary bytes, and `CustodyLog.head_hash` is available. Add a `habitable anchor` command
that timestamps the current custody head (optionally to multiple authorities) and records
the anchor in the vault; `verify` reports the earliest anchor time as the "chain existed
by" bound. Optionally support publishing the head hash (a 32-byte value revealing nothing)
to a public log. Touch `capture.py`/a new module, `evidence.py`, `verify.py`, docs.

**Effort.** L.

**Risks/dependencies.** Anchoring cadence is a policy choice (every capture is costly;
periodic is cheaper but widens the rewrite window) — document the tradeoff honestly.
Publishing to a third-party log adds a party; keep it hash-only and optional. Pairs with
`FIX-05`.

**Excellence bar.** `verify` can state "this custody chain provably existed by
`<anchor time>`," and the threat model's §5 hostile-keyholder row moves from "unmitigated"
to "mitigated for events before the last anchor."

### EXP-02 — Deterministic packets + a recipient-facing "packet diff"

**Pitch.** Make two exports of the same case state byte-identical, and give recipients a
tool to see exactly what changed between two versions of a packet.

**Impact.** Reproducibility is claimed as a quality attribute, but `bundle.json` embeds a
fresh `generated_at` each export, so two packets of the same evidence differ. A judge or
inspector (P-09, P-10) who receives an updated packet has no honest way to see what moved.
A deterministic core plus a diff ("issue 2's severity changed; 3 captures added; nothing
removed") makes updates trustworthy and supports the "old packets keep verifying" contract.

**Shape of the work.** Separate the evidentiary bundle (deterministic) from a small
non-signed manifest carrying `generated_at`; add `habitable diff old/ new/` over two
packet directories comparing items, hashes, custody heads, and disclosures. Touch
`packet.py`, `verify.py`, a new diff module, `docs/bundle-schema.md`.

**Effort.** M.

**Risks/dependencies.** Determinism must not remove needed provenance; keep the timestamp
in a clearly non-evidentiary field. Complements reproducible-build work (roadmap A).

**Excellence bar.** Exporting the same case twice yields identical `bundle.json` bytes;
`diff` output is human-readable in EN/ES and lists added/changed/removed items precisely.

### EXP-03 — On-device, honest "evidence-strength" self-assessment

**Pitch.** Show a tenant, before they hand anything over, how strong each item's *record*
is — timestamp present, redundant authorities, custody depth, corroborating timeline —
framed strictly as record strength, never as a legal claim.

**Impact.** Tenants and organizers (P-01, P-07) cannot currently tell a strong record from
a weak one until a recipient verifies. A local, telemetry-free indicator ("this photo:
hash ✓, 2 timestamp authorities ✓, in a timeline with a repair request and inspection")
turns the invisible evidence machinery into actionable feedback and nudges toward stronger
documentation — without ever implying admissibility (which stays a hard non-goal).

**Shape of the work.** Compute a per-item and per-issue strength summary from data already
present (`verified_authorities`, custody length, linked timeline entries) and surface it in
`status`/the app, with the `disclosure.py` honesty framing attached. Touch
`appserver.status`, `app/app.js`, `cli.py` (`_cmd_status`).

**Effort.** M.

**Risks/dependencies.** Must never read as a legal score — copy reviewed against R-26/R-41
and the "Requests we should decline" table (no admissibility promises). On-device only (no
telemetry).

**Excellence bar.** A tenant can see, offline, which items are single-authority or missing
a timestamp and what would strengthen them, with plain-language caveats that it is record
strength, not legal weight.

### EXP-04 — Evidentiary threading: link captures to timeline events

**Pitch.** Let a capture attach to a specific timeline event (repair request sent,
landlord response, inspection) so a packet tells the request→silence→worsening story as
connected evidence, not a flat list.

**Impact.** Extends E-01 (recurrence linking) into full narrative threading — the legal
story Alejandra (P-12) and Inspector Diaz (P-10) actually argue is *causal and temporal*:
"requested repair on X, no response, condition worse by Y." Today captures and timeline
entries are independent grow-logs with no cross-links.

**Shape of the work.** Add optional `timeline_entry_id`/`capture_id` cross-references in
`model.GrowLog` payloads (append-only, so no CRDT conflict) and render the thread in the
packet and inspector view. Touch `model.py`, `packet.py`, `htmlpacket.py`, `pdf.py`.

**Effort.** M.

**Risks/dependencies.** Keep links immutable (grow-log semantics). Complements the
jurisdiction/inspector rendering (E-16/E-17).

**Excellence bar.** A packet can render "repair requested → 14 days silence → worsened
(photo)" as one threaded issue, and `verify` still checks each linked item independently.

---

## Horizon 2 — adjacent capabilities, audiences, integrations

### EXP-05 — Zero-install, in-browser WASM verifier (offline static page)

**Pitch.** Compile the Apache-2.0 verifier subset to run entirely in the recipient's
browser, so a clerk drags a packet onto a static page and gets a verdict with no install
and no server ever touching the case.

**Impact.** This is the concrete, buildable mechanism behind E-15 (which the research pass
named as the biggest expansion gap): P-09's "a packet that says 'run `habitable verify`' is
a packet I will not verify." Because `verify` already imports only `canonical/crypto/`
`evidence/tsa/errors`, it is uniquely portable. A WASM (via Pyodide) or a small
JS/TS re-implementation of the verification contract, served as a static offline-capable
page, lets any recipient confirm integrity while the project still hosts no case data.

**Shape of the work.** Either (a) run the existing Python subset under Pyodide in a static
page, or (b) re-implement the documented verification contract
(`docs/verifier-decision-table.md`, `docs/bundle-schema.md`) in TypeScript and cross-test
it against the Python verifier over the golden corpus. Ship it on the existing Pages site
(`site/`, `.github/workflows/pages.yml`) as an offline PWA.

**Effort.** L.

**Risks/dependencies.** A second verifier implementation is a maintenance and correctness
liability — pin it to the golden corpus and the decision table so drift fails CI. RFC 3161
cert-chain checking in-browser is the hard part; scope carefully.

**Excellence bar.** A non-technical recipient verifies a real packet in a browser, offline,
with no install; the in-browser verdict matches the Python verifier on 100% of the golden
corpus (CI-enforced).

### EXP-06 — Jurisdiction-native export profiles + municipal form filling

**Pitch.** Emit packets that speak a jurisdiction's code-citation vocabulary and can
pre-fill common municipal habitability-complaint forms.

**Impact.** Deepens E-16 (jurisdiction template library) and R-28 from *presentation*
templates into *semantic* mappings: Inspector Diaz (P-10) needs habitable's six categories
mapped to his code sections, and a tenant needs the local complaint form filled from case
data. This is where a packet becomes directly *actionable* by an agency.

**Shape of the work.** A config-driven mapping from habitable categories/rooms to a
jurisdiction's citation taxonomy, plus a form-fill export (PDF form fields) for a first
jurisdiction (California, matching the pilot scope). Community-contributable, so it does not
grow the core (R-44). Touch `config.py`, `packet.py`, a new templates directory,
`docs/legal/california-evidence-notes.md`.

**Effort.** L.

**Risks/dependencies.** Requires a real SME/legal reviewer per jurisdiction (human gate);
ship only jurisdictions a lawyer has vetted, clearly scoped (R-34).

**Excellence bar.** A California packet cites the relevant code sections in the inspector's
own vocabulary and pre-fills the local complaint form, all from existing case data, with a
lawyer's sign-off on the mapping.

### EXP-07 — Real audio/video evidence pipeline

**Pitch.** Turn the half-built video path (`FIX-11`) into a first-class capability:
capture, seal, timestamp, metadata-strip, and packetize short audio/video.

**Impact.** Some habitability evidence is inherently temporal — a landlord's recorded
threat, a furnace that won't ignite, water actively dripping. Today these can be sealed but
not shared. A real pipeline serves cases photos cannot.

**Shape of the work.** Add video/audio metadata stripping (ffmpeg or a vetted library),
a shared-copy path in `packet._build_item`, a poster-frame or transcript for the accessible
HTML/PDF rendering (alt-text/transcript ties to E-03/R-06), and verify support. Touch
`exif.py`/a new media module, `capture.py`, `packet.py`, `htmlpacket.py`, `verify.py`.

**Effort.** L.

**Risks/dependencies.** A media dependency weighs against the low-end-device/small-footprint
values (R-03); make it optional. Accessibility: video needs captions/transcripts to meet the
same axe/AT bar.

**Excellence bar.** A short video captures, seals, timestamps, strips metadata, packetizes,
and verifies — with a transcript or captions that pass the accessibility gate.

### EXP-08 — On-device campaign engine over multiple vaults

**Pitch.** A local organizer tool that reads the several vaults an organizer already holds
keys to and produces a building-level evidence-health roll-up and a campaign narrative —
strictly on-device, no server.

**Impact.** Defines the data model behind E-11 (multi-case campaign view): Renee (P-07)
manages ~12 cases and cannot tell which units still need a timestamp, are export-ready, or
have a broken chain. This aggregates read-only across vaults the organizer can already open,
producing per-unit badges and a whole-building packet — the rent-strike/organizing artifact
the tool is ultimately for.

**Shape of the work.** A new local aggregator that opens N vaults (with their passphrases /
the organizer's own keys) read-only, computes `status`-style health per case, and can emit a
combined building packet. Touch a new `campaign` module, `cli.py`, the app. Must reuse the
tested core, not fork it.

**Effort.** L.

**Risks/dependencies.** Must not become a central store (invariant #1/#3) — it reads local
vaults the organizer legitimately holds, computes on-device, and persists nothing new
centrally. Interacts with co-custodian survivability (E-12) and key custody (E-14).

**Excellence bar.** An organizer sees a building-wide evidence-health board and exports a
multi-unit packet entirely on their own device, with zero case data leaving it.

### EXP-09 — Instrument-corroborated conditions (sensor CSV import)

**Pitch.** Import an independent instrument's readings — a temperature logger for a no-heat
case, a moisture meter for mold — hashed and timestamped like any capture, to corroborate a
condition with something other than the tenant's own photo.

**Impact.** Directly answers opposing counsel's (P-11) strongest line — "the timestamp
doesn't prove the *condition*." An $15 temperature logger's CSV, sealed and RFC-3161
timestamped, is independent corroboration a landlord's lawyer cannot wave away as "you set
that up." High evidentiary leverage for the classic no-heat and mold cases.

**Shape of the work.** Treat a CSV/data file as a capture type: hash, seal, timestamp,
render a small chart in the packet (accessible: table + text equivalent). Touch
`capture.py`, `packet.py`, `htmlpacket.py`/`pdf.py`. Reuse the whole evidence spine.

**Effort.** M.

**Risks/dependencies.** Charts must meet the accessibility bar (data table + text
equivalent, never color-only). Do not overclaim: the reading is corroboration, not proof of
cause (R-26 framing).

**Excellence bar.** A temperature log imports, seals, timestamps, and appears in the packet
as an accessible chart+table that `verify` treats as a first-class, hash-anchored item.

### EXP-10 — Reference importer + signed "evidence receipt" for legal-aid tooling

**Pitch.** Ship a small, tested reference importer and a signed machine-readable receipt so
a legal-aid case-management system can ingest and re-verify a habitable packet in minutes.

**Impact.** Extends E-26/E-27 (published schema + embedding cookbook) with something
runnable: P-23 (integrator) wants "verify a habitable bundle in 20 lines," and Alejandra
(P-12) wants the bundle to plug into her tooling. A reference importer against the published
`docs/packet-bundle.schema.json` makes the interop contract real and testable.

**Shape of the work.** A tiny, dependency-light importer library (built on the Apache-2.0
verifier subset) plus a signed "receipt" summarizing a verified packet for downstream
systems. Cross-test against the golden corpus. Touch a new `contrib/` importer,
`docs/embedding-the-verifier.md`, `docs/bundle-schema.md`.

**Effort.** M.

**Risks/dependencies.** Keep it within the Apache-2.0 subset so integrators inherit no AGPL
obligation. Pin to the schema's semver contract so a version bump can't silently break
integrators.

**Excellence bar.** A third-party system ingests and independently re-verifies a packet
using only the published schema + reference importer, validated against the golden corpus in
CI.

---

## Horizon 3 — transformative bets

### EXP-11 — Threshold (M-of-N) social custody of recovery keys

**Pitch.** Split a case's recovery key across several union members so no single steward is
a honeypot and a case survives any one person losing their phone — turning the E-05/E-14
*playbooks* into a cryptographic mechanism.

**Impact.** By-design unrecoverability terrifies non-technical users (P-03 Dorothy) and the
union's IT steward (P-08 Sam), who otherwise becomes the very honeypot the project forbids.
Shamir secret sharing (say 2-of-3) lets a case be recovered by a quorum without any single
custodian holding enough to read it, and without any server — closing the recoverability gap
while honoring "no central authority."

**Shape of the work.** Add threshold-shared recovery blobs (split the DEK-wrapping secret
via Shamir), a share-distribution flow, and a quorum-recovery command with a rehearsal/drill
mode (E-13). Touch `crypto.py`, `vault.py`, `cli.py` (`key` subcommands),
`docs/key-custody-playbook.md`.

**Effort.** XL.

**Risks/dependencies.** New crypto = must be reviewed by the pending external cryptographer
before any real use. Must not reintroduce a party who alone can recover (each share is
insufficient). Pairs with `FIX-08`.

**Excellence bar.** A case is recoverable by a 2-of-3 quorum with a documented, drilled
procedure; no single share holder can read or recover the case; the construction is in
`docs/crypto-spec.md` and audit-reviewed.

### EXP-12 — Metadata-resistant transport

**Pitch.** Hide even *who syncs with whom, when, and how much* — the one exposure the relay
cannot avoid today — via padding/batching or an anonymity-network transport.

**Impact.** `threat-model.md` §5 lists relay metadata as unmitigated except by not using a
relay. For a maximum-retaliation tenant (P-04) sharing infrastructure, connection metadata
is itself sensitive. This is the deep version of E-23/R-46 (which document and self-audit
metadata); this *reduces* it.

**Shape of the work.** Evaluate options: fixed-size padded messages + batched flush,
cover traffic, or a `Transport` implementation over an existing anonymity network. Document
the residual exposure precisely in the threat model. Touch `sync.py` (new transport),
`relay.py`, `docs/relay-observability-matrix.md`, `docs/threat-model.md`.

**Effort.** XL.

**Risks/dependencies.** Traffic-analysis resistance is genuinely hard and easy to get
subtly wrong — needs the external review, and must not be overclaimed (honest residual-risk
statement). Padding costs bandwidth (tension with P-06's data cap).

**Excellence bar.** A documented, reviewed transport that measurably reduces what a relay
operator can infer about sync partners, with the *remaining* exposure stated honestly in the
threat model.

### EXP-13 — Extract a reusable local-first evidence kernel

**Pitch.** Package `evidence` + `tsa` + `verify` + `crypto` + `canonical` as a standalone,
Apache-2.0 tamper-evidence kernel other civic tools can adopt.

**Impact.** Portfolio-level leverage: the hardest, most valuable part of habitable — a
correct, fail-closed, RFC-3161-backed, custody-linked evidence spine with an independent
verifier — is exactly what a wage-theft documenter, an environmental-hazard logger, or any
"prove this record wasn't altered after the fact" tool needs. The architecture already
isolates this subset (the verifier island; the Apache-2.0 dual license). Extracting it turns
one tool's investment into a shared civic-tech primitive.

**Shape of the work.** Carve the subset into an installable package with its own docs,
golden corpus, and semver contract; habitable depends on it. Touch packaging
(`pyproject.toml` already isolates a `verify` extra), a new repo/package boundary, docs.

**Effort.** XL.

**Risks/dependencies.** A published library is a long-term maintenance commitment for a
single maintainer (P-18/R-44) — only worth it if a second adopter is real. Keep the API
small and the license permissive.

**Excellence bar.** A second civic tool adopts the kernel to add tamper-evidence without
copying code, and both tools' verifiers cross-check the same golden corpus.

### EXP-14 — Opt-in, on-device aggregate housing-conditions commons (no telemetry)

**Pitch.** Let unions *voluntarily* contribute cryptographically de-identified, aggregate
counts (e.g. "this building: N mold issues over M months") to a public housing-conditions
commons — computed on-device, never per-user, never automatic.

**Impact.** Funders (P-21) and organizers want population-level impact, but the project
measures *nothing* about users by principle. A strictly opt-in, aggregate-only,
on-device-computed contribution — a union chooses to publish a coarse, de-identified summary
— could build a public evidence base for housing advocacy without any telemetry or central
case store. This is a genuinely new capability at the edge of the invariants, and must be
designed to stay inside them.

**Shape of the work.** An explicit, per-union, opt-in export of coarse aggregate counts with
k-anonymity/thresholding and no linkage to cases or people; publication is a deliberate act,
never a background phone-home. Touch a new aggregation module, docs, and the "Requests we
should decline" analysis (to prove it is *not* telemetry).

**Effort.** XL.

**Risks/dependencies.** The invariant risk is severe — this must be provably opt-in,
aggregate-only, and de-identified, or it is declined outright. Requires the "decline table"
discipline and likely external review of the privacy model before any release.

**Excellence bar.** A union can *choose* to publish a k-anonymous building-level summary that
reveals nothing about any individual or case, with a written argument (audited) that it does
not violate the no-telemetry / no-central-data invariants — or a documented decision to
decline it.

### EXP-15 — Honest, limits-first coercion-resistance ("distress" model)

**Pitch.** Design and build the safety feature the docs already promise (`FIX-14`) — but
limits-first: a red-team-reviewed distress/decoy model that states exactly what it can and
cannot stop, at the moment of use.

**Impact.** Maximum-retaliation and shared-phone personas (P-04 Tobias, P-03 Dorothy, and the
adversary lens P-22) need *some* real coercion mitigation, but a duress feature that
overpromises can get someone hurt. The right version is honest and modest: perhaps a separate
decoy vault under its own passphrase, with a clear, scary explanation of its forensic and
coercion limits shown when it is enabled (R-15).

**Shape of the work.** After the `FIX-14` doc reconciliation, design the model with the
red-team doc (`docs/audits/packet-attack-redteam.md`) and the threat model; implement only
what survives that review; surface limits at point-of-use. Touch `vault.py`, `crypto.py`,
`app/app.js`, `cli.py`, threat-model docs.

**Effort.** L (after the S doc-reconciliation in `FIX-14`).

**Risks/dependencies.** Must never claim a guarantee (the research decline-table forbids
duress *guarantees*). Needs red-team/security review before release. Depends on `FIX-14`
shipping the honest-docs correction first.

**Excellence bar.** If shipped, the feature ships with a red-team-reviewed, point-of-use
statement of its exact limits and no guarantee language; if not shipped, the docs plainly say
the capability does not exist.
