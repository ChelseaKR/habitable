<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Funding & impact brief — for a mutual-aid / privacy-tech grantmaker

> **For funders evaluating habitable.** This is a short, honest brief for a
> mutual-aid or privacy-technology grantmaker. It states the harm-reduction
> thesis, how we demonstrate impact **without surveilling the people we
> protect**, who keeps the project alive, and a concrete funding ask.
>
> **Read this first: it is alpha.** habitable is at **v0.2.0, alpha**. The
> evidence core, encryption, offline-first sync, the bilingual app with automated accessibility checks,
> the export packets, and the optional relay all work and are tested
> ([`../ROADMAP.md`](../ROADMAP.md)) — but until the
> [v1.0 gate](../ROADMAP.md#the-v10-gate-when-alpha-comes-off) is met (an
> independent security/crypto audit, a recorded screen-reader pass, a real
> tenant-union pilot, and more), **no one should rely on it for a real legal
> matter.** We will not pretend otherwise to win a grant. A funder's money is
> part of how the caveat comes off.

## What habitable is, in one paragraph

A tenant — or their union — documents a habitability problem (mold, no heat, a
leak, pests, electrical or structural hazards) on the only device they have,
offline, end-to-end encrypted. Each photo or note is sealed byte-for-byte,
content-hashed at capture, given an RFC 3161 timestamp token once the device has a
connection, and recorded in an append-only chain of custody. One command
exports a court- or inspector-ready packet that the **other side** can verify
hasn't been altered — using a small, standalone verifier, with no call back to
this project. There is no server holding tenant data, no account system, and no
operator who can read or revoke a union's records. The union owns its data.

## The harm-reduction thesis

The dominant way to "help tenants document problems" is to build an app that
uploads every tenant's photos and home address to a company cloud. That design
*creates the harm it claims to reduce*: a single honeypot to breach, a single
party to subpoena or pressure, and a vendor a union becomes dependent on.
habitable is built to refuse each of those failure modes — and the refusals are
enforced by architecture, not by a privacy policy you have to trust.

- **No honeypot.** There is no central database of tenants, addresses, photos,
  or cases. Plaintext never leaves a device unencrypted. The only optional
  network components are a sync relay that sees ciphertext alone and a public
  timestamp authority that sees a bare hash. Because the project never holds a
  union's contents, **nothing it operates can be subpoenaed for them.**
- **No vendor lock-in.** Each union holds its own keys and data. Forking the
  code or self-hosting the relay changes nothing about who can read the data:
  still only the keyholders. Exported packets are self-contained and verifiable
  with off-the-shelf RFC 3161 and hashing tools; the verifier is additionally
  offered under Apache-2.0 so a court or legal-aid group can embed it. **Even if
  this project disappears, a tenant's evidence still verifies.**
- **No paid infrastructure.** The tool runs locally on a tenant's existing
  phone, uses free public timestamp authorities, and needs no server the
  project must keep online and fund. A union keeps the tool working with no
  budget and no operator. This is also why a lapse in funding cannot strand a
  user — there is nothing to shut off.
- **No telemetry, ever.** The tool measures nothing about its users. This is a
  hard invariant, not a setting. It constrains how we report impact to you, and
  we accept that constraint deliberately (see below).

The adversary we design against is a **retaliating landlord** with resources and
motive. The honesty about limits — "not legal advice," "a timestamp bounds when
content existed, not who made it or what it depicts," "a lost passphrase with no
backup means lost data" — is part of the harm reduction: overpromising in a
courtroom or a safety feature fails the people relying on the tool.

## How we demonstrate impact without surveilling users

We collect no usage data by principle, so we cannot — and will not — report
downloads, active users, session counts, or "engagement." Those metrics would
require instrumenting the exact people the tool exists to protect. Instead,
progress is measured by **artifacts and outcomes**, all of them publicly
checkable in the repository
([`../ROADMAP.md` → Measuring progress without surveillance](../ROADMAP.md#measuring-progress-without-surveillance)).
A grant report against habitable would cite, with links to committed artifacts:

| What we report | What it actually demonstrates | Where it lives |
| --- | --- | --- |
| **Audits completed and findings closed** (security, cryptographic, threat-model) | The privacy/tamper-evidence claims were independently validated, not asserted | `docs/audits/` |
| **Recorded accessibility passes** (NVDA + VoiceOver) with no open moderate-or-worse finding | A disabled tenant can actually *complete a case*, not just pass automated checks | `docs/audits/`, `docs/accessibility/` |
| **Pilots run, with written outcomes** | Real unions/legal-aid used it, including whether a produced packet was usable in its forum and what broke | pilot write-ups, `ROADMAP.md` |
| **Languages shipped (string-parity enforced) and jurisdiction templates added** | Reach into the communities served, verified by a test that fails if any language is incomplete | `app/i18n/`, packet templates |
| **Verifier robustness** | Fuzzing green; cross-checks against general-purpose RFC 3161/hashing tools agree | `tests/test_verify_fuzz.py`, `docs/` |
| **Reproducible, signed releases** | A downloader can confirm a release was built from this source | release workflow, `docs/releasing.md` |

The unit of impact is therefore **a tenant who won or was protected partly
because the record held up — and nothing leaked in the process** — evidenced
through pilot partners' own written accounts, never through our watching anyone.
If a metric would require instrumenting users, it is the wrong metric, and we
will tell you so rather than quietly add it.

## Sustainability and the bus factor — stated plainly

- **Steward today: one person.** habitable is an independent personal
  open-source project by Chelsea Kelly-Reif, on the author's own time and
  equipment — not a funded product, not affiliated with any employer or client
  ([`governance.md`](governance.md)). **The current bus factor is one.** We do
  not hide this; it is the single largest project risk and a funder should weigh
  it directly.
- **Why bus-factor-1 is acceptable for *alpha*, and only for alpha.** The thing
  that would actually harm a user if the maintainer vanished — their evidence —
  does not depend on the maintainer being reachable. Produced packets are
  self-verifying and the verifier is Apache-2.0, so **losing the maintainer
  would stall new development; it would not invalidate anyone's evidence or lock
  anyone out of their data** ([`sustainability.md`](sustainability.md)). The
  successor's handover set is small and entirely in the repo (build/test/release
  docs, ADRs, the threat model). The only non-repo handover items are
  release-signing identity and publishing rights — operational, not
  data-bearing.
- **No paid dependency, no service to fund.** There is no operating cost imposed
  on users and no hosted service whose shutdown would strand them
  ([`sustainability.md` §4](sustainability.md)). Funding therefore does not buy
  "keeping the lights on"; it buys **assurance and reach** — exactly the work a
  solo maintainer cannot do alone.
- **The honest sustainability commitment.** There is no SLA and no promise the
  project reaches v1.0. What is committed is that a user's evidence, their
  ability to verify it, and their access to their own data are designed *not* to
  depend on this project's survival. Funding without strings means: no grant
  will introduce a server holding tenant data, a single-vendor dependency, or
  telemetry. An item that required any of those is the wrong item.

## What we are asking for

The work that lifts the alpha caveat is, by design, the work a single maintainer
**cannot** do alone: independent review, paid expert testing, and a real-world
pilot. That is where grant money has the highest leverage. The ask is scoped to
the v1.0 gate and to the recruitment needs already documented in
[`recruitment/`](recruitment/) and the
[audit-funding playbook](recruitment/audit-funding.md).

1. **Independent security + cryptographic audit (highest priority).** A focused
   review of the crypto (vault-at-rest, sealed-box sync, custody commitments,
   RFC 3161 timestamping) and the standalone verifier. The scope is
   deliberately bounded — one maintainer, a small documented codebase, a frozen
   hash-pinned threat-model baseline, synthetic test data only — to keep cost
   toward the low end of the **~$30k–$200k** market range cited by OSTIF for a
   crypto + app audit. We keep a costed RFP ready so a "yes" converts to an
   award in days. *A funder can pay the audit directly, or fund it through a
   facilitator (OTF Security Lab, OSTIF); we are channel-agnostic.*
2. **Stipended accessibility testing.** Pay an assistive-technology user to run
   and **record** an NVDA + VoiceOver end-to-end pass (capture → seal → export →
   verify), repeated each release. This is a v1.0 gate item and should be paid
   work, not volunteered.
3. **A real tenant-union / legal-aid pilot (currently scoped to California).** A
   modest stipend for a pilot partner's time to use the tool on real cases and
   write up the outcomes — including whether a packet was usable in its intended
   forum. This is the only way to validate the tool in the power imbalance it is
   built for.
4. **Lower the bus factor.** Small support for contributor onboarding,
   localization, and jurisdiction-template work so the project can be carried by
   more than one person — directly addressing the funder's largest risk.

**What success looks like, reported back to you:** committed audit reports with
findings closed, a recorded AT pass with no open moderate+ finding, at least one
pilot write-up describing real outcomes, and additional languages/jurisdiction
templates shipped with enforced parity — every one of them a checkable artifact,
none of them produced by watching a single user.

**Contact.** Chelsea Kelly-Reif — ckellyreif@gmail.com —
github.com/ChelseaKR/habitable.
