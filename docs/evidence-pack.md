<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Funder evidence pack — a verification map

> **How to read this document.** Every claim below is paired with **where to verify it**: a
> file in this repository, a CI job by its exact name, or a live artifact. Nothing here asks
> to be taken on trust, and nothing aspirational is presented as done — open items are in
> their own section, labeled open. All claims were checked against `main`
> (commit `e31c42a`) on the date in the [verification log](#verification-log) at the bottom.

> **Read this first — alpha.** habitable is **pre-1.0 alpha** (v0.2.0). The project's own
> rule, stated in the README, the roadmap, and every adoption document, is:
> **do not rely on it for real legal matters yet.** It is ready to evaluate, practice with,
> and fund toward its v1.0 trust gate — it is not yet something a tenant in a live case
> should depend on, and this project does not market it to them.
> *Verify:* `README.md` (status line: "do not rely on this for real legal matters yet"),
> `ROADMAP.md` ("Alpha caveat"), `docs/adoption/README.md`, `docs/adoption/quickstart-en.md`.

---

## 1. What habitable is, and who it serves

| Claim | Where to verify |
| --- | --- |
| habitable is a **tenant evidence vault**: a privacy-first, offline-capable tool that lets tenants and tenant unions document habitability problems (mold, no heat, leaks, pests, electrical/structural hazards) as evidence that holds up — dated photos, condition notes, and a timeline, assembled into a packet for a court or housing inspector. | `README.md` (top); live sample packet at <https://chelseakr.github.io/habitable/> |
| Every captured item is **hashed at capture** (SHA-256), the original is **sealed byte-for-byte**, and a **trusted timestamp** (RFC 3161) is obtained over the hash. | `src/habitable/capture.py`, `src/habitable/evidence.py`; `docs/evidence-method.md`, `docs/crypto-spec.md` |
| Records are **tamper-evident and hash-chained**: an append-only, hash-linked chain-of-custody log; the export refuses to present an item whose hash, timestamp, or custody chain does not verify. | `src/habitable/evidence.py`, `src/habitable/verify.py`; tamper-detection tests under `tests/` (fixtures include tampered items and broken chains); README "Hard rules" §3 |
| A packet is **independently verifiable by the other side**: a standalone verifier re-derives every hash and checks every token with no call back to this project. | `src/habitable/verify.py`; `habitable verify` in `README.md`; `docs/embedding-the-verifier.md`; the verifier subset is additionally licensed **Apache-2.0** (`NOTICE`) so courts/legal aid can embed it |
| Sharing is **end-to-end encrypted**: a tenant hands a case (or a redacted subset) to a union organizer, signed and sealed to the organizer's verified public key; any relay or courier sees only ciphertext. | `src/habitable/sync.py`, `src/habitable/crypto.py`; `docs/sharing-trust-model.md`; README "Shares with an organizer, end to end" |
| **No server-side personal data, ever** — no accounts, no cloud of cases, no operator who can read or produce a union's records. This is checkable, not asserted: `habitable prove-no-plaintext` runs a real sync through a relay, captures every byte on the wire, and greps for planted plaintext markers. | README "Hard rules" §1; `docs/prove-no-plaintext.md`; `docs/threat-model.md`; E2E-encryption guard in `tests/test_sync.py` |
| **Who it serves:** tenants, tenant-union organizers, and the legal-aid advocates working with them — distributed through those organizations (an adoption kit for organizers and unions, a board-level risk briefing, a workshop guide), not through consumer marketing. | `docs/adoption/` (`README.md`, `workshop-facilitator-guide.md`, `board-risk-briefing.md`, bilingual quickstarts); `docs/legal/` (California-scoped evidence education for advocates, explicitly not legal advice) |
| The threat model assumes a **retaliating landlord with resources**; the tool collects **no analytics and no telemetry**, by principle. | `docs/threat-model.md`; README "Hard rules" §5; `ROADMAP.md` "Guiding principles" §2 and "Measuring progress without surveillance" |
| The app is **bilingual (EN/ES)** and accessibility-gated (WCAG 2.2 AA target, axe-core scan in both languages blocks merges). | `app/i18n/`; CI job `axe-core WCAG scan (merge gate)` (`.github/workflows/a11y.yml`); `docs/accessibility/` |

## 2. The enforced CI gates, by actual job name

All GitHub Actions are pinned to commit SHAs and dependencies are locked (`uv.lock`).
Branch protection on `main` **requires** these three checks to pass before merge
(verifiable in the repository's branch-protection settings, and visible on any PR):

| Required check (exact job name) | Workflow | What it enforces |
| --- | --- | --- |
| `lint · types · tests (the merge gate)` | `.github/workflows/ci.yml` (job `gate`) | `make verify`: ruff + `mypy --strict` + full pytest suite (property-based, tamper-detection, CRDT-convergence) with coverage floors — 85% overall, 95% on the evidence-integrity core (crypto/vault/TSA/verify) — plus i18n parity and marker hygiene |
| `axe-core WCAG scan (merge gate)` | `.github/workflows/a11y.yml` (job `axe`) | Real-browser axe-core scan of the app **and** the accessible `packet.html`, in both EN and ES; any WCAG violation fails the build |
| `CodeQL (python)` | `.github/workflows/codeql.yml` (job `analyze`, matrix incl. `actions`) | Static security analysis on every push/PR plus a weekly schedule |

These additional jobs run on every push and pull request (their failure is public on the
commit even where branch protection does not list them as required):

| Job name | Workflow | What it does |
| --- | --- | --- |
| `secret scanning (gitleaks)` | `.github/workflows/ci.yml` (job `secrets`) | Gitleaks over the full checkout history of the push/PR; any finding fails the build, no ignore file |
| `verifier subset compiles on older Pythons` | `.github/workflows/ci.yml` (job `verifier-portability`) | Keeps the standalone verifier embeddable beyond the app's own Python 3.14 |
| `dependency vulnerability audit` | `.github/workflows/ci.yml` (job `audit`) | `pip-audit` against the locked dependency set |
| `build wheel + sdist` | `.github/workflows/ci.yml` (job `build`) | The package always builds |
| `mechanical i18n gates — UTF-8 · BCP 47 · EN/ES parity (merge gate)` | `.github/workflows/i18n.yml` (job `gates`) | String/plural/placeholder parity across locales |
| `Trivy image scan (relay)` | `.github/workflows/container-scan.yml` (job `scan`) | Container vulnerability scan of the optional relay image (also weekly for DB freshness) |
| `zizmor workflow security scan` | `.github/workflows/zizmor.yml` (job `zizmor`) | Audits the CI workflows themselves |

Scheduled assurance jobs:

| Job name | Workflow | Cadence |
| --- | --- | --- |
| `TruffleHog full-history scan (verified credentials only)` | `.github/workflows/secret-scan-scheduled.yml` (job `trufflehog-full-history`) | Weekly — walks the *entire* git history, not just the current diff |
| `stamp + verify against real public RFC 3161 authorities` | `.github/workflows/tsa-integration.yml` (job `public-tsa`) | Weekly — proves real public timestamp authorities verify end to end, not just the local issuer |
| `Scorecard analysis` | `.github/workflows/scorecard.yml` (job `analysis`) | Weekly OpenSSF Scorecard; the honest, itemized reading of the score is maintained at `docs/audits/scorecard-2026-07.md` |

Release pipeline (tag-triggered): job `build · SBOM · provenance · publish` in
`.github/workflows/release.yml`, then `publish to PyPI (Trusted Publishing)` — see §3.

*Verify all of the above:* read `.github/workflows/` at `main`; the public Actions tab
shows the runs (all green on `main` as of the verification date below).

## 3. Security and privacy posture — what is real today

| Claim (true today) | Where to verify |
| --- | --- |
| **Loopback-only app server.** The local web app's server refuses to bind to anything but loopback — `localhost`/`127.0.0.1` is enforced in code, not just documented, so the unlocked vault is never exposed on a network interface. There is deliberately no hosted app. | `src/habitable/appserver.py` (`_is_loopback_host`; the builder raises on any non-loopback host); README "Just want to look?" |
| **Secret scanning, three independent gates:** (1) a pre-commit gitleaks hook on staged changes, (2) the CI job `secret scanning (gitleaks)` on every push/PR, and (3) the weekly job `TruffleHog full-history scan (verified credentials only)` over the entire repository history. | `.pre-commit-config.yaml` (gitleaks hook); `.github/workflows/ci.yml` (job `secrets`); `.github/workflows/secret-scan-scheduled.yml` (header comment documents the three-gate design) |
| **Signed build provenance + SBOM ship with releases since v0.2.0.** The release job attests build provenance via Sigstore (`actions/attest-build-provenance`) and publishes a CycloneDX SBOM alongside the wheel and sdist; the v0.2.0 GitHub release carries `sbom.cdx.json` and a successful provenance-attestation step. | `.github/workflows/release.yml` (job `build · SBOM · provenance · publish`, step "Attest build provenance (signed via Sigstore)"); the v0.2.0 release assets and its Actions run; `ROADMAP.md` "Releases & versioning" |
| **Release identity guards (fail closed).** The current release workflow re-runs the full `make verify` gate at the tagged commit, smoke-tests the installed wheel, requires the tag version to match `pyproject.toml`, and refuses to build an **unsigned tag**. Note the honest state: the signed-tag guard is in place and fails closed, but the maintainer's signing key is not yet enrolled in `.github/allowed_signers` — so tag signing is *enforced-but-not-yet-operational* and remains an open v1.0 item (§4). | `.github/workflows/release.yml` ("Guard: tag must be signed", "Guard: tag version must match pyproject.toml"); `.github/allowed_signers` (header states plainly that no real key is enrolled yet); `docs/releasing.md` |
| **Supply-chain hygiene:** all Actions SHA-pinned, dependencies locked, Dependabot/Renovate, `pip-audit` + CodeQL on every change, harden-runner egress monitoring on CI jobs, no long-lived PyPI token (Trusted Publishing via OIDC). | `.github/workflows/*.yml`; `uv.lock`; `renovate.json`; `docs/sustainability.md` §3 |
| **Exported identifiers leak no device metadata.** Packet ids and clock fields are opaque, per-case-salted digests (no wall-clock, no node id); a guard test pins the invariant, and v1 packets still verify (golden corpus). | `ROADMAP.md` workstream A, *Shipped (FIX-10)*; `tests/` (`test_guards`, golden corpus) |
| **Relay observes ciphertext + metadata only, and says so.** Logs are metadata-only with the room id redacted, pinned by tests; the metadata exposure itself is documented, with pure peer-to-peer and sneakernet (USB/SD) sync as the no-relay alternatives. | `src/habitable/relay.py`; `tests/test_relay.py` (`test_access_log_never_leaks_room_id_key_or_payload`); `docs/threat-model.md`; `docs/sneakernet-sync.md` |
| **Coordinated disclosure channel** with response targets (3 business days to acknowledge, 90 days to fix or mitigate). | `SECURITY.md` |

## 4. The open v1.0 gates — named by this project's own roadmap, not done

habitable's roadmap defines v1.0 as a **trust threshold**, and the alpha caveat stays until
every box is checked. These are **open**, and this document does not claim otherwise
(*verify:* `ROADMAP.md`, "The v1.0 gate"):

- **Independent security and cryptographic review** — not yet performed. The project has
  published a call for reviewers (`docs/recruitment/role-auditor.md`,
  `docs/recruitment/audit-funding.md`) and keeps an audits directory ready
  (`docs/audits/README.md`); funding this review is precisely the kind of help that moves
  the caveat.
- **Recorded human screen-reader pass** (NVDA + VoiceOver) — not yet done. Automated
  axe-core gating is real today (§2), but the roadmap is explicit that automation cannot
  certify usability with assistive technology (`docs/accessibility/manual-testing.md`).
- **A real tenant-union or legal-aid pilot with written outcomes** — not yet run. The
  adoption kit (`docs/adoption/`) and the pilot-partner call
  (`docs/recruitment/role-pilot-partner.md`) exist to make one possible; the repository's
  jurisdiction-education docs are California-scoped (`docs/legal/`).
- **Independent threat-model review**, including a lawyer's read of the "not legal advice /
  no admissibility guarantee" framing — not yet done (`docs/threat-model.md` is
  self-maintained today, with a dated baseline in `docs/audits/threat-model-baseline.md`).
- **Operational signed release tags** — the fail-closed CI guard exists (§3), but the
  signing key is not yet enrolled, so no release tag has been signature-verified yet.
- **Recovery, key-rotation, and multi-device flows tested for a non-technical organizer** —
  documented design exists (`docs/key-management.md`, `docs/key-custody-playbook.md`);
  the tested, organizer-grade UX does not.

Also honest and open, from the README itself: the duress-safe open state is *planned, not
implemented* (today's at-rest protection is vault encryption), and signed native app-store
binaries do not exist (`docs/mobile.md` states the support boundary; PWA install works).

## 5. Sustainability, honestly

| Claim | Where to verify |
| --- | --- |
| This is an **independent, single-maintainer open-source project** (AGPL-3.0), built on the author's own time and equipment, with **no external funding** today; if funding arrives it will be disclosed in the governance docs. | `docs/sustainability.md` §2, §4; `docs/governance.md`; `LICENSE`; `NOTICE` |
| The bus-factor risk is named, not hidden, and mitigated structurally: ADRs record rationale (`docs/adr/`), onboarding is one command (`scripts/bootstrap.sh`, `.devcontainer/`), and a shared-governance trigger is documented for when sustained contributors arrive. | `ROADMAP.md` "Risks & mitigations"; `docs/good-first-issues.md`; `docs/governance.md` |
| **The durability floor does not depend on the project surviving:** packets are self-contained; verification re-derives every hash with no call home; the verifier subset is Apache-2.0 so anyone can keep verifying old packets even if this repository disappears; old packets keep verifying is a versioned contract. | `docs/sustainability.md` §1; `NOTICE`; `docs/evidence-method.md`; `docs/governance.md` |
| There is **no hosted infrastructure whose bill or shutdown strands users**: the tool is local; the optional relay is self-hostable; public RFC 3161 authorities are free to query. | `docs/sustainability.md` §4; `docs/relay-deploy.md` |
| A separate, fuller funder brief (harm-reduction thesis, impact measurement without surveillance) is maintained in-repo. | `docs/funding-impact-brief.md` |

## 6. Live artifacts

- **Landing page + verifiable sample packet:** <https://chelseakr.github.io/habitable/>
  (deployed by job `deploy landing + sample preview` in `.github/workflows/pages.yml`;
  built from `site/` — synthetic data only).
- **OpenSSF Scorecard:** badge in `README.md`; interpreted honestly in
  `docs/audits/scorecard-2026-07.md`.
- **Releases:** the v0.2.0 GitHub release (wheel, sdist, `sbom.cdx.json`, provenance
  attestation) at <https://github.com/ChelseaKR/habitable/releases>.
- **Public CI history:** <https://github.com/ChelseaKR/habitable/actions>.

## Verification log

| | |
| --- | --- |
| **Last verified** | **2026-07-10**, against `main` @ `e31c42a`, current version v0.2.0 (`pyproject.toml`, `CHANGELOG.md`) |
| **How it was verified** | Every file path read at that commit; CI job names taken verbatim from `.github/workflows/`; branch-protection required checks read from the repository settings; the v0.2.0 release run and weekly scheduled runs (public-TSA, TruffleHog, Scorecard) confirmed green in the Actions history; `make verify` run locally at the same commit |
| **Recheck cadence** | Re-verify this document against `main` **at every release and at least quarterly**, whichever comes first — re-read the workflow job names, re-run `make verify`, and re-confirm the §4 items are still open (or move them to §3 when they close). A claim that can no longer be verified is removed, not softened. |

Anything in this document that stops being true gets corrected here before it gets repeated
anywhere else. That is the same rule the rest of the repository follows: say what it does,
say what it does not do, and make both checkable.
