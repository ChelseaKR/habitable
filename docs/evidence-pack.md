<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Funder evidence pack — a verification map

> **Alpha boundary.** Habitable is a pre-1.0 reference implementation. It has no
> completed tenant-union/legal-aid pilot, independent security or cryptographic
> audit, legal/court/inspector validation, recorded human screen-reader pass, or
> signed native phone package. Use synthetic data only; do not rely on it for a
> real legal matter yet.

This page is a short due-diligence map, not a second marketing narrative. The
current source of truth is the [capability and claim ledger](capabilities.md),
which separates **shipped**, **partial**, **planned**, and **externally
unvalidated** work and gives every row a local evidence path and an explicit gap.

## 1. What can be verified in the repository

| Claim | Status and evidence |
| --- | --- |
| A local encrypted vault seals original media and checks original-byte fixity on read. | **Shipped under synthetic tests.** See [vault tests](../tests/test_vault_capture.py), [crypto tests](../tests/test_foundation.py), and [the threat model](threat-model.md). Malware, an unlocked endpoint, or a compelled passphrase remains outside that protection. |
| Supported media and instrument files enter a seal, SHA-256, timestamp-token, and custody pipeline. | **Shipped under synthetic tests.** See [media tests](../tests/test_media_pipeline.py), [sensor tests](../tests/test_sensor.py), and [the evidence method](evidence-method.md). This does not prove source identity, cause, or what media depicts. |
| A signed packet can be checked without calling a Habitable service. | **Shipped.** See [packet tests](../tests/test_packet_verify.py), [golden compatibility tests](../tests/test_golden.py), and the [embedding guide](embedding-the-verifier.md). The packet carries the producer key, so the signature does not establish a real-world identity. |
| RFC 3161 token validity and authority trust are distinct. | **Partial pending PR #83 on the public presentation surface.** Current code checks token imprint/signature and can evaluate a caller-supplied certificate anchor; without an accepted root, do not call the authority trusted. See [TSA tests](../tests/test_tsa.py) and the [decision table](verifier-decision-table.md). |
| Peer/local-mailbox and relay transport payloads are encrypted. | **Shipped, with a pairing/authorization gap.** See [sync tests](../tests/test_sync.py), [relay tests](../tests/test_relay.py), and [sharing trust model](sharing-trust-model.md). Relay timing/volume remain visible, and expected-peer pairing is still being hardened. |
| The local browser client has EN/ES catalog parity and automated accessibility checks. | **Partial, not a conformance finding.** See [app i18n tests](../tests/test_app_i18n.py), [axe tests](../tests/test_app_axe.py), [keyboard/reflow tests](../tests/test_app_keyboard.py), and the [ACR](accessibility/ACR.md). Human assistive-technology and Spanish review remain open. |
| Builds include the local app and are smoke-tested as installed wheels. | **Shipped in CI.** See the [CI workflow](../.github/workflows/ci.yml) and [installed-wheel smoke script](../scripts/smoke_test_installed_wheel.py). This is not a signed native phone or desktop package. |

## 2. Enforced automated gates

Branch protection currently requires these exact checks on `main`:

| Required check | What it establishes |
| --- | --- |
| `lint · types · tests (the merge gate)` | Ruff, strict mypy, the non-network test suite, overall and integrity-core coverage floors, EN/ES parity, documentation-link/claim evidence, and marker hygiene. |
| `axe-core WCAG scan (merge gate)` | Automated axe checks for the local app and accessible HTML packet. It does not establish WCAG conformance or human screen-reader usability. |
| `CodeQL (python)` | Static security analysis for Python changes. |

Additional every-PR or scheduled workflows cover i18n mechanics, dependency
audit, verifier parsing on older supported Python versions, relay-container
scanning, workflow analysis, public-TSA integration, Scorecard, and secret
scanning. Inspect the pinned definitions in [`.github/workflows/`](../.github/workflows/)
and the public Actions history rather than relying on this prose for the latest
run state.

Secret scanning has three layers: a staged-change pre-commit hook, CI gitleaks,
and scheduled full-history scanning. A narrowly scoped `.gitleaksignore`
fingerprint exists for synthetic RFC 3161 CMS tokens in the public sample; it is
not a blanket exemption.

## 3. Release and supply-chain evidence

- The [v0.2.0 release](https://github.com/ChelseaKR/habitable/releases/tag/v0.2.0)
  publishes a wheel, source archive, and CycloneDX SBOM.
- The [release workflow](../.github/workflows/release.yml) reruns the full gate,
  checks the tag/version relationship, smoke-tests the installed wheel, and
  produces build-provenance attestations.
- PyPI Trusted Publishing is wired through OIDC, but registry-side setup and an
  actual successful publish must be verified externally; repository configuration
  is not proof of publication.
- Signed-tag enforcement is fail-closed but not operational: the placeholder
  [allowed-signers file](../.github/allowed_signers) contains no maintainer key.
- Reproducible wheel/sdist verification is being reviewed in PR #85; the relay
  container does not yet have an equivalent byte-identical rebuild check.

## 4. Open trust gates a grant could fund

These are outcomes, not repository checkboxes that can be truthfully marked done
without outside people or infrastructure:

- an independent security and cryptographic review, with findings remediated or
  explicitly accepted;
- qualified legal/court/inspector review of packet usefulness and terminology;
- compensated tenant, organizer, recipient, Spanish-language, and assistive-
  technology sessions using synthetic scenarios;
- one scoped tenant-union or legal-aid pilot with incident support and written
  exit criteria;
- a reviewed on-device package, safe update path, backup/restore drill, and
  platform signing/distribution;
- operational release-signing keys and verified tagged releases.

Recruitment scopes exist for an [auditor](recruitment/role-auditor.md),
[legal reviewer](recruitment/role-legal-reviewer.md),
[accessibility tester](recruitment/role-accessibility-tester.md), and
[pilot partner](recruitment/role-pilot-partner.md). Their existence is evidence
of preparedness, not evidence the review or pilot occurred.

## 5. Sustainability and durability

Habitable is currently a single-maintainer, unfunded open-source project. See
[governance](governance.md) and [sustainability](sustainability.md) for the bus-
factor and stewardship boundaries.

The technical durability floor is narrower but useful: packet artifacts are
self-contained, old-format behavior has golden fixtures, and the standalone
verification subset has an Apache-2.0 additional permission in [`NOTICE`](../NOTICE).
That supports continued technical verification if the application is no longer
maintained; it does not guarantee future operating-system compatibility, trusted
timestamp-root availability, legal acceptance, or user support.

## Verification log

| Field | Value |
| --- | --- |
| **Source-review baseline** | 2026-07-10, `main` after claim-ledger PR #84 |
| **Automated recheck** | `make verify` checks every local Markdown/evidence path and all capability-ledger rows. |
| **Manual recheck cadence** | At every release and at least quarterly: re-read branch protection, workflow job names, release assets, registry publication, and every external gate above. |

When this page and the capability ledger differ, the ledger controls. A claim
that cannot be re-verified is removed or downgraded before it is repeated.
