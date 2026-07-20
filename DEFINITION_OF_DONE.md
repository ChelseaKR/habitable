<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Definition of Done — habitable

This is the gate-by-gate contract behind the README's one-sentence
[definition of done](README.md#definition-of-done), required at repo root by the
portfolio's [quality standard](docs/standards/QUALITY-AND-METRICS-STANDARD.md)
(§Definition of Done). It is CODEOWNER-protected — changing the quality bar is a
reviewed decision, not a drive-by edit — and reviewed quarterly.

A change is **done** when every applicable tier below holds. "Applicable" is decided
honestly: deviations are listed at the bottom with reasons, never silently assumed.

## Tier 1 — AUTO-GATE (CI on every pull request)

`make verify` runs stages 1–6 locally, byte-for-byte identical to the CI merge-gate job,
so local green means CI green.

| # | Stage | Command / where it runs | Owning standard |
|---|-------|-------------------------|-----------------|
| 1 | Format + lint, complexity ≤ 10 (`C90`) | `make lint` (ruff format --check + ruff check) | [CODE-QUALITY](docs/standards/CODE-QUALITY-STANDARD.md) |
| 2 | Strict types | `make type` (mypy --strict, zero errors) | CODE-QUALITY |
| 3 | Tests + coverage: ≥ 85 % overall, ≥ 95 % on the evidence-integrity core (`crypto.py`, `vault.py`, `tsa.py`, `verify.py`); includes property-based, tamper-detection, fuzz, golden-corpus, and the [low-end-device performance budget](docs/performance-budget.md) (`tests/test_perf_budget.py`) | `make cov` (pytest `-m "not integration"`) | CODE-QUALITY / QUALITY-AND-METRICS |
| 4 | i18n: UTF-8, BCP 47 validity, EN/ES key + plural + placeholder parity | `make i18n` | [I18N](docs/standards/INTERNATIONALIZATION-STANDARD.md) |
| 5 | Documentation truth: local Markdown links resolve; every capability-ledger claim carries a live evidence path | `make doc-links` over [`docs/capabilities.md`](docs/capabilities.md) | [DOCUMENTATION](docs/standards/DOCUMENTATION-STANDARD.md) |
| 6 | Markers: no bare `TODO`/`FIXME`/`HACK`, no un-issued `noqa`/`type: ignore` | `make markers` | CODE-QUALITY |
| 7 | Accessibility: axe-core WCAG 2.2 scan of the app shell, the freshly generated packet, the committed sample packet, and the site pages — zero violations | `make a11y` / [`a11y.yml`](.github/workflows/a11y.yml) (required status check, with a docs-only twin) | [ACCESSIBILITY](docs/standards/ACCESSIBILITY-STANDARD.md) |
| 8 | Secret scanning: gitleaks pre-commit and on every PR; TruffleHog weekly | `.pre-commit-config.yaml`; [`ci.yml`](.github/workflows/ci.yml); [`secret-scan-scheduled.yml`](.github/workflows/secret-scan-scheduled.yml) | [SECURITY](docs/standards/SECURITY-AND-SUPPLY-CHAIN-STANDARD.md) |
| 9 | Static + supply-chain security: CodeQL (python **and** actions), pip-audit, Trivy relay-image scan, zizmor workflow-SAST, Harden-Runner, every `uses:` SHA-pinned | [`codeql.yml`](.github/workflows/codeql.yml), [`ci.yml`](.github/workflows/ci.yml), [`container-scan.yml`](.github/workflows/container-scan.yml), [`zizmor.yml`](.github/workflows/zizmor.yml) | SECURITY / [CI-CD](docs/standards/CI-CD-STANDARD.md) |
| 10 | Verifier portability: the Apache-2.0 verifier subset byte-compiles on older Pythons | `ci.yml` (`verifier-portability` job) | CODE-QUALITY |
| 11 | Reproducibility (when the container path is touched): byte-identical relay OCI rebuild | `make relay-repro` in the container merge gate | SECURITY |

## Tier 2 — REVIEW-GATE (human judgment, attested in the PR)

Each item is a checkbox in [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md);
the artifact it points at must be in the diff or linked.

- Anything touching evidence handling carries a **tamper-detection test**; the verifier
  (`src/habitable/verify.py`) stays independent of vault/sync.
- No real tenant data anywhere; the README hard rules (no server-side PII, no telemetry,
  no central authority, tamper-evidence mandatory, retaliation threat model) are upheld.
- Any change to the threat model, packet format, or verification protocol is named,
  versioned, and gets a `CHANGELOG.md` entry — **old packets keep verifying**.
- **Observability impact** is stated: relay-facing changes reconcile
  [`docs/relay-observability-matrix.md`](docs/relay-observability-matrix.md); app/CLI
  paths declare N/A under the no-telemetry rule.
- **Rollback / migration** is noted for changes to the vault layout, packet format, or
  sync protocol (migrations are one-way, idempotent, and tested).
- The **ISO 25010 characteristic(s)** the change serves are named.
- Any **new dependency** has a written rationale (five runtime dependencies today; the
  floor stays deliberate).
- New external attack surface → threat-model update, routed through CODEOWNERS.
- New custom interactive UI → the manual protocol in
  [`docs/accessibility/manual-testing.md`](docs/accessibility/manual-testing.md) applies.

## Tier 3 — RELEASE-GATE (tagged releases)

Enforced by [`release.yml`](.github/workflows/release.yml); procedure in
[`docs/releasing.md`](docs/releasing.md):

- Tag is **signed** and verifies against `.github/allowed_signers`; tag version matches
  `pyproject.toml` (both guards run before any build step).
- `make verify` reruns at the exact tagged commit.
- Wheel + sdist build **byte-reproducibly** (`make repro`); the relay image rebuilds
  byte-identically (`make relay-repro`).
- A CycloneDX SBOM and a Sigstore-signed build-provenance attestation ship with the
  release; PyPI publishing uses Trusted Publishing and republishes only the exact
  attested artifacts.
- Audit-as-artifact currency: the committed audit record under
  [`docs/audits/`](docs/audits/README.md) (and the ACR, DPIA, threat-model baselines it
  indexes) is re-verified for the release rather than left stale.

## Deliberate deviations and open gaps (named, not hidden)

- **Review count:** required approvals are waived at zero — the explicit solo-maintainer
  exception in [ADR 0006](docs/adr/0006-solo-maintainer-review-count-exception.md), with
  its own revisit trigger. Review still happens; the waiver is about *required* reviews.
- **Observability stages (OTel spans, structured-log gates, SLOs):** N/A-with-reason —
  the no-telemetry principle excludes them for the app/CLI; the relay's deliberately
  minimal surface is documented in
  [`docs/relay-observability-matrix.md`](docs/relay-observability-matrix.md).
- **pa11y-ci and Lighthouse:** not wired; axe-core is the browser engine in the a11y gate
  today. The portfolio standard asks for both — an open gap, tracked in the standards
  conformance table in the README, not claimed here.
- **DORA metrics ledger:** not yet kept (the quality standard's §Metrics ledger table for
  `ROADMAP.md` is still open remediation item P2-7).
- **Merge queue:** N/A at solo-maintainer scale (single-writer main).

---

Last verified: 2026-07-17 · Recheck cadence: quarterly, and immediately when a gate is
added, removed, or reweighted (such a change must update this file in the same PR).
