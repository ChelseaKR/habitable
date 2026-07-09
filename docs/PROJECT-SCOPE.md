# Project Scope

Last reviewed: 2026-07-08. Base branch: `main`.

This file is a plain-language map of the project as it exists on `main`. It does not replace the README, roadmap, audit docs, or source comments. It points to them so a reviewer can see the whole shape without reading every file first.

## What This Project Is

Habitable helps tenants collect housing-condition evidence safely. It packages photos, notes, timestamps, integrity records, and reports so a tenant or advocate can show what happened without losing control of the data.

Package metadata checked in this pass:

- Python package `habitable` for Python `>=3.14`.

## Who It Serves

- Tenants documenting habitability problems.
- Tenant organizers, legal-aid staff, and advocates reviewing evidence packets.
- Maintainers building local-first evidence capture with careful disclosure controls.

## What It Covers

- A web/PWA evidence capture surface.
- Python vault, packet, report, and export code.
- Docs for architecture, adoption, accessibility, audits, ADRs, and I18N.
- TSA timestamping, CRDT, evidence receipt, and campaign design material.
- Tests around guards, vaults, PDFs, capture, export, and accessibility.

## How It Is Put Together

- app/ contains the browser evidence tool.
- src/habitable/ contains core config, vault, packet, receipt, and CLI code.
- docs/adoption/ contains quickstarts and workshop material.
- docs/adr/ records design choices for evidence state, timestamps, and campaign use.
- tests/ covers evidence handling and user-facing outputs.

Observed source and operations surfaces:

- `Makefile`
- `app/`
- `pyproject.toml`
- `relay/`
- `scripts/`
- `site/`
- `src/`

GitHub workflow files checked:

- `.github/workflows/a11y.yml`
- `.github/workflows/ci.yml`
- `.github/workflows/codeql.yml`
- `.github/workflows/container-scan.yml`
- `.github/workflows/i18n.yml`
- `.github/workflows/pages.yml`
- `.github/workflows/release.yml`
- `.github/workflows/scorecard.yml`
- `.github/workflows/secret-scan-scheduled.yml`
- `.github/workflows/tsa-integration.yml`
- `.github/workflows/zizmor.yml`

## Trust Boundaries

- Evidence can be sensitive, so defaults favor local control and careful export.
- The docs distinguish what a packet proves from what it cannot prove.
- Legal and advocacy use still needs human review, jurisdiction-specific advice, and consent from the person whose evidence is included.

## Outside This Scope

- It is not a law firm or inspection authority.
- It cannot guarantee that a landlord, agency, or court will accept an evidence packet.
- Real pilots and counsel review remain outside code-only work.

## Docs And Evidence Checked

This pass checked 68 hand-authored doc or metadata files, 40 test files, and 11 workflow files on `main`. The count excludes vendored provider licenses, dependency folders, generated cache files, and large generated artifact history.

Large content groups were counted rather than listed file by file:

- `docs/standards/`: 12 files

Primary docs checked:

- `.github/PULL_REQUEST_TEMPLATE.md`
- `CHANGELOG.md`
- `CITATION.cff`
- `CODE_OF_CONDUCT.md`
- `CONTRIBUTING.md`
- `LICENSE`
- `NOTICE`
- `README.md`
- `ROADMAP.md`
- `SECURITY.md`
- `docs/ARCHITECTURE.md`
- `docs/I18N.md`
- `docs/accessibility/ACR.md`
- `docs/accessibility/manual-testing.md`
- `docs/adoption/README.md`
- `docs/adoption/board-risk-briefing.md`
- `docs/adoption/quickstart-en.md`
- `docs/adoption/quickstart-es.md`
- `docs/adoption/workshop-facilitator-guide.md`
- `docs/adr/0001-record-architecture-decisions.md`
- `docs/adr/0002-state-based-crdt-and-hlc.md`
- `docs/adr/0003-rfc3161-with-offline-dev-tsa.md`
- `docs/adr/0004-accessible-html-packet-as-conformant-rendering.md`
- `docs/adr/0005-i18n-g12-cldr-na-by-design.md`
- `docs/adr/0006-solo-maintainer-review-count-exception.md`
- `docs/adr/0007-limits-first-distress-decoy-vault-model.md`
- `docs/audits/README.md`
- `docs/audits/onboarding.md`
- `docs/audits/packet-attack-redteam.md`
- `docs/audits/scorecard-2026-07.md`
- `docs/audits/threat-model-baseline.md`
- `docs/bundle-schema.md`
- `docs/commons.md`
- `docs/crypto-spec.md`
- `docs/embedding-the-verifier.md`
- `docs/evidence-kernel.md`
- `docs/evidence-method.md`
- `docs/funding-impact-brief.md`
- `docs/good-first-issues.md`
- `docs/governance.md`
- `docs/ideation/02-large-scale-fixes.md`
- `docs/key-custody-playbook.md`
- `docs/key-management.md`
- `docs/legal/README.md`
- `docs/legal/california-evidence-notes.md`
- `docs/legal/declaration-template.md`
- `docs/legal/foundation-guidance.md`
- `docs/localization-guide.md`
- `docs/mobile.md`
- `docs/performance-budget.md`
- `docs/privacy.md`
- `docs/prove-no-plaintext.md`
- `docs/recruitment/README.md`
- `docs/recruitment/audit-funding.md`
- `docs/recruitment/role-accessibility-tester.md`
- Plus 13 more files in the same inventory.

Representative test files checked:

- `tests/conftest.py`
- `tests/golden/kernel/vectors.json`
- `tests/golden/packet-v1/bundle.json`
- `tests/golden/packet-v1/bundle.sig.json`
- `tests/golden/packet-v1/media/cap-001767312000004.000000.9e9988c4dd36aa51.jpg`
- `tests/golden/packet-v2/bundle.json`
- `tests/golden/packet-v2/bundle.sig.json`
- `tests/golden/packet-v2/media/cap-aa8d494deb3af534.jpg`
- `tests/test_app_accessibility.py`
- `tests/test_app_axe.py`
- `tests/test_app_i18n.py`
- `tests/test_app_keyboard.py`
- `tests/test_app_pwa.py`
- `tests/test_appserver.py`
- `tests/test_archive.py`
- `tests/test_cli_demo.py`
- `tests/test_cli_key.py`
- `tests/test_cli_social_recovery.py`
- `tests/test_commons.py`
- `tests/test_critical_paths.py`
- `tests/test_evidence_exif.py`
- `tests/test_foundation.py`
- `tests/test_golden.py`
- `tests/test_guards.py`
- `tests/test_htmlpacket.py`
- `tests/test_i18n_format.py`
- `tests/test_kernel_golden.py`
- `tests/test_model.py`
- `tests/test_packet_verify.py`
- `tests/test_pdf.py`
- `tests/test_perf_budget.py`
- `tests/test_prove.py`
- `tests/test_relay.py`
- `tests/test_site_axe.py`
- `tests/test_sync.py`
- `tests/test_threshold.py`
- `tests/test_tsa.py`
- `tests/test_tsa_integration.py`
- `tests/test_vault_capture.py`
- `tests/test_verify_fuzz.py`

## Validation Notes

For this docs PR, validation means the scope file was generated from the clean `origin/main` worktree, reviewed against repo metadata and docs inventory, and checked with `git diff --check`. Project test suites are still the authority for code behavior, because this PR changes documentation only.
