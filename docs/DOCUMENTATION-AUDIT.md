# Documentation Audit

Last reviewed: 2026-07-08. Base branch: `main`.

This audit records the documentation sweep and remediation loop for this repository. It checks the docs as a system: entry points, root-level process and legal files, project scope, setup and validation notes, safety and privacy posture, architecture and planning docs, local links, and the places where code, tests, workflows, and docs meet.

## Audit Results

| Area | Result | Evidence |
| --- | --- | --- |
| Entry docs | pass | `README.md` present |
| Security/process docs | pass | CONTRIBUTING.md, SECURITY.md, CHANGELOG.md |
| Architecture/planning docs | pass | 9 architecture/interface docs; 4 planning/research docs |
| Safety/privacy/audit docs | pass | 15 safety/privacy/accessibility/audit docs |
| Validation surface | pass | 32 test files; 11 workflow files |
| Local doc links | pass | 526 authored-doc links checked; 0 unresolved |

## Root-Level Documentation Audit

This section covers hand-authored documentation at the repository root and root-adjacent GitHub templates. It is separate from the `docs/` inventory so README, process, legal, release, and project-specific root files do not get hidden inside the larger docs tree.

| Surface | Result | Evidence |
| --- | --- | --- |
| Root README | pass | Present: `README.md` |
| Root process docs | pass | Present: `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md` |
| Root legal, citation, and conduct docs | pass | Present: `LICENSE`, `NOTICE`, `CITATION.cff`, `CODE_OF_CONDUCT.md` |
| Other root project docs | info | `ROADMAP.md` |
| Root-adjacent GitHub templates | pass | `.github/PULL_REQUEST_TEMPLATE.md`, `.github/CODEOWNERS` |
| Root/template doc links | pass | 48 root-level/template links checked; 0 unresolved |

Root-level files checked:

- `CHANGELOG.md`
- `CITATION.cff`
- `CODE_OF_CONDUCT.md`
- `CONTRIBUTING.md`
- `LICENSE`
- `NOTICE`
- `README.md`
- `ROADMAP.md`
- `SECURITY.md`

Root-adjacent template files checked:

- `.github/PULL_REQUEST_TEMPLATE.md`
- `.github/CODEOWNERS`

## Remediation In This PR

- Added missing root-level remediation docs found by the audit loop, including legal, conduct, contribution, or security files where absent.
- Added `docs/PROJECT-SCOPE.md` as the plain-language project and boundary map.
- Added this audit record so future doc changes have a dated baseline.
- Added or refreshed the docs index so scope, audit, and primary docs are easy to find.
- Fixed or added root/doc remediation files: `docs/evidence-kernel.md`, `docs/recruitment/README.md`, `docs/standards/README.md`.

## Repo Surfaces Checked

Package and workspace metadata:

- Python package `habitable` (>=3.14).

Source and operations surfaces seen at the repo root:

- `app/`
- `Makefile`
- `pyproject.toml`
- `scripts/`
- `src/`
- `tests/`
- `uv.lock`

Workflow files checked:

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

## Documentation Inventory

| Category | Count | Representative files |
| --- | ---: | --- |
| architecture and interfaces | 9 | `docs/ARCHITECTURE.md`, `docs/adr/0001-record-architecture-decisions.md`, `docs/adr/0002-state-based-crdt-and-hlc.md`, `docs/adr/0003-rfc3161-with-offline-dev-tsa.md`, `docs/adr/0004-accessible-html-packet-as-conformant-rendering.md`, `docs/adr/0005-i18n-g12-cldr-na-by-design.md`, `docs/adr/0006-solo-maintainer-review-count-exception.md`, `docs/adr/0007-limits-first-distress-decoy-vault-model.md`, plus 1 more |
| entry points and repo process | 10 | `.github/CODEOWNERS`, `.github/PULL_REQUEST_TEMPLATE.md`, `CHANGELOG.md`, `CITATION.cff`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `LICENSE`, `NOTICE`, plus 2 more |
| examples and guides | 3 | `docs/adoption/workshop-facilitator-guide.md`, `docs/localization-guide.md`, `docs/setup-guide.md` |
| operations and release | 1 | `docs/relay-deploy.md` |
| other docs | 30 | `docs/I18N.md`, `docs/PROJECT-SCOPE.md`, `docs/README.md`, `docs/adoption/README.md`, `docs/adoption/quickstart-en.md`, `docs/adoption/quickstart-es.md`, `docs/commons.md`, `docs/crypto-spec.md`, plus 22 more |
| planning and research | 4 | `ROADMAP.md`, `docs/ideation/02-large-scale-fixes.md`, `docs/research/execution-log.md`, `docs/research/synthetic-personas-feedback.md` |
| safety, privacy, accessibility, and audits | 15 | `docs/DOCUMENTATION-AUDIT.md`, `docs/accessibility/ACR.md`, `docs/accessibility/manual-testing.md`, `docs/adoption/board-risk-briefing.md`, `docs/audits/README.md`, `docs/audits/onboarding.md`, `docs/audits/packet-attack-redteam.md`, `docs/audits/scorecard-2026-07.md`, plus 7 more |
| grouped generated/source content | 12 | `docs/standards/` counted as a content group, not listed file by file |

Full hand-authored doc inventory checked by this pass:

- `.github/CODEOWNERS`
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
- `docs/DOCUMENTATION-AUDIT.md`
- `docs/I18N.md`
- `docs/PROJECT-SCOPE.md`
- `docs/README.md`
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
- `docs/recruitment/role-auditor.md`
- `docs/recruitment/role-legal-reviewer.md`
- `docs/recruitment/role-pilot-partner.md`
- `docs/relay-deploy.md`
- `docs/relay-observability-matrix.md`
- `docs/relay-operator-self-audit.md`
- `docs/releasing.md`
- `docs/research/execution-log.md`
- `docs/research/synthetic-personas-feedback.md`
- `docs/setup-guide.md`
- `docs/sustainability.md`
- `docs/threat-model.md`
- `docs/verifier-decision-table.md`

Grouped content counts:

- `docs/standards/`: 12 files

## Link Check

- Checked 526 local links in authored Markdown and MDX docs.
- Unresolved authored-doc links after remediation: 0.
- Root-level/template unresolved links after remediation: 0.

Audit scope notes:

- Grouped content directories are counted so they stay visible without making the audit readable without hiding them.

## Validation Notes

- The audit was generated from a clean worktree based on `origin/main` for this PR branch.
- Ran a local relative-link check over hand-authored Markdown and MDX docs.
- Ran an explicit root-level documentation presence and link check for README, process, legal, project, and template docs.
- Ran `git diff --check` across the PR worktrees after remediation.
- Product test suites remain the authority for runtime behavior; this PR changes documentation only.
