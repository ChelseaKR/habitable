# Reviewer & pilot onboarding

> **Status: alpha / concept stage.** This is how to evaluate habitable. It is written
> so a security auditor, an accessibility tester, or a tenant-union / legal-aid pilot
> partner can start without a meeting. Everything here runs offline on synthetic data;
> **no real tenant data is needed, wanted, or ever committed.**

habitable is a court-ready, offline-first, end-to-end-encrypted tool for tenants to
document habitability problems. The design promise is "verify, don't trust" — so this
onboarding is built to let you check the claims yourself rather than take them on
faith.

## 1. Who this is for, and what to review

| You are a… | Your scope | Start with |
| --- | --- | --- |
| **Security / cryptographic auditor** | The threat model and whether the code keeps its promises: vault-at-rest, E2E sync, RFC 3161 timestamping + archive chaining, fixity, hash-linked custody, the standalone verifier. | The frozen baseline [`threat-model-baseline.md`](threat-model-baseline.md) (**B1**) and its residual-risk list. |
| **Accessibility tester** | The local web app and the produced `packet.html` against WCAG 2.2 AA in EN **and** ES, with a real screen reader (NVDA + VoiceOver). | [`../accessibility/manual-testing.md`](../accessibility/manual-testing.md) and the ACR [`../accessibility/ACR.md`](../accessibility/ACR.md). |
| **Pilot partner (union / legal aid)** | Whether the workflow fits a real matter and whether a produced packet is usable in your forum — using **synthetic data only** for evaluation. | §3 below, then [`../setup-guide.md`](../setup-guide.md) and [`../evidence-method.md`](../evidence-method.md). |

What is **explicitly out of scope** for evaluation is stated in the threat model §5
and reproduced in the baseline: hostile-keyholder local-chain rewrite, relay metadata,
the limits of the duress state, lost-key data loss, and what a timestamp does and does
not prove. We are not asking you to disprove claims the project never makes — we are
asking whether the claims it *does* make are honest and met.

## 2. Run instructions

Prerequisites: [`uv`](https://docs.astral.sh/uv/) (it pins and fetches **Python 3.14**;
no system Python needed) and `git`.

```sh
git clone https://github.com/ChelseaKR/habitable.git
cd habitable
uv sync --all-extras                 # creates the env, installs deps from uv.lock
uv run habitable --version           # confirms the toolchain (Python 3.14)

# The full quality gate — what every merge and release must pass.
make verify                          # ruff format+check, mypy --strict, pytest (~85% cov)
```

Optional deeper checks:

```sh
make integration   # real public RFC 3161 authorities (DigiCert, FreeTSA) — needs network
make a11y          # axe-core via Playwright/Chromium against the app + packet.html
make cov           # coverage report
```

Reproduce the evidence claims end to end against the standalone verifier:

```sh
uv run habitable demo                # see §3 — builds a synthetic case + packet
# then verify the produced packet with the independent verifier:
uv run habitable verify <packet-dir>
```

The verifier (`habitable.verify` and the pure modules it uses) is offered under
Apache-2.0 as the "verification subset" so it can be embedded and run independently —
auditing it as a standalone artifact is encouraged. See [`../../NOTICE`](../../NOTICE).

## 3. Synthetic data — never real tenant data

`uv run habitable demo` walks the whole flow — init an encrypted vault, add issues,
capture synthetic photos, build a signed packet (`bundle.json` + accessible
`packet.html` + PDF), and verify it — **with no network and no real information.** All
sample data is generated; nothing is read from a real device.

For accessibility and pilot evaluation, point the app at a throwaway demo vault:

```sh
uv run habitable demo                 # creates a demo vault + packet under a temp/working dir
uv run habitable app --vault <demo-vault>   # the local web app, EN/ES, to test in a browser/AT
```

**Do not load real tenant data to evaluate habitable.** The tool is alpha and
unaudited; that is the whole reason for this onboarding. If a pilot moves to real use
later, that is gated on the external audit, the lawyer review, the recorded AT pass,
and a signed pilot MOU (productionization Phase 1–2).

## 4. How to report findings

habitable runs **audit-as-artifact**: reviews are committed to the repo, not kept as
private assurances, so anyone can diff them across releases.

- **Security vulnerabilities:** follow [`../../SECURITY.md`](../../SECURITY.md) for
  coordinated disclosure — do **not** open a public issue for an unfixed vulnerability.
- **Findings, once a fix or accepted-risk rationale exists,** are recorded under
  [`docs/audits/`](.) with their resolution, so a given release tag carries the audit
  state that was true for it.
- **Accessibility findings** feed [`../accessibility/ACR.md`](../accessibility/ACR.md)
  and the per-release AT cadence.
- **Pilot outcomes** (what broke, whether a produced packet was usable in-forum) are
  written up and committed under `docs/audits/` per the productionization plan.

A finding that contradicts a stated protection is the most valuable thing you can send
us. So is a residual risk we failed to list.
