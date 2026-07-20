<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
## What and why

<!-- What does this change and why? Link any issue or ADR. -->

## Checklist

- [ ] `make verify` is green (ruff format+check, mypy --strict, pytest+coverage)
- [ ] Tests added/updated; anything touching evidence has a **tamper-detection** test
- [ ] No real tenant data anywhere; `.gitignore` still excludes vaults/packets/keys
- [ ] Respects the hard rules in `README.md` (no server-side PII, no telemetry, no
      central authority, tamper-evidence mandatory, retaliation threat model)
- [ ] The verifier (`src/habitable/verify.py`) stays independent of vault/sync
- [ ] Conventional Commit title; commits signed off (`git commit -s`, DCO)
- [ ] Noted any change to the threat model, packet format, or verification protocol
      (these are versioned), with a `CHANGELOG.md` entry
- [ ] Observability impact stated: relay-facing changes reconcile
      `docs/relay-observability-matrix.md`; app/CLI paths declare N/A under the
      no-telemetry rule (say which applies)
- [ ] Rollback/migration noted for any change to the vault layout, packet format, or
      sync protocol — old packets keep verifying; migrations are one-way and tested
- [ ] ISO 25010 quality characteristic(s) this change serves named in the description
- [ ] Any new dependency has a written rationale in the PR (the runtime-dependency
      floor stays deliberate; the standalone verifier stays independent)

The full, gate-by-gate bar these boxes attest to is [`DEFINITION_OF_DONE.md`](../DEFINITION_OF_DONE.md).
