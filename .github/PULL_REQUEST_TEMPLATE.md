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
