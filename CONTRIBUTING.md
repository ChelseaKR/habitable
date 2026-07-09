# Contributing to habitable

Thank you for helping build a tool that gives tenants power. This project guards
people under threat of retaliation, so correctness, privacy, and honesty about
limits matter more than speed or features.

## Ground rules

- **Never commit real tenant data.** Tests and demos use synthetic data only. The
  `.gitignore` excludes case vaults, packets, and keys; keep it that way.
- **The hard rules in `README.md` are non-negotiable.** No server-side personal
  data, no telemetry, no central authority, tamper-evidence stays mandatory, and
  the threat model is retaliation. Changes that weaken these will not be merged.
- **Say what the tool does not do.** Honesty about limits is a feature here.

## Development setup

You need [uv](https://docs.astral.sh/uv/). Python 3.14 is installed automatically.

**Fastest path:** open the repo in a
[devcontainer](.devcontainer/devcontainer.json) or GitHub Codespaces, or run
`./scripts/bootstrap.sh` (or `make bootstrap`) on a local checkout. Either path
installs `uv` if needed, provisions the Python 3.14 environment, and prints the
next steps. The script is idempotent, so re-running it is safe.

Already have uv? The individual steps:

```console
$ uv sync                 # create the env on Python 3.14 + install dev tools
$ uv run habitable demo   # walk the whole pipeline on synthetic data, offline
$ make verify             # the full gate: ruff format+check, mypy --strict, pytest+coverage
```

`make verify` must be green before you open a pull request. Other helpers:
`make fmt` (auto-format/fix), `make test`, `make type`, `make audit`, `make demo`.

## What good changes look like

- **Typed and linted.** `mypy --strict` and `ruff` are clean. Match the existing
  style; keep modules small and behind clear interfaces.
- **Tested.** Add unit tests; for anything touching evidence, add a
  tamper-detection test (a forged/altered input that must fail verification). CRDT
  changes need a property test for convergence.
- **The verifier stays independent.** `src/habitable/verify.py` must not grow a
  dependency on the vault or sync layers; a skeptic must be able to run it alone.
- **Deterministic.** Hashing, packet assembly, and verification must be
  reproducible. Inject clocks/time sources rather than calling the wall clock in
  logic under test.

## Commits and PRs

- Use [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `test:`, `chore:`, `refactor:`).
- Sign off your commits (`git commit -s`) to certify the
  [Developer Certificate of Origin](https://developercertificate.org/).
- Keep PRs focused; explain the *why*, and note any change to the threat model,
  the packet format, or the verification protocol (these are versioned).
- New decisions of consequence get an ADR in `docs/adr/`.

## Security

Do not open public issues for vulnerabilities — see `SECURITY.md` for private
reporting.

## License

By contributing you agree your contributions are licensed under AGPL-3.0-or-later
(with the verification tooling additionally available under Apache-2.0, per
`NOTICE`).
