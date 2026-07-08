<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Good first issues — where to start

Welcome, and thank you for considering a contribution. habitable guards people
under threat of retaliation, so **correctness, privacy, and honesty about limits
matter more than speed or features** — but that does *not* mean there is no room
for a first-time contributor. There is plenty, and a lot of the highest-value
work is not deep cryptography at all: it is plain-language copy, templates,
localization, tests, and docs.

This guide gives you a newcomer's map of the codebase, a path to a green
`make verify`, and a categorized list of where to start. Read it alongside
[`../CONTRIBUTING.md`](../CONTRIBUTING.md), which is the source of truth for the
ground rules.

> **One ground rule up front, because it shapes everything:** the
> [hard rules in the README](../README.md#hard-rules-enforced-not-aspirational)
> are non-negotiable. No server-side personal data, no telemetry ever, no
> central authority over a union's records, mandatory tamper-evidence, and the
> threat model is a retaliating landlord. A change that weakens any of these
> will not be merged — it is out of scope by definition, not weighed against its
> benefits. If an idea seems to need one of those, that is a sign to ask first.

## Architecture for newcomers

You do not need to understand all of habitable to contribute. The codebase is
six small, independent layers (`src/habitable/`), each behind a clear interface.
The flow of a piece of evidence runs left to right:

```
capture  →  evidence  →  crypto  →  sync  →  packet  →  verify
```

- **capture** (`capture.py`) — media comes in; the original is hashed (SHA-256),
  sealed unmodified, an RFC 3161 timestamp is fetched over the hash once online,
  and a custody entry is appended.
- **evidence** (`evidence.py`) — content hashing, fixity re-checks, and the
  append-only, hash-linked chain-of-custody log.
- **crypto** (`crypto.py`) — local encryption at rest, end-to-end sync keys, and
  key backup/rotation. (Crypto changes are *not* a good first issue — see
  below.)
- **sync** (`sync.py`) — peer-to-peer encrypted sync; the relay client only ever
  sees ciphertext.
- **packet** (`packet.py`) — assemble the court/inspector PDF and HTML packet
  with an evidence appendix.
- **verify** (`verify.py`) — independently re-derive every hash, validate each
  timestamp token, and walk the custody chain.

**The single most important architectural fact for a newcomer:** **`verify`
depends on none of the other layers.** A skeptic — a court, opposing counsel —
must be able to run it alone, so it must not grow a dependency on the vault or
sync code. The repo enforces this; if you touch `verify.py`, keep it standalone.

Around the engine: `app/` is the local-first web client (plain HTML/CSS/JS, no
build step) with its translation bundles in `app/i18n/`; `relay/` is the
optional ciphertext-only sync relay; `tests/` holds unit, property-based, and
tamper-detection tests with fixtures of clean, altered, and chain-broken cases;
`docs/` holds the architecture, threat model, ADRs, and committed audits.

For the full picture see [`ARCHITECTURE.md`](ARCHITECTURE.md) and the README's
*Architecture* section.

## Get the dev environment running

You need [uv](https://docs.astral.sh/uv/); the right Python (3.14) is fetched
automatically. For a **one-command setup**, open the repo in a devcontainer or
GitHub Codespace, or run `./scripts/bootstrap.sh` on a local checkout — it
installs `uv`, provisions the environment, and prints these next steps. The
manual steps below do the same thing by hand.

```console
$ git clone https://github.com/ChelseaKR/habitable && cd habitable
$ uv sync                 # create the env on Python 3.14 + install dev tools
$ uv run habitable demo   # walk the whole pipeline on synthetic data, offline
$ make verify             # the full gate — this must be green before a PR
```

`make verify` runs ruff (format + check), `mypy --strict`, and the full pytest
suite (including tamper-detection and CRDT-convergence tests). Other helpers:
`make fmt` (auto-format/fix), `make test`, `make type`, `make audit`,
`make demo`.

To poke at the app: `uv run habitable app` serves it on `localhost` (it runs
locally on purpose — your case never leaves the device).

If `make verify` is **green on a clean checkout before you change anything**, you
have a working baseline. Getting it green is itself a worthwhile first
milestone; if the Python 3.14 toolchain gives you trouble, the one-command
`./scripts/bootstrap.sh` (or the devcontainer/Codespace) exists to smooth
exactly that friction.

## Where to start — categorized

These are drawn from the project's backlog and persona research
([`research/synthetic-personas-feedback.md`](research/synthetic-personas-feedback.md)).
They are framed as *kinds of work that are wanted*, not as numbered issues — the
maintainer will help you turn one into a scoped issue. Difficulty is a rough
guide:

- 🟢 **Starter** — mostly self-contained; little of the engine needed.
- 🟡 **Intermediate** — touches code paths or tests; read the surrounding layer.
- 🔴 **Deep** — security/crypto/evidence-critical; **not** a first issue, listed
  so you know what to grow toward (and what to leave alone for now).

### Docs and onboarding

- 🟢 Fix typos, broken links, or unclear wording in any `docs/` file or the
  README. Genuinely useful and a good way to learn the codebase by reading it.
- 🟢 Expand the newcomer architecture walkthrough above with anything that
  confused *you* while getting set up — first-contributor friction is best
  reported by a first contributor.
- 🟢 Improve the one-command dev bootstrap / devcontainer for the Python 3.14
  toolchain — `./scripts/bootstrap.sh` and `.devcontainer/` now exist (R-42/R-43);
  report any friction you hit on your OS or extend them (e.g. more editors). Making
  `make verify` green frictionless everywhere is ongoing.

### Jurisdiction and packet templates

- 🟢/🟡 Presentation-only packet templates that match a jurisdiction's
  expectations (layout, labels, ordering). These are **config-driven and do not
  touch the verification protocol** — exactly the kind of community-extensible
  surface the project wants to grow. (Backlog E-16 / roadmap workstream C.)
- 🟡 Extend a template's vocabulary to speak a recipient's code/citation
  categories rather than only the six built-in categories — coordinate with
  someone who knows that jurisdiction. (Backlog R-28.)

> Templates are *presentation only*. A change that altered what a packet
> *proves*, or how it verifies, is not a template change and is out of scope for
> this lane.

### Localization

- 🟢/🟡 Add or improve a language. The workflow (per-language JSON bundles under
  `app/i18n/`, with a parity test that fails if any key is missing) has its own
  guide: [`localization-guide.md`](localization-guide.md). **Read it first** —
  some strings are legally sensitive and must be translated faithfully, never
  softened. (Backlog R-47 / E-24.)
- 🟢 A pseudo-locale or text-expansion check to catch layouts that break under
  longer translations. (Backlog E-24.)

### Plain-language and accessibility copy

- 🟢 Rewrite UI status labels in plain, reassuring language — what "awaiting
  timestamp" means, that the photo is *already safe*, and what to do next. This
  is one of the highest-leverage frictions in the persona research and is mostly
  copy work (in `app/i18n/en.json`, then mirrored in every language). (Backlog
  R-01.)
- 🟢 Ensure no screen is a dead end: every state names a clear next action.
  (Backlog R-02.)
- 🟡 Live-region (ARIA) announcements for async transitions like
  awaiting-timestamp → timestamped, tested with assistive technology. (Backlog
  R-07.)

### Tests

- 🟡 Add tests around existing behavior to raise coverage in a layer you have
  been reading — a great way to learn the code safely. Match the patterns in
  `tests/`.
- 🟡 **For anything touching evidence, a tamper-detection test is required**: a
  forged or altered input that *must fail* verification. The fixtures of clean,
  altered, and chain-broken cases live in `tests/`. Writing one is a good way to
  understand the evidence guarantees.

### Grow toward (not a first issue)

- 🔴 Anything in `crypto.py`, `evidence.py`, the custody chain, or `verify.py`'s
  acceptance logic. These are evidence- and security-critical; changes need a
  tamper-detection test, must keep the verifier independent, and often need an
  ADR. Start by *reading* them and writing tests against them, not by changing
  them.

## When you open a PR

- `make verify` must be green.
- Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`,
  `fix:`, `docs:`, `test:`, …) and **sign off** your commits (`git commit -s`)
  to certify the DCO.
- Keep PRs focused and explain the *why*. Note any change to the threat model,
  the packet format, or the verification protocol — these are versioned and need
  extra care (often an ADR in `docs/adr/`).
- **Security vulnerabilities never go in a public issue or PR** — use the private
  path in [`../SECURITY.md`](../SECURITY.md).

Not sure which item fits you? Open a draft issue describing what you would like
to work on and the maintainer will help scope it. A good first contribution that
sticks is worth more to this project than a large one that does not.
