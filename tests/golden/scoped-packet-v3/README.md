<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# A pre-block issue-scoped packet (`packet_version` 3)

This is the only scoped packet in the corpus. Every `packet-vN/` fixture beside it is
`scope.type == "unit"`, so before this directory existed the compatibility claim that
matters most to the scoped-export work — *old scoped packets keep verifying* — was
pinned by nothing at all (issue #279, item 3).

It is deliberately **not** named `packet-v*`. The `packet-v*` glob is the
one-fixture-per-format-version corpus that `tests/test_golden.py`,
`tests/test_verify_fuzz.py` and `tests/test_contrib_importer.py` enumerate; this is a
second packet of a version that already has one, and enrolling it in those harnesses is
a separate decision from committing it. `tests/test_golden.py` verifies it explicitly.

## What it is evidence of

Issue-scoped export lived in this repository for about thirty hours: `bd90034`
(2026-07-09, "minimal-disclosure export scoping") until `dd17172` (2026-07-10, "fail
closed on scoped custody exports"). Nothing it produced was ever committed — the only
`bundle.json` files in this repository's history are the four `packet-v*` fixtures and
the site sample, all of them whole-unit. So this format existed, shipped, and left no
artifact behind.

The bundle says, in its own signed `scope.statement` and `disclosures`:

> Scope: issue `issue-d5b048fca7f5a1b4` only — captures, timeline entries, and custody
> records from other issues in this vault are not included.

and its `custody_proof.items` then names `cap-3cbf05d983c31784` and
`tl-839fd8292269d9fb`, which are the capture and timeline entry of the **excluded**
issue. `custody_proof.length` is 10 for a packet disclosing three records. That
contradiction — a scoped packet whose complete custody proof names what the scope
excluded — is the defect the block exists to prevent, and
[`../../../docs/adr/0018-scoped-custody-views-prove-membership-not-a-shorter-chain.md`](../../../docs/adr/0018-scoped-custody-views-prove-membership-not-a-shorter-chain.md)
(fact 3) describes it in prose. This is the same thing as bytes a reader can open.

It also verifies today: `verify_packet` reports `structurally_intact`, `signature_ok`
and `custody_ok`, with one cryptographically verified item and no problems — the same
verdict every other fixture in this corpus gets, and the reason the contradiction above
is worth having on disk. Whatever scoped format eventually ships has to be compared
against something.

## Provenance — read this before trusting it

**These bytes were produced on 2026-09-05 by re-running the code at `5dd76bc`, not
captured in July 2026.** `5dd76bc` ("fix(verify): confine packet file references (#96)")
is the direct parent of the commit that closed scoping, so it is the last tree in which
`build_packet(..., issue_id=…)` returned a packet rather than raising. Every structural
decision in the file below was made by that tree; the only things chosen for this
fixture are its inputs — two issues, one capture and one timeline entry each, export
scoped to the first — which is the same kind of choice `scripts/make_golden_packet.py`
makes for every other fixture in this corpus.

That distinction matters and is the reason this section exists. This is evidence about
what the old *code* emitted, which is what a format fixture is for. It is not an
artifact recovered from July, and nobody should cite it as one.

The synthetic data is synthetic in the same way as the rest of the corpus: a 48×48
generated JPEG, a self-signed local RFC 3161 issuer (`golden-tsa`), and a fixed clock.
No part of it is real tenant data. Like the other fixtures it ships no external trust
root, so `evidence_ready` and `ok` are both false by design.

## Regenerating it

The working tree cannot build this packet — `packet.build_packet` raises on `issue_id`,
and that refusal is not being lifted. Reproduce it from history instead, without
touching the checkout:

```sh
mkdir -p /tmp/habitable-5dd76bc
git archive 5dd76bc | tar -x -C /tmp/habitable-5dd76bc
PYTHONPATH=/tmp/habitable-5dd76bc/src .venv/bin/python make_scoped_v3.py <out-dir>
```

where `make_scoped_v3.py` is `scripts/make_golden_packet.py` **as it stood at
`5dd76bc`** (`git show 5dd76bc:scripts/make_golden_packet.py`) with three changes:

1. add a second issue and give it its own timeline entry and capture, so the scope has
   something to exclude;
2. pass `issue_id=<the first issue>` to `build_packet`;
3. write to the directory named on the command line instead of `tests/golden/packet-v3`,
   so the run cannot overwrite a committed fixture.

The runtime dependencies at `5dd76bc` (`cryptography`, `asn1crypto`, `reportlab`,
`pillow`, `piexif`) are unchanged in the current `pyproject.toml`, which is why the old
tree runs against today's virtualenv. The output is not byte-reproducible: the local TSA
mints a fresh key each run, so a regenerated packet will carry different hashes and a
different signature. Compare structure, not bytes.
