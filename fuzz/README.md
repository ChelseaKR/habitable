<!-- SPDX-License-Identifier: Apache-2.0 -->
# `fuzz/` — continuous-fuzzing harnesses for the verification subset

Two [Atheris](https://github.com/google/atheris) harnesses over the entry points a
skeptic actually calls, plus the OSS-Fuzz project files that would run them
continuously. Everything here targets the **verification subset** only —
`canonical`, `crypto`, `errors`, `evidence`, `timeline`, `tsa`, `verify` — which is
the part of this project offered under Apache-2.0 (see [`../NOTICE`](../NOTICE) and
[`../docs/embedding-the-verifier.md`](../docs/embedding-the-verifier.md)), and the
part whose entire purpose is to be run against input an adversary supplied.

| File | What it fuzzes |
|---|---|
| [`fuzz_verify_packet.py`](fuzz_verify_packet.py) | `verify_packet` over a golden packet with one part replaced by fuzzer bytes: the bundle, the signature file, or a media file |
| [`fuzz_timestamp_token.py`](fuzz_timestamp_token.py) | `TimestampToken.from_dict` and `verify_token`, for both dev and RFC 3161 tokens |

## What the harnesses assert

The same contract the rest of the project states in prose, and nothing more:

- **One named error.** Hostile input yields `VerificationError` / `TimestampError`
  and never a `KeyError`, a `binascii.Error`, or an ASN.1 decoder traceback. An
  embedder catches this project's own exception type; a traceback is not a verdict.
- **Never an accept on tamper.** A packet whose bytes are not the exported ones
  must not come back structurally intact.
- **Trust is never manufactured.** With no certificate anchor supplied, no token
  may report `trusted_chain=True`.

Note that the accept property is stated against `structurally_intact`, not against
`report.ok`. `ok` is an alias for `evidence_ready`, which also demands a trusted
timestamp anchor; the golden corpus deliberately ships no trust root, so `ok` is
already `False` for a *pristine* golden packet and an assertion built on it could
never fail.

## Running them

No Atheris required — that is the point. Each harness carries its own seed corpus
in code and replays it when run directly:

```console
$ make fuzz                                    # replay both seed corpora
$ python fuzz/fuzz_verify_packet.py            # or one at a time
$ python fuzz/fuzz_timestamp_token.py corpus/  # replay a directory of inputs
```

With Atheris installed, the same file is a real fuzz target:

```console
$ pip install atheris
$ python fuzz/fuzz_verify_packet.py -atheris_runs=1000000
```

`tests/test_verify_fuzz.py` imports both harnesses and runs their seed corpora on
every merge. That is deliberate: an out-of-tree fuzz target that nothing exercises
rots silently, and the first anyone hears of it is a build failure in someone
else's infrastructure months later.

## OSS-Fuzz status — honest version

[`oss-fuzz/`](oss-fuzz/) holds the reviewable source for the three files OSS-Fuzz
needs: [`project.yaml`](oss-fuzz/project.yaml), [`Dockerfile`](oss-fuzz/Dockerfile),
and [`build.sh`](oss-fuzz/build.sh). OSS-Fuzz does **not** read them from here — it
builds from `projects/habitable/` in its own repository — so they are kept next to
the harnesses they configure rather than only in a pull request against someone
else's tree, where they would drift out of review.

**What is done:** the harnesses, their seed corpora, the local runner, the merge-gate
check that they still work, and the project configuration.

**What is not:** the project is not submitted to or accepted by OSS-Fuzz, and is
therefore not running continuously. That step needs a maintainer to open the
upstream pull request and be named as the contact, which is not something this
repository can do to itself. Until it lands, OpenSSF Scorecard's Fuzzing check
still reports 0/10 for this project regardless of what is in this directory —
the check looks for membership in fuzzing infrastructure, not for harnesses.

**Two things to decide before submitting.** The Python floor: OSS-Fuzz's Python
base image ships an interpreter older than the project's declared `>=3.14`, so
[`build.sh`](oss-fuzz/build.sh) installs the subset's two runtime dependencies and
puts `src/` on `PYTHONPATH` rather than `pip install .`. That works because the
subset's real floor is 3.12 and CI pins it there — but it should be confirmed
against whatever the base image ships at submission time. And the alternative:
[ClusterFuzzLite](https://google.github.io/clusterfuzzlite/) runs the same
harnesses from a GitHub Actions workflow in this repository, needs no upstream
acceptance, and is also detected by the Scorecard fuzzing check. It costs CI
minutes on every pull request, which is why it is named here as an option rather
than added.

## Reporting what a harness finds

Anything these find in acceptance logic is a security finding about evidence
someone may be relying on in a housing dispute. Report it through the private path
in [`../SECURITY.md`](../SECURITY.md) — never a public issue, and never a public
reproducer. `project.yaml` sets `file_github_issue: false` for the same reason.
