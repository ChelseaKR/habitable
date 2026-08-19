<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# The habitable tamper-evidence challenge

> **Status: mechanism built, challenge not yet published.** Nobody has attempted this
> challenge. No external party has validated habitable's evidentiary claims. This
> document defines the rules and publishes the measured baseline; the prerequisites in
> [§7](#7-before-this-can-go-live) must be met before it is opened. Do not cite this
> page as evidence that habitable withstood adversarial review.

habitable's central claim is that a packet is *checkable* rather than *trustworthy* —
that a recipient can confirm what was captured without taking the producer's word for
it. A claim like that is worth exactly as much as the effort spent trying to break it,
and so far that effort has been ours alone, against data we generated. This is the
cheapest honest way to change that: publish a signed packet, publish the anchors, and
invite people to alter it without the verifier noticing.

It requires no tenant data, no consent, and no legal review, because the subject of the
photographs is irrelevant. The claim under test is about signing and verification, not
about housing. The challenge substrate is synthetic and labelled as such.

---

## 1. What the verifier actually checks

Run against a packet directory, `habitable verify` decides these things and no others:

| Check | What passing means |
| --- | --- |
| Shared-media fixity | every file in `media/` hashes to the `shared_hash` recorded for it |
| Original fixity | *if* `originals/` is embedded, each file hashes to its `content_hash` |
| Custody chain | entries are strictly sequenced, each `prev_hash` links, each `entry_hash` recomputes, and the walked head equals the declared `head_hash` |
| Bundle signature | `bundle.json` hashes to `bundle_sha256`, and the Ed25519 signature verifies over it |
| Timestamp token | the RFC 3161 token's imprint equals the item's `content_hash` and its CMS signature verifies |
| Authority anchor (`--trusted-cert`) | the token's signing certificate **is**, or was **directly issued by**, a certificate you supplied |
| Producer pin (`--expected-producer-key`) | the key that signed the bundle equals a key you supplied |

The last two are assertions *you* make. Omit them and they are not checked — the report
says so (`anchors_supplied`, `producer_key_pinned`), and `evidence_ready` stays false
without an anchor.

## 2. What it explicitly does not check

- **That a photograph depicts what the case says it depicts.** No hash proves a ceiling
  was stained. Tamper-evidence protects a true record; it cannot create one.
- **That the producer is honest.** Everything here is written by the producer's own
  device. Someone with the vault can author whatever they like *before* any of these
  proofs are computed, and every check will pass. The threat model this challenge tests
  is alteration *after* export, in transit or in a recipient's hands.
- **Admissibility, weight, or any legal outcome.** `evidence_ready` is a technical
  verdict about bytes.
- **Full X.509 path validation.** `--trusted-cert` is a deliberate one-hop check
  (`habitable.tsa.ANCHOR_RULE`); it does not walk intermediates or check revocation,
  validity periods, or key usage. `openssl ts -verify` checks *more*. See
  [`verifier-decision-table.md`](verifier-decision-table.md) §5.
- **That `content_hash` refers to anything you can see.** In a default packet
  `has_original` is false and the original bytes are not shipped. The timestamp token
  binds a hash of bytes that are not in the packet. This matters — see §4.

## 3. The rules

**A break is a modified packet that changes what a reader would conclude, and that this
command still reports as `evidence_ready`:**

```console
$ habitable verify \
    --trusted-cert <published-tsa-root.pem> \
    --expected-producer-key <published-producer-key> \
    ./challenge-packet
```

Both anchors are mandatory in the challenge invocation, and both are published out of
band alongside the packet. That is the whole point: an anchor a challenger can rewrite
is not an anchor. A "break" found by omitting them is not a break — it is the documented
behaviour in §4, and it is why the flags exist.

**In scope**

- Altering, substituting, adding, or removing evidence media.
- Rewriting the narrative: issues, timeline, dates, unit, case identity.
- Reordering, truncating, splicing, or rebuilding the custody chain.
- Forging, replacing, backdating, or re-anchoring a timestamp token.
- Making the verifier crash, hang, or report a verdict it cannot justify.
- Making two verifiers disagree about the same packet.

**Out of scope**

- Attacks that need the producer's private key, the vault passphrase, or the TSA's
  signing key. Compromising a key is not defeating tamper-evidence.
- Changing what the anchors say. Substituting the published producer key or TSA root is
  assumed impossible by construction; that is what "out of band" means.
- Denial of service against any host, and anything touching a real person's data.
- Findings against `evidence_ready` computed without the pin (§4).

**Reporting.** Privately, per [`SECURITY.md`](../SECURITY.md): GitHub private
vulnerability reporting, or `ckellyreif@gmail.com` with a subject starting
`[habitable security]`. Include the modified packet, the exact command you ran, and its
output. There is no paid bounty; credit is given in the advisory unless you'd rather be
anonymous.

## 4. The measured baseline — what already fails, before anyone tries

Publishing a challenge without publishing its known-broken cases would be dishonest. The
table below is produced by `tests/test_tamper_challenge.py`, which carries out every
attack and asserts the verdict. The attacker there uses only published information: the
custody hash is recomputed from [`crypto-spec.md`](crypto-spec.md) §6.2, not by importing
this project's code.

The crux is that **the bundle signature is self-attesting**. `bundle.sig.json` carries
the very public key used to check it, so an attacker rewrites `bundle.json`, recomputes
the entire custody chain (all unkeyed SHA-256), signs with a freshly generated key, and
writes their own `sign_public`. This is tracked as unimplemented **FIX-05**
(`docs/ideation/02-large-scale-fixes.md`) and disclosed on the
[trust and limitations](https://habitable.chelseakr.com/trust-limitations/) page.

| Attack (all re-signed with a foreign key) | Without pin | With pin |
| --- | --- | --- |
| Media byte flipped / truncated, bundle untouched | **caught** | caught |
| Bundle edited, not re-signed | **caught** | caught |
| Custody entry deleted, sequence left with a gap | **caught** | caught |
| Item's `content_hash` altered | **caught** (token imprint) | caught |
| Timestamp token removed | **caught** | caught |
| Token re-minted by an attacker-controlled authority | **caught** (anchor) | caught |
| Issue narrative rewritten | **MISSED** | caught |
| An evidence item deleted entirely | **MISSED** | caught |
| Capture date moved | **MISSED** | caught |
| Unit and case identity swapped | **MISSED** | caught |
| `producer_fingerprint` copied across verbatim | **MISSED** | caught |
| **The photograph replaced, genuine token retained** | **MISSED** | caught |
| Same, in a packet built with `--include-originals` | **MISSED** | caught |
| Embedded *original* replaced | **caught** (token imprint) | caught |

Two results deserve emphasis, because neither was previously written down:

**The visible photograph is not protected by the timestamp.** The RFC 3161 token binds
`content_hash`, which is the hash of the *original* bytes. A default packet does not ship
the originals, so nothing a recipient can open is bound by the token. The image rendered
into `packet.html` and `packet.pdf` is bound only by `shared_hash`, which sits in the
rewritable bundle. An attacker replaces the picture, updates `shared_hash`, rewrites the
`copied_for_sharing` custody entry, rebuilds the chain, re-signs — and keeps the genuine,
unforgeable timestamp token in place. The verifier reports `evidence_ready`.

**`--include-originals` does not close it.** With originals embedded, replacing the
*original* is caught, because that hash is what the token signed. Replacing only the
*shared copy* still passes: nothing ties the two files to each other except a custody
entry the attacker has already rewritten. The attacker has no reason to touch the
original — nobody looks at `originals/`.

Both collapse to the same root cause, and the pin closes both.

## 5. Pinning the producer key

`--expected-producer-key` takes the base64 Ed25519 key from the `sign_public` field of a
packet you already trust, obtained through a channel the packet's courier does not
control. Supplying it makes a substituted signing key a structural failure:

```console
$ habitable verify --json ./packet | jq -r '.problems[]'
$ habitable verify --expected-producer-key 'BASE64…' ./packet
habitable: … integrity: FAILED
  packet signing key does not match the pinned producer key
```

It fails closed: an unparseable, empty, or unmatchable pin is a problem, never a skipped
check. `producer_key_pinned` in the JSON report distinguishes "asserted" from "not
asserted" so an unpinned pass is never mistaken for a pinned one.

**What pinning does not do.** It is a recipient-side assertion, not FIX-05. It helps only
a recipient who already holds a trustworthy copy of the key; a first-time recipient who
receives packet and key through the same channel gains nothing, because an attacker
controlling that channel supplies both. Binding packet authenticity into the custody
chain — so authenticity travels with the evidence instead of depending on the recipient's
diligence — remains open and is a design question, not a patch.

**Note on the fingerprint.** `producer_fingerprint` is *not* a usable anchor. It is
derived from `sign_public ‖ box_public`, and `box_public` is not in the packet, so a
recipient cannot recompute it from what they hold. The verifier never reads it. Pin the
key, not the fingerprint.

## 6. Reproducing the baseline

```console
$ uv run pytest tests/test_tamper_challenge.py -v
```

Every row in §4 is one test. Misses are asserted *as misses*, so the day one is closed
the suite fails and this document has to be corrected in the same commit.

## 7. Before this can go live

1. **Generate and publish the challenge packet**, with its anchors (producer key, TSA
   root) published separately from the packet itself.
2. **Decide the timestamp authority.** The current site sample uses a synthetic authority
   minted at build time. For a public challenge a *real* public authority (FreeTSA is
   already exercised in `tests/test_tsa_real_authority.py`) is materially better: nobody
   has to take our word that a synthetic signing key was discarded.
3. **Decide whether to ship the pin as the default posture** — including whether the
   packet-producing side should publish the producer key somewhere durable, and what a
   recipient with no prior relationship is expected to do.
4. **Set the terms**: disclosure window, credit, and whether findings are published in
   full.
5. **Consider closing FIX-05 first.** Opening a challenge whose headline gaps are already
   published is defensible only if the pinned invocation is the one under test. That is
   how §3 is written, deliberately — but it is a judgement call worth making explicitly
   rather than by default.

## 8. Cross-references

- [`verifier-decision-table.md`](verifier-decision-table.md) — the full pass/fail truth
  table, and how to cross-check a packet with `openssl` and `sha256sum` instead of this
  tool.
- [`embedding-the-verifier.md`](embedding-the-verifier.md) — running the verifier subset
  standalone, under Apache-2.0.
- [`crypto-spec.md`](crypto-spec.md) — the constructions an attacker needs.
- [`threat-model.md`](threat-model.md) — the adversary this project designs against.
- [`SECURITY.md`](../SECURITY.md) — disclosure process.
