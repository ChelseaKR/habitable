<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# The habitable tamper-evidence challenge

> **Status: mechanism built, challenge not yet published.** Nobody has attempted this
> challenge. No external party has validated habitable's evidentiary claims. This
> document defines the rules and publishes the measured baseline; the setup in
> [§7](#7-is-this-publishable-now) remains before it is opened. Do not cite this
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
| Packet seal | *if present*, an RFC 3161 token whose imprint is the SHA-256 of the whole `bundle.json` — so it covers every field at once, including every `shared_hash` |
| Authority anchor (`--trusted-cert`) | the token's signing certificate **is**, or was **directly issued by**, a certificate you supplied |
| Producer pin (`--expected-producer-key`) | the key that signed the bundle equals a key you supplied |
| Seal requirement (`--require-packet-seal`) | a packet seal is present, valid, and anchored |
| Seal date (`--seal-not-after`) | the seal was minted no later than an instant you name — normally the day you received the packet |

The last four are assertions *you* make. Omit them and they are not checked — the report
says so (`anchors_supplied`, `producer_key_pinned`, `packet_seal.required`), and
`evidence_ready` stays false without a certificate anchor.

A seal that *is* present is always checked, whether or not you asked for one. What
`--require-packet-seal` adds is a verdict on its **absence** — which is the only move an
attacker has left once a packet is sealed.

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
  `has_original` is false and the original bytes are not shipped. An *item's* timestamp
  token binds a hash of bytes that are not in the packet. The **packet seal** is what
  covers the bytes you can open, and only if the packet has one — see §4.
- **Who the producer is.** No packet establishes that, and after the seal it still
  doesn't. A seal says *these exact bytes were countersigned by this authority at this
  time*; it never says who assembled them. Authenticating an unknown party requires an
  anchor, and habitable has no PKI and runs no key log
  ([ADR 0011](adr/0011-authority-seal-over-the-whole-packet.md)).

## 3. The rules

**A break is a modified packet that changes what a reader would conclude, and that this
command still reports as `evidence_ready`:**

```console
$ habitable verify \
    --trusted-cert <published-tsa-root.pem> \
    --require-packet-seal \
    --seal-not-after <the packet's publication date> \
    ./challenge-packet
```

Note what is *not* in that command: `--expected-producer-key`. The challenge is run
unpinned on purpose, because a pin only helps a recipient who already holds a trustworthy
key, and most recipients do not. Everything above is either published (the TSA
certificate), a policy switch (`--require-packet-seal`), or a date anyone can read off
this page (`--seal-not-after`). None of it is a secret an entrant lacks.

The publication date is the anchor that makes this hard. No authority will backdate a
token, so any packet an entrant re-seals is provably younger than the challenge itself.
That is the same protection a real recipient gets from the date they took delivery.

A "break" found by *omitting* these flags is not a break — it is the documented behaviour
in §4, and it is why the flags exist.

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
- Changing what the anchors say. Substituting the published TSA root is assumed
  impossible by construction; that is what "out of band" means.
- Denial of service against any host, and anything touching a real person's data.
- Findings against `evidence_ready` computed without the flags in §3 — those are the
  measured baseline in §4, not discoveries.
- Persuading the timestamp authority to backdate a token. That is an attack on the TSA,
  not on habitable, and it is the assumption every RFC 3161 deployment rests on.

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
writes their own `sign_public`. This was tracked as unimplemented **FIX-05**
(`docs/ideation/02-large-scale-fixes.md`) and disclosed on the
[trust and limitations](https://habitable.chelseakr.com/trust-limitations/) page.

The **packet seal** ([ADR 0011](adr/0011-authority-seal-over-the-whole-packet.md)) is the
structural answer: an RFC 3161 token over the SHA-256 of the whole `bundle.json`, so one
signature the attacker cannot mint covers every field they wanted to edit — including
every `shared_hash`, i.e. the photographs. Columns 2–4 below are the three postures a
recipient can take, from weakest to strongest.

| Attack (all re-signed with a foreign key) | Nothing asserted | `--require-packet-seal` | + `--seal-not-after` |
| --- | --- | --- | --- |
| Media byte flipped / truncated, bundle untouched | **caught** | caught | caught |
| Bundle edited, not re-signed | **caught** | caught | caught |
| Custody entry deleted, sequence left with a gap | **caught** | caught | caught |
| Item's `content_hash` altered | **caught** (token imprint) | caught | caught |
| Timestamp token removed | **caught** | caught | caught |
| Token re-minted by an attacker-controlled authority | **caught** (anchor) | caught | caught |
| Seal retained over a rewritten bundle | **caught** (seal imprint) | caught | caught |
| Seal lifted from a different, genuine packet | **caught** (seal imprint) | caught | caught |
| Seal replaced with a malformed record | **caught** | caught | caught |
| Issue narrative rewritten | **MISSED** | **caught** | caught |
| An evidence item deleted entirely | **MISSED** — see the note below | **caught** | caught |
| Capture date moved | **MISSED** | **caught** | caught |
| Unit and case identity swapped | **MISSED** | **caught** | caught |
| `producer_fingerprint` copied across verbatim | **MISSED** | **caught** | caught |
| **The photograph replaced, genuine item token retained** | **MISSED** | **caught** | caught |
| Same, in a packet built with `--include-originals` | **MISSED** | **caught** | caught |
| Embedded *original* replaced | **caught** (token imprint) | caught | caught |
| Seal deleted outright, then the bundle rewritten | **MISSED** | **caught** | caught |
| Fully rehashed forgery re-sealed by an authority you did **not** anchor | **MISSED** | **caught** | caught |
| Fully rehashed forgery re-sealed by an authority you **did** anchor | **MISSED** | **MISSED** | **caught** |

Note the **"an evidence item deleted entirely"** row. It stays MISSED, but the
margin narrowed in a way worth being precise about. Since issue #278 the verifier
checks `custody_proof.length` as well as `head_hash`, so a rewriter who deletes an
item and relinks the chain while leaving the declared count stale is now caught on
the contradiction. That is a real improvement and it is **not** what this row
claims. The row is about a *competent* rewriter, and a competent rewriter
republishes both halves of a summary they control — this project's own attacker
toolkit in `tests/test_tamper_challenge.py` was updated to do so, because a
demonstration that only works against a careless adversary demonstrates nothing
about the threat model's adversary. Unpinned and unsealed, that rewriter is still
missed.

Note the **"re-sealed by an authority you did not anchor"** row, because the obvious
guess is wrong. A seal from an authority you never anchored does **not** by itself sink
the verdict: like an absent seal, an untrusted one is reported rather than fatal. Making it fatal would mean a
producer who seals with an authority you happen not to trust ends up *worse off than one
who never sealed at all* — a rule that punishes the more careful producer. So the
untrusted seal is visible in `verify`'s output and in `packet_seal.trusted`, and it
becomes a verdict under `--require-packet-seal`. The trade is deliberate; it is not an
oversight, and it is why the challenge invocation in §3 carries that flag.

Every `--expected-producer-key` row from the previous revision of this table still holds:
the pin catches everything in the MISSED column too. It is left out of the table because
it answers a different question (*is this the producer I know?*) and because it is
useless to the recipient this challenge is about — one with no prior relationship.

### The three results that deserve emphasis

**The visible photograph was not protected by the timestamp, and now can be.** The RFC
3161 *item* token binds `content_hash`, the hash of the original bytes. A default packet
does not ship the originals, so nothing a recipient can open was bound by it. The image
rendered into `packet.html` and `packet.pdf` is bound by `shared_hash`, which sits in the
bundle — and the seal's imprint is the bundle. An attacker who replaces the picture must
now also delete the seal, which is a thing a recipient can ask about; before, they had to
delete nothing.

**`--include-originals` still does not close it on its own.** With originals embedded,
replacing the *original* is caught because that hash is what the item token signed.
Replacing only the *shared copy* passes every item-level check: nothing ties the two files
to each other except a custody entry the attacker rewrote. It is the seal, not the
embedded original, that catches it.

**A forger who can reach your own authority is not stopped, only dated.** FreeTSA and
every other public authority will stamp any digest for anyone. Such an attacker re-seals
the rewritten bundle and passes `--require-packet-seal`. What they cannot do is backdate
it: the new seal carries the true time of the forgery. `--seal-not-after` — normally the
date you received the packet — is what turns that into a caught case. This is measured in
`test_the_fully_rehashed_forgery_is_MISSED_when_it_can_reach_your_authority`, asserted as
a miss in the middle column and as caught in the last.

### The residual, in one sentence

An attacker who can reach an authority you trust **and** can put the packet in front of
you before you ever saw the genuine one is not detected by anything in this table. That
is the honest boundary of tamper-evidence without a producer identity anchor, and it is
why `--expected-producer-key` still exists for the recipients who can use it.

## 4a. Requiring the seal, and dating it

```console
$ habitable verify --trusted-cert tsa.pem --require-packet-seal ./packet
habitable: integrity: intact; timestamp authority: trusted (2/2 items); evidence readiness: READY
           authority seal: this packet's exact contents were countersigned by …

$ habitable verify --trusted-cert tsa.pem --require-packet-seal ./tampered
habitable: … integrity: NOT INTACT …
           authority seal: none. Nothing binds this packet's contents as a whole, …
  · packet seal required, but this packet carries no authority seal over its contents
```

The seal line is printed on **every** run, pass or fail, pinned or not. "No seal" is the
state that lets a rewritten packet through, so a recipient must never have to know to ask
before being told.

`--seal-not-after` takes any ISO 8601 instant; a bare date means midnight UTC, so
`--seal-not-after 2026-08-19` means "nothing minted after that day began". Both flags fail
closed: an unparseable date, or either assertion made against a packet with no seal at
all, is a problem rather than a skipped check.

On the producing side, sealing is automatic whenever an authority is configured and
reachable — it is the first network fetch `habitable export` has ever made. `--no-seal`,
`--dev-tsa`, `--wifi-only`, and simply being offline each produce an unsealed packet
rather than a failed export, and the command says which happened.

**What the seal does not do.** It does not identify the producer, and a packet built
offline has none — that is a real state, not a failure, and it verifies exactly as it did
before. An attacker's cheapest move against a sealed packet is to delete the seal, and no
field inside the bundle can prevent that, because the attacker rewrites the bundle. Only
the recipient asking for one does.

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

**What pinning does not do.** It helps only a recipient who already holds a trustworthy
copy of the key; a first-time recipient who receives packet and key through the same
channel gains nothing, because an attacker controlling that channel supplies both. That
is why FIX-05 was answered with the seal (§4a) rather than with the pin: the seal's
anchor is a published certificate and the recipient's own calendar, neither of which has
to be handed over by the producer. The pin remains the right tool for a recipient who
*does* have a prior relationship — an organizer receiving from a tenant they have already
paired with, for instance — and it catches strictly more than the seal does, including
the residual in §4.

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

## 7. Is this publishable now?

**Yes — the blocker is cleared.** The reason it could not be published was that the
honest invocation (no pin, because most recipients have no key to pin) lost to a text
editor: rewrite the bundle, re-sign with a fresh key, done. Every entrant would have won
in an afternoon. With the seal, an entrant must produce an RFC 3161 token, from an
authority the published certificate anchors, over a bundle they wrote — and dated before
the challenge was published. Nothing in §4 does that.

That is a claim about difficulty, not impossibility, and the residual is stated in §4
rather than buried: an adversary who reaches the same public authority **and** intercepts
the packet before its intended recipient ever sees it is still not detected. A challenge
cannot simulate that adversary, because a published packet has, by definition, already
been seen.

Remaining work before opening it — none of it a blocker, all of it setup:

1. **Generate and publish the challenge packet**, sealed, with the TSA certificate
   published separately from the packet itself, and the publication date stated on this
   page so `--seal-not-after` is unambiguous.
2. **Decide the timestamp authority.** The current site sample uses a synthetic authority
   minted at build time. For a public challenge a *real* public authority (FreeTSA is
   already exercised in `tests/test_tsa_real_authority.py`) is materially better: nobody
   has to take our word that a synthetic signing key was discarded. Note the trade-off
   the seal makes explicit — a public authority is one an entrant can also use, which is
   exactly why `--seal-not-after` is in the challenge invocation.
3. **Set the terms**: disclosure window, credit, and whether findings are published in
   full.
4. **Decide the default export posture.** Sealing now happens automatically whenever an
   authority is configured, but a tenant exporting in a basement with no signal gets an
   unsealed packet. Whether the app should nag, queue a re-export, or say nothing beyond
   the current disclosure line is a product decision, not a security one.

## 8. Cross-references

- [`verifier-decision-table.md`](verifier-decision-table.md) — the full pass/fail truth
  table, and how to cross-check a packet with `openssl` and `sha256sum` instead of this
  tool.
- [`embedding-the-verifier.md`](embedding-the-verifier.md) — running the verifier subset
  standalone, under Apache-2.0.
- [`crypto-spec.md`](crypto-spec.md) — the constructions an attacker needs.
- [`adr/0011-authority-seal-over-the-whole-packet.md`](adr/0011-authority-seal-over-the-whole-packet.md)
  — why the seal, why not a certificate or a key log, and what stays impossible.
- [`threat-model.md`](threat-model.md) — the adversary this project designs against.
- [`SECURITY.md`](../SECURITY.md) — disclosure process.
