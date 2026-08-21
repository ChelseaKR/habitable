# 11. Bind a packet's contents with a timestamp-authority seal, and stop pretending producer identity is knowable without an anchor

Status: Accepted (2026-08-19)

## Context

`bundle.sig.json` carries the very public key used to verify it. `signature_ok` therefore
means *"this bundle is internally consistent with the key sitting next to it"*, never
*"the producer signed this"*. This is tracked as **FIX-05**
([`../ideation/02-large-scale-fixes.md`](../ideation/02-large-scale-fixes.md)).

[PR #193](https://github.com/ChelseaKR/habitable/pull/193) measured how far the
consequence reaches, in `tests/test_tamper_challenge.py`. An attacker who holds only a
copy of the packet and `docs/crypto-spec.md` can rewrite `bundle.json`, recompute the
whole custody chain (all unkeyed SHA-256, published algorithm), sign with a freshly
generated Ed25519 key, and write their own `sign_public`. Six documented attacks pass
`habitable verify --trusted-cert` as `evidence_ready`, including the sharpest one:

> **The photograph a reader actually looks at is not bound by the trusted timestamp.**
> An RFC 3161 imprint is `content_hash` — the hash of the *original* bytes. A default
> packet does not ship the originals (`has_original: false`), so no file a recipient can
> open is covered by a token. The image rendered into `packet.html`/`packet.pdf` is bound
> only by `shared_hash`, which lives in the rewritable bundle. Replace the picture,
> update `shared_hash`, rewrite the `copied_for_sharing` custody entry, rebuild the
> chain, re-sign — and *keep the genuine, unforgeable timestamp token in place*.
> `--include-originals` does not close it: replacing the embedded original is caught,
> replacing only the shared copy is not, because nothing ties the two files together
> except a custody entry the attacker already rewrote.

PR #193 added `verify --expected-producer-key` — an out-of-band key pin. It catches every
one of the six. But it is a **recipient-side assertion that presupposes the answer**: it
helps only someone who already holds a trustworthy copy of the producer's key. A
first-time recipient handed the packet and the key through the same channel gains
nothing. That is why the public tamper challenge cannot be published against the unpinned
invocation: every entrant would win trivially.

Two structural facts constrain any fix:

1. **Everything inside `bundle.json` is attacker-rewritable.** The bundle cannot
   authenticate itself, cannot declare "I must be sealed", and cannot fix its own version
   — any such marker is one more field the attacker edits. No in-packet datum can defeat
   a downgrade. Only recipient policy can.
2. **The only unforgeable material already in a packet is the RFC 3161 tokens**, and each
   binds exactly one value: one item's `content_hash`. Nothing binds the packet as a
   whole, and nothing binds the bytes a recipient can actually open.

## Decision

### 1. Seal the whole packet with the authority the recipient already anchors

At export, after `bundle.json` is written, the producer sends `bundle_sha256` — the
SHA-256 of the exact bundle bytes — to an RFC 3161 timestamp authority and stores the
returned token in `bundle.sig.json` under a new optional key:

```json
"packet_seal": { "kind": "rfc3161", "tsa_name": "…", "token_b64": "…" }
```

The value is exactly a `TimestampToken` record — the same shape, parser, and verifier
already used for item timestamps. Nothing else changes: the bundle format is untouched
and `packet_version` does **not** move, because the seal lives in the signature sidecar,
which was never covered by the signature it contains.

Because `bundle_sha256` is a digest of the whole bundle, the seal binds *every* field the
six documented misses attack — the narrative, the item list, `captured_at`, `unit`,
`case_id`, every `shared_hash`, `generated_at`, and the custody `head_hash`. **The
photograph a reader looks at is bound**, because its hash is in the bundle and the bundle
is in the imprint. There is no partially-bound subset to reason about and no new
canonicalization to get wrong: the imprint covers the file as it sits on disk.

The custody chain is bound the same way — its head hash is inside the bundle — so this
*is* "authenticity bound into the custody chain", reached from the outside rather than by
threading a commitment through it. A sealing entry *inside* the chain was rejected: the
chain is inside the bundle, so committing to the bundle digest from within it is
circular, and the two-phase "body digest" construction needed to break the cycle adds a
second canonicalization whose coverage would have to be re-argued on every future field
addition. A binding that is subtly incomplete is worse than the current honest gap.

### 2. Verification: check what is there, fail closed, and let the recipient raise the bar

`verify_packet` gains two keyword arguments and `habitable verify` two flags:

| Behaviour | Rule |
| --- | --- |
| No seal, nothing asserted | Reported as absent. Not a problem. `evidence_ready` unchanged. |
| Seal present | **Always** verified: imprint against the recomputed bundle digest, and token signature. A seal that does not cover this packet is a problem regardless of flags. |
| Seal present, authority not anchored | Reported (`seal.trusted = False`), **not** fatal on its own. Making it fatal would leave a producer who sealed with an authority this recipient happens not to trust worse off than one who never sealed — a rule that punishes the more careful producer. |
| `--require-packet-seal` | Absence, invalidity, **or** an unanchored authority becomes a problem. |
| `--seal-not-after ISO8601` | A seal minted after that instant is a problem. Asserting it against a packet with no seal is also a problem. |

Both flags fail closed on malformed input, exactly like `--expected-producer-key`: an
unparseable date or an unmatchable assertion is always a problem, never a skipped check.
A `dev`-kind seal is never trusted, mirroring the existing `DevTSA` rule.

Seal problems flow into the existing `problems` tuple, so they surface through
`structurally_intact` and the existing `integrity_failed` status. **No verdict or status
code is added or redefined**, and no existing packet's verdict changes unless the
recipient asks for more. A fourth claim — the seal — is reported alongside the three of
[ADR 0008](0008-separate-integrity-timestamp-trust-and-readiness.md) rather than folded
into them.

### 3. What a recipient must possess

Only what they already needed, plus knowledge that a flag exists:

- **a certificate for the timestamp authority** (`--trusted-cert`) — already mandatory for
  `evidence_ready`, and for a public authority it is published, not confided;
- **`--require-packet-seal`** — a policy switch, not a secret;
- optionally, **the date they received the packet** (`--seal-not-after`) — a fact every
  recipient possesses by definition of having received it.

That is the whole point of choosing this construction over the pin. The pin's anchor is a
secret you must already have been given. The seal's anchor is a public certificate and
your own calendar.

### 4. Alternatives rejected

- **A certificate for the producer.** Requires a CA that vouches "this key belongs to
  this union". habitable has no PKI, a solo maintainer cannot run one, and a certificate
  *names* its subject — tenants documenting their landlord are exactly the population for
  whom a durable, third-party-issued identity record is a hazard. Rejected on both
  feasibility and safety.
- **A key transparency log.** Technically the right answer for producer identity, and the
  one to revisit if habitable ever has institutional operators. Today it needs an
  always-on log plus gossip (contradicting the offline-first, no-operator design) and it
  publishes tenant device keys, making packets from one household linkable to each other
  forever by anyone. Rejected for now, recorded as the successor.
- **A TSA-countersigned key-birth token (trust on first use).** Timestamp the producer's
  `sign_public` and require the key to predate the evidence it signs. Cheap and
  tempting — and it only *moves* the problem: an adversary mints their own key-birth
  token years in advance for the price of one HTTP request, and a genuine tenant who
  replaces a lost phone looks like the attacker. Rejected as a security theatre risk; the
  seal subsumes its useful part.
- **Timestamping the shared copy at capture.** Would bind the visible bytes with no new
  trust assumptions — and is impossible: the shared copy is produced by
  `packet._build_item` at export, from a sanitizer whose output depends on the export-time
  policy. It does not exist when the capture token is fetched.
- **Making `evidence_ready` require a seal by default.** Effective only if it cannot be
  downgraded, and it can be: the attacker strips `packet_seal`, and a legacy-tolerant
  verifier accepts the result. Requiring it for *every* version instead would fail every
  packet built offline and every packet in `tests/golden/`, in exchange for a guarantee
  the attacker sidesteps in one line. Rejected; see "what remains impossible".

## Consequences

### What this closes

Every attack in the PR #193 table that was **MISSED** without a pin is caught by a
recipient who requires the seal — the narrative rewrite, the deleted item, the moved
capture date, the swapped unit/case identity, the copied fingerprint, and both photograph
substitutions — **provided the attacker cannot obtain a token from an authority the
recipient trusts.** That condition is stated exactly, not glossed.

### What it does not close, stated plainly

- **Producer identity is still unknowable without an anchor.** A seal says *"these exact
  bytes were countersigned by authority A at time T"*. It never says who assembled them.
  Cryptography cannot authenticate an unknown party; every scheme that appears to do so
  has relocated the anchor to a CA, a log, or an authority. This one relocates it to the
  TSA, which is the anchor a habitable recipient already has.
- **An adversary who can reach a trusted public authority can re-seal a rewritten
  packet.** FreeTSA will stamp any digest for anyone. Against such an adversary the seal
  does not *prevent* the forgery; it forces the forgery to carry an unforgeable,
  authority-signed record of **when it was made**. A packet filed on the 3rd whose seal
  says its contents came into existence on the 30th is provably a reconstruction.
  Concretely, the seal is caught when the check point is after the forgery
  (`--seal-not-after`) and missed when the forgery precedes first delivery.
- **Downgrade by stripping.** An attacker removes `packet_seal` and rewrites at will; a
  recipient who does not pass `--require-packet-seal` is back to the PR #193 baseline.
  The default is a ratchet for honest producers, not a defence. The defence is the flag —
  which is why the flag needs no secret, and why the CLI names the absence out loud on
  every run instead of staying quiet about it.
- **Nothing here concerns a dishonest producer.** Everything in a packet is authored on
  the producer's device before any proof is computed. This is tamper-evidence, not truth.

### Costs and follow-ups

- **Export now touches the network** when an authority is configured — the first time
  `habitable export` ever has. `--no-seal` and an unreachable authority both degrade to
  an unsealed packet rather than a failed export: capture's offline-first rule extended
  to export. The CLI says which happened, and prints the bytes used (R-18).
- **Export joins the metered-link gate (R-19).** `--wifi-only` (or `[network]
  allow_metered = false`) skips sealing rather than refusing the export, because unlike
  `resolve`, the fetch is not the operation — the packet is. `resolve` still refuses.
- **The test suite gained an offline guard.** A vault's default config names public
  authorities, so sealing made the merge gate silently depend on freetsa.org being up.
  `tests/conftest.py` now fails any non-`integration` test that opens a connection off
  the machine; loopback stays open for the relay and app-server tests.
- **A packet built offline cannot be sealed.** There is no deferred-seal queue: a seal is
  over a specific bundle's bytes, so it must be minted while that bundle is being written.
  Re-export once online. (A `resolve`-style follow-up could re-seal an existing packet
  directory in place; deliberately not built here.)
- **Only the primary authority seals.** Item timestamps support redundant authorities
  (R-16); the seal does not yet. Follow-up.
- **`packet.html` and `packet.pdf` cannot show the seal.** They render from the bundle,
  and the seal is deliberately outside it, so the human-readable views say nothing about
  it. Only `habitable verify` can. Surfacing it in the renderings means handing them
  `bundle.sig.json`, which is a rendering-layer change and was left out of this one.
- **`campaign export` and the Apache-2.0 legal-aid receipt were not extended.** A
  multi-unit organizer roll-up has no authority in hand and produces unsealed packets;
  `contrib/legal_aid_importer.py` still records the three ADR 0008 claims and not the
  seal. Neither states anything untrue — the receipt's fields keep exactly their old
  meaning — but a receipt that recorded the seal would be a receipt v3, i.e. a migration
  for embedders, and that decision is not this ADR's to make.
- **The seal is not mentioned in `bundle.json`'s `disclosures`.** It deliberately cannot
  be: a disclosure lives inside the bundle, so an attacker could add a reassuring line to
  an unsealed forgery or delete an accurate one. Seal status is reported by the verifier,
  which is the only party in a position to say anything trustworthy about it.
- **The tamper challenge becomes publishable against the unpinned invocation**, because a
  challenge has the one thing an ordinary recipient lacks: a *published* start date. No
  entrant can obtain a token dated before the packet was published, so
  `--seal-not-after <publication date>` is an anchor the rules can state and the entrant
  cannot forge. See [`../tamper-challenge.md`](../tamper-challenge.md) §3 and §7.
