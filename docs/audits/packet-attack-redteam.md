<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# How to attack a habitable packet — an adversary playbook

> **Status: alpha / concept stage. Do not rely on this for a real legal matter yet.**
> This document names habitable's own evidentiary and security weaknesses before an
> opposing counsel or a red-team does. It is written as an adversary's playbook: each
> entry frames an attack the way a hostile reviewer would, states what actually happens
> against the current design, and then concedes the residual risk that remains and the
> honest mitigation. Where an objection is *correct*, this document says so plainly —
> conceding a true limit is the point, not a failure of it.

This is backlog item **E-18** from
[`../research/synthetic-personas-feedback.md`](../research/synthetic-personas-feedback.md),
driven by persona **P-11** ("opposing counsel") and **P-22** ("the retaliating landlord /
red-team"). It is the companion attack-side reading of the
[evidence method](../evidence-method.md) and the [threat model](../threat-model.md):
the evidence method says what the mechanism proves, the threat model says what is and is
not protected, and this document plays the other side of the table.

Two ground rules frame everything below, and both are load-bearing for a tenant:

1. **habitable strengthens a true record; it does not manufacture a case.** Every
   mitigation here makes an *honest* photo harder to discredit. None of them make a
   *dishonest* claim true. An adversary's strongest moves are almost always against
   things the tool never claimed to prove (authorship, depiction) — so the tool's own
   honesty about those gaps is the tenant's shield, not a crack in it.
2. **The verifier fails closed.** `verify_packet` rejects malformed, tampered, or
   newer-than-supported packets; it does not "best-effort" them into a pass. So most
   tampering attacks below do not yield a *quietly wrong* verdict — they yield a *loud
   rejection*, which is itself the defense.

---

## Contents

- [Integrity attacks](#integrity-attacks)
  - [A1 · Edit or substitute a photo](#a1--edit-or-substitute-a-photo)
  - [A2 · Backdate or forge a timestamp](#a2--backdate-or-forge-a-timestamp)
  - [A3 · Tamper with or reorder the custody chain](#a3--tamper-with-or-reorder-the-custody-chain)
- [Credibility attacks (in the courtroom)](#credibility-attacks-in-the-courtroom)
  - [A4 · "The tool and the verifier are rigged"](#a4--the-tool-and-the-verifier-are-rigged)
  - [A5 · "The timestamp proves nothing about depiction or authorship" (conceded)](#a5--the-timestamp-proves-nothing-about-depiction-or-authorship-conceded)
  - [A6 · "The chain is self-serving / self-authenticating" (largely conceded)](#a6--the-chain-is-self-serving--self-authenticating-largely-conceded)
- [Discovery and legal-process attacks](#discovery-and-legal-process-attacks)
  - [A7 · Over-broad discovery demanding the whole vault](#a7--over-broad-discovery-demanding-the-whole-vault)
  - [A8 · Subpoena the relay operator (metadata)](#a8--subpoena-the-relay-operator-metadata)
- [Device and supply-chain attacks](#device-and-supply-chain-attacks)
  - [A9 · Device seizure, forensics, and coercion vs duress mode](#a9--device-seizure-forensics-and-coercion-vs-duress-mode)
  - [A10 · Supply-chain or dependency compromise](#a10--supply-chain-or-dependency-compromise)
  - [A11 · Social engineering as a reviewer or pilot partner](#a11--social-engineering-as-a-reviewer-or-pilot-partner)
- [What this means for a tenant](#what-this-means-for-a-tenant)

---

## Integrity attacks

### A1 · Edit or substitute a photo

**(a) The attack, as the adversary frames it.** "The tenant doctored the photo — painted
in mold, brightened a water stain — or swapped a convincing photo from another apartment
into the packet. Either way the image in front of the court is not the image they
captured, and nobody can tell."

**(b) What actually happens.** At capture, the original media's bytes are hashed with
streaming SHA-256 and that `content_hash` is recorded; the original is sealed and treated
as immutable, and fixity is re-derived on every read (`verify_fixity` raises
`FixityError` on any mismatch). In a packet, the verifier (`_verify_item`) re-derives the
SHA-256 of the shared media and confirms it equals the recorded `shared_hash`; a signed
`copied_for_sharing` custody entry binds that `shared_hash` to the original
`content_hash`; the RFC 3161 token is checked over `content_hash`; and, if the original is
embedded (`include_originals=True`), its content hash is re-derived directly. **Editing
the pixels after capture changes the bytes, which changes the hash, which fails fixity and
breaks the timestamp binding.** Substituting a different photo means producing one with
the *same* SHA-256 — a second-preimage attack on SHA-256, which is not feasible — or
re-capturing the substitute fresh, in which case it carries its own later timestamp and
its own honest capture time, not a backdated one.

**(c) Residual risk and honest mitigation.** The hash binds *bytes*, not *truth*. Nothing
stops a tenant from photographing a *staged* scene, or another apartment, and capturing
that honestly — the tool will faithfully prove that *those exact bytes* existed by a
certain time. The tool does not adjudicate **depiction** (see [A5](#a5--the-timestamp-proves-nothing-about-depiction-or-authorship-conceded)).
The defense against staging is not cryptographic; it is the rest of the record — the
timeline, repair requests, an inspector's corroboration, cross-examination — exactly as
with any photographic evidence. habitable's claim is narrow and it holds: *this image was
not altered after it was captured.* It does not claim more, and a packet should not be
argued as if it did.

### A2 · Backdate or forge a timestamp

**(a) The attack.** "The 'trusted timestamp' is just something the tenant generated. They
set their clock back, or used their own toy authority, and stamped January onto a photo
they took last week."

**(b) What actually happens.** A production timestamp is an **RFC 3161** token from a
public authority that signs over the SHA-256 message-imprint and returns its own `genTime`
— the device clock is irrelevant to what the token says. `verify_token`
(`_verify_rfc3161_token`) checks the CMS `SignedData` structure, that the token's imprint
algorithm is SHA-256 and its `hashed_message` equals the `content_hash` being verified
(a token minted for a different hash is rejected), that the signed-attributes signature
verifies against the signing certificate, and that the signing certificate chains to a
supplied trusted root or pin. Forging this requires forging the authority's signature.
A "toy authority" is caught by the chain check: with no trusted certificate supplied the
chain is reported **untrusted** (signature still validated, but flagged), and the
non-production `DevTSA` tokens *self-describe* as non-production with `trusted_chain=False`
and an explicit note. The token proves the content existed **no later than** `genTime`.

**(c) Residual risk and honest mitigation.** Three honest gaps remain. First, the bound is
**upper only** — the token says nothing about how much *earlier* the content existed, so it
cannot, by itself, defeat "you could have taken this even earlier" (rarely the adversary's
goal) nor establish a precise capture moment. Second, a verifier that is handed **no
trusted roots** will report a token as untrusted rather than failing outright; an honest
packet therefore depends on the recipient supplying real RFC 3161 roots, and a packet
built only with `DevTSA`/`LocalRfc3161TSA` tokens is **not real evidence** and says so.
Third, trust still rests on the **authority**: a single compromised, colluding, or
coerced TSA could in principle backdate or refuse. The mitigations are configuring
**multiple authorities** so the proof does not rest on one party, **offline verification**
against pinned certificate chains, and naming the TSA in each token so a recipient can
weigh it. Offline capture is not a weakness here: an item captured with no signal is
hashed and sealed instantly and serializes `"timestamp": null` with an `awaiting
timestamp` note — the verifier does **not** treat the absence as a pass — and the hash
still anchors the exact content at capture even before a token is fetched.

### A3 · Tamper with or reorder the custody chain

**(a) The attack.** "I'll find the entry that hurts me — the one showing they sat on this
for months, or copied it somewhere — and I'll get it deleted, reordered, or altered. Or
I'll show the chain is so easily rewritten it means nothing."

**(b) What actually happens.** The chain of custody is an **append-only, hash-linked** log:
each `CustodyEntry` carries a `seq`, an HLC stamp, and `prev_hash` (the previous entry's
hash; the first links to 64 zeros), and the `entry_hash` is the SHA-256 over the entry's
canonical-JSON public payload, which *includes* `prev_hash`. `CustodyLog.verify()` walks
the chain and raises `CustodyError` on a wrong `seq`, a `prev_hash` that does not match the
running hash (reordering or deletion), or an entry whose recomputed hash differs from its
stored `entry_hash` (alteration). The packet carries the integrity proof and a declared
`head_hash`, and the verifier rebuilds the chain from the proof's entries and confirms the
walk reproduces that head. **Any insertion, deletion, reordering, or edit of a single entry
breaks the link math and is detected** — the verifier fails closed, it does not silently
accept a re-stitched chain.

**(c) Residual risk and honest mitigation.** This is **tamper-evident, not tamper-proof
against the device owner**, and habitable says so directly. The hash-link makes
*after-the-fact* alteration detectable, but it does **not** prevent the holder of the vault
key from discarding the whole log and writing a *new, internally consistent* chain before
any external party has seen the head hash — the new chain would verify against itself. This
overlaps with [A6](#a6--the-chain-is-self-serving--self-authenticating-largely-conceded):
detection of a wholesale rewrite depends on an **external anchor** — a counterpart who
already holds the chain head (peer sync distributes the head to other devices), or an RFC
3161 timestamp taken over the head hash. The honest framing is: the chain answers "was this
record altered after the fact?" — it does **not** bind a hostile keyholder who rewrites
everything before anyone external sees it.

---

## Credibility attacks (in the courtroom)

### A4 · "The tool and the verifier are rigged"

**(a) The attack.** "This is the tenant's own software checking the tenant's own evidence
and declaring it good. Of course it says 'verified.' How does anyone know the verifier
isn't cooked to pass tampered packets?"

**(b) What actually happens.** The verifier does not have to be trusted, because it does
not have to be *used*. The `verify` module and the pure modules it imports are offered
under **Apache-2.0** (a GPLv3 §7 additional permission) precisely so a court, a legal-aid
group, or **opposing counsel** can read it, embed it, and run it themselves. More
important: verification rests only on the packet plus **standard primitives** — SHA-256,
RFC 3161, Ed25519 — so a skeptic can **cross-check with general-purpose tooling** instead
of habitable's verifier at all: hash the shared media with any SHA-256 utility and compare
to `shared_hash`; validate the RFC 3161 token with standard tooling against the content
hash; verify the Ed25519 bundle signature with any conforming library. If the project's
verifier and off-the-shelf tools disagree, the off-the-shelf tools win and the project's
claim is falsified in public — which is the whole bargain. The verifier also **fails
closed**: malformed or newer-than-supported packets are rejected, not mis-verified.

**(c) Residual risk and honest mitigation.** A documented, **step-by-step cross-check
procedure** using only general RFC 3161 and hashing tools is a tracked remediation (R-31)
and is what makes "don't trust our verifier" actionable rather than rhetorical; until it
ships, a skeptic must assemble the cross-check from the [evidence method](../evidence-method.md).
Independent assurance of the verifier's failure modes — a published adversarial/fuzz report
showing no accept-on-tamper and no crash (R-32), a documented decision/truth table (R-39),
and an external security audit — is **roadmapped, not yet done**; this is alpha software and
the verifier has not been independently audited. The right posture for a tenant is to *invite*
the cross-check, not resist it: the tool is built to be checked by the other side.

### A5 · "The timestamp proves nothing about depiction or authorship" (conceded)

**(a) The attack.** "Granted the bytes are old and unaltered. So what? The token doesn't
say *who* took this, that it's *this* unit, or that the condition was real on that day. It
could be a photo of anywhere, by anyone, staged."

**(b) What actually happens — this objection is correct, and habitable already says so.**
An RFC 3161 token bounds *time*, full stop. The evidence method states it in plain terms:
the token does **not** prove who created the content, does **not** prove what it depicts or
that a described condition was real, and does **not** prove the content did not exist
earlier. Conceding this is not a concession of weakness — it is the difference between a
tool that *strengthens true records* and one that *overpromises in a courtroom and gets the
people relying on it hurt*. The packet's own "what this proves / what it does not" framing
is meant to put this in front of the court **first**, so the tenant is not blindsided by it
on cross.

**(c) Residual risk and honest mitigation.** The residual is real and it is *legal*, not
cryptographic: depiction and authorship are established the ordinary way — the tenant's own
sworn testimony laying foundation ("I took this in my bathroom on that date"), the
corroborating timeline, repair requests, and an inspector's report. The tool's job is to
remove *one* line of attack ("you edited it / you backdated it") so the fight is about the
facts, not the file. Surfacing the upper-bound semantics on the packet itself (R-26, R-29)
and providing a witness-foundation **declaration template** (E-19) are how this concession
becomes the tenant's shield rather than the adversary's opening.

### A6 · "The chain is self-serving / self-authenticating" (largely conceded)

**(a) The attack.** "Your custody log shows the *tenant* held the device the entire time.
That's not independent corroboration — that's the tenant vouching for the tenant. It is
self-authentication dressed up as proof, and the exported chain has had the names stripped
out, so I can't even test who did what."

**(b) What actually happens — this is largely true, and worth stating plainly.** What the
chain proves is **internal integrity**: no insertion, deletion, reordering, or alteration
*after the fact*, plus that it was produced by the holder of the producer's Ed25519 key
(the bundle signature). What it does **not** prove is **independent custody by a neutral
party**: in the common case it shows the tenant or union controlled the device throughout,
which is closer to **self-authentication** than to third-party attestation. The
identity-stripping is deliberate and pulls in two directions: the exported chain carries a
**salted actor commitment**, not the actor in clear, so a recipient can confirm the chain
is intact **without learning which organizer viewed or copied an item** (protecting
organizers from targeted retaliation) — at the cost of the chain not naming, on its face,
an independent custodian.

**(c) Residual risk and honest mitigation.** Two honest residuals. First, "self-serving" is
a fair characterization of a single-device chain, and the honest answer is that the chain is
**one corroborating layer, not standalone proof** — its strength rises when the head hash
was externally anchored early (an RFC 3161 timestamp over the head, or a peer who already
holds it via sync) so a wholesale rewrite ([A3](#a3--tamper-with-or-reorder-the-custody-chain))
is foreclosed, and when more than one person on a case has synced the same head. Second,
the **identity-stripping itself** can be framed by an adversary as hiding something; the
counter is that the clear identity, salt, and signatures **remain in the vault** and the
construction is published, so the redaction is minimization, not concealment — and a court
can be told exactly what was dropped and why. **Foundation guidance for counsel** on
introducing a packet as self-authenticating-plus-corroboration rather than independent proof
(R-30) is the non-code half of this, and it is a tracked, not-yet-written, gap.

---

## Discovery and legal-process attacks

### A7 · Over-broad discovery demanding the whole vault

**(a) The attack.** "They produced a packet for unit 4B. Now I'll demand the **entire union
vault** in discovery — every case, every building, every organizer's notes — and either
bury them, expose other tenants and organizers, or find something to use elsewhere."

**(b) What actually happens.** A packet is a **whole-unit export of the opened case vault**,
not a dump of every case vault a tenant or union maintains. Current packet-v3 construction
includes every issue, timeline entry, and capture in that case plus its complete public custody
proof; issue/date requests fail before output. Separate people or units therefore need separate
case vaults. The vault is encrypted at rest on the user's own devices, the exported custody form
is **identity-stripped**, and shared copies have embedded metadata stripped by default.
Sealed originals are optional, preserve their original metadata (including possible location),
and are called out in the packet disclosure when embedded.

**(c) Residual risk and honest mitigation.** Whether a court *grants* an over-broad request
is a **legal** question the tool cannot answer, and the scope of producible material is
ultimately set by discovery rules, not by software. The architecture limits one export to
the opened case vault and avoids a central plaintext database, but it does **not** select only
legally relevant issues or dates. Review the whole-unit packet before producing it; if that is
too broad, do not export and seek case-specific legal advice. Shared-copy metadata stripping and
withholding sealed originals reduce disclosure inside that fixed boundary. A new versioned,
scoped/rehashed custody view is still required for narrower export (R-35). This is harm-reduction
by design, not a guarantee about what a given judge will order.

### A8 · Subpoena the relay operator (metadata)

**(a) The attack.** "I can't break the encryption, so I'll subpoena whoever runs the sync
relay and get the metadata: which devices talk to which, when, and how much — enough to map
the organizing, identify who is on a case, and time my retaliation."

**(b) What actually happens.** Every sync message is **sealed to the recipient's X25519 key
before it leaves the sender**, so the relay is a dumb mailbox that stores and returns opaque
ciphertext and **cannot read contents** — there is nothing to subpoena *for the contents*.
The relay is designed **no-log** (only aggregate passthrough counts: rooms, posted, fetched,
bytes) and **self-hostable**, so a union can run its own, and **pure peer-to-peer** sync
(`LocalDirTransport` over a shared directory / USB / SD card) removes the relay party
entirely.

**(c) Residual risk and honest mitigation — conceded.** A relay, *if used*, necessarily
observes **connection metadata**: who connects, to which room, when, and roughly how much
data moves. habitable does **not** implement traffic-analysis resistance — no padding, no
mixing, no cover traffic — so this metadata is real and is **not** hidden. This must be
stated airtight and prominently (R-33) precisely so an adversary cannot spin it as a
concealed leak. The mitigations are honest but bounded: a no-log, self-hosted relay reduces
*who holds* the metadata; **pure peer-to-peer / sneakernet sync removes it entirely**; and
network-level observation (an ISP or Wi-Fi operator watching connections) is outside the
app's control and is the user's responsibility (Tor/VPN). A metadata-resistant relay profile
and an operator "what I can and cannot observe" matrix are roadmapped (R-46, E-23), not
shipped. The one structural win that *is* real: there is **no central operator holding any
tenant's contents** to subpoena, ever.

---

## Device and supply-chain attacks

### A9 · Device seizure, forensics, and coercion vs duress mode

**(a) The attack.** "The strongest move isn't math — it's the phone. I'll get the device:
seized in an eviction, searched at the door, repaired, or borrowed. I'll image it and have
a forensic lab analyze it at rest. Or I'll just make the tenant unlock it. Their 'duress
mode' is theater."

**(b) What actually happens.** A **locked** vault on a **clean** device is ciphertext: every
blob and sealed original is ChaCha20-Poly1305 under a DEK that is wrapped by a scrypt-derived
KEK from the passphrase, and only `config.toml` (no secrets) and the passphrase-wrapped
keyfile sit in the clear. An adversary holding a locked device gets the keyfile and
ciphertext, not the contents. There is **no duress-safe, panic, or decoy state** in the
current app. A coerced unlock with the real passphrase exposes the real vault.

**(c) Residual risk and honest mitigation — this is where the design is weakest, and it is
documented as such.** Several gaps are real and conceded:

- **Duress mode is planned, not shipped.** It provides no protection today. Any future
  implementation must first survive human red-team review and surface its limits at the
  point of use; [ADR 0007](../adr/0007-limits-first-distress-decoy-vault-model.md) records
  that gate.
- **An unlocked vault, or a compelled passphrase, exposes everything.** The cryptography
  assumes a trustworthy endpoint; malware, a keylogger, or a screen recorder on an unlocked
  device defeats it entirely.
- **A weak passphrase is offline-guessable** once the keyfile and ciphertext are seized, and
  future cryptographic breaks are a standing risk on any data the adversary keeps.
- **Discreet-presence leakage.** On a shared phone, the app's name/icon, notifications, and
  app-switcher surface can reveal a case exists at all (R-12, R-13, R-14 track this).

Hardening at-rest defaults against forensic recovery (R-49) is tracked. The honest bottom
line, stated in the threat model: **endpoint compromise defeats everything**, and a
state-level actor, a targeted exploit, or a capable forensic lab can defeat parts of this
model. The tool reduces harm against a resourced landlord; it does not promise safety
against a forensic search or coercion.

### A10 · Supply-chain or dependency compromise

**(a) The attack.** "Forget the packet. I'll poison the well — compromise a dependency, or
the build, so the shipped binary quietly exfiltrates data, backdoors the timestamp flow, or
weakens the crypto. Every packet built after that is mine."

**(b) What actually happens.** The project's supply-chain posture is: **pinned, hashed
dependencies**; GitHub Actions **pinned to commit SHAs** with **build-provenance
attestations**; **signed releases**; and `pip-audit`, `gitleaks`, and CodeQL in CI, with a
published SECURITY policy and disclosure path. Crucially, the **verifier is independent and
its trust can be externalized**: because a packet verifies against standard SHA-256 / RFC
3161 / Ed25519 primitives, a backdoored *producer* build cannot make a tampered packet pass
a **clean, independent verifier** or off-the-shelf tooling (see [A4](#a4--the-tool-and-the-verifier-are-rigged)).
A compromise that weakened *production* would still be caught when the other side verifies
with their own tools.

**(c) Residual risk and honest mitigation.** **Reproducible builds** — which let a skeptic
confirm the shipped binary matches the audited source — are **roadmapped and in progress,
not finished**, so today a user cannot fully verify the binary against source. A compromise
of the **producer device or build** before capture could affect what gets *captured*
(the cryptography assumes a trustworthy endpoint, and a poisoned capture path could record
chosen bytes honestly). And no dependency-audit tooling catches a *novel* supply-chain
attack proactively — it catches *known* advisories. The mitigations reduce, not eliminate,
this class; the strongest structural defense remains that **independent verification with
the recipient's own tools** does not trust the producer's build at all.

### A11 · Social engineering as a reviewer or pilot partner

**(a) The attack.** "I'll skip the tech entirely. I'll pose as a security 'reviewer,' a
legal-aid 'pilot partner,' or a friendly translator, get invited in, and either obtain
access to real case data or quietly introduce a weakness."

**(b) What actually happens.** There is structurally **no central access to grant**: no
operator, no account system, no hosted cloud of cases, and no admin who can read or revoke a
union's data. A "reviewer" cannot be handed other people's cases because **no one holds
them** — onboarding and all evaluation run on **synthetic data only**, and no real tenant
data is wanted or committed. Security vulnerabilities go **privately through SECURITY.md**,
never a public issue, so a hostile "reviewer" cannot harvest a live bug from an open thread.

**(c) Residual risk and honest mitigation.** Social engineering targets **people, not the
protocol**, so it routes around the architecture: a malicious "contributor" could attempt a
subtle code change (mitigated by review, signed commits, and the independent verifier that
would expose a verification weakening), and a malicious "organizer" already *inside* a union
holds real keys and real trust that no software can revoke from the outside — that is a
human-trust boundary, not a cryptographic one. **Partner/reviewer vetting guidance, keeping
disclosures private, and confirming there is no central access to grant (R-50)** are tracked.
The honest framing: the architecture removes the **honeypot** a social-engineering attack
usually aims at, but it cannot remove the need to vet the humans a union chooses to trust.

---

## What this means for a tenant

The honest framing above is not a list of cracks — it is the tenant's shield. Read together,
the attacks fall into three groups, and a tenant should hold each differently:

- **Attacks on integrity mostly fail loudly.** Editing a photo, swapping it, backdating a
  timestamp, or rewriting custody entries do not produce a quietly-accepted forgery — they
  produce a **rejection** from a verifier that fails closed and can be cross-checked with the
  other side's own standard tools. This is the part the tool is built to win, and it removes
  the landlord's easiest line: *"you faked it."*

- **Some objections are true, and saying so is the point.** A timestamp does not prove *who*
  took a photo or *what* it shows; a single-device custody chain is closer to
  self-authentication than to independent proof; a relay sees connection metadata; duress mode
  is not forensic-proof. habitable concedes every one of these, in the threat model, in the
  evidence method, and on the packet itself. An honest tool that names its own limits is
  **far harder to ambush on cross-examination** than one that overpromised — the tenant is
  never blindsided by a weakness their own packet already disclosed.

- **The deepest risks are about the device and the people, not the math.** A seized,
  unlocked, or coerced device, a poisoned build before capture, or a social-engineered insider
  can defeat parts of this model. These are real, they are documented, and several mitigations
  are still **roadmapped, not done** — which is exactly why this is **alpha software that must
  not be relied on for a real legal matter yet.**

The bargain habitable offers a tenant is narrow and honest: it makes a **true** record of a
real condition very hard to discredit as *altered* or *backdated*, while refusing to pretend
it can prove anything it cannot. The strongest thing a tenant can do with a habitable packet
is to **invite the other side to verify it** — and to let the tool's own candor about its
limits be the answer when opposing counsel reaches for the weaknesses this document already
named.

> The full mitigation for each limit lives in [`../threat-model.md`](../threat-model.md);
> what the method does and does not establish is in [`../evidence-method.md`](../evidence-method.md);
> the remediation IDs (R-/E-) trace to
> [`../research/synthetic-personas-feedback.md`](../research/synthetic-personas-feedback.md).
