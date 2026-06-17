# habitable — threat model

> **Status: alpha / concept stage. Do not rely on this for a real legal matter yet.**
> habitable is a reference-implementation spec at concept stage. The design below describes
> what the tool is built to do, but it has not been audited, hardened, or proven in court. The
> default development timestamp authority is explicitly non-production. Until a release says
> otherwise, treat habitable as a prototype for evaluation, not as a tool to protect a tenant who
> is actually in a fight with a landlord. This document is part of how we earn the right to drop
> that warning, by saying plainly what is protected, what is not, and where the residual risk sits.

This document is the companion to the **Hard rules** and **Honest limits** sections of the
[README](../README.md). It states the adversary we design against, the assets we protect, the
trust boundaries and what each party can see, what is and is not protected, and the residual risk
that remains after each mitigation.

---

## 1. Adversary

The threat model is **a landlord who retaliates**, together with their lawyer, and treated as an
adversary with resources and motive — not a casual snoop.

We assume the adversary may:

- **Retaliate** against a tenant for documenting conditions or organizing — with eviction filings,
  rent disputes, harassment, or selective enforcement — and will use anything they learn to do it.
- **Gain physical access to a device.** A phone or laptop may be seized, borrowed, repaired,
  searched at a doorstep, or examined during an eviction or a building-access dispute. Assume the
  adversary can, at some point, hold the hardware.
- **Pressure or subpoena third parties.** A lawyer can subpoena a company, an ISP, or an
  infrastructure operator, and can pressure a less-careful organizer or tenant. The design goal is
  that **there is no third party holding a tenant's contents to subpoena** — the only optional
  network parties (a relay and a timestamp authority) never hold the contents in the first place.
- **Contest the evidence.** Even a landlord with no access to the data will, in court, attack the
  credibility of a bare photo — "you could have taken that anytime," "you could have edited it."
  Much of the design exists to answer that attack with something independently checkable.

We do **not** claim to defend against every adversary. A state-level actor, a targeted device
exploit, or a sufficiently capable forensic lab can defeat parts of this model; the limits are
called out explicitly in §5 and §6.

---

## 2. Assets to protect

| Asset | Why it matters |
| --- | --- |
| **Tenant identity and location** | A home address tied to a tenant who is organizing is exactly what enables retaliation. Originals carry EXIF GPS and capture time; that must never leak through a shared copy or an operator. |
| **Case contents** | The photos, video, condition notes, and timeline are sensitive both as private home imagery and as the substance of a legal position the landlord wants to know and weaken. |
| **Integrity of the evidence** | The whole value of the tool is that a record was not altered after capture and existed by a given time. If integrity can be quietly broken, the evidence is worthless or worse. |
| **Organizer identities** | Who is helping whom — which organizer works which building — is sensitive. Exposure invites targeted retaliation and chills organizing. Custody logs record who did what to an item; that "who" must stay inside the union. |

---

## 3. Trust boundaries — what each party can see

habitable has three parties that can ever touch a case, in decreasing order of trust. The design
goal is that trust **decreases sharply** as you move away from the device, and that the parties
outside the device never see contents at all.

### 3.1 The device — plaintext + keys (encrypted at rest)

The device is the trusted base. It is the only place that ever holds plaintext or key material.

- A **vault** is a directory holding one case (`vault.py`). Sealed originals, the CRDT case
  document, the chain of custody, the device identity, and the deferred-timestamp queue are all
  **encrypted at rest** under a data-encryption key (DEK).
- The DEK is a random 32-byte key used with **ChaCha20-Poly1305** (an AEAD: confidentiality plus
  integrity). It is itself wrapped under a key-encryption key (KEK) derived from the user's
  passphrase with **scrypt** (`crypto.py`).
- The only plaintext on disk is `config.toml` (committed policy, no secrets) and `keyfile.json`
  (the passphrase-wrapped DEK). Everything else — `case.enc`, `custody.enc`, `identity.enc`,
  `deferred.enc`, the sealed `originals/` — is ciphertext.
- The device also holds the **Ed25519** signing key (signs custody entries, sync messages, packets)
  and the **X25519** key-agreement key (receives sealed sync deltas).

**What an adversary with the device gets:** the ciphertext, the keyfile, and the config. Without
the passphrase they do not get the contents. **With** the passphrase (or while the vault is
unlocked) they get everything — see §6 (physical access / duress).

### 3.2 The optional relay — ciphertext + connection metadata, never contents

A union that cannot sync device-to-device can run a relay (`relay.py`, `RelayClient` in `sync.py`).
It is deliberately a dumb mailbox: ciphertext in, ciphertext out.

- Every sync message is **sealed to the recipient's public key before it leaves the sender**
  (`seal_to` in `crypto.py`), so the relay only ever stores opaque blobs per room and hands them
  back. It **cannot read anything**.
- The relay keeps **no logs beyond aggregate passthrough counts** (rooms, posted, fetched,
  bytes_relayed). It does not log request lines, peer addresses, or message contents.

**What the relay can nonetheless see — connection metadata:** because it forwards traffic, it
necessarily observes **who connects, to which room, when, and roughly how much data moves**. That
is metadata, not contents, but it is real (see §5 and §6). The mitigations are: a **no-log,
self-hostable** relay (a union runs its own), and **pure peer-to-peer sync with no relay at all**
(`LocalDirTransport` over a shared directory / USB / AirDrop-style transfer), which removes the
party entirely.

### 3.3 The RFC 3161 timestamp authority — a SHA-256 hash, never the file

To prove a record existed by a certain time, the tool sends a timestamp request to an RFC 3161
authority (`tsa.py`).

- The authority receives **only the SHA-256 hash** of the content (the message imprint), **never
  the file** and never any case metadata. It returns a signed token that says "this exact digest
  existed no later than this time."
- A hash discloses nothing about the photo: the authority cannot tell what was photographed, who
  took it, or where. Multiple authorities can be configured so the proof does not rest on one party.

**What the authority can see:** that *someone* asked it to stamp *some* 32-byte hash at a given
time, plus whatever the network exposes (the requester's IP, unless the request is proxied). It
learns nothing about the contents.

---

## 4. What is protected

| Property | How it is achieved | Where |
| --- | --- | --- |
| **Confidentiality at rest** | Every vault blob and sealed original is encrypted with ChaCha20-Poly1305 under the DEK, which is wrapped under a scrypt-derived KEK from the user's passphrase. | `crypto.py`, `vault.py` |
| **End-to-end encryption in sync** | Each sync message is sealed to the recipient's X25519 public key via an ECIES-style sealed box (ephemeral X25519 → HKDF → ChaCha20-Poly1305) and signed by the sender's Ed25519 key. The relay never holds a key that can open it. | `crypto.py` (`seal_to` / `open_sealed`), `sync.py` |
| **Tamper-evidence (content)** | Originals are hashed (SHA-256) at capture and sealed byte-for-byte; every read re-checks the hash, so silent corruption or tampering surfaces as a `FixityError` instead of a quietly altered exhibit. | `evidence.py` (`verify_fixity`), `vault.py` (`read_original`) |
| **Tamper-evidence (sequence)** | The chain of custody is an append-only, hash-linked log: each entry commits to the previous entry's hash, so any insertion, deletion, or reordering breaks the chain detectably. Entries can also be Ed25519-signed. | `evidence.py` (`CustodyLog`) |
| **Upper-bound timestamps** | A SHA-256 hash is sent to an RFC 3161 authority, which returns a signed token proving the content existed *no later than* that time. Tokens travel inside the packet for offline verification, and the verifier checks the signature and certificate chain. | `tsa.py` (`Rfc3161HttpTSA`, `verify_token`) |
| **Location stripping on shared copies** | The sealed original keeps EXIF (capture time, GPS) for evidentiary integrity; any shared or exported copy strips location by default, and the user is shown what a packet discloses before it is produced. | README *Hard rules* #4; `exif.py` (per architecture) |
| **Custody-identity minimization in exports** | Each custody entry binds a *salted commitment* to the actor, not the actor in clear. The exported (packet) form drops the actor, salt, and signature entirely, so a recipient can confirm the chain is intact **without** learning who viewed or copied an item. The clear identity stays in the vault. | `evidence.py` (`public_payload`, `redacted`, `integrity_proof`) |
| **No telemetry / no analytics / no phone-home** | The tool collects no analytics and contacts no servers it is not told to. The relay logs only aggregate ciphertext-passthrough counts. There is no account system and no central database. | README *Hard rules* #1, #5; `relay.py` |

---

## 5. What is NOT protected — explicit limits

Being precise about the boundaries is part of being credible. A tool that overpromises in a
courtroom fails the people relying on it.

- **A timestamp proves *when*, not *who* or *what*.** An RFC 3161 token bounds the time the content
  existed — an *upper bound* on creation. It does **not** prove who created the content or that the
  content depicts what a tenant says it depicts. Tamper-evidence and a timestamp strengthen a true
  record; neither manufactures a case the facts do not support.
- **The local custody log is tamper-*evident*, not tamper-*proof*, against the device owner.** The
  hash-linked chain makes after-the-fact alteration *detectable* by anyone who verifies it. It does
  **not** prevent the holder of the vault key from discarding the whole log and writing a new
  internally-consistent one before any external party has seen the head hash. Detection depends on
  an external anchor (a counterpart who already holds the chain head, or a timestamp over it). The
  chain answers "was this record altered after the fact?" — it cannot bind a hostile keyholder.
- **Relay metadata is not hidden.** Even a no-log relay observes who syncs with whom and when, and
  roughly how much moves. habitable does not implement traffic-analysis resistance, padding, or
  mixing. The only way to remove this exposure entirely is to not use a relay (pure peer-to-peer).
- **The duress-safe state hides contents; it is not a guarantee.** Opening the app to a duress-safe
  state hides case contents from someone glancing at the screen or coercing a quick unlock. It is
  **not** a guarantee against a sufficiently capable coercing adversary (who can compel the real
  passphrase) or a forensic adversary (who images the device and analyzes storage at rest). It is a
  harm-reduction mitigation with documented limits, not a safe.
- **Lost keys with no backup mean lost data.** There is no operator, no account recovery, and no
  one who can read or reset a union's data. A lost passphrase with no recovery blob (`crypto.py`
  `export_recovery_blob`) and no surviving synced peer means the data is **unrecoverable** —
  by design. The flip side of "no one can be subpoenaed for it" is "no one can recover it for you."
- **The development TSA is non-production.** `DevTSA` in `tsa.py` signs with a local Ed25519 key and
  is reported as an untrusted chain; its tokens self-describe as non-production. `LocalRfc3161TSA`
  issues real RFC 3161 tokens but from a **self-signed** authority for tests and demos. Neither is a
  trusted third-party time source. Real evidence requires a real public RFC 3161 authority
  (`Rfc3161HttpTSA`) whose certificate chains to a trusted root.
- **Not legal advice, and no guarantee of admissibility.** habitable produces well-documented
  evidence. Whether a court or agency admits it, or how much weight it carries, is a legal question
  this tool cannot answer.
- **Endpoint compromise defeats everything.** Confidentiality at rest protects a *locked* vault on
  a *clean* device. Malware on an unlocked device, a keylogger capturing the passphrase, or a screen
  recorder defeats the encryption entirely. The cryptography assumes a trustworthy endpoint.

---

## 6. Mitigations and residual risk

| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Device seized while **locked** | ChaCha20-Poly1305 at rest under a scrypt-wrapped DEK; contents and identity are ciphertext. | Offline guessing of a weak passphrase; future cryptographic breaks; the keyfile and ciphertext are in the adversary's hands for as long as they keep the device. |
| Device seized while **unlocked**, or passphrase **coerced** | Duress-safe open state hides case contents; passphrase rotation; recovery blob under an independent passphrase. | Not a guarantee against coercion or forensic imaging; an unlocked vault exposes plaintext; a compelled passphrase reveals everything. |
| Relay operator or its subpoena | Messages sealed to recipient keys before leaving the sender; no-log, self-hostable relay; pure peer-to-peer option removes the party entirely. | Connection **metadata** (who/when/how-much) is visible to any relay; only peer-to-peer sync avoids it. |
| Timestamp authority compromised, colluding, or subpoenaed | Authority sees only a SHA-256 hash; multiple authorities configurable; tokens verified offline against their certificate chain. | A single TSA could backdate or refuse; a hash leak still reveals nothing about contents; trust in *any one* TSA is reduced, not eliminated, by using several. |
| Evidence altered after capture | SHA-256 fixity re-checked on every read; append-only hash-linked custody; RFC 3161 upper-bound timestamps; standalone verifier. | Custody is tamper-*evident* only: a hostile keyholder can rewrite the whole local chain before any external anchor exists; detection needs a counterpart or a timestamp over the head. |
| Tenant location leaked through sharing | Originals sealed with EXIF intact; shared/exported copies strip location by default; the user is shown what a packet discloses before producing it. | User error or an out-of-band copy (a screenshot, a forwarded original) can still leak; stripping covers habitable's own outputs, not other apps. |
| Organizer identity exposed via exported records | Custody actor stored only as a salted commitment; exports drop actor, salt, and signature; clear identity stays in the vault. | The in-vault clear identity is exposed if the vault itself is compromised; correlation across packets or out-of-band knowledge can still re-identify. |
| Tracking via telemetry | No analytics, no telemetry, no phone-home; relay logs only aggregate counts. | Network-level observation (ISP, Wi-Fi operator) of *connections* is outside the app's control; use of Tor/VPN is the user's responsibility. |
| Lost access to data | Encrypted recovery blob; multi-peer sync replicates the case; encrypted backup. | No operator-side recovery: lost passphrase + no recovery blob + no surviving peer = permanent data loss, by design. |

---

## 7. Summary

habitable concentrates trust on the **device**, keeps the **relay** to ciphertext plus unavoidable
connection metadata, and shows the **timestamp authority** only a hash. It protects confidentiality
at rest, end-to-end encryption in sync, content and sequence tamper-evidence, location stripping,
and custody-identity minimization, with no telemetry. It does **not** protect against a hostile
keyholder rewriting the local chain before any external anchor, relay metadata, a coercing or
forensic adversary defeating the duress state, lost keys with no backup, or an endpoint that is
already compromised — and a timestamp proves only *when*, never *who* or *what*.

**This is alpha / concept-stage software. It must not be relied on for a real legal matter yet.**
When that changes, this document and the README will say so explicitly.
