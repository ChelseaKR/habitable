# Privacy statement (DPIA-style)

> **Status: alpha / concept stage.** This is a Data-Protection-Impact-Assessment-style
> statement of how habitable handles personal data by design. It is not legal advice and
> not a certification. It is written in the structure of a DPIA (GDPR Art. 35 / ICO
> guidance) because the tool processes sensitive data about people in a position of
> vulnerability, and that deserves an honest, checkable account — see the
> [threat model](threat-model.md) for the adversarial analysis this complements.

## 1. Why this assessment exists

habitable helps tenants document habitability problems to use as evidence. That record
necessarily contains **sensitive personal data**: images of a person's home, their
address (via photo EXIF/GPS), a timeline of their housing situation, and — for organizers
— who is helping whom. The data subjects are often in an acute power imbalance with a
landlord who may retaliate. High-risk processing of this kind is exactly what a DPIA is
for, even though, as set out below, the project itself processes almost none of it.

## 2. Who processes what — roles

- **The project (the software and its maintainer) is not a data controller or processor
  of tenant data.** habitable is a tool that runs on the user's own device. It operates
  **no service that receives, stores, or sees** tenant personal data. There is no account
  system, no analytics, no telemetry, and no central database (README *Hard rules* #1, #5).
- **The union / tenant who runs habitable is the controller** of their own case data, and
  holds the only keys to it.
- **Optional network parties are deliberately blind:** a sync **relay** sees only
  ciphertext sealed to recipient keys plus unavoidable connection metadata, never contents;
  an **RFC 3161 timestamp authority** sees only a SHA-256 hash, never the file or any
  metadata. Neither is a processor of personal data in any readable form.

The practical consequence: **there is no operator who can be compelled to produce, or who
can accidentally leak, a tenant's data — because no operator holds it.**

> **Check it yourself.** The "relay sees ciphertext only" claim is externally demonstrable, not
> just asserted: run `habitable prove-no-plaintext` (a real sync through an in-process relay with a
> byte-for-byte wire capture you can `grep`), or capture a self-hosted relay with `tcpdump` — both
> are documented in [prove-no-plaintext.md](prove-no-plaintext.md). For your *own* case, `habitable
> status --xray` prints a local, telemetry-free per-component account of what each part would
> expose externally.

## 3. Data inventory and flows

| Data | Where it lives | Form | Leaves the device? |
| --- | --- | --- | --- |
| Photos/video (sealed originals, incl. EXIF GPS + capture time) | Device vault `originals/` | Encrypted (ChaCha20-Poly1305) | Only as **shared copies with location stripped** in an exported packet, at the user's explicit action |
| Case document (issues, notes, timeline) | Device vault `case.enc` | Encrypted | Only via E2E-sealed sync to a peer the user chooses, or in an exported packet |
| Chain of custody (who did what, when) | Device vault `custody.enc` | Encrypted; actor stored as a **salted commitment** | Exported form **drops the actor, salt, and signature** — the chain verifies without naming anyone |
| Device identity / keys | Device vault `identity.enc`, `keyfile.json` | Encrypted (keyfile passphrase-wrapped) | Never |
| Sync messages | Relay mailbox (if used) | **Sealed to recipient's key** | Ciphertext only; relay cannot read |
| Content hash | RFC 3161 authority (if used) | SHA-256 imprint | Hash only; discloses nothing about contents |
| Operational data | — | — | **None.** No telemetry, no logs of users; relay keeps only aggregate ciphertext-passthrough counts |

## 4. Necessity, proportionality, and minimization

- **Sealed originals keep EXIF** (GPS, capture time) because that metadata is part of the
  evidentiary value of the original. It is held **encrypted at rest** and is never the copy
  that gets shared.
- **Shared/exported copies strip location by default**, and the user is shown exactly what a
  packet discloses *before* it is produced. Disclosure is a deliberate, informed, per-export
  act — not a default.
- **Custody minimization:** organizer identities stay inside the union as salted commitments
  and are removed entirely from exports, so a recipient can verify integrity without learning
  who viewed or copied an item.
- **No collection the tool does not need:** no contact lists, no location services beyond the
  photo's own EXIF, no usage analytics. The minimal-by-construction design means there is
  little personal data to mishandle in the first place.

## 5. Data-subject rights — how the design serves them

Because the controller holds all the data locally and unencrypted only in memory:

- **Access & portability:** the user has the complete record on their own device and can
  export a self-contained, openly-verifiable packet at any time. The packet format and
  standalone Apache-2.0 verifier mean the data is not locked to this software.
- **Erasure:** deleting the vault (and any synced copies) destroys the data; there is no
  operator copy to chase. There is no backup the user did not themselves make.
- **Rectification:** the CRDT case model lets the user correct the working record, while the
  append-only custody chain preserves an honest, tamper-evident history of changes.
- **No automated decision-making or profiling** occurs.

## 6. Risks to data subjects and mitigations

This mirrors the [threat model](threat-model.md) §6; the residual risks are reproduced in the
frozen [audit baseline](audits/threat-model-baseline.md).

| Risk to the data subject | Mitigation | Residual risk |
| --- | --- | --- |
| Home address / identity leaked through a shared copy | Location stripped from shared/exported copies by default; pre-export disclosure summary | A screenshot or forwarded *original* taken outside habitable can still leak; stripping covers habitable's own outputs only |
| Device seized | Vault encrypted at rest; passphrase rotation; duress-safe open state | A coerced passphrase or forensic imaging of an unlocked device defeats it |
| Organizer re-identified from an exported record | Custody actor exported only as nothing (dropped); salted commitment in-vault | Correlation across packets or out-of-band knowledge can still re-identify; in-vault clear identity exposed if the vault itself is breached |
| Network party (relay/TSA) sees something | Relay gets ciphertext + metadata only; TSA gets a hash only; self-host / peer-to-peer options | Relay connection **metadata** is observable; only peer-to-peer removes it |
| Data loss harms the subject | Encrypted recovery blob; multi-peer sync replicates the case | No operator recovery: lost passphrase + no blob + no peer = permanent loss, by design |
| Endpoint compromised | Encryption assumes a clean, locked device | Malware/keylogger on an unlocked device defeats confidentiality entirely |

## 7. Residual risk and ownership

The project's deliberate choice is to **hold no personal data centrally**, which removes
whole categories of breach, subpoena, and secondary-use risk — at the cost of placing
recovery and endpoint security on the user/controller. The residual risks above are owned by
the controller (the union/tenant) and are stated plainly here and in the threat model so the
controller can make an informed choice. **Until the alpha caveat is removed, habitable must
not be relied on for a real matter**; this statement describes the design's privacy posture,
not a guarantee for live use.
