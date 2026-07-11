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
| Photos/video (sealed originals, incl. EXIF GPS + capture time) | Device vault `originals/` | Encrypted (ChaCha20-Poly1305) | Only at explicit action: sealed to a chosen sync/share peer; or in a packet as shared copies under the configured metadata policy and, with `--include-originals`, byte-exact originals with full metadata |
| Browser-upload / packet-sanitization working copy | Process memory, then a random OS temporary path **outside the vault** while a path-based media tool runs | Plaintext; short-lived; owner-only `0700` directory and `0600` file on POSIX | Habitable does not transmit this working file; local path-based tools process it. Removed on success and exceptions, but unlinking is not secure erasure and a compromised endpoint or tool can still expose it |
| Case document (issues, notes, timeline) | Device vault `case.enc` | Encrypted | Only via E2E-sealed sync to a peer the user chooses, or in an exported packet |
| Chain of custody (who did what, when) | Device vault `custody.enc` | Encrypted; each entry stores the clear actor, a random salt, its salted actor commitment, and a signature | Public packet proof **drops the clear actor, salt, and per-entry signature**, retains the salted actor commitment, and re-hashes the identity-stripped chain |
| Device identity / keys | Device vault `identity.enc`, `keyfile.json` | Encrypted (keyfile passphrase-wrapped) | Never |
| Primary, additional, and archive timestamp tokens (TSA name and token-embedded time) | Device vault `tokens/<sha256(capture_id)>.tokens.enc` | Consolidated per capture and AEAD-encrypted under the vault DEK | Yes, deliberately: sync and exported packets carry the unchanged public token records so a recipient can verify them |
| Configuration (including TSA names/URLs and user-edited peer, sharing, packet, or letter settings) | Device vault `config.toml` | **Plaintext policy** | Settings drive local/network behavior; configured packet/letter text may appear in an output the user creates |
| Sync messages | Relay mailbox (if used) | **Sealed to recipient's key** | Ciphertext only; relay cannot read |
| Content hash | RFC 3161 authority (if used) | SHA-256 imprint | Hash only; discloses nothing about contents |
| Aggregate commons summary (opt-in) | A file the union writes | **k-anonymous counts** by building label / category / coarse period | Only as a file the union **manually chooses to publish**; computed on-device, aggregate-only, no case/person linkage, and never transmitted by the tool (EXP-14, see [`commons.md`](commons.md)) |
| Operational data | — | — | **None.** No telemetry, no logs of users; relay keeps only aggregate ciphertext-passthrough counts |

## 4. Necessity, proportionality, and minimization

- **Sealed originals keep EXIF** (GPS, capture time) because that metadata is part of the
  evidentiary value of the original. It is held **encrypted at rest** and omitted from packets
  by default; `--include-originals` deliberately embeds its byte-exact contents and metadata.
- **Packet shared-media copies strip embedded metadata by default.** The signed packet records the
  configured handling and item-level transformation. Review those disclosures before handoff:
  a retention policy or embedded original can carry location. Sync and organizer sharing transfer
  sealed originals to the chosen peer and therefore carry their original metadata.
- **Custody minimization:** clear actors, salts, and per-entry signatures stay inside the encrypted
  vault. The public packet retains salted actor commitments in its identity-stripped proof, so a
  recipient can verify the chain without receiving the clear actor names.
- **No collection the tool does not need:** no contact lists, no location services beyond the
  photo's own EXIF, no usage analytics. The minimal-by-construction design means there is
  little personal data to mishandle in the first place.
- **No plaintext upload staging in the vault:** the browser and packet-sanitization paths use a
  random, restrictive OS temporary workspace outside the vault and remove it on all ordinary and
  exceptional exits. Older `_incoming` directories are removed when the app server starts without
  following a symlink.
- **Timestamp tokens are encrypted while local, public when shared:** local sidecars conceal the
  token, TSA name, and embedded generation time while the vault is locked. Their deterministic
  hashed filenames still link repeated observations of the same capture id; ciphertext length
  approximates token volume, and filesystem `mtime`/`ctime` reveal update timing to a storage
  observer. Sidecars do not pad contents or hide filesystem metadata. AEAD does not establish
  timestamp authenticity; packet recipients verify the token/imprint and an independently trusted
  authority chain. Legacy token JSON is encrypted and durably verified before unlinking, but unlink
  is not secure erasure of old filesystem blocks, snapshots, or backups.

## 5. Data-subject rights — how the design serves them

Because the controller holds all case contents locally and decrypts them only in memory (while
reviewable policy in `config.toml` remains plaintext):

- **Access & portability:** the user has the complete record on their own device and can
  export a self-contained, openly-verifiable packet at any time. The packet format and
  standalone Apache-2.0 verifier mean the data is not locked to this software.
- **Erasure:** deleting the vault (and any synced copies) removes the active application data;
  there is no operator copy to chase and no backup the user did not themselves make. This is not
  a physical-media sanitization claim: unlinked temporary blocks, swap, and filesystem snapshots
  follow the endpoint/storage platform's retention behavior.
- **Rectification:** the CRDT case model lets the user correct the working record, while the
  append-only custody chain preserves an honest, tamper-evident history of changes.
- **No automated decision-making or profiling** occurs.

## 6. Risks to data subjects and mitigations

This mirrors the [threat model](threat-model.md) §6; the residual risks are reproduced in the
frozen [audit baseline](audits/threat-model-baseline.md).

| Risk to the data subject | Mitigation | Residual risk |
| --- | --- | --- |
| Home address / identity leaked through an export | Packet shared-media copies strip embedded metadata by default; optional originals and configured metadata handling are named in the packet disclosure | Retaining packet metadata, embedding originals, sync/organizer sharing, taking a screenshot, or forwarding an original can reveal location or identity |
| Device seized | Vault encrypted at rest; passphrase rotation (a duress-safe open state is planned, not yet implemented) | A coerced passphrase or forensic imaging of an unlocked device defeats it |
| Timestamp metadata exposed from local storage | Primary/additional/archive records are consolidated into DEK-encrypted sidecars with filename-bound AEAD; legacy plaintext is removed only after durable encrypted publication | Stable hashed filenames leak equality/linkability and permit guesses; ciphertext length approximates token volume; filesystem `mtime`/`ctime` reveal update timing; there is no padding or metadata hiding; an unlocked endpoint and exports expose token/TSA/time contents; unlinking legacy JSON is not secure erasure |
| Temporary plaintext recovered from the endpoint | Random owner-only workspace outside the vault; generic names; partial-write and downstream-failure cleanup; legacy `_incoming` cleanup | Decoded bytes exist in memory and briefly in OS temp. `SIGKILL`/power loss can prevent cleanup, and unlink cannot defeat swap, snapshots, SSD remanence, privileged malware, or forensic recovery; use full-disk encryption on a trusted device |
| Organizer re-identified from an exported record | Public packet custody drops the clear actor, salt, and per-entry signature but retains the salted actor commitment | Commitment correlation across packets or out-of-band knowledge can still re-identify; a breached vault exposes the clear actor and salt |
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
