<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Deep dive — current-state assessment (2026-07-01)

A current-state read of habitable from the source, not the prose. Every claim below
is grounded in a file I read; where I did not run the code, I say so.

## 1. Architecture as it actually is

The layering the [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md) describes is real and
enforced by the import graph, not just asserted:

- **Foundation** — `canonical.py` (deterministic JSON + hex SHA-256), `clock.py`
  (a hybrid logical clock giving a total `(wall_ms, counter, node_id)` order),
  `crypto.py` (ChaCha20-Poly1305 AEAD at rest, scrypt-wrapped DEK, Ed25519/X25519,
  an ECIES-style `seal_to`), `errors.py` (a typed exception hierarchy).
- **Evidence/model** — `evidence.py` (`verify_fixity` + an append-only, hash-linked
  `CustodyLog` with salted actor commitments), `exif.py`, `tsa.py` (a genuinely
  standards-shaped RFC 3161 implementation — issues real CMS `SignedData` tokens in
  `LocalRfc3161TSA`, verifies imprint/signature/cert-chain in `_verify_rfc3161_token`,
  handles RSA *and* ECDSA per the token's own algorithms), `model.py` (a state-based
  CRDT: `LWWRegister` + `ORSet` + `GrowLog`, with a commutative/associative/idempotent
  `merge`).
- **Vault/capture** — `vault.py` (one encrypted directory per case; every
  `read_original` re-checks fixity; AEAD associated data binds a sealed blob to
  `original:<capture_id>:<hash>`), `capture.py` (hash → seal → custody → now-or-deferred
  timestamp, never blocking on the network), `config.py` (plain-TOML policy).
- **Packet/verify** — `packet.py` (deterministic signed `bundle.json`,
  location-stripped shared copies, the privacy/verifiability binding via a signed
  `copied_for_sharing` custody entry), `pdf.py` + `htmlpacket.py` (presentation),
  `verify.py` (the Apache-2.0 island: imports only `canonical`, `crypto`, `evidence`,
  `tsa`, `errors`).
- **Sync/transport** — `sync.py` (signed-then-sealed CRDT messages;
  `LocalDirTransport` and `RelayClient`), `relay.py` (a stdlib-only ciphertext mailbox
  with `/livez`/`/readyz`/`/healthz` and opt-in metadata-only JSON access logs).
- **Entry points** — `cli.py` (`init/issue/capture/timeline/status/resolve/`
  `retimestamp/export/verify/sync/relay/app/key/demo`), `appserver.py` (a loopback
  JSON API holding the *unlocked* vault in memory), `demo.py`.

The verifier really is an island: `test_guards.py` shells out to prove the
Apache-2.0 subset imports without the AGPL modules, and even guards against a
Python-3.14-only `except` syntax (BUG-01) creeping back in. The determinism story
(`canonical_json`, injected clocks, HLC-stamped ids) holds up on inspection.

## 2. What is genuinely strong

- **The evidence spine is real, not a mock.** `tsa.py` builds and parses real RFC 3161
  CMS tokens and follows the token's own digest/signature algorithms — this is the hard
  part done properly. Archive re-timestamping (`retimestamp`, `verify_archive_chain`)
  and multi-authority redundancy (`additional_timestamps`) are both implemented and
  wired through `capture.py`, `vault.py`, `packet.py`, and `verify.py`.
- **Fail-closed verification.** `verify.py` treats every malformed input as a clean
  rejection: `_parse_bundle` catches invalid JSON *and* invalid UTF-8; `_verify_custody`
  wraps the whole walk in a broad catch and returns "broken," never a crash;
  `_check_packet_version` rejects newer-than-supported packets instead of mis-verifying.
  `test_verify_fuzz.py` enforces "never accept on tamper, never crash on hostile input"
  with Hypothesis.
- **Privacy-by-construction in the custody log.** `evidence.py` splits every entry into
  a hashed/exported `public_payload` (salted actor *commitment* only) and vault-only
  `actor`/`actor_salt`/`signature`/`private_details`. `redacted()` drops identity on
  export; `test_guards.py` proves a tenant's source filename and an importing peer's
  fingerprint never reach `bundle.json`.
- **Honesty discipline is load-bearing, not decorative.** The `disclosure.py` module is
  a single localized (EN/ES) source of the "what this packet proves / does not prove"
  framing, rendered into both HTML and PDF so they cannot drift; the threat model's §5
  ("what is NOT protected") is unusually candid, naming the hostile-keyholder gap, the
  relay-metadata gap, and the duress limit.
- **Accessibility + bilingual are gated, not aspirational.** CI runs an axe-core scan in
  EN and ES, structural/keyboard/320px-reflow tests, and mechanical i18n gates
  (UTF-8/BCP-47/key-parity). The app (`app.js`) is a dependency-free shell with an
  `aria-live` announcer and per-language dictionaries.

## 3. Structural debt and gaps I actually observed

These are net-new to the planning docs. They are grounded in specific code and are
developed as `FIX-##` in [`02-large-scale-fixes.md`](02-large-scale-fixes.md).

1. **The `node_id` is derived from the passphrase and then leaked in plaintext and in
   every packet.** `vault.py:99` computes
   `node_id = sha256_bytes(case_id.encode() + passphrase.encode())[:16]`, a single
   un-salted SHA-256. That `node_id` is written to the **plaintext** `config.toml`
   (`config.py` `default_config_toml`, whose own comment says "This file holds no
   secrets"), and — because every HLC stamp encodes it and every `capture_id`/
   `issue_id`/timeline id embeds the HLC — it is exported into `bundle.json`. The sample
   packet's `cap-001767312000006.000000.a561aba5562888f6` ends in exactly that value.
   Consequence: the vault passphrase is offline-brute-forceable against a *fast* hash
   both from a seized device and **from a packet handed to opposing counsel**, bypassing
   the scrypt KDF that is supposed to make guessing expensive. This is the single most
   serious finding of the pass (`FIX-01`).
2. **Sync is full-state, including every sealed original, on every exchange.**
   `sync.export_message` loops over *all* captures and base64-embeds every original's
   bytes each time; there is no delta. For a prepaid-data tenant or a long case this is
   O(total case size) per sync (`FIX-02`).
3. **The loopback app server has no authentication, and the mobile guide tells users to
   expose it.** `appserver.py` serves the unlocked vault's full API; `docs/mobile.md`
   instructs `habitable app --host 0.0.0.0` to reach it from a phone — putting an
   unauthenticated capture/export/status API on the LAN (`FIX-03`).
4. **The relay is an unauthenticated shared mailbox with a silent-eviction failure
   mode.** `relay.py` `RelayStore.post` does `queue.pop(0)` at
   `_MAX_MESSAGES_PER_ROOM = 10_000`; anyone who knows a room id can flood it and evict
   real pending ciphertext, and the store is in-memory so a restart drops undelivered
   messages (`FIX-04`).
5. **Export strips per-entry custody signatures; the bundle signature is
   self-certifying.** `evidence.redacted()` drops the Ed25519 signature on export, and
   `verify._verify_signature` trusts the `sign_public` embedded in the packet itself, so
   `signature_ok` proves internal consistency only — exactly opposing counsel's "how do
   I know the verifier isn't cooked / the packet wasn't rebuilt" attack (`FIX-05`).
6. **Offline captures never get timestamp redundancy.** `_try_timestamp` queues a single
   digest and `resolve_deferred` stamps against one authority — so the *most* at-risk
   items (captured in a dead zone, per persona P-06) rest on a single TSA, the opposite
   of the R-16 default the online path now enjoys (`FIX-06`).
7. **The CRDT has no per-field provenance or authorization.** `model.LWWRegister` means
   any synced peer can silently overwrite an issue's title/severity/status by winning on
   HLC, with no record of who changed what field (`FIX-07`).
8. **A documented safety feature does not exist in code.** README, `privacy.md`, and
   `threat-model.md` all describe a "duress-safe open state," but `grep` for
   `duress`/`panic`/`decoy` across `src/` and `app/` finds **nothing**. The claim is
   currently ahead of the implementation — a direct tension with the project's own
   honesty ethos (`FIX-14`).

Smaller but real: scrypt is tuned low (`n=2**15`) and not per-device upgradeable with no
DEK-rotation path (`FIX-08`); a packet that includes awaiting-timestamp items verifies as
"NOT intact" with no export-time warning (`FIX-09`); HLC ids leak device wall-clock ms
and internal event ordering into every packet (`FIX-10`); video is captured and sealed
but cannot be packetized or metadata-stripped, so packets silently omit video shared
copies (`FIX-11`); the app i18n has no pluralization/ICU and the CLI hardcodes "(s)"
(`FIX-12`); and the "debuggability under a debug flag" the README promises has no
local structured-log implementation yet (`FIX-13`).

## 4. Strategic position in the portfolio

habitable is the portfolio's **privacy-first, local-first, adversarial** exemplar — the
sibling that carries the civic-data projects' discipline on auditability, accessibility,
and honest limits into a setting where the threat model is a *person* (a retaliating
landlord), not a dataset. Its distinctive assets are transferable: the tamper-evidence
kernel (`evidence` + `tsa` + `verify` + `crypto`) is a reusable spine other civic tools
could adopt (developed as `EXP-13`), and its "prove, don't trust" verifier is a pattern
the whole portfolio can point to.

Its strategic risk is the mirror of its strength: it is **alpha and single-maintainer**,
and its v1.0 gate depends on things an engineer cannot self-serve — a real security/crypto
audit, a recorded assistive-technology pass, and a real tenant-union/legal-aid pilot
(currently scoped to California, deferred pending a real organization). The fixes below
matter precisely because the audit and the pilot are coming: `FIX-01` in particular is
the kind of finding an external cryptographic reviewer *will* raise, and it is far
cheaper to close now than to discover in a courtroom or an audit report.
