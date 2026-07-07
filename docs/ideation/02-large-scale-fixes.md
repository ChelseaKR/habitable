<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Large-scale fixes (2026-07-01)

Deep, structural fixes surfaced by reading the source. Each is **net-new** to
[`ROADMAP.md`](../../ROADMAP.md) and the `R-##` backlog in
[`docs/research/synthetic-personas-feedback.md`](../research/synthetic-personas-feedback.md);
where a fix sharpens an existing item, the ID is cited. Effort tiers: **S** (days),
**M** (1–2 weeks), **L** (weeks), **XL** (a month+ or needs external review).

Format per item: pitch · why it matters · shape of the work · effort · risks &
dependencies · what "excellent" looks like (a measurable bar).

---

## FIX-01 — Stop deriving `node_id` from the passphrase and leaking it

**Pitch.** The vault passphrase is currently offline-brute-forceable from plaintext on
a seized device *and* from a packet handed to opposing counsel; sever that link.

**Why it matters (impact, for whom).** This is the highest-severity finding of the
pass. `vault.py:99` sets `node_id = sha256_bytes(case_id + passphrase)[:16]` — a single,
un-salted, fast SHA-256. That `node_id` is written to the **plaintext** `config.toml`
(`config.py` `default_config_toml`) and, because every HLC stamp encodes it and every
`capture_id`/`issue_id`/timeline id embeds the HLC, it is exported into `bundle.json`
(confirmed: the sample packet's `cap-…a561aba5562888f6`). An adversary who seizes the
device, or the *literal modelled adversary* who receives a court packet, can compute
`sha256(case_id + guess)[:16]` at billions/sec and recover the passphrase — completely
bypassing the scrypt KDF that protects `keyfile.json`. This breaks README Hard Rule #1
and the threat-model §4 "confidentiality at rest" claim for anyone using a
human-memorable passphrase (which the design explicitly targets: "interactive unlock on
a phone"). It harms every tenant, and most acutely the maximum-retaliation personas
(P-04 Tobias, P-05 Priya).

**Shape of the work.** Make `node_id` a random 16-byte value generated at
`Vault.create`, independent of the passphrase, stored **inside** the encrypted vault
(not in `config.toml`). Separately, decide the packet-id policy with `FIX-10`: either
strip `node_id` from exported ids or replace HLC-in-id with an opaque per-case-salted id.
Touch points: `vault.py` (`create`), `config.py` (drop `node_id` from the plaintext
default and from `Config`), `clock.py`/`model.py` (id derivation), and a golden-packet
migration since ids change (guard with `packet_version` per `verify.SUPPORTED_PACKET_VERSION`).
Add a regression test in the spirit of `test_guards.py`:
`test_packet_ids_do_not_encode_passphrase_derived_material`.

**Effort.** L (crypto-adjacent, format migration, back-compat for existing vaults).

**Risks & dependencies.** Changing id derivation changes `bundle.json` bytes → a
`packet_version` bump and a golden-corpus update; existing vaults need a migration that
rewrites `config.toml` and re-keys the clock's node id without breaking the append-only
custody chain (the chain hashes `hlc`, so this must be a versioned, one-way migration).
Coupled to `FIX-10`. Should be reviewed by the pending external cryptographer.

**Excellent =** no value derivable from the passphrase appears in any plaintext file or
any exported artifact; a red-team script that brute-forces the sample packet's passphrase
today returns nothing after the fix; the guard test fails the build if the leak recurs.

---

## FIX-02 — Incremental sync deltas instead of full-state-plus-originals

**Pitch.** Every sync currently re-sends the entire case and every sealed original;
make sync transmit only what the peer lacks.

**Why it matters.** `sync.export_message` iterates *all* `vault.document.captures()` and
base64-embeds every original's bytes on each exchange. A 3-issue, 27-capture case
re-uploads all 27 photos every time two people sync. This is O(total case size) per sync,
punishing exactly the prepaid-data, dead-zone tenant (P-06 Marcus) and any month-long
campaign (P-07 Renee, 12 peers). It also inflates what a relay stores and forwards. R-18
(data-cost transparency) treats the symptom; this is the root cause.

**Shape of the work.** Add a "have" set exchange: the CRDT already gives a mergeable
state, so send a compact manifest of `capture_id → content_hash` the peer already holds
and transmit only missing originals; for state, send the full CRDT document (small) but
gate originals on need. Extend `Transport`/`RelayClient` with a lightweight
"advertise then request" step or keep it stateless by having the sender omit originals the
recipient can prove it has. Touch `sync.py` (`export_message`, `import_messages`, `sync`)
and add a size assertion to `tests/test_sync.py`.

**Effort.** L.

**Risks & dependencies.** Must preserve idempotency and the fixity re-check on import
(`store_original_bytes`). A naive "have" exchange leaks which items a peer holds to a
relay — keep the manifest inside the sealed envelope. Interacts with `FIX-04` (relay).

**Excellent =** re-syncing an unchanged case transfers < 5% of the bytes it does today
(asserted in a test); a second sync after adding one capture transfers ~one photo, not
the whole case.

---

## FIX-03 — Authenticate the loopback app server (and fix the mobile guidance)

**Pitch.** The unlocked-vault API has no auth, and `docs/mobile.md` tells users to bind
it to `0.0.0.0`; close that hole before a real pilot ships.

**Why it matters.** `appserver.py` serves `status/capture/export/resolve` over plain
HTTP with the vault held unlocked in memory and no credential of any kind. The default is
loopback, but `docs/mobile.md` explicitly instructs `habitable app --host 0.0.0.0` so a
phone can reach a laptop — which places a "read/write this tenant's whole case" API on
church-basement Wi-Fi (P-07's actual setting). Anyone on the LAN can capture, export, and
read case status. This directly enables the retaliation threat model over the network.

**Shape of the work.** Generate a per-session bearer token at `make_app_server`, print it
with the URL in `_cmd_app`, require it on every `/api/*` request, and set
`Access-Control` + a strict same-origin/host check. Prefer a QR/opaque-URL handoff for the
phone case over `0.0.0.0`; if remote binding is kept, force a token and warn loudly.
Rewrite the `docs/mobile.md` `0.0.0.0` step. Touch `appserver.py`, `cli.py` (`_cmd_app`),
`app/app.js` (attach the token), `docs/mobile.md`; add `tests/test_appserver.py` cases for
401-without-token.

**Effort.** M.

**Risks & dependencies.** Token in a URL can leak via history/referrer — use a header and
a short-lived token bound to the process. Must not break the PWA offline shell (the
service worker is network-only for `/api/`, so the token flow stays online-only, which is
correct).

**Excellent =** every `/api/*` call without the session token returns 401; the mobile
guide no longer recommends an unauthenticated `0.0.0.0` bind; a test proves an
unauthenticated LAN client cannot read case status.

---

## FIX-04 — Authenticated, durable relay rooms (eviction-proof, restart-safe)

**Pitch.** Make a relay room something only its peers can write to, and stop silently
dropping pending messages.

**Why it matters.** `relay.py` `RelayStore.post` does `queue.pop(0)` once a room hits
`_MAX_MESSAGES_PER_ROOM = 10_000`. Anyone who learns a room id (they travel as the sync
`channel`) can flood it and **evict the oldest — i.e. real, undelivered — ciphertext**, a
silent availability attack against a tenant's evidence sync. The store is in-memory, so a
relay restart also drops anything not yet fetched (fatal for async "post now, fetch next
week" use). This is distinct from the roadmapped metadata-resistance work (E-23/R-46) and
from padding/batching — it is about room authorization and durability.

**Shape of the work.** Add a per-room write capability: peers derive a room secret from
shared key material (they already exchange X25519 identities out of band) and present a
MAC/token on `post`; the relay verifies it without ever seeing plaintext. Add
opt-in disk persistence (append-only, size-capped) so a restart preserves undelivered
blobs, and switch eviction from silent `pop(0)` to explicit TTL + a `413` when a room is
full. Touch `relay.py` (`RelayStore`, handler), `sync.py` (`RelayClient` presents the
token), and `tests/test_relay.py`.

**Effort.** M.

**Risks & dependencies.** Must keep the relay dependency-free (stdlib only) and
metadata-minimal — the room token must not become a linkable identifier in logs (reuse the
`/rooms/{room}` redaction). Persistence adds an at-rest ciphertext store an operator must
handle; document it in `docs/relay-operator-self-audit.md`.

**Excellent =** a client without the room token cannot post; a flood attack cannot evict a
legitimate unfetched message (test); a relay restart with persistence enabled loses zero
undelivered blobs.

---

## FIX-05 — Bind packet authenticity to the custody chain (not a self-certifying key)

**Pitch.** Make `signature_ok` mean "this producer, tied to the custody chain, signed
this," not merely "this bundle is internally consistent."

**Why it matters.** On export, `evidence.redacted()` drops each custody entry's Ed25519
signature, and `verify._verify_signature` trusts the `sign_public` embedded *in the packet
itself*. So anyone can rebuild a modified bundle, sign it with a fresh key, set
`producer_fingerprint` to match, and the verifier reports `signature_ok = True`. This is
exactly opposing counsel's (P-11) "how do I know the verifier isn't cooked / the packet
wasn't reconstructed?" and it undercuts the whole "verify, don't trust" promise for a
*third-party* recipient. R-30/R-31 address the legal framing and cross-check procedure;
this is the underlying protocol gap.

**Shape of the work.** Keep verifiable per-entry custody signatures (or a single
signature over the custody head that binds the producer key to the chain), and have the
verifier check that the bundle-signing key is the same identity that signed the custody
chain — so a rebuilt packet with a new key fails unless the attacker also forged the whole
signed chain. Optionally support pinning a producer's public identity out of band (the
tenant's device fingerprint from `habitable id`) so a recipient who was given the
fingerprint can assert authorship. Touch `evidence.py` (export form), `packet.py`,
`verify.py`; extend `docs/verifier-decision-table.md` and `docs/bundle-schema.md` (with a
`packet_version` bump).

**Effort.** L.

**Risks & dependencies.** Re-introducing signatures to exports must not re-introduce
identity leakage — sign over commitments, not clear actors (preserve the `test_guards.py`
invariant). Format change → version bump + golden update. Best reviewed with `FIX-01` and
the external audit.

**Excellent =** a packet rebuilt/re-signed with a different key verifies as NOT authentic;
`docs/verifier-decision-table.md` gains a row distinguishing "internally consistent" from
"authored by the pinned producer."

---

## FIX-06 — Extend multi-TSA redundancy to offline/deferred captures

**Pitch.** Give the *most* at-risk items — captured with no signal — the same
multiple-authority proof the online path already gets.

**Why it matters.** R-16 made redundant stamping a default, but only for the online path:
`capture._try_timestamp` queues a **single** digest, and `resolve_deferred` stamps against
**one** authority. So a furnace photo taken in a dead zone (P-06) and resolved later rests
on a single TSA — precisely the item whose provenance a landlord will attack hardest.

**Shape of the work.** Carry the configured extra authorities through the deferred queue so
`resolve_deferred` stamps each queued item against all of them (mirroring
`_stamp_additional`), and have `retimestamp_all` also archive the additional tokens (today
it archives only `latest_token`). Touch `capture.py` (`resolve_deferred`,
`retimestamp_all`), `vault.py` (queue may need to remember the authority set),
`tests/test_packet_verify.py`.

**Effort.** S–M.

**Risks & dependencies.** Extra network calls on a metered connection — pair with a
Wi-Fi-only option (R-19) so redundancy does not cost a rationing tenant data.

**Excellent =** an item captured offline and later resolved carries ≥2 verified
authorities in `verified_authorities`, asserted by a test that captures offline then
resolves.

---

## FIX-07 — Per-field provenance and authorization in the CRDT

**Pitch.** Record *who* changed each issue field, and let a case decide whose edits win,
so a synced peer cannot silently rewrite the record.

**Why it matters.** `model.LWWRegister` resolves conflicts purely by HLC: any peer you
sync with can overwrite an issue's `title`, `severity`, or `status` and it simply wins,
with no attribution and no way to review it. In a 30-unit campaign (P-07) with 12 peers of
varying trust, that is both a correctness risk (accidental clobber) and an integrity risk
(a compromised or hostile peer edits the narrative). E-12 (co-custodian survivability) and
the roadmap's "merge/conflict surfacing" touch adjacent ground; neither adds provenance.

**Shape of the work.** Attach a signed provenance stamp (actor commitment + signature)
to each `LWWRegister` write, exposed as an on-device "history of this field" view; make
the read model able to prefer edits from a configured set of trusted device fingerprints
when concurrent. Touch `model.py` (register payload + merge tiebreak), `sync.py` (verify
provenance on merge), the app/CLI review surfaces. Keep it identity-minimizing on export.

**Effort.** L.

**Risks & dependencies.** CRDT merge must stay commutative/associative/idempotent — the
property tests in `tests/test_model.py`/`test_sync.py` are the guardrail. Do not turn this
into an account/authority system (invariant #3) — it is per-case, key-based, and local.

**Excellent =** the app can show "severity changed from high→low by device
`ab12-…` at `T`"; a property test proves provenance survives merge in any order.

---

## FIX-08 — Upgradeable KDF and a DEK-rotation path

**Pitch.** Make at-rest hardening adjustable per device and give the vault a way to rotate
the data key, not just the passphrase.

**Why it matters.** `crypto.KdfParams` defaults to `n=2**15` scrypt — defensible for a
phone in 2020, light for 2026, and *fixed*: there is no path to raise it as devices get
faster, and `rotate_passphrase` re-wraps the *same* DEK, so a suspected DEK compromise has
no remedy short of a new vault. (Note: until `FIX-01` lands, KDF strength is moot because
the plaintext `node_id` is a cheaper oracle — these two are a pair.)

**Shape of the work.** Version the keyfile's KDF params (already versioned:
`KEYFILE_VERSION`) and add a `key harden` command that re-derives under stronger scrypt
(or Argon2id, adding one well-reviewed dependency) and re-wraps. Add true DEK rotation:
generate a new DEK and re-encrypt vault blobs + sealed originals (expensive but bounded,
and rare). Touch `crypto.py`, `vault.py`, `cli.py` (`key` subcommands),
`docs/key-management.md`, `docs/crypto-spec.md`.

**Effort.** M.

**Risks & dependencies.** Argon2id adds a dependency the "small, auditable crypto"
principle must weigh; scrypt-parameter bumps avoid that. DEK rotation must re-check fixity
on every re-encrypt. Coordinate with the crypto audit (workstream A).

**Excellent =** `docs/crypto-spec.md` documents a device-tunable KDF cost with a bump
procedure; a `key rotate-dek` drill re-encrypts a sample vault and every item still
verifies.

---

## FIX-09 — Make awaiting-timestamp packets an explicit, honest state at export

**Pitch.** A packet containing un-timestamped items verifies as "NOT intact" — surface
and explain that at export instead of shipping a silently-degraded packet.

**Why it matters.** `ItemVerdict.ok` requires `timestamp_verified`, so any awaiting-item
makes `VerificationReport.ok` false. `packet.build_packet` and `_cmd_export` happily
produce such a packet with no warning; the tenant learns it "fails" only when a recipient
runs verify. For P-06 (offline for two weeks) this is a trap. R-17 asks to *document* the
integrity meaning of the gap; this is the export-time correctness/UX fix.

**Shape of the work.** At export, count awaiting items and either (a) warn + require a
`--allow-incomplete` flag, or (b) emit a distinct, honest status in the disclosure and
`bundle.json` (e.g. "N of M items are awaiting a trusted timestamp; the content hash still
anchors them at capture"), reusing the `disclosure.py` framing so HTML/PDF stay in sync.
Surface the same in the app export result. Touch `packet.py`, `disclosure.py`,
`cli.py` (`_cmd_export`), `appserver.py`, `app/app.js`.

**Effort.** S–M.

**Risks & dependencies.** Must not imply an awaiting item is worthless — the hash *does*
anchor content at capture; the copy has to say so precisely (coordinate with the
plain-language pass R-41).

**Excellent =** exporting with awaiting items prints a clear count and next step, and the
packet's own disclosure states the awaiting status in plain EN/ES; a test asserts the
warning fires.

---

## FIX-10 — Minimize the metadata a packet leaks through its identifiers

**Pitch.** Stop encoding device wall-clock time and node identity into every id that
ships in a packet.

**Why it matters.** Every `capture_id`/`issue_id`/timeline id is
`{wall_ms:015d}.{counter:06d}.{node_id}` (`clock.HLCTimestamp.encode`). A packet handed to
a court therefore discloses the exact device millisecond of every event and the internal
total ordering of the whole case — timing metadata a landlord's lawyer can mine, and (with
`FIX-01`) the passphrase-derived `node_id`. The evidentiary time is the *timestamp token*,
not the id, so the id needs none of this.

**Shape of the work.** Keep HLC for internal ordering/merge, but derive exported ids from
an opaque, per-case-salted mapping (e.g. HMAC(case-salt, hlc) truncated) so ids stay
stable and deterministic without leaking wall time or node id. Touch `model.py` (id
minting + read model), `packet.py`, and the golden corpus (`packet_version` bump). Natural
companion to `FIX-01`.

**Effort.** M.

**Risks & dependencies.** Ordering and idempotent merge must be preserved (property
tests). Format change → version bump. Do together with `FIX-01`/`FIX-05` to amortize one
migration.

**Excellent =** an exported id reveals neither device wall-clock time nor any
passphrase-derived value; internal merge/order tests still pass unchanged.

---

## FIX-11 — Resolve the half-supported video path

**Pitch.** habitable claims to capture "short video," but video cannot be put in a packet;
either finish the pipeline or refuse video honestly at capture.

**Why it matters.** `capture._MEDIA_TYPES` accepts `.mp4`/`.mov`, and such files are hashed
and sealed — but `packet._EXT_BY_TYPE` has no video entry, so `_build_item` produces
`shared_name=""`, no shared copy, and `verify` notes "no shared media included." A tenant
who documents a landlord's spoken threat or a running/failing appliance gets a capture that
silently cannot be shared, and `exif.make_shared_copy` cannot strip video metadata
(explicitly out of scope). This contradicts the README and the honesty ethos.

**Shape of the work.** Short term: refuse (or clearly flag) video at capture with an honest
message until stripping/packetizing exists. Longer term (see `EXP-07`): a real
audio/video pipeline with metadata handling. Touch `capture.py`, `packet.py`, `exif.py`,
README, `docs/evidence-method.md`.

**Effort.** M (honest-refusal is S; full pipeline is `EXP-07`).

**Risks & dependencies.** Video metadata stripping needs a dependency (e.g. ffmpeg) that
the "small footprint / low-end device" values must weigh. Depends on the strip decision in
`exif.py`.

**Excellent =** either video makes it into a packet as a metadata-stripped shared copy that
`verify` accepts, or capture refuses video with a plain-language reason and the README no
longer overclaims it.

---

## FIX-12 — Real pluralization and locale formatting (bilingual equity at scale)

**Pitch.** Move counts, plurals, dates, and numbers to a proper i18n mechanism so Spanish
(and future languages) is grammatically correct, not English-shaped.

**Why it matters.** The app dictionary (`app/i18n/en.json`, 94 keys) has label prefixes
like `issue_captures_count` but no plural rules, and the CLI hardcodes English "(s)"
(`_cmd_status`, `_cmd_export`). Spanish gender/number and date/number formatting are not
handled. Bilingual equity is a stated invariant (roadmap principle #7); "correct but
English-shaped" undercuts it, and RTL/text-expansion (R-48) will break layouts. This is
the repo-level i18n gap distinct from the roadmap's "languages beyond EN/ES."

**Shape of the work.** Adopt ICU MessageFormat-style plural/select in the app dictionary
(a tiny dependency-free formatter is feasible) and route CLI counts through a
locale-aware helper; add locale date/number formatting. Extend the mechanical i18n gates
(`scripts/check_i18n_parity.py`) to check plural-category parity. Touch `app/app.js`,
i18n JSONs, `cli.py`, `scripts/`.

**Effort.** M.

**Risks & dependencies.** Keep the app dependency-free (a hand-rolled minimal
plural/select is preferable to pulling a library). Sequence before onboarding more
languages (R-47/E-24) so contributors inherit the right mechanism.

**Excellent =** ES renders correct singular/plural and localized dates/numbers with no
"(s)" artifacts; a parity gate fails if a locale is missing a plural category.

---

## FIX-13 — Local, opt-in structured logging for debuggability

**Pitch.** Deliver the "trace a case from capture through custody under a debug flag" the
README promises, as opt-in, on-device, never-exfiltrated logs.

**Why it matters.** The README's *Observability/Debuggability* claims a debug trace, and
the roadmap notes "opt-in `--log-format json` is future work" for the Tier-C CLI surface —
so this is acknowledged but unbuilt. Without it, a maintainer diagnosing a sync/timestamp
failure (P-18, and any pilot support case) has no structured signal. The relay already has
a clean stdlib-JSON logging model (`relay._JsonFormatter`) to mirror.

**Shape of the work.** Add an opt-in `--log-format json` / `HABITABLE_LOG` to the CLI and
app server that emits metadata-only, plaintext-free structured lines for capture/sync/
export/verify steps, staying strictly on-device (the no-phone-home invariant). Reuse the
relay's formatter pattern. Touch `cli.py`, `capture.py`, `sync.py`, `appserver.py`; add a
"never logs plaintext/keys" guard test paralleling the relay's.

**Effort.** S–M.

**Risks & dependencies.** The log must be as disciplined as the relay's — a guard test
must prove no case contents, filenames, or key material ever reach it.

**Excellent =** a maintainer can reproduce a capture→custody→packet trace from a debug log
with zero plaintext or key material present, enforced by a test.

---

## FIX-14 — Reconcile the "duress-safe state" claim with the code (honesty gate)

**Pitch.** A documented safety feature does not exist in the source; either build it or
stop claiming it — the project's own ethos demands the reconciliation.

**Why it matters.** README, `docs/privacy.md`, and `docs/threat-model.md` all describe a
"duress-safe open state that hides case contents," and personas lean on it (P-04 Tobias).
But `grep` for `duress`/`panic`/`decoy` across `src/` and `app/` returns **nothing** — it
is not implemented. For a tool whose credibility rests on "say what it does not do," a
safety feature that exists only in prose is the most damaging possible kind of overclaim,
and it is exactly what an auditor (P-14) or a careful tenant will catch.

**Shape of the work.** Immediate (S): correct the docs to state the duress state is
*planned, not implemented*, so nothing overclaims. Then decide the real design (see
`EXP-15`): a limits-first "distress" model (e.g. a separate decoy vault under its own key)
with a red-team-reviewed threat analysis, or a documented decision not to build it. Touch
README, `docs/privacy.md`, `docs/threat-model.md` now; `EXP-15` for the build.

**Effort.** S to reconcile the docs; L to build the feature (`EXP-15`).

**Risks & dependencies.** Building duress badly is worse than not having it (a false sense
of safety can get someone hurt — the research "Requests we should decline" table already
warns against duress *guarantees*). The doc-reconciliation must ship first regardless.

**Excellent =** no document claims a safety capability the code lacks; if built, the
feature ships with an honest, red-team-reviewed statement of exactly what it can and cannot
stop, surfaced at the moment of use (R-15).
