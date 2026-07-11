<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Relay operator self-audit — verify and attest the relay logs nothing sensitive

> **For the relay self-hoster (persona P-19).** You are standing up the **optional**
> habitable sync relay for a union and you want to *prove to that union* — not just
> assert — that the box you run never sees note text, image bytes, or sender identity,
> and that it logs nothing it could later be subpoenaed for. This guide tells you
> exactly what the relay does and does not hold, gives you the data/log schema, and
> walks you through a self-audit you can run and show as evidence.
>
> Backlog item **R-45**. Companion to [`relay-deploy.md`](relay-deploy.md) (how to run
> it) and [`relay-observability-matrix.md`](relay-observability-matrix.md) (what an
> operator or a subpoena *can* still observe — the metadata). Read both: this document
> is about what the relay **stores and logs**; the matrix is about what it can
> **observe in passing**, which is a different and larger question.

---

## 1. First principle: the relay is optional and dumb

The relay is **not required**. Two peers can sync device-to-device with no server at
all — a shared directory, a USB stick, an AirDrop-style transfer
(`LocalDirTransport` in `src/habitable/sync.py`). Run a relay only when peers cannot
reach each other directly. Whatever you, the operator, can or cannot see, the strongest
mitigation always remains *"don't run a relay for this exchange."*

The relay itself (`src/habitable/relay.py`) is deliberately a dumb mailbox:
**ciphertext in, ciphertext out.** Every sync message is sealed to the recipient's
public key *before it ever leaves the sender* (`seal_to` in `crypto.py`, called from
`export_message` in `sync.py`), so the relay only stores opaque blobs per room and
hands them back. It holds no key that can open them.

---

## 2. What the relay actually stores — grounded in `relay.py`

This section describes the code as written, not an aspiration. The store is the
`RelayStore` dataclass in `src/habitable/relay.py`:

```python
@dataclass(slots=True)
class RelayStore:
    rooms: dict[str, list[tuple[float, bytes]]]  # room id -> [(store_ts, ciphertext)]
    tokens: dict[str, str]                       # room id -> bound write-capability token
    posted: int                                  # total POSTs accepted
    fetched: int                                 # total messages handed back on GET
    bytes_relayed: int                           # total bytes of ciphertext moved
    persist_dir: Path | None                     # opt-in on-disk journal; None = memory-only
    capacity_rejections: int                     # aggregate rejected size/cap writes
    journal_load_rejections: int                 # aggregate unsafe/invalid startup records
```

**It stores, in process memory only:**

| Held in memory | What it is | Sensitive? |
| --- | --- | --- |
| `rooms` keys | The **room id** chosen by the peers (the `--channel` value). 1–128 chars, `[A-Za-z0-9_-]`. | Metadata. Peer-chosen; opaque to the relay. See §6 and the observability matrix. |
| `rooms` values | Per room, a list of `(store_ts, ciphertext)` pairs: a coarse store timestamp (used only for TTL expiry — see §4.5) beside each **sealed ciphertext blob**. Fixed retained-state ceilings are 10,000 messages and 128 MiB per room, plus 4,096 rooms, 50,000 messages, and 512 MiB globally. Above-cap POSTs return **413**; nothing is silently displaced. | Ciphertext + a coarse per-message timestamp. The relay cannot open the blob. |
| `tokens` values | Per live room, the **write-capability token** bound on first use (see §4.4), 1–256 ASCII characters in `[A-Za-z0-9_-]`. Capacity and size checks complete before a new binding is committed. | Metadata capability; its ASCII grammar makes `hmac.compare_digest` total, and it is never logged. |
| passthrough / live-state / rejection counters | Accepted/fetched byte and message totals; current live rooms/messages/bytes; capacity and rejected-journal counts. | Aggregate metadata only. |

**Crucial facts about this storage:**

- **It is in-memory by default; on-disk persistence is opt-in.** With no `persist_dir`
  (the default, and what the shipped read-only container runs), `relay.py` never opens a
  file, never writes a database, and restarting the process **drops every undelivered
  message and resets every counter.** The relay is not a backup; peers simply re-sync
  (sync is idempotent — see `sync.py`). An operator can *opt in* to a best-effort at-rest
  **ciphertext** journal (`--persist-dir` / `HABITABLE_RELAY_PERSIST_DIR`); what that
  writes, and what it does not, is documented in §4.6. It is a bounded best-effort
  restart aid, not an fsync-backed delivery guarantee. Nothing touches disk unless you
  turn it on.
- **It stores no peer addresses and no sender identity.** The sender's identity rides
  *inside* the sealed envelope (`export_message` puts `sender`/`sig` inside the bytes
  handed to `seal_to`), so it is encrypted; the relay never extracts or records it. It
  does keep a coarse per-message **store timestamp**, used only to expire stale
  undelivered ciphertext (§4.5) — never a wall-clock log of who posted when to a log
  stream.
- **The blobs are opaque.** On `GET /rooms/<id>` the handler base64-encodes the stored
  bytes and returns them; it never parses, decodes, or inspects their structure.

> **Honest caveat — memory is still memory.** "In memory, not on disk" is a property of
> the application code, not a hardware guarantee. While the process runs, the ciphertext
> blobs and the room ids are in RAM and could be read by a process memory dump, a core
> dump, or swap if the host swaps memory to disk. This is *ciphertext and room
> metadata*, never plaintext — but if you are attesting to a high-risk union, disable
> swap on the host (or run with swap encrypted) and avoid writing core dumps. In its
> default mode the relay code does not, by itself, persist anything to disk; the only way
> it writes an at-rest store is the opt-in `persist_dir` you enable deliberately (§4.6).

> **Memory cap is not RSS.** The 512 MiB ceiling covers ciphertext retained in
> `RelayStore`. One handler can additionally hold a request body up to 128 MiB, and the
> process also needs Python objects, threads, socket buffers, and runtime overhead. GET
> responses are length-counted and base64-streamed in 48 KiB chunks, so a full room no
> longer creates a second ~171 MiB encoded list plus a complete JSON body. Journal startup
> streams bounded lines but can temporarily hold one encoded record and its decoded bytes.
> Budget headroom and configure reverse-proxy concurrency/body-rate limits; this code does
> not claim that whole-process RSS equals the retained-state cap.

---

## 3. What the relay does NOT store or log

- **No request logging by default.** Python's `BaseHTTPRequestHandler` normally prints
  a request line (`"GET /rooms/... 200"`) to stderr for every request. The relay
  **suppresses this** by overriding `log_message` to a no-op (`relay.py`):

  ```python
  # Don't write BaseHTTPRequestHandler's ad-hoc request lines to stderr; the
  # relay does its own structured, metadata-only logging instead.
  def log_message(self, _format: str, *_args: object) -> None:
      return
  ```

  So out of the box the relay does **not** emit normal per-request log lines, peer IPs,
  room ids, or sizes to its own logs. The stdlib's separate handler-error path is also
  overridden: expected resets/broken pipes are silent instead of attacker-amplifiable,
  while an unexpected handler fault emits only the fixed metadata-only event
  `relay request handler failed`. A structured,
  **metadata-only** per-request access log remains **opt-in and off by default**
  (`HABITABLE_RELAY_LOG=json`); see §4.3 for exactly what is emitted.

- **No contents, ever.** No note text, no image bytes (raw or base64), no sender
  fingerprint. These never reach the relay in cleartext; they are inside the sealed
  box. See the guard tests in §5.

- **No accounts, no auth database, no central record.** There is no login, no user
  table, and no per-*peer* identity state. The only authorization state is a per-*room*
  write-capability token bound trust-on-first-use (§4.4) — a room→token map, not a user
  directory, and never an identity the relay can link to a person. Forking or
  self-hosting changes nothing about who can *read* the data: still only the keyholders.

- **The only thing it exposes about itself is `/healthz`**, which returns:

  ```json
  {"status":"ok","rooms":0,"live_messages":0,"live_ciphertext_bytes":0,
   "posted":0,"fetched":0,"bytes_relayed":0,"capacity_rejections":0,
   "journal_load_rejections":0}
  ```

  That is the *entire* observable summary — aggregate retained-state, traffic, and
  rejection integers plus a status. It contains no room ids, journal paths, tokens, or
  contents. `tests/test_relay.py::test_healthz_exposes_only_aggregate_counts`
  pins exactly this: it posts to a room named `room-SECRETNAME-123` with a
  `SECRET-CIPHERTEXT-PAYLOAD` body and asserts neither the room name nor the payload
  appears anywhere in the `/healthz` response.

---

## 4. The documented data / log schema (what to attest)

This is the complete schema you can hand the union. Every field is either **ciphertext**
or **aggregate metadata** — never plaintext contents.

### 4.1 In-memory store (`RelayStore`)

| Field | Type | Contents | Persistence |
| --- | --- | --- | --- |
| `rooms[<room_id>]` | list of `(store_ts, bytes)` | Sealed ciphertext blobs, opaque to the relay, each with a coarse store timestamp for TTL expiry | RAM by default; capped at 10,000 messages / 128 MiB per room and 4,096 rooms / 50,000 messages / 512 MiB globally (over-cap → 413, no silent eviction); dropped on restart unless persistence is on (§4.6) |
| `tokens[<room_id>]` | `str` (`[A-Za-z0-9_-]{1,256}`) | Write-capability token bound on first accepted use (§4.4) | RAM by default; a rejected size/capacity check never claims a new token; persisted with live messages when persistence is on |
| `posted` | `int` | Count of accepted POSTs | RAM only; reset on restart |
| `fetched` | `int` | Count of messages handed back | RAM only; reset on restart |
| `bytes_relayed` | `int` | Total ciphertext bytes moved | RAM only; reset on restart |
| live-state / rejection metrics | `int` | Current live messages/bytes and aggregate capacity/journal-load rejections | RAM only; reset on restart |

Room ids are the keys; the **count** of rooms (`len(self.rooms)`) is exposed via
`/healthz`, but the room **ids themselves are never serialized out** by any handler
(and, when persistence is on, never used as an on-disk *filename* — the journal file is
named by the SHA-256 of the room id; §4.6).

### 4.2 HTTP surface (the only network-observable schema)

| Route | Method | Request body | Response body | Stores / logs |
| --- | --- | --- | --- | --- |
| `/rooms/<id>` | POST | raw sealed bytes (≤ 128 MiB, `_MAX_BODY`); requires exactly one ≤9-digit ASCII-digits-only `Content-Length` and one `X-Habitable-Room-Token` (§4.4) | `{"status": "stored"}` | Rejects duplicate/transfer-encoded/nondigit/overlong framing before integer conversion, validates exact body length, verifies the existing token, checks all caps atomically, then binds a first token/appends/increments counts |
| `/rooms/<id>` | POST (bad token) | — | `403 {"error":"room token mismatch"}` (or `"room write requires a token"`) | Nothing stored |
| `/rooms/<id>` | POST (room/relay/size cap) | — | `413` with fixed `room full`, `relay full`, or `message too large` vocabulary | Candidate room/token/message is not stored; earlier messages are **not** evicted. A bounded TTL-only cleanup sweep may reclaim expired rooms before a global decision. |
| `/rooms/<id>` | GET | — | `{"messages": [<base64 blob>, ...]}` | Increments `fetched`; expires stale messages lazily; returns stored ciphertext unchanged and **does not clear it**. JSON/base64 is streamed in bounded chunks with an exact length. |
| `/healthz` | GET | — | status plus aggregate retained-state, passthrough, and rejection counts | Nothing |
| anything else | any | — | `{"error":"not found"}` (404) / `413` on bad/oversized body | Nothing |

Reads (`GET`) are **not** token-gated: the room's contents are already sealed
end-to-end, so a fetch reveals only ciphertext. The token gates **writes**, which is
what stops an unrelated party from claiming or scribbling into a room (§4.4).

### 4.3 Application logs

**Structured JSON, metadata-only, and free of request lines by default.** The relay
logs through the Python standard-library `logging` module (no third-party logging
dependency), emitting one JSON object per line. There are four kinds of line:

- **Lifecycle lines — always emitted.** One at startup and one at shutdown. The
  startup line (`serve()` in `relay.py`) carries only the bind host/port you
  configured and nothing about any peer or message:

  ```json
  {"ts":"2026-01-02T00:00:00+00:00","level":"info","msg":"relay listening (ciphertext passthrough only)","host":"0.0.0.0","port":8787,"access_log":false,"persist":false}
  ```

  The startup line logs only *whether* persistence is on (`"persist":true|false`), never
  the `persist_dir` path itself.

- **Bounded-startup warning — only when a journal record/path is rejected.** One aggregate
  warning may report `journal_load_rejections: N`. It carries no filename, room id, token,
  timestamp, or body and is not emitted once per hostile line, so malformed persistence
  input cannot create a content-bearing log or an unbounded log storm.

- **Handler-failure line — fixed metadata only.** If an expected client reset, abort, or
  broken pipe reaches `ThreadingHTTPServer.handle_error`, the relay emits nothing; these
  unauthenticated faults cannot amplify logs. An unexpected handler fault emits exactly
  `ts`, `level`, and fixed `msg: "relay request handler failed"`. The override never
  delegates to the stdlib implementation, so no peer IP/port, exception class/text,
  traceback, room, token, or request body reaches stderr. The fixed unexpected-fault line
  can appear even when access logging is off; it contains no request-derived value.

- **Per-request access lines — opt-in and OFF by default.** `log_message` is a no-op
  (§3), so `BaseHTTPRequestHandler`'s own request lines stay suppressed. A structured
  access line is emitted per request **only** when you set `HABITABLE_RELAY_LOG=json`.
  When enabled, each line carries **only metadata** — a random per-request id, the
  HTTP method, a **redacted** route (`/rooms/{room}`, **never** the actual room id),
  the response status, and the latency in milliseconds. It **never** contains peer IP
  addresses, room ids, message contents, **or the room write-capability token**
  (the token is compared with `hmac.compare_digest` and never serialized into a log or
  error body), and the health probes (`/livez`, `/readyz`, `/healthz`) are excluded from
  it. Leave it off (the default) to preserve the "no request lines" property this audit
  attests; the guarantee that no room id, IP, token, or content ever reaches the logs
  holds whether it is on or off.
  `tests/test_relay.py::test_access_log_never_leaks_the_room_write_token` pins that the
  token never appears in a captured log stream.

### 4.4 Room write capability (trust-on-first-use token)

Writes to a room are gated by a **write-capability token**. Peers already agree on the
room id (the `--channel` value), so both sides deterministically derive the same token
from it — `sha256("habitable room token v1:" + channel)` in `RelayClient` — and send it
in the `X-Habitable-Room-Token` header on every POST. The relay **binds the first token
it sees for a room** (trust-on-first-use) and thereafter rejects any POST whose token
does not match (`hmac.compare_digest`) with **403**; a POST with no token is likewise
rejected. This replaces the previous "any anonymous client may write to any room id"
behavior: a room, once claimed, can only be written by a peer presenting the matching
token. Every admission path (HTTP/direct post, explicit constructor state, and journal
startup) enforces `[A-Za-z0-9_-]{1,256}` before `hmac.compare_digest`, so a non-ASCII
first-use value cannot bind and later crash comparison.

Honest scope, so you can attest accurately: because the token is *derived from the room
id*, it defends against **accidental cross-talk and casual room-squatting by a party who
does not know the room id**, and it binds a room to the first key that claims it. It is
**not** a secret-based defense against an adversary who already knows the room id — such
a party can derive the same token. That is an acceptable, documented trade for a
self-contained, stdlib-only relay; the real confidentiality guarantee remains the
end-to-end sealing (§5), not this token. The interface (an opaque header compared with
`hmac.compare_digest`) leaves room to swap in a shared-secret HMAC later without changing
the relay's contract.

The binding is live-state scoped: when TTL cleanup removes a room's last message, it
removes that room's token too. A later accepted POST can therefore bind the now-empty
room again. This keeps token memory under the same 4,096-room cap and matches restart
behavior (a journal with no fresh message restores no token). With TTL disabled, the
message and binding remain until restart; a different token still receives 403.

### 4.5 Message TTL and explicit capacity rejection (413)

- **TTL.** Each stored message carries a coarse store timestamp, and undelivered
  ciphertext older than `_MESSAGE_TTL_SECONDS` (default **30 days**) is expired
  **lazily** — dropped the next time a post or fetch touches that room, so the relay
  does not accumulate stale ciphertext indefinitely. Tune it with the
  **`HABITABLE_RELAY_TTL_SECONDS`** environment variable (a non-positive value disables
  expiry). Shorter TTL = less at-rest ciphertext retained; pick a value that still lets
  your peers reconnect and drain their rooms.
- **Clock-skew bound.** A persisted store timestamp more than **five minutes ahead** of
  startup's finite clock is skipped and counted as invalid. The boundary permits a small
  host-clock correction without allowing an attacker-authored far-future record to pin a
  room token or retained capacity indefinitely; an accepted boundary record still expires
  under the normal TTL.
- **Bounded global reclaim.** If a new POST would hit a global cap, the store sweeps all
  retained rooms for TTL-expired messages under the same lock, then recomputes capacity.
  That sweep is itself bounded by 4,096 rooms / 50,000 messages and prevents stale rooms
  whose ids no caller remembers from deadlocking the relay. It may remove expired
  room/token state even if the candidate still receives 413; it never binds the candidate.
- **No silent eviction.** The fixed ceilings are 10,000 messages / 128 MiB per room and
  4,096 rooms / 50,000 messages / 512 MiB globally. Crossing one returns **413** with
  fixed `room full`, `relay full`, or `message too large` vocabulary instead of deleting
  an unexpired message. GET is intentionally non-destructive, so fetching does not make
  room capacity disappear; peers can wait for the documented TTL/retry or use a new
  deployment after the operator deliberately changes retention/capacity policy.

### 4.6 Opt-in on-disk persistence (the at-rest ciphertext store)

By default the relay writes nothing to disk. If you set **`--persist-dir PATH`** (CLI) or
**`HABITABLE_RELAY_PERSIST_DIR=PATH`** (env), the relay keeps a compactable,
at-rest ciphertext JSONL journal as a **best-effort restart aid**. Attest to it precisely:

- **One file per room, named by a hash — not the room id.** Each room's journal is
  `sha256(<room id>).hexdigest() + ".jsonl"`, so a **raw room id never becomes a
  filename** on disk. (`tests/test_relay.py::test_raw_room_id_never_becomes_a_filename`
  pins this.)
- **What each line contains.** One JSON object per accepted message:
  `{"room": "<room id>", "token": "<write token>", "ts": <store_ts>, "blob": "<base64
  ciphertext>"}`. So the *contents* of the file are exactly what the relay already holds
  in RAM — **ciphertext, the room id, its write token, and a coarse timestamp** — and
  **never** plaintext, image bytes, keys, or sender identity (those are inside the sealed
  blob). Enabling persistence writes the room id and token *to disk* where in the default
  mode they lived only in RAM; that is the whole trade-off, and it is why persistence is
  off unless you choose it.
- **Bounded append and compaction.** A room's journal is capped at 256 MiB. Before an
  append would cross that cap, a random owner-only temporary file is written from the
  current TTL-filtered live queue and atomically replaces the journal. No append silently
  evicts a live message, and the on-disk path is never intentionally grown past the cap.
  If an earlier interrupted `os.write` left a non-newline tail, the next POST does not
  concatenate another record onto it: after identity-checked open, the relay atomically
  compacts the complete current live queue before acknowledging that POST.
  Any post/fetch TTL cleanup also compacts promptly; when no live message/token remains,
  identity-verified non-following cleanup removes the canonical journal instead of leaving
  unbounded empty files behind.
- **Bounded crash-temp cleanup.** Compaction uses only exact app-owned names matching
  `.habitable-relay-[0-9a-f]{32}.tmp`. Before journal admission, startup may identity-check
  and non-followingly remove at most 128 regular remnants. That is a separate allowance:
  cleanup may traverse up to 8,192 non-temp entries **plus** 128 exact temp entries, so a
  temp after the ordinary-entry boundary is not order-stranded. A 129th exact temp or an
  over-limit non-temp scan fails closed before any journal loads; near-match names and
  nonregular paths are not removed.
- **Bounded, non-following startup.** After temp cleanup, startup examines at most 8,192
  directory entries
  and reads at most 20,000 physical lines per journal, 200,000 lines / 1 GiB in total,
  considers only canonical 64-hex `.jsonl` regular files, opens with non-following and
  nonblocking flags where the OS provides them, confirms the opened descriptor is regular,
  and refuses an oversized file/line. Symlinks and FIFOs are never followed or blocking-read.
  Lines are streamed, not loaded with `read_text()`. JSON structure, 1–128-character room
  syntax, canonical room-hash filename, live-token grammar/consistency, finite timestamp within
  the five-minute future-skew window, strict base64, TTL, per-room caps, and global caps are
  checked before a staged record can bind a token or enter live state. A malformed record is
  skipped and counted; valid records for one room/token elsewhere in that same journal may
  still load, but the mixed source file is left untouched rather than compacted. Expired records
  are eligible for pruning but do not establish or conflict with the staged live TOFU token; this
  permits a post-TTL rebind even if an earlier unlink transiently failed. Noncanonical paths are
  not opened, while a live-room/token-ambiguous or over-cap journal is refused as a unit, left
  untouched, and counted; ambiguous live tokens never win by file iteration order. After a completely valid load, expired
  lines are compacted away before startup completes; a stale-only, zero-byte, or blank-only
  canonical journal is identity-checked and removed. This prevents repeated clean restarts
  from accumulating expired lines ahead of a newer live append.
- **Honest durability limit.** Appends are not fsynced and there is no acknowledgement
  protocol with the host storage device. A process/host/storage failure can lose the most
  recent accepted append or leave a malformed partial record. Startup skips and counts
  that record, may load earlier valid same-room/same-token records, and leaves the mixed source
  journal untouched. If the process survives the interrupted append, a later retry repairs
  the tail as described above; it cannot recover state lost with process memory. Compaction
  uses atomic rename on the configured filesystem but is not a transactional database.
  A crash can leave an exact temp containing room/token/time/ciphertext until bounded startup
  cleanup runs. Unlinking a journal or temp is ordinary cleanup, **not secure erasure** from
  snapshots, remanence, or storage forensics. POSIX cleanup keeps the verified descriptor open;
  Windows closes it, rechecks device/inode/size/mtime/ctime, then unlinks because Windows rejects
  unlinking an open file. That fallback assumes a single local relay writer per persistence
  directory, and a dedicated Windows CI lane remains out of scope. Peers must retain/retry their
  sealed sync delta; do not describe this option as guaranteed delivery or a backup.
  (`tests/test_relay.py::TestPersistence` pins round-trip, TTL/future-skew behavior, caps,
  strict decoding, noncanonical/token conflict rejection, generation swaps, symlink/FIFO
  behavior, interrupted-append recovery, bounded crash-temp cleanup, Windows fallback, and
  bounded compaction.)

If you enable persistence for a high-risk union, give exactly one local relay process ownership
of the `persist_dir` and treat it like any at-rest ciphertext store: put it on an encrypted
volume, restrict its permissions, and include it in your retention story (the TTL bounds how
long undelivered ciphertext remains **eligible** for retention; lazy expiry is enforced on a
room touch, a prospective global-cap sweep, or startup, so physical state/journals can linger
until one of those events, and crash remnants last until cleanup).
The shipped read-only container does **not** enable persistence; to use it you must mount a
writable volume and set the env var deliberately.

---

## 5. The invariant the project itself tests (your strongest evidence)

You do not have to take the prose above on faith — the test suite pins the
ciphertext-only property. Cite these to the union; they are the project's own guard
tests, runnable by anyone who clones the repo.

- **`tests/test_sync.py::test_relay_sync_is_end_to_end_encrypted`** — runs a real sync
  through a real relay store, then asserts that **none** of these plaintext markers
  appears in any stored blob *or* in the base64 the relay's GET handler serves back:
  the note text, the raw original image bytes, the base64 form of the image bytes, and
  **the sender's own identity fingerprint**. (The marker list is `_no_content_markers`
  in that file.) This is the direct, executable statement of "ciphertext in, ciphertext
  out — including hiding sender identity."

- **`tests/test_sync.py::test_localdir_mailbox_holds_only_ciphertext`** — the same
  marker check against an on-disk mailbox (the no-relay `LocalDirTransport` path), so
  the no-plaintext property holds whether or not a relay is used.

- **`tests/test_relay.py::test_healthz_exposes_only_aggregate_counts`** — pins that
  `/healthz` leaks no room ids and no message contents, only aggregate retained-state,
  traffic, and rejection counts.

> **A precise note for accuracy.** `tests/test_guards.py` exists, but it guards a
> *different* invariant — that an exported **packet/bundle** drops the source filename
> and the importing peer's custody-actor identity. The no-plaintext-to-a-relay invariant
> lives in `tests/test_sync.py` as named above. If you are pointing the union at "the
> guard test," point them at `test_sync.py` for the relay claim.

Run the relevant guards yourself:

```console
$ uv run pytest tests/test_sync.py::test_relay_sync_is_end_to_end_encrypted \
    tests/test_sync.py::test_localdir_mailbox_holds_only_ciphertext \
    tests/test_relay.py -q
```

A green run is evidence you can attach to your attestation.

---

## 6. Step-by-step self-audit procedure

Run this against the relay you actually operate, capture the output, and keep it as the
evidence packet you show the union. The point is reproducibility: anyone can re-run it.

### Step 0 — Record what you are running

Record the exact image/commit and how it is launched. With the shipped container, the
hardened defaults are already in `relay/docker-compose.yml` (read-only filesystem,
`cap_drop: ALL`, `no-new-privileges`, non-root uid 10001, pinned base digest) and
`relay/Dockerfile`. Note the image digest:

```console
$ docker inspect --format '{{.Image}}' habitable-relay
$ git -C <repo> rev-parse HEAD
```

### Step 1 — Confirm no application request logging

With access logging left at its default (off — do **not** set `HABITABLE_RELAY_LOG`),
drive a request and show the container logs contain no request lines or peer data:

```console
$ curl -s http://localhost:8787/healthz >/dev/null
$ curl -s -X POST --data-binary 'AUDIT-PROBE-PLAINTEXT' \
    http://localhost:8787/rooms/audit-probe-room
$ docker logs habitable-relay
# Expect ONLY the structured JSON startup line, e.g.:
#   {"ts":"...","level":"info","msg":"relay listening (ciphertext passthrough only)",
#    "host":"0.0.0.0","port":8787,"access_log":false}
# Expect NO per-request lines, NO IPs, NO "audit-probe-room", NO "AUDIT-PROBE-PLAINTEXT".
```

If you deliberately enable access logging (`HABITABLE_RELAY_LOG=json`), you will see one
`{"msg":"request",...}` line per request — but still only metadata: method, status,
latency, a random request id, and the **redacted** route `/rooms/{room}` (never the room
id `audit-probe-room`), and never `AUDIT-PROBE-PLAINTEXT`.

If you put a reverse proxy in front (you should, for TLS — see `relay-deploy.md`), audit
**that proxy's** access/error logs too: by default nginx/Caddy/Traefik log client IPs,
request paths (which include the room id), and sizes. That log, not the relay, is where
metadata leaks accumulate — turn it off or minimize it (§7).

### Step 2 — Confirm `/healthz` exposes only aggregate counts

```console
$ curl -s http://localhost:8787/healthz
{"status":"ok","rooms":1,"live_messages":1,"live_ciphertext_bytes":21,
 "posted":1,"fetched":0,"bytes_relayed":21,"capacity_rejections":0,
 "journal_load_rejections":0}
```

Confirm the response contains aggregate counters and `status` only — no room id
(`audit-probe-room` must not appear), token, journal path, or body content.

### Step 3 — Confirm the relay cannot read what it forwards

Optional but persuasive: post known-plaintext to a room, fetch it back, and show the
relay treated it as an opaque blob (it round-trips byte-for-byte and is never parsed).
This demonstrates the *passthrough* behavior. The real end-to-end-encryption guarantee
is established by the senders sealing before posting (Step 5), not by the relay.

### Step 4 — Confirm persistence is off (memory-only mode)

Persistence is **opt-in** (§4.6). To attest the memory-only mode, first confirm the
persistence env var is unset and no `--persist-dir` was passed, then show state resets:

```console
# No persistence configured (expect empty output):
$ docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' habitable-relay \
    | grep HABITABLE_RELAY_PERSIST_DIR
# The shipped compose file runs the container read-only; show it:
$ docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' habitable-relay   # -> true
# Show the relay writes no data files of its own:
$ docker diff habitable-relay   # expect no added/changed files under the app dir
# Restart and show state is gone (proving memory-only storage):
$ docker restart habitable-relay
$ curl -s http://localhost:8787/healthz   # live state and passthrough counters back to 0
```

A reset-to-zero after restart is direct evidence the relay persists nothing in this mode.
If you *deliberately* enabled persistence, this step will instead show the journal
directory and may show accepted state restored after a clean restart — attest to that
best-effort mode using §4.6, and disclose the encrypted-at-rest handling of the
`persist_dir` plus its non-fsync durability limit.

### Step 5 — Confirm the end-to-end-encryption invariant holds in the code you run

Run the guard tests from §5 against the same source tree the relay image was built from:

```console
$ uv run pytest tests/test_sync.py::test_relay_sync_is_end_to_end_encrypted \
    tests/test_relay.py::test_healthz_exposes_only_aggregate_counts -q
```

### Step 6 — Write the attestation

Assemble: the recorded image digest + commit (Step 0); the `docker logs` output showing
only the startup line (Step 1); the `/healthz` body (Step 2); the read-only/`docker
diff`/restart-resets-state evidence (Step 4); and the green guard-test run (Step 5). A
short signed statement to the union can then say, truthfully:

> *"This relay, running image `<digest>` from commit `<sha>` with on-disk persistence
> disabled, stores only opaque ciphertext blobs, per-room write tokens, and aggregate
> counters in memory under fixed aggregate/per-room caps; it persists nothing to disk;
> it writes no request logs; its `/healthz` exposes only aggregate counts; room writes
> are gated by a capability token
> (never logged); and the project's own guard tests confirm note text, image bytes, and
> sender identity never reach it. It can still observe connection metadata — see the
> observability matrix — which I have disclosed separately and have not tried to hide."*

The last sentence matters: an honest attestation names the residual metadata exposure
rather than overstating the relay as a black box. See
[`relay-observability-matrix.md`](relay-observability-matrix.md).

---

## 7. Running no-log / minimal-retention

The relay is already no-log and minimal-retention by default. To keep it that way:

- **Don't add request logging back.** Leave `log_message` as the no-op it is; don't
  patch in access logs "for debugging." If you must debug, do it transiently and
  off-production.
- **Minimize the reverse proxy's logs.** TLS is terminated at a proxy in front of
  `:8787` (the client refuses non-HTTP(S) relay URLs but adds no TLS itself). The proxy
  is the most likely place to accumulate IPs, room ids (in the path), timestamps, and
  sizes. Configure it to **not** log access lines, or to drop the request path and
  client IP. Treat the proxy config as part of your audit (Step 1).
- **Memory hygiene for high-risk unions.** Disable swap or use encrypted swap; disable
  core dumps for the process; the shipped container already runs read-only, non-root,
  with all capabilities dropped and `no-new-privileges`.
- **Embrace restart-as-erasure (default mode).** With persistence off (the default),
  storage is in-memory, room/message/byte-capped, and TTL-bounded (§4.5): the relay
  retains only recent, undelivered ciphertext and forgets everything on restart. Leaving
  persistence off *is* the minimal-retention story. If you need a best-effort restart
  aid, enabling it (§4.6) is a deliberate, bounded, encrypted-at-rest choice — not a
  default — and the TTL still caps how long undelivered ciphertext lingers; keep the TTL
  as short as your peers' reconnect cadence allows (`HABITABLE_RELAY_TTL_SECONDS`).
- **Scale to zero between sessions.** A union can run one appropriately memory-sized
  instance only when a sync session is happening, or none at all — pure peer-to-peer
  needs no relay.

---

## 8. What this audit does *not* prove

Be honest in your attestation about the boundary:

- It does **not** make the relay unable to observe **connection metadata** (which rooms
  are busy, when, roughly how much moves, and — at the network/proxy layer — peer IPs).
  That is a real, documented exposure; see [`relay-observability-matrix.md`](relay-observability-matrix.md)
  and [`threat-model.md`](threat-model.md) §3.2, §5, §6.
- It does **not** prove anything about a *modified* relay. The attestation is only as
  good as the image digest/commit you pin (Step 0). A different binary needs a different
  audit. The AGPL is part of why a fork that changes behavior must publish its source.
- It does **not** implement traffic-analysis resistance (padding, batching, mixing).
  That is roadmap work, not present in the code — see the matrix, §"Roadmap."
