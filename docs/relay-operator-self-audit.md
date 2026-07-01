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
    rooms: dict[str, list[bytes]]   # room id -> queue of opaque ciphertext blobs
    posted: int                     # total POSTs accepted
    fetched: int                    # total messages handed back on GET
    bytes_relayed: int              # total bytes of ciphertext moved
```

**It stores, in process memory only:**

| Held in memory | What it is | Sensitive? |
| --- | --- | --- |
| `rooms` keys | The **room id** chosen by the peers (the `--channel` value). 1–128 chars, `[A-Za-z0-9_-]`. | Metadata. Peer-chosen; opaque to the relay. See §6 and the observability matrix. |
| `rooms` values | A list of **sealed ciphertext blobs** (`bytes`) per room. Capped at 10,000 per room (`_MAX_MESSAGES_PER_ROOM`); oldest is dropped when full. | Ciphertext only. The relay cannot open it. |
| `posted` / `fetched` / `bytes_relayed` | Three running integer counters. | Aggregate metadata only. |

**Crucial facts about this storage:**

- **It is in-memory, not on disk.** `relay.py` never opens a file, never writes a
  database. There is no `open(...)`, no SQLite, no log file in the module. Restarting
  the process **drops every undelivered message and resets every counter.** The relay
  is not a backup; peers simply re-sync (sync is idempotent — see `sync.py`).
- **It stores no peer addresses, no per-message timestamps, no sender identity.** The
  sender's identity rides *inside* the sealed envelope (`export_message` puts
  `sender`/`sig` inside the bytes handed to `seal_to`), so it is encrypted; the relay
  never extracts or records it.
- **The blobs are opaque.** On `GET /rooms/<id>` the handler base64-encodes the stored
  bytes and returns them; it never parses, decodes, or inspects their structure.

> **Honest caveat — memory is still memory.** "In memory, not on disk" is a property of
> the application code, not a hardware guarantee. While the process runs, the ciphertext
> blobs and the room ids are in RAM and could be read by a process memory dump, a core
> dump, or swap if the host swaps memory to disk. This is *ciphertext and room
> metadata*, never plaintext — but if you are attesting to a high-risk union, disable
> swap on the host (or run with swap encrypted) and avoid writing core dumps. The relay
> code does not, by itself, persist anything.

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

  So out of the box the relay does **not** emit per-request log lines, peer IPs, room
  ids, or sizes to its own logs. A structured, **metadata-only** per-request access
  log is available but **opt-in and off by default** (`HABITABLE_RELAY_LOG=json`); see
  §4.3 for exactly what it does and does not contain.

- **No contents, ever.** No note text, no image bytes (raw or base64), no sender
  fingerprint. These never reach the relay in cleartext; they are inside the sealed
  box. See the guard tests in §5.

- **No accounts, no auth database, no central record.** There is no login, no user
  table, no per-peer state. Forking or self-hosting changes nothing about who can read
  the data: still only the keyholders.

- **The only thing it exposes about itself is `/healthz`**, which returns:

  ```json
  {"status": "ok", "rooms": 0, "posted": 0, "fetched": 0, "bytes_relayed": 0}
  ```

  That is the *entire* observable summary — four aggregate integers and a status. It
  contains no room ids and no contents. `tests/test_relay.py::test_healthz_exposes_only_aggregate_counts`
  pins exactly this: it posts to a room named `room-SECRETNAME-123` with a
  `SECRET-CIPHERTEXT-PAYLOAD` body and asserts neither the room name nor the payload
  appears anywhere in the `/healthz` response, and that the response keys are a subset
  of `{status, rooms, posted, fetched, bytes_relayed}`.

---

## 4. The documented data / log schema (what to attest)

This is the complete schema you can hand the union. Every field is either **ciphertext**
or **aggregate metadata** — never plaintext contents.

### 4.1 In-memory store (`RelayStore`)

| Field | Type | Contents | Persistence |
| --- | --- | --- | --- |
| `rooms[<room_id>]` | list of `bytes` | Sealed ciphertext blobs, opaque to the relay | RAM only; dropped on restart; FIFO-capped at 10,000/room |
| `posted` | `int` | Count of accepted POSTs | RAM only; reset on restart |
| `fetched` | `int` | Count of messages handed back | RAM only; reset on restart |
| `bytes_relayed` | `int` | Total ciphertext bytes moved | RAM only; reset on restart |

Room ids are the keys; the **count** of rooms (`len(self.rooms)`) is exposed via
`/healthz`, but the room **ids themselves are never serialized out** by any handler.

### 4.2 HTTP surface (the only network-observable schema)

| Route | Method | Request body | Response body | Stores / logs |
| --- | --- | --- | --- | --- |
| `/rooms/<id>` | POST | raw sealed bytes (≤ 128 MiB, `_MAX_BODY`) | `{"status": "stored"}` | Appends blob to room queue; increments `posted`, `bytes_relayed` |
| `/rooms/<id>` | GET | — | `{"messages": [<base64 blob>, ...]}` | Increments `fetched`; returns stored ciphertext unchanged |
| `/healthz` | GET | — | `{"status":"ok","rooms":N,"posted":N,"fetched":N,"bytes_relayed":N}` | Nothing |
| anything else | any | — | `{"error":"not found"}` (404) / `413` on bad/oversized body | Nothing |

### 4.3 Application logs

**Structured JSON, metadata-only, and free of request lines by default.** The relay
logs through the Python standard-library `logging` module (no third-party logging
dependency), emitting one JSON object per line. There are two kinds of line:

- **Lifecycle lines — always emitted.** One at startup and one at shutdown. The
  startup line (`serve()` in `relay.py`) carries only the bind host/port you
  configured and nothing about any peer or message:

  ```json
  {"ts":"2026-01-02T00:00:00+00:00","level":"info","msg":"relay listening (ciphertext passthrough only)","host":"0.0.0.0","port":8787,"access_log":false}
  ```

- **Per-request access lines — opt-in and OFF by default.** `log_message` is a no-op
  (§3), so `BaseHTTPRequestHandler`'s own request lines stay suppressed. A structured
  access line is emitted per request **only** when you set `HABITABLE_RELAY_LOG=json`.
  When enabled, each line carries **only metadata** — a random per-request id, the
  HTTP method, a **redacted** route (`/rooms/{room}`, **never** the actual room id),
  the response status, and the latency in milliseconds. It **never** contains peer IP
  addresses, room ids, or message contents, and the health probes (`/livez`,
  `/readyz`, `/healthz`) are excluded from it. Leave it off (the default) to preserve
  the "no request lines" property this audit attests; the guarantee that no room id,
  IP, or content ever reaches the logs holds whether it is on or off.

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
  `/healthz` leaks no room ids and no message contents, only the four aggregate counts.

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
{"status": "ok", "rooms": 1, "posted": 1, "fetched": 0, "bytes_relayed": 21}
```

Confirm the response contains the four counters and `status` only — no room id
(`audit-probe-room` must not appear) and no body content.

### Step 3 — Confirm the relay cannot read what it forwards

Optional but persuasive: post known-plaintext to a room, fetch it back, and show the
relay treated it as an opaque blob (it round-trips byte-for-byte and is never parsed).
This demonstrates the *passthrough* behavior. The real end-to-end-encryption guarantee
is established by the senders sealing before posting (Step 5), not by the relay.

### Step 4 — Confirm no on-disk persistence

```console
# The shipped compose file runs the container read-only; show it:
$ docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' habitable-relay   # -> true
# Show the relay writes no data files of its own:
$ docker diff habitable-relay   # expect no added/changed files under the app dir
# Restart and show state is gone (proving memory-only storage):
$ docker restart habitable-relay
$ curl -s http://localhost:8787/healthz   # rooms/posted/fetched/bytes_relayed back to 0
```

A reset-to-zero after restart is direct evidence the relay persists nothing.

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

> *"This relay, running image `<digest>` from commit `<sha>`, stores only opaque
> ciphertext blobs and four aggregate counters in memory; it persists nothing to disk;
> it writes no request logs; its `/healthz` exposes only aggregate counts; and the
> project's own guard tests confirm note text, image bytes, and sender identity never
> reach it. It can still observe connection metadata — see the observability matrix —
> which I have disclosed separately and have not tried to hide."*

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
- **Embrace restart-as-erasure.** Because storage is in-memory and FIFO-capped, the
  relay naturally retains only recent, undelivered ciphertext and forgets everything on
  restart. Don't bolt on persistence; the lack of it *is* the retention story.
- **Scale to zero between sessions.** A union can run one small instance only when a
  sync session is happening, or none at all — pure peer-to-peer needs no relay.

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
