<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Deploying the optional sync relay

A relay is **optional**. Two organizers can sync device-to-device with no server
at all (`habitable sync … --dir <shared folder>`). Run a relay only when peers
can't reach each other directly — for example, two phones on different networks.

**The relay can read nothing.** Every message is sealed to a peer's key before it
arrives; the relay stores and forwards opaque ciphertext per room and keeps only
aggregate passthrough counts. It still sees connection *metadata* (which rooms are
busy, when, and message sizes) — see [`threat-model.md`](threat-model.md). The
image is dependency-free (standard library only), runs as a non-root user, and is
read-only with all capabilities dropped.

## One-command deploy (Docker)

From the repository root:

```console
$ docker compose -f relay/docker-compose.yml up -d --build
$ curl -s http://localhost:8787/healthz
{"status":"ok","rooms":0,"live_messages":0,"live_ciphertext_bytes":0,
 "posted":0,"fetched":0,"bytes_relayed":0,"capacity_rejections":0,
 "journal_load_rejections":0}
```

Or without compose:

```console
$ docker build -f relay/Dockerfile -t habitable-relay .
$ docker run -d --name habitable-relay -p 8787:8787 \
    --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    habitable-relay
```

Without Docker, the relay is one command (no install needed beyond the source):

```console
$ HABITABLE_RELAY_HOST=0.0.0.0 uv run habitable relay --host 0.0.0.0 --port 8787
```

## Point peers at it

Each organizer runs `habitable id`, shares their **public-id**, verifies the
**fingerprint** out of band, then syncs through a shared room id:

```console
$ uv run habitable sync --vault ./case-4B --peer <their-public-id> \
    --channel <shared-room-id> --relay https://relay.example.org
```

## Operating it

- **TLS:** terminate HTTPS at a reverse proxy (Caddy/nginx/Traefik) in front of
  `:8787`. Peers should use an `https://` relay URL; the client refuses non-HTTP(S)
  URLs but does not add TLS itself.
- **Health:** `GET /healthz` returns `200` with aggregate passthrough, retained-state,
  capacity-rejection, and rejected-journal counts; the container ships a `HEALTHCHECK`
  that polls it. These metrics contain no room id, token, or body data.
- **Storage:** retained messages are capped at 4,096 live rooms, 50,000 live messages
  (10,000/room), 512 MiB ciphertext aggregate, and 128 MiB/room. A write above any cap
  gets 413; no older message is silently evicted, and GET does not clear capacity. Wait for
  the configured TTL and retry, or deliberately adjust operator retention/capacity. The default
  memory-only relay is not a backup. Restarting it drops undelivered messages — peers simply
  re-sync (sync is idempotent).
- **Opt-in persistence:** keep one local relay process per persistence directory. Startup
  bounds journal bytes/lines/entries, rejects timestamps over five minutes in the future,
  and cleans at most 128 exact app-owned compaction crash temps under a separate allowance
  before journal admission. An over-allowance directory fails closed. Unterminated append
  tails are rebuilt from live state before the next POST is acknowledged. This is not
  fsync-backed delivery; unlinking stale journals/temps is cleanup, not secure erasure, and
  Windows uses a mechanically tested close/recheck/unlink fallback but has no dedicated CI lane.
- **Memory sizing:** 512 MiB is the retained-ciphertext ceiling, not a whole-process RSS
  promise. A handler can additionally hold one request body (up to 128 MiB), Python/runtime
  bookkeeping, and socket buffers. GET computes an exact response length and streams base64
  in 48 KiB chunks instead of materializing a roughly 171 MiB encoding for a full room.
  Opt-in journal startup also holds one bounded encoded line plus its decoded ciphertext.
  Put concurrency/body-rate limits at the TLS reverse proxy and budget headroom above the
  retained-state cap.
- **Logs:** request lines remain off by default. Lifecycle lines, a fixed-vocabulary aggregate
  journal-rejection warning, and a fixed `relay request handler failed` event for unexpected
  faults may appear. Expected resets/broken pipes are silent. The override replaces the
  stdlib's client-address + traceback dump; none of these lines includes a peer IP, room id,
  token, path, exception, or body. Keep reverse-proxy request logging minimized too.
- **Scaling:** it scales to zero between sessions; a union can run one appropriately
  memory-sized instance, or none at all. Fixed caps are fail-closed single-process limits,
  not horizontal coordination across several relay replicas.

## What it is not

The relay is **not** a place your case lives. There is no account, no plaintext,
and no authority over a union's records on it — forking or self-hosting changes
nothing about who can read the data: still only the keyholders.
