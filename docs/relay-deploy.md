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
{"status": "ok", "rooms": 0, "posted": 0, "fetched": 0, "bytes_relayed": 0}
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
- **Health:** `GET /healthz` returns `200` with passthrough metrics; the container
  ships a `HEALTHCHECK` that polls it.
- **Storage:** messages are held in memory (capped per room) and forwarded; the
  relay is not a backup. Restarting it drops undelivered messages — peers simply
  re-sync (sync is idempotent).
- **Logs:** the relay does not log request lines or contents, only aggregate
  counts via `/healthz`. Keep it that way; a no-log relay is part of the privacy
  posture.
- **Scaling:** it scales to zero between sessions; a union can run one small
  instance, or none at all.

## What it is not

The relay is **not** a place your case lives. There is no account, no plaintext,
and no authority over a union's records on it — forking or self-hosting changes
nothing about who can read the data: still only the keyholders.
