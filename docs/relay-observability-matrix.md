<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Relay observability matrix — what a relay operator (or a subpoena) can and cannot see

> **Purpose (items R-46, R-33, E-23).** A relay is an **optional** component of
> habitable. When one is used, an honest tool must state — plainly enough that it can
> never be spun as "hidden" (R-33) — exactly what the operator of that relay, or anyone
> who **subpoenas or compromises** it, can and cannot observe. This page is that
> statement: contents are **not** observable; certain **metadata is**. It then lists the
> mitigations, including the metadata-resistance work that is **roadmapped but not yet
> implemented** (E-23), clearly labeled as future.
>
> Companion to [`threat-model.md`](threat-model.md) (§3.2 the optional relay, §5
> explicit limits, §6 residual-risk table), [`relay-operator-self-audit.md`](relay-operator-self-audit.md)
> (how an operator verifies and attests what the relay logs), and
> [`relay-deploy.md`](relay-deploy.md) (how to run it). The adversary lens here is
> persona **P-22** (the retaliating landlord who will subpoena *something*) and the
> self-hoster **P-19**.

---

## 1. The one-paragraph honest summary

The relay (`src/habitable/relay.py`) is a dumb ciphertext mailbox: every sync message is
sealed to the recipient's key *before it leaves the sender* (`seal_to` /
`export_message` in `src/habitable/sync.py`), so the relay **cannot read note text,
image bytes, or sender identity** — not in its store, not in what it serves back, not in
`/healthz`. But because it **forwards traffic**, it unavoidably **observes connection
metadata**: which room ids are active, when, how often, and roughly how much data moves;
and at the network/transport layer (or its TLS-terminating proxy) the **peer IP
addresses**. habitable does **not** currently implement traffic-analysis resistance
(padding, batching, mixing). The only way to remove the metadata exposure entirely is to
**not use a relay** — sync peer-to-peer.

---

## 2. The matrix — contents (NO) vs metadata (varies)

"Operator" = whoever runs the relay. "Subpoena/compromise" = an adversary who seizes the
host, compels the operator, or takes over the process — i.e. the worst realistic case
for a single relay. Grounded in `relay.py` and `sync.py`.

### 2.1 Contents — NOT observable

| Item | Operator? | Subpoena / compromise? | Why |
| --- | --- | --- | --- |
| Note / condition text | **No** | **No** | Rides inside the CRDT state, sealed to the recipient before posting. |
| Image / video bytes | **No** | **No** | Carried as `original_b64` *inside* the sealed envelope. |
| Case id, issue titles, rooms, categories | **No** | **No** | All inside the sealed `inner` payload. |
| **Sender identity** (who posted) at the application layer | **No** | **No** | The sender pubkey + signature ride *inside* the sealed box (`export_message`); the relay never extracts them. Pinned by `tests/test_sync.py::test_relay_sync_is_end_to_end_encrypted`. |
| Recipient identity at the application layer | **No** | **No** | Addressing is by sealing to a key, not by any field the relay reads. |
| Timestamp tokens, custody log | **No** | **No** | Sealed inside the envelope. |

A subpoena served on the relay yields **ciphertext blobs and counters** — nothing a
keyholder's keys are needed to open, and the relay holds no such key. This is the design
goal in `threat-model.md` §1: *"there is no third party holding a tenant's contents to
subpoena."*

### 2.2 Metadata — observable to the extent below

| Item | Operator? | Subpoena / compromise? | Notes |
| --- | --- | --- | --- |
| **Room id** (`--channel`) of active traffic | **Yes** | **Yes** | Room ids are the store's keys and appear in the request path (`/rooms/<id>`). They are peer-chosen and opaque, but stable: the same id recurring links sessions together. |
| **Who-syncs-with-whom**, by room | **Partly** | **Partly** | The relay sees *that a room is active* and (at the network layer) *which IPs* touch it. It does not see identities, but **co-occurrence of IPs on a room id** reveals that those parties sync together. This is the core "who-with-whom" leak. |
| **Timing** — when a sync happens | **Yes** | **Yes** | Every POST/GET is handled in real time; even with no logs, a live operator or a tap sees activity as it occurs. |
| **Volume / size** — roughly how much moves | **Yes** | **Yes** | `bytes_relayed` is counted aggregate; per-message size is visible at handling time and via `Content-Length`. No padding is applied, so blob size tracks real payload size. |
| **Frequency** — how often a room syncs | **Yes** | **Yes** | Inferable from repeated activity on a room id. |
| **Peer IP addresses** | **Yes** (at network/proxy layer) | **Yes** | Not stored by `relay.py` itself, but visible to the host's network stack, the TLS-terminating proxy, and any on-path observer. The relay's *application* logs are empty by default (see audit doc), but the proxy and the network are not the application. |
| Aggregate counts (`rooms`, `posted`, `fetched`, `bytes_relayed`) | **Yes** | **Yes** | Exposed by `/healthz` by design; harmless aggregates, but they do confirm the relay is in use and how busy it is. |

### 2.3 The residual exposure, stated so it can't be spun as hidden (R-33)

> **Even a perfectly-behaved, no-log, self-hosted relay can observe who syncs with whom,
> when, how often, and roughly how much — by room id and by IP. habitable does not hide
> this and does not currently defeat it. If your threat model cannot tolerate that
> metadata reaching the relay's operator or anyone who subpoenas or compromises the
> relay, do not use a relay: sync peer-to-peer.**

This is the same limit stated in `threat-model.md` §5 ("Relay metadata is not hidden")
and §6 (residual-risk row "Relay operator or its subpoena"). It is repeated here, and at
point of use, precisely so it can never be characterized as something the project
concealed.

---

## 3. Why contents (and sender identity) are safe — the mechanism

- `export_message` (`sync.py`) builds an envelope `{sender, inner_b64, sig}`, then calls
  `seal_to(recipient, ...)` over the **whole envelope**. The sender pubkey and signature
  are therefore *inside* the sealed box, not a header the relay reads.
- The relay's `post()` stores the resulting bytes verbatim; `fetch()`/`do_GET` returns
  them base64-encoded, unparsed. The relay never calls `open_sealed` and holds no key
  that could.
- `tests/test_sync.py::test_relay_sync_is_end_to_end_encrypted` asserts that the note
  text, raw image bytes, base64 image bytes, **and the sender's fingerprint** appear in
  none of the stored blobs nor in the base64 the relay serves back.
  `tests/test_relay.py::test_healthz_exposes_only_aggregate_counts` asserts `/healthz`
  leaks no room id and no contents.

(Note: `tests/test_guards.py` guards a *different* invariant — packet/bundle export
minimization. The relay claim is pinned in `test_sync.py`/`test_relay.py`.)

---

## 4. Mitigations available **today**

### 4.1 Use no relay at all — removes the party entirely

The strongest mitigation needs no new code: **pure peer-to-peer sync.**
`LocalDirTransport` (`sync.py`) moves the same sealed bytes through a shared directory,
which doubles as the **sneakernet** path — a USB stick or SD card handed over in person,
or an AirDrop-style transfer. No relay, no operator, no network metadata at the relay.
If two organizers can meet or share a folder, they need no relay and there is no relay
metadata to leak.

### 4.2 Run a no-log, self-hosted relay

If a relay is needed, a union running **its own** relay shrinks the trust surface to
itself. The shipped relay is already no-log by default (request logging is suppressed in
`relay.py`; it persists nothing to disk; `/healthz` exposes only aggregate counts). The
operator can verify and attest all of this — see
[`relay-operator-self-audit.md`](relay-operator-self-audit.md). This does **not** remove
the metadata exposure (a self-hosted relay still observes who/when/how-much), but it
keeps that metadata inside the union rather than with a third party, and it removes the
"third party to subpoena" entirely.

### 4.3 Minimize the network/proxy layer

The relay code does not log IPs, but the host network stack and the TLS-terminating
reverse proxy can. Configure the proxy to drop access logs and not record client IPs;
this is part of the operator self-audit (audit doc §6 Step 1, §7).

### 4.4 Operational hygiene that blunts (not eliminates) metadata

- **Restart-as-erasure.** Storage is in-memory and FIFO-capped; a restart drops
  undelivered ciphertext and resets counters.
- **Scale to zero between sessions.** Run the relay only during a sync window, so there
  is less time during which any activity can be observed.
- **Reuse room ids minimally.** Because a stable room id links sessions, a union can
  reduce linkability by not reusing a single long-lived room id across unrelated
  exchanges. (This is operational advice, not a code feature, and it does not defeat
  IP-level correlation.)
- **Network anonymity is the user's responsibility.** Tor/VPN can hide peer IPs from the
  relay and on-path observers; habitable does not provide this and the threat model
  (§"Tracking via telemetry" residual risk) states network-level observation is outside
  the app's control.

---

## 5. Roadmap — metadata resistance (NOT yet implemented)

The following is **future work** (backlog **E-23**, and **R-46** "advance metadata
resistance," marked *planned* in
[`docs/research/synthetic-personas-feedback.md`](research/synthetic-personas-feedback.md)).
It is **not in the code today.** Do not attest or claim these properties for the current
relay.

- **Padding** — pad ciphertext blobs to fixed/bucketed sizes so size no longer tracks
  real payload size. *Not implemented:* blob size today equals payload size.
- **Batching / cover traffic / mixing** — delay and batch deliveries, or inject decoy
  traffic, so timing and frequency stop revealing real sync events. *Not implemented:*
  every POST/GET is handled in real time.
- **A hardened relay profile** combining the above into an opt-in "metadata-resistant"
  mode. *Not implemented.*
- **Transport-level protections** beyond "use TLS + bring your own Tor/VPN." *Not
  implemented in the app.*

Until these ship, the honest statement is the one in §2.3: a relay observes who/when/
how-much, and the only way to avoid that is to not use a relay.

---

## 6. Quick reference

| Question | Answer today |
| --- | --- |
| Can the relay read my notes/photos? | **No** — sealed before it arrives. |
| Can it tell who sent a message? | **No** at the app layer (sender id is inside the sealed box). **But** it can correlate IPs to a room. |
| Can it tell which peers sync together? | **Partly** — via room-id activity and IP co-occurrence. |
| Can it see when / how often / how much? | **Yes** (timing, frequency, size). |
| Does it store any of this on disk or in logs? | **No** by default (in-memory, no request logs, `/healthz` aggregates only) — but the network/proxy layer can. |
| Does it pad/batch/mix to resist traffic analysis? | **No** — roadmapped (E-23), not implemented. |
| How do I avoid relay metadata entirely? | **Don't use a relay** — sync peer-to-peer (`LocalDirTransport`, USB/SD/shared folder). |

See [`threat-model.md`](threat-model.md) §3.2, §5, and §6 for the canonical statement of
these boundaries and residual risks.
