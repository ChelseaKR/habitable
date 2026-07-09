# Prove it: no plaintext ever reaches the relay

> **For skeptics.** habitable claims a sync relay only ever moves *ciphertext* — it
> never sees a note, a photo, a filename, or who you are. A test in the suite asserts
> this, but you should not have to trust our test. This page gives you two ways to
> **see it yourself**: a one-command built-in check you can audit, and a manual
> packet capture against a real relay with `tcpdump`/`tshark`.

Related reading: the [privacy statement](privacy.md) (data-flow table), the
[threat model](threat-model.md) (what a relay *can* still observe — metadata), and
the on-device [data-flow X-ray](#the-on-device-data-flow-x-ray) below.

---

## 1. The built-in check: `habitable prove-no-plaintext`

```console
$ habitable prove-no-plaintext
```

What it does, end to end, with **no real data and no external network**:

1. **Fabricates a synthetic case** seeded with distinctive, easily-grepped plaintext
   *markers* — a note, an issue title, a source filename, the vault passphrase, the
   passphrase-derived `node_id`, the device fingerprint, and the raw image bytes.
2. **Starts the real relay** ([`src/habitable/relay.py`](../src/habitable/relay.py))
   in-process on `127.0.0.1`.
3. **Wire-taps the transport** used by sync so every byte sent to or fetched from the
   relay is written, *verbatim*, to a capture file.
4. **Runs a real sync round-trip** (the same code path a phone uses over a remote
   relay).
5. **Greps the captured bytes** — raw, base64-encoded, and base64-decoded — for every
   marker. **One hit fails the check** (non-zero exit).
6. Prints the byte count, the markers searched, the hit count, and the **capture
   file path** so you can repeat the grep by hand.

Then audit it yourself — the capture file is just the raw wire bytes:

```console
$ xxd relay-wire-capture.bin | less
$ grep -a 'PLAINTEXT-XRAY-title-uninhabitable-unit-4B-mold' relay-wire-capture.bin
        # expect: no output — the marker never crossed the wire
```

The logic lives in [`src/habitable/prove.py`](../src/habitable/prove.py) and is
exercised by [`tests/test_prove.py`](../tests/test_prove.py), which also proves the
check **fails** when a deliberate plaintext leak is injected — so you know the grep
is real and not a no-op.

Why trust the grep? Because it is inverted: a *deliberately leaky* build makes the
command exit non-zero. A check that can only ever pass proves nothing; this one can
fail, and the test suite demonstrates it failing.

---

## 2. The manual check: capture a real relay with `tcpdump`

The built-in check captures the **application-layer** bytes (what habitable hands the
transport). To convince yourself independently, capture the packets on a relay you
run yourself.

### Set up a self-hosted relay

See [`docs/relay-deploy.md`](relay-deploy.md). In short:

```console
$ HABITABLE_RELAY_HOST=0.0.0.0 python -m habitable.relay   # listens on :8787
```

### Capture while you sync

On the relay host (or any box on the path), record the traffic to a file:

```console
$ sudo tcpdump -i any -s 0 -w relay.pcap 'tcp port 8787'
```

From your device, run a **real** sync through that relay:

```console
$ habitable sync --vault ./vault --peer <PEER-PUBLIC-ID> \
      --channel <ROOM> --relay http://<relay-host>:8787
```

Stop `tcpdump` (Ctrl-C).

### Grep for your own plaintext

Search the raw capture for anything you actually wrote — a note, your unit number, a
filename. **None of it should appear:**

```console
$ strings relay.pcap | grep -i 'unit-4B'          # expect: no output
$ tshark -r relay.pcap -T fields -e data | xxd     # inspect the bytes directly
```

You will see only:

- **Ciphertext**: each message is a sealed box (X25519 + XChaCha20-Poly1305),
  addressed to the recipient's public key and signed by the sender — opaque bytes.
- **Metadata**: the room id in the request path, byte counts, timing, and IP
  addresses. This is exactly what the [threat model](threat-model.md) says a relay
  observes and cannot avoid. The room id and connection metadata are *not* contents;
  peer-to-peer sync (no relay) removes even that.

### TLS vs. app-layer ciphertext (important caveat)

- If you put the relay **behind TLS** (recommended in production), `tcpdump` sees the
  TLS record layer, i.e. ciphertext *wrapped a second time*. You then cannot read the
  habitable ciphertext directly from the wire — which is fine for privacy but less
  illustrative. To inspect habitable's own sealing, either:
  - capture on the **loopback**/plaintext side of your TLS terminator (nginx/Caddy),
    or
  - run the relay **without TLS on a trusted local network** for the demonstration
    only, so the app-layer bytes are what `tcpdump` records.
- Seeing ciphertext under TLS proves confidentiality *in transit*; seeing ciphertext
  under **no** TLS proves habitable itself never emits plaintext. The built-in
  `prove-no-plaintext` check does the latter, on the loopback, with markers you can
  grep for.

---

## The on-device data-flow X-ray

Separately, you can ask habitable — for **your own** vault, fully offline, with no
telemetry — exactly what each component would expose externally:

```console
$ habitable status --vault ./vault --xray
```

It prints a per-component table derived from your actual case:

| component | leaves the device | |
| --- | --- | --- |
| on-device capture | **nothing** | seal + SHA-256 run locally |
| RFC 3161 timestamp | a **SHA-256 hash** only | one hash per stamped item |
| relay sync (optional) | **sealed blobs + a mailbox id** | ciphertext to a chosen peer |
| packet export | a **full plaintext packet** | only when *you* run `habitable export` |

No network calls, no logging — it reads your vault and prints. It is the personal,
auditable companion to the whole-system claims above.
