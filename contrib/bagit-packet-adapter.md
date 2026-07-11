<!-- SPDX-License-Identifier: Apache-2.0 -->
# BagIt adapter for exact packet transfer

`bagit_packet_adapter.py` is a small reference CLI/module for transferring one Habitable packet
through systems that understand the [BagIt File Packaging Format 1.0 (RFC
8493)](https://www.rfc-editor.org/rfc/rfc8493.html). It uses the Python standard library and
Habitable's permissively licensed verification subset; it adds no package dependency.

BagIt and Habitable answer different questions:

- BagIt payload and tag manifests detect an incomplete or accidentally corrupted transfer.
- Habitable verifies the packet's signed bundle, shared-media hashes, custody proof, timeline
  commitments, and timestamp tokens. Independently supplied trust roots determine whether a valid
  timestamp authority is trusted.

BagIt is **not designed to resist an active attacker** who can replace payload bytes and rewrite
the manifests. Creating or validating a bag must never be described as authenticating the packet,
establishing who produced it, trusting its timestamp authority, making it evidence-ready, or
deciding admissibility.

## Command line

Create a new bag after Habitable structural verification:

```console
$ python contrib/bagit_packet_adapter.py create 4B-packet 4B-transfer.bag
created 4B-transfer.bag: 6 exact packet file(s), 48231 byte(s)
```

The output path must not exist. This fail-closed rule preserves any prior output unchanged and lets
the adapter publish a fully built and validated staging directory with one same-filesystem rename.
The packet directory is read but never rewritten.

Validate the bag after copying it to another system:

```console
$ python contrib/bagit_packet_adapter.py validate 4B-transfer.bag
valid Habitable transfer bag: 6 payload file(s), 48231 byte(s), 2 digested tag file(s)
$ habitable verify 4B-transfer.bag/data/packet --trusted-cert independently-trusted-tsa.pem
```

`create` and `validate` return `0` on success and `1` on a failed packet/bag/input check. The
receiver should run both BagIt validation and Habitable verification. A BagIt-valid transfer can
still contain a packet whose signature, custody, timestamp token, or authority-trust check fails.

As a module:

```python
import sys
sys.path.insert(0, "contrib")

from bagit_packet_adapter import create_bag, validate_bag

created = create_bag("4B-packet", "4B-transfer.bag")
assert created.packet_report.structurally_intact
assert created.validation.ok

received = validate_bag("received/4B-transfer.bag")
assert received.ok
```

`structurally_intact` is intentional: creating a transfer envelope does not require or infer a
timestamp trust root. A recipient who needs the stronger `evidence_ready` verdict supplies an
independently trusted TSA certificate to the Habitable verifier.

## Emitted profile and RFC choices

The adapter emits this closed profile:

```text
4B-transfer.bag/
├── bagit.txt
├── manifest-sha256.txt
├── tagmanifest-sha256.txt
└── data/
    └── packet/
        └── ... exact Habitable packet files ...
```

- `bagit.txt` declares BagIt `1.0` and `UTF-8` with LF line endings and no BOM.
- The stable `data/packet/` prefix avoids changing bag bytes when a source directory is renamed.
- `manifest-sha256.txt` lists every payload file exactly once. The adapter preserves every file's
  bytes and sorts manifest paths by their UTF-8 bytes for reproducible output.
- `tagmanifest-sha256.txt` covers `bagit.txt` and `manifest-sha256.txt`. RFC 8493 makes a tag
  manifest optional, but including it detects corruption of the declaration and payload manifest.
  A tag manifest must not list itself.
- SHA-256 is used for both manifests. BagIt 1.0 requires validators to support SHA-256 and SHA-512
  and recommends SHA-512 as a general default; this narrow adapter deliberately uses SHA-256 to
  match Habitable's packet digest vocabulary and the transfer-profile contract.
- `bag-info.txt`, `Bagging-Date`, and other clock- or host-derived tags are omitted. The same packet
  therefore produces the same tag and manifest bytes.
- RFC 8493 requires `%`, CR, and LF in manifest paths to be percent-encoded. This profile encodes
  `%` as `%25` and rejects control characters, including CR and LF, before packaging.

The validator is intentionally a validator for this profile, not for every legal BagIt extension.
It rejects other checksum algorithms, `fetch.txt`, extra tag files, and payload outside
`data/packet/` rather than silently interpreting a broader format.

## Filesystem safety and portability

Before copying, the adapter walks the packet without following links. Habitable's verifier opens
its fixed control files and bundle-named references through bounded, regular-file-only reads. The
adapter then checks every source file's device, inode, size, and modification time before and after
copying. It
rejects:

- symlinks and non-regular objects such as FIFOs, sockets, and devices;
- absolute paths, `.`/`..` traversal, empty components, and backslash separator ambiguity;
- paths that collide after case-folding or Unicode NFC normalization;
- control characters, leading/trailing whitespace, Windows-reserved characters/names, and other
  names that cannot transfer predictably between common Unix and Windows filesystems;
- an output inside the packet, a packet inside the output, and any pre-existing output path.

The same checks are applied to manifest paths before the validator opens a listed file. After the
copy, Habitable verifies the copied packet, every payload and tag digest is recomputed, the exact
payload/tag sets are compared to their manifests, and only then is the bag published.

## Limits

- The transfer manifest covers file bytes and names, not ownership, mode bits, extended attributes,
  filesystem timestamps, or directory metadata. Empty directories are preserved by this directory
  adapter but are not checksummed by BagIt.
- Publication and link checks assume the local filesystem is not being concurrently manipulated by
  an active attacker. Ordinary file mutation is detected, but a hostile process that can replace
  parent directories or restore metadata can still race portable path-based checks. That is
  consistent with RFC 8493's active-attack limitation; use controlled source/destination
  directories when creating a transfer. Publication is atomically visible on the same filesystem,
  but the adapter does not claim crash-durable persistence across hardware or filesystem failure.
- A directory-form BagIt bag is not a ZIP or TAR archive. If another tool serializes it, validate
  the extracted bag before relying on the transfer and then run Habitable verification again.

The focused tests in
[`../tests/test_contrib_bagit_adapter.py`](../tests/test_contrib_bagit_adapter.py) cover deterministic
output and ordering; payload/tag tamper; missing and extra files; invalid source packets; symlinks,
FIFOs, traversal, and nested escape; case/Unicode collisions; separator ambiguity; safe existing
output handling; and failure cleanup.
