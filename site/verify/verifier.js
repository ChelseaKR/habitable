// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0
// Copyright 2026 Chelsea Kelly-Reif
//
// Zero-install, client-side verification of a habitable evidence packet.
//
// This is the Apache-2.0 verification subset, re-expressed for the browser so a
// recipient (a court clerk, an inspector, an opposing attorney) can confirm a
// packet's integrity with NO install and NO upload — every byte stays in their
// browser; this page sends nothing to any server. It mirrors the Python verifier
// (see docs/verifier-decision-table.md) for the checks the platform Web Crypto API
// can perform natively: content-hash fixity, the producer's Ed25519 signature, and
// the append-only chain of custody.
//
// Honest scope: full RFC 3161 trusted-timestamp chain verification (ASN.1/CMS +
// the TSA's X.509 certificate path) is NOT performed in-browser — it is reported as
// present and must be confirmed with the standalone `habitable verify` tool or with
// general RFC 3161 tooling (see docs/verifier-decision-table.md §5). Integrity,
// signature, and custody ARE fully checked here.

const GENESIS = "0".repeat(64);

/** Recursively sort object keys so serialization is canonical (matches Python's
 *  canonical_json: sorted keys, compact separators, UTF-8). */
function canonicalize(value) {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(canonicalize);
  const out = {};
  for (const key of Object.keys(value).sort()) out[key] = canonicalize(value[key]);
  return out;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

const subtle = () => globalThis.crypto.subtle;

export async function sha256Hex(bytes) {
  const digest = await subtle().digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function utf8(text) {
  return new TextEncoder().encode(text);
}

function b64ToBytes(b64) {
  const bin = atobShim(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// atob in browsers; Buffer fallback under Node for the test harness.
function atobShim(b64) {
  if (typeof atob === "function") return atob(b64);
  return Buffer.from(b64, "base64").toString("binary");
}

/** Verify the append-only, hash-linked chain of custody.
 *  Returns { ok, length, headOk, problems[] }. */
export async function verifyCustody(custodyProof) {
  const problems = [];
  const entries = (custodyProof && custodyProof.entries) || [];
  let prev = GENESIS;
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    const expectedSeq = i + 1;
    if (entry.seq !== expectedSeq) {
      problems.push(`custody out of order at position ${i}: seq ${entry.seq} (expected ${expectedSeq})`);
    }
    if (entry.prev_hash !== prev) {
      problems.push(`custody chain broken at seq ${entry.seq}: prev_hash mismatch`);
    }
    const { entry_hash, ...payload } = entry; // public_payload excludes entry_hash
    const recomputed = await sha256Hex(utf8(canonicalJson(payload)));
    if (recomputed !== entry_hash) {
      problems.push(`custody entry seq ${entry.seq} has been altered`);
    }
    prev = entry.entry_hash;
  }
  const declaredHead = (custodyProof && custodyProof.head_hash) || GENESIS;
  const headOk = declaredHead === prev;
  if (!headOk) problems.push("custody head_hash does not match the recomputed chain head");
  return { ok: problems.length === 0, length: entries.length, headOk, problems };
}

/** Verify the producer's Ed25519 signature over the bundle bytes.
 *  bundleBytes: Uint8Array of bundle.json; sigDoc: parsed bundle.sig.json. */
export async function verifySignature(bundleBytes, sigDoc) {
  if (!sigDoc) return { ok: false, reason: "no bundle.sig.json present" };
  const bundleHash = await sha256Hex(bundleBytes);
  if (sigDoc.bundle_sha256 !== bundleHash) {
    return { ok: false, reason: "bundle.json does not match the signed hash (bundle_sha256)" };
  }
  if (typeof sigDoc.sign_public !== "string" || typeof sigDoc.signature !== "string") {
    return { ok: false, reason: "signature file is missing sign_public or signature" };
  }
  try {
    const key = await subtle().importKey("raw", b64ToBytes(sigDoc.sign_public), { name: "Ed25519" }, false, ["verify"]);
    const ok = await subtle().verify("Ed25519", key, b64ToBytes(sigDoc.signature), utf8(bundleHash));
    return ok
      ? { ok: true, fingerprint: sigDoc.producer_fingerprint || "" }
      : { ok: false, reason: "Ed25519 signature did not verify" };
  } catch (err) {
    return { ok: false, reason: `signature check unavailable: ${err && err.message ? err.message : err}` };
  }
}

/** Verify one media item's fixity + timestamp presence.
 *  getBytes(name) -> Promise<Uint8Array|null> resolves media/<name> and originals/<capture_id>. */
export async function verifyItem(item, getMedia, getOriginal) {
  const notes = [];
  let sharedOk = true;
  let originalOk = null;

  if (item.shared_name) {
    const bytes = await getMedia(item.shared_name);
    if (!bytes) {
      sharedOk = false;
      notes.push("shared media file missing");
    } else if ((await sha256Hex(bytes)) !== item.shared_hash) {
      sharedOk = false;
      notes.push("shared media does not match its recorded hash");
    }
  } else {
    notes.push("no shared media for this item");
  }

  if (item.has_original) {
    const bytes = await getOriginal(item.capture_id);
    if (!bytes) {
      notes.push("sealed original declared but not included");
    } else {
      originalOk = (await sha256Hex(bytes)) === item.content_hash;
      if (!originalOk) notes.push("embedded original failed fixity");
    }
  }

  const tokens = [];
  if (item.timestamp && typeof item.timestamp === "object") tokens.push(item.timestamp.tsa_name || item.timestamp.kind);
  for (const extra of item.additional_timestamps || []) tokens.push(extra.tsa_name || extra.kind);
  const timestampPresent = tokens.length > 0;
  if (!timestampPresent) notes.push("awaiting timestamp");

  return {
    capture_id: item.capture_id,
    content_hash: item.content_hash,
    sharedOk,
    originalOk,
    timestampPresent,
    timestampAuthorities: tokens,
    ok: sharedOk && originalOk !== false,
    notes,
  };
}

/** Top-level: verify a whole packet from already-loaded files.
 *  files = { bundleBytes: Uint8Array, bundle: object, sig: object|null,
 *            getMedia(name), getOriginal(captureId) } */
export async function verifyPacket(files) {
  const problems = [];
  const bundle = files.bundle;
  const version = bundle && bundle.packet_version;
  if (!Number.isInteger(version)) {
    return { ok: false, problems: ["bundle has no integer packet_version"], items: [] };
  }

  const signature = await verifySignature(files.bundleBytes, files.sig);
  const custody = await verifyCustody(bundle.custody_proof || {});
  const items = [];
  for (const item of bundle.items || []) {
    items.push(await verifyItem(item, files.getMedia, files.getOriginal));
  }

  const itemsOk = items.every((i) => i.ok);
  const allTimestamped = items.every((i) => i.timestampPresent);
  const ok = signature.ok && custody.ok && itemsOk && problems.length === 0;
  return {
    ok,
    signature,
    custody,
    items,
    allTimestamped, // integrity can pass while some items still await a timestamp
    problems,
    note: "RFC 3161 timestamp chains are reported as present, not cryptographically verified here; confirm with `habitable verify`.",
  };
}
