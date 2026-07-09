// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0
// Copyright 2026 Chelsea Kelly-Reif
//
// habitable — in-browser verifier (the zero-install recipient path, E-15/EXP-05).
//
// This is a faithful JavaScript port of the Apache-2.0 verification subset
// (src/habitable/verify.py and the pure helpers it relies on), pinned to
// docs/verifier-decision-table.md and cross-tested against the Python verifier
// over the golden packet corpus in CI (tests/test_web_verifier.py). It runs
// entirely in the browser: no network requests, no upload, no server.
//
// Contract (same as the Python verifier): it FAILS CLOSED. Anything this
// environment cannot check — a missing WebCrypto capability, an algorithm this
// port does not implement — is reported as not verified plus an entry in
// `browser_limits`, never silently passed. A packet is reported intact only
// when every check this page can make has actually passed and nothing was
// skipped.
//
// Two deliberate, documented differences from the Python verifier:
//  * Trusted TSA roots cannot be supplied here, so (exactly like running the
//    CLI without --trusted-cert) a valid token is flagged as not chained to a
//    trusted root. A reviewer or court should cross-check with the CLI or
//    OpenSSL per docs/verifier-decision-table.md §5.
//  * JSON numbers: JavaScript cannot distinguish `1.0` from `1`, so a
//    `packet_version` written as `1.0` is accepted here but rejected by
//    Python. No habitable release has ever emitted a non-integer version.

(function () {
  "use strict";

  var SUPPORTED_PACKET_VERSION = 1;
  var GENESIS_PREV_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

  var subtle = (typeof crypto !== "undefined" && crypto.subtle) ? crypto.subtle : null;

  // ---- canonical serialization (mirrors habitable.canonical) ---------------

  // json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
  function canonicalJson(value) {
    if (value === null || typeof value === "boolean") {
      return JSON.stringify(value);
    }
    if (typeof value === "string") {
      return JSON.stringify(value); // same escaping rules as Python for JSON text
    }
    if (typeof value === "number") {
      if (!Number.isFinite(value) || !Number.isInteger(value)) {
        throw new Error("canonical JSON: only integers are supported in this port");
      }
      return String(value);
    }
    if (Array.isArray(value)) {
      return "[" + value.map(canonicalJson).join(",") + "]";
    }
    if (typeof value === "object") {
      var keys = Object.keys(value).sort();
      var parts = [];
      for (var i = 0; i < keys.length; i++) {
        parts.push(JSON.stringify(keys[i]) + ":" + canonicalJson(value[keys[i]]));
      }
      return "{" + parts.join(",") + "}";
    }
    throw new Error("canonical JSON: unsupported value");
  }

  function encodeUtf8(text) {
    return new TextEncoder().encode(text);
  }

  function decodeUtf8(bytes) {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  }

  function hexOf(buffer) {
    var view = new Uint8Array(buffer);
    var out = "";
    for (var i = 0; i < view.length; i++) {
      out += view[i].toString(16).padStart(2, "0");
    }
    return out;
  }

  function hexToBytes(hex) {
    if (typeof hex !== "string" || hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) {
      throw new Error("not a hex string");
    }
    var out = new Uint8Array(hex.length / 2);
    for (var i = 0; i < out.length; i++) {
      out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  function b64ToBytes(b64) {
    var bin = atob(String(b64).replace(/\s+/g, ""));
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) {
      out[i] = bin.charCodeAt(i);
    }
    return out;
  }

  function bytesEqual(a, b) {
    if (a.length !== b.length) {
      return false;
    }
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff === 0;
  }

  function requireSubtle() {
    if (!subtle) {
      throw new EnvError(
        "WebCrypto (crypto.subtle) is not available in this browser context; " +
        "open this page over https:// or file:// in a modern browser"
      );
    }
    return subtle;
  }

  function sha256Hex(bytes) {
    return requireSubtle().digest("SHA-256", bytes).then(hexOf);
  }

  function digestBytes(algoName, bytes) {
    return requireSubtle().digest(algoName, bytes).then(function (buf) {
      return new Uint8Array(buf);
    });
  }

  function ed25519Verify(publicKeyBytes, message, signature) {
    var s = requireSubtle();
    return s
      .importKey("raw", publicKeyBytes, { name: "Ed25519" }, false, ["verify"])
      .then(
        function (key) {
          return s.verify({ name: "Ed25519" }, key, signature, message);
        },
        function (err) {
          throw new EnvError("Ed25519 is not supported by this browser's WebCrypto: " + err);
        }
      );
  }

  // An environment limitation (as opposed to a failed check). Fails closed but
  // is reported distinctly so the UI can say "use the CLI", not "tampered".
  function EnvError(message) {
    this.name = "EnvError";
    this.message = message;
  }
  EnvError.prototype = Object.create(Error.prototype);

  // A check failure with the same message the Python verifier would produce.
  function CheckError(message) {
    this.name = "CheckError";
    this.message = message;
  }
  CheckError.prototype = Object.create(Error.prototype);

  // ---- minimal DER reader (enough for CMS/TSTInfo/X.509 as habitable uses them)

  function derNode(bytes, offset) {
    if (offset + 2 > bytes.length) {
      throw new CheckError("malformed DER: truncated");
    }
    var tagByte = bytes[offset];
    if ((tagByte & 0x1f) === 0x1f) {
      throw new CheckError("malformed DER: high-tag-number form not supported");
    }
    var lenByte = bytes[offset + 1];
    var headerLen = 2;
    var length = 0;
    if (lenByte < 0x80) {
      length = lenByte;
    } else if (lenByte === 0x80) {
      throw new CheckError("malformed DER: indefinite length is not DER");
    } else {
      var n = lenByte & 0x7f;
      if (n > 4 || offset + 2 + n > bytes.length) {
        throw new CheckError("malformed DER: bad length");
      }
      for (var i = 0; i < n; i++) {
        length = length * 256 + bytes[offset + 2 + i];
      }
      headerLen = 2 + n;
    }
    var contentStart = offset + headerLen;
    var end = contentStart + length;
    if (end > bytes.length) {
      throw new CheckError("malformed DER: content overruns buffer");
    }
    return {
      tagByte: tagByte,
      tagClass: tagByte >> 6,
      constructed: (tagByte & 0x20) !== 0,
      tagNum: tagByte & 0x1f,
      start: offset,
      contentStart: contentStart,
      end: end,
      bytes: bytes,
    };
  }

  function derChildren(node) {
    var out = [];
    var pos = node.contentStart;
    while (pos < node.end) {
      var child = derNode(node.bytes, pos);
      out.push(child);
      pos = child.end;
    }
    return out;
  }

  function derContent(node) {
    return node.bytes.subarray(node.contentStart, node.end);
  }

  function derSlice(node) {
    return node.bytes.subarray(node.start, node.end);
  }

  function oidOf(node) {
    var content = derContent(node);
    if (content.length === 0) {
      throw new CheckError("malformed DER: empty OID");
    }
    var parts = [Math.floor(content[0] / 40), content[0] % 40];
    var value = 0;
    for (var i = 1; i < content.length; i++) {
      value = value * 128 + (content[i] & 0x7f);
      if ((content[i] & 0x80) === 0) {
        parts.push(value);
        value = 0;
      }
    }
    return parts.join(".");
  }

  var OID = {
    signedData: "1.2.840.113549.1.7.2",
    tstInfo: "1.2.840.113549.1.9.16.1.4",
    messageDigestAttr: "1.2.840.113549.1.9.4",
    sha1: "1.3.14.3.2.26",
    sha256: "2.16.840.1.101.3.4.2.1",
    sha384: "2.16.840.1.101.3.4.2.2",
    sha512: "2.16.840.1.101.3.4.2.3",
    rsaEncryption: "1.2.840.113549.1.1.1",
    sha1Rsa: "1.2.840.113549.1.1.5",
    sha256Rsa: "1.2.840.113549.1.1.11",
    sha384Rsa: "1.2.840.113549.1.1.12",
    sha512Rsa: "1.2.840.113549.1.1.13",
    ecdsaSha1: "1.2.840.10045.4.1",
    ecdsaSha256: "1.2.840.10045.4.3.2",
    ecdsaSha384: "1.2.840.10045.4.3.3",
    ecdsaSha512: "1.2.840.10045.4.3.4",
    ecPublicKey: "1.2.840.10045.2.1",
    p256: "1.2.840.10045.3.1.7",
    p384: "1.3.132.0.34",
    p521: "1.3.132.0.35",
  };

  var DIGEST_BY_OID = {};
  DIGEST_BY_OID[OID.sha1] = "SHA-1";
  DIGEST_BY_OID[OID.sha256] = "SHA-256";
  DIGEST_BY_OID[OID.sha384] = "SHA-384";
  DIGEST_BY_OID[OID.sha512] = "SHA-512";

  // signature-algorithm OID -> { kind, hash | null (fall back to digest alg) }
  var SIG_BY_OID = {};
  SIG_BY_OID[OID.rsaEncryption] = { kind: "rsa", hash: null };
  SIG_BY_OID[OID.sha1Rsa] = { kind: "rsa", hash: "SHA-1" };
  SIG_BY_OID[OID.sha256Rsa] = { kind: "rsa", hash: "SHA-256" };
  SIG_BY_OID[OID.sha384Rsa] = { kind: "rsa", hash: "SHA-384" };
  SIG_BY_OID[OID.sha512Rsa] = { kind: "rsa", hash: "SHA-512" };
  SIG_BY_OID[OID.ecdsaSha1] = { kind: "ecdsa", hash: "SHA-1" };
  SIG_BY_OID[OID.ecdsaSha256] = { kind: "ecdsa", hash: "SHA-256" };
  SIG_BY_OID[OID.ecdsaSha384] = { kind: "ecdsa", hash: "SHA-384" };
  SIG_BY_OID[OID.ecdsaSha512] = { kind: "ecdsa", hash: "SHA-512" };

  var CURVE_BY_OID = {};
  CURVE_BY_OID[OID.p256] = { name: "P-256", size: 32 };
  CURVE_BY_OID[OID.p384] = { name: "P-384", size: 48 };
  CURVE_BY_OID[OID.p521] = { name: "P-521", size: 66 };

  // ---- X.509 certificate (just the fields the verifier needs) ---------------

  function parseCertificate(certNode) {
    var top = derChildren(certNode);
    if (top.length < 1) {
      throw new CheckError("malformed certificate");
    }
    var tbsFields = derChildren(top[0]);
    var index = 0;
    if (tbsFields.length && tbsFields[0].tagClass === 2 && tbsFields[0].tagNum === 0) {
      index = 1; // explicit [0] version
    }
    // serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
    if (tbsFields.length < index + 6) {
      throw new CheckError("malformed certificate body");
    }
    return {
      serialDer: derSlice(tbsFields[index]),
      issuerDer: derSlice(tbsFields[index + 2]),
      spkiDer: derSlice(tbsFields[index + 5]),
      spkiNode: tbsFields[index + 5],
    };
  }

  function spkiAlgorithm(spkiNode) {
    var fields = derChildren(spkiNode);
    var alg = derChildren(fields[0]);
    var algOid = oidOf(alg[0]);
    if (algOid === OID.rsaEncryption) {
      return { kind: "rsa" };
    }
    if (algOid === OID.ecPublicKey) {
      var curveOid = alg.length > 1 ? oidOf(alg[1]) : "";
      var curve = CURVE_BY_OID[curveOid];
      if (!curve) {
        throw new EnvError("unsupported EC curve in TSA certificate: " + curveOid);
      }
      return { kind: "ecdsa", curve: curve };
    }
    throw new EnvError("unsupported public-key algorithm in TSA certificate: " + algOid);
  }

  function ecdsaDerToRaw(sigBytes, size) {
    var seq = derNode(sigBytes, 0);
    var ints = derChildren(seq);
    if (ints.length !== 2) {
      throw new CheckError("malformed ECDSA signature");
    }
    function fixed(intNode) {
      var content = derContent(intNode);
      var i = 0;
      while (i < content.length - 1 && content[i] === 0) {
        i++;
      }
      var trimmed = content.subarray(i);
      if (trimmed.length > size) {
        throw new CheckError("malformed ECDSA signature integer");
      }
      var out = new Uint8Array(size);
      out.set(trimmed, size - trimmed.length);
      return out;
    }
    var raw = new Uint8Array(size * 2);
    raw.set(fixed(ints[0]), 0);
    raw.set(fixed(ints[1]), size);
    return raw;
  }

  function parseGeneralizedTime(node) {
    var text = decodeUtf8(derContent(node));
    var m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z$/.exec(text);
    if (!m) {
      throw new CheckError("token has no genTime");
    }
    return m[1] + "-" + m[2] + "-" + m[3] + "T" + m[4] + ":" + m[5] + ":" + m[6] + "Z";
  }

  // ---- RFC 3161 token verification (mirrors tsa._verify_rfc3161_token) ------

  function verifyRfc3161Token(tokenBytes, digestHex, tsaName) {
    var signedData;
    var contentDer;
    var tstInfo;
    try {
      var contentInfo = derNode(tokenBytes, 0);
      var ciFields = derChildren(contentInfo);
      if (oidOf(ciFields[0]) !== OID.signedData) {
        throw new CheckError("token is not CMS SignedData");
      }
      signedData = derChildren(ciFields[1])[0]; // [0] EXPLICIT -> SignedData
      var sdFields = derChildren(signedData);
      // version, digestAlgorithms, encapContentInfo, [0] certs?, [1] crls?, signerInfos
      var encap = sdFields[2];
      var encapFields = derChildren(encap);
      if (oidOf(encapFields[0]) !== OID.tstInfo) {
        throw new CheckError("token does not encapsulate TSTInfo");
      }
      var eContent = derChildren(encapFields[1])[0]; // [0] EXPLICIT -> OCTET STRING
      contentDer = derContent(eContent);
      tstInfo = derNode(contentDer, 0);
    } catch (exc) {
      if (exc instanceof CheckError && /^token /.test(exc.message)) {
        throw exc;
      }
      throw new CheckError("malformed RFC 3161 token: " + exc.message);
    }

    var tstFields = derChildren(tstInfo);
    // version, policy, messageImprint, serialNumber, genTime, ...
    var imprintFields = derChildren(tstFields[2]);
    var imprintAlg = oidOf(derChildren(imprintFields[0])[0]);
    if (imprintAlg !== OID.sha256) {
      throw new CheckError("token imprint is not SHA-256");
    }
    if (!bytesEqual(derContent(imprintFields[1]), hexToBytes(digestHex))) {
      throw new CheckError("token imprint does not match the content digest");
    }

    var sdFields2 = derChildren(signedData);
    var certsNode = null;
    var signerInfosNode = null;
    for (var i = 3; i < sdFields2.length; i++) {
      var field = sdFields2[i];
      if (field.tagClass === 2 && field.tagNum === 0) {
        certsNode = field;
      } else if (field.tagClass === 0 && field.tagNum === 17) {
        signerInfosNode = field; // SET OF SignerInfo
      }
    }
    if (!signerInfosNode) {
      throw new CheckError("malformed RFC 3161 token: no signerInfos");
    }
    var signerInfo = derChildren(signerInfosNode)[0];
    var siFields = derChildren(signerInfo);
    // version, sid, digestAlgorithm, [0] signedAttrs?, signatureAlgorithm, signature
    var sid = siFields[1];
    var digestAlgOid = oidOf(derChildren(siFields[2])[0]);
    var cursor = 3;
    var signedAttrs = null;
    if (siFields[cursor] && siFields[cursor].tagClass === 2 && siFields[cursor].tagNum === 0) {
      signedAttrs = siFields[cursor];
      cursor++;
    }
    var sigAlgOid = oidOf(derChildren(siFields[cursor])[0]);
    var signatureBytes = derContent(siFields[cursor + 1]);

    var signerCert = findSignerCert(certsNode, sid);
    if (!signerCert) {
      throw new CheckError("token does not contain its signing certificate");
    }

    if (!signedAttrs) {
      throw new CheckError("token signer has no signed attributes");
    }
    var digestName = DIGEST_BY_OID[digestAlgOid];
    if (!digestName) {
      throw new EnvError("unsupported digest algorithm in token: " + digestAlgOid);
    }
    var sigSpec = SIG_BY_OID[sigAlgOid];
    if (!sigSpec) {
      throw new EnvError("unsupported signature algorithm: " + sigAlgOid);
    }
    var sigHash = sigSpec.hash || digestName;

    var messageDigestAttr = null;
    var attrs = derChildren(signedAttrs);
    for (var a = 0; a < attrs.length; a++) {
      var attrFields = derChildren(attrs[a]);
      if (oidOf(attrFields[0]) === OID.messageDigestAttr) {
        messageDigestAttr = derContent(derChildren(attrFields[1])[0]);
      }
    }

    return digestBytes(digestName, contentDer).then(function (contentDigest) {
      if (!messageDigestAttr || !bytesEqual(messageDigestAttr, contentDigest)) {
        throw new CheckError("signed message-digest attribute does not match TSTInfo");
      }
      // The signature is over the signedAttrs re-tagged as an explicit SET OF
      // (the [0] IMPLICIT tag is replaced by 0x31) — standard CMS behavior.
      var toVerify = new Uint8Array(derSlice(signedAttrs));
      toVerify[0] = 0x31;

      var parsed = parseCertificate(signerCert);
      var keyAlg = spkiAlgorithm(parsed.spkiNode);
      var s = requireSubtle();
      var importPromise;
      var verifyAlg;
      var sig = signatureBytes;
      if (sigSpec.kind === "rsa" && keyAlg.kind === "rsa") {
        importPromise = s.importKey(
          "spki", parsed.spkiDer, { name: "RSASSA-PKCS1-v1_5", hash: sigHash }, false, ["verify"]
        );
        verifyAlg = { name: "RSASSA-PKCS1-v1_5" };
      } else if (sigSpec.kind === "ecdsa" && keyAlg.kind === "ecdsa") {
        importPromise = s.importKey(
          "spki", parsed.spkiDer, { name: "ECDSA", namedCurve: keyAlg.curve.name }, false, ["verify"]
        );
        verifyAlg = { name: "ECDSA", hash: sigHash };
        sig = ecdsaDerToRaw(signatureBytes, keyAlg.curve.size);
      } else {
        throw new CheckError(
          "unsupported signature algorithm: " + sigSpec.kind + " with this key type"
        );
      }
      return importPromise
        .then(
          function (key) {
            return s.verify(verifyAlg, key, sig, toVerify);
          },
          function (err) {
            throw new EnvError("could not import the TSA public key: " + err);
          }
        )
        .then(function (ok) {
          if (!ok) {
            throw new CheckError("token signature is invalid");
          }
          var genTimeNode = tstFields[4];
          return {
            kind: "rfc3161",
            tsa_name: tsaName,
            gen_time: parseGeneralizedTime(genTimeNode),
            trusted_chain: false, // no trusted roots can be supplied in-browser
          };
        });
    });
  }

  function findSignerCert(certsNode, sid) {
    if (!certsNode || sid.tagClass !== 0) {
      return null; // subjectKeyIdentifier sid form is not produced by habitable TSAs
    }
    var sidFields = derChildren(sid); // IssuerAndSerialNumber: issuer Name, serial INTEGER
    var wantIssuer = derSlice(sidFields[0]);
    var wantSerial = derSlice(sidFields[1]);
    var certs = derChildren(certsNode);
    for (var i = 0; i < certs.length; i++) {
      try {
        var parsed = parseCertificate(certs[i]);
        if (bytesEqual(parsed.serialDer, wantSerial) && bytesEqual(parsed.issuerDer, wantIssuer)) {
          return certs[i];
        }
      } catch (exc) {
        /* skip unparseable certificate entries */
      }
    }
    return null;
  }

  // ---- dev token verification (mirrors tsa._verify_dev_token) ---------------

  function verifyDevToken(tokenBytes, digestHex) {
    var doc;
    try {
      doc = JSON.parse(decodeUtf8(tokenBytes));
    } catch (exc) {
      return Promise.reject(new CheckError("dev token is not valid JSON"));
    }
    if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
      return Promise.reject(new CheckError("dev token must be an object"));
    }
    var sig = doc.sig;
    delete doc.sig;
    if (typeof sig !== "string") {
      return Promise.reject(new CheckError("dev token missing signature"));
    }
    if (typeof doc.pubkey !== "string") {
      return Promise.reject(new CheckError("dev token missing pubkey"));
    }
    return ed25519Verify(b64ToBytes(doc.pubkey), encodeUtf8(canonicalJson(doc)), b64ToBytes(sig))
      .then(function (ok) {
        if (!ok) {
          throw new CheckError("dev token signature is invalid");
        }
        if (doc.digest !== digestHex) {
          throw new CheckError("dev token digest does not match the content");
        }
        if (typeof doc.gen_time !== "string") {
          throw new CheckError("dev token missing gen_time");
        }
        return {
          kind: "dev",
          tsa_name: typeof doc.tsa_name === "string" ? doc.tsa_name : "dev-tsa",
          gen_time: doc.gen_time,
          trusted_chain: false,
        };
      });
  }

  // ---- token dispatch (mirrors tsa.verify_token, no trusted roots) ----------

  function verifyToken(tokenDict, digestHex) {
    if (typeof tokenDict !== "object" || tokenDict === null) {
      return Promise.reject(new CheckError("token must be an object"));
    }
    var kind = tokenDict.kind;
    var name = tokenDict.tsa_name;
    var tokenB64 = tokenDict.token_b64;
    if (typeof kind !== "string" || typeof name !== "string" || typeof tokenB64 !== "string") {
      return Promise.reject(new CheckError("malformed timestamp token record"));
    }
    var bytes;
    try {
      bytes = b64ToBytes(tokenB64);
    } catch (exc) {
      return Promise.reject(new CheckError("malformed timestamp token record"));
    }
    if (kind === "rfc3161") {
      return Promise.resolve().then(function () {
        return verifyRfc3161Token(bytes, digestHex, name);
      });
    }
    if (kind === "dev") {
      return verifyDevToken(bytes, digestHex);
    }
    return Promise.reject(new CheckError("unknown token kind: " + kind));
  }

  // ---- chain of custody (mirrors evidence.CustodyLog + verify._verify_custody)

  function custodyPublicPayload(record) {
    function str(key) {
      var value = record[key];
      if (typeof value !== "string") {
        throw new CheckError("custody field '" + key + "' must be a string");
      }
      return value;
    }
    var seq = record.seq;
    if (typeof seq !== "number" || !Number.isInteger(seq) || typeof seq === "boolean") {
      throw new CheckError("custody field 'seq' must be an integer");
    }
    var rawDetails = record.details === undefined ? {} : record.details;
    if (typeof rawDetails !== "object" || rawDetails === null || Array.isArray(rawDetails)) {
      throw new CheckError("custody entry 'details' must be an object");
    }
    var details = {};
    var keys = Object.keys(rawDetails).sort();
    for (var i = 0; i < keys.length; i++) {
      details[keys[i]] = String(rawDetails[keys[i]]);
    }
    return {
      seq: seq,
      action: str("action"),
      item_id: str("item_id"),
      hlc: str("hlc"),
      actor_commitment: str("actor_commitment"),
      details: details,
      prev_hash: str("prev_hash"),
    };
  }

  function verifyCustody(bundle) {
    var proof = bundle.custody_proof;
    if (typeof proof !== "object" || proof === null || Array.isArray(proof)) {
      proof = {};
    }
    var rawEntries = Array.isArray(proof.entries) ? proof.entries : [];
    var records = rawEntries.filter(function (e) {
      return typeof e === "object" && e !== null && !Array.isArray(e);
    });

    var walk = Promise.resolve({ prev: GENESIS_PREV_HASH, bindings: {} });
    records.forEach(function (record, index) {
      walk = walk.then(function (state) {
        var payload = custodyPublicPayload(record); // throws CheckError when malformed
        if (payload.seq !== index + 1) {
          throw new CheckError("custody chain out of order at position " + index);
        }
        if (payload.prev_hash !== state.prev) {
          throw new CheckError("custody chain broken at seq " + payload.seq);
        }
        var entryHash = record.entry_hash;
        if (typeof entryHash !== "string") {
          throw new CheckError("custody field 'entry_hash' must be a string");
        }
        return sha256Hex(encodeUtf8(canonicalJson(payload))).then(function (recomputed) {
          if (recomputed !== entryHash) {
            throw new CheckError("custody entry seq " + payload.seq + " has been altered");
          }
          if (payload.action === "copied_for_sharing") {
            var content = payload.details.content_hash || "";
            var shared = payload.details.shared_hash || "";
            if (!state.bindings[payload.item_id]) {
              state.bindings[payload.item_id] = [];
            }
            state.bindings[payload.item_id].push(content + " " + shared);
          }
          state.prev = entryHash;
          return state;
        });
      });
    });

    return walk.then(
      function (state) {
        var headOk = proof.head_hash === state.prev;
        return {
          custody_ok: headOk,
          custody_length: records.length,
          bindings: state.bindings,
        };
      },
      function (exc) {
        if (exc instanceof EnvError) {
          throw exc; // an environment gap must not report "broken chain"
        }
        // Any parse/walk failure is a broken chain, never a crash — and the
        // bindings are withheld, exactly like the Python verifier.
        return { custody_ok: false, custody_length: records.length, bindings: {} };
      }
    );
  }

  // ---- bundle signature (mirrors verify._verify_signature) ------------------

  function verifySignatureFile(sigBytes, bundleHashHex) {
    if (!sigBytes) {
      return Promise.resolve(false);
    }
    return Promise.resolve()
      .then(function () {
        var doc = JSON.parse(decodeUtf8(sigBytes));
        if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
          return false;
        }
        if (doc.bundle_sha256 !== bundleHashHex) {
          return false;
        }
        if (typeof doc.sign_public !== "string" || typeof doc.signature !== "string") {
          return false;
        }
        return ed25519Verify(
          b64ToBytes(doc.sign_public),
          encodeUtf8(bundleHashHex),
          b64ToBytes(doc.signature)
        );
      })
      .catch(function (exc) {
        if (exc instanceof EnvError) {
          throw exc;
        }
        return false; // any malformed signature file is a failed signature
      });
  }

  // ---- per-item verification (mirrors verify._verify_item) ------------------

  function verifyItem(item, files, bindings, limits) {
    var captureId = typeof item.capture_id === "string" ? item.capture_id : "";
    var contentHash = typeof item.content_hash === "string" ? item.content_hash : "";
    var sharedName = typeof item.shared_name === "string" ? item.shared_name : "";
    var sharedHash = typeof item.shared_hash === "string" ? item.shared_hash : "";
    var notes = [];
    var state = {
      capture_id: captureId,
      content_hash: contentHash,
      timestamp_verified: false,
      gen_time: "",
      tsa_name: "",
      shared_media_ok: true,
      custody_binding_ok: true,
      original_fixity_ok: null,
      verified_authorities: [],
    };

    var chain = Promise.resolve();

    // 1. Trusted timestamp(s): primary token, archive chain, then redundant
    //    additional authorities over the same content hash.
    var tokenRaw = item.timestamp;
    if (typeof tokenRaw === "object" && tokenRaw !== null && !Array.isArray(tokenRaw)) {
      chain = chain
        .then(function () {
          return verifyToken(tokenRaw, contentHash);
        })
        .then(function (info) {
          state.timestamp_verified = true;
          state.gen_time = info.gen_time;
          state.tsa_name = info.tsa_name;
          state.verified_authorities.push(info.tsa_name);
          if (!info.trusted_chain) {
            notes.push("timestamp valid but authority not chained to a trusted root");
          }
          var archivesRaw = item.archive_timestamps;
          var archives = Array.isArray(archivesRaw)
            ? archivesRaw.filter(function (a) {
                return typeof a === "object" && a !== null && !Array.isArray(a);
              })
            : [];
          if (!archives.length) {
            return null;
          }
          // Each archive token must stamp the SHA-256 of the previous token's
          // bytes (tsa.verify_archive_chain).
          var previousBytes = b64ToBytes(tokenRaw.token_b64);
          var archiveChain = Promise.resolve();
          archives.forEach(function (archive) {
            archiveChain = archiveChain.then(function () {
              return sha256Hex(previousBytes)
                .then(function (prevDigest) {
                  return verifyToken(archive, prevDigest);
                })
                .then(function () {
                  previousBytes = b64ToBytes(archive.token_b64);
                });
            });
          });
          return archiveChain.then(function () {
            notes.push("archive-timestamped (" + archives.length + " link(s))");
          });
        })
        .catch(function (exc) {
          // Mirrors the Python verifier: a failure here adds a note but does not
          // undo an already-verified primary (e.g. a bad archive link); and a
          // failed primary does not, by itself, condemn the item if a redundant
          // authority below still verifies the same content hash.
          if (exc instanceof EnvError) {
            limits.push("item " + captureId + ": " + exc.message);
            notes.push("primary timestamp not verifiable in this browser: " + exc.message);
            return;
          }
          notes.push("primary timestamp check failed: " + exc.message);
        });
    } else {
      notes.push("awaiting timestamp");
    }

    var additionalRaw = item.additional_timestamps;
    if (Array.isArray(additionalRaw)) {
      additionalRaw.forEach(function (extraRaw) {
        if (typeof extraRaw !== "object" || extraRaw === null || Array.isArray(extraRaw)) {
          return;
        }
        chain = chain.then(function () {
          return verifyToken(extraRaw, contentHash).then(
            function (extraInfo) {
              state.verified_authorities.push(extraInfo.tsa_name);
              notes.push("also timestamped by " + extraInfo.tsa_name);
              if (!extraInfo.trusted_chain) {
                notes.push(
                  "additional authority " + extraInfo.tsa_name +
                  " not chained to a trusted root"
                );
              }
              if (!state.timestamp_verified) {
                state.timestamp_verified = true;
                state.gen_time = extraInfo.gen_time;
                state.tsa_name = extraInfo.tsa_name;
              }
            },
            function (exc) {
              if (exc instanceof EnvError) {
                limits.push("item " + captureId + ": " + exc.message);
                notes.push("additional timestamp not verifiable in this browser: " + exc.message);
                return;
              }
              notes.push("additional timestamp check failed: " + exc.message);
            }
          );
        });
      });
    }

    // 2. Shared media hashes to its recorded shared_hash.
    chain = chain.then(function () {
      if (!sharedName) {
        notes.push("no shared media included for this item");
        return null;
      }
      var media = files.lookup("media/" + sharedName);
      if (!media) {
        state.shared_media_ok = false;
        notes.push("shared media file missing");
        return null;
      }
      return sha256Hex(media).then(function (digest) {
        if (digest !== sharedHash) {
          state.shared_media_ok = false;
          notes.push("shared media does not match its recorded hash");
        }
      });
    });

    // 3. Custody binds the shared copy to the sealed original's content hash.
    chain = chain.then(function () {
      if (sharedName) {
        var bound = (bindings[captureId] || []).indexOf(contentHash + " " + sharedHash) !== -1;
        state.custody_binding_ok = bound;
        if (!bound) {
          notes.push("no signed custody entry binds the shared copy to the original");
        }
      }
    });

    // 4. If the sealed original is embedded, re-derive its content hash.
    chain = chain.then(function () {
      var original = files.lookup("originals/" + captureId);
      if (!original) {
        return null;
      }
      return sha256Hex(original).then(function (digest) {
        state.original_fixity_ok = digest === contentHash;
        if (!state.original_fixity_ok) {
          notes.push("embedded original failed fixity");
        }
      });
    });

    return chain.then(function () {
      state.notes = notes;
      state.ok =
        state.timestamp_verified &&
        state.shared_media_ok &&
        state.custody_binding_ok &&
        state.original_fixity_ok !== false;
      return state;
    });
  }

  // ---- file-map handling -----------------------------------------------------

  // entries: [{ path, bytes: Uint8Array }] — path may be a bare filename (flat
  // multi-file selection) or a relative path (folder selection / drag-and-drop).
  function makeFileMap(entries) {
    var byPath = {};
    var byBase = {};
    entries.forEach(function (entry) {
      var path = String(entry.path || "").replace(/\\/g, "/").replace(/^\/+/, "");
      byPath[path] = entry.bytes;
      var base = path.split("/").pop();
      if (!(base in byBase)) {
        byBase[base] = entry.bytes;
      } else {
        byBase[base] = null; // ambiguous basename: only exact paths may match it
      }
    });
    var root = "";
    var bundleKeys = Object.keys(byPath).filter(function (p) {
      return p === "bundle.json" || /\/bundle\.json$/.test(p);
    });
    if (bundleKeys.length) {
      bundleKeys.sort(function (a, b) { return a.length - b.length; });
      root = bundleKeys[0].slice(0, -"bundle.json".length);
    }
    return {
      lookup: function (relpath) {
        if (Object.prototype.hasOwnProperty.call(byPath, root + relpath)) {
          return byPath[root + relpath];
        }
        if (Object.prototype.hasOwnProperty.call(byPath, relpath)) {
          return byPath[relpath];
        }
        var base = relpath.split("/").pop();
        if (Object.prototype.hasOwnProperty.call(byBase, base) && byBase[base]) {
          return byBase[base];
        }
        return null;
      },
    };
  }

  // ---- packet verification (mirrors verify.verify_packet) --------------------

  function checkPacketVersion(bundle) {
    var version = bundle.packet_version;
    if (typeof version !== "number" || !Number.isInteger(version)) {
      return "bundle has no integer packet_version";
    }
    if (version > SUPPORTED_PACKET_VERSION) {
      return (
        "packet_version " + version + " is newer than supported " +
        SUPPORTED_PACKET_VERSION + "; upgrade habitable to verify this packet"
      );
    }
    return null;
  }

  function summarize(report) {
    var total = report.items.length;
    if (report.ok) {
      return (
        report.verified_items + "/" + total +
        " items verify against their sealed originals and timestamp tokens — packet intact"
      );
    }
    return (
      report.verified_items + "/" + total + " items verified; " +
      "signature=" + (report.signature_ok ? "ok" : "FAILED") + ", " +
      "custody=" + (report.custody_ok ? "ok" : "BROKEN") + " — packet NOT intact"
    );
  }

  // entries: [{ path, bytes }]. Resolves to a report object (shape mirrors
  // `habitable verify --json`, plus `browser_limits`), or `{ error }` for the
  // two pre-structural conditions the Python verifier raises on.
  function verifyPacket(entries) {
    return Promise.resolve().then(function () {
      var files = makeFileMap(entries);
      var bundleBytes = files.lookup("bundle.json");
      if (!bundleBytes) {
        return { error: "no bundle.json in the selected files" };
      }
      var bundle;
      try {
        bundle = JSON.parse(decodeUtf8(bundleBytes));
      } catch (exc) {
        return { error: "bundle is not valid JSON: " + exc.message };
      }
      if (typeof bundle !== "object" || bundle === null || Array.isArray(bundle)) {
        return { error: "bundle must be a JSON object" };
      }

      var limits = [];
      var report = {
        ok: false,
        summary: "",
        signature_ok: false,
        custody_ok: false,
        custody_length: 0,
        verified_items: 0,
        item_count: 0,
        problems: [],
        items: [],
        browser_limits: limits,
      };

      return sha256Hex(bundleBytes)
        .then(function (bundleHash) {
          return verifySignatureFile(files.lookup("bundle.sig.json"), bundleHash).catch(
            function (exc) {
              if (exc instanceof EnvError) {
                limits.push("bundle signature: " + exc.message);
                return false; // fail closed: unverifiable is not verified
              }
              throw exc;
            }
          );
        })
        .then(function (signatureOk) {
          report.signature_ok = signatureOk;
          var versionProblem = checkPacketVersion(bundle);
          if (versionProblem !== null) {
            report.problems.push(versionProblem);
            return report; // early return: custody forced false, items empty
          }
          return verifyCustody(bundle)
            .then(function (custody) {
              report.custody_ok = custody.custody_ok;
              report.custody_length = custody.custody_length;
              var itemsRaw = Array.isArray(bundle.items) ? bundle.items : [];
              var chain = Promise.resolve();
              itemsRaw.forEach(function (raw) {
                chain = chain.then(function () {
                  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
                    report.problems.push("malformed item in bundle");
                    return null;
                  }
                  return verifyItem(raw, files, custody.bindings, limits).then(function (verdict) {
                    report.items.push(verdict);
                  });
                });
              });
              return chain;
            })
            .then(function () {
              return report;
            });
        })
        .then(function () {
          report.item_count = report.items.length;
          report.verified_items = report.items.filter(function (item) {
            return item.ok;
          }).length;
          report.ok =
            report.signature_ok &&
            report.custody_ok &&
            report.problems.length === 0 &&
            report.items.every(function (item) {
              return item.ok;
            }) &&
            limits.length === 0; // fail closed on any environment gap
          report.summary = summarize(report);
          return report;
        });
    }).catch(function (exc) {
      if (exc instanceof EnvError) {
        return { error: exc.message };
      }
      throw exc;
    });
  }

  var api = {
    SUPPORTED_PACKET_VERSION: SUPPORTED_PACKET_VERSION,
    verifyPacket: verifyPacket,
    canonicalJson: canonicalJson,
  };

  if (typeof globalThis !== "undefined") {
    globalThis.HabitableVerifier = api;
  }
})();
