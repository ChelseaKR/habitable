# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/). The **packet format** and the
**verification protocol** are versioned independently (see `docs/evidence-method.md`).

## [Unreleased]

### Fixed

- **An expired TSA certificate no longer mints indefinitely-trusted timestamps**
  (#204, split from #121). `_verify_cert_chain` matched an anchor by fingerprint
  or direct issuance and stopped there, so a certificate that expired years ago
  went on producing `trusted_chain: True` forever — in the one field a recipient
  reads to decide whether a timestamp is from who it says. The signing
  certificate must now have been inside its own validity period at the token's
  `genTime`. The comparison is against `genTime` and never the wall clock, so a
  packet minted in 2021 still verifies in 2031 after its authority rotates a key;
  what stops is an authority minting *new* tokens on a dead certificate.

  The outcome is reported in its own `TimestampInfo.cert_validity` field
  (`within` / `expired` / `not-yet-valid` / `not-applicable` / `not-checked`)
  rather than folded silently into `trusted_chain`, because "expiry was checked
  and was fine" and "expiry was not checked" are different facts. The note for a
  matched-but-expired anchor says so in those words, so a recipient who supplied
  exactly the right certificate is not sent off to re-download it. `ANCHOR_RULE`
  and four documents that stated validity was never consulted are corrected.

- **Corrupt KDF parameters fail as `CryptoError`, not a raw traceback** (#212).
  `crypto.py` promises in its module docstring that every failure surfaces as
  `CryptoError`; `KdfParams.from_dict` type-checked `n`/`r`/`p`/`length` and
  passed them straight to scrypt. Since `cli.main()` catches only
  `HabitableError`, a bit-rotted keyfile or a courier-damaged recovery blob
  crashed `habitable key restore` with an unhandled traceback. Three library
  exceptions escaped, not the one reported: `ValueError`, `OverflowError` (which
  does *not* subclass `ValueError`), and `MemoryError` — the last a
  resource-exhaustion vector, since a single flipped digit in `n` can ask scrypt
  for a terabyte. Parameters are now screened by arithmetic before scrypt sees
  them, with a memory ceiling derived from the project's own `KDF_PROFILES`.

- **A packet's metadata disclosure no longer contradicts its own item records**
  (#211). `_disclosures` built the prominent "What this packet discloses" line
  from the configured `SharingPolicy` alone. But `make_shared_media_copy` always
  remuxes video and audio with `-map_metadata -1` regardless of policy, so under
  a deliberate retain-metadata policy the packet told its reader that a video's
  embedded location had been kept while the same signed bundle's item record said
  it was removed. The harm runs the surprising way: a tenant who chose that policy
  specifically to preserve a video's GPS as evidence was told they had it. The
  disclosure is now derived from the items' own `stripped` fields, and the
  policy-derived sentence is scoped to still images.

- **`scope_statement` resolves regional locale tags like its siblings** (#210).
  `habitable init --lang es-MX` produced a Spanish packet whose "Scope of this
  export" section — the one stating whether the packet covers the whole unit or a
  single issue — silently reverted to English. Two of `disclosure.py`'s three
  lookups normalized the tag and the third did an exact-match lookup. All three
  now share one resolver, since the defect was drift between hand-rolled copies.

- **Keyboard focus no longer lands off-screen while tabbing** (#202). Re-diagnosed
  before fixing: the report blamed tab order leaking into a stale "underlying Atlas
  view" and proposed `inert`, which would have deleted real controls from the
  keyboard path — the app is a single scrolling document with no view switching.
  The actual cause is `scroll-behavior: smooth`, wanted for the skip link and
  anchors, also animating the scroll that Tab triggers; the animation is slower
  than a keypress. At ordinary typing speed 20 focus stops landed outside the
  viewport with the focus ring painted where nobody could see it (WCAG 2.4.7,
  2.4.3); with a generous settle, none did. Focus is now snapped into view
  instantly, leaving anchor navigation smooth.

### Added

- **`habitable issue --category`/`--severity` are validated against a vocabulary**
  (#206). They accepted arbitrary free text while `timeline --type`/`--source`
  next door were enum-constrained, so a mistyped category was accepted silently
  and — with no correction path and export scoping blocked (#203) — rode into the
  exported packet. `other` remains available with a required `--other-label` /
  `--severity-detail`, because a closed vocabulary with no escape hatch would
  force a real condition to be misfiled. Validation is at CLI entry only:
  categories already stored in a vault are grandfathered and keep loading. The
  local web app's free-text condition field is unchanged and is documented as a
  known scope boundary.

- **A third letter framing profile, `ew_disrepair`** (#207), for England and
  Wales. Presentation-only wording held to the same bar as its two siblings: no
  statute, no section number, and no jurisdiction-specific deadline. Marked
  UNREVIEWED in source — no solicitor or advice worker for that jurisdiction has
  read it.

### Changed

- **The planning documents stopped reserving work that had already shipped.**
  #228 corrected `docs/capabilities.md` and `docs/letter-generator.md` when
  `ew_disrepair` landed, but `ROADMAP.md` and `docs/novel-use-cases-plan.md`
  were not in that sweep and still described jurisdiction template growth as
  unstarted: "left open for a first-time contributor (issue #207)", "reserved as
  good first issue #207", "deliberately reserved for a first-time contributor".
  The framing had shipped on 2026-08-28 and the issue is closed, so a reader
  planning contribution was being pointed at finished work. All four claims now
  say what is true — the engineering path is walked, further framings stay open
  to a newcomer, and what remains gated on a named legal reviewer is a
  *reviewed* framing, since all three that ship are UNREVIEWED for their
  jurisdiction.

  The half of that this project can check mechanically is now checked.
  `test_current_state_docs_name_every_framing_that_ships` holds every
  describes-what-ships-today document to a conditional rule: a document that
  names one built-in framing must name all of them, so a partial list can never
  read as the complete one. It is conditional on purpose — prose that never
  enumerates the framings is left alone — and ADRs and this changelog are
  excluded on purpose, because they are dated records and editing them to
  mention later work would falsify exactly the property the guard protects.
  FAIL-BEFORE against the pre-fix plan: `names ['generic', 'us_habitability']
  but not ['ew_disrepair']`.

  The prose claim about *whether an issue is still open* has no offline check
  behind it and does not now: that would need the issue tracker. It was found by
  reading, and this entry says so rather than implying the new guard covers it.

- **Several gates that could not fail were repaired.** A site test guarding the
  "do not put tenant data in a public issue" warning had never executed a single
  assertion: it matched a URL that appears nowhere on the site, and iterated a
  page list that excluded the only page carrying public issue links. Repaired, it
  immediately found the real gap, and `site/review/index.html` now carries the
  data boundary its linked issues already state. The `pytest -m a11y` suite —
  behind a *required* status check — exits 0 when every test skips for want of a
  browser; that is now a hard failure in CI plus a floor on the selected count.
  `check_bcp47.py`'s "no tags found" guard was dead code, since one always-populated
  source ran first; each of its five sources now carries its own floor.
  `test_format_date_month_abbreviations` asserted only that output was non-empty
  and contained the year; it now checks the abbreviations. Archive-timestamp trust
  verdicts were computed and discarded; the note now reports them. Plus a
  non-emptiness floor on the `aria-describedby` scan, `.NOTPARALLEL:` so
  `verify`'s documented lock-check ordering survives `make -j`, a lockstep test
  for the docs-only a11y twin's path list, and a corrected `.pre-commit-config.yaml`
  comment that claimed a scope equivalence with `make lint` that was never true.

### Added

- **The published sample packet said nothing about being indexed, and the
  sitemap had gone stale.** A technical SEO audit of habitable.chelseakr.com
  found `site/sample-packet/packet.html` reachable and linked from the
  homepage, absent from `sitemap.xml`, and carrying no `robots` directive, so
  a crawler was free to index a synthetic tenancy record as an ordinary page of
  this site. `docs/research/product-expansion-seo-2026-07-09.md` had called for
  exactly the opposite and nothing had implemented it.

  Both packet renderers in `src/habitable/htmlpacket.py` now emit
  `<meta name="robots" content="noindex, nofollow">`. A packet is a record
  about somebody's home -- rooms, dates, photographs, the conditions they are
  living in -- and wherever one ends up behind a web server it should not be
  for a search engine to collect. A `noindex` cannot stop a determined crawler
  and does not pretend to; it stops the ordinary well-behaved ones, which is
  the difference between a packet being findable by name and findable at all.

  `tests/test_site_seo.py` gains the check that would have caught it: every
  `.html` file under `site/` is either offered for indexing in the sitemap or
  says it is not for indexing. A page can be left out. It cannot be left out
  silently.

- **`campaign export` seals each unit packet, with that unit's own authority.**
  ADR 0011 listed `campaign export` among the surfaces it had left unsealed, and
  the gap was sharper than a missing feature: `campaign.py`'s own docstring
  promises that "a unit's packet is exactly what `habitable export` already
  produces", and since ADR 0011 that includes an RFC 3161 token over the whole
  bundle. Every combined building packet built since then contained packets
  weaker than the same vault would have exported on its own, and said nothing
  about it.

  The authority is resolved **per vault**, not per campaign, and so is the
  metered-link gate: it is that tenant's configured authority and that tenant's
  link and data allowance, so an organizer's single choice never overrides six
  tenants' configurations. `--no-seal` and `--dev-tsa` behave exactly as they do
  for `export`, and `--wifi-only`/`--allow-metered` apply per unit.

  Sealing stays best-effort per unit, which is ADR 0011's own degradation: an
  unconfigured, unreachable, or metered-gated authority costs that packet its
  seal, never its existence, and never anybody else's seal. The operator is told
  which of the four things happened for each unit, because "you passed
  --no-seal", "this unit's link is metered", "this unit configured no authority"
  and "the authority could not be reached" are different facts and only the
  first two are knowable at the call site.

  Seal state is written into **neither the manifest nor the index page**, for
  the reason ADR 0011 kept it out of `disclosures`: a seal is a file an attacker
  can delete, so a rendering that announced one would be confidently wrong the
  moment it was stripped. It is reported to the operator at build time and to
  the recipient by `habitable verify --require-packet-seal`.

  This needed no ADR of its own: ADR 0011 made the decision and named this
  surface as unfinished, so this executes it. One existing test now passes
  `--no-seal`, because `conftest`'s outbound-network guard correctly caught the
  merge gate newly depending on a real public TSA, exactly as it was written to.

- **A packet dropped from a joint submission is no longer undetectable.** The
  joint index (ADR 0015) recomputes every listed member's digest, which speaks
  only for members still on the list. A submission that arrives with a
  household quietly removed leaves every remaining packet valid, every
  remaining digest correct, and nothing unlisted on disk. For a building-wide
  submission that is the damaging direction: the packet a landlord would most
  like missing is the one that is missing.

  `habitable joint build --seal-tsa URL` now asks an authority to countersign
  the finished index, writing the token to `joint_index.sig.json` in the same
  record shape `bundle.sig.json` already uses. Removing a row changes the bytes
  that token covers, and no attacker can mint a replacement.

  This is ADR 0011's mechanism, with its three rules inherited and none of them
  softened: a present seal is always checked against the index in front of it,
  an absent seal is reported rather than fatal until the recipient passes
  `habitable joint check --require-seal`, and every assertion fails closed. A
  `dev` seal verifies and is never trusted. `--seal-not-after <the day the
  submission reached you>` catches the one residual an authority cannot help
  with: an attacker who can reach an anchored authority can re-seal a rewritten
  list, but cannot backdate the token.

  It was chosen over signing the index with an organizer key, which is the
  substantive decision: a signature would require inventing an organizer
  identity, a key, a distribution story, and a name attached to a document that
  travels to a landlord's lawyer. ADR 0011 already declined that for producers
  on safety grounds. The index therefore still carries **no signature of its
  own** and `index_signed` stays `false`; a seal and a signature are different
  claims and this project has kept them apart since ADR 0008.

  Nothing is sealed by default: sealing is the one part of `joint` that touches
  the network, and the organizer names the authority. Rebuilding without one
  deletes a stale sidecar rather than leaving a token beside bytes it no longer
  covers. `joint_index_version` stays 1, so an index written before this change
  parses identically and reports an absent seal, which is the truth about it.
  See `docs/adr/0016-authority-seal-over-the-joint-index.md`.

- **An organizer can hand over several tenants' packets as one submission,
  without merging anything.** `docs/novel-use-cases-plan.md` ranks a joint
  multi-tenant case bundle as candidate #13 and specifies the only safe shape
  for it: "closer to a signed table of contents over N already-signed
  `bundle.json` files than a new packet shape," because a merged custody chain
  would reopen the scoped and rehashed custody-view gate workstream A is still
  closing.

  `habitable joint build` writes exactly that, beside packets it never
  modifies. This is the organizer `campaign` cannot serve: `campaign` rolls up
  vaults whose keys the organizer holds, and the commoner situation in a union
  is six households who each exported on their own device and handed over a
  folder. No key, no vault, and no network is involved.

  Each row binds its member by the SHA-256 of that packet's own `bundle.json`
  bytes, which is the same digest the member's signature covers and an
  authority seals. `habitable joint check` then re-derives every recorded claim
  from the packets themselves: it recomputes the digest and throws away the
  recorded readiness in favour of a fresh `verify_packet` verdict. A doctored
  index therefore cannot produce a passing verdict, and a packet directory
  present beside the index but missing from it is reported and fails the check
  rather than being absorbed. A submission subdirectory with no `bundle.json`
  is refused by name, never skipped.

  The index is presentation only and carries **no signature of its own**, which
  it says in its JSON (`index_signed: false`), in its HTML, and in the
  command's output, alongside two other limits it must not let a reader assume
  away: it merges no chain of custody, and listing households together says
  nothing about whether their conditions share a cause. ADR 0015 named two
  candidate mechanisms for authenticating the index itself and deferred the
  choice between them; ADR 0016 made it later in the same cycle, so this entry
  is read alongside the authority seal above. As shipped, the index is
  unsigned, and can be sealed.

  `packet_version` stays 4, `bundle.json` and `bundle.sig.json` are untouched,
  and `habitable.verify` gains no import: the index carries its own
  `joint_index_version`, because it is not a packet. Without a `--trusted-cert`
  anchor no member is evidence-ready and the command exits non-zero, exactly as
  `habitable verify` does. See
  `docs/adr/0015-joint-multi-tenant-submission-index.md`.

- **The repair-request letter's jurisdiction wording is now dated, and lapsed
  wording is withheld instead of sent.** `ROADMAP.md` (workstream E) and
  `docs/novel-use-cases-plan.md` (candidate #12) both queue jurisdiction
  template growth on the stated precondition that jurisdictions expand "only
  with dated owners and expiry policy — now enforceable rather than
  aspirational (ADR 0012)." That precondition was not true here: ADR 0012's
  machinery lives on `UseCaseProfile`, and `LetterProfile` had no reviewer, no
  review date, and no expiry at all.

  It matters most on this surface. `docs/letter-generator.md` designates
  `[letter] header`/`footer` as the home for a **locally verified statutory
  citation** — correctly, since habitable must not invent law — but that left
  the one string this project emits that can silently stop being true sitting
  in an undated field, on the one document that leaves the tenant's control and
  goes to a landlord under the tenant's name.

  `[letter]` now takes `local_law_reviewer`, `local_law_reviewed_at`, and
  `local_law_expires_at`. Wording whose review has lapsed is left out of both
  the HTML and the PDF — they read the same two fields, so they cannot
  disagree about what was withheld — and `habitable letter` reports what was
  dropped and what to do about it, in the requested language. Undated wording
  is still used, and reported as undated, so no existing config breaks.
  Backdating the letter with `--date` cannot resurrect expired wording.
  Review dates must be plain `YYYY-MM-DD` days, rejected at config load
  otherwise.

  `LetterProfile` gains `reviewer`/`reviewed_at`/`expires_at` and a
  `framing_expired` predicate mirroring `usecases.profile_expired`; an expired
  framing falls back to `generic` and says so. Both built-in framings are dated
  and neither expires — they name no statute, so they have no specifics to go
  stale. No new jurisdiction framing ships: that stays blocked on a named legal
  reviewer, deliberately, per ADR 0013. No packet, bundle, or verifier change;
  `packet_version` and `CONFIG_SCHEMA_VERSION` are unmoved. See
  [ADR 0013](docs/adr/0013-dated-expiring-letter-jurisdiction-framing.md).
- **A move-out condition and deposit-dispute record (ADR 0014).** A tenant who
  moves out, has part of their deposit withheld, and receives an itemized
  statement of deductions could already photograph the unit and seal the
  statement — but only as an untyped `other_document`, with the link between the
  charge and the condition it charges for living in a free-text note a recipient
  has no reason to trust. Two additions to existing vocabularies close that,
  exactly as `docs/novel-use-cases-plan.md` sized this work: a
  `deduction_itemization` artifact type, so the landlord's statement is a
  first-class sealed document on the unchanged capture/custody/timestamp spine,
  and a `deduction_for` relationship, which runs from that document (or the
  timeline entry recording its arrival) to the issue or the specific photograph
  it charges against. A new `move_out_deposit` profile pairs them with the
  existing `before_of`/`after_of` move-in/move-out comparison and `supports` for
  the tenant's own receipts.

  The profile decides nothing. Two disclosures travel with every export and are
  asserted in the rendered handoff, not merely documented: an itemized deduction
  is the landlord's assertion, and recording it here neither accepts nor rebuts
  it; condition records do not establish wear and tear, damage, cost, or what a
  deposit is owed. `deduction_for` cannot connect two documents, so a chain of
  itemizations can never be presented as though the record joined them, and a
  packet forged to do it is rejected by a recipient's verifier on both the
  endpoint rule and the broken commitment.

  `packet_version` stays 4 and every existing packet verifies unchanged. The
  forward direction is stated rather than papered over: a verifier built before
  this change does not know the two new terms and will refuse a packet using
  them, which is the fail-closed direction. Published schema enums
  (`docs/packet-bundle.schema.json`), the browser app's document-type and
  relationship pickers, and the EN/ES app labels are updated together.

- **Workflow-profile review expiry is now enforced, not just recorded.** ADR
  0010 gave every use-case profile a `reviewed_at`/`expires_at` pair, and the
  plan that introduced it named the acceptance criterion: "an expired
  jurisdiction profile warns and falls back instead of silently presenting
  stale guidance." That shipped the field, not the behavior — nothing ever
  read `expires_at`. None of the ten built-in profiles sets one today, so this
  was latent, not actively wrong, but the roadmap's next product-expansion
  work plans jurisdiction-specific and community-contributed profiles that
  will carry a real one.

  `habitable profile set` (CLI and app) now refuses to select an
  already-expired profile. A profile that instead expires *between* selection
  and a later `export` no longer gets silently presented: the export carries
  **no** profile — as if none were ever selected — records a
  `use_case_profile_fallback` object in `bundle.json` naming what was
  requested and why, and appends a plain-language disclosure that surfaces
  wherever disclosures already render (CLI, app, `packet.html`,
  `packet.pdf`). `habitable profile list`, `habitable status`, and the app's
  `/api/profile` listing now flag an expired profile before it ever forces
  that fallback. The verifier validates the new field's shape but does not
  re-derive an expiry judgment from its own wall clock, so old packets (which
  lack the key) verify unchanged and `packet_version` stays 4. See
  `docs/adr/0012-profile-review-expiry-enforcement.md`.

- **The packet seal: an RFC 3161 countersignature over the whole bundle (FIX-05).**
  Every proof in a packet used to bind exactly one value — an item's
  `content_hash`, one custody entry's predecessor — and nothing bound the packet as
  a unit. `habitable export` now asks the configured timestamp authority to stamp
  the SHA-256 of the finished `bundle.json` and stores the token as `packet_seal`
  in `bundle.sig.json`. Because the imprint is a digest of the whole file, one
  signature no producer's device can mint covers every field at once: the
  narrative, `unit`, `case_id`, `generated_at`, every `captured_at`, every
  `shared_hash` — **the photographs a reader actually opens** — and the custody
  `head_hash`.

  This is what closes the headline finding below. Substituting the visible
  photograph, rewriting the narrative, deleting an item, moving a capture date, and
  swapping unit and case identity all now cost the attacker the seal, which they
  cannot re-mint from an authority the recipient anchored.

  `habitable verify` reports the seal as a fourth claim beside the three of ADR
  0008, and prints its state — including "there is no seal" — on every run in EN
  and ES. **A present seal is always checked**, asserted or not: a seal that does
  not cover the packet is a problem. An **absent** seal is a state, not a failure,
  until a recipient passes `--require-packet-seal`; requiring it by default would
  fail every offline export in exchange for a guarantee an attacker sidesteps by
  deleting one JSON key. `--seal-not-after ISO8601` rejects a seal minted after an
  instant the recipient names — normally the day they received the packet, which is
  an anchor every recipient holds without being given anything.

  **No packet format change and no `packet_version` bump**: the seal lives in the
  signature sidecar, which no version has ever covered, so every packet in
  `tests/golden/` verifies exactly as before.

  This is the first time `habitable export` has used the network. `--no-seal`,
  `--dev-tsa`, an unreachable authority, and `--wifi-only` all degrade to an
  unsealed packet rather than a failed export — capture's offline-first rule
  extended to export — and the command says which happened and what it cost
  (R-18/R-19). `resolve` still *refuses* under `--wifi-only`, because there the
  fetch is the whole operation; for export the packet is.

  Stated as plainly as the gap was: this does **not** establish producer identity,
  and it does not stop an adversary who can obtain a token from an authority the
  recipient trusts — it forces that forgery to carry the true time it was made,
  which `--seal-not-after` then catches. Both residuals are asserted as misses in
  `tests/test_tamper_challenge.py`, tabulated in `docs/tamper-challenge.md` §4, and
  reasoned through in
  `docs/adr/0011-authority-seal-over-the-whole-packet.md`, which also records why a
  producer certificate, a key transparency log, and a TSA-countersigned key birth
  were rejected. The tamper challenge is publishable against the *unpinned*
  invocation as a result; the remaining items in §7 are setup, not blockers.

- **`habitable verify --expected-producer-key`, and a measured account of what
  the verifier does not catch without it.** The bundle signature has always been
  self-attesting: `bundle.sig.json` carries the very public key used to check it,
  so `signature_ok` means "this bundle is internally consistent with the key
  sitting next to it", not "the producer signed this". That is unimplemented
  FIX-05 and was disclosed in prose. What was not written down is how far it
  reaches, so `tests/test_tamper_challenge.py` now carries out the attacks and
  asserts the verdicts — with the attacker recomputing the custody chain from
  `docs/crypto-spec.md` rather than importing this project's code.

  The result that matters: **the photograph a reader actually looks at is not
  protected by the timestamp.** An RFC 3161 token's imprint is `content_hash`,
  the hash of the *original* bytes, and a default packet does not ship the
  originals — so no file a recipient can open is bound by the token. The shared
  copy is bound only by `shared_hash`, which lives in the re-signable bundle. An
  attacker replaces the image, updates `shared_hash`, rewrites the
  `copied_for_sharing` custody entry, rebuilds the chain, re-signs with a fresh
  key, and keeps the genuine token in place; `verify --trusted-cert` reports
  `evidence_ready`. `--include-originals` does **not** close this: replacing the
  embedded original is caught, because that hash is what the token signed, but
  replacing only the shared copy still passes — nothing ties the two files
  together except a custody entry the attacker has already rewritten. Rewriting
  the narrative, deleting an item, moving a capture date, and swapping unit and
  case identity are all likewise undetected.

  `--expected-producer-key` takes the base64 Ed25519 key from a packet the
  recipient already trusts, obtained out of band, and makes a substituted signing
  key a structural failure. It catches every attack above and fails closed on an
  unparseable, empty, or unmatchable pin. It is a recipient-side assertion that
  presupposes its own answer — it helps only someone who already holds a
  trustworthy copy of the key — which is why the packet seal above, and not the
  pin, is what answered FIX-05. The pin remains the stronger tool for a recipient
  who does have a prior relationship, and it still catches the seal's residuals.
  `producer_fingerprint` is not a usable substitute — it is derived from
  `sign_public ‖ box_public`, `box_public` is not in the packet, so a recipient
  cannot recompute it, and the verifier never reads it.

  `docs/tamper-challenge.md` publishes the rules for a public tamper-evidence
  challenge built on this, including the measured baseline above. **The challenge
  has not been opened and no external party has attempted it**; the prerequisites
  are listed in its §7.

- **Packet-level problems are now shown in human-readable `verify` output.** A
  failing version check, a malformed item, or a pinned-key mismatch was only ever
  visible via `--json`; a human saw `integrity: NOT INTACT` with no reason given.

### Fixed

- **`site/robots.txt` allowed a path this site has not served since it moved to
  its own domain.** The line read `Allow: /habitable/`, left over from the
  GitHub Pages project path. An `Allow` with no `Disallow` beside it blocks
  nothing either way, so the line was harmless and wrong, which is the kind of
  thing that survives longest. It reads `Allow: /` now, and a new check refuses
  any `Allow`/`Disallow` naming a path the site does not serve.

- **Every `lastmod` in `site/sitemap.xml` was eleven weeks stale.** Ten pages
  were dated `2026-07-10` and two `2026-07-16`; the files behind them had last
  changed on `2026-07-23` and `2026-08-21`. The only assertion on those dates
  was that they were not in the future, so nothing noticed. A stale `lastmod`
  is not a neutral one: a crawler that has already read a page and is told it
  has not changed since has been given a reason not to look again. Each date is
  now pinned to a SHA-256 of the bytes it describes, so editing a page fails the
  gate until the date moves with it.

- **One `<title>` carried a bare `&`.** `site/review/changes/index.html` wrote
  `Reviewer Findings & Changes` where every other title on the site writes
  `&amp;`.

- **`twitter:image:alt` was on the homepage and nowhere else.** The other
  eleven pages set `twitter:image` with no alternative text for it, so a card
  rendered from one offered a screen-reader user an unlabelled image. Each now
  mirrors the `og:image:alt` it already carried.

- **Three references to the move-out and deposit-dispute record cited ADR 0013,
  which is the letter-framing decision.** The record is ADR 0014. Corrected in
  `docs/novel-use-cases-plan.md` and in two test docstrings. In a project whose
  documents are the argument, a citation pointing at the wrong decision is a
  defect, not a typo.

- **The verifier's copy of the workflow vocabulary can no longer drift from the
  registry.** `verify.py` restates `ARTIFACT_TYPES`, `RELATIONSHIP_TYPES`, and
  `RELATIONSHIP_ENDPOINT_KINDS` instead of importing `habitable.usecases`,
  because the Apache-2.0 verifier subset must stay standalone for embedders —
  but nothing held the two copies equal. A term added to the registry alone
  would have let a vault seal evidence that its own verifier then rejects, and an
  endpoint pair loosened on one side would have left the two disagreeing about
  what is valid. `tests/test_guards.py` now fails on drift in either direction,
  and a companion guard pins the browser app's `<option>` lists to the same
  vocabularies so the app cannot offer a type the engine rejects, or omit one it
  accepts.

- **The test suite can no longer reach the internet without saying so.** A vault's
  default config names public timestamp authorities, so the moment `export` learned
  to seal, several CLI tests began making real HTTPS requests to freetsa.org —
  turning the merge gate into something that depends on a third party being up and
  on somebody else's rate limit, with nothing red to show for it. `tests/conftest.py`
  now fails any test not marked `integration` that opens a connection off the
  machine, naming the URL and the offline fixture or flag to use instead. Loopback
  stays open for the relay and app-server tests, and tests that fake `urlopen`
  themselves are unaffected. Caught while reviewing the seal change, not by CI.

- **The relay image is now both patched and byte-reproducible, which had been
  treated as a choice between the two.** `container-scan` had been failing on
  CVE-2026-53615 (integer overflow in util-linux, HIGH), which reaches nine
  binary packages in the base image: `util-linux`, `bsdutils`, `mount`, `login`,
  and the `libblkid1` / `libmount1` / `libsmartcols1` / `libuuid1` /
  `liblastlog2-2` runtime libraries. Debian fixed it in `2.41.5-0+deb13u1` and
  shipped that to `trixie-security`, but the upstream `python:3.14-slim` image
  has not been rebuilt against it — the newest published digest as of
  2026-08-17 still ships the vulnerable `2.41-5` — so bumping the pinned digest
  could not clear the finding. `relay/Dockerfile` now applies Debian security
  updates over the pinned base.

  An earlier attempt at that upgrade layer broke `make relay-repro`, the gate
  requiring two no-cache rebuilds to produce byte-identical OCI archives, and
  the two properties looked mutually exclusive. They are not. Diffing the
  failing archives layer by layer found exactly one file differing between two
  builds of an identical package set: `/var/cache/ldconfig/aux-cache`, which
  stores each shared library's inode number and ctime *inside its own bytes* and
  therefore survives BuildKit's `rewrite-timestamp` normalisation of file
  mtimes. The four apt/dpkg logs were the visible half of the problem and had
  already been removed; aux-cache was the half keeping the gate red. Removing it
  too makes the rebuild byte-identical on both `linux/amd64` and `linux/arm64`,
  with the CVE cleared.

  Stated limit: the reproducibility claim now counts Debian archive state among
  its inputs, and `scripts/check_reproducible_relay_image.sh` and
  `docs/releasing.md` say so. Two builds seconds apart see the same archive and
  must match. A rebuild months later, after Debian has published a newer
  security upload, is expected to differ — that difference is the patch
  arriving, not a reproducibility regression. The image is reproducible at a
  point in time, not across time.

- **The scanned image is built without cache.** Now that the image applies
  Debian security updates at build time, a reused `apt-get upgrade` layer would
  let Trivy scan a package set captured from an earlier archive state and report
  it as current. Hosted runners start cold, so this was latent rather than live;
  `--no-cache` removes the assumption instead of depending on it, and a test
  asserts it stays.

- **A regression test for the cleanup, not only for the wiring.**
  `tests/test_reproducible_build.py` now asserts that the security-update layer
  exists *and* that it erases every path measured to be nondeterministic. Both
  halves are deliberate: requiring the upgrade to be present means the test
  cannot be satisfied by deleting the layer, so dropping the security updates
  has to be an explicit decision rather than a quiet edit that turns the suite
  green.

### Changed

- **The committed `main` ruleset now records the repository owner's standing
  bypass, because the live one has always had it and must keep it.**
  `.github/rulesets/main-branch.json` declared `"bypass_actors": []` while live
  ruleset `18752848` carried `{"actor_id": 5, "actor_type": "RepositoryRole",
  "bypass_mode": "always"}` — and the file, its `_comment`, ADR 0006 and the
  2026-07 scorecard note all argued the empty list was the stricter, correct
  posture. It is not. It is a lockout waiting to be re-applied: an agent once
  applied a ruleset with no bypass and locked the owner out of their own
  repository, and restoring access took a sweep across eighteen repositories.
  The committed file is what was wrong, so the committed file changed; **no
  live ruleset or repository setting was touched by this entry.** ADR 0006
  carries a dated superseding note withdrawing its "no bypass actor, including
  for the repository owner" clause while leaving its review-count waiver
  intact, and the scorecard note carries a dated correction saying plainly that
  Scorecard scores a standing admin bypass down and that the number stays
  honest rather than the configuration being changed to flatter it.

  The `v*` tag ruleset (`.github/rulesets/release-tags.json`, live ruleset
  `18815834`) is **unchanged and stays at no bypass actor**: a released tag must
  not be movable by anyone, owner included. Both JSON `_comment` fields now say
  the two rulesets differ on purpose and must not be harmonised in either
  direction.

  `tests/test_release_workflow.py` no longer compares the two sides to each
  other. The owner's bypass is asserted against the live ruleset and against the
  committed file **independently**, and any *other* actor is a finding, because
  a plain equality check would report conformance on the day both sides were
  emptied together — which is the incident recurring with a green tick on it.
  That case is now a test, and it must produce two findings rather than zero.

- **Every CI job now installs with `uv sync --locked`, not `uv sync --frozen`**
  (`ci.yml` twice, `a11y.yml`, `release.yml` twice, `tsa-integration.yml`).
  `--frozen` installs from `uv.lock` without reading `pyproject.toml`, so it
  cannot see the two disagree and it exits 0 on a drifted lock; `--locked`
  re-resolves against `pyproject.toml` and exits 1. Nothing was actually
  unguarded: each of those six steps is already preceded by `uv lock --check`,
  and three of them are even named "locked". The point is that the gate no
  longer depends on a separate step surviving a future reorder. The comment
  above each `uv lock --check` now explains the ordering constraint (a bare
  `uv run` silently relocks) rather than describing a `--frozen` call that is
  no longer there. Workflow YAML only: nothing under `relay/`, no build input,
  no dependency, no lockfile change.

## [0.4.0] — 2026-08-16

### Added

- **A recorded, per-case consent record for the fixed pattern question**
  (`habitable consent record` / `--withdraw` / `habitable consent show`). The
  record is a signed, HLC-timestamped register in that household's own case
  document, carrying the same authorship provenance `habitable provenance`
  prints for any other mutable field, and merging to paired devices like any
  other case fact. A withdrawal is a write, not a delete, so "never recorded"
  and "recorded, then withdrawn" stay distinguishable.

- **A stored adversarial corpus for sync protocol v2**
  (`tests/golden/sync-v2-adversarial/malformed-inner-fields.json`, driven by
  `tests/test_sync_fail_closed.py`). Every hostile sync message in the suite was
  previously produced by `export_message` and re-sealed by the tests' own
  helper, so nothing ever omitted or mistyped a field the encoder always emits
  well-formed — which is why the `have`-ordering defect above went unnoticed.
  The corpus freezes one malformed shape per signed inner field (missing,
  wrong-typed, out of range) and each case asserts an *absence*: the recipient's
  canonical CRDT state must be byte-identical after the rejection, with no
  imported original, no queued receipt, no recorded peer inventory, and no
  seen-marker. A further test fails if a signed inner field is ever added
  without an adversarial case, and another checks that field list against what
  `export_message` actually emits. Stated limit: these are stored *mutations*
  applied to a genuinely signed, sealed, paired message — not committed sealed
  envelope bytes, which would require committing a recipient private key. That
  pins the decoder's validation order, not the encoder's output; issue #163's
  full ask for committed envelope bytes stays open.

- **Claim-ledger rows for the five shipped capabilities that had none** —
  `letter`, `campaign`, `commons`, `pattern`, and `capsule` (issue #161). The
  ledger states that it "controls when their historical wording differs from
  current code"; for these five there was nothing to control, so the project's
  honesty mechanism did not reach them. Each row carries the claim its tests
  actually support and a gap column naming what it does not do: the letter's
  English-only limit and absent legal review; `campaign`'s `export_ready` being
  a vault-level signal and not `verify`'s `evidence_ready`; the commons and
  pattern k-anonymity threshold bounding re-identification within one summary
  but not across several publications or against external datasets; and a
  capsule signature establishing that a key signed those bytes, never that a
  partner organization is who it claims to be.

- **Property-based invariants for the assurance-critical core**
  (`tests/test_property_invariants.py`), covering the four primitive-level targets
  named in the productionization plan's §E17 (“Expand property-based testing”).
  This is not all of §E17: its acceptance criterion also asks for a *stateful*
  harness over hostile packet/token input, which is still open. The verifier
  already had a hostile-input fuzz target; the four primitives its verdicts rest
  on now have executable invariants of their own: canonical-JSON round-trip,
  key-order independence, sorted-key and no-insignificant-whitespace encoding,
  and streaming-digest agreement across the read-chunk boundary; custody-chain
  append/verify invariants that reject every reordering, replay, interior
  deletion, hashed-field edit, and forged signature, and answer hostile records
  and signatures with exactly one named `CustodyError`; sealed-box and vault-AEAD
  round-trips that answer hostile bytes with exactly one named `CryptoError`; and
  timestamp-token parse/verify invariants over dev, RFC 3161, and archive chains.
  Two boundaries are pinned honestly rather than overclaimed: a hash-linked chain
  proves a *prefix*, so suffix truncation is visible only because the head hash is
  committed separately; and an RFC 3161 CMS wrapper legitimately carries bytes
  outside its signature, so — exercised both with a synthetic certificate anchor
  configured and with none — what is asserted is that mutation can never move the
  attested `gen_time` or `digest` and can never *manufacture* trust. Trust is
  losable in the fail-closed direction: an edit to the embedded certificate breaks
  the anchor match and drops `trusted_chain` from `true` to `false`, which the
  suite pins with an executable case rather than claiming away.

- **`habitable status` names which capture is awaiting a timestamp token, not
  just how many.** The status line already reported an aggregate
  `timestamps: N/total present; M awaiting`, but a tenant capturing evidence
  with intermittent connectivity had no way to tell *which* capture that was
  short of inspecting the vault directly. Each issue's listing now names any
  of its captures still queued offline, by capture id, using the same
  `capture_awaiting` message the `capture` command already prints — so the
  next `habitable resolve` has a concrete target instead of a bare count.

### Fixed

- **`habitable pattern` wrote `"explicit_per_export": true` into an export
  nobody consented to (issue #182).** The consent token was
  `sha256("pattern-consent::" + case_id + "::" + out_path)` — a hash of the
  operator's own command line, derivable by the very process the field was
  meant to gate, never stored, never compared, and not the product of any act
  by the household it spoke for. The `consent` block was a hardcoded literal, so
  the field was true by construction for every file the command could produce.
  Consent is now a real record: `habitable pattern` reads a per-case,
  per-question consent record out of each vault and **refuses the whole export**
  if any offered case has no record or a recorded withdrawal, naming the vault.
  A case is never silently dropped, because a silently smaller cohort still
  publishes. `build_no_heat_weekly_summary` no longer accepts a caller-supplied
  household token at all — it derives one from the consent record's own
  provenance — so no caller can reintroduce a synthesised token. The emitted
  block (`schema_version` 2) now reports the mechanism that exists, the number
  of records actually read, and `"explicit_per_export": false`; the field is
  kept, with the opposite value, so a reader who saw an old file sees the
  correction rather than a silent removal. There is still no per-export consent
  step and the export no longer claims one; `docs/novel-use-cases-plan.md` §N4
  now describes what was built and why the per-export version is a design
  change rather than a bug fix. The question prompt and the CLI's success line
  drop "consented" for a phrasing that names the population the data covers.

- **"0 awaiting a timestamp" and "export-ready" were computed from a local
  queue, so a synced-in capture with no token counted as neither timestamped
  nor awaiting (issue #180).** `habitable status`, `habitable campaign status`
  and the roll-up HTML all answered "does this still need a timestamp?" by
  reading `vault.deferred()` -- the append-only queue this device writes when it
  captures something offline. Sync never wrote to that queue, so a capture that
  arrived from a tenant's device without a token was invisible on both sides of
  the tally: it was missing from the numerator *and* absent from the awaiting
  count, and its unit rolled up as **export-ready**. Awaiting is now derived
  from token *presence* over captures plus artifacts
  (`Vault.awaiting_timestamp`), the same population the denominator uses. The
  CLI's `timestamps: N/M present` line previously counted only captures in `M`
  while counting artifacts in the awaiting figure, so three deferred documents
  beside one stamped photo printed `1/1 present; 3 awaiting`; both halves now
  describe the same set, and the `⧗` lines name awaiting artifacts as well as
  awaiting captures. The app's "Waiting for a timestamp token" tile reads a new
  `awaiting` field rather than the queue length. Separately, sync now queues an
  imported capture that arrived without a token, so `habitable resolve` can
  actually fetch one -- previously nothing could -- and clears a queued entry
  when a peer supplies the token, so `resolve` no longer fetches a second
  primary over content already stamped.

- **Every handoff section was handed the whole bundle, so a packet with no
  delivery receipt still rendered "Delivery — 1 evidence item(s), 1
  relationship(s)" (issue #181).** `build_handoff_manifest` computed one set of
  issue/item/artifact/relationship id lists over the entire bundle and wrote
  those identical lists into every `section_id` the profile declared, and the
  renderer printed their lengths under each `<h2>`. The repo's own
  `repair_delivery` fixture — one repair request, one `documents_condition`
  relationship, no delivery receipt, no landlord response — therefore told a
  caseworker or a code inspector that its Delivery section held delivery
  evidence and its Response section held response evidence. It held neither, and
  the manifest travels inside the signed `bundle.json`, so a verified packet
  carried the inflated counts with the signature's authority behind them.
  `repair_comparison`'s **Proof Limits** heading got the same treatment.
  Nothing in the case model records which record belongs to which section, so
  manifest version 2 stops pretending otherwise: sections carry `section_id` and
  nothing else, a `section_membership: "not_recorded"` field says why, and the
  only counts in the document are the bundle-wide `counts`, printed once under
  "This handoff as a whole" and labelled as covering the whole packet. The
  section headings stay — they are the recipient's expected reading order — with
  no count attached. Packet v1 manifests still verify; the verifier's handoff
  checks are structural and never read `sections`.

- **The documented "per-module 95% floor on the evidence-integrity core" was a
  pooled floor, and `vault.py` was below it (issue #183).** `DEFINITION_OF_DONE`,
  `pyproject.toml` and `RESPONSIBLE-TECH-AUDITS` all described a per-module 95%
  floor on `crypto.py`, `vault.py`, `tsa.py` and `verify.py`, listed under
  **Enforcement. AUTO**. The gate was a single
  `coverage report --include=<all four> --fail-under=95`, and `--fail-under`
  tests only the TOTAL row — one pooled number. Measured on the committed
  `coverage.xml`: `crypto.py` 100.00%, `tsa.py` 98.72%, `verify.py` 95.57%,
  `vault.py` **94.42%**, pooled TOTAL **95.56% — green**. `crypto.py` was
  subsidising the largest module in the set, and the one that holds the
  encrypted store at rest. `vault.py` could have fallen to roughly 91% before
  the build turned red. `make cov` now runs one `--fail-under=95` per module and
  reports every module before failing, so one pass names each module below the
  line rather than only the first. `vault.py` is at **95.44%**, raised by
  covering the fail-closed and legacy-migration paths that were its largest
  untested region: the pre-FIX-01 plaintext `node_id` migration and its refusal
  when there is nothing to migrate, a corrupt node-identity record, a corrupt or
  wrongly-shaped peer-have record, a corrupt sync-security record, a peer
  identity that does not decode, and a peer filed under a fingerprint that is
  not its own (`tests/test_vault_legacy_and_corruption.py`).

- **`human_bytes` labelled petabyte-scale sizes with a terabyte-scale number.**
  The unit loop divides once per entry in `("KB", "MB", "GB", "TB")` and the
  fallback returned that same terabyte-scaled value with a `PB` suffix, so 2.5 PB
  rendered as "2500.0 PB" — a number and a unit that disagree by a factor of a
  thousand. Found while covering `vault.py` for the floor above.

- **A documented fail-closed sync property failed open: the `have` manifest was
  validated after the CRDT merge (issue #163).** `docs/sync-threat-model.md`
  states "A validation failure cannot partially merge the message's CRDT state"
  and `docs/sync-protocol-v2.md` §3 states "Any failure aborts that message
  before merge". For one signed inner field both sentences were false: the
  `have` manifest was shape-checked one line *after* `vault.document.merge`, so
  a malformed manifest from an already-paired peer (version-skewed, buggy, or
  partially written) raised `SyncError` with the recipient's case document
  already mutated — and, because the raise preceded `mark_sync_message_seen`
  and `queue_sync_receipt`, with the custody and receipt record saying the
  message had never arrived, leaving the same message to merge again on the
  next exchange. The manifest is now parsed and validated inside
  `_validate_message`, which returns before the merge or not at all; *which*
  declared holdings this device can confirm is still computed after the merge
  (so a capture arriving in the same message counts and its bytes are not
  re-sent), but that step can no longer reject anything. `docs/sync-protocol-v2.md`
  §3's ordered checklist — which omitted `have` entirely, and so was the
  document that drifted from the code — now enumerates it and states the
  confirmation/validation split explicitly.

- **The relay's operator surface reported success it had not verified (issue
  #162).** Three separate false signals, all in the surfaces
  `docs/relay-operator-self-audit.md` tells an operator to inspect and attest to
  their union:

  - **`/healthz` reported an idle relay for "refused to load".** When bounded
    startup replay refused the persistence directory, `metrics()` reported
    in-memory state — `rooms: 0`, `status: ok` — while a directory of members'
    sealed sync traffic sat unread on disk. `/healthz` now carries
    `startup_replay` (`disabled` / `complete` / `degraded` / `incomplete`) and a
    fixed-vocabulary `startup_replay_reason`, reports `status: degraded` for
    anything it did not fully verify, and `/readyz` returns **503** on
    `incomplete` — the state where the amount of unloaded at-rest ciphertext is
    *unknown*. The counts are documented, in code and in the audit doc, as
    describing process memory and never the disk.
  - **The counter counted events, not records.** `journal_load_rejections`
    incremented by exactly one whether a single line was malformed or the whole
    directory was refused, and three documents called it a record count. It is
    replaced by `journal_records_rejected` (lines), `journal_files_rejected`
    (whole journals), and `journal_load_refusals` (the directory or its
    remainder — an unknown quantity). The startup log line now distinguishes a
    `warning` for bounded, known loss from an `error` naming the orphaned state:
    a refusal is sticky, leaves ciphertext unreferenced, and needs a human, so
    the audit doc gained a manual-recovery section (§4.8) instead of the relay
    silently deciding to ignore or delete a union's sync traffic.
  - **The access log recorded `status: 200` for a request that returned
    nothing.** `_status` was initialised to `200` before routing and logged from
    a `finally`, so an exception escaping the route left the peer with
    `RemoteDisconnected` and the attestable log with `200`. The status is now set
    only by the code that writes the response, and each line carries
    `response: complete|partial|none`; a request that sent nothing logs **no**
    `status` field rather than a fabricated one.

  Three stale statements in `docs/relay-observability-matrix.md` are corrected in
  the same change: the sync envelope shape (it omitted `pairing_id` and `mac`,
  the two fields carrying the v2 pairing binding), the unqualified "it persists
  nothing to disk" (true only with the opt-in journal disabled), and
  "restart-as-erasure", which was doubly wrong — storage is not FIFO-capped
  (silent `pop(0)` eviction was deliberately replaced by a 413 `RoomFullError`)
  and a persisted relay *reloads* undelivered ciphertext across a restart, so
  restart is not the privacy mitigation that section offered.

- **Timestamp-authority trust had only ever been anchored to certificates this
  repository generated, and the untrusted verdict could not be told apart from
  operator error (issue #159).** `timestamp_authority_trusted` gates every READY
  verdict, and its anchor check had never been exercised against a certificate
  the project did not mint: the integration test proved a real authority could
  *issue* a token (verifying it with no anchor at all), and every anchor
  assertion used `LocalRfc3161TSA`'s own certificate or one generated inside the
  test.

  - **The join is now asserted, offline.** `tests/golden/tsa-freetsa/` commits a
    real FreeTSA token over a synthetic digest together with FreeTSA's published
    root and responder certificates (provenance and re-derivation steps in that
    directory's README), and `tests/test_tsa_real_authority.py` anchors the one
    to the other in every `make verify` — no network, no flakiness. The live
    counterpart in `tests/test_tsa_integration.py` now anchors a freshly stamped
    token to the authority's published root as well, so a change in that
    authority's chain shape is a visible failure rather than a silent one.
  - **The three anchor outcomes are distinguishable.** "No anchor was supplied",
    "anchors were supplied and none chained", and "anchored" produced one
    sentence about a certificate "not chained to a trusted root". A reviewer who
    downloaded an authority's published root, passed it, and got NOT TRUSTED was
    told to do the thing they had just done. `TimestampInfo.note` and
    `VerificationReport.guidance()` now say which case occurred,
    `VerificationReport.anchors_supplied` exposes it to machine consumers (also
    in `habitable verify --json`), and the no-anchor case states plainly that
    authority trust was *not assessed* — which is not a finding against the
    token. The machine-readable `status` value is unchanged.
  - **The anchor rule is stated instead of inferred.** `habitable.tsa.ANCHOR_RULE`
    documents that this is a *one-hop* check — the anchor must be the signing
    certificate or the certificate that directly issued it — and that
    intermediates, validity periods, basic constraints, key usage, name
    constraints, and revocation are **not** checked. It is not widened here:
    widening it means this project hand-rolling X.509 path validation inside the
    one function every READY verdict rests on. `docs/embedding-the-verifier.md`
    stopped instructing embedders to pass roots (which fails for any authority
    issuing through an intermediate, DigiCert included) and now says to pass the
    *issuing* certificate or pin the responder; `docs/verifier-decision-table.md`
    §5 records that `openssl ts -verify -CAfile` does build a path and can
    therefore succeed where this check declines, so the two tools are not in
    conflict about the token.
  - **The anchor check is no longer RSA-only.** `_issuer_signed` returned
    `False` for every non-RSA issuer key, so a legitimate EC-issued authority
    chain was reported exactly as a forged one. Each hop is now delegated to
    `cryptography`'s `verify_directly_issued_by` (RSA, ECDSA, Ed25519, Ed448),
    which also checks that issuer and subject names chain. Nothing about what is
    *not* checked changed.

- **Packet v4 was the only format habitable emits and nothing that pins the
  format covered it (issue #160).** No golden fixture, a fuzz harness on v1, a
  reference importer on v1, a BagIt adapter on v3, and a decision table
  describing itself as normative for v2 — while two documents stated that
  "every version ever emitted keeps verifying, guarded by the committed
  golden-packet corpus".

  - `tests/golden/packet-v4/` is committed, and `scripts/make_golden_packet.py`
    now builds a fixture that actually exercises the version's own surfaces: an
    artifact item, a relationship, a use-case profile, and a handoff view. A
    fixture carrying only the shape every version shares would leave
    `_verify_v4_workflows` — roughly 250 lines of hostile-input parsing in the
    standalone verifier — as unguarded as no fixture at all.
  - `tests/test_golden.py` asserts a fixture exists for **every** version in
    `1..SUPPORTED_PACKET_VERSION`, and that the newest one carries those
    surfaces. The corpus previously passed with whatever happened to be on disk,
    which is why a version bump could forget its fixture and stay green. This is
    the assertion that stops it recurring.
  - The fuzz harness draws from the whole corpus instead of `packet-v1`, and its
    structural mutation reaches **nested** objects and array elements rather
    than only top-level keys — so the v3 timeline and v4
    artifact/relationship/profile/handoff structures are now fuzzed at all
    (448 addressable positions in the v4 bundle, against 114 in v1). The
    reference importer is parametrized over every committed version, and the
    BagIt adapter test follows `SUPPORTED_PACKET_VERSION` rather than a pinned
    v3.
  - Documentation corrected rather than left describing the old state: the two
    "every version ever emitted" sentences now say what the corpus is actually
    required to contain, and `docs/verifier-decision-table.md`'s header no
    longer claims to be normative for `SUPPORTED_PACKET_VERSION = 2`. It states
    which checks its rows are complete for and which version-specific checks it
    does not yet enumerate, and tells a reviewer to derive those from the code
    and the corpus rather than from a stale table. `tests/test_site_sample.py`
    records that the published sample is a freshness gate, not a compatibility
    pin.

- **The repair-request letter declared `lang="es"` while being English-only, and
  claimed a verifiable packet with zero photographs (issue #161).** `habitable
  letter` produces the one document that leaves the tenant's control and lands
  in a landlord's hands, and it made two claims it had not earned:

  - **Language.** Every string in `letter.py` is an English literal, but
    `render_letter_html` emitted `<html lang="{vault language}">`, so a vault
    configured `language = "es"` produced byte-identical English prose under a
    Spanish language tag — a WCAG 3.1.1 failure that makes a screen reader
    pronounce English with Spanish phonetics. The letter is now always emitted
    and labelled `lang="en"`, and `habitable letter` prints the unmet request
    **in the requested language**. The translation is deliberately not
    machine-generated: this document carries legal framing and goes out under a
    tenant's name, so a legal-register Spanish version needs a Spanish-speaking
    legal-aid reviewer first. That is recorded as an open gap for Spanish-speaking
    unions in `docs/capabilities.md` and `docs/letter-generator.md`, not as a
    settled decision.
  - **Evidence.** The evidence sentence was built unconditionally, so a case with
    an issue and no captures asserted "documented by 0 photograph(s) … A
    complete, independently-verifiable evidence packet is available on request".
    It is now gated on there being captures; with none the letter states that no
    photographs are attached to the request yet and makes no packet offer.

  Found while fixing the above: `LetterOptions.language` defaulted to `"en"`,
  which made `options.language or vault.config.language` dead code — a vault
  configured `language = "es"` was never consulted by `habitable letter` at all.
  It now defaults to empty ("use the vault's setting"), so a Spanish-speaking
  union's configuration is actually read, and reported on.

- **A capture whose media type had no packet export mapping (`.heic`, the iPhone
  default photo format) used to ship with no bytes, no custody binding, and a
  `habitable verify` verdict of READY (issue #158).** `packet.build_packet` now
  refuses to publish any item that would carry neither a metadata-stripped shared
  copy nor an embedded original, naming the capture id and media type in a clear
  `PacketError` -- an operator sees "I cannot export this, here's why" instead of a
  packet that looks fine and isn't; `--include-originals` remains a real, working,
  deliberately higher-disclosure way to export such an item byte-exact. `capture.py`
  and `packet.py` now read one canonical registry (`habitable.media_types`) instead
  of two independently hand-maintained maps, so this class of gap cannot recur
  unnoticed; a regression test asserts every registered media type has a working
  export path, proven end to end. `habitable.verify.ItemVerdict` gained
  `evidence_present`, folded into `structurally_intact`: an item with no shared
  media and no embedded original can never be `evidence_ready`, even with an
  otherwise-valid, authority-trusted timestamp -- defense-in-depth for a
  hand-crafted bundle or a packet from a different tool, since a normal export can
  no longer produce that state at all. `packet.html`'s per-item figure and evidence
  appendix now visibly say when an item carries no shared preview (an embedded
  original still exists to download) or no evidence bytes at all, rather than
  rendering an empty figure that looked identical to an intact one. Incidentally
  surfaced and fixed along the way: `exif.py`'s non-JPEG raster metadata-stripping
  path (PNG/WEBP/TIFF) called a Pillow accessor this project's Pillow floor
  (12.3.0) deprecated, previously uncaught because no existing test captured and
  exported a non-JPEG still image end to end.

- **Hostile timestamp, custody, and sealed-box input now always fails closed with
  a named error.** Five paths surfaced by the new property suites could raise a raw
  library exception — or, in one case, accept a byte-level change — instead of
  habitable's own error type:
  - `open_sealed` let a degenerate (all-zero/low-order) ephemeral public key
    escape as `ValueError` from X25519 instead of `CryptoError`, contradicting
    `crypto.py`'s stated contract that every authentication failure is a
    `CryptoError`.
  - `TimestampToken.from_dict` let malformed base64 escape as `binascii.Error`.
    Peer sync (`_token_or_none` / `_token_list`) has no broad handler, so an
    authorized peer's malformed token record raised a traceback rather than a
    `SyncError`; `vault.py` had already worked around this locally.
  - `_verify_dev_token` let invalid UTF-8 in token bytes escape as
    `UnicodeDecodeError`, and malformed base64 in its `pubkey`/`sig` fields
    escape as `binascii.Error`.
  - `_verify_dev_token` accepted non-canonical base64 spellings of its `pubkey`
    and `sig`, so a change to a token's trailing signature character went
    undetected. Dev tokens now reject alternate spellings the same way
    `pairing.py` already rejects them for pairing material, and no byte mutation
    of a dev token is accepted.
  - `CustodyLog.verify` let malformed base64 in a signed entry's `signature`
    escape as `binascii.Error` — the same defect class as the token paths above,
    on the one primitive of the four that had no “hostile input yields exactly one
    named error” property. It now decodes strictly and raises `CustodyError`, and
    the missing property is in place.

  No packet, vault, or sync format changed, and every committed golden packet
  still verifies: all tokens and custody signatures habitable has ever emitted are
  canonical base64.

### Changed

- Moved the five-minute synthetic quickstart into the README’s visitor-facing
  opening so the first useful command is visible without traversing product
  internals.
- Split releases into a read-only trusted-main verification/build job, a
  checkout-free GitHub publication job that rechecks the exact annotated-tag
  object, and the existing isolated PyPI Trusted Publishing job. Releases are
  now explicitly dispatched from `main` for an existing signed stable tag.
- Rebuilt the local app, public Unit 4B example, and review surfaces around the
  condition-first **Repair Trail**. The interface now keeps Reported and Secured
  dates distinct, separates tenant statements from checkable proof, moves entry
  creation into focused dialogs, and makes the tenant-copy/review-copy boundary
  explicit in words as well as color.
- Refreshed screenshots, support-page descriptions, setup guidance, accessibility
  test protocols, and the capability ledger to match the Repair Trail workflow.
  Dated research and execution documents now identify themselves as historical
  snapshots and defer current claims to the capability ledger.
- Vendored the portfolio standards at **v2.0.0** (`docs/standards/`).
- Added a `lockfile drift (CQ-09)` gate. `uv.lock` is committed and every CI job
  installs with `uv sync --frozen`, which the standard used to call the
  lockfile-drift check. It is not one: `--frozen` installs from `uv.lock`
  *without reading* `pyproject.toml`, so by construction it cannot notice that
  the two disagree, and it exits 0 on a drifted lock. `uv lock --check` now runs
  first in CI, before any command that could rewrite the lock — a bare `uv run`
  silently relocks, so a gate invoked that way repairs the very thing it checks.
- Gave `gh release create` its repository through `GH_REPO`, so the publication
  job no longer depends on a checkout it deliberately does not have.
- Added an "Idea or feature request" issue form, so a reporter is not handed a
  blank box, and a Ko-fi support link in the README.
- Routine dependency maintenance across the range: the pinned `cryptography`,
  CodeQL, `harden-runner`, `attest-build-provenance`, `setup-uv`, `checkout`,
  `scorecard-action`, `trufflehog`, `zizmor-action`, `gh-action-pypi-publish`,
  and relay base-image digests, plus three grouped dev-dependency bumps.

### Security

- **CVE-2026-69247 in `cryptography`, remediated by pinning 50.0.0.** The
  `pyproject.toml` constraint (`cryptography>=44`) already admitted the fixed
  version, so this was a lockfile-only bump (`uv lock --upgrade-package
  cryptography`) rather than a constraint change.
- **The weekly secret scan had been scanning zero commits since it was added.**
  With `path`, `base`, and `head` all unset, the TruffleHog action resolves base
  and head to the same commit and exits on its own guard — "BASE and HEAD commits
  are the same. TruffleHog won't scan anything." Every scheduled run had failed
  that way, not on a finding: the logs carry no chunk count and no
  `verified_secrets` line, because no scan ever started. The comment in the
  workflow asserted the opposite, that omitting base/head falls back to a full
  scan, and that assumption is what broke it. Setting `path: ./` makes it a
  whole-repository scan for real — 4,875 chunks over the full history, confirmed
  locally against the same pinned v3.96.0 image. That first real scan surfaced 37
  verified findings, **all of them false**: the Lob detector matches `test_` or
  `live_` followed by alphanumerics, which is the shape of every pytest function
  name under `tests/`, and its verifier confirms them because it cannot tell a
  malformed key from an unauthorized one. There is no Lob integration in this
  repository. The detector is excluded by name rather than by path, because
  skipping `tests/` would blind the scan to real secrets in fixtures, which is
  where they are most often committed by accident.

## [0.3.0] — 2026-07-23

### Added

- **Roadmap drain and novel-use-case implementation plan.** A dated execution
  register reconciles the strategic/research roadmaps, current-main tests, and
  live GitHub queue into shipped, externally blocked, and protocol/research-
  blocked outcomes with named triggers and completion artifacts. A companion
  Now/Next/Later plan scores ten application-fit use cases and specifies the
  shared profile, artifact, relationship, handoff, aggregation, migration,
  accessibility, privacy, and verification work needed to build them without
  broadening into a cloud evidence platform.

- **Profile-driven evidence workflows / packet v4.** Ten housing-specific
  workflows now share versioned bilingual profiles, sealed/timestamped document
  artifacts, explicit custody-bound evidence relationships, accessible signed
  handoff manifests, encrypted peer-sync support, standalone v4 verification,
  CLI and localhost-app creation paths, a fixed consented/no-heat weekly
  aggregate with household suppression, and a signed partner evidence capsule
  adapter. Review-dependent inspector, accommodation, public-housing, health,
  building-pattern, and partner workflows remain visibly marked
  `external_review_required`; implementation is not represented as domain
  approval. Packet v1–v3 golden compatibility remains executable. See
  [`docs/migrations/packet-v4-workflows.md`](docs/migrations/packet-v4-workflows.md)
  and [`docs/adr/0010-profile-driven-evidence-workflows.md`](docs/adr/0010-profile-driven-evidence-workflows.md).

- **Bounded public review hub.** `/review/` now routes tenant organizers, legal-aid
  reviewers, accessibility testers, and security/verifier reviewers into four
  fixed-time synthetic workflows with six concrete tasks and expected outputs. A
  user-started 75-second walkthrough demonstrates the synthetic case, packet export,
  and verifier limit; public technical feedback, private no-case-data organization
  contact, and private vulnerability reporting remain separate. `/review/changes/`
  opens a dated “what reviewers found / what changed” ledger without inventing
  findings, and neither page accepts evidence uploads.

- **Evidence Atlas local-app overhaul.** The case workspace now joins captures and
  timeline facts on an interactive, issue-filterable chronology with visible evidence
  links, proof-state overlays, guided keyboard story navigation, collision-safe same-date
  controls, a synchronized fact inspector, and an accessible table equivalent. The
  redesigned record, readiness, and disclosure workspaces remain bilingual, responsive,
  telemetry-free, and localhost-only; the loopback API exposes only the minimal hash,
  timestamp, custody, and relationship projection the atlas needs—never media or token
  bytes.

- **Byte-reproducible relay-image gate.** `make relay-repro` builds two no-cache
  linux/amd64 OCI archives from the pinned relay base under the commit's fixed
  `SOURCE_DATE_EPOCH`, uses BuildKit timestamp rewriting, and compares the complete
  archives byte for byte. The container merge gate and tagged release workflow both
  block on it. The claim is deliberately scoped to the pinned platform and builder
  invocation, not cross-builder or cross-architecture identity. The gate builds from
  a clean archive of tracked source, and normal Docker contexts now exclude Python
  caches so release-time test bytecode cannot leak into or perturb the relay image.

- **Strict BagIt 1.0 packet-transfer adapter.** The Apache-2.0 reference CLI under
  `contrib/` verifies and copies one exact Habitable packet into `data/packet/`,
  emits deterministic SHA-256 payload and tag manifests, rejects unsafe or
  non-portable filesystem paths, detects source mutation, and publishes a validated
  bag atomically to a new destination. BagIt provides transfer fixity—not producer
  authenticity, timestamp-authority trust, evidence readiness, or admissibility.
- **Capability/claim ledger and documentation truth gate.** `docs/capabilities.md`
  separates shipped, partial, planned, and externally unvalidated claims and links each
  row to repository evidence plus its explicit gap. A standard-library Markdown-link
  checker now runs in `make verify`, fails on missing local targets, and requires every
  ledger row to retain a live local evidence path.
- **Reproducible-build verification for the wheel/sdist** (`make repro`,
  `scripts/check_reproducible_build.py`). Builds the package twice from two
  independent clean copies of the git-tracked source, with a normalized
  `SOURCE_DATE_EPOCH` (the tagged commit's timestamp) and `PYTHONHASHSEED`, and
  fails — naming the differing file(s) — if the two builds aren't byte-identical.
  The `release` workflow now runs this as a release-blocking gate before the SBOM,
  provenance attestation, and publish steps, so a downloader's provenance
  verification and an independent rebuild agree on the same artifact. Documented
  in `docs/releasing.md`. The relay container image is not yet covered by an
  equivalent check (tracked in `ROADMAP.md`).

- **Authenticated sync protocol v2.** Sync and redactable sharing now require
  signed, recipient-sealed, case-bound pairing. Messages enforce exact peer
  allowlists, pairing-key authentication, recipient/case binding, replay
  protection, signed import receipts, and downgrade-resistant signed per-field
  CRDT provenance (with explicit legacy migration attestations).
  Round trips preserve primary, additional, and archive timestamp tokens plus
  verified source custody material.

- **Timeline 2.0 / packet v3.** Timeline events now separate the reported occurrence date from the
  device recording time and record a reviewed source; use reviewed condition/notice/delivery/
  response/inspection/repair/recurrence/impact choices or an explicit Other label. Events can link
  captures and the notice→delivery→response chain, recurrence reopens the same issue, and every new
  event is committed into a signed local custody entry. Packet v3 uses `order_token` rather than
  reusing v2 `hlc`, carries the semantic commitment and binding stage, renders the same signed fields
  deterministically in EN/ES app/HTML/PDF views, and verifies the commitment/link types. Legacy case
  entries migrate without invented occurrence/source facts; committed packet-v1/v2/v3 goldens keep
  backward verification executable. See
  [`docs/migrations/packet-v3-timeline.md`](docs/migrations/packet-v3-timeline.md).

- **Reusable, local-first evidence kernel (`habitable.kernel`)** — EXP-13. The
  verification-facing spine (canonical serialization + SHA-256, chain-of-custody model +
  verification, RFC 3161 timestamp verification, Ed25519 signature verification, and the
  fail-closed packet verifier) is now exposed as a single, stable, **Apache-2.0**
  embeddable surface so other civic tools can adopt tamper-evidence without copying code.
  Ships with a **semver contract** (`KERNEL_API_VERSION`, versioned independently of the
  app), a `pip install "habitable[kernel]"` extra, a spec at
  [`docs/evidence-kernel.md`](docs/evidence-kernel.md), and a **language-independent golden
  corpus** (`tests/golden/kernel/vectors.json`, regenerated by
  `scripts/gen_kernel_corpus.py`) that lets two independent implementations cross-check the
  same canonical bytes, hashes, and custody head hashes. A guard test keeps
  `import habitable.kernel` within the Apache-2.0 subset (no relay/sync/cli/app/capture/vault).

- **Instrument-corroborated conditions — sensor CSV import** (EXP-09). An independent
  instrument's readings (a temperature logger for a no-heat case, a moisture meter for
  mold) can now be captured as a first-class item: a `.csv` file runs the *same* evidence
  spine as a photo — hashed, sealed, RFC 3161 timestamped, and custody-logged — so
  `verify` treats it as a hash-anchored item with no special-casing. The packet interprets
  the CSV (new `habitable.sensor` module: conservative `label,value[ (unit)]` parsing that
  degrades to "no chart" rather than guessing) and renders it accessibly: a summary
  sentence, the full readings table (header scopes + caption; the source of truth), and a
  small line chart marked `aria-hidden` over that text equivalent — never color-only. A
  data file is copied into `media/` verbatim (a CSV carries no embedded location metadata
  to strip) and disclosed as such. Framed as corroboration, **not** proof of cause
  (R-26). New `item.sensor` field documented in `docs/bundle-schema.md` and
  `docs/packet-bundle.schema.json`; see the expansion backlog in
  `docs/research/synthetic-personas-feedback.md` (EXP-09).

- **Relay observability — structured JSON logs + `/livez` / `/readyz`** (per the
  portfolio OBSERVABILITY-STANDARD). The optional sync relay now logs one JSON object
  per line via the stdlib `logging` module (it stays dependency-free — no structlog/OTel
  wheels in its image): `ts`, `level`, `msg`, `request_id`, `method`, `path`, `status`,
  `latency_ms`. The privacy gate is absolute and metadata-only: logs never carry
  ciphertext, plaintext bodies, keys, or peer IPs, and the room id is **redacted** to the
  route template `/rooms/{room}` so it cannot link sync sessions. Per-request access
  logging is **opt-in and off by default** (`HABITABLE_RELAY_LOG=json`), preserving the
  threat-model default of no request lines. New `/livez` (liveness, no dependency calls)
  and `/readyz` (readiness — fails **closed** with 503 when the store is unhealthy) sit
  alongside the existing `/healthz`; health probes are excluded from the access log.
  The threaded server's error hook also replaces stdlib's client-address + traceback stderr
  dump: attacker-triggerable connection resets/broken pipes are silent, while an unexpected
  handler fault emits one fixed `{ts,level,msg}` event. Guard tests cover normal access lines,
  direct fault classification, and repeated real TCP RSTs.

### Changed

- The local app's last jargon-heavy timestamp recovery action now says “Add
  missing timestamp tokens” / “Agregar sellos de tiempo faltantes”; English uses
  an action-first result and Spanish consistently uses *sello de tiempo*. EN/ES
  parity and a dedicated terminology regression test guard the wording.

- **Distinctive tenant-evidence identity and custom domain.** The public site and
  installable app now share a structural H-frame/evidence-seal mark, self-hosted civic
  signage typography, a cool field-record palette, and a building-section case-spine
  motif grounded in repair documentation rather than generic software cards. Canonical,
  social, sitemap, and schema URLs now use `https://habitable.chelseakr.com/`; the public
  site remains a static synthetic preview and still hosts no tenant case data.

- **Enforced PR-only, current-check updates to `main`.** Live repository ruleset
  `18752848` now requires every update through a pull request, requires all merge
  gates to pass against current `main`, resolves review conversations, blocks
  force-push/deletion, and has no bypass actors. The committed ruleset now matches
  the live policy. Approval and code-owner review remain explicitly zero/disabled
  under ADR 0006 until a second maintainer can supply a real independent review.

- **Node.js 24 artifact transport in CI.** All workflow uses of
  `actions/upload-artifact` now pin v7.0.1 and release promotion pins
  `actions/download-artifact` v8.0.1. This removes the hosted-runner Node.js 20
  deprecation path; named archived-artifact behavior is unchanged, while downloaded
  artifact digest mismatches now fail closed by default. A regression guard prevents
  an older artifact-action major from returning unnoticed. The verifier portability
  matrix now also passes its version through a quoted environment variable instead of
  interpolating an Actions expression directly into shell commands.

- **Protected release-tag identity.** The committed `v*` tag ruleset is now active on
  GitHub (ruleset `18815834`): release tags cannot be moved or deleted, and future tags
  must be signed. Release documentation and regression coverage now keep the live
  protection contract distinct from the still-open maintainer signing-key setup.

- **Plain-language & cognitive review of the in-app copy and setup guide (R-41 / R-04).**
  A reviewed plain-language pass (target ~grade 6–8) over `app/i18n/en.json`,
  `app/i18n/es.json`, and `docs/setup-guide.md`. Jargon was replaced or glossed:
  "Device fingerprint" → "Device ID", "Chain of custody" → "Evidence trail",
  "Awaiting timestamp" → "Waiting for timestamp", "Content hash" → "Content
  fingerprint". Two in-context help strings were added (a practice/untrusted-timestamp
  warning and a sealed-originals note), wired via `aria-describedby`. (`resolve_deferred`
  / `resolve_help` / `msg_resolved` were left as-is on this pass — a concurrently
  merged change already made them plain, and `capture_awaiting_reassure`'s
  guard-tested reference to that exact button text stays intact.) The Spanish was
  de-lawyered; the honest-limits
  strings (`alpha_*`, `verify_*`, `custody_*`, `capture_timestamped_no`,
  `footer_note`) were left at full strength, and EN/ES key + placeholder + plural
  parity is unchanged. Dated review record: `docs/audits/plain-language-review.md`.

### Fixed

- **Canonical conformance metadata and ADR integrity.** The enforced 85% baseline is
  now recorded in `pyproject.toml`, Python 3.14 is pinned for fresh clones, and the
  README uses the canonical Security & Supply-Chain label. The ADR log gains its
  portfolio 0000 governance record and authoring template; the later of two records
  previously numbered 0008 (authenticated sync) is renumbered 0009 with its link
  repaired, while the earlier timestamp trust/readiness decision retains 0008. The
  EOF-normalization hook now excludes signature-bound golden/sample artifacts so a
  routine pre-commit run cannot rewrite their exact bytes.
- **Relay retained state and persistence startup are now resource-bounded.** The shared
  threaded store atomically caps live rooms (4,096), messages (50,000 aggregate / 10,000
  per room), ciphertext (512 MiB aggregate / 128 MiB per room), and ASCII base64url-style
  room tokens; excess POSTs return an explicit 413 without evicting messages or claiming a
  new TOFU token. Content lengths must be a bounded ASCII-digits-only field before parsing.
  A bounded TTL sweep can reclaim otherwise unreachable stale rooms before a global
  rejection. GET remains non-destructive but now streams base64/JSON in fixed-size chunks.
  Persistence startup scans and reads bounded amounts without following symlinks or blocking
  on FIFOs, validates canonical room journals, timestamps no more than five minutes ahead of
  startup, live-token consistency, and strict base64, and applies the same live caps. Individual
  malformed records are skipped and counted; valid same-room/same-token records beside them may
  still load, but the mixed source journal is left untouched. Expired records do not establish
  or conflict with live TOFU state, so a legitimate post-TTL rebind survives a transient cleanup
  failure and restart. Live-token-ambiguous or over-cap journals are refused as a unit, and
  noncanonical paths are not opened. Fully valid loads prune expired lines and remove
  stale-only/empty canonical files. Device, inode, size, mtime, and ctime
  generation checks protect startup, append, and cleanup; Windows uses a close/recheck/unlink
  fallback under the documented single-local-writer assumption.
  Journals compact before crossing their cap and repair an unterminated prior append from live
  state before acknowledging the next POST. Exact app-owned compaction crash temps have their own
  128-file startup cleanup allowance, separate from the 8,192 non-temp scan allowance; excess
  remnants fail closed before journal admission. Persistence remains a best-effort restart aid,
  not an fsync-backed delivery guarantee; abrupt failure can lose the newest append or leave a
  malformed record/temp, and unlink cleanup is not secure erasure.
- **Timestamp-token sidecars no longer expose token/TSA/time metadata as plaintext at rest.**
  Each capture's primary, additional, and archive tokens now share one canonical
  ChaCha20-Poly1305 sidecar under the vault DEK, named by the SHA-256 of its capture id and bound
  to that digest with domain-separated associated data. Writes are atomic, flushed, and `0600` on
  POSIX; a pinned no-follow directory descriptor anchors bounded enumeration/read/write/rename/
  unlink so traversal, directory swaps, symlinks, FIFOs, oversize input, filename swaps, and tamper
  fail closed. Platforms without the required descriptor-relative operations reject whole-vault
  create/open rather than making an unreopenable vault or using an unsafe fallback. A successful
  unlock migrates legacy JSON by publishing and
  verifying encrypted state before unlinking, and resumes safely after a crash between publication
  or individual plaintext deletions, including one strictly validated cap-overlap entry during
  migration. DEK rotation now validates and re-encrypts sidecars too; immediately before its first
  publish attempt, cleanup becomes conservative so a post-syscall asynchronous exception preserves
  the remaining new-key stages and wrapped new key for manual recovery. Before publication, every
  intended root, original, token, and keyfile stage is registered, exclusively created no-follow at
  `0600`, fully written and file-synced, and checked by device/inode/size/mtime/ctime; ordinary
  failures remove only the exact app-created generation, while raced-in/replaced entries fail closed.
  All stage directories are synced and the wrapped-key stage is generation-verified and pinned
  before the first rename; data/original/token stages are then published and their directories
  synced before the pinned wrapped key is committed last and the vault root synced. A raced
  post-commit keyfile is atomically forward-repaired from the expected wrapped key before the
  original error is reraised.
  If the fixed keyfile stage is detached during partial publication, a random
  `keyfile.json.recovery-<32hex>.new` is durably retained and reported for manual recovery without
  overwriting the alien entry. Failed repair artifacts are named only after their bytes are
  positively verified; otherwise the primary exception says no verified artifact was retained.
  Retries fail closed on known root/original/keyfile or token stages and exact random forward-repair/
  recovery names, without following or deleting regular files, symlinks, or FIFOs; the root scan is
  capped at 256 entries. Secondary prepublication cleanup failures are attached to, rather than
  replacing, the primary rotation error. Concurrent writers remain non-isolated. Rotation can
  transiently add
  one `.new` per sidecar (bounded doubling), and `SIGKILL` leftovers require manual recovery. Public
  `TimestampToken`, sync, and packet formats are unchanged. Encryption supplies local
  confidentiality/integrity—not TSA
  authenticity—and stable hashed filenames remain linkable. Ciphertext length approximates token
  volume and filesystem `mtime`/`ctime` expose update timing; there is no padding or metadata hiding.
  `config.toml` authority/policy metadata stays plaintext, unlocked endpoints expose tokens, and
  unlinking is not secure erasure.
- **Browser uploads no longer create plaintext files inside the encrypted vault.** The
  app server now hands path-based capture tools a random file in a short-lived operating-system
  temporary workspace outside the vault, created with owner-only `0700`/`0600` modes on POSIX and
  removed on success or failure. Packet sanitization uses the same private workspace instead of
  umask-dependent plaintext source files. App startup removes the reserved legacy `_incoming`
  path without following symlinks. This is cleanup, not secure erasure: decoded bytes still exist
  in process memory and briefly in OS temporary storage, and crash remnants, swap, snapshots, or
  storage forensics remain endpoint risks.
- **Normal vault state saves are recoverable transactions instead of direct sequential
  overwrites.** The five mutable encrypted blobs are now staged with flushed encrypted backups,
  published by same-directory replacement behind prepared/committed recovery metadata, and cleaned
  only after the new generation is durable to the extent the host filesystem supports. Injected
  partial writes and real child-process deaths—including a second death during rollback
  finalization—prove that the next open either restores the complete old generation or keeps the
  complete committed one. Recovery bounds and validates the journal as a regular file and rejects
  symlink/FIFO backup inputs. Existing vault filenames and encryption format are unchanged. This
  does not include key rotation, per-capture token-sidecar replacement, sealed-original creation,
  network filesystems, unsupported directory `fsync`, or concurrent writers in that five-blob
  transaction.
- **Scoped packet and organizer-share exports now fail closed instead of leaking the
  complete source custody chain.** Packet v3 issue/date selectors and sync v2 issue
  subsets previously filtered visible records while still serializing custody entries
  for excluded records. Those selectors now stop before staging, custody mutation, or
  message creation. Whole-unit/full-case flows remain available; restoring narrower
  exports requires a new versioned, scoped/rehashed custody-view contract.
- **Unsupported custody-identity packet export now fails closed.** The compatibility
  setting `sharing.export_custody_identities = true` previously changed only the disclosure
  note while the public custody proof remained identity-stripped. Packet construction now
  rejects that setting before staging or custody mutation instead of publishing a false claim.
- **JPEG shared copies now remove every embedded metadata carrier under the default
  strip-all policy.** Export decodes and applies EXIF orientation, rebuilds pixels,
  removes APP0–APP15 and comment segments plus trailing data, verifies a metadata-free
  output, and publishes atomically. This closes the XMP/IPTC/ICC/comment leak left by
  EXIF-only removal; sealed originals remain byte-for-byte unchanged.
- **Release identity and artifact promotion are bound end to end.** Manual release
  runs now resolve the requested signed tag, require its commit to be on the fetched
  default-branch history, and detach there before checking the version or building.
  The reproducibility-checked wheel and sdist are built once,
  smoke-tested, attested, uploaded to the GitHub release, and passed unchanged into
  the isolated OIDC-enabled PyPI job; that job no longer checks out source or rebuilds.
- **Packet publication is transactional and re-export is clean.** Exports are
  rendered in a fresh sibling directory and published only after every artifact
  succeeds. Reusing an output path replaces the whole directory, so sealed originals,
  an inspector view, media, or other files from a prior higher-disclosure whole-unit
  export cannot survive a later export that omits those optional artifacts. Ordinary
  render/publish failures restore the previous packet and roll back the uncommitted
  custody entries.
- **Unlocked app server is loopback-only.** `habitable app` now rejects LAN,
  wildcard, tunneled, and public bind targets instead of exposing an unlocked case
  API over plaintext HTTP. Phone and workshop guides no longer recommend the old
  `0.0.0.0` path and state honestly that a reviewed on-device package is not shipped.
- **Public documentation now matches the implementation and validation state.** Timeline
  notes are no longer described as individually hashed/timestamped; valid RFC 3161 tokens
  are distinguished from recipient-anchored authority trust; automated accessibility is
  distinguished from the still-open human pass; and court readiness, duress mode, pilot
  completion, PDF/UA, and signed native packaging are no longer implied as shipped.
- **The published sample packet verifies again.** The GitHub Pages sample is now a
  current signed export with its required `bundle.sig.json`, opaque public IDs,
  sanitized shared media, and explicit synthetic-data labeling. A regression test
  runs the standalone verifier against the literal committed sample and fails CI if
  its signature, custody chain, packet version, or privacy properties drift.
- **Verifier subset now imports on Python < 3.14 again.** Three multi-type `except`
  clauses in the Apache-2.0 verification subset (`verify.py`, `tsa.py`, `exif.py`)
  used the PEP 758 parenthesis-free form, a `SyntaxError` before Python 3.14 — which
  contradicted the 0.2.0 note that the subset is portable for legal-aid embedders.
  The root cause is that the ruff formatter targets `py314` and strips the
  parentheses, so the clauses now reference a **named exception tuple** (e.g.
  `except _SIGNATURE_READ_ERRORS:`), which is formatter-stable and portable. A new
  guard test (`test_verifier_subset_avoids_py314_only_except_syntax`) fails the gate
  if the 3.14-only form is reintroduced.

### Added

- **Court-ready evidence bundle.** Every exported `packet.html` and `packet.pdf` now
  opens with a **cover sheet** (case, scope, counts, producer device, date range of the
  evidence), a single **chronological evidence timeline** that interleaves logged notes
  with captured photos across every issue in time order, and a **chain-of-custody /
  integrity summary** (per-item content hashes, RFC 3161 timestamp authorities and archive
  counts, and the append-only custody-chain head). The sections are derived purely from the
  already-signed `bundle.json` (no schema change, no `packet_version` bump, golden packets
  unaffected) by a new shared `bundleview` module, so the HTML and PDF cannot drift. The
  accessible HTML remains the conformant rendering (ADR 0004); the PDF keeps its
  accessibility hygiene.
- **E2E-encrypted full-case sharing (`habitable share` / `habitable receive`).** A
  tenant can hand a full case, optionally with the `unit` metadata field omitted, to a
  tenant-union organizer who was not previously on the case, preserving end-to-end
  encryption: the payload is the full-case CRDT state plus any sealed originals the organizer
  does not already hold; it is **signed** by the tenant and **sealed** to the organizer's verified
  public key, so a relay/courier sees
  only ciphertext. Reuses the existing crypto + CRDT primitives; trust is direct and
  out-of-band (verify the short fingerprint), with no key directory. Trust/key-exchange
  model documented in `docs/sharing-trust-model.md`.
- **Repair-request letter generator (`habitable letter`).** Generates a dated repair-request
  / notice letter from the logged evidence (issues, dates, photo/timestamp counts),
  rendered as an accessible HTML letter and a PDF. Jurisdiction-aware *framing only*: a
  small set of built-in profiles (`generic`, `us_habitability`) that make **no
  statute-specific claim**, overridable via a new `[letter]` config block, with a standing
  "not legal advice" disclaimer. Assumptions documented in `docs/letter-generator.md`.
- **Packet "what this proves — and what it does not" disclosure.** Every exported
  `packet.html` and `packet.pdf` now carries a plain-language, localized (EN/ES)
  statement of the upper-bound timestamp semantics and the limits of the evidence
  (it does not prove authorship, depiction, the underlying condition, or
  admissibility), with how to verify. Single source in `src/habitable/disclosure.py`
  so the HTML and PDF cannot drift. (Recipient personas: housing-court clerk,
  opposing counsel.)
- **Recipient-facing disclosures.** Packets now carry a localized (EN/ES) "what
  this packet discloses" note (shared copies have location removed under the default policy; sealed
  originals, when embedded, retain full metadata), and the machine-readable
  `disclosures` list is included in the signed `bundle.json` (schema documented).
- **`habitable verify --json`.** A structured verification report (overall verdict
  plus per-item content hash, timestamp, custody, fixity, and notes) for scripts,
  downstream integrators, and screen-reader users.
- **`habitable verify --trusted-cert PEM`** (repeatable). Anchors each RFC 3161
  timestamp to a TSA root certificate the verifier trusts, so a court or auditor can
  assert the authority chain rather than only the token signature.
- **Multiple-authority timestamp redundancy by default.** Capture now stamps every
  configured timestamp authority (the default config ships more than one), recording
  the primary token in `timestamp` and independent tokens over the same content hash
  in `additional_timestamps`. The verifier checks all of them, reports
  `verified_authorities` per item (and in `verify --json`), and counts an item as
  timestamped if at least one authority verifies — so no packet's proof rests on a
  single TSA. Additive and backward-compatible: existing single-authority packets
  verify exactly as before.

- **Synthetic-persona research and derived backlog** in `docs/research/`
  (`synthetic-personas-feedback.md`, `execution-log.md`): a broad persona study,
  interviews, and a prioritized list of remediations/expansions checked against the
  project's invariants.
- **Reviewer & integrator documentation** realizing backlog items from that study:
  a standalone cryptographic design spec (`docs/crypto-spec.md`), a verifier
  decision table + independent cross-check procedure
  (`docs/verifier-decision-table.md`), a documented, versioned packet/bundle format
  (`docs/bundle-schema.md` + `docs/packet-bundle.schema.json`), a verifier-embedding
  cookbook (`docs/embedding-the-verifier.md`), and a "how to attack a packet"
  red-team document (`docs/audits/packet-attack-redteam.md`).
- **Legal-scaffolding docs** (`docs/legal/`): tenant/custodian declaration
  templates, foundation guidance for counsel, and California-scoped evidence notes
  (all explicitly not legal advice).
- **Adoption kit** (`docs/adoption/`): a train-the-trainer workshop guide, printable
  EN/ES quick-starts, and a board-level risk/benefit briefing.
- **Community, sustainability & ops docs**: a funder impact brief
  (`docs/funding-impact-brief.md`), a newcomer/good-first-issues guide
  (`docs/good-first-issues.md`), a localization-contributor guide
  (`docs/localization-guide.md`), a union key-custody playbook
  (`docs/key-custody-playbook.md`), and relay operator self-audit + observability
  docs (`docs/relay-operator-self-audit.md`, `docs/relay-observability-matrix.md`).

## [0.2.0] — 2026-06-17

Alpha hardening and reviewer-handoff release. Still alpha — do not rely on it for a
real legal matter yet. This release closes out the maintainer-only "Phase 0" work:
durable proofs, a frozen threat-model baseline, automated assurance, and the
materials an external auditor, accessibility tester, or pilot partner needs.

### Added

- **Archive (re-)timestamping.** `habitable retimestamp` re-stamps each capture's
  most recent token before the issuing authority's certificate or hash algorithm
  ages out (RFC 4998-style chaining). Existence stays anchored at the primary
  token's time; packets carry `archive_timestamps` per item and the standalone
  verifier walks the chain, failing closed on any break. (`tsa.retimestamp`,
  `tsa.verify_archive_chain`, `capture.retimestamp_all`.)
- **Vault key lifecycle.** `habitable key rotate | backup | restore` — passphrase
  rotation and an independent-passphrase recovery blob, with a non-technical-organizer
  walkthrough in `docs/key-management.md`.
- **Backward-compatibility guard.** A versioned packet/protocol contract in the
  verifier plus a committed golden-packet corpus, so every format version ever
  emitted must keep verifying and a newer-than-supported packet is rejected cleanly,
  never mis-verified.
- **Assurance automation.** A verifier fuzz/property harness; a scheduled,
  network-gated public-TSA integration job (DigiCert + FreeTSA); and a signed
  build-provenance + CycloneDX SBOM release pipeline.
- **Invariant guard tests.** `tests/test_guards.py` and hardened sync tests pin two
  promises: no plaintext (note text, image bytes, or a sender identity) reaches a
  relay or on-disk mailbox, and importing `habitable.verify` pulls in only the
  Apache-2.0 verification subset — no AGPL-only/heavy modules.
- **Frozen threat-model baseline B1.** A content-pinned (`SHA-256`) freeze of the
  threat model for external review, with a section-by-section re-review and an
  append-only baseline trail (`docs/audits/threat-model-baseline.md`, tag
  `threat-model-baseline-B1`).
- **Reviewer/pilot handoff docs.** `docs/audits/onboarding.md`, a DPIA-style
  `docs/privacy.md`, `docs/sustainability.md` (incl. bus-factor minimum), and a
  multi-year `ROADMAP.md`.
- **Accessibility.** Automated keyboard-navigation and 320 px reflow checks added to
  the a11y gate.

### Changed

- The verification subset (`verify`/`tsa`/`exif`) now writes its multi-type `except`
  clauses with explicit parentheses — behaviour-identical, but valid on every
  Python 3 and unambiguous to auditors and legal-aid embedders of the Apache-2.0
  verifier (no reliance on the PEP 758 syntax that 3.14 newly accepts).
- `docs/governance.md` "Releases" reconciled with the actual signed/provenanced
  pipeline.

### Fixed

- **RFC 3161 interoperability with real public authorities.** The client now reads
  `PKIStatus` whether rendered as an int or a name, follows the token's own digest
  algorithm instead of assuming SHA-256, and dispatches signature verification for
  both RSA (PKCS#1 v1.5) and ECDSA — verified against DigiCert and FreeTSA.
- Two verifier robustness bugs found by the fuzz harness: invalid-UTF-8 bundle bytes
  and a malformed custody chain are now clean rejections, never a crash.

### Security

- **Custody-actor identity and tenant filename no longer leak into exported packets.**
  The importing peer's fingerprint (`details.from`) and the original source filename
  (`details.source`) were being carried in the signed, shared `bundle.json`,
  weakening the "exports name no one" guarantee. They now live in a **vault-only
  `private_details`** field that is never hashed and never exported, while the union
  keeps them for its own audit. Previously-produced packets still verify unchanged.
  Regression-guarded by `tests/test_guards.py`.

## [0.1.0] — 2026-06-17

First public release. Alpha — a working reference implementation; do not rely on
it for real legal matters yet. It pairs the evidence spine with a local app,
accessibility gates, mobile/PWA install, an optional relay deploy, and a static
preview site.

### Added — app, accessibility, and operations

- **Local app.** `habitable app` runs a loopback-only HTTP server that holds the
  unlocked vault and serves an accessible, bilingual (English/Spanish) web client —
  capture, timeline, status, resolve, and export-and-verify over a small JSON API;
  nothing leaves the device. Installable PWA (manifest, maskable/Apple icons, and
  an offline service worker that is network-only for `/api/`).
- **axe-core accessibility gate.** A real WCAG scan of the running app in English
  and Spanish (Playwright/Chromium), blocking on any moderate/serious/critical
  violation, in a dedicated `a11y` CI workflow and `make a11y`; the app reports
  **zero** violations. Manual NVDA/VoiceOver/keyboard/zoom protocol documented in
  `docs/accessibility/manual-testing.md`.
- **Accessible HTML packet.** Every export also produces `packet.html` — a
  self-contained WCAG 2.2 AA rendering that passes the same axe gate — alongside a
  PDF that declares its language, sets `DisplayDocTitle`, and carries a navigable
  outline; all bundle-derived text is escaped before rendering.
- **Configurable packet templates** (per-jurisdiction wording, presentation only).
- **Optional relay deploy.** A dependency-free, non-root, read-only container and a
  one-command `docker compose` for the ciphertext-only sync relay
  (`docs/relay-deploy.md`).
- **Docs & preview.** Setup guide, mobile guide, and a static landing page with a
  live sample packet (GitHub Pages).

### Limitations

A *recorded* human screen-reader pass (protocol shipped), a fully tagged PDF/UA
structure tree (not available in reportlab's open-source API — the HTML packet is
the accessible rendering until then), and signed native app-store binaries (the
installable PWA covers mobile today) remain — see the ACR and the build plan.

### Added — evidence core

- **Evidence core.** Streaming SHA-256 fixity and an append-only, hash-linked
  chain of custody whose entry hashes commit to *salted actor commitments*, so an
  exported chain verifies as intact without revealing who viewed or copied an
  item. Tamper, deletion, and reordering are all detectable.
- **Trusted timestamping.** Real RFC 3161 (a local issuer for offline use/tests
  and an HTTP client for production) plus a clearly non-production offline dev
  TSA. The verifier enforces digest binding, validates the CMS signature and
  certificate chain, and detects `genTime` tampering.
- **Encryption.** ChaCha20-Poly1305 vault encryption under a scrypt-wrapped data
  key (cheap passphrase rotation and encrypted recovery backups), Ed25519 device
  identity, and an X25519 sealed box for end-to-end sync.
- **Offline-first model.** A CRDT case document (LWW registers, an OR-Set of
  issues, append-only timeline/captures) with commutative, associative,
  idempotent merge.
- **Vault + capture.** Encrypted on-disk case vault with fixity re-checked on
  read; capture pipeline that hashes, seals, and records custody offline, then
  obtains a trusted timestamp when online (queuing otherwise).
- **Packet + verify.** Deterministic signed `bundle.json`, default location-stripped
  shared media, and an accessible paginated PDF; a standalone verifier
  (additionally Apache-2.0) that re-derives hashes, validates tokens and the
  producer signature, and walks custody.
- **Sync + relay.** End-to-end-encrypted peer-to-peer sync over a shared
  directory or an optional ciphertext-only relay.
- **CLI.** `habitable init|id|issue|capture|timeline|status|resolve|export|verify|sync|relay|demo`,
  plus `python -m habitable`.
- **Engineering.** uv project on Python 3.14; `ruff` + `mypy --strict`; pytest
  with property-based and tamper-detection tests (`make verify` green, ~85%
  coverage); SHA-pinned GitHub Actions, CodeQL, Dependabot, `pip-audit`.

[Unreleased]: https://github.com/ChelseaKR/habitable/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/ChelseaKR/habitable/compare/v0.2.0...v0.4.0
<!-- No [0.3.0] link is published here. 0.3.0 was prepared on `main` on 2026-07-23 — the
     version was bumped in `pyproject.toml` and the section below was written — but it was
     never tagged and never released, so `v0.3.0` does not exist as a ref and there is no
     release page to point at. The previous links here (`compare/v0.2.0...v0.3.0` and
     `compare/v0.3.0...HEAD`) both resolved to 404s for that reason. The 0.4.0 comparison
     therefore runs from `v0.2.0`, the last tag that actually exists, and spans both bodies
     of work. The [0.3.0] section stays below as the dated record of what landed that day.
     This link is restored, pointing at a real tag, if v0.3.0 is ever cut. -->
[0.2.0]: https://github.com/ChelseaKR/habitable/releases/tag/v0.2.0
[0.1.0]: https://github.com/ChelseaKR/habitable/releases/tag/v0.1.0
