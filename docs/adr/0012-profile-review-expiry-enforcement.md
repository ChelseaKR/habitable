<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# ADR 0012: Profile review-expiry enforcement

- Status: Accepted
- Date: 2026-08-22

## Context

ADR 0010 added a versioned `UseCaseProfile` registry and gave every profile a
`reviewed_at`/`expires_at` pair, with the stated acceptance criterion (see
`docs/novel-use-cases-plan.md`, foundation sequence N0) that "an expired
jurisdiction profile warns and falls back instead of silently presenting stale
guidance." That criterion shipped the field but not the behavior: `expires_at`
was serialized into every exported profile record, but nothing ever read it.
None of the ten built-in profiles sets one today, so this was latent rather
than actively wrong — but the roadmap's product-expansion workstream (see
`ROADMAP.md`, workstream E) plans to grow the profile registry with
jurisdiction-specific and community-contributed profiles, several of which will
carry a real, dated review expiry. Landing that growth on top of an
unenforced field would let a case keep presenting a profile whose named review
window has passed, which is exactly the silently-stale-guidance failure the
project's honesty principle ("say what it does not do") forbids.

Two moments matter, and they call for different responses:

1. **Selecting** a profile onto a case (`habitable profile set`, the app's
   profile form). The profile is being chosen *now*; if its review already
   expired, there is no reason to persist it going forward.
2. **Exporting** a packet from a case that already carries a profile selection
   made earlier, when that profile's review has *since* expired. The evidence
   itself is unaffected and must still export; only the workflow framing is
   stale.

## Decision

1. Add a single pure predicate, `usecases.profile_expired(profile, *, today=None)`,
   comparing `expires_at` (a plain `YYYY-MM-DD` string) against the calendar
   date — real wall-clock by default, injectable for tests. A profile with no
   `expires_at` never expires.
2. **Selection refuses an expired profile.** `CaseDocument.set_use_case_profile`
   — the single implementation both the CLI and the app call — raises
   `HabitableError` rather than persisting an already-stale choice.
3. **Export falls back rather than blocking.** `packet.build_packet` resolves
   the case's selected (or `--handoff-profile`-named) profile; if it has
   expired since selection, the export proceeds with **no** profile (as if
   none were ever selected: no `use_case_profile`, no `handoff_views`), and:
   - records a structured `use_case_profile_fallback` object in `bundle.json`
     naming what was requested and why (`reason: "expired"`), so the export is
     never silent about the substitution — mirroring the project's existing
     "state the absence, don't erase it" pattern (e.g. the consent block's
     `explicit_per_export` correction, `handoff_views`'s `section_membership:
     "not_recorded"`);
   - appends a plain-language disclosure sentence to the bundle's existing
     `disclosures`, so it surfaces for free everywhere disclosures already
     render: CLI `export` output, the app's export-result panel, `packet.html`,
     and `packet.pdf`.
4. **The verifier validates the fallback record's shape** (present only when
   `use_case_profile` is null; well-formed when present) but does **not**
   independently re-derive an expiry judgment from its own wall clock. The
   verifier's verdict must stay a function of the bundle's bytes, not of when
   verification happens — old packets (which lack the key entirely) verify
   unchanged.
5. The CLI (`profile list`, `status`) and the app (`/api/profile`'s per-profile
   `expired` flag, computed at request time — not baked into the packet-facing
   `UseCaseProfile.to_json()`) surface expiry as an annotation, so a maintainer
   or organizer can see it coming before it forces an export-time fallback.

## Options considered

| Option | Assessment |
| --- | --- |
| Leave `expires_at` unenforced until a profile actually needs it | Rejected: ships the same known gap the roadmap explicitly flags, and defers the harder design work to whichever future PR is under the most schedule pressure to add a jurisdiction profile — the worst time to design a fallback contract carefully. |
| Hard-fail export when the selected profile has expired | Rejected: the evidence is not stale, only the workflow framing is; refusing the whole export over presentation metadata would make a real tenant's packet unavailable for a reason they cannot immediately fix (they need a fresh review, not a retry). |
| Silently drop the profile at export with no record | Rejected outright: this is the "silently stale" failure by omission in the other direction — a recipient comparing this packet to an earlier one from the same case would see the workflow framing vanish with no explanation, and a maintainer investigating a bug report would have nothing to point to. |
| Verifier independently re-derives "is this expired as of right now" | Deferred, not rejected: a genuinely useful advisory ("this profile's review window has since passed") for a packet verified years after export, but it makes a verifier verdict depend on wall-clock-at-verify-time, which the hostile-input-hardened verifier core deliberately avoids elsewhere. Worth revisiting once a real expiring profile exists to motivate it. |

## Consequences

- No packet version bump: `use_case_profile_fallback` is additive and optional
  (`null` when absent), and old packets simply lack the key. `packet_version`
  stays 4.
- `PacketResult` gains a `profile_fallback` field or the CLI/app cannot report
  what happened without re-deriving it from `disclosures` string matching.
- Growing the profile registry with a jurisdiction/community profile that
  carries a real `expires_at` can now rely on this mechanism rather than
  needing to invent its own.
- Nothing changes for any of the ten shipped profiles today; this is
  forward-looking infrastructure, verified with a synthetic expired profile in
  tests rather than a real one (`tests/test_usecases.py`,
  `tests/test_artifact_workflows.py`, `tests/test_appserver.py`,
  `tests/test_cli_workflows.py`).

## Action items

- [x] `usecases.profile_expired` predicate.
- [x] Selection-time refusal in `CaseDocument.set_use_case_profile`.
- [x] Export-time fallback, `use_case_profile_fallback` bundle field, and
      disclosure in `packet.build_packet`.
- [x] Verifier structural validation of the new field.
- [x] CLI (`profile list`, `status`) and app (`/api/profile`) expiry surfacing.
- [x] Tests: pure-predicate, selection refusal, export fallback, verifier
      rejection of a malformed/contradictory record, CLI/app annotations.
- [ ] A live "this profile's review has since passed" verifier-time advisory
      (deferred; see options considered above).
