# Profile review: `building_pattern` — for a tenant organizer who has run a building campaign

> **Bounded, unpaid, synthetic data only.** A review of *framing* and of a consent model —
> not legal advice, not an endorsement, and not a request to run this on your building.
> Shared terms (what a profile is, what the review is not, credit, conflicts) are in
> [profile-reviews.md](profile-reviews.md); this page is only what is specific to
> `building_pattern`. **One profile is a complete contribution.**

habitable is an alpha, offline-first tool where each household holds its own encrypted case.
This profile is the one place the tool counts across households: a single fixed question,
answered locally, with small numbers suppressed. It ships implemented and marked
`external_review_required`, because the project's own plan said to build the aggregation only
after a pilot organizer defined a real question — and no organizer ever did.

## Who this is for

Someone who has **run a building-wide or landlord-wide campaign**: a tenant-union organizer,
a tenant-association or building-committee leader, a housing organizer at a community
organization, an organizer who has run a rent strike, a code-complaint campaign, or a
collective repair demand. Someone who has had to answer "how many units, and since when?" in
front of a landlord, a council member, an agency, or a reporter.

The expertise wanted is **organizing judgement, not statistics**: whether this is a number
you would use, and whether the consent model is one you would be willing to stand behind in
front of your neighbours.

## What the profile actually asserts

Verbatim from [`src/habitable/usecases.py`](../../src/habitable/usecases.py):

- **Name:** "Consented building pattern summary" (Spanish: "Resumen consentido de patrones
  del edificio")
- **Summary:** *"Answer a fixed organizing question with threshold-suppressed local
  aggregates."*
- **Document type it declares:** `other_document`
- **Relationship type it declares:** `supports`
- **Reading order it declares:** `question` → `cohort` → `suppressed_summary` →
  `privacy_limits`
- **Its disclosure, which travels with the export and cannot be suppressed:**
  *"Published aggregates cannot be remotely revoked and may permit differencing."*

And the machinery behind it, from [`src/habitable/patterns.py`](../../src/habitable/patterns.py)
(background in [`docs/commons.md`](../commons.md)):

- **There is exactly one question**, hard-coded: *"In each building and ISO week, how many
  households that recorded consent to this question reported no heat?"* No other question can
  be asked. No maps, no cross-building joins, no exact addresses, no narrative text, no
  media, no household identifiers.
- **Counts are per (building label, condition, ISO week).** The building label is supplied by
  whoever runs the export, not by the household.
- **Cells below the threshold are suppressed** — five distinct households by default.
- **Consent is a standing, per-case, per-question record** written into each household's own
  vault (`habitable consent record`), signed and timestamped like any other case fact, and
  read back at export. A withdrawal is recorded as a write, so "never consented" and
  "consented, then withdrew" stay distinguishable.
- **A missing or withdrawn record refuses the whole export**, rather than quietly dropping
  that household — because a silently smaller cohort still publishes.
- **Nobody is asked again at export time.** The output file states this itself:
  `"explicit_per_export": false`, with the mechanism named. An earlier version of the format
  claimed the opposite; the field was kept, with the honest value, so a reader who saw the
  old file sees the correction.
- **The organizer runs it over vaults they already hold keys to**, on their own machine, with
  no network. `--confirm-consent` is a required flag: an acknowledgement by the operator that
  they reviewed *this release* for differencing risk.
- **A published aggregate cannot be recalled.** Withdrawal stops future exports and nothing
  else.

**One thing to know about what the number means.** The question used to count conditions
stored under the exact label `no_heat`, which no supported path could store — so the export
came back empty for reasons that had nothing to do with the building (issue #276, fixed).
It now counts `heat`, and that category does not separate *no heat at all* from *inadequate
heat* from *heat a household cannot control*. The export says so in its own `scope_note`.
Whether a count that groups those three is the number an organizer can actually use is
question 1 below, and it is the one this brief most wants your answer to.

## The questions this profile needs answered

1. **Is this a number you would actually use?** Consenting households reporting a heat
   condition — no heat, inadequate heat, and heat they cannot control, counted together — by
   building and week. In a landlord meeting, a press ask, a code complaint, a council
   hearing, a rent strike vote — where does it land, and what would you have to say next to
   make it matter?
2. **If it is the wrong question, what is the right one?** Only one ships, deliberately.
   Naming the question you would actually ask is the single most valuable output of this
   review.
3. **Does a five-household threshold work in the buildings you organize?** It silences small
   buildings entirely. Is that the correct trade, or does it make the tool useless exactly
   where organizing is hardest?
4. **Is the consent model honest enough to publish under?** Consent is recorded once, in
   advance, per household — and then an organizer runs the export without asking again. Would
   your members read that as consent to *this* release? Would you want each household asked
   again before publication, and if so, would that ever actually happen in a campaign?
5. **Is refuse-the-whole-export the right failure?** One neighbour who has not recorded
   consent blocks the entire summary. That is deliberate, so a smaller cohort never publishes
   under a heading claiming consent — but does it create pressure on the holdout, which is
   exactly the dynamic a consent model should avoid?
6. **Who holds the keys, in your model?** The export reads vaults the organizer can already
   unlock. Is one organizer holding neighbours' case keys something you would do, or is it
   a concentration of risk (and of power) you would refuse? What happens when that organizer
   leaves, or is evicted, or falls out with the committee?
7. **What do you do when someone withdraws after publication?** The number is out; it cannot
   be recalled. Is there a practice you would follow, and should the tool say something about
   it before the first export rather than after?
8. **Weekly releases add up.** Repeated overlapping releases can let a reader difference one
   against another and infer an individual household. Today that risk is a warning in the
   file plus an operator acknowledgement flag. Is a warning enough for a real campaign, or
   does it need a rule the tool enforces?

### If you only have twenty minutes

Answer 1, 2, and 6. Whether the number is useful, what question you would ask instead, and
whether the key-holding shape is one an organizer should accept.

## What would make this fail review

- Organizers do not ask this question, and the one they do ask cannot be answered this way.
- The consent model would be read by tenants as more consent than it is — the point at which
  a privacy-preserving feature becomes a way to publish about people who did not expect it.
- The all-or-nothing refusal creates real pressure on a household that said no.
- One organizer holding many households' keys is unsafe in a real campaign, especially where
  the organizer is a neighbour, a member of a landlord-adjacent household, or under pressure.
- The threshold makes the tool useless in small buildings, or fails to protect a household in
  a building of eight.

Any of those, and the honest answer is to change the feature or leave the profile gated.

## Out of scope, deliberately

habitable also has an organizer-side roll-up across vaults (`habitable campaign`) and a
multi-tenant submission index (`habitable joint`). Both are separate surfaces with their own
design, and neither is part of this review — the ask is kept to one profile so it stays a
short read. If you look at them anyway and something is wrong, say so.

## What this review is not

Not legal advice, not an endorsement of habitable, which stays alpha regardless, and not a
request to use this on your building or your members. Not a security or accessibility review
— separate tracks in [profile-reviews.md](profile-reviews.md). **No real household data is
involved**: everything is evaluated with generated synthetic cases.

## How your answer is recorded

A dated entry for `building_pattern` in the public capability ledger
([`docs/capabilities.md`](../capabilities.md)), the profile's `reviewer` and `reviewed_at`
fields filled in, and an expiry date if your read is tied to a moment or a place. If your
answer changes the question, the threshold, or the consent model, that change lands first and
the ledger row follows it. Credit or anonymity is your call
([profile-reviews.md](profile-reviews.md#credit-and-conflicts-of-interest)); organizers often
prefer role-only credit, which is fine.

## Finding this reviewer (maintainer note)

No verified leads; channel types only. The existing
[pilot-partner brief](role-pilot-partner.md) has a target list built the right way (verified,
dated, with confidence noted) — reuse its approach, not its names, since it was scoped to a
different ask.

- **Tenant unions and tenant-association federations**, through organizing or membership
  staff.
- **Building committees and tenant associations** that have run a campaign recently — the
  most direct experience, the least time.
- **Housing organizers at community organizations and mutual-aid networks.**
- **Organizer training programs**, where reviewing a tool is a normal thing to be asked.
- **Data-for-organizing and community-technology projects**, whose staff already think about
  aggregation and re-identification.

Say plainly that this is not a pilot ask and involves no member data.

## Outreach note

> **Subject:** Would you actually use this number? 20 minutes, unpaid, no member data
>
> Hi [name],
>
> I maintain **habitable**, an open-source, offline tool where each household keeps its own
> encrypted record of housing conditions. Unfunded personal project, **alpha, not for real
> use yet**.
>
> It has one feature that counts across households: a single fixed question — *how many
> consenting households in this building reported no heat, by week* — computed locally, with
> cells under five households suppressed, and consent recorded in advance in each household's
> own vault.
>
> **No organizer has ever reviewed it.** My own plan said to build it only after an organizer
> defined a real question, and I built it anyway, so it ships marked as needing outside
> review.
>
> The ask is one page and three questions: is that a number you would actually use, what
> question would you ask instead, and is "one organizer holds the keys to everyone's vault"
> a shape you would accept?
>
> Unpaid, synthetic data only, **not a pilot** — I am not asking you to run this on your
> building or your members. Credit, role-only credit, or anonymous, your choice.
>
> The brief:
> https://github.com/ChelseaKR/habitable/blob/main/docs/recruitment/profile-building-pattern.md
>
> "This is not how organizing works" is a completely useful answer.
>
> Chelsea Kelly-Reif · ckellyreif@gmail.com · https://github.com/ChelseaKR/habitable
