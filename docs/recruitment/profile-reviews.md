# Workflow profile reviews — six gated profiles, one domain reader each

> **Status: alpha / concept stage.** habitable is an independent, unfunded personal
> open-source project with a bus factor of one, and it is **not to be relied on for a real
> legal matter.** Every review described here is **unpaid, bounded, and done on synthetic
> data only.** These are reviews of **framing** — how a workflow talks to the person on the
> receiving end — and they are **not legal, medical, or code-compliance advice**, do not
> certify the tool, and create no professional or client relationship with anyone.

Eleven built-in workflow profiles ship ([ADR 0010](../adr/0010-profile-driven-evidence-workflows.md)).
Five are marked `maintainer_reviewed`. **Six are implemented but marked
`external_review_required`**, and that marking is a **named-reviewer gate, not an
engineering gap.** The code runs, the tests pass, the state is signed into every packet.
What is missing is a person from the relevant field who has read what the profile asserts
and said whether it is right.

A profile a domain expert would find naive is worse than no profile at all: it puts a
tenant in front of an inspector, a housing authority, a clinician, or an advocacy org
holding a document that reads as though it knows the rules. That is the failure this gate
exists to prevent, and only an outside reader can lift it.

## One profile is a complete contribution

This is the part worth saying first. **You do not have to review six, or two.** Each brief
below is a separate, self-contained ask about a single workflow. One answered brief closes
one gate, is recorded on its own date, and is useful whether or not anybody ever reviews
the other five. This should not be done all at once, and it should not be done by one
person — the six audiences have almost nothing in common.

## The six briefs

| Profile | Who we are looking for | Brief |
| --- | --- | --- |
| `inspector_handoff` | A code-enforcement or housing inspector — someone who receives tenant documentation and decides what to do with it | [profile-inspector-handoff.md](profile-inspector-handoff.md) |
| `accommodation_request` | A disability-rights advocate or fair-housing worker who has helped tenants make and document accommodation requests | [profile-accommodation-request.md](profile-accommodation-request.md) |
| `public_housing_remediation` | Someone who has worked with or against a housing authority on a remediation cycle | [profile-public-housing-remediation.md](profile-public-housing-remediation.md) |
| `health_corroboration` | A clinician or public-health worker who has written housing-related letters | [profile-health-corroboration.md](profile-health-corroboration.md) |
| `building_pattern` | A tenant organizer who has run a building-wide campaign | [profile-building-pattern.md](profile-building-pattern.md) |
| `partner_capsule` | A legal-aid or advocacy organization that receives referrals and evidence from outside | [profile-partner-capsule.md](profile-partner-capsule.md) |

This page holds what all six have in common — what a profile is, what the review is and is
not, how to see one, and how your answer is recorded. Each brief holds what only its own
profile needs: what it actually asserts, the questions it needs answered, and what would
make it fail.

## What a profile is — and what it cannot do

A profile is a small, versioned, built-in record in
[`src/habitable/usecases.py`](../../src/habitable/usecases.py). It carries:

- an id and a version;
- a name and a one-line summary, in English and Spanish;
- the **document types** it offers (e.g. `inspection_report`, `clinician_letter`);
- the **relationship types** it offers (e.g. `inspection_finding_for`, `supports`);
- an ordered list of **handoff section headings** — the order a recipient is expected to
  read in;
- its **disclosures** — sentences that travel with the export and cannot be suppressed; and
- its review metadata: `review_state`, `reviewer`, `jurisdiction`, `reviewed_at`,
  `expires_at`.

That is the whole surface. A profile is **presentation and prompting policy only.** It
cannot change hashing, custody, timestamping, sync, or a verifier's verdict, and it cannot
suppress a disclosure — those are the invariants ADR 0010 was written to protect. So the
question in front of you is never "does the cryptography work"; it is **"does this
vocabulary, this reading order, and this set of disclosures describe your world honestly?"**

**Two limits to know before you look at any of them.**

- **The sections do not sort anything.** The handoff view lists a profile's section
  headings, but the case model does not record which record belongs to which heading. The
  manifest says so in as many words (`"section_membership": "not_recorded"`), the rendered
  page says so, and the only counts printed are for the whole packet. So the headings today
  are a *stated reading order*, not routing. If a brief says "chronology" and you expect
  records sorted under it, they will not be.
- **The document and relationship types are declared, not enforced.** A profile's lists are
  published inside the packet as that workflow's vocabulary, and they are what the briefs
  quote — but nothing in the tool restricts a case to them. The app offers all thirteen
  document types whatever profile is selected. Read the lists as "this is what this
  workflow says it is about", not "this is all a tenant can add".

## Where a profile is actually visible

Worth knowing so you review what a recipient really sees:

- `habitable profile list` prints one line per profile with a gate column —
  `external review required` for all six of these.
- `habitable profile set` prints, on selection, that external domain or accessibility
  review is still required before pilot use.
- `bundle.json` inside an exported packet carries the whole profile — including
  `"external_review_required": true` — under `use_case_profile`, signed with the rest of
  the bundle.
- Exporting with `--handoff-profile <id>` writes `handoff-<id>.html` beside the packet.
  For a gated profile that page opens with: *"External review required. This workflow is
  implemented for synthetic evaluation; it is not a legal, medical, inspector, or
  accessibility approval."*
- `packet.html` — the main accessible rendering a recipient reads — carries the project's
  standing disclosures but **does not mention the profile at all.** If you think a
  profile's disclosure needs to reach the recipient, say so; today it reaches them only
  through the handoff page and `bundle.json`.

## Seeing it for yourself (about ten minutes, no real data)

You do not have to run anything — every brief quotes the exact strings under review. If you
want to see it in context, it is offline and synthetic:

```sh
git clone https://github.com/ChelseaKR/habitable.git
cd habitable
uv sync --all-extras
uv run habitable profile list                     # the eleven profiles and their gates
uv run habitable demo                             # a synthetic case + packet, no network needed
uv run habitable export --vault <demo-vault> --out <dir> --handoff-profile <profile_id>
```

The demo prints where it put its vault; its passphrase is the synthetic literal at the top
of [`src/habitable/demo.py`](../../src/habitable/demo.py). Full run instructions are in
[`docs/audits/onboarding.md`](../audits/onboarding.md).

**Synthetic data only — never real tenant, client, or patient data, ever.** Nothing about
this review needs a real case, and a real one would create a risk the project has no way to
carry.

## What the review is, and is not

**It is:** a read of one profile's vocabulary, reading order, and disclosures against how
your field actually works, and a judgement on whether anything it produces overclaims.

**It is not:**

- **Not advice.** Not legal advice, not a medical opinion, not a code determination, not a
  compliance opinion. Nothing you say is presented as advice to any tenant.
- **Not certification.** Answering a brief does not endorse habitable, does not mean you
  think it is fit for a real matter, and does not attach your name to the tool. The project
  stays alpha either way.
- **Not representation or a client relationship**, and not an evaluation of anybody's real
  case.
- **Not a security, accessibility, or code review.** Those are separate tracks —
  [role-auditor.md](role-auditor.md),
  [role-accessibility-tester.md](role-accessibility-tester.md).
- **Not an audit of anything you are responsible for.** You are reading a tool's copy, not
  your employer's process.

**And it is unpaid.** There is no funding behind this project and no bounty (see
[`SECURITY.md`](../../SECURITY.md) and [`docs/sustainability.md`](../sustainability.md)).
That is why each brief is scoped to something you could answer over one coffee rather than
one weekend. If the ask is still too big, say which single question you *can* answer —
that is a real contribution too.

## What to send back

Whatever is easiest for you. Inline notes on the brief, an email, a voice memo, a GitHub
issue, a pull request — all fine. Pointed beats comprehensive:

> *"Nobody in code enforcement calls that a 'finding'. And the third heading should come
> first — I look at the chronology before I look at the room."*

The **single most valuable answer is a place where the profile overclaims**, or a word it
uses that already means something specific and different in your field. The second most
valuable is a thing the profile leaves out that you always need.

If your answer is "this is wrong and should not ship", say that. A profile withdrawn on a
domain reader's advice is a good outcome, not a failed review.

## How your answer is recorded

Per profile, dated, in public — the project runs
[audit-as-artifact](../audits/README.md), so a review is a committed file rather than a
private assurance, and anyone can diff it across releases.

1. **A dated row in [`docs/capabilities.md`](../capabilities.md)**, the ledger that controls
   what habitable may honestly claim, naming the profile, the date, and what you found.
2. **The profile's own fields** — `reviewer`, `reviewed_at`, and where relevant
   `jurisdiction` — are filled in from your review, and the review state stops saying
   external review is required. Those fields are signed into every packet exported
   afterwards, so a recipient sees the review travelling with the evidence.
3. **An expiry, if your read is jurisdiction- or practice-dependent.** A profile can carry
   `expires_at`; once it passes, selecting that profile is refused and an export that had
   already selected it falls back to no profile rather than presenting stale guidance
   ([ADR 0012](../adr/0012-profile-review-expiry-enforcement.md)). Tell us how long you
   think your answer stays true.

Findings that require changing the profile land as a change first; the ledger row follows
the change rather than announcing it in advance.

## Credit, and conflicts of interest

**Credit is your choice.** We are glad to name you and your organization, to credit a role
without a name ("a code-enforcement inspector, 2026-09"), or to record the review with no
attribution at all. Say which; the default is to ask you before publishing anything.

**On conflicts.** Several of these reviews ask people who work inside the institutions the
tool hands evidence to. That is the point — nobody else knows the answer — but it means:

- **Review as yourself, not for your employer**, unless your employer has agreed. Nothing
  recorded will describe your organization as having reviewed or endorsed anything unless
  you explicitly ask for that.
- **Tell us any affiliation you would want a reader to know**, and it goes in the record
  next to your answer.
- **Do not use a real matter, a real client, or a real patient** to test this. Ever.
- If reviewing this could create a problem for you at work, in a professional-conduct rule,
  or with a client — **do not do it.** No brief here is worth that, and an anonymous
  answer is available if it helps.

## How to reach the maintainer

Async-first; a call is opt-in and never the entry point.

1. **Fastest:** the
   [reviewer intake form](https://github.com/ChelseaKR/habitable/issues/new?template=reviewer-intake.yml)
   — pick the closest role and name the profile in the free-text field.
2. **Scoping questions:** a
   [GitHub Discussion](https://github.com/ChelseaKR/habitable/discussions).
3. **Email:** ckellyreif@gmail.com.

Realistic cadence from a solo maintainer: acknowledgment within a few business days.
Silence is not a no.

## Notes for the maintainer

- **These briefs carry no target list.** [role-legal-reviewer.md](role-legal-reviewer.md)
  and [role-pilot-partner.md](role-pilot-partner.md) name organizations because those were
  verified at a date; nothing was verified for these six, so each brief describes the
  *kind* of channel to approach and stops there. Add named leads only after checking them,
  with the date, the way the existing kits do.
- **Pitch hygiene carries over unchanged.** Never a client-intake line, never a clinical
  intake line, never a complaint hotline. Route to outreach, education, training,
  communications, professional-association, or volunteer-coordinator channels, and lead
  with "synthetic data, framing only, not representation, unpaid, one profile".
- **Do not describe availability inside habitable as domain approval.** The profiles
  disclose their own state; these briefs must never contradict that.
- The intake form's role dropdown does not yet have an option for this work; until it does,
  reviewers land under "Other".
