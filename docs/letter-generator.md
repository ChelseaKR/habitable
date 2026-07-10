<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Repair-request letter generator — design & jurisdiction assumptions

> **Audience.** Tenants and organizers using `habitable letter`, and reviewers checking
> that the generator does not overstate the law. Companion to
> [`evidence-method.md`](evidence-method.md).

## What it does

`habitable letter` turns the case a tenant has already documented (issues, the timeline,
and the timestamped photos) into a dated, on-paper **repair-request / notice letter**
addressed to the landlord, rendered both as accessible HTML (`letter.html`) and as a PDF
(`letter.pdf`). The letter:

- addresses the landlord and identifies the unit (the landlord already knows the address —
  this is the tenant's own outgoing correspondence, **not** the location-redacted court
  packet);
- lists each condition with its room, severity, description, and the date it was first
  documented;
- states that the conditions are backed by *N* photographs (with *M* carrying an
  independent trusted timestamp) whose content hashes allow integrity verification, and
  that a full, independently-verifiable evidence packet is available on request;
- makes a dated repair request with a configurable cure period; and
- carries a standing **"this is not legal advice"** disclaimer.

The structured content is produced once (`letter.py`) and rendered identically to HTML and
PDF, so the two cannot drift. Every dynamic value is escaped before rendering — letter
content is treated as data, never markup.

## Jurisdiction-awareness, honestly scoped

Habitability law is **state- and city-specific**, and habitable is not a lawyer. The
generator is deliberately **framing-only and template-driven** so it can be useful without
asserting law it cannot guarantee:

- A `LetterProfile` supplies the *wording*: an opening framing, a **hedged** reference to
  the kind of law that commonly applies, and a default cure period (days).
- The built-in profiles **make no claim about a specific statute or code section.** They
  use widely-recognized concepts in hedged language and tell the reader to confirm their
  own jurisdiction:
  - **`generic`** (default) — assumes no jurisdiction. "Many jurisdictions require a
    landlord to maintain rental housing in a safe and habitable condition… Please treat
    this letter as written notice."
  - **`us_habitability`** — generic U.S. framing. "In *most* U.S. jurisdictions a
    residential tenancy carries an implied warranty of habitability and a duty to repair
    within a reasonable time after written notice; the specific deadlines, remedies… and
    notice requirements **vary by state and city. Please confirm the rules that apply.**"
- A test (`test_jurisdiction_profiles_and_fallback`) asserts the built-ins contain no
  section sign (`§`) or `U.S.C` citation, guarding against drift toward false precision.

### Assumptions a reviewer should know

1. **The default cure period is 14 days** — a common but *not* universal figure. It is a
   placeholder, overridable per letter (`--cure-days`) or in config
   (`[letter] cure_period_days`). It is **not** a legal deadline for any specific place.
2. **The implied warranty of habitability is not universal.** Some U.S. jurisdictions
   recognize it by statute, some by case law, and a few barely at all; the `us_habitability`
   framing says "most" and "where recognized" precisely because of this.
3. **"Written notice" framing assumes notice is relevant.** In many places written notice
   to the landlord is a precondition to remedies, but the form and delivery requirements
   vary; the letter does not assert it satisfies any particular notice statute.
4. **No remedy is asserted.** The letter requests a repair; it does not threaten or invoke
   repair-and-deduct, rent withholding, or termination, because those remedies and their
   preconditions are jurisdiction-specific.

### Where local law belongs: config, not code

A union that has **confirmed** its local law encodes that in `config.toml`, mirroring the
`[packet_template]` philosophy — verified, reviewable, per-union wording rather than
hard-coded claims:

```toml
[letter]
sender_name = "Tenant Name"
sender_contact = "phone or email"
recipient_name = "Acme Property Management"
recipient_address = "123 Main St"
jurisdiction = "us_habitability"   # or "generic"
cure_period_days = 14              # 0 = use the profile default
header = "Notice under <your state> habitability law, § <verified citation>"
footer = "Prepared with the <your tenant union>. Not legal advice."
```

The `header`/`footer` are the right place to put a **locally-verified** statutory citation;
the generator itself will never invent one.

## Relationship to the evidence

The letter is *generated from* the logged evidence but is **not** itself the proof. It
references counts, dates, and the availability of the verifiable packet; the cryptographic
record remains `bundle.json` and is produced by `habitable export`. A landlord or court who
wants to check the claims uses `habitable verify` on the packet, not the letter.
