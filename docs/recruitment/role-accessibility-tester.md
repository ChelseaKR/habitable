# Role: accessibility tester — recorded NVDA + VoiceOver pass (EN + ES)

> **Status: alpha / concept stage.** habitable is not to be relied on for a real legal
> matter yet, and one of the few things gating the removal of that caveat is exactly the
> review described here. This is a **paid** engagement (or a fair stipend for an
> individual tester). We do **not** ask disabled people for free accessibility labor.

We are recruiting **one accessibility tester who uses assistive technology daily** to do a
single bounded, **recorded, moderated** screen-reader pass of habitable's two
user-facing artifacts in **English and Spanish**, against **WCAG 2.2 AA**. The findings
are published in-repo under our audit-as-artifact model and feed the Accessibility
Conformance Report.

This is **not** an open-ended audit. Automation already does the breadth; we need the one
thing automation cannot do — a human who hears the screen reader confirming that the app
and the packet are actually comprehensible and operable.

---

## 1. Who this is for

The single highest-value tester is a **native- or fluent-Spanish screen-reader user**,
because the load-bearing check is that the reader switches to a Spanish voice when the page
language changes — a sighted bilingual tester cannot verify that. We can split the matrix
across more than one tester if needed (e.g. one NVDA/Windows user, one VoiceOver/Apple
user), but a Spanish-fluent AT user is the one we most want to reach.

You do **not** need to be a developer or know the codebase. You need to use NVDA and/or
VoiceOver as a daily driver and be willing to think aloud while we record the session.

---

## 2. Scope — exactly two artifacts, two ATs, two languages

The full protocol you will work from is
[`docs/accessibility/manual-testing.md`](../accessibility/manual-testing.md); findings land
in [`docs/accessibility/ACR.md`](../accessibility/ACR.md). The scope below mirrors them.

**Two artifacts:**

1. **`packet.html`** — the designated evidence rendering whose real AT usability this pass must validate ([ADR 0004](../adr/0004-accessible-html-packet-as-conformant-rendering.md)).
   Confirm: a single `h1`; landmarks/headings let you jump between issues and the evidence
   appendix; the appendix table announces its column headers with each cell; every evidence
   image has a meaningful text alternative or an adjacent real-text caption; evidence status
   is announced **in words**, never by colour alone.
2. **The local web app** — `uv run habitable app --vault <demo-vault>`. Walk the full flow:
   add an issue → capture a (synthetic) photo → add a timeline entry → resolve timestamps →
   export → read the result. Confirm: a **skip link** on first Tab to `<main>`; labelled
   controls with required state announced; the resolve button announces its
   `aria-describedby` help; results and errors arrive via the polite live region; the
   language toggle is reachable and operable.

**AT matrix (2 artifacts × 2 ATs × 2 languages):**

- **NVDA + Firefox** on Windows
- **VoiceOver + Safari** on macOS, and **VoiceOver + Safari** on iOS (mobile is in
  [`docs/mobile.md`](../mobile.md) scope)
- **English and Spanish**, on **both** artifacts. The Spanish pass must confirm the reader
  switches to a Spanish voice when the page `lang` changes — the single most important
  reason we want a Spanish-fluent AT user.

The EN macOS+iOS VoiceOver run and the ES NVDA+VoiceOver run are the load-bearing ones.

**Standard:** WCAG 2.2 AA.

**What you do NOT need to re-test** (CI automation already covers it): axe-core scans in
EN + ES, structure/landmarks/alt/labels/no-positive-tabindex, EN/ES string parity, and PWA
installability. Your pass focuses on what only a human can judge: real screen-reader
comprehensibility, announcement order and quality, reading order, focus management,
live-region timing, table semantics in context, image-alt usefulness in context,
status-in-words, keyboard operability with no trap, 200% zoom + 320px reflow,
`prefers-reduced-motion`, and the EN↔ES voice switch.

---

## 3. Data — synthetic only, never real tenant data

You build everything from generated data; there is no IRB, consent, or privacy friction,
and nothing real is ever touched.

```sh
uv run habitable demo                        # builds a synthetic demo vault + packet
uv run habitable app --vault <demo-vault>    # the local web app, EN/ES, in a browser/AT
```

`packet.html` is produced by `habitable demo`. Full run instructions are in
[`docs/audits/onboarding.md`](../audits/onboarding.md) §2–3. **Do not load real tenant data
to evaluate habitable.**

---

## 4. What's provided to you

- The GitHub repo: <https://github.com/ChelseaKR/habitable>
- [`docs/audits/onboarding.md`](../audits/onboarding.md) — run instructions, synthetic data
- [`docs/accessibility/manual-testing.md`](../accessibility/manual-testing.md) — the exact
  checklist to fill (keyboard, screen readers, low-vision/zoom, cognitive/stress, exported
  packet)
- [`docs/accessibility/ACR.md`](../accessibility/ACR.md) — where findings land (VPAT 2.5,
  Rev 508; WCAG 2.2 A/AA)
- [`docs/mobile.md`](../mobile.md) — mobile/iOS scope
- A one-paragraph plain-language description of what habitable is, plus the alpha caveat

---

## 5. Deliverable

1. **Recordings** — screen capture **plus audio of the screen-reader speech** for each
   artifact × AT × language combination.
2. **A dated entry for [`docs/audits/`](../audits/)** — your name or handle, the
   NVDA/VoiceOver/browser versions used, pass/fail per `manual-testing.md` section, and each
   issue tagged with its **WCAG 2.2 AA success criterion + severity**.
3. **Findings that feed [`ACR.md`](../accessibility/ACR.md).**

**Recording-and-publishing consent is an explicit engagement term.** We publish the
recording and the report in-repo under our audit-as-artifact model
([`docs/audits/`](../audits/) + the ACR). Confirm up front that you consent to that, and
note any redaction you want (e.g. publish your handle, not your legal name).

**Re-test buffer.** Per the repo rule, a release **must not ship with an open
moderate-or-worse manual finding**, so the engagement includes a small fix-and-recheck
loop: we fix what you find, you confirm the fixes. Please scope a little time for that.

---

## 6. Effort estimate (to quote against)

Roughly **1–2 hours of moderated session per (AT × language) combination** once setup is
done — on the order of a **half-day to a full day** of tester time for the full matrix,
plus the small recheck buffer.

---

## 7. Where to find a tester — paid, pro-bono, and community channels

Listed cheapest-realistic to priciest. In every outreach we lead with: it is **paid**,
**synthetic-data-only**, a **public-interest AGPL/Apache FOSS** tool, the scope is **two
artifacts × NVDA+VoiceOver × EN+ES**, the deliverable is **recordings + a published WCAG
2.2 AA findings list**, and we ask explicitly about **Spanish-fluent screen-reader testers**
and **whether sessions are recorded by default**.

### Community — hire an individual (often the most affordable route)

- **A11y / web-a11y Slack** (~12k members; free to join, hire individuals). The standard
  venue to hire a single screen-reader user per session. Join via
  <https://accessibility.github.io/a11yslack/> (the shared invite link rotates; use the
  welcome page if a direct link 404s). Read the Code of Conduct, post a **paid** gig in the
  appropriate jobs/help channel, and ask for **Spanish/bilingual** screen-reader users.
- **Accessibility Mastodon / Fediverse instances** — `a11y.social`
  (<https://a11y.social/about>), `dragonscave.space` (blind-admin-run, many blind users and
  AT experts — best place to ask for **Spanish-speaking** screen-reader users), `a11y.info`.
  Post a clear **paid** gig with image alt text and CamelCase hashtags
  (`#Accessibility #ScreenReader #a11y`): scope, NVDA+VoiceOver, EN+ES, recorded
  deliverable, rate.
- **University Disability Resource Centers / AT labs** — especially **Hispanic-Serving
  Institutions** and Spanish-language programs for the ES pass. Email AT-lab coordinators
  describing a **paid one-off recorded** test on synthetic data and offer a fair per-session
  stipend. Availability is ad hoc; the synthetic-data-only design removes IRB friction.
  (e.g. <https://accessibility.harvard.edu/Assistive-Technology-Center>)
- **National Federation of the Blind (NFB) — Center of Excellence in Nonvisual
  Accessibility** (<https://nfb.org/programs-services/center-excellence-nonvisual-access>).
  Formal certification is overkill for an alpha tool, but NFB state/local chapters and
  member listservs are a strong channel to recruit individual blind testers, including
  **Spanish-speaking members**, for a paid per-session pass.
- **AccessAbility Officer — Certified AccessAbility Tester (CAT) program**
  (<https://accessabilityofficer.com/blog/cat-program-launch-your-digital-accessibility-career-as-a-blind-professional>).
  Credentialed blind/low-vision testers (~$25/hr). Ask whether you can engage a
  graduate/apprentice for a single recorded NVDA + VoiceOver pass, and about Spanish
  capability.

### Mission-based vendors — managed, recorded, paid disabled testers (ask for a single-pass minimum and a FOSS/nonprofit rate)

- **WeCo — Digital Accessibility by WeCo** (<https://theweco.com/accessibility-services/>).
  Disabled certified testers; offers a **low-cost/baseline tier and a FREE sample review** —
  a realistic way to scope before committing. Request the free review first (phone
  855-849-5050 or the site form), then ask for a baseline disability-focused test on
  NVDA and/or VoiceOver, recorded, EN+ES. **Confirm explicitly** that they record sessions,
  that they cover VoiceOver specifically, and whether any tester works in Spanish.
- **Knowbility AccessWorks** (<https://knowbility.org/services/accessworks>). A managed panel
  of disabled testers (daily NVDA/JAWS/VoiceOver users), run by a long-standing accessibility
  nonprofit — engaging them also supports the disability-employment mission. Best fit for the
  recorded moderated pass. Email **aw-services@knowbility.org** with the study (artifacts,
  ATs, EN+ES, recorded sessions + WCAG 2.2 AA findings) and ask for a quote/SOW, the
  **minimum engagement size**, whether they **record by default**, **bilingual/native-Spanish
  tester** availability, and any **nonprofit/community/FOSS rate**.
  - Related: **Knowbility AccessU 2026 + the Accessibility Internet Rally (AIR)** pro-bono
    program (<https://knowbility.org/programs/john-slatin-accessu-2026/volunteers>) — a
    community to recruit a tester from, and a possible pro-bono structural route. Ask whether
    a public-interest FOSS legal-aid tool qualifies for AIR or a community-rate engagement.
- **Equalize Digital — Web Accessibility User Testing**
  (<https://equalizedigital.com/services/web-accessibility-user-testing/>). Real blind/VI
  testers (partnered with the Texas School for the Blind) using JAWS/NVDA/VoiceOver, paid
  above minimum wage; values-aligned and approachable for small/independent projects. Submit
  their contact form for a custom estimate; state the artifacts, ATs (NVDA + VoiceOver,
  desktop + iOS), EN+ES, that you want **recorded** sessions, and that it is an unfunded
  AGPL/Apache FOSS public-interest tool. Ask about a **minimum-scope single pass** and
  **Spanish** capability.

### Aspirational — only if a grant or sponsor appears

- **Fable (Make It Fable)** (<https://makeitfable.com/pricing/>). Crowdtesting by disabled
  daily AT users (NVDA + VoiceOver), with **video where you hear what the screen-reader user
  hears** — recordings by default, a direct match to our deliverable. **But** self-serve
  Fable Engage starts at **~$3,750 USD/project** (verified Jun 2026) — likely out of reach
  for an unfunded solo project. Treat as the option for if a sponsor/grant appears; if
  contacting sales, ask whether a smaller single-artifact package or any FOSS/nonprofit
  discount exists.

> **Verification note (Jun 2026).** Vendor existence, model, and AT coverage are verified.
> **Pricing, minimum scope, whether sessions are recorded by default, and Spanish-fluent
> tester availability are UNVERIFIED for every agency** and must be confirmed by direct
> contact. **Spanish-language coverage is the weakest-confirmed dimension everywhere** — the
> most reliable ES route is hiring an individual native/fluent-Spanish screen-reader user via
> NFB chapters, `dragonscave.space`, or an HSI AT lab rather than assuming an agency has one
> on the bench.

---

## 8. Ready-to-send outreach email / post

> **Subject:** Paid recorded screen-reader pass (NVDA + VoiceOver, EN + ES) — open-source tenant-rights tool
>
> Hi —
>
> I maintain **habitable**, a free, open-source (AGPL-3.0 / Apache-2.0), offline-first tool
> that helps tenants document housing-habitability problems as tamper-evident evidence. It's
> an independent, unfunded public-interest project, currently in alpha.
>
> I'm looking to **pay** a screen-reader user for a small, bounded, **recorded moderated**
> accessibility pass against **WCAG 2.2 AA**. Scope is fixed and small:
>
> - **Two artifacts:** an accessible HTML evidence packet (`packet.html`) and a small local
>   web app.
> - **Two assistive technologies:** **NVDA + Firefox** (Windows) and **VoiceOver + Safari**
>   (macOS **and** iOS).
> - **Two languages:** **English and Spanish** on both artifacts. The most important single
>   check is that the screen reader switches to a Spanish voice when the page language
>   changes — so I'd especially love to reach a **native- or fluent-Spanish screen-reader
>   user**.
>
> Everything runs on **synthetic, generated data** — no real personal or tenant data is ever
> involved, so there's no privacy/consent friction. Estimated effort is roughly **1–2 hours
> per assistive-technology × language combination** (about a half-day to a day total), plus a
> little time to re-check fixes I make from your findings.
>
> **Deliverable:** screen + audio recordings of each pass, and a short findings list mapped
> to WCAG 2.2 AA. I publish accessibility reviews openly in the project's repository as part
> of how the project keeps itself honest, so **consent to publish the recording and report
> (under whatever name/handle you choose) would be part of the engagement** — happy to
> discuss redaction.
>
> Could you let me know:
> 1. Your **rate** for a pass of this scope (and any minimum)?
> 2. Whether you **record sessions** by default (or whether I should)?
> 3. Whether you / your testers can work in **Spanish**?
> 4. Earliest availability?
>
> I'll provide everything needed to run it: the repo, plain-language run instructions, the
> exact test checklist, and a one-paragraph description of the tool. Thank you — and to be
> explicit, this is paid work; I'm not asking for free labor.
>
> Best,
> Chelsea Kelly-Reif — habitable — https://github.com/ChelseaKR/habitable

For Slack/Mastodon, trim to the scope + the four questions + the explicit "this is paid,"
use the right jobs/gigs channel, and follow each community's Code of Conduct.

---

## 9. Related roles

The independent **security + cryptographic auditor** role and the reviewer onboarding live
in [`docs/audits/onboarding.md`](../audits/onboarding.md) and
[`docs/audits/README.md`](../audits/README.md). The housing-lawyer and pilot-partner roles
are recruited separately and are out of scope for this brief.
