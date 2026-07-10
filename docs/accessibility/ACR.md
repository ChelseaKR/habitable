# habitable — Accessibility Conformance Report (ACR)

Based on the **Voluntary Product Accessibility Template (VPAT) version 2.5 (Rev 508)**.

> **Update (2026-07-09): the local web app is built and has automated accessibility gates.**
> `habitable app` ships with semantic landmarks, a skip link, a single `h1`,
> programmatically labelled controls (the resolve action uses `aria-describedby`),
> `lang`/`title`/viewport, an `aria-live` status region, visible focus, no positive
> `tabindex`, and mechanical English/Spanish catalog parity. These are enforced in CI with:
> structural tests (`tests/test_app_accessibility.py`, `tests/test_app_i18n.py`), **a
> real `axe-core` scan** of the running app in **both languages** (blocking on any
> moderate/serious/critical violation, `tests/test_app_axe.py`), and **keyboard +
> reflow tests** that verify the skip link is first in tab order, every major control
> is reachable without a trap, and the layout reflows at 320px with no horizontal
> scrolling (`tests/test_app_keyboard.py`; WCAG 2.1.1, 2.4.3, 1.4.10). All run in the
> `a11y` workflow and the app currently reports **zero** axe violations. The remaining
> evidence required before any conformance *claim* includes the documented human
> keyboard, zoom/reflow, language, and **screen-reader (NVDA/VoiceOver) pass**, per
> [`manual-testing.md`](manual-testing.md); none has been recorded yet. Automated
> results are not a WCAG conformance determination.
>
> **Packet accessibility.** ReportLab's open-source API has no marked-content, so a
> fully tagged **PDF/UA structure tree is not produced**. Instead: (a) the PDF declares
> its **language** (`/Lang`, matching the configured locale), sets **DisplayDocTitle**,
> and carries a navigable **outline/bookmarks** with selectable text; and (b) every
> packet also ships **`packet.html`** — a self-contained HTML rendering built toward
> WCAG 2.2 AA
> (landmarks, one `h1`, a captioned appendix table with header scopes, meaningful image
> `alt`, the document language) that **passes the same axe-core gate**
> (`tests/test_htmlpacket.py`). The machine-verifiable `bundle.json` remains the
> canonical record.
>
> **`packet.html` is the designated accessible rendering** of a packet, and the PDF is a
> best-effort print/presentation convenience that makes **no PDF/UA conformance claim**.
> The HTML's automated axe result is evidence, not a complete WCAG conformance claim
> (decided in [ADR 0004](../adr/0004-accessible-html-packet-as-conformant-rendering.md)).
> A fully tagged PDF/UA file is revisited only if a suitable open-source tagging
> toolchain becomes available; the PDF rows below describe its current best-effort
> behaviour, not a conformance target.

## Name of Product / Version

**habitable** — version **0.2.0** (alpha / working reference implementation).

## Report Date

2026-07-09

## Product Description

habitable is an alpha, offline-first, end-to-end-encrypted habitability-documentation tool for
tenant unions. Captured media receives a content hash, RFC 3161 token, and custody records; timeline
notes are narrative CRDT records included in the signed bundle, not individually hashed or
timestamped. Exports include an HTML rendering, a best-effort PDF, and a verifiable bundle. No legal,
court, inspector, or accessibility fitness claim has been externally validated.

## Contact Information

- Project: habitable (independent personal open-source project, AGPL-3.0)
- Issues, source, and accessibility feedback: the project's GitHub repository (file an issue, or use
  the alternate contact in the repository's `SECURITY` / `CONTRIBUTING` documents)

## Notes

This is an implemented but **alpha and externally unvalidated** project. The local web app exists;
there is no signed native app-store package. To avoid overclaiming:

- Criteria that depend on the application (the capture flow, timeline, review list, sync UI, settings,
  and the desktop/PWA client) remain **"Not Evaluated"** where a human AT or usability judgment is
  required. Automated checks are cited as evidence but are not statements of full conformance.
- Criteria that the **packet PDF renderer** touches *are* assessed against current behavior, because
  that component exists (`src/habitable/pdf.py`). Those rows describe what the code does today,
  including its known gaps.

## Evaluation Methods Used

- **Source inspection** of the PDF packet renderer (`src/habitable/pdf.py`) and the project's
  accessibility commitments (`README.md`, "Accessibility and Section 508 conformance"). The renderer
  sets the PDF document title, author, and subject metadata; sets the document language to `en`; emits
  **real, selectable/searchable text** (not rasterized text); and renders the evidence appendix as a
  text table. It does **not** yet emit a fully tagged **PDF/UA** structure tree (headings, table
  header associations, reading order, figure alternate text); that work is tracked.
- **Automated app testing** includes axe in EN/ES plus keyboard-order and 320 px reflow checks. No
  recorded human NVDA/VoiceOver pass, human Spanish review, or complete manual WCAG walkthrough has
  been performed. Those evaluations remain release gates (see *Roadmap*).

---

## Applicable Standards / Guidelines

This report covers the following standards and guidelines.

| Standard / Guideline | Included in report |
| --- | --- |
| [Web Content Accessibility Guidelines (WCAG) 2.2](https://www.w3.org/TR/WCAG22/) | Level A (yes) · Level AA (yes) · Level AAA (no) |
| Revised Section 508 standards (36 CFR Part 1194) — Chapter 3, Functional Performance Criteria | Yes |
| Revised Section 508 standards — Chapter 5, Software | Yes |
| Revised Section 508 standards — Chapter 6, Support Documentation and Services | Yes |

**On Section 508 applicability.** habitable is a tenant-union tool, not federal ICT, so the Revised
Section 508 Standards are **not legally required** here. The project adopts them anyway as a values and
usability position: disabled tenants face housing discrimination and habitability harms at high rates,
a tool meant to give tenants power that a disabled tenant cannot operate has failed at its purpose, and
conforming to the standard governments audit to also makes the packets usable to the legal-aid workers
and inspectors who receive them. WCAG 2.2 AA is the primary target; the Revised 508 chapters are
mapped here for completeness and to keep the discipline auditable.

---

## Terms / Conformance Levels

The terms used to describe each criterion's conformance level are:

| Term | Meaning |
| --- | --- |
| **Supports** | The functionality of the product has at least one method that meets the criterion without known defects, or meets it with equivalent facilitation. |
| **Partially Supports** | Some functionality of the product does not meet the criterion. |
| **Does Not Support** | The majority of product functionality does not meet the criterion. |
| **Not Applicable** | The criterion is not relevant to the product. |
| **Not Evaluated** | Available automated evidence is insufficient for a conformance finding, or the criterion still requires human evaluation. The target is WCAG 2.2 AA. |

Throughout the tables below, two scopes are distinguished:

- **App (implemented; human evaluation open):** the local web client has automated axe, keyboard,
  reflow, and catalog-parity evidence. Rows remain **Not Evaluated** where no human result exists.
- **Packet PDF (current):** the existing renderer in `src/habitable/pdf.py`, assessed against current
  behavior.

---

## Chapter 3: Functional Performance Criteria (FPC)

Notes distinguish automated app evidence from human evaluation still required, and describe the
packet PDF's current behavior where the PDF is relevant.

| Criteria | Conformance Level | Remarks and Explanations |
| --- | --- | --- |
| **302.1 Without Vision** | Not Evaluated (app); Partially Supports (PDF) | **App:** semantic/axe automation exists; real NVDA/VoiceOver completion is untested. **PDF current:** text is selectable and the document language is set, but the PDF is **not PDF/UA-tagged**, so reading order, heading structure, and table associations are not programmatically guaranteed. |
| **302.2 With Limited Vision** | Not Evaluated (app); Partially Supports (PDF) | **App:** 320 px reflow is automated; human zoom/magnification review remains open. **PDF current:** text zooms without rasterization, but the fixed page layout does not reflow and tagging is incomplete. |
| **302.3 Without Perception of Color** | Not Evaluated (app); Supports (PDF) | **App:** text equivalents are structurally tested; human review remains open. **PDF current:** evidence status is rendered as words in captions and the appendix table, not by color alone. |
| **302.4 Without Hearing** | Not Applicable (PDF); Not Evaluated (app) | The packet PDF has no audio. The app supports text transcripts for captured audio/video, but a human evaluation has not been completed. |
| **302.5 With Limited Hearing** | Not Applicable (PDF); Not Evaluated (app) | Same as 302.4 — no audio is required to operate the product or read a packet. |
| **302.6 Without Speech** | Not Applicable | The product requires no speech input. |
| **302.7 With Limited Manipulation / Strength / Reach** | Not Evaluated (app) | Keyboard navigation has automated coverage; a human limited-dexterity/pointer evaluation has not been completed. The packet PDF requires no manipulation to read. |
| **302.8 With Limited Reach and Strength** | Not Evaluated (app) | Covered by the keyboard and pointer-use evaluation above; human evaluation remains open. |
| **302.9 With Limited Cognition, Language, or Learning** | Not Evaluated (app); Partially Supports (PDF) | The app uses text status and has automated EN/ES catalog parity, but plain-language and cognitive-usability review are open. **PDF current:** the packet uses status words and a non-legal-advice disclaimer; human review remains open. |

---

## WCAG 2.x Report — Level A and AA

For each success criterion, the table gives the app's **current automated evidence or remaining
human-evaluation target** and the **current status for the packet PDF**. Where a criterion does not
apply to a non-interactive PDF, that is noted.

The packet PDF's central honest caveat: it emits **real selectable text** with document language and
title/author/subject metadata, but it is **not yet a tagged PDF/UA document** — headings, table header
cell associations, figure alternate text, and an explicit reading-order structure tree are not yet
emitted. That gap is tracked work and affects several rows below.

### Table 1: Success Criteria, Level A

| Criteria | Conformance Level | Remarks and Explanations |
| --- | --- | --- |
| **1.1.1 Non-text Content** (A) | Not Evaluated (app); Partially Supports (PDF) | App target: text alternatives for all non-text content. **PDF current:** evidence photos are embedded as images **without programmatic alternate text**; however each image is immediately followed by a real-text caption (capture time, hash prefix, timestamp status) that conveys its evidentiary meaning. Tagged figure `/Alt` is tracked. |
| **1.2.1 Audio-only / Video-only (Prerecorded)** (A) | Not Applicable (PDF); Not Evaluated (app) | The PDF carries no time-based media. App target covers captured video where present. |
| **1.2.2 Captions (Prerecorded)** (A) | Not Applicable (PDF); Not Evaluated (app) | App target: captions for any prerecorded video evidence shown in-app. |
| **1.2.3 Audio Description or Media Alternative** (A) | Not Applicable (PDF); Not Evaluated (app) | App target as above. |
| **1.3.1 Info and Relationships** (A) | Not Evaluated (app); Partially Supports (PDF) | App target: semantic structure exposed programmatically. **PDF current:** visual structure (title, headings, appendix table) is present and reads as real text, but the document is **not yet tagged**, so heading levels and table header-to-data associations are not programmatically determinable. Tracked. |
| **1.3.2 Meaningful Sequence** (A) | Not Evaluated (app); Partially Supports (PDF) | **PDF current:** visual/content order is logical (issue → timeline → photos → appendix) and selectable text follows that order, but no explicit tagged reading-order tree is emitted yet. |
| **1.3.3 Sensory Characteristics** (A) | Not Evaluated (app); Supports (PDF) | **PDF current:** instructions and status do not rely on shape, size, or location; status is stated in words. |
| **1.3.4 Orientation** (AA) | Not Evaluated (app) | App target: no orientation lock (mobile-first PWA). N/A to the PDF. |
| **1.3.5 Identify Input Purpose** (AA) | Not Evaluated (app) | App target: programmatic input-purpose identification on relevant fields. N/A to the PDF (no inputs). |
| **1.4.1 Use of Color** (A) | Not Evaluated (app); Supports (PDF) | **PDF current:** no information is conveyed by color alone; evidence status is words. |
| **1.4.2 Audio Control** (A) | Not Applicable | No auto-playing audio. |
| **2.1.1 Keyboard** (A) | Not Evaluated (app) | App target: all functionality keyboard-operable; manual NVDA/VoiceOver and keyboard-only review at the release gate. N/A to the static PDF. |
| **2.1.2 No Keyboard Trap** (A) | Not Evaluated (app) | App target. N/A to the PDF. |
| **2.1.4 Character Key Shortcuts** (A) | Not Evaluated (app) | App target. N/A to the PDF. |
| **2.2.1 Timing Adjustable** (A) | Not Evaluated (app); Supports (PDF) | App target: time limits avoidable so a tenant documenting under stress is not rushed. **PDF current:** static document imposes no time limit. |
| **2.2.2 Pause, Stop, Hide** (A) | Not Applicable (PDF); Not Evaluated (app) | No moving/auto-updating content in the PDF. App target where applicable. |
| **2.3.1 Three Flashes or Below Threshold** (A) | Not Applicable (PDF); Not Evaluated (app) | No flashing content in the PDF. |
| **2.4.1 Bypass Blocks** (A) | Not Evaluated (app) | App target: skip mechanisms/landmarks. N/A to the PDF. |
| **2.4.2 Page Titled** (A) | Not Evaluated (app); Supports (PDF) | **PDF current:** the document title metadata is set (e.g. "habitability evidence packet — unit 4B"), so assistive tech announces a meaningful title. |
| **2.4.3 Focus Order** (A) | Not Evaluated (app) | App target. N/A to the static PDF. |
| **2.4.4 Link Purpose (In Context)** (A) | Not Evaluated (app) | App target. The PDF has no hyperlinks. |
| **2.5.1 Pointer Gestures** (A) | Not Evaluated (app) | App target: no reliance on multipoint/path-based gestures; capture works without precise pointer control. N/A to the PDF. |
| **2.5.2 Pointer Cancellation** (A) | Not Evaluated (app) | App target. N/A to the PDF. |
| **2.5.3 Label in Name** (A) | Not Evaluated (app) | App target. N/A to the PDF. |
| **2.5.4 Motion Actuation** (A) | Not Evaluated (app) | App target: no motion-only actuation. N/A to the PDF. |
| **3.1.1 Language of Page** (A) | Not Evaluated (app); Supports (PDF) | **PDF current:** the document language is set to `en` (`lang="en"`) in the renderer, so assistive tech selects the correct pronunciation/voice. |
| **3.2.1 On Focus** (A) | Not Evaluated (app) | App target. N/A to the PDF. |
| **3.2.2 On Input** (A) | Not Evaluated (app) | App target. N/A to the PDF. |
| **3.3.1 Error Identification** (A) | Not Evaluated (app) | App target. N/A to the PDF (no input). |
| **3.3.2 Labels or Instructions** (A) | Not Evaluated (app) | App target. N/A to the PDF (no input). |
| **4.1.2 Name, Role, Value** (A) | Not Evaluated (app); Partially Supports (PDF) | App target: all UI components expose correct name/role/value/state. **PDF current:** content is real text but, untagged, structural roles (heading, table header) are not yet programmatically exposed; tracked with the PDF/UA work. |

### Table 2: Success Criteria, Level AA

| Criteria | Conformance Level | Remarks and Explanations |
| --- | --- | --- |
| **1.2.4 Captions (Live)** (AA) | Not Applicable | No live media. |
| **1.2.5 Audio Description (Prerecorded)** (AA) | Not Applicable (PDF); Not Evaluated (app) | App target where video evidence is shown in-app. |
| **1.4.3 Contrast (Minimum)** (AA) | Not Evaluated (app); Supports (PDF) | App target: all text/UI meets AA contrast, verified by axe + manual review. **PDF current:** body text is black on white; the appendix header row is white on `#222222`, both exceeding 4.5:1. |
| **1.4.4 Resize Text** (AA) | Not Evaluated (app); Partially Supports (PDF) | App target: 200% resize without loss. **PDF current:** text is real and zooms in a conforming reader without rasterization, but fixed-page layout limits reflow. |
| **1.4.5 Images of Text** (AA) | Not Evaluated (app); Supports (PDF) | **PDF current:** text is rendered as real text, not images of text. Evidence photos are content, not text. |
| **1.4.10 Reflow** (AA) | Not Evaluated (app); Partially Supports (PDF) | App target: reflow to a single column at 320 CSS px equivalent. **PDF current:** a paginated letter-size PDF does not reflow; mitigated by the machine-readable `bundle.json` companion that carries the same data in a structure-agnostic form. |
| **1.4.11 Non-text Contrast** (AA) | Not Evaluated (app); Supports (PDF) | **PDF current:** the appendix table grid uses a grey line that, with surrounding contrast and adjacent text labels, conveys structure; no meaning rests on a low-contrast graphic alone. |
| **1.4.12 Text Spacing** (AA) | Not Evaluated (app); Not Applicable (PDF) | App target. A fixed-layout PDF does not support author-overridable text spacing. |
| **1.4.13 Content on Hover or Focus** (AA) | Not Applicable (PDF); Not Evaluated (app) | No hover/focus content in the PDF. App target. |
| **2.4.5 Multiple Ways** (AA) | Not Evaluated (app) | App target. N/A to a single PDF document. |
| **2.4.6 Headings and Labels** (AA) | Not Evaluated (app); Partially Supports (PDF) | App target: descriptive headings/labels. **PDF current:** headings are descriptive in their visible text ("Evidence appendix", "Issue: …", "Timeline"), but are not yet tagged as headings programmatically. Tracked. |
| **2.4.7 Focus Visible** (AA) | Not Evaluated (app) | App target. N/A to the static PDF. |
| **2.4.11 Focus Not Obscured (Minimum)** (AA, 2.2) | Not Evaluated (app) | New in WCAG 2.2. App target. N/A to the PDF. |
| **2.5.7 Dragging Movements** (AA, 2.2) | Not Evaluated (app) | New in WCAG 2.2. App target: no drag-only operations. N/A to the PDF. |
| **2.5.8 Target Size (Minimum)** (AA, 2.2) | Not Evaluated (app) | New in WCAG 2.2. App target: minimum 24×24 CSS px targets, supporting limited manipulation. N/A to the PDF. |
| **3.1.2 Language of Parts** (AA) | Not Evaluated (app); Partially Supports (PDF) | App target: per-part language (relevant to Spanish parity). **PDF current:** document language is set; per-part language tagging (e.g. Spanish content within an English document) is not yet emitted. |
| **3.2.3 Consistent Navigation** (AA) | Not Evaluated (app) | App target. N/A to a single PDF. |
| **3.2.4 Consistent Identification** (AA) | Not Evaluated (app); Supports (PDF) | **PDF current:** status terms are used consistently across captions and the appendix. |
| **3.2.6 Consistent Help** (AA, 2.2) | Not Evaluated (app) | New in WCAG 2.2. App target: consistent help/contact placement. N/A to the PDF. |
| **3.3.3 Error Suggestion** (AA) | Not Evaluated (app) | App target. N/A to the PDF (no input). |
| **3.3.4 Error Prevention (Legal, Financial, Data)** (AA) | Not Evaluated (app) | App target: confirmation before sharing/exporting (the README's "show exactly what a packet will disclose"). N/A to the static PDF. |
| **3.3.7 Redundant Entry** (AA, 2.2) | Not Evaluated (app) | New in WCAG 2.2. App target. N/A to the PDF. |
| **3.3.8 Accessible Authentication (Minimum)** (AA, 2.2) | Not Evaluated (app) | New in WCAG 2.2. App target: no cognitive-function test required for authentication; note the product has no central account by design. N/A to the PDF. |
| **4.1.3 Status Messages** (AA) | Not Evaluated (app); Not Applicable (PDF) | App target: evidence-status changes announced to assistive tech via live regions. Static PDF has no status messages. |

---

## Revised Section 508 Report

### Chapter 5: Software

| Criteria | Conformance Level | Remarks and Explanations |
| --- | --- | --- |
| **501.1 Scope — Incorporation of WCAG 2.0 AA** | See WCAG tables | The application targets WCAG 2.2 AA. App rows remain **Not Evaluated** where automated evidence is insufficient without a human pass; PDF rows are assessed above. |
| **502 Interoperability with Assistive Technology** | Not Evaluated (app) | Semantic HTML and axe evidence exist, but interoperability has not been evaluated with real NVDA/VoiceOver pairings. |
| **503 Applications** | Not Evaluated (app) | The local web app exists; human review of preferences, platform settings, and alternative-content affordances remains open. |
| **504 Authoring Tool** | Not Applicable | habitable is not an authoring tool for third-party content in the 504 sense; it documents the user's own evidence. (The packet PDF it produces is the relevant content output and is assessed in the WCAG tables.) |

### Chapter 6: Support Documentation and Services

| Criteria | Conformance Level | Remarks and Explanations |
| --- | --- | --- |
| **602.2 Accessibility and Compatibility Features** | Partially Supports | Project documentation uses structured Markdown and describes current accessibility features and gaps. No human conformance review of the documentation has been completed. |
| **602.3 Electronic Support Documentation** | Partially Supports | Setup, mobile, and reviewer documentation exists as real-text Markdown/HTML. End-user comprehension and AT usability remain unvalidated. |
| **603.2 Information on Accessibility Features** | Supports | Accessibility commitments and status are documented openly (README "Accessibility and Section 508 conformance" and this committed ACR). |
| **603.3 Accommodation of Communication Needs** | Supports | Support is via the GitHub repository (issues, written channels) with an **alternate contact** in `SECURITY`/`CONTRIBUTING`; written, asynchronous channels accommodate a range of communication needs. |

---

## Legal Disclaimer (habitable)

This ACR is a project self-assessment, not an independent certification. The local web application
exists and has the automated evidence named above; rows marked "Not Evaluated" identify missing
human evidence, not missing code. The packet-PDF rows describe current behavior and its known gaps,
especially the absence of PDF/UA tagging. This document is not legal advice or a warranty.

---

## Roadmap

Automated axe, keyboard, and reflow checks are merge-blocking today. A recorded **manual NVDA and
VoiceOver** review remains a release gate. `packet.html` remains the designated accessible rendering;
tagged PDF/UA is planned only if a viable open-source path exists. This ACR is refreshed when evidence
changes.
