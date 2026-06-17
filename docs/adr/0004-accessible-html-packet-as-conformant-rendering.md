# 4. The accessible HTML packet is the conformant rendering; the PDF is a print convenience

- Status: Accepted
- Date: 2026-06-17

## Context

An evidence packet must be readable by everyone, including disabled tenants,
organizers, and the legal-aid workers and inspectors who receive it. Our
accessibility target is WCAG 2.2 AA. A packet is produced in three forms: a
machine-verifiable `bundle.json`, a paginated `packet.pdf`, and a self-contained
`packet.html`.

The roadmap's v1.0 gate calls for a "tagged (PDF/UA) packet." A spike confirmed
the blocker: the PDF is generated with reportlab, and **reportlab's open-source
API has no marked-content / structure-element support** (`canvas` exposes no
`beginMarkedContent`/`endMarkedContent`), so it cannot emit a real PDF/UA
structure tree (tagged headings, table structure, image alt text). What it *can*
do — and now does — is declare the document language (`/Lang`), set
`DisplayDocTitle`, carry a navigable outline/bookmarks, and keep text selectable.
That is useful but is **not** a PDF/UA conformance claim, and a veraPDF check
would fail.

Meanwhile `htmlpacket.py` already produces `packet.html`: semantic landmarks, a
single `h1`, a captioned appendix table with header scopes, meaningful image
`alt`, the document language, and high-contrast text. It **passes the same
axe-core gate** as the app (`tests/test_htmlpacket.py`) with zero violations and
is fully operable by assistive technology.

The options were: (a) adopt a different, tagging-capable PDF toolchain to chase
PDF/UA; or (b) treat the HTML packet as the conformant accessible rendering and
keep the PDF as a print/presentation convenience.

## Decision

Adopt **`packet.html` as the conformant, accessible human-readable rendering** of
an evidence packet. The PDF remains a print/presentation convenience with its
existing accessibility hygiene (language, title display, outline, selectable
text), and we make **no PDF/UA conformance claim** for it. The machine-verifiable
`bundle.json` remains the canonical record either way.

This satisfies the accessible-packet intent of the v1.0 gate via equivalent
facilitation. We will revisit producing a fully tagged PDF/UA file only if a
suitable open-source tagging toolchain becomes available; until then, chasing it
in reportlab is not a good use of effort.

## Consequences

- The ACR documents the HTML packet as the conformant rendering and the PDF as a
  best-effort convenience; the "tracked future work" PDF row resolves to this
  decision rather than staying open indefinitely.
- Wherever the packet is offered, the HTML rendering is presented as the
  accessible option; recipients who need an accessible record use `packet.html`.
- The recorded human screen-reader pass (a separate gate item) covers the app and
  `packet.html`, not a PDF/UA structure tree.
- If we later adopt a tagging-capable toolchain, this ADR is superseded and the
  PDF can carry a real PDF/UA claim.

## Gate mapping

This ADR **is** the recorded answer to the productionization plan's Phase-1 task 1.3
("record the PDF/UA decision as an ADR") and to the v1.0 checklist's "tagged (PDF/UA)
packet" line: the accessible-packet requirement is met by `packet.html` as equivalent
facilitation, not by a tagged PDF. The implementing change (task 1.4) wires this in —
the PDF disclaimer points to `packet.html` (`src/habitable/pdf.py`), the axe gate
treats `packet.html` as the conformant artifact (`.github/workflows/a11y.yml`,
`tests/test_htmlpacket.py`), and the ACR and manual-testing protocol target it.
