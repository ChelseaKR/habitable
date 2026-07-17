# Habitable product improvement, expansion, and SEO research

**Research date:** 2026-07-09

**Current upstream baseline:** [`fa8928170910288c44ad2740e8c40d7426364322`](https://github.com/ChelseaKR/habitable/tree/fa8928170910288c44ad2740e8c40d7426364322)

**Local checkout inspected:** `c40a695153d259468153cdd44f9b7797f506582e` (27+ commits behind while this research was running)

**Scope:** product strategy, UX, trust and release readiness, expansion options, market/competitor research, keyword and content strategy, on-page and technical SEO, and a sequenced execution plan.

> **Historical baseline.** This report records the first-pass state and decisions as of its
> research date. Later PRs corrected several findings and changed the open-PR/mainline state; a
> dated sweep addendum records those approvals, deferrals, remediations, and residual risks rather
> than silently rewriting this snapshot.

## Executive verdict

Habitable has a genuinely differentiated core: an offline, encrypted, union-owned habitability case record whose exported evidence can be checked independently. The combination of tenant power alignment, deferred trusted timestamping, peer collaboration, selective disclosure, an open verifier, EN/ES support, and accessibility work is unusual. Competitors increasingly offer one or two of those pieces, but none of the products reviewed clearly offers the whole combination.

The project does **not** currently have an ideation shortage. It has a focus, trust-contract, distribution, and validation bottleneck:

- The latest `main` has accumulated a broad protocol, CLI, PWA, evidence kernel, campaign engine, audio/video support, threshold recovery, padding transport, an evidence-strength assessment, and an aggregate commons before a real tenant-union or legal-aid pilot has been completed.
- The public landing page is a single English page whose main conversion is “View on GitHub.” It exposes almost none of the repository's substantial educational, legal-scaffolding, adoption, privacy, or audit material to nontechnical visitors or search engines.
- The public “verifiable” sample currently fails the repository's own verifier because it lacks `bundle.sig.json`. It is also a legacy packet-v1 artifact without the current disclosures and with old HLC/node identifiers. This is the highest-priority public trust problem.
- The verifier currently separates token integrity from certificate-chain trust internally, but an untrusted/self-signed timestamp can still contribute to an overall “intact” verdict. The product needs an explicit distinction between **structurally intact**, **authority trusted**, and **evidence ready**.
- Installation still assumes Git, `uv`, Python 3.14, and a terminal. The intended “tenant with only a phone” cannot safely reach the product today. The documented LAN phone path exposes an unlocked local API; the open session-token PR reduces unauthorized access but does not make plaintext LAN HTTP a safe mobile delivery architecture.
- Search demand is problem-first: “landlord won't make repairs,” “how do I document this,” “how do I prove notice,” and condition-specific queries. “Court-ready habitability evidence” is solution language, not an established search category.
- The repository had 23 open PRs during research: 21 owner-authored PRs plus two dependency updates. All 21 owner PRs returned as mergeable, non-draft, and with no requested reviewer. Several change evidence/security semantics and overlap one another.

The recommended strategy is therefore:

> **Own the category of tenant-owned habitability case evidence. Build the case, not just the photo. Pause broad expansion until the public proof, trust semantics, install path, and one real pilot are credible.**

## The seven decisions that matter most

1. **Fix the proof before promoting it.** Regenerate and sign the public sample from current `main`; add a CI gate that runs the public artifact through `habitable verify` and checks its packet version, disclosure fields, and identifier privacy.
2. **Split “intact” into honest verdicts.** A packet can be structurally intact while its timestamp authority is untrusted. Make that impossible to misunderstand in CLI, JSON, HTML, PDF, and the future browser verifier.
3. **Make pilot readiness the roadmap's organizing principle.** Security fixes, mobile distribution, zero-install recipient verification, recurrence/timeline semantics, backup/recovery, and real human review outrank sensors, generic evidence-platform expansion, or more cryptographic surface.
4. **Position around a complete case, not commodity proof primitives.** SnapProof and ProofMode already make hashes, timestamps, and verification legible. Habitable's moat is condition + notice + response/silence + progression + collective custody + selective handoff.
5. **Turn the site into the owned explanation layer.** Publish the annotated packet, evidence checklist, repair timeline template, technical trust explainers, audience pages, and qualified California guides as static HTML rather than burying them in GitHub Markdown.
6. **Use a fixed public descriptor.** “Habitable” conflicts with a habit app, housing terminology, and astrobiology. Use **Habitable Evidence** or **Habitable — tenant-owned evidence** consistently while keeping the package name.
7. **Treat Spanish as a first-class acquisition surface.** Build stable `/es/` URLs with human-reviewed content and reciprocal `hreflang`, not only an in-app language toggle.

## Method and limits

This assessment combined:

- source, tests, docs, release, roadmap, public sample, and open-PR inspection;
- rendered desktop and 375 px mobile inspection of the landing page, sample packet, and local app;
- live HTTP checks against `https://chelseakr.github.io/habitable/`;
- current SERP sampling across English and Spanish problem, product, legal-preparation, and technical-evidence queries;
- primary-source competitor pages, app-store listings, documentation, pricing, audits, and content hubs;
- current government/court guidance and standards sources.

Keyword demand and difficulty in this report are **qualitative**. No Google Search Console property, Ahrefs, Semrush, or equivalent rank/volume dataset was available. Connect one of those for exact impressions, positions, volume, difficulty, and backlink counts. Search-result sampling is a directional opportunity analysis, not a claim of exhaustive ranking data.

This is product and marketing research, not legal advice. Jurisdiction-specific pages should not publish without qualified local review and a dated maintenance owner.

## Current-state assessment

### What is already strong

- A coherent evidence spine: original-file fixity, RFC 3161 timestamps, append-only custody, privacy-minimized exports, and a standalone verifier.
- A defensible threat model: no project-run account or plaintext case database, no product analytics, explicit relay-metadata limits, and user-controlled disclosure.
- Offline-first behavior that matters in the real context: capture can seal now and timestamp after connectivity returns.
- A collective model rather than a landlord-controlled portal: E2E/P2P sync, campaign rollups, co-custody/recovery work, and no central administrator over case contents.
- Strong engineering artifacts: threat model, crypto spec, schema, golden packets, property/fuzz tests, release provenance, accessibility documentation, and a reusable verifier/evidence kernel.
- An unusually honest product voice about admissibility, authorship, depiction, coercion, and metadata limits.
- EN/ES localization, axe-gated HTML, keyboard/reflow tests, and an accessible HTML packet path.

### The product's stated and actual users are different

The stated protected user is a tenant documenting unsafe housing on the only phone they have. The user served today is a technical organizer, developer, auditor, or evaluator:

- setup requires cloning the repository, installing `uv`, provisioning Python 3.14, initializing a vault, and launching a local server;
- the landing page's primary action is GitHub;
- the local app's first screen prioritizes a device fingerprint, timestamp counts, custody integrity, and a long sequence of forms;
- category and timeline “kind” are free text rather than guided, jurisdiction-aware choices;
- the developer TSA option is exposed in the ordinary capture UI;
- the app is a long operational dashboard, not a one-task-at-a-time capture flow;
- many newly merged capabilities remain CLI-first and are not legible in the tenant UI.

The rendered layout itself is clear, responsive, and accessible. The main usability gap is workflow and distribution, not visual polish.

### P0 trust and release blockers

| Finding | Why it matters | Recommended correction |
|---|---|---|
| Public sample fails verification | `uv run habitable verify site/sample-packet` returns `signature=FAILED` and `packet NOT intact`, while the site calls it a live verifiable packet | Regenerate from current main, include `bundle.sig.json`, and CI-verify the exact published directory |
| Public sample is stale packet v1 | It lacks current disclosures and still exposes legacy HLC/node-style identifiers, while current main emits packet v2 | Publish a current signed fixture with realistic synthetic media; fail CI on an old packet version or forbidden identifier pattern |
| Timestamp trust is not part of overall readiness | A token can pass imprint/signature validation without a trusted root; the overall verdict can still say intact | Expose `integrity_valid`, `authority_trusted`, and `evidence_ready`; require at least one configured trusted root for the last state |
| Dev timestamp can look valid | A development/self-signed authority is useful for tests but must never read as production evidence | Hide it outside explicit dev builds and render a prominent “test only — authority untrusted” state everywhere |
| Wheel omits app assets | Current packaging includes `src/habitable` but not the sibling `app/`; an installed `habitable app` can fail | Package assets under the Python package, load with `importlib.resources`, and add an installed-wheel smoke test before PyPI publishing |
| Phone path exposes unlocked API on LAN | The docs instruct `--host 0.0.0.0`; the current server is unauthenticated, and a bearer token over plaintext LAN HTTP still does not solve interception or PWA secure-context limits | Do not market this as the phone path; prioritize a signed on-device package. Treat session auth as defense-in-depth for loopback only |
| Passphrase-derived node ID remains on main | A fast SHA-256 value derived from a guessable case ID and passphrase creates an avoidable offline passphrase oracle | Independently review and land PR #49 with a migration and regression test |
| Packet authenticity PR conflicts with packet v2 history | PR #54 treats all v2+ packets as custody-signature-bound, but main already emits v2 packets without those signatures | Introduce packet v3 or an explicit capability field; preserve v1/v2 golden compatibility |
| Timeline claims exceed implementation | README says timeline entries are hashed/timestamped, while current entries primarily carry kind/text/HLC and packet rendering omits meaningful occurrence dates | Define occurred-at/source/recorded-at semantics; bind timeline entries to custody or correct the claim; render dates and links to captures/notices |
| Sync trust is under-specified | A self-declared sender can be signature-valid without being an expected case peer; inner case binding is weak | Add allowlisted QR pairing, expected peer identity, inner `case_id` binding, replay/receipt semantics, and all-token/custody transfer |
| Export/persistence can leave stale or partial state | Direct writes and reused output directories can leave corruption or previously exported originals behind a narrower export | Build into a fresh temporary directory, fsync as appropriate, atomically replace, and add crash/re-export privacy tests |
| Human-readable disclosure can diverge from policy | HTML/PDF copy can say GPS was stripped even when a non-default policy retained it | Render from the signed machine-readable disclosure, not a hard-coded sentence |

### Repository and roadmap control is now a product risk

The [open PR list](https://github.com/ChelseaKR/habitable/pulls) showed 23 open PRs. The connected GitHub view returned 21 owner-authored PRs; all 21 were mergeable, all were non-draft, and none had a requested reviewer. They include security and protocol changes, pilot workflow changes, and speculative expansions. This creates three problems:

1. overlapping branches can each be locally correct and jointly incompatible;
2. docs can say “shipped” when the code is only in an open PR, or refer to files that are not on main;
3. security-critical changes can look ready because they are non-draft even though the roadmap itself requires outside review.

One concrete example is packet versioning: current main uses packet v2 for opaque exported identifiers, while PR #54 also assigns new custody-binding semantics to v2. Another is the evidence-kernel and ADR documentation linking to `docs/ideation/03-expansions.md`, which was not present on the inspected main tree.

Recommended PR lanes:

| Lane | Representative PRs | Decision rule |
|---|---|---|
| Security/trust gate | #49 node ID, #50 app auth, #52 sync deltas, #53 CRDT provenance, #54 packet authenticity | Mark review-required; merge only with compatibility/security sign-off and a migration story |
| Pilot slice | #43 plain language, #44 recurrence, #29 storage/data cost, #33 incomplete export, #40 minimal disclosure, #38 inspector view, #15 packaging | Choose the smallest coherent pilot bundle and test the installed artifact end to end |
| Post-pilot expansion | #58 packet diff, #59 external anchoring, #61 sensor CSV, #62 legal-aid receipt, #36 structured logging, #46 sneakernet | Keep as drafts unless a pilot or adopter validates the need |
| Overlapping umbrella | #16 evidence bundle + sharing + letters | Split or close in favor of focused PRs; do not merge a multi-domain bundle that conflicts with narrower work |

Add three milestones: `v0.2.1 trust repair`, `v0.3 pilot-ready`, and `post-pilot experiments`. A feature registry or claim ledger should generate/version the public status, README capability table, and sample artifact checks so documentation cannot drift silently.

## Market and competitive landscape

### Need and timing

The addressable problem is large even though Habitable should begin narrowly. The Legal Services Corporation says more than 45 million U.S. households rent and that low-income Americans receive inadequate or no legal help for 92% of their civil legal problems. Its civil-court initiative has collected more than 30 million records across 30 states. These figures support the importance of self-help evidence organization, but not a conclusion that every renter is a direct product user. [LSC Civil Court Data Initiative](https://civilcourtdata.lsc.gov/), [LSC housing-stability brief](https://www.lsc.gov/press-release/landlords-and-legal-aid-can-collaborate-housing-stability-lsc-brief-shows).

The market moved quickly in spring 2026. Several new products now claim timestamped, hashed, court-organized, or tamper-evident rental records. Cryptographic photo proof alone is no longer a durable category.

### Competitor comparison

| Product | What it does well | Where Habitable can remain distinct | Strategic response |
|---|---|---|---|
| [JustFix](https://www.justfix.org/en/) | Trusted housing-justice nonprofit; lawyer-vetted repair letters; certified mail; building research; EN/ES; strong jurisdictional content and partners | No complete authenticated-media case, offline encrypted union vault, P2P case collaboration, or independent packet verifier is shown | Treat as both search competitor and potential notice/delivery partner |
| [Rentfile](https://play.google.com/store/apps/details?id=com.skyhi.rentfile) | Room/severity/status issues, communications, appointments, impact, timeline, reports, letters, encrypted backup | No public trusted timestamp, verifier, custody chain, multi-user union sync, or OSS/audit claim | Borrow case completeness and impact/appointment workflow |
| [Tenant Trace](https://tenanttrace.app/) | Local-first rental reports, timestamps/GPS, public anchoring, QR verification, co-sign/decline, before/after comparison, one-time pricing | iOS/English and move-in/deposit focus; depends on public registry/App Attest; no union campaign or ongoing notice/repair case | Borrow co-sign state and comparison UX; do not chase deposit SEO yet |
| [SnapProof](https://getsnapproof.com/) | Polished SHA-256 + DigiCert RFC 3161 story, cases/timelines, certified reports, QR/public verification, broad consumer funnel | Requires connectivity at capture; general/single-user; no union ownership, complete habitability workflow, append-only case custody, or no-tracking claim comparable to Habitable | Biggest messaging threat; stop leading with proof primitives alone |
| [ProofMode](https://proofmode.org/) | Open source, C2PA, capture/proof bundles, web verification, current standards credibility | Generic media provenance, not a housing condition/notice/response case | Integrate/import rather than duplicate its media-provenance ecosystem |
| [Tella](https://tella-app.org/) | Best-in-class operational security, offline mobile UX, camouflage/lock/delete, 25 languages, audits, organization deployments | No comparable public RFC 3161 court-packet/verifier or housing case model | Use as the safety, documentation, localization, and field-deployment benchmark |
| [RentCheck](https://www.getrentcheck.com/product-overview) | Excellent guided inspections, reminders, reports, signatures, comparisons, dashboards, integrations | Landlord/cloud controlled; not an independent tenant record under retaliation risk | Learn from its guided capture, but position explicitly against power asymmetry |
| [Truepic Vision](https://www.truepic.com/vision/inspection-platform) | Enterprise controlled capture, spoof/rebroadcast checks, operational workflow and APIs | Expensive, enterprise/cloud controlled, built for the party judging the submitter | It defines the high-end authenticity ceiling, not the target market |
| Habitable | Complete union-owned case, offline seal/deferred timestamp, open verifier/schema, P2P collaboration, selective disclosure, EN/ES and accessibility | Installation, recipient UX, trusted-root semantics, proof artifact, pilot evidence, and content/distribution | Own the collective, retaliation-safe habitability **case** |

### Positioning whitespace

The open quadrant is:

> **Collective + tenant-controlled + case-complete + independently verifiable.**

The strongest story is not “our hashes are better.” It is:

- **Build the case, not just the photo:** condition → notice → delivery → silence/response → inspection/repair → recurrence/impact → packet.
- **Collective power without a central honeypot:** tenant and organizer collaborate while the union keeps control.
- **Offline truth:** seal immediately and add a trusted time bound when connectivity returns.
- **Retaliation-aware privacy:** no account, product analytics, or central plaintext; default packet shared-media metadata stripping; signed disclosure of metadata/original choices.
- **Verification that survives the project:** open bundle, standard cryptography, CLI/browser verifier, backward-compatible fixtures.

### Recommended public positioning

**Public descriptor:** `Habitable Evidence`

**Category:** `tenant-owned habitability evidence`

**Secondary phrases:** `offline tenant evidence app`, `verifiable housing condition record`, `tenant union case documentation`

**Recommended hero:**

> Build a verifiable habitability case—not just a folder of photos.

**Recommended support copy:**

> Document unsafe conditions, repair notices, landlord responses, and recurring harm in an encrypted record your tenant union owns—even when you are offline.

**Proof bullets:**

- Seal the record now; add an independent timestamp when connected.
- No account, analytics, or central case database.
- Share only the evidence you choose.
- Give a recipient a packet they can verify without trusting Habitable.

Use “verifiable evidence packet for court or inspection” or “court-organized evidence” until qualified reviewers approve the stronger unqualified “court-ready” claim. Never use “tamper-proof,” “guaranteed admissible,” or language implying a hash proves what a photo depicts.

### Three strategic models

| Model | Upside | Risk | Recommendation |
|---|---|---|---|
| Vertical tenant-union product | Strongest differentiation and clearest protected user; validates the whole protocol in context | Requires distribution, partner trust, field UX, and support | **Primary for the next 12 months** |
| Evidence kernel embedded by partners | Larger long-term leverage and lower need to operate case services | Can become a maintainer-heavy library without a real adopter | Keep ready, but split/publish only when a second adopter commits |
| Generic “evidence for anything” platform | Large apparent market and many adjacent queries | Loses housing-power alignment; competes with SnapProof, ProofMode, Truepic, and dozens of court-record apps | Do not pursue now |

The “opposite” option is credible: Habitable could remain an evidence kernel/reference implementation and partner into JustFix, Tella, or legal-aid systems rather than becoming a consumer app. Do not choose that by drift. Test the vertical product with one real partner first; then decide whether the reference app or the kernel is pulling harder.

## Product opportunity tree

```text
Outcome: one tenant-union/legal-aid pilot safely produces a packet a recipient can use
|
+-- Tenant can create a complete, understandable record
|   +-- Guided condition capture and photo checklist
|   +-- Recurrence/progression on one issue
|   +-- Notice, communication, document, receipt, and inspection ingestion
|   +-- Clear offline/timestamp/trust states
|
+-- Organizer can keep multiple cases safe and ready
|   +-- QR pairing, trusted peers, sync receipts
|   +-- Campaign view with next actions, not just counts
|   +-- Co-custody, recovery drill, member offboarding
|   +-- Storage/data-cost and incomplete-evidence warnings
|
+-- Recipient can understand and verify quickly
|   +-- Zero-install offline browser verifier
|   +-- One-page “proves / does not prove” summary
|   +-- Chronological narrative, exhibit numbering, packet diff
|   +-- Selective disclosure and redaction manifest
|
+-- Partner can trust adoption and maintenance
    +-- Signed installable app and current verifying sample
    +-- Security, legal, accessibility, and Spanish review
    +-- Stable schema/importer and documented support policy
    +-- Real pilot outcome and incident/feedback process
```

### Ranked product opportunities

| Rank | Opportunity | Impact | Confidence | Effort | Why now |
|---:|---|---:|---:|---:|---|
| 1 | Close trust semantics and review security-critical PRs | 5/5 | 5/5 | L | Promotion is unsafe while “intact” can be misunderstood and core security fixes remain unreviewed |
| 2 | Run real tenant, organizer, recipient, security, legal, Spanish, and AT reviews | 5/5 | 5/5 | M/external | The existing persona work is explicitly synthetic; feature velocity is outrunning evidence |
| 3 | Repair the public sample and claim surface | 5/5 | 5/5 | S | The current proof artifact contradicts the product's central promise |
| 4 | Ship a genuine on-device install path with packaged assets, unlock/autolock, backup, and safe update | 5/5 | 5/5 | XL | The protected user cannot currently install the product safely |
| 5 | Zero-install offline browser verifier | 5/5 | 5/5 | L | Recipient adoption fails if a clerk/lawyer must install a CLI; competitors already normalize web verification |
| 6 | Timeline 2.0: occurred-at, source, notice/response/silence, recurrence, capture threading, custody semantics | 5/5 | 4/5 | L | The legal narrative is the actual product; current claims and rendering are incomplete |
| 7 | Safe sync: allowlisted pairing, case binding, deltas/resume, all proofs, receipts | 5/5 | 5/5 | XL | Collective use is the moat and the highest-risk protocol boundary |
| 8 | Complete tenant capture UX: guided mode, gallery/detail, issue close/edit, alt text, documents, review-before-share | 5/5 | 4/5 | L | Current app exposes an engineering model rather than the stressed user's task |
| 9 | Organizer GUI over the shipped campaign engine | 4/5 | 4/5 | L | The engine exists, but the value is finding the next incomplete case in seconds |
| 10 | Notice/delivery bridge with JustFix or a legally reviewed generic receipt workflow | 4/5 | 4/5 | M/L | Proving the landlord knew is a high-intent user job and a major content opportunity |
| 11 | C2PA/ProofMode credential import | 3/5 | 3/5 | M | Interoperability is more credible than another proprietary camera silo |
| 12 | Sensor evidence and aggregate commons expansion | 2/5 | 2/5 | L | Interesting, but not a current adoption bottleneck; validate abuse/privacy and pilot demand first |

### What to remove or hide

Improvement does not always mean adding surface area.

- Hide device fingerprints, raw hashes, TSA configuration, and custody internals behind an “evidence details” view.
- Remove the dev TSA checkbox from ordinary builds.
- Replace the long page of independent forms with a guided sequence: **Document condition → Add context → Record notice/response → Review evidence → Share/export**.
- Replace free-text “Category” and “Kind” with reviewed choices plus “Other,” while preserving a neutral factual record.
- Do not put newly merged campaign, commons, padding, or kernel concepts into tenant navigation unless a user task requires them.
- Keep legal and advanced cryptographic language out of the first 100 words of user-facing pages; put it in the proof layer.

### Cheapest experiments before more build work

1. **Recipient verifier comprehension:** give five clerks/legal staff a signed synthetic packet and a clickable verifier prototype. Success: verify and explain “what it proves / does not” in under two minutes without help.
2. **Guided capture test:** run five EN/ES participants through a synthetic mold/no-heat scenario on old phones. Success: first complete issue in under three minutes, no one mistakes “awaiting timestamp” for data loss.
3. **Organizer triage prototype:** show a static 10-unit campaign dashboard. Success: identify every case missing notice, timestamp, or backup within 60 seconds.
4. **Case-completeness paper test:** compare current capture against a checklist covering condition, notice, delivery, response, recurrence, impact, and third-party reports. Measure missing evidence, not feature preference.
5. **JustFix/manual bridge:** with one legal partner, manually attach a certified-mail receipt and repair notice to a Habitable timeline before building an integration.
6. **Installed artifact drill:** install a signed package on five supported low-end devices from scratch. Success: create, capture, close, reopen offline, export, backup, restore, and verify without a terminal.
7. **Strategy test:** ask two prospective organizations whether they want the full Habitable workflow or the kernel/importer inside an existing system. A committed pilot/adopter is stronger evidence than survey enthusiasm.

## SEO audit

### Executive summary

The SEO foundation **needs work**, primarily because almost no owned content surface exists. The homepage is crawlable, HTTPS, semantic, responsive, and text-first, but it is one English page that routes users to GitHub. The biggest opportunities are an annotated evidence-packet example, practical documentation/checklist/template pages, and real EN/ES audience/jurisdiction pages. The first three priorities are: fix the public proof artifact, establish indexation/canonical/sitemap basics, and publish the problem-first content cluster.

The strongest technical advantage is simplicity: static HTML, no client-rendering dependency, and a small document. The strongest content advantage is the repository's deep evidence/privacy/adoption material. The weakness is that search engines and nontechnical users cannot discover that depth on the owned site.

### Live technical checklist

| Check | Status | Details |
|---|---|---|
| HTTPS | Pass | GitHub Pages returns HTTP/2 200 over HTTPS |
| Crawlable server-rendered HTML | Pass | Core copy and links are present in the initial document |
| Semantic hierarchy | Pass | One H1, logical H2 sections, landmarks, skip link |
| Mobile layout | Pass | 375 px inspection was readable and reflowed correctly |
| Image alt text | Pass | Screenshots have detailed contextual alternatives |
| Canonical URL | Fail | No self-referencing canonical |
| XML sitemap | Fail | `/habitable/sitemap.xml` returned 404 |
| `robots.txt` | Warning | `/habitable/robots.txt` returned 404; absence does not block indexing, but it cannot point crawlers to the sitemap |
| Search Console/indexation verification | Warning | Sampled `site:` and exact-title queries did not surface the landing page; the page was recently updated, so verify rather than infer exclusion |
| Title | Warning | 63 characters and solution/category heavy |
| Meta description | Warning | 244 characters; likely truncated and packed with technical concepts |
| Open Graph/Twitter metadata | Fail | None found |
| Structured data | Warning | No `SoftwareApplication`, `SoftwareSourceCode`, `Article`, or breadcrumb markup |
| EN/ES indexable URLs | Fail | Landing page is English only; app localization is not a crawlable Spanish acquisition page |
| `hreflang` | Fail | No alternate language URLs or reciprocal annotations |
| Internal content architecture | Fail | One landing page plus raw sample artifacts; most links leave for GitHub |
| Sample artifact validity | Critical fail | Published sample lacks signature, is legacy v1, and fails verification |
| Image sizing/loading | Warning | About 884 KB of screenshots; no intrinsic dimensions on the large images, no lazy loading, no modern variants |
| Raw sample index policy | Warning | No deliberate canonical/noindex policy for explanatory page vs HTML/PDF/bundle artifacts |

Google says a sitemap should list canonical, fully qualified URLs and can be submitted in Search Console or referenced from `robots.txt`: [Build and submit a sitemap](https://developers.google.com/search/docs/crawling-indexing/sitemaps/build-sitemap). Google also recommends different URLs for language versions and reciprocal `hreflang`: [multilingual sites](https://developers.google.com/search/docs/advanced/crawling/managing-multi-regional-sites).

### On-page issues

| Page/surface | Issue | Severity | Recommended fix |
|---|---|---:|---|
| Homepage | H1 begins with low-demand solution language | High | Lead with the user job: build/document a habitability case |
| Homepage | Primary CTA is GitHub | High | Primary CTA: join pilot; secondary: explore verified sample; tertiary: evidence method/source |
| Homepage | “Court-ready” is stronger than current alpha/legal validation | High | Use verifiable/court-organized until reviewed; keep the honest alpha warning |
| Homepage | No audience routing | High | Add paths for unions, legal aid/attorneys/inspectors, auditors/contributors, and a safe tenant-help notice |
| Homepage | Technical proof dominates before the workflow | Medium | Explain condition, notice, response, progression, and packet before RFC/SHA details |
| Homepage | No reviewer, pilot, or external-validation proof | High | Show status truthfully: audits complete/open, named reviewers only when real, pilot recruitment |
| Sample | Fails verification and uses stale format | Critical | Replace before any SEO/outreach push |
| Sample | 64×64 synthetic color blocks are not persuasive evidence | High | Use realistic, clearly synthetic, privacy-safe staged condition media and an annotated explainer |
| Sample | Recipient must run CLI | High | Add the zero-install local browser verifier and verification transcript |
| Site | No Spanish acquisition content | High | Human-reviewed `/es/` mirror for core pages |
| Site | Deep docs only on GitHub | High | Publish selected docs as static HTML with strong internal links |
| Site | No contact/pilot route for non-GitHub users | High | Add a low-data email/contact path; explicitly say never send case evidence or PII |

### Keyword opportunity table

Demand and difficulty are qualitative signals from current result density, authority, commercial presence, freshness, and repeated query patterns—not measured volume.

| Keyword / cluster | Demand signal | Difficulty | Opportunity | Intent | Recommended page |
|---|---|---:|---:|---|---|
| how to document apartment repair problems | High | Moderate-hard | High | Informational/action | Pillar guide + checklist |
| what evidence do I need for a habitability claim | High | Hard broadly; moderate for workflow | High | Legal preparation | CA-scoped evidence guide |
| how to prove landlord knew about repairs | Med-high | Moderate | High | Informational/action | Notice + receipt + timeline guide |
| habitability evidence checklist | Medium | Easy-moderate | High | Download/action | HTML + accessible EN/ES printable |
| tenant repair log template / apartment repair timeline | Med-high | Moderate | High | Template/transactional | Local-only builder + CSV/PDF |
| tenant evidence packet / habitability evidence packet example | Low-med explicit, very high fit | Easy | High | Example/commercial | Annotated signed sample hub |
| how to organize landlord evidence for court | Med-high | Moderate-hard | High | Legal preparation | Court-organized packet guide |
| how to photograph housing disrepair | Med-high | Moderate | High | Informational | Wide/context/detail/repeat field guide |
| can apartment photos be used as evidence | High | Moderate-hard | High | Question | Concise answer + limits/foundation |
| tenant evidence app / housing disrepair evidence app | Low-med, emerging | Moderate | High | Commercial | Product/category page |
| tenant union evidence tool / case documentation | Low volume, high value | Easy | High | Organizational | `/for/tenant-unions/` |
| legal aid habitability intake / organize repair evidence | Low volume, high partnership value | Easy | High | Professional | `/for/legal-aid/` |
| privacy-first / offline tenant records | Low-med | Easy-moderate | High | Commercial | Plain-language privacy page |
| timestamped apartment photos / landlord dispute | Medium, rising | Moderate-hard | Medium-high | Commercial/informational | Product page + honest comparison |
| mold apartment California evidence / prove mold | High | Hard | Medium-high | Urgent informational | Reviewed condition guide |
| water leak / damp apartment evidence | Med-high | Moderate-hard | Medium-high | Urgent informational | Repeat-photo + moisture/timeline guide |
| no heat / no hot water landlord evidence | Seasonal high | Hard | Medium-high | Urgent informational | Measurement/notice checklist |
| landlord harassment log / document retaliation | High | Hard | Medium | Urgent/legal preparation | Neutral incident-log template + referrals |
| landlord won't make repairs California | Very high | Very hard | Medium | Urgent informational | Evidence-focused adjunct, not generic legal summary |
| EXIF timestamp evidence / is photo metadata reliable | Medium | Moderate | Medium | Technical informational | EXIF vs hash vs RFC 3161 explainer |
| how to authenticate digital photos / prove photo not edited | Med-high | Hard | Medium | Technical/commercial | Local tamper demo + limits |
| chain of custody for digital photos | Medium-low | Moderate | Medium | Professional/technical | Plain-language evidence-method guide |
| cómo documentar moho o reparaciones en un apartamento | Med-high fit; sparse practical results | Moderate | High | Spanish informational/action | Human-reviewed `/es/` guide + checklist |
| pruebas de condiciones inhabitables California | Medium | Moderate-hard | High | Spanish legal preparation | Spanish CA evidence page with official sources |

Broad terms such as “warranty of habitability California” are dominated by government, courts, established legal publishers, and law firms. Habitable should not try to win with generic legal summaries. It should own the operational layer those sources tell tenants to perform: document conditions, preserve notice, build a timeline, and organize the record.

### Recommended information architecture

```text
/
|-- examples/habitability-evidence-packet/
|-- templates/
|   |-- habitability-evidence-checklist/
|   `-- tenant-repair-timeline/
|-- guides/
|   |-- document-apartment-repairs/
|   |-- prove-landlord-notice/
|   |-- photograph-housing-conditions/
|   |-- organize-evidence-for-court/
|   |-- california-habitability-evidence/
|   |-- document-mold/
|   |-- document-leaks-and-damp/
|   `-- document-no-heat-or-hot-water/
|-- evidence/
|   |-- what-a-hash-proves/
|   |-- trusted-timestamps/
|   |-- chain-of-custody/
|   `-- exif-vs-trusted-timestamp/
|-- verify/
|-- for/
|   |-- tenant-unions/
|   |-- legal-aid/
|   `-- attorneys-and-inspectors/
|-- trust/
|   |-- privacy-and-threat-model/
|   |-- evidence-method/
|   |-- audits-and-open-gaps/
|   `-- what-habitable-does-not-prove/
`-- es/  (human-reviewed mirrors of the core paths)
```

Prefer evergreen guides/tools over a chronological blog. Keep the site static and server-rendered. A small template build is justified once duplication becomes costly; do not turn the marketing/docs site into a client-side application.

### Highest-value content gaps

| Asset | Why it matters | Priority | Effort |
|---|---|---:|---:|
| Annotated signed packet example | Best proof, conversion path, link target, and recipient education asset | High | Moderate |
| EN/ES habitability evidence checklist | Directly serves a repeated search/user job and workshop use | High | Moderate |
| Local-only repair timeline builder/template | Captures template intent and demonstrates local-first value | High | Moderate/substantial |
| Housing-condition photo field guide | Practical, visual, image-search friendly, useful before any legal claim | High | Moderate |
| California habitability evidence pillar | Connects official rights sources to the documentation workflow | High | Substantial; qualified review required |
| “Prove landlord notice” guide | High-intent bridge to JustFix/certified-mail workflows | High | Moderate; legal review |
| Zero-install verifier page | Table-stakes recipient UX and a linkable technical asset | High | Substantial |
| Tenant-union and legal-aid audience pages | Clarify the collective moat and pilot conversion | High | Quick/moderate |
| EXIF vs hash vs trusted timestamp interactive demo | Makes the proof legible and earns technical/security links | Medium-high | Substantial |
| Evidence method/schema/test-vector HTML hub | Converts repository depth into developer/legal-tech authority | Medium | Moderate |

### Five priority content briefs

#### 1. Annotated habitability evidence packet

- **Target:** `habitability evidence packet example`, `tenant evidence packet`
- **Promise:** show an end-to-end synthetic case and explain each record's value and limitation.
- **Sections:** case summary; condition progression; repair notice and proof of delivery; landlord response/silence; third-party inspection; media; what integrity verification proves; what it does not; disclosure manifest; verify locally.
- **CTA:** try the offline verifier / join a pilot.
- **Guardrail:** the exact downloadable packet must pass current verification in CI.

#### 2. Habitability evidence checklist (EN/ES)

- **Target:** `habitability evidence checklist`, `housing disrepair evidence checklist`.
- **Format:** answer-first HTML, table of record / why it matters / limitation, accessible print/PDF.
- **Inputs:** condition photos/video, occurrence dates, written notice, delivery receipt, responses, recurrence, expenses, inspection reports, medical documentation where appropriate, tenancy proof.
- **Guardrail:** distinguish general recordkeeping from jurisdiction-specific legal requirements.

#### 3. Tenant repair timeline template/builder

- **Target:** `tenant repair log template`, `apartment repair timeline`.
- **Mechanism:** runs locally in the browser, no upload, exports CSV/print view.
- **Fields:** occurred date, recorded date, event type, neutral factual note, related issue/media, notice/delivery, response, source.
- **CTA:** move the log into a verifiable Habitable case when the product is pilot-ready.

#### 4. How to photograph housing conditions

- **Target:** `how to photograph housing disrepair`, condition-specific photo queries.
- **Structure:** safety first; wide/context/detail/repeat sequence; scale/measurement; recurring conditions; originals/edits; metadata/privacy; inspector handoff.
- **Visual asset:** a labeled, clearly staged synthetic sequence.
- **Guardrail:** do not imply a photo alone proves cause, authorship, or a legal violation.

#### 5. California habitability evidence guide

- **Target:** `what evidence do I need for a habitability claim California`.
- **Sources:** CA AG tenant guidance, 2026 CA DRE guide, California Courts self-help, Civil Code §1941.1, local legal-aid review.
- **Structure:** plain answer; conditions; notice; documentation; inspection; organizing records; legal-help referral; last reviewed/reviewer/corrections.
- **Guardrail:** no advice to withhold rent or take a remedy without jurisdiction-specific counsel.

### Spanish strategy

Spanish SERPs contained many government PDFs and law-firm summaries, but relatively few practical, accessible, tool-led evidence workflows. That is a strong fit, not a shortcut.

Start with:

- `/es/guias/documentar-reparaciones/`
- `/es/plantillas/lista-de-pruebas-habitabilidad/`
- `/es/ejemplos/paquete-de-pruebas-habitabilidad/`
- `/es/guias/pruebas-condiciones-inhabitables-california/`
- `/es/para/sindicatos-de-inquilinos/`

Every version should have visible translated content, a stable URL, reciprocal `hreflang`, `x-default`, human review, localized metadata, and parity in update dates. Do not auto-translate legal claims or launch dozens of jurisdiction pages.

Useful Spanish primary sources include [USAGov tenant rights](https://www.usa.gov/es/derechos-inquilinos), the [California AG Spanish habitability guide](https://oag.ca.gov/system/files/media/Know-Your-Rights-Habitability-Spanish.pdf), and [California public-health mold guidance in Spanish](https://www.cdph.ca.gov/Programs/CCDPHP/DEODC/EHLB/IAQ/CDPH%20Document%20Library/CDPH_Mold_Booklet_2021-Feb-1_SPA.pdf).

### Structured data and search presentation

- Add accurate `SoftwareApplication`/`SoftwareSourceCode` JSON-LD to the product page and `Article` + `BreadcrumbList` to reviewed guides.
- A free offer can be represented honestly, but do not fabricate `aggregateRating` or reviews to chase a software rich result. Google documents the supported software-app properties here: [SoftwareApplication structured data](https://developers.google.com/search/docs/appearance/structured-data/software-app).
- FAQ sections are useful for people and long-tail questions, but do not expect FAQ rich results; Google generally limits those to authoritative government/health sites.
- Add self-referencing canonicals, unique title/descriptions, OG/Twitter cards, a favicon, and a reusable social image.
- Give the raw sample an intentional policy. The safest static-host pattern is an indexable explanatory page plus downloadable signed artifacts; do not put raw bundle/PDF URLs in the sitemap. Add `noindex` to the raw sample HTML. GitHub Pages cannot easily add `X-Robots-Tag` to a PDF, so consider distributing raw artifacts as a release/ZIP while the explanatory HTML owns search.

### Recommended homepage metadata and copy

**Title (58 characters):**

> Habitable Evidence — Offline Tenant Repair Documentation

**Meta description (141 characters):**

> Habitable Evidence helps tenants and unions document repairs, notices, photos, and timelines offline—then share a packet anyone can verify.

**Primary CTA while alpha:** `Join a tenant-union or legal-aid pilot`

**Secondary CTA:** `Explore a verified sample case`

**Tertiary CTA:** `Review the evidence method`

Add a tenant-facing safety route near the alpha warning: this is not ready for a real legal case; never send case photos or personal details through the pilot contact; link to current government/legal-aid finders.

### Link earning and partnerships

The best links will come from useful artifacts and qualified partnerships, not generic guest posts.

- Co-review the California guide/checklist with a housing clinic, tenant union, or legal-aid partner.
- Offer the annotated packet and verifier fixture to legal-tech, civic-tech, digital-preservation, and court-technology communities.
- Publish current security/accessibility findings and remediations, not only badges.
- Cross-document C2PA/ProofMode import and standard RFC 3161 verification when real interoperability exists.
- Turn the existing organizer workshop and EN/ES quick starts into searchable HTML and offer a recorded synthetic-data workshop.
- Submit the open schema/kernel only to relevant OSS/civic-tech directories after the package/install path is real.
- Use ethical comparison pages: tenant-owned evidence vs landlord portal; verified photo vs complete habitability record; local-first vs cloud evidence storage.

### Measurement without product surveillance

Do not add analytics to the case app or verifier. If governance accepts it, use aggregated Google Search Console query/page data on the public documentation site; this requires no Habitable client tracker. Pair it with manual/outcome measures:

- canonical pages discovered and indexed;
- non-brand impressions and average position by cluster;
- clicks to the annotated sample, verifier, and pilot contact;
- signed sample verification success in CI;
- partner referrals and workshop requests;
- pilot recruitment, completion, and recipient usability outcomes;
- no privacy incidents and no unsupported claim regressions.

Traffic alone is not success. The north-star remains a safe, usable record that helps a tenant or organizer act.

## Prioritized action plan

### Immediate trust repair: before promotion

| Action | Impact | Effort | Dependency |
|---|---:|---:|---|
| Regenerate/sign the sample from current main; realistic synthetic media; CI verification/privacy/version gate | High | S-M | Resolve current packet trust semantics |
| Split verifier verdicts into integrity/trust/readiness and hide dev TSA in normal UI | High | M | Legal/crypto review of terminology |
| Triage 23 open PRs into trust/pilot/post-pilot; make speculative work draft; request reviewers | High | S | Maintainer decision |
| Fix installed-wheel assets and add clean-environment app smoke test; block PyPI publication until green | High | M | Packaging decision |
| Correct capability/docs drift and broken internal links; add claim ledger/link check | High | M | Current-main inventory |
| Stop recommending `0.0.0.0` as a safe phone path | High | S | Documentation update |

### Quick SEO wins: one week after proof repair

| Action | Impact | Effort | Dependency |
|---|---:|---:|---|
| Verify Search Console, request indexing, add canonical, sitemap, and `robots.txt` reference | High | S | Stable public URL |
| Rewrite title, description, H1, lede, and CTAs around documentation/case intent | High | S | Positioning decision |
| Add OG/Twitter metadata, favicon, image dimensions, lazy loading, and modern image variants | Medium | S-M | Social image asset |
| Add a pilot/contact route that asks for no case evidence or PII | High | S | Contact owner/privacy copy |
| Publish `/for/tenant-unions/`, `/for/legal-aid/`, and trust/open-gaps page | High | M | Pilot scope |

### 30–90 day strategic work

1. Ship the annotated signed packet hub and local zero-install verifier prototype.
2. Run real recipient comprehension tests before declaring the verifier done.
3. Publish the EN/ES evidence checklist, photo field guide, repair timeline template, and five-page California evidence cluster with qualified review.
4. Package a pilot build that installs without Git/Python/terminal and passes backup/restore/offline/update drills.
5. Run 5–8 compensated sessions across tenants, organizers, recipients, Spanish, and AT users with synthetic data.
6. Choose and land the minimum pilot PR set; defer sensor, generic platform, and aggregate-network work.
7. Start one tenant-union or legal-aid pilot with written exit criteria and incident/escalation support.

### 3–12 month investments

- signed native-quality packaging and update path;
- trusted QR pairing, efficient/resumable sync, and case-bound peer authorization;
- timeline/notice/document model and progression views;
- organizer GUI over campaign health;
- recovery ceremony and drill mode;
- qualified jurisdiction packs based on partner demand;
- ProofMode/C2PA or JustFix interoperability only after a partner validates the path;
- independent crypto/security review, recorded human screen-reader pass, and pilot outcome report.

### Explicitly defer

- generic evidence verticals;
- security-deposit/move-in SEO as a product expansion;
- AI legal advice, automated cause detection, or mass state-law content;
- a project-run cloud case store or usage analytics;
- more aggregate/commons functionality before privacy/abuse review;
- separate kernel packaging before a second adopter commits;
- “tamper-proof,” “certified,” or admissibility guarantees.

## 90-day outcome scorecard

| Outcome | Evidence of completion |
|---|---|
| Public proof is credible | Published sample is current, signed, privacy-checked, and verifies in CI |
| Trust language is honest | Users can distinguish intact, authority-untrusted, and evidence-ready in EN/ES |
| Product is pilot-installable | Clean target device installs and completes capture→backup→restore→export→verify without terminal use |
| Recipient path is plausible | Five recipients verify and interpret a packet in under two minutes without assistance |
| Search foundation exists | Canonical/sitemap/Search Console complete; core pages indexed or diagnosed |
| Owned content answers real jobs | Annotated packet, checklist, timeline template, photo guide, and CA pillar live in EN; priority Spanish pages live |
| Roadmap is controlled | Every open PR belongs to trust repair, pilot, or post-pilot; speculative work is draft/deferred; reviewers assigned where required |
| Real validation begins | Pilot partner and qualified security/legal/accessibility reviewers have written scope and dates |

## Source notes

### Habitable

- [Live landing page](https://habitable.chelseakr.com/)
- [Repository](https://github.com/ChelseaKR/habitable)
- [Open pull requests](https://github.com/ChelseaKR/habitable/pulls)
- [v0.2.0 release](https://github.com/ChelseaKR/habitable/releases/tag/v0.2.0)
- Current source snapshot used for the final re-audit: [`fa892817`](https://github.com/ChelseaKR/habitable/tree/fa8928170910288c44ad2740e8c40d7426364322)

### Housing, courts, and evidence

- [California Attorney General tenant guidance](https://oag.ca.gov/tenants)
- [2026 California DRE Landlord-Tenant Guide](https://www.dre.ca.gov/publications/ResourceGuidebook/2026_Landlord_Tenant_Guide.pdf)
- [California Courts tenant trial evidence guidance](https://selfhelp.courts.ca.gov/pa/node/925)
- [California Civil Code §1941.1](https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1941.1)
- [LSC Civil Court Data Initiative](https://civilcourtdata.lsc.gov/)
- [RFC 3161](https://www.rfc-editor.org/info/rfc3161/)
- [NIST hash-chain glossary](https://csrc.nist.gov/glossary/term/hash_chain)
- [Library of Congress fixity guidance](https://www.loc.gov/programs/digital-collections-management/inventory-and-custody/data-integrity-management/)
- [FBI digital-image integrity guidance](https://archives.fbi.gov/archives/about-us/lab/forensic-science-communications/fsc/april2008/standards/2008_04_standards02.htm)
- [C2PA explainer](https://spec.c2pa.org/specifications/specifications/2.2/explainer/Explainer.html)

### Search guidance

- [Google: creating helpful, reliable, people-first content](https://developers.google.com/search/docs/fundamentals/creating-helpful-content)
- [Google: build and submit a sitemap](https://developers.google.com/search/docs/crawling-indexing/sitemaps/build-sitemap)
- [Google: multilingual and multi-regional sites](https://developers.google.com/search/docs/advanced/crawling/managing-multi-regional-sites)
- [Google: control search snippets](https://developers.google.com/search/docs/appearance/snippet)
- [Google: SoftwareApplication structured data](https://developers.google.com/search/docs/appearance/structured-data/software-app)

### Competitors and adjacent benchmarks

- [JustFix](https://www.justfix.org/en/)
- [Rentfile](https://play.google.com/store/apps/details?id=com.skyhi.rentfile)
- [Tenant Trace](https://tenanttrace.app/)
- [SnapProof](https://getsnapproof.com/)
- [ProofMode](https://proofmode.org/)
- [Tella](https://tella-app.org/)
- [RentCheck](https://www.getrentcheck.com/product-overview)
- [Truepic Vision](https://www.truepic.com/vision/inspection-platform)
- [OpenArchive Save](https://www.open-archive.org/guides/how-to-use-save)
- [eyeWitness to Atrocities](https://www.eyewitness.global/)
