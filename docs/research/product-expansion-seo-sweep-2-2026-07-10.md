<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Product, expansion, security, and SEO sweep 2

**Research and execution date:** 2026-07-10 (America/Los_Angeles; CI completed after
midnight UTC on 2026-07-11)

**Starting point:** the dated
[product-expansion and SEO baseline](product-expansion-seo-2026-07-09.md)

**Scope:** a second research → ideate → review → approve/defer/reject → implement →
independent-review → merge loop. This addendum records decisions and changed facts rather than
rewriting the first-pass snapshot.

## Executive result

The second sweep kept the baseline strategy—make public proof and trust semantics credible before
broadening the product—but moved from broad diagnosis to narrow, adversarial implementation.
Three kinds of work were approved:

1. close disclosure, filesystem, verifier, and release gaps that could make a narrow or safe claim
   false;
2. publish problem-first educational pages and a bounded tenant-union organizing template;
3. add one interoperable transfer adapter whose trust boundary is strictly weaker than Habitable's
   signed packet verification.

Ideas were not approved merely because they were useful. Each accepted item needed a bounded
contract, executable regression, honest residual-risk statement, and a separate PR that could be
rebased and reviewed against the immediately preceding merge. Risky shortcuts—especially custody
chain truncation, unacknowledged destructive queue cleanup, and stronger legal/authenticity
claims—were rejected.

## Method

This pass combined:

- repository-wide source, test, workflow, documentation, configuration, and generated-artifact
  inspection;
- hostile-input reproductions for packet references, metadata carriers, scoped disclosure, upload
  staging, persistence, and release identity;
- desktop/mobile and PDF rendering review where the output was visual;
- problem-first content/keyword ideation, internal-link and sitemap review, metadata/schema review,
  and claim-safety checks;
- primary standards and official-source review for BagIt, release artifact promotion, California
  inspection records, and New York City HPD records;
- serial GitHub merge discipline: rebase onto the latest `main`, run focused checks, require the
  repository's full gate and security scans, merge one PR, then repeat.

No Search Console, analytics, paid keyword-volume, or backlink dataset was connected. SEO
priorities remain qualitative until the static site has enough impressions for query/page data.
This is product and technical research, not legal advice.

## Approval framework

An idea was **approved now** when it met all of these tests:

- it corrected a demonstrable false claim, privacy leak, integrity gap, or high-confidence search
  need;
- it fit a narrow compatibility story and could fail closed where the honest feature did not yet
  exist;
- it was independently reviewable in one PR with regression coverage;
- it did not require pretending that technical integrity proves truth, authorship, receipt,
  compliance, admissibility, or a remedy.

An idea was **deferred** when the need was plausible but required partner validation, a new
protocol, external setup, human language/legal/accessibility review, or product telemetry. It was
**rejected** when its shortest implementation would destroy evidence semantics, silently discard
data, expand collection, or overstate trust.

## Approved and implemented

| Decision | Why it passed | Implementation and review result |
| --- | --- | --- |
| Preserve maintenance-request records guide | Problem-first search intent; useful without collecting tenant data; clear receipt/notice limits | PR #92; official-source review, contextual inbound links, SEO/content/axe gates |
| Preserve housing inspection records guide | Distinguishes agency records, tenant observations, and changing portal status | PR #95; California and NYC official sources, five inbound paths, status-is-not-condition guard |
| Tenant-union building survey template | Concrete organizing utility with no public intake/database | PR #98; blank CSV, private/aggregate separation, formula-injection guidance, pseudonymous routing, storage claim corrected |
| Remove all JPEG metadata carriers | EXIF-only stripping left XMP/IPTC/ICC/comment/trailing payloads | PR #94; pixel rebuild, orientation handling, decompression-bomb check, atomic publish, post-write metadata assertion |
| Confine packet verifier reads | Signed bundle fields and fixed control files could escape, follow links, block, or consume unbounded input | PR #96; signature-gated reference reads, basename/containment/file-type/size checks, hostile-root/control tests |
| Fail closed on scoped custody exports | Filtered visible records still carried a complete custody proof naming excluded records | PR #99; issue/date packets and issue-subset shares stop before output/state mutation; no chain is truncated and called complete |
| Promote exact release artifacts | Manual dispatch could build branch bytes; PyPI rebuilt instead of publishing tested bytes | PR #97; exact signed-tag commit, mainline-ancestry guard, build once, pinned artifact transfer, isolated OIDC publish job |
| Add a strict BagIt adapter | Archival/legal-aid transfer interoperability without changing packet bytes | PR #100; RFC 8493 profile, exact `data/packet/`, SHA-256 manifests, strict paths, source-mutation checks, BagIt explicitly not authenticity |
| Publish the first research baseline | Preserve evidence and reasoning instead of replacing old findings with a success narrative | PR #101; historical note, link gate, documentation-only |
| Remove plaintext upload/sanitization staging | Reproduction showed protected input could be durably staged in the vault | PR #103; random restrictive OS-temp workspace outside the vault, symlink-safe legacy cleanup, failure cleanup, and explicit no-secure-erasure limit |
| Make ordinary vault saves atomic | Multi-blob direct writes could expose a mixed-generation vault after interruption | PR #102; prepared/committed five-blob transaction, repeatable two-crash rollback, bounded no-follow recovery controls, and explicit filesystem/concurrency limits |
| Correct remaining scoped/disclosure claims | Post-fix audit found stale selective-export language and a custody-identity policy that claimed an unimplemented export | PR #104; actual-config fail-close, whole-unit/public-commitment corrections across code/docs/site, retained-metadata EN/ES HTML/PDF disclosure, and historical-scope compatibility |
| Bound relay resources and journal recovery | Per-message/per-room-count limits did not bound aggregate memory, response size, room count, or startup reads | PR #105; aggregate caps, streaming GET, strict framing/token/time validation, bounded journal/temp recovery, privacy-safe handler errors, post-TTL rebind recovery, 785-test exact-tree gate, and independent exact-head approval |
| Encrypt timestamp-token sidecars | Token records exposed capture linkage, authority, generation time, and token bytes despite the broad encrypted-at-rest story | PR #106; merged as `bec3fb7`, 897-test full gate, 95.15% protected-core coverage, 174-test exact-head review, GitHub security/merge gates green |

## Review findings that changed otherwise approvable PRs

The review loop produced material corrections; green first drafts were not treated as approval:

- The verifier PR initially failed the protected-core 95% coverage gate after adding hostile-file
  branches. The threshold was not weakened. Additional adversarial cases restored the gate before
  merge.
- The BagIt adapter's original direct `bundle.json` preflight would have bypassed the newly bounded
  verifier control-file reader. It was removed; ordinary same-inode mutation is now checked before
  and after every copy.
- The release PR was extended from “checkout the tag” to “checkout a tag whose commit is already on
  reviewed default-branch history.” Exact bytes from that build are the only PyPI inputs.
- The tenant survey's “local-only” wording was false for a downloaded CSV. Review changed it to
  user-chosen storage, added spreadsheet formula-prefix guidance, and replaced a potential owner
  name with a role/pseudonymous reference.
- “Redact unit” was narrowed to its real behavior: omission of one CRDT metadata field. Case text,
  identifiers, custody records, transport metadata, and original EXIF/GPS can still identify a
  household.
- A five-page synthetic PDF was rendered and inspected. Its bundled self-signed authority remains
  explicitly untrusted unless a verifier deliberately pins the synthetic certificate.
- A second synthetic Spanish PDF was generated under the nondefault metadata-retention policy.
  Extracted text showed the retention/location warning rather than the default metadata-removed
  copy; this remains a mechanical review, not native-speaker or full PDF-accessibility validation.
- The first atomic-vault-save draft restored the old generation correctly but deleted rollback
  copies while its marker still said `prepared`. A second crash during that cleanup could make
  recovery non-repeatable. Review required durable marker removal before backup cleanup, a real
  two-crash regression, and bounded no-follow recovery reads before approval.
- The relay's first bounded-startup draft still let expired lines strand a newer record behind the
  line ceiling, trusted a reusable device/inode pair as a complete file identity, accepted Python's
  permissive integer syntax for `Content-Length`, and allowed far-future timestamps to pin a TOFU
  binding. Review added stale-only pruning, size/mtime/ctime generation checks, literal ASCII
  framing, and a bounded future-clock allowance.
- Further relay fault injection found an unterminated append that could poison the next restart,
  unbounded compaction crash debris, a Windows unlink difference, and a misleading 413 instruction
  to “fetch and clear” even though GET is non-destructive. The approved design repairs a partial
  tail from live state before acknowledgement, has a separately bounded exact temporary namespace,
  documents its single-writer/Windows boundary, and tells peers to wait for TTL/retry or ask the
  operator to change capacity deliberately.
- GitHub CodeQL then rejected a world-writable default in an adversarial `os.open` test shim. The
  production call already used `0600`, but the test helper was corrected rather than dismissing the
  alert. A later exact-head review reproduced Python's default server error hook printing a peer IP,
  port, exception text, and traceback with access logging off; expected disconnects are now silent
  and unexpected faults produce only one fixed metadata-only event.
- A final relay restart reproduction showed acknowledged data loss after TTL cleanup failed: a new
  token was appended behind an expired old-token line and the restart rejected both as ambiguous.
  Expired records now validate and prune without establishing live TOFU identity; only conflicting
  live records reject the journal. The exact cleanup-failure → rebind → acknowledgement → restart
  sequence is a regression test.
- The token change started with authenticated, encrypted, per-capture sidecars that consolidate the
  primary timestamp token, additional tokens, and archive records. Review made legacy plaintext
  migration eager at unlock instead of getter-driven: publish and durably sync the encrypted
  replacement, authenticate its readback, and only then unlink the bounded plaintext source.
  Interrupted cleanup and a surviving encrypted/plaintext pair follow an explicit recovery path;
  unlink is not represented as secure erasure.
- The encrypted-token draft initially scanned the whole directory on every getter, admitted a
  4,097th ordinary entry, stranded cleanup temporaries at the live-entry ceiling, and allowed a
  swapped `tokens/` ancestor to redirect child operations outside the vault. Review moved child
  operations under one rechecked no-follow directory descriptor, separated bounded temporary and
  live allowances, enforced the prospective creation cap, and made migration scanning eager and
  once-per-open. Vault creation and opening now fail closed on platforms that cannot provide the
  required descriptor-relative, no-follow operations, rather than creating a vault that cannot be
  reopened safely.
- Hostile legacy JSON exposed three independent parser risks: recursive depth, very wide structures,
  and arbitrarily long integer atoms. A raw-byte pre-scan was also bypassable with UTF-16/UTF-32
  encodings. The accepted parser first requires strict UTF-8, then bounds nesting, structural-token
  width, and numeric atom length before using a bounded integer parser; ciphertext, plaintext,
  per-token text, list, and aggregate-entry limits are enforced separately.
- Legacy capture identifiers can themselves end in `.additional` or `.archive`, so filename suffix
  parsing alone changed an identifier's meaning. Migration now uses the bounded top-level JSON
  shape—object for a primary token, list for additional/archive records—to retain suffix-ending IDs.
  The documentation also states the unavoidable collision rule: if the old layout overwrote one
  logical record with another at the same physical path, only the surviving, shape-valid plaintext
  value can be recovered.
- Encryption does not make the sidecar directory metadata-free. Review required disclosure that
  stable hashed filenames expose record equality, entry count remains visible, ciphertext length
  approximates token volume, and filesystem modification/change times expose write timing. The
  design intentionally does not claim padding, filename randomization, metadata hiding, or secure
  erasure.
- A more serious key-rotation review found that cleanup after one successful rename could delete
  the only wrapped new key while live files already used that key. Rotation now pre-registers every
  stage and creates the wrapped-key stage exclusively, no-follow and restrictive, before
  publication; a nonblocking, no-follow descriptor pins its exact file generation before any live
  rename. This placement matters: an earlier draft pinned only after publishing data, so a FIFO race
  could leave new-key data beside the old keyfile. Publication becomes conservatively non-cleanable
  before the first rename attempt, including the asynchronous window after the kernel succeeds but
  before Python records success.
- Rotation ordering was tightened again after directory-entry durability was missing from the first
  repair. Every staged file and its parent directory is synced and revalidated before publication;
  rotated root data, originals, and token sidecars are renamed and their destination directories
  synced before the wrapped key is replaced as the commit point. Cleanup removes a stage only when
  its full recorded generation still matches, so a raced symlink, replacement file, or ambiguous
  partial publication is preserved for diagnosis/manual recovery instead of deleting an attacker's
  path or the only recoverable key.
- Final keyfile fault injection then found post-syscall, same-inode, detached-path, false-artifact,
  and secondary-cleanup-error cases. Once all data renames are known complete, the in-memory vault
  adopts the new DEK even if final proof or repair reports the original error. A mismatched live
  keyfile is atomically forward-repaired from pre-synced expected bytes; a partial publication whose
  fixed key stage was detached keeps a separately named owner-only
  `keyfile.json.recovery-<32hex>.new`. Recovery paths are reported only after exact-byte
  verification, secondary errors are attached without masking the primary fault, and exact random
  recovery names block retry under a bounded no-follow root scan until manual review.
- Exactly 4,096 legacy token entries also could not migrate because safe encrypted-first publication
  briefly needs one extra entry. Review added one strictly authenticated migration-only overlap,
  strengthened file-generation checks, and discloses that DEK-rotation staging can transiently
  double token-directory entries. Fault injection covers prepublication failure, partial
  publication, exact cleanup, and retry; process death during a multi-file rotation can still leave
  fixed stages that require the documented manual recovery boundary.

## Approved architecture, but deferred implementation

| Idea | Decision | Exit criteria |
| --- | --- | --- |
| Scoped packet/share restoration | Defer | New packet/sync versions define a derived, domain-separated, scope-bound custody view; golden compatibility, privacy tests, migration notes, and independent cryptographic review |
| Signed acknowledgement and sync-receipt compaction | Defer | Acknowledgement cannot be forged or lost; replay/idempotence survives pruning; old peers retain compatibility |
| Production ledger / public anchoring | Defer | Machine-readable disclosure, privacy threat model, operator ownership, retention/erasure policy, and pilot demand |
| Generic recipient handoff preflight | Defer | Start infrastructure-only; no claim of legal-aid/CMS integration without a real adopter and data-processing agreement |
| Native phone distribution | Defer after spike | Signed on-device package, supported update path, device security review, accessibility pass, and field pilot; loopback web server is not a mobile distribution strategy |
| Spanish acquisition pages and full packet parity | Defer | Native-speaker review, stable `/es/` information architecture, reciprocal `hreflang`, translated structured metadata, and ongoing maintenance owner |
| Jurisdiction expansion | Defer | Qualified local reviewer, dated source owner, update cadence, and no deadline/remedy calculator without maintained legal logic |
| Search-driven scale-out | Defer | Search Console query/page evidence, content maintenance capacity, and proof that pages are not thin programmatic variants |

## Rejected shortcuts

- **Truncate or renumber the existing custody chain for a scoped export.** That either breaks
  verification or misrepresents a derived fragment as a complete source chain.
- **Silently evict relay messages or destructively fetch them without an authenticated receipt.**
  Delivery and replay semantics must be explicit; capacity pressure is not permission to lose data.
- **Prune sync receipts by age alone.** A disconnected peer can return after the local retention
  window; pruning needs signed acknowledgement/protocol semantics.
- **Treat BagIt validity as packet authenticity or evidence readiness.** Manifests can be rewritten
  by an active attacker; the signed packet and independently supplied trust roots remain separate.
- **Publish a live national official-record scraper.** It creates freshness, privacy, terms, and
  jurisdictional interpretation obligations that a small static project cannot currently own.
- **Collect survey responses on the public site.** The useful artifact is a blank download with
  private handling guidance, not a new central tenant-data store.
- **Call one omitted metadata field anonymization.** Rare facts, dates, locations, text, identifiers,
  and original media can reidentify a household.
- **Claim custody identities are exported when the serializer strips them.** Until a versioned
  representation exists, the non-default policy must fail before output.

## SEO and content decisions

The accepted pages follow a small problem-first cluster rather than a high-volume content farm:

1. safe repair documentation checklist;
2. preserve a maintenance request from input through closure/export;
3. preserve complaint, inspection, citation, reinspection, and closure records;
4. tenant-union building condition survey template;
5. role pages for tenant unions, legal-aid reviewers, and inspectors.

Every new indexable page has a unique title and description, canonical URL, visible reviewed date,
sitemap entry, restrained Article/Breadcrumb structured data where appropriate, and contextual
inbound links. Pages avoid live lookups, address forms, analytics, scraped status, legal deadline
calculators, and “proof” language. The primary conversion is safe evaluation with synthetic data,
not submission of a real case to GitHub.

Measurement remains the missing loop. After indexing, review impressions, queries, click-through,
country/language, and page performance in Search Console. Use the evidence to consolidate weak
pages, improve useful ones, or reject a cluster; do not infer demand from publication alone.

## Residual engineering backlog

The following risks remain real after this batch and should be independently scoped:

1. sync receipt history can grow without a signed compaction acknowledgement;
2. several normal key/config writes and DEK rotation still have weaker crash-transaction semantics
   than the main vault-save path. Rotation now makes staged data durable before committing the
   wrapped key and performs identity-exact cleanup, but it is still a multi-file publication rather
   than a transaction manifest. A process death can leave fixed `.new` stages or a partial
   publication that is deliberately preserved for a documented manual ceremony; exact forward-
   repair and alternate-recovery artifacts also block retry until inspected. Ambiguous or replaced
   stages are not deleted automatically, and concurrent writers are not transaction-isolated. Token
   staging can transiently double directory entries, the encrypted layout still exposes
   stable-filename equality, entry count, approximate token volume, and write timing, plaintext
   unlink is not secure erasure, and platforms without the required descriptor-relative primitives
   are unsupported for the whole vault;
3. the relay's retained-ciphertext cap is not a process-RSS bound. Handler concurrency and body
   rate still need reverse-proxy limits. Persistence is best-effort rather than fsync-backed
   delivery or backup, unlink is not secure erasure, one local writer is assumed, physical expiry
   is lazy, and the mechanically exercised Windows cleanup path has no dedicated CI lane;
4. Spanish packet/application coverage needs a native-speaker and end-to-end recipient review;
5. the public sample's trust anchor is intentionally synthetic, and production release signing,
   PyPI environment policy, and trusted timestamp roots require external setup;
6. automated accessibility checks do not replace a recorded keyboard, zoom, screen-reader, and
   PDF recipient review;
7. no completed tenant-union/legal-aid pilot establishes usability, safety, legal fitness, or
   outcomes;
8. no Search Console or analytics evidence yet validates the new content cluster's impressions,
   queries, click-through, language demand, or consolidation opportunities.

## Primary references used in this sweep

- [Google Search Essentials](https://developers.google.com/search/docs/essentials) and
  [SEO Starter Guide](https://developers.google.com/search/docs/fundamentals/seo-starter-guide)
- [Google Article structured data](https://developers.google.com/search/docs/appearance/structured-data/article)
  and [localized versions / hreflang](https://developers.google.com/search/docs/specialty/international/localized-versions)
- [RFC 8493: BagIt File Packaging Format 1.0](https://www.rfc-editor.org/rfc/rfc8493.html)
- [PyPA Trusted Publishing action guidance](https://github.com/pypa/gh-action-pypi-publish)
- [actions/checkout history behavior](https://github.com/actions/checkout#fetch-all-history-for-all-tags-and-branches)
- [California Health and Safety Code, Part 1.5, Chapter 5](https://leginfo.legislature.ca.gov/faces/codes_displayText.xhtml?article=2.&chapter=5.&division=13.&lawCode=HSC&part=1.5.&title=)
- [NYC HPD maintenance issue process](https://www.nyc.gov/site/hpd/services-and-information/report-a-maintenance-issue.page)
  and [HPD Online information](https://www.nyc.gov/site/hpd/about/hpd-online.page?no_journeys=true)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)

## Implementation close-out

- The implementation batch closed on `main` commit
  `bec3fb7e529905583121072a66df343980b95422`, the merge commit for PR #106.
- Open implementation PR count at close-out: **0**. This addendum is published afterward as the
  only documentation PR in the final queue.
- Each implementation PR was rebased onto the immediately latest `main`, reviewed independently,
  required its focused and full local gates, passed the repository's GitHub merge/security checks,
  and was merged serially before the next PR.
- No pending implementation placeholder remains. Deferred and rejected items above remain
  explicitly non-shipped rather than being converted into roadmap claims.
