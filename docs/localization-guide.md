<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Localization guide — for translation contributors

Thank you for helping habitable reach more people. A tool a Spanish-speaking,
Haitian-Creole-speaking, or Vietnamese-speaking tenant cannot operate has failed
at its purpose — **accessibility and bilingual/multilingual reach are not
optional** here, they are a project invariant. This guide is how to add and test
a language, how to write copy that sounds like a person rather than a lawyer or a
machine, and — importantly — which strings you must **never** soften or
reinterpret.

## How the string bundles work

The app (`app/`) is plain HTML/CSS/JS with no build step. All user-facing text
lives in **per-language JSON bundles** under `app/i18n/`:

```
app/i18n/
├── en.json     # the SOURCE OF TRUTH — every key originates here
└── es.json     # Spanish; same keys, translated values
```

Each bundle is a flat object of `"key": "translated string"`. The English
bundle, `en.json`, is the **source of truth**: every key that exists must exist
there first, and every other language mirrors its key set exactly. At runtime
`app/app.js` fetches `i18n/<lang>.json`, looks up each element's `data-i18n`
(and `data-i18n-aria`) attribute, and substitutes the string. The set of
selectable languages is the `SUPPORTED` array in `app/app.js`, and each has a
language button in `app/index.html`.

### The parity test — your safety net

`tests/test_app_i18n.py` enforces three things, and the build fails if any
breaks:

1. **Key parity** — every language has *exactly* the same keys as `en.json`. A
   missing key (or an extra one) fails `make verify`. This is what guarantees no
   user is ever shown a half-translated screen.
2. **No empty values** — every string is non-empty after trimming.
3. **Actually translated** — a sanity check that a non-English bundle is not just
   a copy of English (at least half the shared strings must differ).

So the workflow has a hard, automatic floor: **you cannot ship an incomplete
language.** Use that — run the test early and often.

## Add a new language

1. **Copy the source bundle.** Start from `app/i18n/en.json` so you have the
   complete, correct key set:

   ```console
   $ cp app/i18n/en.json app/i18n/<code>.json   # e.g. ht.json, vi.json, fr.json
   ```

   Use the standard two-letter (or BCP 47) language code; it must match what you
   register in step 3.

2. **Translate the *values* only — never rename a key.** Keys are the contract
   the code and the parity test depend on. Leave every key exactly as it is;
   change only the text to the right of the colon. Keep any placeholder syntax,
   punctuation that carries meaning (the `…` ellipsis on loading states), and
   capitalization intent.

3. **Register the language in the app.** Add the code to the `SUPPORTED` array in
   `app/app.js`, and add a language button in `app/index.html` modeled on the
   existing `lang-en` / `lang-es` buttons (`data-lang="<code>"`, an accessible
   label). Without this, the bundle exists but no one can select it.

4. **Test it.**

   ```console
   $ uv run pytest tests/test_app_i18n.py    # key parity, no-empties, actually-translated
   $ make verify                             # the full gate, incl. accessibility
   $ uv run habitable app                    # then switch to your language in the UI and read every screen
   ```

   The accessibility gate (axe-core) runs against the app; a translation that
   breaks structure or leaves a control unlabeled can fail it. Reading every
   screen in your language, end to end, is the step automation cannot do for you.

## Writing good copy — plain and human, not stiff and not lawyerly

The people using habitable are often documenting a problem at midnight after a
fight with a landlord. Stress lowers effective reading level. The persona
research is blunt about this: the Spanish was *correct* but "sounded like a
lawyer," and tenants wanted it to "sound like a person." Aim for that.

- **Translate the meaning, not the words.** A literal, word-for-word rendering of
  English idiom usually reads as machine output. Say what a careful, warm human
  who speaks the language would actually say.
- **Plain over formal.** Prefer everyday vocabulary and short sentences. Match
  the calm, reassuring register of the existing strings (e.g. the footer "Nothing
  leaves your computer").
- **Reassure and point to the next step.** Status and error strings should leave
  the reader knowing they are okay and what to do next, not stranded. (A tenant
  left "Awaiting timestamp" for a day, afraid to close the screen — that is the
  failure mode to write against.)
- **Avoid jargon, or gloss it.** "Chain of custody," "fixity," "hash" are terms
  of art. Where the UI must use one, prefer a plain phrasing or a short
  explanation in your language over a stiff calque.
- **But do not weaken the legally-sensitive strings** (next section). Plain is
  not the same as soft. "Not legal advice" must stay an unambiguous, honest
  warning — just an unambiguous, honest warning in *natural* language.

## Legally-sensitive strings — translate faithfully, never soften

Some strings are not just UI text: they are **honest-limits and warning
language** that protects the tenant. The whole credibility of the tool rests on
saying plainly what it does *not* do. **These must be translated faithfully —
accurate, equally strong, and equally clear. Never soften, hedge, omit, or
"improve" them, and never make them sound more reassuring than the English.** If
a faithful translation is hard, ask in the PR rather than guessing.

Current legally-sensitive keys in `app/i18n/en.json` (re-scan on every release —
this list can grow):

| Key | English | Why it is sensitive |
| --- | --- | --- |
| `alpha_warning` | "Alpha software — do not rely on this for real legal matters yet." | The core honesty caveat. Must stay a real warning, not a soft "still improving." |
| `alpha_label` | "Alpha software warning" | The accessible label for the warning; must read as a warning to AT users too. |
| `alpha_tag` | "Alpha" | A status badge; keep it as a clear maturity marker, not omitted. |
| `verify_ready` / `verify_intact_untrusted` / `verify_failed` / `verify_awaiting` | Ready / intact-but-untrusted / failed / awaiting | Integrity, authority trust, and readiness are separate claims. Never round token presence or structural integrity up to evidence readiness. |
| `custody_broken` | "Broken — verify the record" | A tamper/integrity warning. Must stay a clear "something is wrong, check it," never softened to "minor issue." |
| `custody_intact` | "Intact" | Its honest counterpart; do not overstate it as a guarantee of truth. |
| `capture_timestamped_no` | "not timestamped" | Reflects a real, weaker evidentiary state. Do not phrase it as if equivalent to "timestamped." |
| `footer_note` | "habitable runs entirely on this device. Nothing leaves your computer." | A privacy claim users rely on; translate it precisely, neither stronger nor weaker. |

Beyond these exact keys, the same rule applies to **any** future string that
states a limit, a warning, a privacy/security property, or an evidence verdict.
When in doubt, treat it as sensitive and flag it.

These mirror the honest-limits discipline of the README's
[*Honest limits*](../README.md#honest-limits--what-habitable-does-not-do) and the
hard rule that we *say what the tool does not do*. A translation that quietly
makes the tool sound safer or more authoritative than it is would put a tenant at
risk in exactly the moment the warning exists for.

## Readiness cautions: text expansion, RTL, and formats

habitable has had an initial **RTL-readiness pass** (R-48): the plumbing below is
in place, but a native-speaker visual QA is still required before an RTL or
heavily-expanding bundle ships. Flag any breakage you find rather than assuming
it is fully solved.

- **Text expansion.** Many languages run noticeably longer than English (German,
  French, Spanish in places). Buttons, badges, and labels now use
  `white-space: normal` / `overflow-wrap` / `flex-wrap`, so long strings wrap
  rather than overflow, and a static pseudo-locale check keeps compact-UI labels
  bounded. Still check your longest strings against narrow layouts — the app is
  tested down to a **320px reflow**, so test there.
- **Right-to-left (RTL).** The CSS has been audited to use only logical
  (`*-inline-*`, `inset-inline-*`, `text-align: start`) properties, `<html>`
  carries an explicit `dir="ltr"` default, and the app flips `dir` to `rtl` for
  RTL scripts (`ar`, `he`, `fa`, `ur`) alongside `lang` when the language
  changes. No RTL bundle ships yet, so **before shipping one, get a native
  speaker to visually QA every screen** — automated checks catch physical-
  direction regressions, not mirroring nuances (icons, progress direction).
- **Dates and numbers.** These are already rendered through `Intl.DateTimeFormat`
  / `Intl.NumberFormat` / `Intl.PluralRules` keyed to the active language, so
  date order and decimal/thousands separators follow the locale, not an English
  convention. Confirm they read correctly in your language and flag anything that
  still looks hard-coded.

## A per-language glossary of terms of art

We recommend each language ship a short **glossary of terms of art** — the
handful of recurring domain words and how this project renders them in that
language: *timestamp*, *chain of custody*, *hash / content hash*, *packet*,
*seal / sealed original*, *verify*, *evidence*, *duress mode*, *recovery*. The
goals:

- **Consistency** — the same concept gets the same word everywhere in the bundle,
  not three near-synonyms.
- **Honesty** — the chosen rendering preserves the precise (and limited) meaning;
  e.g. a "timestamp" word that does not imply the photo's *authorship* or *what
  it depicts*, only *when the content existed*.
- **Handoff** — the next translator into that language inherits your decisions
  instead of re-litigating them.

Keep the glossary short and put it where the next contributor will find it (a
note in the PR, or a small `app/i18n/glossary-<code>.md`). A glossary is a
recommendation, not a gate — but it is how a language stays coherent as it grows.

## When you open a PR

- Run `uv run pytest tests/test_app_i18n.py` and `make verify` until green.
- Read every screen in your language in the running app.
- Call out any legally-sensitive string you were unsure how to render, and any
  text-expansion / RTL / format breakage you hit.
- Sign off your commits (`git commit -s`); see
  [`../CONTRIBUTING.md`](../CONTRIBUTING.md).
