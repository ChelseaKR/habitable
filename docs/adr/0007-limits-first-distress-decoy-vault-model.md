# 7. Limits-first distress / decoy-vault model: design accepted, implementation gated on human red-team review

Status: Accepted (2026-07-08)

## Context

The maximum-retaliation and shared-phone personas need *some* real coercion
mitigation, but a safety feature that overpromises can get someone hurt. Three
threads in the project converge on this decision:

- **The personas.** P-04 (Tobias, maximum-retaliation) is "most afraid of the gap
  the docs admit: duress mode is *not a guarantee against a coercing or forensic
  adversary*," and needs that limit "in plain language at the moment he turns it
  on, not only in the threat-model doc" ([R-15], `docs/research/synthetic-personas-feedback.md`).
  P-03 (Dorothy, shared phone) and the adversary lens P-22 (the retaliating landlord /
  red-team) sharpen the same need.
- **The red-team playbook.** `docs/audits/packet-attack-redteam.md` §A9 already
  plays the attacker: "I'll just make the tenant unlock it. Their 'duress mode' is
  theater." Its honest concession — "this is where the design is weakest, and it is
  documented as such" — is the design constraint, not a footnote: a decoy state
  hides contents from a casual or quick-coercion look and is **not** proof against a
  coercing adversary who can compel the real passphrase, nor against a forensic
  adversary who images storage at rest.
- **The decline table.** `synthetic-personas-feedback.md` lists *"Make duress mode
  guarantee safety against a forensic search"* as a request the project must
  **decline**: "overpromising in a safety feature can get someone hurt; the limit is
  real." The sanctioned response is to disclose the limit at point of use ([R-15])
  and harden at-rest defaults ([R-49]) **without** claiming a guarantee.

This is expansion **EXP-15** in `docs/ideation/03-expansions.md`. Its excellence
bar is a clean binary: *if shipped*, the feature ships with a red-team-reviewed,
point-of-use statement of its exact limits and no guarantee language; *if not
shipped*, the docs plainly say the capability does not exist. EXP-15 explicitly
depends on **FIX-14** — the docs correction that stops describing a
"duress-safe open state" as an existing capability — landing first.

Two facts about the current state make the decision below necessary rather than
optional:

1. **The capability does not exist in code.** Grepping `src/` and `app/` for
   `duress` / `panic` / `decoy` returns nothing. `vault.py` opens exactly one
   case under one passphrase-wrapped data key; `crypto.py` wraps a single DEK with
   a single scrypt-derived KEK. There is no second-vault or decoy path.
2. **FIX-14 has not merged.** As of this ADR, `README.md`, `docs/privacy.md`, and
   `docs/threat-model.md` on `main` still describe the "duress-safe open state" in
   the present tense, as if it existed. The honest-docs correction is an open PR,
   not yet on `main`. Building the feature before that reconciliation lands would
   layer a real-but-unreviewed mechanism under prose that already overclaims.

A coercion-resistance feature is safety-critical in the literal sense: the failure
mode is a person physically harmed because the tool implied a protection it did not
deliver. [R-15] and the decline table both name a **human red-team / security
review before release** as a hard gate. An automated implementation pass cannot
conduct a genuine adversarial review of its own cryptographic design, and
fabricating evidence that one occurred would be exactly the overclaim this feature
exists to avoid.

## Decision

We **adopt the limits-first design below** and **formally gate its implementation**
behind two prerequisites that this pass cannot satisfy. We do **not** ship any
distress/decoy crypto in code as part of EXP-15's first pass. This ADR is the
"design the model … implement only what survives that review" work product EXP-15
calls for; it records the reviewed-ready design and the go/no-go, not the feature.

### The design (what would be built, once the gates clear)

- **Separate decoy vault, separate passphrase — never a re-key of the real one.**
  A decoy is its own vault directory with its own `keyfile.json` (its own
  scrypt-wrapped DEK) and its own — plausibly mundane — case contents. Unlocking
  the app with the decoy passphrase opens the decoy vault; the real passphrase opens
  the real one. The two DEKs are independent: compromising or compelling one reveals
  nothing about the other's contents, and there is **no** stored pointer from the
  decoy to the real vault. This reuses the existing `crypto.create_keyfile` /
  `open_keyfile` primitives unchanged; the new surface is *selection*, not new
  cryptography.
- **No count-revealing metadata.** The on-disk layout must not betray how many
  vaults exist. A decoy that is obviously "the fake one" (an extra file, a flag in
  `config.toml`, a differing directory shape) is worse than nothing. This is the
  single hardest engineering constraint and the primary thing a red-team must break:
  storage-at-rest indistinguishability against a forensic adversary who images the
  device. **If that property cannot be met honestly, the feature is not built** —
  see Consequences.
- **Point-of-use limits, unavoidable at enable time.** The scary-honest statement
  below is shown, in full, at the moment the user turns the feature on, and is
  re-surfaced (short form) wherever the decoy is opened. It is bilingual (EN/ES) to
  match the project's civic surface, and it is copy this ADR pins so it cannot drift
  into softer language later. Touch points if built: `app/app.js` (enable flow +
  unlock screen), `cli.py` (a `--decoy` / setup path), with the limits string
  sourced from the i18n catalog.
- **No panic-wipe in the first version.** A destructive "burn it all" action is
  attractive and dangerous: it invites a coercer to escalate ("I saw you tap
  something") and it can destroy the very evidence the tenant needs. If a panic
  action is ever added it is a separate, later decision with its own review; the
  first shippable version is *hide*, not *destroy*.

### The point-of-use limits statement (pinned copy)

> **This does not make you safe. Read this before you turn it on.**
>
> A decoy vault can hide your real case from someone who glances at your screen or
> forces a quick unlock. It **cannot** protect you from someone who can make you
> give up your real passphrase, and it **cannot** protect you from a forensic lab
> that takes your device and analyzes its storage. It is harm reduction, not a safe.
>
> If someone with power over you might search this phone, do not rely on this alone.
> The strongest protections are not on this device: tell someone you trust, keep a
> copy somewhere the other person cannot reach, and get advice from a tenant or legal
> advocate.
>
> We will never tell you this feature guarantees your safety, because it does not.

(Spanish translation to be authored with the same register — plain, unhedged, and
without any word that reads as a guarantee — as part of implementation, and reviewed
by the same red-team gate.)

### The gates (both required before any code ships)

1. **FIX-14 must be merged** so the honest-docs baseline exists: the project must
   already say the capability is *planned, not implemented* before a real mechanism
   is added beneath it.
2. **A genuine human red-team / security review** of the concrete implementation —
   specifically the storage-at-rest indistinguishability property — must be
   completed and recorded. Not a self-review by an automated pass; an adversarial
   review by a person or team playing P-22. Implementation proceeds **only on what
   survives that review**, and the feature ships only if the point-of-use statement
   above (or a stricter one) ships with it.

## Consequences

- **The docs must keep saying the capability does not exist**, in the present tense,
  until it actually ships — satisfying EXP-15's "if not shipped, the docs plainly say
  the capability does not exist." FIX-14 carries out that correction; this ADR does
  not duplicate it, but it depends on it and would be contradicted by any doc that
  re-introduces present-tense "duress-safe state" language.
- **No guarantee language, ever** — in the feature, its enable flow, the docs, or
  marketing. This is an invariant from the decline table, and this ADR is the durable
  record of it for the distress feature specifically.
- **The hardest risk is named and made falsifiable.** If a red-team shows that a
  decoy vault cannot be made forensically indistinguishable from a single-vault
  device on the target platforms, then the honest outcome is to **not build it** and
  to say so — a decoy that a forensic examiner can trivially detect as a decoy can
  escalate coercion and is worse than none. That negative result is an acceptable,
  in-scope outcome of the gate, not a failure to deliver.
- **Cheaper, lower-risk mitigations are not blocked by this gate** and remain the
  recommended near-term harm reduction: discreet-presence work (app name/icon,
  notification and recent-apps surface — R-12/R-13/R-14) and at-rest hardening
  (R-49), none of which claim to defeat coercion and none of which need this ADR's
  crypto review.
- **When the gates clear, implementation starts from a reviewed spec** rather than a
  blank page: this ADR is immutable once Accepted (per ADR 0001), so a later decision
  to build, to defer further, or to abandon the feature is recorded as a *new* ADR
  that supersedes this one, keeping an honest trail of how the thinking changed.
