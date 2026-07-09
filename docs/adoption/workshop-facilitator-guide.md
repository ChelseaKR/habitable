<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Workshop facilitator guide — onboarding your union to habitable

A future ~90-minute workshop for an organizer onboarding union members. The curriculum is
retained for review, but **must not be run as a phone-install workshop yet**: the alpha has no
safe on-device package, and the unlocked local server is restricted to loopback. Until the
release gates in [`docs/mobile.md`](../mobile.md) pass, use a facilitator-controlled laptop,
synthetic data, and discussion only. Do not connect participant phones to the app server.

> **Alpha software. Say this out loud in the room.** habitable works end to end, but it is
> **not audited and not proven in court**, and the default development timestamp authority
> is non-production. **Today this workshop is practice, not a live legal tool.** Tell
> participants plainly: *do not rely on this for a real case yet.* When that changes, the
> [README](../../README.md) and [threat model](../threat-model.md) will say so. This
> honesty is not a disclaimer to rush past — it is the whole posture of the tool, and
> modeling it builds the trust the workshop depends on.

---

## Before you start (facilitator prep)

**Do a full dry run yourself first.** Walk the entire setup guide
([`docs/setup-guide.md`](../setup-guide.md)) and the mobile install
([`docs/mobile.md`](../mobile.md)) end to end on your own device a day ahead. You cannot
teach a flow you have not done.

**Prepare the room:**

- A laptop you can run `uv run habitable app` on. Keep the app on loopback and project or
  screen-share the synthetic demonstration; participant phones must not connect.
- The printed quick-start, **in both languages**: [English](quickstart-en.md) and
  [Spanish](quickstart-es.md). Print enough for everyone plus spares.
- A few **practice photos** on a USB stick or shared folder (a picture of a wall, a
  window — anything; *no real case material*), so people who don't want to photograph their
  own home still have something to capture.
- Index cards and pens for writing down passphrases and recovery details by hand.
- For the verify demo: have `uv run habitable demo` ready to run on your laptop.

**Set expectations in the invite**, not just on the day: "Bring the phone you'd actually
use to document a problem. We'll install an app and practice — no real case data, nothing
gets uploaded anywhere, no account to create."

**Plan for the margins.** Some people will have old, low-storage phones; some will read
Spanish, not English; some use a screen reader or large text; some are anxious about
"breaking something." That is normal and expected — see *Accessibility & language reminders*
at the end, and weave it through the whole session, not just one segment.

---

## Agenda at a glance (≈90 minutes)

| Time | Segment | Type |
| --- | --- | --- |
| 0:00–0:10 | Welcome + what this is (and isn't) | Talk |
| 0:10–0:25 | **Consent, safety, and retaliation risk** | Talk + discussion |
| 0:25–0:40 | Review the planned phone workflow | Discussion |
| 0:40–0:55 | Capture a practice issue | Hands-on |
| 0:55–1:05 | "Awaiting timestamp" — what it means | Talk + watch |
| 1:05–1:20 | Export & verify a practice packet | Demo + hands-on |
| 1:20–1:30 | Back up your key (the one that matters most) | Hands-on + talk |
| 1:30 | Common questions + close | Discussion |

Times are a guide. If a group is moving slowly, **cut the export hands-on to a demo** and
protect the consent and key-backup segments — those two are the ones people get hurt by
skipping.

---

## 0:00–0:10 — Welcome + what this is

Keep it short and plain.

- **What it does:** lets a tenant document a habitability problem — mold, no heat, pests,
  water, electrical, structural — as photos, notes, and a timeline, captured so the record
  can be shown not to have been altered after the fact, and assembled into a packet for a
  court or inspector.
- **Why it's different:** there is **no company server, no account, no tracking**. The data
  lives encrypted on *your* phone. The union holds its own keys. Nobody — not even this
  project — can read it, hand it over, or recover it for you.
- **The honest limit, up front:** it is **alpha**. We are practicing today. It produces
  *documentation*, not legal advice, and it cannot promise a court will accept anything.

Invite one sentence from each person on what they're documenting (or would). It grounds the
rest of the session in real problems.

---

## 0:10–0:25 — Consent, safety, and retaliation risk (do not skip)

This is the most important fifteen minutes. The tool's threat model is **a landlord who
retaliates** ([threat model §1](../threat-model.md#1-adversary)). Treat people's safety as
the first feature, not the fine print.

Cover, in plain language:

- **Documenting can carry risk.** A landlord who learns a tenant is building a case may
  retaliate — eviction filings, harassment, selective enforcement. Each person decides for
  themselves whether and how to document. **No one is required to participate**, and that is
  a real, respected choice in this room.
- **Heightened risk for some.** Undocumented tenants, people on shared phones, and anyone
  already facing threats carry more exposure. Make space for them to opt out quietly or talk
  to you one-on-one afterward — do not put anyone on the spot.
- **Shared phones leak.** If someone shares a device, others may see the app's icon, its
  name in the app-switcher, or notifications. Name this honestly: the tool reduces risk, it
  does not erase it. (This is a known gap; see [threat model §5](../threat-model.md#5-what-is-not-protected--explicit-limits).)
- **Duress mode is not implemented.** Do not tell participants that the app can hide a real
  vault behind a decoy state. Today the icon, local files, and an unlocked session can reveal
  use of the tool. A future design is documented with strict limits, but it is not protection
  anyone can rely on now.
- **What leaves the device, ever.** Only two optional things, and only if used: an encrypted
  sync relay (sees scrambled data plus *who-connected-when* metadata, never contents) and a
  timestamp authority (sees a one-way fingerprint of a file, never the file). Photos of
  someone's home never go to a server. Location is stripped from anything shared.
- **Consent to share is separate from consent to document.** Capturing for yourself is one
  decision; handing a packet to a lawyer, a court, or the union is another. Nothing is shared
  automatically.

**Discussion prompt (5 min):** "What would feel unsafe about documenting your situation, and
what would make it feel safer?" Listen. Adjust the rest of the session to what you hear.

---

## 0:25–0:40 — Review the planned phone workflow (discussion)

Follow [`docs/mobile.md`](../mobile.md). The supported alpha evaluation is on the same laptop
as the engine; phone installation is blocked pending an on-device package.

1. You (facilitator) start the server on your laptop and keep it on loopback:
   ```console
   $ uv run habitable app
   ```
   Project or screen-share the interface. Do not read out the URL for phones to open.
2. Explain the intended future home-screen flow without asking participants to install it:
   - **Android / Chrome:** ⋮ menu → *Add to Home screen* / *Install app*.
   - **iOS / Safari:** Share → *Add to Home Screen*.
3. Record questions and safety concerns for the packaging review.

**Watch for:** old phones where the menu looks different (walk over, don't call it out);
people worried the icon is too visible on a shared phone (acknowledge it — see the consent
segment); and low storage. Do not imply that a facilitator-hosted LAN session is safe even
for practice.

---

## 0:40–0:55 — Capture a practice issue (hands-on)

**Use practice material, not a real case.** The practice photos you brought, or a harmless
photo of the room you're in.

Have everyone:

1. Start a practice issue: pick a category (say `mold`) and a room (say `bathroom`), give it
   a title like "Practice — ignore."
2. Capture a photo into that issue.
3. Add one timeline entry — e.g. "Practice note."

Narrate what just happened underneath: the moment a photo is captured, the original is
**sealed** (kept exactly as-is) and **fingerprinted** (a content hash), instantly and
offline. That's what later lets anyone check it wasn't edited. Nothing was uploaded.

**Reassure the anxious (this matters):** "You cannot break this by tapping around. It's a
practice case. There is nothing here you'll regret." Point out where confirmation and undo
live for anything destructive.

---

## 0:55–1:05 — "Awaiting timestamp": what it means

This is the single most common point of confusion (a real, repeated finding), so slow down.

Explain it as a calm, plain story:

- When you capture a photo, it is **already safe**: sealed and fingerprinted on your phone
  the instant you take it, with no internet needed.
- A **trusted timestamp** is a separate, extra step: the app sends only the *fingerprint*
  (never the photo) to an outside time service that signs "this exact content existed by
  this date." That needs a connection, so until it happens the item shows
  **awaiting timestamp**.
- **"Awaiting timestamp" is not an error and not a warning.** Your evidence is not lost or
  weaker for sitting in that state. It just means the date-stamp step is still queued.
- **What to do:** when you next have Wi-Fi or signal, the app fetches the timestamp (the
  *Resolve awaiting timestamps* action). You can keep using the app, or close it, in the
  meantime. Being offline for days or weeks is fine — the fingerprint already anchors the
  content to capture time.

If you have a connection in the room, have people resolve their practice items and watch the
status change. If not, just show it on your laptop. The point is to retire the fear: *it
worked, you're safe, the date-stamp catches up later.*

---

## 1:05–1:20 — Export and verify a practice packet

The payoff: a packet isn't "trust me," it's a set of claims anyone — including the other
side — can independently check.

**Demo on your laptop** (fastest, reliable):

```console
$ uv run habitable demo
```

This captures synthetic photos, builds a packet with location stripped from the shared
copies, and verifies it — all offline. When you see `packet intact`, say what that means:
every item was checked against its sealed original and its timestamp, and nothing was
altered.

Then, time permitting, **let participants export and verify their own practice case** from
the setup-guide flow ([`docs/setup-guide.md` §5](../setup-guide.md)), or watch you do it
once more slowly. The key teaching point: **the recipient runs the check, not you** — that's
why the evidence is credible. (A note for later: a non-technical recipient like a court
clerk can't run a command line today; a drag-and-drop recipient verifier is on the roadmap,
not built yet. Be honest about that if asked.)

---

## 1:20–1:30 — Back up your key (the part people most regret skipping)

Walk this from [`docs/key-management.md`](../key-management.md). Say the hard truth plainly,
because it is the one that hurts people:

> **If you lose your passphrase, and you have no recovery backup, and no other device still
> has the case — the data is gone. Permanently. No one can recover it, on purpose.** That's
> the same property that means a landlord, a breach, or a subpoena can't get it either.

So everyone does this, today:

1. **Write the passphrase down by hand** on an index card and keep it somewhere safe — not a
   sticky note on the phone.
2. **Make a recovery backup:**
   ```console
   $ uv run habitable key backup --vault ./case --out ./case-recovery.txt
   ```
   The recovery file uses its *own* separate passphrase. Keep the file and that passphrase
   **in a different place** from the everyday one.
3. **A good union habit:** a second trusted organizer holds each tenant's recovery file,
   with a recovery passphrase only that organizer knows — so no single phone loss is fatal,
   and no single person becomes a pile-of-everyone's-keys honeypot. (Storing every family's
   keys on one laptop recreates exactly the central target the tool exists to avoid — spread
   them out.)

If time is tight elsewhere, **protect this segment.** A lost-key story is the worst outcome
of adoption, and it is fully preventable here.

---

## Common questions (and honest answers)

- **"Can the company / you read my photos?"** No. There is no company server and no account.
  The data is encrypted on your device with your passphrase. No operator can read it, hand it
  over, or reset it.
- **"What if my phone is lost or stolen?"** Locked, it's encrypted — an adversary gets
  scrambled data without your passphrase. If you've synced to another device or made a
  recovery backup, the *case* survives the lost phone. If not, it may be gone (see key
  backup).
- **"Is 'awaiting timestamp' bad?"** No. Your photo is already sealed and safe. The
  date-stamp is an extra step that catches up when you're online.
- **"Will this win my case / is it admissible?"** It can't promise that. It produces strong
  *documentation*; whether a court accepts it is a legal question for your attorney. And
  remember — it's **alpha**, so today it's for practice.
- **"Does it cost anything / use my data plan?"** The tool is free and uses free public
  time-services. Capturing is offline. Syncing or fetching timestamps over cellular uses a
  little data; prefer Wi-Fi when you can.
- **"Someone on my shared phone might see the app."** Honest answer: yes, that's a real
  limit. The icon, app-switcher, and notifications can leak. We reduce risk, we don't erase
  it. Talk to me one-on-one about your situation.
- **"I tapped something — did I delete my evidence?"** Almost certainly not, and there's
  confirm/undo on the things that matter. Today it's a practice case anyway. You can't break
  this by exploring.

---

## Accessibility & language reminders (carry these through the whole session)

- **Two languages, fully.** The app is bilingual EN/ES — the whole interface, not half.
  Hand out the [Spanish quick-start](quickstart-es.md) without anyone having to ask, and run
  the session bilingually if your group needs it. Don't make Spanish speakers translate for
  themselves under stress.
- **Assistive-technology users.** Some participants use a screen reader (VoiceOver /
  TalkBack) or large text. Give them extra time, don't grab their phone, and let them drive.
  Be honest: a recorded end-to-end screen-reader pass is a v1.0 gate that isn't finished
  yet, so if an AT user hits a wall, **write it down** — that feedback is gold and goes to
  the project.
- **Low reading level under stress.** People document at midnight after a fight with a
  landlord; stress drops effective reading age. Use plain words, one step at a time, and
  point to the picture-based status help. Avoid jargon — say "date-stamp" not "RFC 3161
  token," "fingerprint" not "hash."
- **Anxiety and dexterity.** Reassure repeatedly that nothing can be broken by exploring.
  Allow imprecise taps; never rush anyone. There are no time limits in the app, and there
  shouldn't be any in your room either.
- **Low-end / low-storage phones.** Expect them. Sealing originals doubles photo storage;
  flag the offload-to-organizer path and don't make anyone feel their phone is "too old."

---

## For the trainer you're training

If your goal is train-the-trainer, hand your trainee this guide and have them **co-run one
segment with you, then lead a full session while you observe.** Tell them the three things
that matter most: protect the **consent/safety** segment, protect the **key-backup**
segment, and **never overpromise** — especially about duress mode, admissibility, and the
alpha status. Everything else they can learn by doing.
