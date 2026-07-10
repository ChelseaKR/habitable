<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Board briefing — should our union adopt habitable?

A plain-language risk-and-benefit briefing for a tenant-union board or decision-maker. It is
written to help you make an honest call, not to sell you anything. Read it alongside the
[threat model](../threat-model.md), which backs up every claim below.

> **Bottom line first.** habitable is a privacy-first, offline tool that helps tenants
> document habitability problems as evidence that can be independently checked. It is also
> **alpha: not independently audited, not proven in court, with a screen-reader pass and
> signed app binaries still outstanding.** Our honest recommendation today is: **pilot it
> small, use it to practice and prepare, and do not yet bet a member's case or safety on it.**
> When that changes, the project will say so in writing.

## What it protects against

- **A landlord who retaliates.** That is the explicit threat model — a landlord (and their
  lawyer) with resources and motive, not a casual snoop.
- **No central honeypot.** There is no company server, no account, and no database of
  tenants, addresses, or photos. Data is encrypted on each member's device. **No operator —
  including this project — can read it, hand it over, or be subpoenaed for it,** because no
  operator ever holds it.
- **Tampering after the fact.** Each photo is fingerprinted and sealed the moment it's
  captured, and gets a trusted date-stamp once online. A packet's claims can be **checked
  independently** by the recipient — even by the opposing side — rather than taken on trust.
- **Accidental location leaks.** A home's GPS location is stripped from anything shared by
  default; the original stays sealed on the device.
- **Surveillance of your members.** No analytics, no telemetry, nothing phones home. The
  union holds its own keys and its own data; no outside party can read, revoke, or seize it.

## What it explicitly does NOT do

Being clear about the boundaries is the point — a tool that overpromises in a courtroom fails
the people relying on it.

- **It is not legal advice and cannot promise admissibility.** Whether a court accepts the
  evidence, or how much weight it carries, is a legal question for your attorney.
- **It cannot prove *who* took a photo or *what* it depicts.** A date-stamp proves content
  existed *by* a certain time; it does not prove authorship or that the image shows this unit
  on that day. It strengthens true records; it does not manufacture a case.
- **It has no duress/decoy mode.** A coerced real passphrase or an unlocked device exposes
  the vault. A future harm-reduction design exists only as an ADR and provides no protection today.
- **It cannot recover lost data.** No operator, no account recovery. The flip side of "no one
  can be subpoenaed for it" is "no one can get it back for you."

## The honest residual risks

After every safeguard, real risk remains. Decide with these in front of you:

- **A relay sees metadata.** If members sync through a relay, that relay can see *who connects
  to which case room, when, and roughly how much data moves* — never the contents, but the
  metadata is real. Avoid it entirely with pure device-to-device sync (a shared folder, USB,
  or in-person transfer).
- **No duress mode exists.** Members must hear this before deciding whether the tool fits
  their risk; vault encryption is the only current at-rest protection.
- **A hostile keyholder can rewrite their own local record.** The tamper-evidence detects
  *outside* alteration; it cannot stop the device owner from discarding and rewriting their
  own chain before anyone else has seen it. Detection depends on an external anchor (a synced
  peer or a timestamp over the record).
- **Lost key = lost data.** A forgotten passphrase with no recovery backup and no surviving
  synced device means the case is **permanently gone, by design.**
- **Shared phones leak.** The app's icon, the app-switcher, and notifications can reveal a
  case exists to others on a shared device. Risk is reduced, not erased.
- **It is alpha and unaudited.** No independent security/crypto audit has been completed, the
  default development timestamp authority is non-production, and the recorded screen-reader
  pass is unfinished. Treat it as a prototype for evaluation until a release says otherwise.

## What adopting responsibly looks like

If the board chooses to move forward, do it this way:

1. **Pilot small first.** A handful of willing, lower-risk members. Practice the full flow —
   capture, export, verify — on practice data before any real case.
2. **Run the onboarding properly.** Use the
   [workshop facilitator guide](workshop-facilitator-guide.md); protect the consent/safety and
   key-backup segments above all.
3. **Make consent real.** Documenting carries risk; no member is obligated to participate.
   Give higher-risk members (shared phones, undocumented status, active threats) a quiet way
   to opt out.
4. **Back up keys, without building a honeypot.** Every member makes a recovery backup. Spread
   custody across trusted organizers — do **not** pile every family's keys on one laptop, which
   recreates the central target the tool exists to avoid.
5. **Prefer device-to-device sync** where you can, to avoid relay metadata; if you run a relay,
   self-host a no-log one.
6. **Don't over-rely before the audit.** Use it to *prepare and organize* now; pair it with
   your tenant attorney or legal-aid group for what actually gets filed. Re-evaluate when the
   independent audit and the screen-reader pass land.

## Questions worth asking before you vote

- Who in our union will hold recovery backups, and how do we keep that from becoming a single
  point of failure?
- What happens when a member quits mid-case, goes unreachable, or is expelled — **whose data is
  it, and how do we hand off the case?** (It is the member's data; the step-by-step handoff flow
  is [`docs/custody-transfer.md`](../custody-transfer.md).)
- Do our highest-risk members have a safe way to opt out — or to use it on a non-shared device?
- Do we have legal-aid or attorney support lined up for what we collect?
- Are we comfortable piloting an **alpha, unaudited** tool for *practice* while we wait for the
  audit?

---

*This briefing is documentation, not legal advice. Full detail and the mitigation for each
risk live in [`docs/threat-model.md`](../threat-model.md) and the
[README's honest limits](../../README.md#honest-limits--what-habitable-does-not-do).*
