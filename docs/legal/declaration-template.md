<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Declaration template — laying foundation for a habitable packet (item E-19)

> **This is not legal advice.** This is a fill-in-the-blank **educational template**, not a
> legal document drafted for your case. A declaration's required form, caption, signature
> block, and penalty-of-perjury wording differ by jurisdiction and court. **A licensed
> attorney in the relevant jurisdiction must review and adapt this before it is signed or
> filed.** Signing a declaration is signing under penalty of perjury — every blank must be
> filled in with the truth, from the declarant's own knowledge.

## How to use this template

- Text in `[BRACKETS]` is a blank to fill in. Italic *How to fill* notes explain each one.
- Keep statements to what the declarant **personally knows**. If the declarant does not know
  something (for example, the technical internals of the timestamp), the declaration says so —
  it does not guess.
- The declaration establishes **foundation**: who captured the media, on what device, that the
  app sealed and hashed it at capture, that the declarant has not altered it, and how the
  packet was produced and verified. It deliberately stops short of legal conclusions about the
  underlying habitability condition — that is what the declarant's testimony and the photos
  themselves are for.
- Two variants follow: a **Tenant/Witness declaration** (the person who captured the media)
  and an optional **Custodian/Organizer declaration** (chain-of-custody foundation for whoever
  assembled and exported the packet).

---

## Variant A — Tenant / Witness declaration

> *Caption, court name, case number, and the penalty-of-perjury formula are
> jurisdiction-specific — leave them to your attorney.*

**DECLARATION OF [DECLARANT FULL NAME]**

1. I am [DECLARANT FULL NAME]. I am over 18 and competent to make this declaration. The facts
   stated here are within my personal knowledge, and if called as a witness I could and would
   testify truthfully to them.
   *How to fill: the declarant's legal name; this paragraph establishes competence and personal knowledge.*

2. I [am / was] a tenant at [UNIT / ADDRESS, or a general description if the address must be
   protected] from approximately [DATE] to [DATE / "the present"].
   *How to fill: identify the unit. If a home address must be protected from disclosure, discuss with your attorney how much to state and whether to file under seal or redact.*

3. On [DATE(S)], I personally observed [SHORT DESCRIPTION OF CONDITION — e.g., "black mold on
   the bathroom ceiling," "the radiator in the bedroom did not produce heat"]. I took the
   photograph(s) and/or video described below myself, at [UNIT / ROOM], to document what I saw.
   *How to fill: state plainly what you saw and that you took the media yourself. This — your own observation — is what proves the condition; the app proves the file was not altered afterward.*

4. I captured this media using the "habitable" application on my [DEVICE — e.g., "personal
   Android phone"] on [DATE(S) / "the dates shown in the packet"].
   *How to fill: name the device and when. "On the dates shown in the packet" is acceptable if you relied on the app rather than independent memory of each date.*

5. Based on how the application works as it was explained to me, when I captured each item the
   application computed a digital fingerprint (a content hash) of the original file and stored
   the original unchanged, and later obtained a trusted timestamp over that fingerprint.
   *How to fill: this is the declarant's lay understanding, not a technical opinion. Keep "as it was explained to me" so the declarant is not testifying as an expert. The attorney may instead establish the technical points through the foundation guidance or a knowledgeable witness.*

6. I have not edited, retouched, cropped, or otherwise altered the original media I captured.
   The photograph(s)/video in the packet fairly and accurately depict what I saw on the
   date(s) I captured them.
   *How to fill: "fairly and accurately depicts what I saw" is the classic foundation for a photograph. Only sign this if it is true; if a shared copy had location metadata removed, that is a metadata change, not a change to the image content — see paragraph 7.*

7. I understand that the copy of the media included in the shared packet has had location
   information removed for my safety, and that this does not change what the image shows.
   *How to fill: include only if a location-stripped shared copy (not the sealed original) is what was produced. The packet's signed custody record binds the stripped copy to the original; your attorney can explain that if asked.*

8. The packet identified as [PACKET NAME / EXHIBIT NO.] is the packet produced from my
   captured media for [UNIT / ISSUE]. [To my knowledge, it has not been altered since it was
   produced. / It was produced and verified by [NAME], whose declaration is attached.]
   *How to fill: choose the bracketed clause that matches reality. If someone else assembled and exported the packet, use the custodian declaration (Variant B) for that part rather than having the tenant vouch for steps they did not perform.*

I declare under penalty of perjury [under the laws of [JURISDICTION]] that the foregoing is
true and correct.

Executed on [DATE] at [CITY, STATE].

_________________________________
[DECLARANT SIGNATURE / PRINTED NAME]

*How to fill: the exact penalty-of-perjury wording and whether a notarization is required are jurisdiction-specific — confirm with your attorney.*

---

## Variant B — Custodian / Organizer declaration (optional, chain-of-custody foundation)

> Use this when the person who **assembled and exported** the packet is not the same person who
> captured the media, or when you want explicit foundation for the chain of custody and the
> verification step. Keep the technical statements to what this declarant actually did and
> observed; do not have a lay custodian offer expert opinions on cryptography.

**DECLARATION OF [CUSTODIAN FULL NAME]**

1. I am [CUSTODIAN FULL NAME], [ROLE — e.g., "a volunteer organizer with [UNION]"]. I am over
   18 and competent to make this declaration, and the facts here are within my personal
   knowledge.

2. In my role I [received from / synced with] the device(s) of [TENANT(S) / "the tenant whose
   declaration is attached"] and assembled the evidence packet identified as
   [PACKET NAME / EXHIBIT NO.] for [UNIT / ISSUE].
   *How to fill: describe how the media reached you (direct device-to-device sync, etc.). habitable holds no central server, so there is no third-party host to account for.*

3. I produced the packet using the "habitable" application's export function on [DATE]. I did
   not edit the captured media. The application assembled the packet and recorded, for each
   item, its content hash, its trusted-timestamp token, and a chain-of-custody record.
   *How to fill: state only what you did. The export is one command; you did not hand-edit the evidence.*

4. After producing the packet, I ran the application's verification function (or it was run by
   [NAME]) against the packet, and it reported that the items verified against their content
   hashes and timestamp tokens and that the chain of custody was intact.
   *How to fill: attach or describe the verification output if available. The same verification can be reproduced independently by the other side — see the foundation guidance.*

5. The chain-of-custody record included in the packet is in an identity-stripped form: it shows
   that the recorded events were not inserted, deleted, or reordered, without disclosing which
   individual performed each action. The records identifying individuals remain in the union's
   files and were not exported.
   *How to fill: this explains, accurately, why the exported chain protects identities while still being verifiable. Do not claim it proves the truth of the condition — it proves the record's integrity.*

6. To my knowledge, the packet identified as [PACKET NAME / EXHIBIT NO.] has not been altered
   since I produced and verified it.

I declare under penalty of perjury [under the laws of [JURISDICTION]] that the foregoing is
true and correct.

Executed on [DATE] at [CITY, STATE].

_________________________________
[CUSTODIAN SIGNATURE / PRINTED NAME]

---

### A note on what these declarations do and do not establish

A declaration here lays **foundation for the digital record** — who captured it, on what
device, that it was sealed and hashed at capture, that the declarant did not alter it, and how
it was produced and verified. The **truth of the underlying condition** (that there really was
mold, that the heat really was out) rests on the declarant's own observation and testimony and
on the images themselves — not on the cryptography. Keep those two things separate, in the
declaration and in argument. See [`foundation-guidance.md`](./foundation-guidance.md).
