<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# The correspondence packet (`packet_version` 4)

This is the only packet in the corpus carrying a `correspondence` record. Before it
existed, **no committed bundle held one** — the sealed-message surface (issue #304)
shipped with nothing in `tests/golden/` pinning it, which is the state
`sensor-packet-v4/README.md` describes for instrument data and gives the argument
for. `tests/golden/` is the corpus two documents point at as the promise that old
packets keep verifying; a format surface absent from it is pinned by nothing.

It is deliberately **not** named `packet-v*`. That glob is the one-fixture-per-format-
version corpus that `tests/test_golden.py`, `tests/test_verify_fuzz.py`,
`tests/test_contrib_importer.py` and `tests/test_property_invariants.py` enumerate;
this is a second packet of a version that already has one, and enrolling it in those
harnesses is a separate decision from committing it — the reasoning
`scoped-packet-v3/README.md` and `sensor-packet-v4/README.md` both record.

## What it is evidence of

Two sealed messages, chosen so the fixture pins the states that are *not* "present":

| message | `From` | `Date` | `Subject` | `Message-ID` | body | attachments declared / read | items |
|---|---|---|---|---|---|---|---|
| `reply.eml` | present | present | present | present | `present` (plain text) | 2 / 2 | 3 |
| `forwarded-fragment.eml` | present | **absent** | **unreadable** | present | **`not_plain_text`** (HTML only) | 2 / **1** | 2 |

The first row is the issue's own acceptance case: *an `.eml` with two attachments
captures as three custody-bound items with relationships; the packet lists all three.*
Five items and three `supports` relationships across the two messages, and
`appendix.item_count` is 5.

The second row is the one that matters, and every cell of it is a different way for
a record to say nothing:

- **`Date` absent** — the message never carried the header. Not the same fact as a
  sender who left it empty, and not the same as one this reader could not decode.
- **`Subject` unreadable** — raw 8-bit bytes with no charset declared. It is there,
  and it cannot be turned into characters, so no value is published rather than a
  damaged one.
- **body `not_plain_text`** — an HTML-only mail. The bytes are in the sealed
  original; this packet declines to render attacker-supplied markup and says so
  instead of showing a blank body.
- **one attachment of two undecodable** — a `text/plain` part labelled with a charset
  that does not exist. It stays in `attachment_count`, is absent from
  `attachments_readable`, is **named in `warnings`**, and is not sealed as its own
  item. A count that quietly shrank to the number of items created would make a
  five-part message and a two-part message look identical from the output side.

`header_dates_are_claims` is `true` in both, and the published schema declares it a
`const`. A `Date:` header is what the sending program wrote; the only time bound on
any of these items is its RFC 3161 token.

## Regenerating it

    uv run python scripts/make_golden_correspondence_packet.py

The script builds a fresh packet through the real pipeline with a deterministic clock
and a fixed-time local RFC 3161 issuer, and preserves this README. The two `.eml`
files are written as literal bytes with fixed MIME boundaries rather than assembled
with `EmailMessage.add_attachment`, which mints a random boundary per run and would
make the fixture unreproducible.

It is pinned to the *current* packet version rather than frozen the way
`scoped-packet-v3` is, because it exists to pin a live format surface:
`test_the_correspondence_fixture_tracks_the_current_format` fails on the next version
bump until it is regenerated.

## It verifies

`verify_packet` reports `structurally_intact`, `signature_ok` and `custody_ok` with no
problems — the same verdict every other fixture in this corpus gets. Synthetic
throughout: there is no real tenant, no real unit, no real managing agent, and both
`example-landlord.test` and `example.test` are reserved names that cannot resolve.

One thing it does **not** do, and it is inherited rather than introduced: like
`packet-v4`, this bundle fails the *published* `docs/packet-bundle.schema.json` on
`custody_proof.entries[].action`, because that enum predates the `artifact_added` and
`relationship_added` custody actions the code has emitted since packet v4. Measured
with `jsonschema` 4.26.0: 13 such errors here, 3 in `packet-v4`, and **no other
error** in either. PR #313 is the correction and is a draft on purpose; nothing in
this fixture re-creates the defect or depends on it.
