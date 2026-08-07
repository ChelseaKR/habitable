# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The single canonical table of capture media types.

Before this module existed, ``capture._MEDIA_TYPES`` (file extension -> MIME
type, used to classify a freshly captured file) and ``packet._EXT_BY_TYPE`` /
``_DATA_EXT_BY_TYPE`` (MIME type -> packet export extension, used to decide
how a captured item's bytes can be shared) were hand-maintained independently
in two modules. ``.heic`` -- the iPhone default photo format -- was added to
the former and never added to the latter, so a ``.heic`` capture silently
exported with no bytes, no custody entry, and a ``habitable verify`` verdict
of READY (issue #158). Both modules now read the same registry, so a future
capture type cannot be taught to one and forgotten in the other:
``tests/test_media_types.py`` asserts every entry here is either exportable
by default or, at minimum, embeddable byte-exact via ``--include-originals``
-- no entry is ever a total dead end. ``packet.build_packet`` also
independently refuses (issue #158 decision 1) to publish any item that would
carry neither, so an omission here fails loudly at export time instead of
producing a packet that verifies clean with none of the evidence in it.

Not every media type has a metadata-stripping sanitizer available.
``image/heic`` is a recognized, capturable evidence type with no *default*
packet export path today: Pillow (this project's only image-processing
dependency) cannot decode HEIC without an additional native codec dependency
(e.g. ``pillow-heif``, which bundles ``libheif``), and adding that dependency
is future work -- it needs its own supply-chain/licensing review (``libheif``
and its bundled codecs are not uniformly permissively licensed) and real
HEIC-fixture testing, not a rider on this fix. A HEIC capture is not
stranded, though: ``--include-originals`` embeds it byte-exact, hash-verified,
as a deliberate, disclosed, higher-disclosure choice -- the same mechanism the
packet format already offers for any capture (see README, "Originals are
sealed; sharing is a deliberate, minimizing act"). Exporting a HEIC capture
*without* that flag now fails closed with a specific, actionable error
instead of silently shipping nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

__all__ = [
    "EXTENSION_TO_MEDIA_TYPE",
    "REGISTRY",
    "ExportKind",
    "MediaTypeSpec",
    "spec_for",
]

ExportKind = Literal["image", "video", "audio", "data", "unsupported"]


@dataclass(frozen=True, slots=True)
class MediaTypeSpec:
    """One capture media type: how to recognize it, and how (if at all) a
    packet export can produce a metadata-stripped shared copy of it.

    ``export_kind`` is ``"unsupported"`` (and ``export_ext`` is ``""``) for a
    type that capture, custody, and ``--include-originals`` all still handle,
    but for which no default sanitized shared copy exists.
    """

    media_type: str
    extensions: tuple[str, ...]
    export_kind: ExportKind
    export_ext: str  # "" iff export_kind == "unsupported"


REGISTRY: tuple[MediaTypeSpec, ...] = (
    MediaTypeSpec("image/jpeg", (".jpg", ".jpeg"), "image", ".jpg"),
    MediaTypeSpec("image/png", (".png",), "image", ".png"),
    # No default export path -- see module docstring. Still recognized at
    # capture time so hashing, sealing, custody, and timestamping proceed
    # exactly as for any other type; packet.build_packet refuses (rather than
    # silently dropping) a default-policy export of one of these, per issue
    # #158 decision 1.
    MediaTypeSpec("image/heic", (".heic",), "unsupported", ""),
    MediaTypeSpec("image/webp", (".webp",), "image", ".webp"),
    MediaTypeSpec("image/tiff", (".tif", ".tiff"), "image", ".tif"),
    MediaTypeSpec("video/mp4", (".mp4",), "video", ".mp4"),
    MediaTypeSpec("video/quicktime", (".mov",), "video", ".mov"),
    MediaTypeSpec("audio/mp4", (".m4a",), "audio", ".m4a"),
    MediaTypeSpec("audio/mpeg", (".mp3",), "audio", ".mp3"),
    MediaTypeSpec("audio/wav", (".wav",), "audio", ".wav"),
    # EXP-09: an independent instrument's CSV export (temperature logger,
    # moisture meter, ...) is a capture type like any other -- copied
    # verbatim (no embedded location metadata to strip) and interpreted for
    # rendering by habitable.sensor.
    MediaTypeSpec("text/csv", (".csv",), "data", ".csv"),
)

EXTENSION_TO_MEDIA_TYPE: dict[str, str] = {
    ext: spec.media_type for spec in REGISTRY for ext in spec.extensions
}

_BY_MEDIA_TYPE: dict[str, MediaTypeSpec] = {spec.media_type: spec for spec in REGISTRY}


def spec_for(media_type: str) -> MediaTypeSpec | None:
    """Return this media type's registry entry, or ``None`` if never registered.

    ``None`` covers a genuinely unknown type -- one that never went through
    :func:`habitable.capture.capture`'s normal extension classification, e.g.
    an explicit caller-supplied ``media_type`` override. A *registered but
    unsupported* entry (see ``image/heic``) still returns a spec here with
    ``export_ext == ""``; callers that care about exportability should check
    ``spec.export_ext``, not merely whether a spec exists.
    """
    return _BY_MEDIA_TYPE.get(media_type)
