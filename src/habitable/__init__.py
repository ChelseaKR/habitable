# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""habitable — verifiable habitability documentation for tenant unions.

Offline-first, end-to-end-encrypted documentation of repair and habitability
problems as evidence that can be independently checked: content-hashed media with
timestamp tokens whose authority trust is assessed separately,
an append-only chain of custody, peer-to-peer sync, and packets that a recipient
can independently verify.

The public API is intentionally small and layered; see the module docstrings and
``docs/ARCHITECTURE.md``. The verification path (:mod:`habitable.verify`) depends
on nothing else in the package so it can be embedded and audited on its own.
"""

from __future__ import annotations

import importlib.metadata

__all__ = ["__version__"]

try:
    # Single source of truth: the installed distribution's version (from
    # pyproject.toml at build time), not a hand-copied literal that can drift from
    # it. REL-02/03: a v0.2.0 release once reported "habitable 0.1.0" because this
    # constant was hand-maintained and forgotten at tag time.
    __version__ = importlib.metadata.version("habitable")
except importlib.metadata.PackageNotFoundError:  # pragma: no cover - editable/uninstalled dev tree
    __version__ = "0.0.0+unknown"
