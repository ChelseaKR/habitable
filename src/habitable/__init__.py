# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""habitable — court-ready habitability evidence for tenant unions.

Offline-first, end-to-end-encrypted documentation of repair and habitability
problems as evidence that holds up: content-hashed and trusted-timestamped media,
an append-only chain of custody, peer-to-peer sync, and packets that a recipient
can independently verify.

The public API is intentionally small and layered; see the module docstrings and
``docs/ARCHITECTURE.md``. The verification path (:mod:`habitable.verify`) depends
on nothing else in the package so it can be embedded and audited on its own.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
