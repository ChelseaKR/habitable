# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Fail a release when the installed wheel cannot serve its local web app."""

from __future__ import annotations

import threading
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory

from habitable.appserver import make_app_server
from habitable.vault import Vault


def main() -> None:
    """Install-time smoke: open a vault and fetch the packaged app shell."""
    with TemporaryDirectory() as tmp:
        vault = Vault.create(
            Path(tmp) / "vault", "test-passphrase", case_id="wheel-smoke"
        )
        server = make_app_server("127.0.0.1", 0, vault, tsa=None)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as response:
                body = response.read().decode("utf-8")
                if response.status != 200 or "habitable" not in body:
                    raise SystemExit("installed wheel did not serve the Habitable app shell")
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/i18n/en.json", timeout=5
            ) as response:
                if response.status != 200:
                    raise SystemExit("installed wheel did not serve app translations")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    main()
