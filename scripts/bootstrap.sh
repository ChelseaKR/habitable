#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
#
# One-command dev bootstrap for habitable (Backlog R-42/R-43).
#
# Idempotent: safe to re-run. Installs uv if it is missing, provisions the
# Python 3.14 environment from pyproject.toml/uv.lock, and prints next steps.
# Works inside the devcontainer/Codespace (see ../.devcontainer/) or on a bare
# local checkout. No paid services; uv fetches Python 3.14 automatically.

set -eu

say() {
	printf '\n\033[36m==>\033[0m %s\n' "$1"
}

# Run from the repository root (the directory above scripts/) so the script
# can be invoked from anywhere.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$REPO_ROOT"

# 1. Install uv if it is not already on PATH (idempotent — skipped when present).
if command -v uv >/dev/null 2>&1; then
	say "uv already installed: $(uv --version)"
else
	say "Installing uv (astral.sh) ..."
	curl -LsSf https://astral.sh/uv/install.sh | sh
	# The installer drops uv in ~/.local/bin; make it available for this run.
	if [ -d "$HOME/.local/bin" ]; then
		PATH="$HOME/.local/bin:$PATH"
		export PATH
	fi
fi

if ! command -v uv >/dev/null 2>&1; then
	printf 'error: uv is not on PATH after install; add %s to your PATH.\n' \
		"$HOME/.local/bin" >&2
	exit 1
fi

# 2. Create the environment and install the project + dev tools. uv fetches the
#    pinned Python (3.14) if needed; re-running is a no-op once the lock is met.
say "Syncing the environment (uv sync) — fetches Python 3.14 if needed ..."
uv sync
uv run python -c "import sys; print('habitable env on Python', sys.version.split()[0])"

# 3. Next steps.
say "Setup complete. Next steps:"
cat <<'EOF'

  uv run habitable demo   # walk the whole pipeline on synthetic data, offline
  make verify             # the full merge gate: lint + types + tests + i18n

Serve the app locally with:  uv run habitable app
EOF
