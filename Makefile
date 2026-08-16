# SPDX-License-Identifier: AGPL-3.0-or-later
# habitable — developer entry points. `make verify` reproduces the full CI gate.
.DEFAULT_GOAL := help
.PHONY: help bootstrap install lock-check fmt lint type test cov i18n doc-links markers verify audit a11y integration demo site-sample build repro relay-repro clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

bootstrap: ## One-command setup from a bare machine (installs uv if missing, then syncs)
	bash scripts/bootstrap.sh

install: ## Create the env and install the project + dev tools (Python 3.14 via uv)
	uv sync
	uv run python -c "import sys; print('habitable env on Python', sys.version.split()[0])"

lock-check: ## CQ-09: fail if uv.lock has drifted from pyproject.toml
	# `uv sync --frozen` is NOT a drift gate. It installs from uv.lock WITHOUT
	# reading pyproject.toml, so by construction it cannot notice the two disagree,
	# and it exits 0 on a drifted lock. `uv lock --check` is the gate.
	#
	# Ordering is load-bearing: this must run before anything that can rewrite the
	# lock. A bare `uv run` — which every other target here uses — silently relocks
	# first, so a gate invoked after one of those repairs the very drift it checks.
	# That is why `verify` lists this target first, and why CI runs it before `uv sync`.
	uv lock --check

fmt: ## Auto-format and auto-fix
	uv run ruff format src tests scripts/check_doc_links.py scripts/check_reproducible_build.py
	uv run ruff check --fix src tests scripts/check_doc_links.py scripts/check_reproducible_build.py

lint: ## Lint (no changes)
	uv run ruff format --check src tests scripts/check_doc_links.py scripts/check_reproducible_build.py
	uv run ruff check src tests scripts/check_doc_links.py scripts/check_reproducible_build.py

type: ## Strict type-check
	uv run mypy

test: ## Run the test suite (excludes network integration tests)
	uv run pytest -m "not integration"

# The security/crypto-critical modules. Each one carries its own 95% floor; see
# the `cov` recipe for why this must be one assertion per module.
COVERAGE_CORE := crypto vault tsa verify

cov: ## Run tests with coverage (85% floor overall, per-module 95% on the evidence-integrity core)
	uv run pytest -m "not integration" --cov=habitable --cov-report=term-missing --cov-report=xml --cov-fail-under=85
	# Per-module floor (CODE-QUALITY-STANDARD, security/crypto-critical paths): the
	# crypto/vault/tsa/verify core must each hold >=95% branch coverage, above the
	# 85% baseline. Scoped re-reports over the .coverage data the pytest run wrote.
	#
	# One `coverage report --fail-under` PER MODULE, not one over all four.
	# `--fail-under` only ever tests the TOTAL row, so a single `--include`
	# listing all four modules is a *pooled* floor: crypto.py at 100% carried
	# vault.py at 94.42% to a green 95.56% while three documents said the floor
	# was per-module (issue #183). Every module is reported before anything
	# fails, so one pass names every module below the line, not just the first.
	@failed=""; \
	for module in $(COVERAGE_CORE); do \
		echo "== per-module 95% floor: src/habitable/$$module.py"; \
		uv run coverage report --include="src/habitable/$$module.py" --fail-under=95 \
			|| failed="$$failed src/habitable/$$module.py"; \
	done; \
	if [ -n "$$failed" ]; then \
		echo "error: below the documented per-module 95% floor:$$failed" >&2; \
		exit 1; \
	fi; \
	echo "habitable: every evidence-integrity module is at or above its own 95% floor"

integration: ## Run the network integration tests (real public TSAs)
	uv run pytest -m integration -v

i18n: ## Mechanical i18n gates: UTF-8 (G1), BCP 47 validity (G3), EN/ES key-parity (G6) — offline, stdlib-only
	uv run python scripts/check_i18n_utf8.py
	uv run python scripts/check_bcp47.py
	uv run python scripts/check_i18n_parity.py

doc-links: ## Validate local Markdown links and capability-ledger evidence paths
	uv run python scripts/check_doc_links.py

markers: ## No bare TODO/FIXME/HACK (must reference an issue, e.g. TODO(#142)); no un-issued noqa/type:ignore
	@bad=$$(grep -rnE '(TODO|FIXME|HACK)' --include='*.py' --include='*.js' src tests app scripts 2>/dev/null \
		| grep -vE '\(#[0-9]+\)' || true); \
	if [ -n "$$bad" ]; then \
		echo "$$bad"; \
		echo "error: bare TODO/FIXME/HACK without a linked issue, e.g. TODO(#142)"; \
		exit 1; \
	fi
	@bad=$$(grep -rnE '# ?noqa|# ?type: ?ignore' --include='*.py' src tests scripts 2>/dev/null \
		| grep -vE '# ?noqa: ?[A-Z]+[0-9]|# ?type: ?ignore\[' || true); \
	if [ -n "$$bad" ]; then \
		echo "$$bad"; \
		echo "error: noqa / type:ignore without an explicit rule code (e.g. noqa: C901, type: ignore[arg-type])"; \
		exit 1; \
	fi
	@echo "habitable: no bare TODO/FIXME/HACK; no un-issued noqa/type:ignore"

verify: lock-check lint type cov i18n doc-links markers ## The full merge gate: lockfile drift + lint + types + tests with coverage + i18n, doc-truth, and marker gates
	@echo "habitable: full gate green on Python $$(uv run python -c 'import sys;print(sys.version.split()[0])')"

audit: ## Dependency vulnerability audit
	uv run pip-audit

a11y: ## Accessibility gate: structural + i18n + PWA, then the axe-core browser scan
	uv run pytest tests/test_app_accessibility.py tests/test_app_i18n.py tests/test_app_pwa.py
	uv run pytest -m a11y
	@echo "Manual pass: keyboard + NVDA/VoiceOver + zoom per docs/accessibility/manual-testing.md."

demo: ## Walk a synthetic case from capture to a verified packet (no real data)
	uv run habitable demo

site-sample: ## Regenerate and verify the synthetic packet published on GitHub Pages
	uv run python scripts/make_site_sample.py

build: ## Build the wheel + sdist
	uv build

repro: ## Verify a byte-identical rebuild of the wheel + sdist (builds twice, compares); writes dist/ on success
	uv run python scripts/check_reproducible_build.py --out-dir dist

relay-repro: ## Verify byte-identical no-cache relay OCI rebuilds
	bash scripts/check_reproducible_relay_image.sh

clean: ## Remove build/test artifacts
	rm -rf dist build .pytest_cache .mypy_cache .ruff_cache .coverage coverage.xml htmlcov
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
