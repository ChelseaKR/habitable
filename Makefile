# SPDX-License-Identifier: AGPL-3.0-or-later
# habitable — developer entry points. `make verify` reproduces the full CI gate.
.DEFAULT_GOAL := help
.PHONY: help install fmt lint type test cov verify audit a11y demo build clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

install: ## Create the env and install the project + dev tools (Python 3.14 via uv)
	uv sync
	uv run python -c "import sys; print('habitable env on Python', sys.version.split()[0])"

fmt: ## Auto-format and auto-fix
	uv run ruff format src tests
	uv run ruff check --fix src tests

lint: ## Lint (no changes)
	uv run ruff format --check src tests
	uv run ruff check src tests

type: ## Strict type-check
	uv run mypy

test: ## Run the test suite
	uv run pytest

cov: ## Run tests with coverage
	uv run pytest --cov=habitable --cov-report=term-missing --cov-report=xml

verify: lint type cov ## The full merge gate: lint + types + tests with coverage
	@echo "habitable: full gate green on Python $$(uv run python -c 'import sys;print(sys.version.split()[0])')"

audit: ## Dependency vulnerability audit
	uv run pip-audit

a11y: ## Accessibility gate: structural + i18n + PWA, then the axe-core browser scan
	uv run pytest tests/test_app_accessibility.py tests/test_app_i18n.py tests/test_app_pwa.py
	uv run pytest -m a11y
	@echo "Manual pass: keyboard + NVDA/VoiceOver + zoom per docs/accessibility/manual-testing.md."

demo: ## Walk a synthetic case from capture to a verified packet (no real data)
	uv run habitable demo

build: ## Build the wheel + sdist
	uv build

clean: ## Remove build/test artifacts
	rm -rf dist build .pytest_cache .mypy_cache .ruff_cache .coverage coverage.xml htmlcov
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
