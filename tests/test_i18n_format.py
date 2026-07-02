# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Test CLDR pluralization, locale formatting, and ICU-MessageFormat rendering (FIX-12)."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import pytest

from habitable.i18n import (
    DEFAULT_LOCALE,
    SUPPORTED_LOCALES,
    cli_text,
    format_date,
    format_datetime,
    format_message,
    format_number,
    normalize_locale,
    plural_category,
    resolve_locale,
)


class TestNormalizeLocale:
    """Locale tag normalization."""

    def test_normalize_en(self) -> None:
        assert normalize_locale("en") == "en"

    def test_normalize_es(self) -> None:
        assert normalize_locale("es") == "es"

    def test_normalize_region_variant(self) -> None:
        """es-MX → es; en-US → en."""
        assert normalize_locale("es-MX") == "es"
        assert normalize_locale("en-US") == "en"
        assert normalize_locale("en_GB") == "en"

    def test_normalize_unsupported_fallback_to_default(self) -> None:
        """Unknown locale falls back to DEFAULT_LOCALE (en)."""
        assert normalize_locale("fr") == DEFAULT_LOCALE
        assert normalize_locale("de-DE") == DEFAULT_LOCALE
        assert normalize_locale("") == DEFAULT_LOCALE
        assert normalize_locale(None) == DEFAULT_LOCALE

    def test_normalize_whitespace(self) -> None:
        """Whitespace is stripped and case is normalized."""
        assert normalize_locale("  EN  ") == "en"
        assert normalize_locale("  ES  ") == "es"

    def test_normalize_underscore_converted_to_dash(self) -> None:
        """Underscores are converted to dashes."""
        assert normalize_locale("es_ES") == "es"


class TestResolveLocale:
    """Locale resolution from vault language and environment."""

    def test_resolve_from_vault_lang(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Vault language is used when HABITABLE_LANG is not set."""
        monkeypatch.delenv("HABITABLE_LANG", raising=False)
        assert resolve_locale("es") == "es"
        assert resolve_locale("en") == "en"

    def test_resolve_env_overrides_vault(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """HABITABLE_LANG environment variable overrides vault language."""
        monkeypatch.setenv("HABITABLE_LANG", "es")
        assert resolve_locale("en") == "es"

    def test_resolve_default_when_both_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """DEFAULT_LOCALE when neither vault nor env is set."""
        monkeypatch.delenv("HABITABLE_LANG", raising=False)
        assert resolve_locale(None) == DEFAULT_LOCALE


class TestPluralCategory:
    """CLDR cardinal plural rules for en and es."""

    @pytest.mark.parametrize(
        "n,category",
        [
            (1, "one"),
            (1.0, "other"),  # v=1 (decimal point present) → other
            (0, "other"),
            (2, "other"),
            (5, "other"),
            (100, "other"),
        ],
    )
    def test_en_plural_categories(self, n: float, category: str) -> None:
        """EN: one is i=1,v=0; other otherwise."""
        assert plural_category(n, "en") == category

    @pytest.mark.parametrize(
        "n,category",
        [
            (1, "one"),
            (0, "other"),
            (2, "other"),
            (5, "other"),
            (1_000_000, "many"),
            (2_000_000, "many"),
        ],
    )
    def test_es_plural_categories(self, n: int, category: str) -> None:
        """ES: one is n=1; many is n≠1 and i%1000000=0; other otherwise."""
        assert plural_category(n, "es") == category

    def test_plural_category_string_input(self) -> None:
        """Operands can be passed as strings."""
        assert plural_category("1", "en") == "one"
        assert plural_category("2", "en") == "other"

    def test_plural_category_decimal_input(self) -> None:
        """Operands can be Decimal."""
        assert plural_category(Decimal("1"), "en") == "one"
        assert plural_category(Decimal("2"), "en") == "other"

    def test_plural_category_unsupported_locale_defaults_to_en(self) -> None:
        """Unsupported locale uses en rules."""
        assert plural_category(1, "fr") == "one"
        assert plural_category(2, "fr") == "other"


class TestFormatNumber:
    """Locale-aware number formatting."""

    @pytest.mark.parametrize(
        "value,en_result,es_result",
        [
            (1, "1", "1"),
            (1234, "1,234", "1.234"),
            (1234.5, "1,234.5", "1.234,5"),
            (1000000, "1,000,000", "1.000.000"),
        ],
    )
    def test_format_number_en_es(
        self, value: float, en_result: str, es_result: str
    ) -> None:
        """EN uses comma for group separator; ES uses period."""
        assert format_number(value, "en") == en_result
        assert format_number(value, "es") == es_result

    def test_format_number_unsupported_locale_defaults_to_en(self) -> None:
        """Unsupported locale uses en formatting."""
        assert format_number(1234.5, "fr") == "1,234.5"


class TestFormatDate:
    """Locale-aware date formatting."""

    def test_format_date_en(self) -> None:
        """EN: MMM d, yyyy."""
        dt = datetime(2026, 1, 2, tzinfo=UTC)
        assert format_date(dt, "en") == "Jan 2, 2026"

    def test_format_date_es(self) -> None:
        """ES: d MMM yyyy."""
        dt = datetime(2026, 1, 2, tzinfo=UTC)
        assert format_date(dt, "es") == "2 ene 2026"

    def test_format_date_iso_string_input(self) -> None:
        """Date can be an ISO 8601 UTC string."""
        iso = "2026-01-02T03:04:05Z"
        assert format_date(iso, "en") == "Jan 2, 2026"
        assert format_date(iso, "es") == "2 ene 2026"

    def test_format_date_month_abbreviations(self) -> None:
        """All 12 months render correctly."""
        for month in range(1, 13):
            dt = datetime(2026, month, 1, tzinfo=UTC)
            en_str = format_date(dt, "en")
            es_str = format_date(dt, "es")
            assert len(en_str) > 0
            assert len(es_str) > 0
            assert "2026" in en_str and "2026" in es_str


class TestFormatDateTime:
    """Locale-aware date-time formatting."""

    def test_format_datetime_en(self) -> None:
        """EN: MMM d, yyyy, h:mm AM/PM UTC."""
        dt = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
        result = format_datetime(dt, "en")
        assert "Jan 2, 2026" in result
        assert "3:04 AM" in result
        assert "UTC" in result

    def test_format_datetime_es(self) -> None:
        """ES: d MMM yyyy, HH:mm UTC (24-hour)."""
        dt = datetime(2026, 1, 2, 15, 4, 5, tzinfo=UTC)
        result = format_datetime(dt, "es")
        assert "2 ene 2026" in result
        assert "15:04" in result
        assert "UTC" in result

    def test_format_datetime_iso_string_input(self) -> None:
        """DateTime can be an ISO 8601 UTC string."""
        iso = "2026-01-02T03:04:05Z"
        en_result = format_datetime(iso, "en")
        es_result = format_datetime(iso, "es")
        assert "Jan 2, 2026" in en_result
        assert "2 ene 2026" in es_result
        assert "UTC" in en_result and "UTC" in es_result

    def test_format_datetime_12_hour_cycle_en(self) -> None:
        """EN: noon and midnight display correctly."""
        noon = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        midnight = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
        assert "12:00 PM" in format_datetime(noon, "en")
        assert "12:00 AM" in format_datetime(midnight, "en")

    def test_format_datetime_24_hour_cycle_es(self) -> None:
        """ES: always 24-hour."""
        noon = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        midnight = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
        assert "12:00" in format_datetime(noon, "es")
        assert "0:00" in format_datetime(midnight, "es")


class TestFormatMessage:
    """ICU-MessageFormat subset: placeholders and plurals."""

    def test_simple_placeholder(self) -> None:
        """Simple {name} interpolation."""
        msg = "Hello {name}!"
        result = format_message(msg, "en", {"name": "world"})
        assert result == "Hello world!"

    def test_numeric_placeholder_formatted(self) -> None:
        """{count} is formatted with locale-aware separators."""
        msg = "You have {count} items."
        assert format_message(msg, "en", {"count": 1234}) == "You have 1,234 items."
        assert format_message(msg, "es", {"count": 1234}) == "You have 1.234 items."

    def test_missing_placeholder_shows_key(self) -> None:
        """Missing placeholder is left verbatim (degrades visibly)."""
        msg = "Hello {name}!"
        result = format_message(msg, "en", {})
        assert result == "Hello {name}!"

    def test_plural_en_one(self) -> None:
        """EN plural: n=1 triggers 'one' branch."""
        msg = "{count, plural, one {# item} other {# items}}"
        result = format_message(msg, "en", {"count": 1})
        assert result == "1 item"

    def test_plural_en_other(self) -> None:
        """EN plural: n≠1 triggers 'other' branch."""
        msg = "{count, plural, one {# item} other {# items}}"
        result = format_message(msg, "en", {"count": 2})
        assert result == "2 items"

    def test_plural_en_zero(self) -> None:
        """EN plural: 0 is 'other'."""
        msg = "{count, plural, one {# item} other {# items}}"
        result = format_message(msg, "en", {"count": 0})
        assert result == "0 items"

    def test_plural_es_one(self) -> None:
        """ES plural: n=1 triggers 'one' branch."""
        msg = "{count, plural, one {# elemento} other {# elementos}}"
        result = format_message(msg, "es", {"count": 1})
        assert result == "1 elemento"

    def test_plural_es_other(self) -> None:
        """ES plural: n≠1 triggers 'other' branch."""
        msg = "{count, plural, one {# elemento} other {# elementos}}"
        result = format_message(msg, "es", {"count": 2})
        assert result == "2 elementos"

    def test_plural_exact_match(self) -> None:
        """Exact =N selector overrides CLDR categories."""
        msg = "{count, plural, =0 {no items} one {# item} other {# items}}"
        assert format_message(msg, "en", {"count": 0}) == "no items"
        assert format_message(msg, "en", {"count": 1}) == "1 item"
        assert format_message(msg, "en", {"count": 2}) == "2 items"

    def test_plural_hash_substitution(self) -> None:
        """# is replaced with the formatted count."""
        msg = "{count, plural, one {You have # thing} other {You have # things}}"
        assert format_message(msg, "en", {"count": 1}) == "You have 1 thing"
        assert format_message(msg, "en", {"count": 5}) == "You have 5 things"

    def test_multiple_placeholders(self) -> None:
        """Multiple placeholders in one message."""
        msg = "{actor} has {count, plural, one {# item} other {# items}} in {location}."
        result = format_message(msg, "en", {"actor": "Alice", "count": 3, "location": "box"})
        assert result == "Alice has 3 items in box."

    def test_missing_plural_other_falls_back(self) -> None:
        """If the required category is missing, falls back to 'other'."""
        msg = "{count, plural, other {# items}}"
        result = format_message(msg, "en", {"count": 1})
        assert result == "1 items"  # 'one' not present, uses 'other'

    def test_nested_plurals(self) -> None:
        """Nested placeholders within plural branches."""
        msg = "{count, plural, one {# item from {actor}} other {# items from {actor}}}"
        result = format_message(msg, "en", {"count": 1, "actor": "Bob"})
        assert result == "1 item from Bob"


class TestCliText:
    """CLI message catalog with pluralization."""

    def test_cli_text_key_lookup(self) -> None:
        """Basic key lookup."""
        result = cli_text("custody_intact", "en")
        assert result == "intact"

    def test_cli_text_spanish_key_lookup(self) -> None:
        """Spanish key lookup."""
        result = cli_text("custody_intact", "es")
        assert result == "intacta"

    def test_cli_text_with_plural_en(self) -> None:
        """English plural in status_custody."""
        result = cli_text("status_custody", "en", verdict="intact", links=1)
        assert "1 entry" in result

    def test_cli_text_with_plural_en_multiple(self) -> None:
        """English plural with multiple links."""
        result = cli_text("status_custody", "en", verdict="intact", links=3)
        assert "3 entries" in result

    def test_cli_text_with_plural_es(self) -> None:
        """Spanish plural in status_custody."""
        result = cli_text("status_custody", "es", verdict="intacta", links=1)
        assert "entrada" in result

    def test_cli_text_status_summary(self) -> None:
        """Complex message with multiple plurals."""
        result = cli_text(
            "status_summary",
            "en",
            unit="4B",
            issues=1,
            captures=2,
            timeline=3,
        )
        assert "unit 4B" in result
        assert "1 issue" in result
        assert "2 captures" in result
        assert "3 timeline entries" in result

    def test_cli_text_fallback_to_en(self) -> None:
        """Unsupported locale falls back to English."""
        en_result = cli_text("custody_intact", "en")
        fr_result = cli_text("custody_intact", "fr")
        assert en_result == fr_result

    def test_all_cli_keys_exist_in_both_locales(self) -> None:
        """All catalog keys are present in en and es."""
        from habitable.i18n import _CLI_MESSAGES

        en_keys = set(_CLI_MESSAGES["en"].keys())
        es_keys = set(_CLI_MESSAGES["es"].keys())
        assert en_keys == es_keys, (
            f"Missing in es: {en_keys - es_keys}; "
            f"Extra in es: {es_keys - en_keys}"
        )


class TestMessageFormatEdgeCases:
    """Edge cases and error handling."""

    def test_unbalanced_open_brace(self) -> None:
        """Unbalanced { raises MessageFormatError."""
        from habitable.i18n import MessageFormatError

        msg = "You have {count items."
        with pytest.raises(MessageFormatError):
            format_message(msg, "en", {"count": 3})

    def test_unknown_argument_type(self) -> None:
        """Unsupported argument type (not 'plural') raises MessageFormatError."""
        from habitable.i18n import MessageFormatError

        msg = "{count, select, one {1} other {many}}"  # 'select' is not supported
        with pytest.raises(MessageFormatError):
            format_message(msg, "en", {"count": 1})

    def test_plural_missing_required_category_at_parity_gate(self) -> None:
        """Plural without 'other' branch is caught at the parity gate."""
        # This is enforced by scripts/check_i18n_parity.py, not the formatter.
        # The parity gate runs during the build and is tested separately.
        from habitable.i18n import MessageFormatError

        msg = "{count, plural, one {# item}}"  # missing 'other'
        with pytest.raises(MessageFormatError):
            format_message(msg, "en", {"count": 1})


class TestLocaleConsistency:
    """Verify en and es are properly wired."""

    def test_supported_locales_includes_en_es(self) -> None:
        """SUPPORTED_LOCALES must include en and es."""
        assert "en" in SUPPORTED_LOCALES
        assert "es" in SUPPORTED_LOCALES

    def test_format_date_works_for_all_supported_locales(self) -> None:
        """format_date works for every supported locale."""
        dt = datetime(2026, 1, 2, tzinfo=UTC)
        for locale in SUPPORTED_LOCALES:
            result = format_date(dt, locale)
            assert isinstance(result, str)
            assert len(result) > 0

    def test_plural_category_works_for_all_supported_locales(self) -> None:
        """plural_category works for every supported locale."""
        for locale in SUPPORTED_LOCALES:
            assert plural_category(1, locale) in {"one", "other"}
            assert plural_category(2, locale) in {"one", "other", "many"}
