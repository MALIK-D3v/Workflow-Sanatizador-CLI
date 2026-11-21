"""Unit tests for deterministic Mexican PII regex & structural validators."""

from __future__ import annotations

import pytest

from opsec_sanitizer.detection.regex_mx import (
    compute_curp_check_digit,
    detect_regex_pii,
    is_valid_curp,
    is_valid_rfc,
)
from opsec_sanitizer.domain.models import PiiCategory

# 100% synthetic CURP prefix (17 chars): G O P A 85 07 14 H DF L R N 0
_SYNTHETIC_CURP_17 = "GOPA850714HDFLRN0"


def _synthetic_valid_curp() -> str:
    return f"{_SYNTHETIC_CURP_17}{compute_curp_check_digit(_SYNTHETIC_CURP_17)}"


class TestCurpValidation:
    def test_validates_synthetic_curp_with_correct_check_digit(self) -> None:
        curp = _synthetic_valid_curp()
        assert len(curp) == 18
        assert is_valid_curp(curp) is True

    def test_rejects_curp_with_wrong_check_digit(self) -> None:
        good_digit = int(compute_curp_check_digit(_SYNTHETIC_CURP_17))
        bad_digit = (good_digit + 1) % 10
        assert is_valid_curp(f"{_SYNTHETIC_CURP_17}{bad_digit}") is False

    def test_rejects_curp_with_impossible_calendar_date(self) -> None:
        # Feb 30 is invalid
        bad_date_17 = "GOPA850230HDFLRN0"
        assert is_valid_curp(f"{bad_date_17}0") is False

    def test_rejects_curp_with_invalid_state_code(self) -> None:
        bad_state_17 = "GOPA850714HZZLRN0"
        assert is_valid_curp(f"{bad_state_17}0") is False


class TestRfcValidation:
    @pytest.mark.parametrize(
        "rfc",
        [
            "GOPA850714AB3",  # Persona física (13 chars)
            "ABC9912319Z0",  # Persona moral (12 chars)
            "XAXX010101000",  # RFC genérico público
        ],
    )
    def test_accepts_valid_rfc_formats(self, rfc: str) -> None:
        assert is_valid_rfc(rfc) is True

    @pytest.mark.parametrize(
        "bad_rfc",
        [
            "GOPA850230AB3",  # Feb 30 invalid date
            "GOPA851301AB3",  # Month 13 invalid
            "SHORT123",
            "GOPA850714ABZ",  # Last char must be 0-9 or A
        ],
    )
    def test_rejects_invalid_rfc(self, bad_rfc: str) -> None:
        assert is_valid_rfc(bad_rfc) is False


class TestDetectRegexPii:
    def test_detects_curp_without_overlapping_rfc_match(self) -> None:
        curp = _synthetic_valid_curp()
        text = f"El servidor público con CURP {curp} firmó el oficio."

        spans = detect_regex_pii(text)

        assert len(spans) == 1
        assert spans[0].category == PiiCategory.CURP
        assert text[spans[0].start : spans[0].end] == curp

    def test_detects_rfc_fisica_and_moral(self) -> None:
        text = "Proveedor RFC ABC9912319Z0 y representante GOPA850714AB3."

        spans = detect_regex_pii(text)

        categories = [s.category for s in spans]
        values = [text[s.start : s.end] for s in spans]
        assert categories == [PiiCategory.RFC, PiiCategory.RFC]
        assert values == ["ABC9912319Z0", "GOPA850714AB3"]

    def test_detects_emails_and_ignores_urls(self) -> None:
        text = "Contacto: fuente.segura+leak@redaccion.org.mx o ver https://gob.mx/transparencia"

        spans = detect_regex_pii(text)

        assert len(spans) == 1
        assert spans[0].category == PiiCategory.EMAIL
        assert text[spans[0].start : spans[0].end] == "fuente.segura+leak@redaccion.org.mx"

    def test_detects_mexican_phone_numbers_without_matching_expedientes(self) -> None:
        text = (
            "Llamar al +52 55 1234 5678 o al (33) 9876-5432. "
            "Expediente 202400012345678 fecha 2024-11-21."
        )

        spans = detect_regex_pii(text)

        phones = [text[s.start : s.end] for s in spans if s.category == PiiCategory.PHONE]
        assert phones == ["+52 55 1234 5678", "(33) 9876-5432"]

    def test_returns_empty_tuple_for_clean_text(self) -> None:
        assert detect_regex_pii("Oficio público sin datos personales.") == ()
