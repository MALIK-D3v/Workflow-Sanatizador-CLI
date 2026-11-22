"""Unit and integration tests for extended PII detectors: CLABE, NSS, INE, and IP addresses."""

from __future__ import annotations

from pathlib import Path

import pymupdf

from opsec_sanitizer.detection.merger import HybridPiiDetector
from opsec_sanitizer.detection.regex_mx import (
    compute_clabe_check_digit,
    compute_nss_check_digit,
    detect_regex_pii,
    is_valid_clabe,
    is_valid_ine_clave,
    is_valid_nss,
)
from opsec_sanitizer.domain.models import PiiCategory
from opsec_sanitizer.processing.pdf_flattener import FlattenOptions, flatten_pdf
from opsec_sanitizer.verification.forensic_gate import verify_pdf_forensically

_SYNTHETIC_CLABE_17 = "00218001600328941"
_SYNTHETIC_NSS_10 = "1285671234"
_SYNTHETIC_INE_CLAVE = "GMPRLN85071409H100"


def _valid_clabe() -> str:
    return f"{_SYNTHETIC_CLABE_17}{compute_clabe_check_digit(_SYNTHETIC_CLABE_17)}"


def _valid_nss() -> str:
    return f"{_SYNTHETIC_NSS_10}{compute_nss_check_digit(_SYNTHETIC_NSS_10)}"


class TestClabeDetector:
    def test_validates_clabe_check_digit_and_rejects_bad_digit(self) -> None:
        clabe = _valid_clabe()
        assert len(clabe) == 18
        assert is_valid_clabe(clabe) is True

        bad_digit = (int(clabe[-1]) + 1) % 10
        assert is_valid_clabe(f"{_SYNTHETIC_CLABE_17}{bad_digit}") is False
        assert is_valid_clabe("12345") is False

    def test_detects_clabe_in_prose_and_ignores_invalid_18_digit_numbers(self) -> None:
        clabe = _valid_clabe()
        bad_digit = (int(clabe[-1]) + 1) % 10
        bad_num = f"{_SYNTHETIC_CLABE_17}{bad_digit}"
        text = f"Cuenta CLABE {clabe} y folio interno {bad_num}."

        spans = detect_regex_pii(text)

        clabes = [text[s.start : s.end] for s in spans if s.category == PiiCategory.CLABE]
        assert clabes == [clabe]


class TestNssDetector:
    def test_validates_imss_luhn_check_digit_and_rejects_bad_digit(self) -> None:
        nss = _valid_nss()
        assert len(nss) == 11
        assert is_valid_nss(nss) is True

        bad_digit = (int(nss[-1]) + 1) % 10
        assert is_valid_nss(f"{_SYNTHETIC_NSS_10}{bad_digit}") is False

    def test_detects_labeled_and_hyphenated_nss_without_false_positives(self) -> None:
        nss = _valid_nss()
        hyphenated = f"{nss[0:2]}-{nss[2:4]}-{nss[4:6]}-{nss[6:10]}-{nss[10]}"
        text = (
            f"Afiliación NSS: {nss} o en formato {hyphenated}. "
            f"Folio genérico sin etiqueta: {nss}."
        )

        spans = detect_regex_pii(text)

        nss_vals = [text[s.start : s.end] for s in spans if s.category == PiiCategory.NSS]
        assert nss_vals == [nss, hyphenated]


class TestIneDetector:
    def test_validates_clave_de_elector_date_and_state(self) -> None:
        assert is_valid_ine_clave(_SYNTHETIC_INE_CLAVE) is True
        assert is_valid_ine_clave("GMPRLN85023009H100") is False  # Feb 30 invalid
        assert is_valid_ine_clave("GMPRLN85071499H100") is False  # State 99 invalid
        assert is_valid_ine_clave("AEIOUU85071409H100") is False  # Vowels not consonants

    def test_detects_clave_de_elector_and_idmex_in_prose(self) -> None:
        text = f"Credencial INE {_SYNTHETIC_INE_CLAVE} y OCR IDMEX1847291045."

        spans = detect_regex_pii(text)

        ine_vals = [text[s.start : s.end] for s in spans if s.category == PiiCategory.INE]
        assert ine_vals == [_SYNTHETIC_INE_CLAVE, "IDMEX1847291045"]


class TestIpAddressDetector:
    def test_detects_valid_ipv4_and_ipv6_ignoring_versions_and_timestamps(self) -> None:
        text = (
            "Acceso desde 187.141.22.10 y 2001:db8::8a2e:370:7334 a las 14:35:09. "
            "Software v2.4.1.0 o inválido 999.1.2.3."
        )

        spans = detect_regex_pii(text)

        ips = [text[s.start : s.end] for s in spans if s.category == PiiCategory.IP_ADDRESS]
        assert ips == ["187.141.22.10", "2001:db8::8a2e:370:7334"]


class TestExtendedPiiPdfFlattening:
    def test_flattens_and_redacts_clabe_nss_ine_and_ip_in_pdf(self, tmp_path: Path) -> None:
        src = tmp_path / "financial_leak.pdf"
        dst = tmp_path / "clean_financial.pdf"
        clabe = _valid_clabe()
        nss = _valid_nss()

        doc = pymupdf.open()
        page = doc.new_page(width=595, height=400)
        page.insert_text((60, 70), "AUDITORIA FINANCIERA PUBLICA", fontsize=14)
        page.insert_text((60, 120), f"CLABE: {clabe}", fontsize=13)
        page.insert_text((60, 160), f"NSS: {nss}", fontsize=13)
        page.insert_text((60, 200), f"Clave INE: {_SYNTHETIC_INE_CLAVE}", fontsize=13)
        page.insert_text((60, 240), "Servidor origen: 187.141.22.10", fontsize=13)
        doc.save(str(src))
        doc.close()

        detector = HybridPiiDetector()
        result = flatten_pdf(
            src,
            dst,
            detector=detector,
            options=FlattenOptions(dpi=150, enable_ocr=False),
        )

        assert result.pii_counts.get(PiiCategory.CLABE, 0) == 1
        assert result.pii_counts.get(PiiCategory.NSS, 0) == 1
        assert result.pii_counts.get(PiiCategory.INE, 0) == 1
        assert result.pii_counts.get(PiiCategory.IP_ADDRESS, 0) == 1
        assert verify_pdf_forensically(dst, detector=detector).passed is True

        raw = dst.read_bytes()
        for secret in (
            clabe.encode(),
            nss.encode(),
            _SYNTHETIC_INE_CLAVE.encode(),
            b"187.141.22.10",
        ):
            assert secret not in raw
