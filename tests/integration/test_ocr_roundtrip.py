"""Integration tests for offline post-redaction OCR roundtrip."""

from __future__ import annotations

from pathlib import Path

import pymupdf
import pytest

from opsec_sanitizer.detection.merger import HybridPiiDetector
from opsec_sanitizer.detection.regex_mx import compute_curp_check_digit
from opsec_sanitizer.domain.models import PiiCategory
from opsec_sanitizer.processing.ocr_engine import RapidOcrEngine
from opsec_sanitizer.processing.pdf_flattener import FlattenOptions, flatten_pdf
from opsec_sanitizer.verification.forensic_gate import verify_pdf_forensically

_CURP_17 = "GOPA850714HDFLRN0"
_VALID_CURP = f"{_CURP_17}{compute_curp_check_digit(_CURP_17)}"


@pytest.mark.slow
class TestOcrRoundtrip:
    def test_flattened_pdf_with_ocr_keeps_public_text_searchable_and_eliminates_pii(
        self, tmp_path: Path
    ) -> None:
        src = tmp_path / "source.pdf"
        dst = tmp_path / "flattened_ocr.pdf"

        doc = pymupdf.open()
        page = doc.new_page(width=595, height=400)
        page.insert_text((72, 90), "CONTRATO PUBLICO DE INFRAESTRUCTURA", fontsize=18)
        page.insert_text((72, 160), f"Identificador: {_VALID_CURP}", fontsize=18)
        page.insert_text((72, 230), "Correo: secreto@fuente.mx", fontsize=18)
        doc.save(str(src))
        doc.close()

        detector = HybridPiiDetector()
        ocr = RapidOcrEngine()

        result = flatten_pdf(
            src,
            dst,
            detector=detector,
            ocr_engine=ocr,
            options=FlattenOptions(dpi=200, padding_px=6, enable_ocr=True),
        )

        assert result.pii_counts.get(PiiCategory.CURP, 0) == 1
        assert result.pii_counts.get(PiiCategory.EMAIL, 0) == 1
        report = verify_pdf_forensically(dst, detector=detector)
        assert report.passed is True

        out_doc = pymupdf.open(str(dst))
        try:
            extracted = out_doc[0].get_text("text")
        finally:
            out_doc.close()

        assert "CONTRATO" in extracted.upper()
        assert "INFRAESTRUCTURA" in extracted.upper()
        assert _VALID_CURP not in extracted
        assert "secreto@fuente.mx" not in extracted
