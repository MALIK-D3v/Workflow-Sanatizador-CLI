"""Unit tests for fail-closed forensic verification gate."""

from __future__ import annotations

from pathlib import Path

import pymupdf
import pytest
from PIL import Image, PngImagePlugin

from opsec_sanitizer.detection.merger import HybridPiiDetector
from opsec_sanitizer.detection.regex_mx import compute_curp_check_digit
from opsec_sanitizer.domain.errors import ForensicLeakError
from opsec_sanitizer.verification.forensic_gate import (
    verify_image_forensically,
    verify_pdf_forensically,
)

_CURP_17 = "GOPA850714HDFLRN0"
_VALID_CURP = f"{_CURP_17}{compute_curp_check_digit(_CURP_17)}"


def _make_clean_pdf(path: Path, text: str = "") -> None:
    doc = pymupdf.open()
    page = doc.new_page()
    if text:
        page.insert_text((72, 72), text)
    doc.del_xml_metadata()
    doc.set_metadata(
        {
            "title": "",
            "author": "",
            "subject": "",
            "keywords": "",
            "creator": "",
            "producer": "",
            "creationDate": "D:19700101000000Z",
            "modDate": "D:19700101000000Z",
        }
    )
    doc.save(str(path), garbage=4, deflate=True, clean=True)
    doc.close()


class TestForensicPdfGate:
    def test_approves_clean_zero_metadata_pdf(self, tmp_path: Path) -> None:
        pdf = tmp_path / "clean.pdf"
        _make_clean_pdf(pdf, text="Informe publico sin datos personales")

        report = verify_pdf_forensically(pdf, detector=HybridPiiDetector())

        assert report.passed is True
        assert report.violations == ()

    def test_rejects_pdf_with_residual_author_metadata(self, tmp_path: Path) -> None:
        pdf = tmp_path / "meta.pdf"
        doc = pymupdf.open()
        doc.new_page()
        doc.set_metadata({"author": "Informante"})
        doc.save(str(pdf))
        doc.close()

        with pytest.raises(ForensicLeakError, match="metadata"):
            verify_pdf_forensically(pdf, detector=HybridPiiDetector())

    def test_rejects_pdf_with_embedded_attachment(self, tmp_path: Path) -> None:
        pdf = tmp_path / "attach.pdf"
        doc = pymupdf.open()
        doc.new_page()
        doc.embfile_add("hidden.txt", b"secret")
        doc.set_metadata({"producer": "", "creator": "", "creationDate": "D:19700101000000Z"})
        doc.save(str(pdf))
        doc.close()

        with pytest.raises(ForensicLeakError, match="embedded"):
            verify_pdf_forensically(pdf, detector=HybridPiiDetector())

    def test_rejects_pdf_with_residual_pii_in_text_layer_without_leaking_value(
        self, tmp_path: Path
    ) -> None:
        pdf = tmp_path / "pii_leak.pdf"
        _make_clean_pdf(pdf, text=f"CURP filtrada: {_VALID_CURP}")

        with pytest.raises(ForensicLeakError) as exc_info:
            verify_pdf_forensically(pdf, detector=HybridPiiDetector())

        # Exception message MUST NOT leak the raw CURP value!
        assert _VALID_CURP not in str(exc_info.value)
        assert "CURP" in str(exc_info.value)

    def test_rejects_pdf_with_deny_list_term_remaining(self, tmp_path: Path) -> None:
        pdf = tmp_path / "deny.pdf"
        _make_clean_pdf(pdf, text="Mencion a Operacion Quetzal en pagina 1")
        detector = HybridPiiDetector(deny_list=frozenset({"Operacion Quetzal"}))

        with pytest.raises(ForensicLeakError) as exc_info:
            verify_pdf_forensically(pdf, detector=detector)

        assert "Operacion Quetzal" not in str(exc_info.value)


class TestForensicImageGate:
    def test_approves_clean_png_and_rejects_dirty_png(self, tmp_path: Path) -> None:
        clean = tmp_path / "clean.png"
        Image.new("RGB", (32, 32), (255, 255, 255)).save(clean, format="PNG")
        assert verify_image_forensically(clean).passed is True

        dirty = tmp_path / "dirty.png"
        meta = PngImagePlugin.PngInfo()
        meta.add_text("Author", "Fuente")
        Image.new("RGB", (32, 32), (255, 255, 255)).save(dirty, format="PNG", pnginfo=meta)

        with pytest.raises(ForensicLeakError):
            verify_image_forensically(dirty)
