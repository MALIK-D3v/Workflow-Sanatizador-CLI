"""Integration tests for DOCX structural sanitization and flattened PDF conversion."""

from __future__ import annotations

import shutil
import zipfile
from pathlib import Path

import pymupdf
import pytest

from opsec_sanitizer.detection.merger import HybridPiiDetector
from opsec_sanitizer.processing.docx_sanitizer import (
    LibreOfficeDocxRenderer,
    PurePythonDocxRenderer,
    sanitize_docx_to_pdf,
    strip_docx_metadata_and_revisions,
)
from opsec_sanitizer.processing.pdf_flattener import FlattenOptions
from opsec_sanitizer.verification.forensic_gate import verify_pdf_forensically

_W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def _create_trapped_docx(path: Path) -> None:
    """Create a synthetic DOCX with author metadata, comments, w:del, w:vanish, and RFC."""
    content_types = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '<Override PartName="/docProps/core.xml" '
        'ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
        "</Types>"
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/>'
        '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" '
        'Target="docProps/core.xml"/>'
        "</Relationships>"
    )
    core_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/">'
        "<dc:creator>InformanteCorp</dc:creator>"
        "<cp:lastModifiedBy>EditorSecreto</cp:lastModifiedBy>"
        "<dc:title>Borrador Confidencial</dc:title>"
        "</cp:coreProperties>"
    )
    comments_xml = (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<w:comments xmlns:w="{_W_NS}">'
        '<w:comment w:id="0" w:author="JefeRedaccion">'
        "<w:p><w:r><w:t>NO_PUBLICAR_COMENTARIO</w:t></w:r></w:p>"
        "</w:comment></w:comments>"
    )
    document_xml = (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<w:document xmlns:w="{_W_NS}">'
        "<w:body>"
        '<w:p w:rsidR="00AB1234">'
        "<w:r><w:t>Informe publico aprobado. </w:t></w:r>"
        '<w:ins w:id="1" w:author="InformanteCorp" w:date="2026-01-10T10:00:00Z">'
        "<w:r><w:t>Clausula aceptada.</w:t></w:r>"
        "</w:ins>"
        '<w:del w:id="2" w:author="InformanteCorp" w:date="2026-01-10T10:05:00Z">'
        "<w:r><w:delText>TEXTO_BORRADO_REVISION</w:delText></w:r>"
        "</w:del>"
        "<w:r><w:rPr><w:vanish/></w:rPr><w:t>TEXTO_OCULTO_VANISH</w:t></w:r>"
        "</w:p>"
        "<w:p><w:r><w:t>Proveedor RFC ABC9912319Z0</w:t></w:r></w:p>"
        "</w:body></w:document>"
    )

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("docProps/core.xml", core_xml)
        zf.writestr("word/comments.xml", comments_xml)
        zf.writestr("word/document.xml", document_xml)


class TestDocxStructuralCleaning:
    def test_strips_core_props_comments_deletions_vanish_and_rsids(self, tmp_path: Path) -> None:
        src = tmp_path / "trapped.docx"
        cleaned = tmp_path / "cleaned.docx"
        _create_trapped_docx(src)

        summary = strip_docx_metadata_and_revisions(src, cleaned)

        assert summary.revisions_removed >= 1
        assert summary.hidden_runs_removed >= 1
        assert "word/comments.xml" in summary.parts_removed

        with zipfile.ZipFile(cleaned, "r") as zf:
            names = set(zf.namelist())
            assert "word/comments.xml" not in names
            all_xml = b"".join(zf.read(n) for n in names)

        for forbidden in (
            b"InformanteCorp",
            b"EditorSecreto",
            b"Borrador Confidencial",
            b"NO_PUBLICAR_COMENTARIO",
            b"TEXTO_BORRADO_REVISION",
            b"TEXTO_OCULTO_VANISH",
            b"00AB1234",
        ):
            assert forbidden not in all_xml
        assert b"Clausula aceptada." in all_xml


class TestSanitizeDocxToPdf:
    def test_full_docx_to_flattened_pdf_with_pure_python_renderer(self, tmp_path: Path) -> None:
        src = tmp_path / "trapped.docx"
        dst = tmp_path / "sanitized.pdf"
        _create_trapped_docx(src)

        detector = HybridPiiDetector()
        result = sanitize_docx_to_pdf(
            src,
            dst,
            detector=detector,
            renderer=PurePythonDocxRenderer(),
            options=FlattenOptions(dpi=150, enable_ocr=False),
        )

        assert dst.exists()
        assert result.page_count >= 1
        assert sum(result.pii_counts.values()) >= 1
        assert verify_pdf_forensically(dst, detector=detector).passed is True

        raw = dst.read_bytes()
        for forbidden in (
            b"InformanteCorp",
            b"NO_PUBLICAR_COMENTARIO",
            b"TEXTO_BORRADO_REVISION",
            b"TEXTO_OCULTO_VANISH",
            b"ABC9912319Z0",
        ):
            assert forbidden not in raw

    @pytest.mark.slow
    @pytest.mark.skipif(shutil.which("soffice") is None, reason="LibreOffice not installed")
    def test_full_docx_to_flattened_pdf_with_libreoffice_renderer(self, tmp_path: Path) -> None:
        src = tmp_path / "trapped.docx"
        dst = tmp_path / "sanitized_lo.pdf"
        _create_trapped_docx(src)

        detector = HybridPiiDetector()
        result = sanitize_docx_to_pdf(
            src,
            dst,
            detector=detector,
            renderer=LibreOfficeDocxRenderer(),
            options=FlattenOptions(dpi=150, enable_ocr=False),
        )

        assert dst.exists()
        assert result.page_count >= 1
        assert verify_pdf_forensically(dst, detector=detector).passed is True
        out_doc = pymupdf.open(str(dst))
        try:
            assert out_doc.page_count >= 1
        finally:
            out_doc.close()
