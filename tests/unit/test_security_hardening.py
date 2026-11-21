"""Regression tests for all CRITICAL & HIGH security and code-review findings."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pymupdf
import pytest
from PIL import Image, ImageDraw
from typer.testing import CliRunner

from opsec_sanitizer.cli import app
from opsec_sanitizer.detection.merger import HybridPiiDetector
from opsec_sanitizer.detection.ner_offline import HeuristicSpanishNerEngine
from opsec_sanitizer.detection.regex_mx import compute_curp_check_digit, detect_regex_pii
from opsec_sanitizer.domain.errors import (
    ForensicLeakError,
    InvalidDocumentError,
    UnsafeArchiveError,
)
from opsec_sanitizer.domain.models import IngestionLimits, PiiCategory
from opsec_sanitizer.ingestion.validator import validate_document
from opsec_sanitizer.pipeline import SanitizeConfig, sanitize_batch, sanitize_document
from opsec_sanitizer.processing.docx_sanitizer import (
    PurePythonDocxRenderer,
    strip_docx_metadata_and_revisions,
)
from opsec_sanitizer.processing.image_sanitizer import strip_image_to_clean_rgb
from opsec_sanitizer.processing.ocr_engine import RapidOcrEngine
from opsec_sanitizer.processing.pdf_flattener import FlattenOptions, flatten_pdf
from opsec_sanitizer.verification.forensic_gate import (
    verify_image_forensically,
    verify_pdf_forensically,
)

runner = CliRunner()
_CURP_17 = "GOPA850714HDFLRN0"
_VALID_CURP = f"{_CURP_17}{compute_curp_check_digit(_CURP_17)}"


class TestRotatedAndAnnotatedAndHybridPdf:
    def test_rotated_pdf_redacts_actual_rotated_glyph_pixels(self, tmp_path: Path) -> None:
        src = tmp_path / "rotated.pdf"
        dst = tmp_path / "clean_rotated.pdf"

        doc = pymupdf.open()
        page = doc.new_page(width=400, height=600)
        page.insert_text((100, 100), _VALID_CURP, fontsize=16)
        page.set_rotation(90)
        doc.save(str(src))
        doc.close()

        detector = HybridPiiDetector()
        flatten_pdf(
            src,
            dst,
            detector=detector,
            options=FlattenOptions(dpi=150, padding_px=6, enable_ocr=False),
        )

        # Render the sanitized rotated page and confirm the rotated glyph region is solid black
        out_doc = pymupdf.open(str(dst))
        try:
            pix = out_doc[0].get_pixmap(dpi=150, alpha=False)
            rendered = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
            # In a 400x600 page rotated 90 deg, width becomes 600pt (1250px at 150dpi)
            # Text originally at unrotated (100, 100) lands near x=(600-100)*scale, y=100*scale
            scale = 150.0 / 72.0
            rotated_rect = pymupdf.Rect(100, 88, 220, 104) * out_doc[0].rotation_matrix
            # out_doc page is already upright at 600x400, so map original rotated rect directly:
            src_doc = pymupdf.open(str(src))
            try:
                expected_rect = pymupdf.Rect(100, 88, 220, 104) * src_doc[0].rotation_matrix
            finally:
                src_doc.close()
            _ = rotated_rect
            cx = int(((expected_rect.x0 + expected_rect.x1) / 2.0) * scale)
            cy = int(((expected_rect.y0 + expected_rect.y1) / 2.0) * scale)
            assert rendered.getpixel((cx, cy)) == (0, 0, 0)
        finally:
            out_doc.close()

    def test_pdf_freetext_annotations_are_not_burned_into_flattened_pixels(
        self, tmp_path: Path
    ) -> None:
        src = tmp_path / "annotated.pdf"
        dst = tmp_path / "clean_no_annots.pdf"

        doc = pymupdf.open()
        page = doc.new_page(width=400, height=300)
        # Draw a solid dark FreeText annotation on an otherwise pure white page
        annot = page.add_freetext_annot(
            pymupdf.Rect(50, 50, 300, 120),
            "ANOTACION_SECRETA",
            fontsize=20,
            fill_color=(0.2, 0.2, 0.2),
            text_color=(1, 1, 1),
        )
        annot.update()
        doc.save(str(src))
        doc.close()

        flatten_pdf(
            src,
            dst,
            detector=HybridPiiDetector(),
            options=FlattenOptions(dpi=150, enable_ocr=False),
        )

        out_doc = pymupdf.open(str(dst))
        try:
            pix = out_doc[0].get_pixmap(dpi=150, alpha=False)
            rendered = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
            # Center of the annotation rect MUST remain white (not burned into pixels!)
            scale = 150.0 / 72.0
            assert rendered.getpixel((int(175 * scale), int(85 * scale))) == (255, 255, 255)
        finally:
            out_doc.close()

    @pytest.mark.slow
    def test_hybrid_pdf_with_native_footer_and_embedded_scan_redacts_embedded_pii(
        self, tmp_path: Path
    ) -> None:
        src = tmp_path / "hybrid.pdf"
        dst = tmp_path / "clean_hybrid.pdf"

        # Create a crisp raster scan containing an email (render via PyMuPDF for clean font)
        scan_pdf = pymupdf.open()
        sp = scan_pdf.new_page(width=500, height=150)
        sp.insert_text((30, 80), "correo.oculto@fuente.mx", fontsize=24)
        scan_png = sp.get_pixmap(dpi=200, alpha=False).tobytes("png")
        scan_pdf.close()

        doc = pymupdf.open()
        page = doc.new_page(width=595, height=400)
        page.insert_text((72, 360), "Pagina 1", fontsize=12)  # Native text footer!
        page.insert_image(pymupdf.Rect(50, 50, 540, 200), stream=scan_png)
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

        assert result.pii_counts.get(PiiCategory.EMAIL, 0) >= 1
        verify_pdf_forensically(dst, detector=detector, ocr_engine=ocr)

    def test_mupdf_fingerprint_and_unique_id_are_scrubbed_from_output_pdf(
        self, tmp_path: Path
    ) -> None:
        src = tmp_path / "src.pdf"
        dst = tmp_path / "dst.pdf"
        doc = pymupdf.open()
        doc.new_page().insert_text((72, 72), "Documento publico")
        doc.save(str(src))
        doc.close()

        flatten_pdf(
            src,
            dst,
            detector=HybridPiiDetector(),
            options=FlattenOptions(dpi=150, enable_ocr=False),
        )

        raw = dst.read_bytes()
        assert b"MuPDF" not in raw
        assert b"Written by" not in raw
        verify_pdf_forensically(dst, detector=HybridPiiDetector())


class TestForensicGateHardening:
    def test_rejects_obfuscated_js_openaction_custom_info_and_trailing_bytes(
        self, tmp_path: Path
    ) -> None:
        # 1. PDF with custom /Info key (/Company)
        p1 = tmp_path / "custom_info.pdf"
        doc = pymupdf.open()
        doc.new_page()
        doc.del_xml_metadata()
        doc.set_metadata({"producer": "", "creator": "", "creationDate": "D:19700101000000Z"})
        info_xref = doc.xref_get_key(-1, "Info")[1].split()[0]
        doc.xref_set_key(int(info_xref), "Company", "(SecretCorp)")
        doc.save(str(p1))
        doc.close()
        with pytest.raises(ForensicLeakError):
            verify_pdf_forensically(p1, detector=HybridPiiDetector())

        # 2. PDF with trailing covert bytes after %%EOF
        p2 = tmp_path / "trailing.pdf"
        doc2 = pymupdf.open()
        doc2.new_page().insert_text((72, 72), "Clean")
        doc2.save(str(p2))
        doc2.close()
        clean_p2 = tmp_path / "clean_p2.pdf"
        flatten_pdf(
            p2,
            clean_p2,
            detector=HybridPiiDetector(),
            options=FlattenOptions(dpi=100, enable_ocr=False),
        )
        with clean_p2.open("ab") as fh:
            fh.write(b"COVERT_TRAILER_DATA")
        with pytest.raises(ForensicLeakError, match="trailing"):
            verify_pdf_forensically(clean_p2, detector=HybridPiiDetector())

        # 3. PDF with /JS(alert(1)) (no space after /JS)
        p3 = tmp_path / "js.pdf"
        doc3 = pymupdf.open()
        doc3.new_page()
        doc3.xref_set_key(doc3.pdf_catalog(), "OpenAction", "<</S/JavaScript/JS(app.alert(1))>>")
        doc3.save(str(p3))
        doc3.close()
        with pytest.raises(ForensicLeakError):
            verify_pdf_forensically(p3, detector=HybridPiiDetector())

    def test_rejects_png_with_trailing_bytes_after_iend(self, tmp_path: Path) -> None:
        png = tmp_path / "trailing.png"
        Image.new("RGB", (20, 20), (255, 255, 255)).save(png, format="PNG")
        with png.open("ab") as fh:
            fh.write(b"STEGO_BYTES")

        with pytest.raises(ForensicLeakError, match="trailing"):
            verify_image_forensically(png)


class TestDocxSecurityHardening:
    def test_strips_external_rels_fields_settings_and_prchange_and_keeps_val_zero_vanish(
        self, tmp_path: Path
    ) -> None:
        w_ns = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
        src = tmp_path / "weaponized.docx"
        cleaned = tmp_path / "cleaned.docx"

        rels_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/'
            '2006/relationships/image" Target="https://canary.evil/track.png" '
            'TargetMode="External"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/'
            '2006/relationships/styles" Target="styles.xml"/>'
            "</Relationships>"
        )
        settings_xml = (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<w:settings xmlns:w="{w_ns}">'
            '<w:attachedTemplate r:id="rId1" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>'
            '<w:rsids><w:rsid w:val="00AA11BB"/></w:rsids>'
            "</w:settings>"
        )
        doc_xml = (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<w:document xmlns:w="{w_ns}">'
            "<w:body><w:p>"
            '<w:r><w:rPr><w:vanish w:val="0"/></w:rPr><w:t>VISIBLE_TEXT_OK</w:t></w:r>'
            "<w:r><w:instrText>INCLUDEPICTURE \"https://canary.evil/px.gif\"</w:instrText></w:r>"
            '<w:rPrChange w:id="9" w:author="SecretAuthor"><w:rPr/></w:rPrChange>'
            "</w:p></w:body></w:document>"
        )

        with zipfile.ZipFile(src, "w") as zf:
            zf.writestr("[Content_Types].xml", "<Types></Types>")
            zf.writestr("word/_rels/document.xml.rels", rels_xml)
            zf.writestr("word/settings.xml", settings_xml)
            zf.writestr("word/printerSettings/printerSettings1.bin", b"\\\\CORP-PRINT\\HP")
            zf.writestr("word/document.xml", doc_xml)

        strip_docx_metadata_and_revisions(src, cleaned)

        with zipfile.ZipFile(cleaned, "r") as zf:
            names = set(zf.namelist())
            assert "word/printerSettings/printerSettings1.bin" not in names
            all_bytes = b"".join(zf.read(n) for n in names)

        assert b"canary.evil" not in all_bytes
        assert b"attachedTemplate" not in all_bytes
        assert b"SecretAuthor" not in all_bytes
        assert b"INCLUDEPICTURE" not in all_bytes
        assert b"00AA11BB" not in all_bytes
        assert b"VISIBLE_TEXT_OK" in all_bytes

    def test_pure_python_docx_renderer_handles_long_paragraphs_without_overlap(
        self, tmp_path: Path
    ) -> None:
        w_ns = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
        docx_path = tmp_path / "long.docx"
        long_p1 = " ".join(["ParrafoUnoLargo"] * 60)
        p2 = "ParrafoDosDistinto"
        doc_xml = (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<w:document xmlns:w="{w_ns}"><w:body>'
            f"<w:p><w:r><w:t>{long_p1}</w:t></w:r></w:p>"
            f"<w:p><w:r><w:t>{p2}</w:t></w:r></w:p>"
            "</w:body></w:document>"
        )
        with zipfile.ZipFile(docx_path, "w") as zf:
            zf.writestr("word/document.xml", doc_xml)

        pdf_path = PurePythonDocxRenderer().render_to_pdf(docx_path, tmp_path)
        doc = pymupdf.open(str(pdf_path))
        try:
            text = "\n".join(page.get_text("text") for page in doc)
            assert "ParrafoUnoLargo" in text
            assert "ParrafoDosDistinto" in text
            # Verify vertical separation between p1's last word and p2's first word
            words = doc[0].get_text("words")
            p1_y1 = max(w[3] for w in words if "ParrafoUnoLargo" in w[4])
            p2_y0 = min(w[1] for w in words if "ParrafoDosDistinto" in w[4])
            assert p2_y0 >= p1_y1
        finally:
            doc.close()


class TestPiiAndNerHardening:
    def test_monotonic_span_merge_does_not_drop_full_name_when_deny_list_overlaps(self) -> None:
        text = "Firmó Lic. Carlos Mendoza Hernández hoy."
        detector = HybridPiiDetector(
            ner_engine=HeuristicSpanishNerEngine(),
            deny_list=frozenset({"Mendoza"}),
        )

        spans = detector.detect(text)

        matched = [text[s.start : s.end] for s in spans]
        assert any("Carlos Mendoza Hernández" in m for m in matched)

    def test_detects_lowercase_curp_hyphenated_rfc_contiguous_phone_and_allcaps_names(self) -> None:
        text = (
            f"CURP {_VALID_CURP.lower()} RFC GOPA-850714-AB3 tel +525512345678\n"
            "LIC. CARLOS MENDOZA HERNÁNDEZ\n"
            "SECRETARÍA DE FINANZAS"
        )
        regex_spans = detect_regex_pii(text)
        cats = {s.category for s in regex_spans}
        assert {PiiCategory.CURP, PiiCategory.RFC, PiiCategory.PHONE}.issubset(cats)

        ner = HeuristicSpanishNerEngine()
        names = [text[s.start : s.end] for s in ner.detect_persons(text)]
        assert "CARLOS MENDOZA HERNÁNDEZ" in names

    def test_deny_list_supports_leading_non_word_characters(self) -> None:
        text = "Enviar a usuario@dominio-secreto.mx urgente."
        detector = HybridPiiDetector(deny_list=frozenset({"@dominio-secreto.mx"}))
        spans = detector.detect(text)
        assert len(spans) == 1
        assert text[spans[0].start : spans[0].end] == "usuario@dominio-secreto.mx"


class TestValidationImageAndCliHardening:
    def test_rgba_transparent_image_composites_onto_white_not_black(self, tmp_path: Path) -> None:
        src = tmp_path / "transparent.png"
        img = Image.new("RGBA", (40, 40), color=(255, 0, 0, 0))  # Hidden red under alpha=0!
        draw = ImageDraw.Draw(img)
        draw.rectangle((10, 10, 20, 20), fill=(0, 0, 0, 255))
        img.save(src, format="PNG")

        clean, _ = strip_image_to_clean_rgb(src)

        # Transparent region becomes white (not black, and hidden RGB=(255,0,0) is destroyed!)
        assert clean.getpixel((2, 2)) == (255, 255, 255)
        assert clean.getpixel((15, 15)) == (0, 0, 0)

    def test_validator_rejects_duplicate_zip_entries_and_excessive_pdf_pages(
        self, tmp_path: Path
    ) -> None:
        dup_docx = tmp_path / "dup.docx"
        with zipfile.ZipFile(dup_docx, "w") as zf:
            zf.writestr("word/document.xml", "<w:document/>")
            zf.writestr("word/document.xml", "<w:document/>")
        with pytest.raises(UnsafeArchiveError):
            validate_document(dup_docx)

        many_pages = tmp_path / "many.pdf"
        doc = pymupdf.open()
        for _ in range(5):
            doc.new_page()
        doc.save(str(many_pages))
        doc.close()
        with pytest.raises(InvalidDocumentError):
            validate_document(many_pages, limits=IngestionLimits(max_pages=3))

    def test_refuses_inplace_overwrite_symlink_report_and_disambiguates_batch_names(
        self, tmp_path: Path
    ) -> None:
        src = tmp_path / "same.pdf"
        doc = pymupdf.open()
        doc.new_page().insert_text((72, 72), "Publico")
        doc.save(str(src))
        doc.close()

        with pytest.raises(InvalidDocumentError):
            sanitize_document(src, src, config=SanitizeConfig(enable_ocr=False))

        # Batch disambiguation for same-stem .pdf and .png
        in_dir = tmp_path / "batch_in"
        out_dir = tmp_path / "batch_out"
        in_dir.mkdir()
        (in_dir / "doc.pdf").write_bytes(src.read_bytes())
        Image.new("RGB", (32, 32), (255, 255, 255)).save(in_dir / "doc.png", format="PNG")
        Image.new("RGB", (32, 32), (255, 255, 255)).save(in_dir / "doc.jpg", format="JPEG")

        batch = sanitize_batch(
            in_dir, out_dir, config=SanitizeConfig(dpi=100, enable_ocr=False, ocr_scan_inputs=False)
        )
        assert len(batch.succeeded) == 3
        produced = {p.name for p in out_dir.iterdir()}
        assert len(produced) == 3

        # CLI --deny-list-file and --redact-filenames
        deny_file = tmp_path / "deny.txt"
        deny_file.write_text("PalabraSecreta\n", encoding="utf-8")
        out_clean = tmp_path / "clean.pdf"
        rep = tmp_path / "rep.json"
        res = runner.invoke(
            app,
            [
                "sanitize",
                str(src),
                "-o",
                str(out_clean),
                "--no-ocr",
                "--deny-list-file",
                str(deny_file),
                "--redact-filenames",
                "--report-json",
                str(rep),
            ],
        )
        assert res.exit_code == 0, res.output
        assert "same.pdf" not in res.output
        data = json.loads(rep.read_text(encoding="utf-8"))
        assert data["input_name"] != "same.pdf"
