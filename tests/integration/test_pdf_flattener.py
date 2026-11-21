"""Integration and unit tests for irreversible PDF flattening and metadata stripping."""

from __future__ import annotations

from pathlib import Path

import pymupdf
from PIL import Image

from opsec_sanitizer.detection.merger import HybridPiiDetector
from opsec_sanitizer.detection.ner_offline import HeuristicSpanishNerEngine
from opsec_sanitizer.detection.regex_mx import compute_curp_check_digit
from opsec_sanitizer.domain.models import BBox, PiiCategory, PiiSpan
from opsec_sanitizer.processing.pdf_flattener import (
    FlattenOptions,
    flatten_pdf,
    map_spans_to_word_boxes,
)

_CURP_17 = "GOPA850714HDFLRN0"
_VALID_CURP = f"{_CURP_17}{compute_curp_check_digit(_CURP_17)}"


def _create_trapped_pdf(path: Path) -> None:
    """Create a synthetic PDF containing all common OPSEC leak vectors."""
    doc = pymupdf.open()
    page = doc.new_page(width=595, height=842)

    # Normal public text
    page.insert_text((72, 80), "Informe Oficial de Obra Publica 2026", fontsize=14)
    # Visible PII that must be detected and pixel-redacted
    page.insert_text((72, 130), f"CURP: {_VALID_CURP}", fontsize=14)
    page.insert_text((72, 170), "Correo: fuente.oculta@redaccion.mx", fontsize=14)

    # Fake redaction: text underneath a solid black rectangle
    page.insert_text((72, 230), "TEXTO_OCULTO_BAJO_CAJA", fontsize=14)
    page.draw_rect(pymupdf.Rect(68, 214, 340, 238), color=(0, 0, 0), fill=(0, 0, 0))

    # Hidden annotation
    page.add_text_annot((400, 100), "Nota secreta del informante")

    # Embedded attachment
    doc.embfile_add("notas_fuente.txt", b"Archivo adjunto confidencial")

    # Explicit metadata + XMP
    doc.set_metadata(
        {
            "author": "Fuente Secreta 01",
            "title": "Filtracion Interna",
            "creator": "Microsoft Word Corp",
        }
    )
    doc.set_xml_metadata(
        '<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>'
        "<x:xmpmeta xmlns:x='adobe:ns:meta/'>"
        "<rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>"
        "<rdf:Description xmlns:dc='http://purl.org/dc/elements/1.1/'>"
        "<dc:creator>FuenteXMP</dc:creator>"
        "</rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end='w'?>"
    )
    doc.save(str(path))
    doc.close()


class TestMapSpansToWordBoxes:
    def test_maps_multi_word_span_to_all_constituent_boxes(self) -> None:
        words = [
            ("Firmado", BBox(10, 10, 50, 20)),
            ("Carlos", BBox(55, 10, 95, 20)),
            ("Mendoza", BBox(100, 10, 150, 20)),
            ("hoy", BBox(155, 10, 180, 20)),
        ]
        # Joined text: "Firmado Carlos Mendoza hoy"
        joined = "Firmado Carlos Mendoza hoy"
        start = joined.index("Carlos Mendoza")
        span = PiiSpan(start=start, end=start + len("Carlos Mendoza"), category=PiiCategory.PERSON)

        boxes = map_spans_to_word_boxes(words, (span,))

        assert boxes == (BBox(55, 10, 95, 20), BBox(100, 10, 150, 20))


class TestFlattenPdf:
    def test_destroys_metadata_attachments_annotations_fake_redactions_and_pii(
        self, tmp_path: Path
    ) -> None:
        src = tmp_path / "trapped.pdf"
        dst = tmp_path / "sanitized.pdf"
        _create_trapped_pdf(src)

        detector = HybridPiiDetector(ner_engine=HeuristicSpanishNerEngine())
        result = flatten_pdf(
            src,
            dst,
            detector=detector,
            options=FlattenOptions(dpi=150, enable_ocr=False),
        )

        assert dst.exists()
        assert result.page_count == 1
        assert result.attachments_removed == 1
        assert result.annotations_removed == 1
        assert "author" in result.metadata_keys_removed
        assert result.pii_counts.get(PiiCategory.CURP, 0) == 1
        assert result.pii_counts.get(PiiCategory.EMAIL, 0) == 1

        raw_bytes = dst.read_bytes()
        for forbidden in (
            b"Fuente Secreta 01",
            b"FuenteXMP",
            b"notas_fuente.txt",
            b"Nota secreta del informante",
            b"TEXTO_OCULTO_BAJO_CAJA",
            _VALID_CURP.encode("ascii"),
            b"fuente.oculta@redaccion.mx",
        ):
            assert forbidden not in raw_bytes

        out_doc = pymupdf.open(str(dst))
        try:
            assert out_doc.page_count == 1
            assert out_doc.embfile_count() == 0
            assert list(out_doc[0].annots() or []) == []
            assert out_doc.get_xml_metadata() == ""
            meta = out_doc.metadata or {}
            assert meta.get("author", "") == ""
            assert meta.get("title", "") == ""
            assert meta.get("creationDate", "") == "D:19700101000000Z"
            # Zero text layer because enable_ocr=False
            assert out_doc[0].get_text("text").strip() == ""

            # Verify output page is rendered (not blank) and CURP area is solid black
            pix = out_doc[0].get_pixmap(dpi=150, alpha=False)
            rendered = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
            scale = 150.0 / 72.0
            curp_pixel = rendered.getpixel((int(140 * scale), int(126 * scale)))
            assert curp_pixel == (0, 0, 0)
        finally:
            out_doc.close()
