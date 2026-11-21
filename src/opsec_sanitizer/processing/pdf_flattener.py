"""Irreversible PDF flattening, pixel-level PII redaction, and clean reconstruction."""

from __future__ import annotations

import io
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import pymupdf
from PIL import Image, ImageFilter

from opsec_sanitizer.detection.merger import HybridPiiDetector
from opsec_sanitizer.domain.models import BBox, PiiCategory, PiiSpan
from opsec_sanitizer.domain.ports import OcrEngine
from opsec_sanitizer.processing.image_sanitizer import redact_image_boxes

_EPOCH_PDF_DATE = "D:19700101000000Z"


@dataclass(frozen=True)
class FlattenOptions:
    """Configuration options for irreversible PDF flattening."""

    dpi: int = 200
    padding_px: int = 4
    enable_ocr: bool = True
    paranoid_denoise: bool = False


@dataclass(frozen=True)
class FlattenResult:
    """Immutable audit summary returned after flattening (never contains raw PII)."""

    page_count: int
    metadata_keys_removed: tuple[str, ...]
    attachments_removed: int
    annotations_removed: int
    pii_counts: dict[PiiCategory, int]


def _join_words_with_offsets(
    words: Sequence[tuple[str, BBox]],
) -> tuple[str, list[tuple[int, int, BBox]]]:
    parts: list[str] = []
    offsets: list[tuple[int, int, BBox]] = []
    cursor = 0
    for idx, (word, box) in enumerate(words):
        if idx > 0:
            parts.append(" ")
            cursor += 1
        start = cursor
        end = start + len(word)
        parts.append(word)
        offsets.append((start, end, box))
        cursor = end
    return "".join(parts), offsets


def map_spans_to_word_boxes(
    words: Sequence[tuple[str, BBox]],
    spans: Sequence[PiiSpan],
) -> tuple[BBox, ...]:
    """Map character-level PiiSpans in joined word text to every intersecting word BBox."""
    if not words or not spans:
        return ()
    _, offsets = _join_words_with_offsets(words)
    boxes: list[BBox] = []
    for w_start, w_end, box in offsets:
        if any(not (w_end <= sp.start or w_start >= sp.end) for sp in spans):
            boxes.append(box)
    return tuple(boxes)


def _scale_boxes(boxes: Sequence[BBox], factor: float) -> tuple[BBox, ...]:
    return tuple(
        BBox(
            x0=b.x0 * factor,
            y0=b.y0 * factor,
            x1=b.x1 * factor,
            y1=b.y1 * factor,
        )
        for b in boxes
    )


def _extract_native_words(page: pymupdf.Page) -> list[tuple[str, BBox]]:
    raw_words = page.get_text("words")
    result: list[tuple[str, BBox]] = []
    for entry in raw_words:
        x0, y0, x1, y1 = float(entry[0]), float(entry[1]), float(entry[2]), float(entry[3])
        text = str(entry[4])
        if text.strip():
            result.append((text, BBox(x0=x0, y0=y0, x1=x1, y1=y1)))
    return result


def _rasterize_page(page: pymupdf.Page, dpi: int, paranoid_denoise: bool) -> Image.Image:
    pix = page.get_pixmap(dpi=dpi, alpha=False)
    img = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
    if paranoid_denoise:
        img = img.convert("L").filter(ImageFilter.MedianFilter(size=3)).convert("RGB")
        img = Image.frombytes("RGB", img.size, img.tobytes())
    return img


def _embed_ocr_text_layer(
    out_page: pymupdf.Page,
    clean_img: Image.Image,
    ocr_engine: OcrEngine,
    dpi: int,
) -> None:
    inv_scale = 72.0 / float(dpi)
    ocr_words = ocr_engine.extract_words(clean_img)
    for word in ocr_words:
        text = word.text.strip()
        if not text:
            continue
        x0 = word.bbox.x0 * inv_scale
        y1 = word.bbox.y1 * inv_scale
        height_pt = max(4.0, (word.bbox.y1 - word.bbox.y0) * inv_scale)
        out_page.insert_text(
            (x0, y1),
            text,
            fontsize=min(height_pt, 36.0),
            render_mode=3,  # Invisible searchable text layer
        )


def _save_clean_pdf(out_doc: pymupdf.Document, output_path: Path) -> None:
    out_doc.del_xml_metadata()
    out_doc.set_metadata(
        {
            "title": "",
            "author": "",
            "subject": "",
            "keywords": "",
            "creator": "",
            "producer": "",
            "creationDate": _EPOCH_PDF_DATE,
            "modDate": _EPOCH_PDF_DATE,
        }
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    out_doc.save(str(output_path), garbage=4, deflate=True, clean=True)


def build_pdf_from_clean_images(
    pages: Sequence[tuple[Image.Image, float, float]],
    output_path: Path,
    *,
    dpi: int = 200,
    ocr_engine: OcrEngine | None = None,
    enable_ocr: bool = True,
) -> None:
    """Create a brand-new zero-metadata PDF from pre-redacted RGB images + optional OCR."""
    out_doc = pymupdf.open()
    try:
        for img, width_pt, height_pt in pages:
            out_page = out_doc.new_page(width=width_pt, height=height_pt)
            buf = io.BytesIO()
            img.save(buf, format="PNG", optimize=True)
            out_page.insert_image(out_page.rect, stream=buf.getvalue())
            if enable_ocr and ocr_engine is not None:
                _embed_ocr_text_layer(out_page, img, ocr_engine, dpi=dpi)
        _save_clean_pdf(out_doc, output_path)
    finally:
        out_doc.close()


def flatten_pdf(
    source_path: Path,
    output_path: Path,
    *,
    detector: HybridPiiDetector,
    ocr_engine: OcrEngine | None = None,
    options: FlattenOptions | None = None,
) -> FlattenResult:
    """Flatten a PDF into clean redacted raster pages and rebuild a zero-metadata PDF."""
    opts = options or FlattenOptions()
    scale = float(opts.dpi) / 72.0

    src_doc = pymupdf.open(str(source_path))
    try:
        raw_meta = src_doc.metadata or {}
        removed_meta = sorted(k for k, v in raw_meta.items() if v)
        if src_doc.get_xml_metadata():
            removed_meta.append("xmp")
        attachments_removed = int(src_doc.embfile_count())
        annotations_removed = 0
        pii_counts: dict[PiiCategory, int] = {}
        clean_pages: list[tuple[Image.Image, float, float]] = []

        for page in src_doc:
            annotations_removed += len(list(page.annots() or []))
            raster = _rasterize_page(page, dpi=opts.dpi, paranoid_denoise=opts.paranoid_denoise)

            native_words = _extract_native_words(page)
            if native_words:
                joined_text, _ = _join_words_with_offsets(native_words)
                spans = detector.detect(joined_text)
                pixel_boxes = _scale_boxes(map_spans_to_word_boxes(native_words, spans), scale)
            elif ocr_engine is not None:
                ocr_words = ocr_engine.extract_words(raster)
                word_pairs = [(w.text, w.bbox) for w in ocr_words]
                joined_text, _ = _join_words_with_offsets(word_pairs)
                spans = detector.detect(joined_text)
                pixel_boxes = map_spans_to_word_boxes(word_pairs, spans)
            else:
                spans = ()
                pixel_boxes = ()

            for sp in spans:
                pii_counts[sp.category] = pii_counts.get(sp.category, 0) + 1

            redacted = redact_image_boxes(raster, pixel_boxes, padding_px=opts.padding_px)
            clean_pages.append((redacted, float(page.rect.width), float(page.rect.height)))

        page_count = src_doc.page_count
    finally:
        src_doc.close()

    build_pdf_from_clean_images(
        clean_pages,
        output_path,
        dpi=opts.dpi,
        ocr_engine=ocr_engine,
        enable_ocr=opts.enable_ocr,
    )

    return FlattenResult(
        page_count=page_count,
        metadata_keys_removed=tuple(sorted(set(removed_meta))),
        attachments_removed=attachments_removed,
        annotations_removed=annotations_removed,
        pii_counts=pii_counts,
    )
