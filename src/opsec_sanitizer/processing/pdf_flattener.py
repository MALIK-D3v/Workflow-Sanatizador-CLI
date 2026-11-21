"""Irreversible PDF flattening, pixel-level PII redaction, and clean reconstruction."""

from __future__ import annotations

import io
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

import pymupdf
from PIL import Image, ImageFilter

from opsec_sanitizer.detection.merger import HybridPiiDetector
from opsec_sanitizer.domain.models import BBox, OcrWord, PiiCategory, PiiSpan
from opsec_sanitizer.domain.ports import OcrEngine
from opsec_sanitizer.processing.image_sanitizer import redact_image_boxes

_EPOCH_PDF_DATE = "D:19700101000000Z"
_MUPDF_COMMENT_RE = re.compile(rb"% Written by MuPDF[^\r\n]*")
_CATALOG_INFO_RE = re.compile(rb"/Info<</Producer\([^)]*\)>>")
_TRAILER_ID_RE = re.compile(rb"/ID\[<([0-9A-Fa-f]+)><([0-9A-Fa-f]+)>\]")


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
    pii_counts: Mapping[PiiCategory, int]


def _join_words_with_offsets(
    words: Sequence[tuple[str, BBox]],
    line_keys: Sequence[tuple[int, int]] | None = None,
) -> tuple[str, list[tuple[int, int, BBox]]]:
    parts: list[str] = []
    offsets: list[tuple[int, int, BBox]] = []
    cursor = 0
    prev_line: tuple[int, int] | None = None
    for idx, (word, box) in enumerate(words):
        curr_line = line_keys[idx] if line_keys is not None else None
        if idx > 0:
            sep = "\n" if (curr_line is not None and curr_line != prev_line) else " "
            parts.append(sep)
            cursor += 1
        start = cursor
        end = start + len(word)
        parts.append(word)
        offsets.append((start, end, box))
        cursor = end
        prev_line = curr_line
    return "".join(parts), offsets


def map_spans_to_word_boxes(
    words: Sequence[tuple[str, BBox]],
    spans: Sequence[PiiSpan],
    *,
    line_keys: Sequence[tuple[int, int]] | None = None,
) -> tuple[BBox, ...]:
    """Map character-level PiiSpans in joined word text to every intersecting word BBox."""
    if not words or not spans:
        return ()
    _, offsets = _join_words_with_offsets(words, line_keys=line_keys)
    return tuple(
        box
        for w_start, w_end, box in offsets
        if any(not (w_end <= sp.start or w_start >= sp.end) for sp in spans)
    )


def _scale_boxes(boxes: Sequence[BBox], factor: float) -> tuple[BBox, ...]:
    return tuple(
        BBox(x0=b.x0 * factor, y0=b.y0 * factor, x1=b.x1 * factor, y1=b.y1 * factor)
        for b in boxes
    )


def _extract_native_words(
    page: pymupdf.Page,
) -> tuple[list[tuple[str, BBox]], list[tuple[int, int]]]:
    raw_words = page.get_text("words")
    rot_matrix = page.rotation_matrix
    words: list[tuple[str, BBox]] = []
    line_keys: list[tuple[int, int]] = []
    for entry in raw_words:
        text = str(entry[4])
        if not text.strip():
            continue
        rect = pymupdf.Rect(float(entry[0]), float(entry[1]), float(entry[2]), float(entry[3]))
        rotated = rect * rot_matrix
        words.append((text, BBox(x0=rotated.x0, y0=rotated.y0, x1=rotated.x1, y1=rotated.y1)))
        line_keys.append((int(entry[5]), int(entry[6])))
    return words, line_keys


def _detect_ocr_boxes(
    ocr_words: Sequence[OcrWord],
    detector: HybridPiiDetector,
) -> tuple[tuple[PiiSpan, ...], tuple[BBox, ...]]:
    if not ocr_words:
        return (), ()
    # Use conservative line_bbox when available so proportional-font splits never leak prefixes
    pairs = [(w.text, w.line_bbox or w.bbox) for w in ocr_words]
    line_keys = [(0, int(round((w.line_bbox or w.bbox).y0 / 12.0))) for w in ocr_words]
    joined, offsets = _join_words_with_offsets(pairs, line_keys=line_keys)
    spans = detector.detect(joined)
    if not spans:
        return (), ()
    boxes = tuple(
        box
        for w_start, w_end, box in offsets
        if any(not (w_end <= sp.start or w_start >= sp.end) for sp in spans)
    )
    return spans, boxes


def _rasterize_page(page: pymupdf.Page, dpi: int, paranoid_denoise: bool) -> Image.Image:
    # annots=False ensures review notes/comments/stamps are NEVER burned into raster pixels
    pix = page.get_pixmap(dpi=dpi, alpha=False, annots=False)
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
    for word in ocr_engine.extract_words(clean_img):
        text = word.text.strip()
        if not text:
            continue
        x0 = word.bbox.x0 * inv_scale
        y1 = word.bbox.y1 * inv_scale
        height_pt = max(4.0, (word.bbox.y1 - word.bbox.y0) * inv_scale)
        out_page.insert_text((x0, y1), text, fontsize=min(height_pt, 36.0), render_mode=3)


def _scrub_mupdf_fingerprints(raw_pdf: bytes) -> bytes:
    """Length-preserving in-place scrub of MuPDF version banner, Catalog /Info, and random /ID."""
    scrubbed = _MUPDF_COMMENT_RE.sub(lambda m: b"%" + (b" " * (len(m.group(0)) - 1)), raw_pdf)
    scrubbed = _CATALOG_INFO_RE.sub(lambda m: b" " * len(m.group(0)), scrubbed)
    scrubbed = _TRAILER_ID_RE.sub(
        lambda m: b"/ID[<" + (b"0" * len(m.group(1))) + b"><" + (b"0" * len(m.group(2))) + b">]",
        scrubbed,
    )
    return scrubbed


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
    raw = bytes(out_doc.tobytes(garbage=4, deflate=True, clean=True))
    scrubbed = _scrub_mupdf_fingerprints(raw)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(scrubbed)


def _append_image_page(
    out_doc: pymupdf.Document,
    img: Image.Image,
    width_pt: float,
    height_pt: float,
    *,
    dpi: int,
    ocr_engine: OcrEngine | None,
    enable_ocr: bool,
) -> None:
    out_page = out_doc.new_page(width=width_pt, height=height_pt)
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    out_page.insert_image(out_page.rect, stream=buf.getvalue())
    if enable_ocr and ocr_engine is not None:
        _embed_ocr_text_layer(out_page, img, ocr_engine, dpi=dpi)


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
            _append_image_page(
                out_doc,
                img,
                width_pt,
                height_pt,
                dpi=dpi,
                ocr_engine=ocr_engine,
                enable_ocr=enable_ocr,
            )
        _save_clean_pdf(out_doc, output_path)
    finally:
        out_doc.close()


def _process_pdf_page(
    page: pymupdf.Page,
    *,
    detector: HybridPiiDetector,
    ocr_engine: OcrEngine | None,
    opts: FlattenOptions,
) -> tuple[Image.Image, tuple[PiiSpan, ...]]:
    scale = float(opts.dpi) / 72.0
    raster = _rasterize_page(page, dpi=opts.dpi, paranoid_denoise=opts.paranoid_denoise)
    native_words, line_keys = _extract_native_words(page)

    all_spans: list[PiiSpan] = []
    pixel_boxes: list[BBox] = []

    if native_words:
        joined, offsets = _join_words_with_offsets(native_words, line_keys=line_keys)
        native_spans = detector.detect(joined)
        all_spans.extend(native_spans)
        if native_spans:
            raw_boxes = [
                box
                for w_s, w_e, box in offsets
                if any(not (w_e <= sp.start or w_s >= sp.end) for sp in native_spans)
            ]
            pixel_boxes.extend(_scale_boxes(raw_boxes, scale))

    # Run OCR on scanned pages AND hybrid pages (native text + embedded images)
    needs_ocr = (not native_words) or bool(page.get_images(full=False))
    if ocr_engine is not None and needs_ocr:
        ocr_spans, ocr_boxes = _detect_ocr_boxes(ocr_engine.extract_words(raster), detector)
        if not native_words:
            all_spans.extend(ocr_spans)
        elif ocr_spans:
            # Record additional embedded-image PII categories not already counted
            all_spans.extend(ocr_spans)
        pixel_boxes.extend(ocr_boxes)

    redacted = redact_image_boxes(raster, pixel_boxes, padding_px=opts.padding_px)
    return redacted, tuple(all_spans)


def flatten_pdf(
    source_path: Path,
    output_path: Path,
    *,
    detector: HybridPiiDetector,
    ocr_engine: OcrEngine | None = None,
    options: FlattenOptions | None = None,
) -> FlattenResult:
    """Stream-flatten a PDF into redacted raster pages and rebuild a zero-metadata PDF."""
    opts = options or FlattenOptions()
    src_doc = pymupdf.open(str(source_path))
    out_doc = pymupdf.open()
    try:
        raw_meta = src_doc.metadata or {}
        removed_meta = sorted(k for k, v in raw_meta.items() if v)
        if src_doc.get_xml_metadata():
            removed_meta.append("xmp")
        attachments_removed = int(src_doc.embfile_count())
        annotations_removed = 0
        pii_counts: dict[PiiCategory, int] = {}

        for page in src_doc:
            annotations_removed += len(list(page.annots() or []))
            redacted, page_spans = _process_pdf_page(
                page, detector=detector, ocr_engine=ocr_engine, opts=opts
            )
            for sp in page_spans:
                pii_counts[sp.category] = pii_counts.get(sp.category, 0) + 1
            _append_image_page(
                out_doc,
                redacted,
                float(page.rect.width),
                float(page.rect.height),
                dpi=opts.dpi,
                ocr_engine=ocr_engine,
                enable_ocr=opts.enable_ocr,
            )

        page_count = src_doc.page_count
        _save_clean_pdf(out_doc, output_path)
    finally:
        out_doc.close()
        src_doc.close()

    return FlattenResult(
        page_count=page_count,
        metadata_keys_removed=tuple(sorted(set(removed_meta))),
        attachments_removed=attachments_removed,
        annotations_removed=annotations_removed,
        pii_counts=MappingProxyType(pii_counts),
    )
