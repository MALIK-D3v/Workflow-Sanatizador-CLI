"""Fail-closed post-sanitization forensic verification for PDFs and images."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pymupdf
from PIL import Image

from opsec_sanitizer.detection.merger import HybridPiiDetector
from opsec_sanitizer.domain.errors import ForensicLeakError

_ALLOWED_DATES = frozenset({"", "D:19700101000000Z"})
_DANGEROUS_PDF_TOKENS = ("/JavaScript", "/JS ", "/Launch", "/RichMedia", "/EmbeddedFile")
_HARMLESS_IMAGE_INFO_KEYS = frozenset(
    {"jfif", "jfif_version", "jfif_unit", "jfif_density", "dpi", "gamma", "srgb"}
)


@dataclass(frozen=True)
class ForensicReport:
    """Result of independent post-sanitization forensic inspection."""

    passed: bool
    violations: tuple[str, ...]


def _check_pdf_metadata(doc: pymupdf.Document) -> list[str]:
    violations: list[str] = []
    meta = doc.metadata or {}
    for key in ("author", "title", "subject", "keywords", "creator", "producer"):
        if str(meta.get(key, "")).strip():
            violations.append(f"residual metadata field: {key}")
    for date_key in ("creationDate", "modDate"):
        if str(meta.get(date_key, "")).strip() not in _ALLOWED_DATES:
            violations.append(f"non-epoch metadata date: {date_key}")
    if doc.get_xml_metadata():
        violations.append("residual XMP metadata stream")
    return violations


def _check_pdf_structure(doc: pymupdf.Document) -> list[str]:
    violations: list[str] = []
    if doc.embfile_count() > 0:
        violations.append(f"residual embedded files: {doc.embfile_count()}")
    for page_idx, page in enumerate(doc, start=1):
        annots = list(page.annots() or [])
        if annots:
            violations.append(f"residual annotations on page {page_idx}: {len(annots)}")
    for xref in range(1, doc.xref_length()):
        obj_str = doc.xref_object(xref, compressed=False)
        for token in _DANGEROUS_PDF_TOKENS:
            if token in obj_str:
                violations.append(f"dangerous PDF object token {token} at xref {xref}")
    return violations


def _check_pdf_text_pii(doc: pymupdf.Document, detector: HybridPiiDetector) -> list[str]:
    violations: list[str] = []
    for page_idx, page in enumerate(doc, start=1):
        text = page.get_text("text")
        if not text.strip():
            continue
        spans = detector.detect(text)
        if spans:
            categories = sorted({sp.category.value for sp in spans})
            violations.append(
                f"residual PII detected on page {page_idx} categories={','.join(categories)}"
            )
    return violations


def verify_pdf_forensically(
    pdf_path: Path,
    *,
    detector: HybridPiiDetector,
) -> ForensicReport:
    """Verify a sanitized PDF has zero metadata, active content, or residual PII."""
    doc = pymupdf.open(str(pdf_path))
    try:
        violations: list[str] = []
        violations.extend(_check_pdf_metadata(doc))
        violations.extend(_check_pdf_structure(doc))
        violations.extend(_check_pdf_text_pii(doc, detector))
    finally:
        doc.close()

    if violations:
        raise ForensicLeakError("; ".join(violations))
    return ForensicReport(passed=True, violations=())


def verify_image_forensically(image_path: Path) -> ForensicReport:
    """Verify a sanitized image has zero EXIF tags and zero metadata chunks."""
    violations: list[str] = []
    with Image.open(image_path) as img:
        if len(img.getexif()) > 0:
            violations.append(f"residual EXIF tags: {len(img.getexif())}")
        residual_keys = sorted(
            str(k) for k in img.info if str(k).lower() not in _HARMLESS_IMAGE_INFO_KEYS
        )
        if residual_keys:
            violations.append(f"residual image metadata keys: {','.join(residual_keys)}")

    if violations:
        raise ForensicLeakError("; ".join(violations))
    return ForensicReport(passed=True, violations=())
