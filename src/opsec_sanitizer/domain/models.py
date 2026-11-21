"""Immutable domain models for OPSEC document sanitization."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class DocumentType(StrEnum):
    """Supported input document formats detected via binary signatures."""

    PDF = "pdf"
    DOCX = "docx"
    IMAGE = "image"


class PiiCategory(StrEnum):
    """Categories of personally identifiable information detected and redacted."""

    CURP = "CURP"
    RFC = "RFC"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    PERSON = "PERSON"
    DENY_LIST = "DENY_LIST"


@dataclass(frozen=True)
class IngestionLimits:
    """Safety bounds enforced prior to parsing untrusted input files."""

    max_file_bytes: int = 100 * 1024 * 1024  # 100 MiB
    max_uncompressed_docx_bytes: int = 200 * 1024 * 1024  # 200 MiB
    max_compression_ratio: float = 100.0
    max_archive_entries: int = 2_000
    max_pages: int = 500
    max_page_pixels: int = 40_000_000
    max_image_pixels: int = 40_000_000
    allow_symlinks: bool = False


@dataclass(frozen=True)
class ValidatedDocument:
    """Immutable metadata for an input file that passed security validation."""

    path: Path
    doc_type: DocumentType
    size_bytes: int
    sha256_hex: str


@dataclass(frozen=True)
class PiiSpan:
    """Immutable character offset span representing detected PII."""

    start: int
    end: int
    category: PiiCategory
    confidence: float = 1.0
    source: str = "regex"


@dataclass(frozen=True)
class BBox:
    """Pixel or point bounding box (x0, y0, x1, y1) with top-left origin."""

    x0: float
    y0: float
    x1: float
    y1: float

    def expand(self, padding: float, max_width: float, max_height: float) -> BBox:
        """Return a new BBox expanded by padding clamped to image bounds."""
        return BBox(
            x0=max(0.0, self.x0 - padding),
            y0=max(0.0, self.y0 - padding),
            x1=min(max_width, self.x1 + padding),
            y1=min(max_height, self.y1 + padding),
        )


@dataclass(frozen=True)
class OcrWord:
    """Single word returned by an OCR engine with top-left pixel coordinates."""

    text: str
    bbox: BBox
    confidence: float = 1.0
    line_bbox: BBox | None = None
