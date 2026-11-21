"""Fail-closed post-sanitization forensic verification for PDFs and images."""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from pathlib import Path

import pymupdf
from PIL import Image

from opsec_sanitizer.detection.merger import HybridPiiDetector
from opsec_sanitizer.domain.errors import ForensicLeakError
from opsec_sanitizer.domain.ports import OcrEngine

_ALLOWED_DATES = frozenset({"", "D:19700101000000Z"})
_STANDARD_EMPTY_KEYS = frozenset(
    {"author", "title", "subject", "keywords", "creator", "producer", "format", "encryption"}
)
_DANGEROUS_PDF_RE = re.compile(
    r"/(?:JavaScript|JS|OpenAction|AA|URI|GoToR|GoToE|SubmitForm|ImportData|AcroForm|XFA|"
    r"Filespec|EF|EmbeddedFiles|EmbeddedFile|PieceInfo|OCProperties|RichMedia|Launch|"
    r"Sound|Movie|3D|Metadata)(?=[\s/<>(\[\]{}%]|$)"
)
_HEX_NAME_ESCAPE_RE = re.compile(r"#([0-9A-Fa-f]{2})")
_PNG_SIG = b"\x89PNG\r\n\x1a\n"
_ALLOWED_PNG_CHUNKS = frozenset({b"IHDR", b"IDAT", b"IEND"})
_HARMLESS_IMAGE_INFO_KEYS = frozenset(
    {"jfif", "jfif_version", "jfif_unit", "jfif_density", "dpi", "gamma", "srgb"}
)


@dataclass(frozen=True)
class ForensicReport:
    """Result of independent post-sanitization forensic inspection."""

    passed: bool
    violations: tuple[str, ...]


def _decode_pdf_name_escapes(raw: str) -> str:
    return _HEX_NAME_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), raw)


def _check_pdf_raw_bytes(raw_bytes: bytes) -> list[str]:
    violations: list[str] = []
    eof_positions = [m.start() for m in re.finditer(rb"%%EOF", raw_bytes)]
    if len(eof_positions) != 1:
        violations.append(
            f"unexpected PDF %%EOF count (incremental updates?): {len(eof_positions)}"
        )
    else:
        tail = raw_bytes[eof_positions[0] + len(b"%%EOF") :].strip()
        if tail:
            violations.append(f"trailing bytes after PDF %%EOF: {len(tail)} bytes")
    if b"Written by MuPDF" in raw_bytes or b"/Producer(MuPDF" in raw_bytes:
        violations.append("residual MuPDF fingerprint banner or catalog Producer")
    return violations


def _check_pdf_metadata(doc: pymupdf.Document) -> list[str]:
    violations: list[str] = []
    meta = doc.metadata or {}
    for key, value in meta.items():
        val_str = str(value or "").strip()
        if key in ("creationDate", "modDate"):
            if val_str not in _ALLOWED_DATES:
                violations.append(f"non-epoch metadata date: {key}")
        elif key == "format":
            continue
        elif val_str:
            violations.append(f"residual metadata field: {key}")

    # Inspect raw /Info dictionary for arbitrary custom keys (e.g. /Company, /Comments)
    info_ref = doc.xref_get_key(-1, "Info")
    if info_ref[0] == "xref":
        info_xref = int(info_ref[1].split()[0])
        for key in doc.xref_get_keys(info_xref):
            if key in ("CreationDate", "ModDate"):
                continue
            ktype, kval = doc.xref_get_key(info_xref, key)
            if ktype != "null" and kval.strip("()<> "):
                violations.append(f"residual custom /Info metadata key: {key}")

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
        decoded = _decode_pdf_name_escapes(doc.xref_object(xref, compressed=False))
        for match in _DANGEROUS_PDF_RE.finditer(decoded):
            violations.append(f"dangerous PDF object token {match.group(0)} at xref {xref}")
    return violations


def _check_pdf_text_pii(
    doc: pymupdf.Document,
    detector: HybridPiiDetector,
    ocr_engine: OcrEngine | None = None,
) -> list[str]:
    violations: list[str] = []
    for page_idx, page in enumerate(doc, start=1):
        text = page.get_text("text")
        if not text.strip() and ocr_engine is not None:
            pix = page.get_pixmap(dpi=150, alpha=False, annots=False)
            img = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
            text = " ".join(w.text for w in ocr_engine.extract_words(img))
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
    ocr_engine: OcrEngine | None = None,
) -> ForensicReport:
    """Verify a sanitized PDF has zero metadata, active content, trailing bytes, or residual PII."""
    raw_bytes = pdf_path.read_bytes()
    violations: list[str] = _check_pdf_raw_bytes(raw_bytes)

    doc = pymupdf.open(str(pdf_path))
    try:
        violations.extend(_check_pdf_metadata(doc))
        violations.extend(_check_pdf_structure(doc))
        violations.extend(_check_pdf_text_pii(doc, detector, ocr_engine=ocr_engine))
    finally:
        doc.close()

    if violations:
        raise ForensicLeakError("; ".join(violations))
    return ForensicReport(passed=True, violations=())


def _check_png_chunks(raw_bytes: bytes) -> list[str]:
    if not raw_bytes.startswith(_PNG_SIG):
        return []
    violations: list[str] = []
    pos = len(_PNG_SIG)
    saw_iend = False
    while pos + 12 <= len(raw_bytes):
        length = struct.unpack(">I", raw_bytes[pos : pos + 4])[0]
        ctype = raw_bytes[pos + 4 : pos + 8]
        chunk_end = pos + 12 + length
        if chunk_end > len(raw_bytes):
            violations.append("truncated PNG chunk structure")
            break
        if ctype not in _ALLOWED_PNG_CHUNKS:
            violations.append(f"disallowed PNG chunk: {ctype.decode('latin-1', errors='replace')}")
        pos = chunk_end
        if ctype == b"IEND":
            saw_iend = True
            if pos < len(raw_bytes):
                violations.append(f"trailing bytes after PNG IEND: {len(raw_bytes) - pos} bytes")
            break
    if not saw_iend:
        violations.append("missing PNG IEND chunk")
    return violations


def verify_image_forensically(
    image_path: Path,
    *,
    detector: HybridPiiDetector | None = None,
    ocr_engine: OcrEngine | None = None,
) -> ForensicReport:
    """Verify a sanitized image has zero EXIF/ancillary chunks, zero trailing bytes, and no PII."""
    raw_bytes = image_path.read_bytes()
    violations: list[str] = _check_png_chunks(raw_bytes)

    with Image.open(image_path) as img:
        if len(img.getexif()) > 0:
            violations.append(f"residual EXIF tags: {len(img.getexif())}")
        residual_keys = sorted(
            str(k) for k in img.info if str(k).lower() not in _HARMLESS_IMAGE_INFO_KEYS
        )
        if residual_keys:
            violations.append(f"residual image metadata keys: {','.join(residual_keys)}")
        if detector is not None and ocr_engine is not None:
            ocr_text = " ".join(w.text for w in ocr_engine.extract_words(img))
            spans = detector.detect(ocr_text)
            if spans:
                categories = sorted({sp.category.value for sp in spans})
                violations.append(
                    f"residual PII detected in image categories={','.join(categories)}"
                )

    if violations:
        raise ForensicLeakError("; ".join(violations))
    return ForensicReport(passed=True, violations=())
