"""Fail-closed document ingestion validator (magic bytes, zip-bomb, encryption, bounds)."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pymupdf
from PIL import Image, UnidentifiedImageError

from opsec_sanitizer.domain.errors import (
    DocumentNotFoundError,
    EncryptedDocumentError,
    FileTooLargeError,
    InvalidDocumentError,
    UnsafeArchiveError,
    UnsupportedFormatError,
)
from opsec_sanitizer.domain.models import DocumentType, IngestionLimits, ValidatedDocument
from opsec_sanitizer.io_utils import assert_no_symlink_in_path, sha256_file

_PDF_MAGIC = b"%PDF-"
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_JPEG_MAGIC = b"\xff\xd8\xff"
_TIFF_MAGICS = (b"II*\x00", b"MM\x00*")
_ZIP_MAGIC = b"PK\x03\x04"
_STREAM_CHUNK = 65_536


def _is_webp(header: bytes) -> bool:
    return len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WEBP"


def _check_zip_member_name(name: str, seen: set[str]) -> None:
    if name in seen:
        raise UnsafeArchiveError("DOCX archive contains duplicate member names")
    seen.add(name)
    if "\\" in name or name.startswith("/") or ".." in Path(name).parts:
        raise UnsafeArchiveError("DOCX archive contains unsafe member path")


def _validate_docx_archive(path: Path, limits: IngestionLimits) -> None:
    try:
        with zipfile.ZipFile(path, "r") as zf:
            infos = zf.infolist()
            if len(infos) > limits.max_archive_entries:
                raise UnsafeArchiveError("DOCX archive exceeds maximum entry count")

            seen: set[str] = set()
            total_uncompressed = 0
            total_compressed = 0
            has_document_xml = False

            for info in infos:
                _check_zip_member_name(info.filename, seen)
                if info.flag_bits & 0x1:
                    raise EncryptedDocumentError("Encrypted DOCX archive is not supported")
                if info.filename == "word/document.xml":
                    has_document_xml = True

                # Bounded streaming count so spoofed ZIP headers cannot bypass limits
                actual_size = 0
                with zf.open(info, "r") as member_fh:
                    while chunk := member_fh.read(_STREAM_CHUNK):
                        actual_size += len(chunk)
                        if total_uncompressed + actual_size > limits.max_uncompressed_docx_bytes:
                            raise UnsafeArchiveError("DOCX archive exceeds uncompressed size limit")

                comp_size = max(info.compress_size, 1)
                if actual_size > 4096 and (actual_size / comp_size) > limits.max_compression_ratio:
                    raise UnsafeArchiveError("DOCX archive entry exceeds safe compression ratio")

                total_uncompressed += actual_size
                total_compressed += comp_size

            if total_compressed > 0 and (
                total_uncompressed / total_compressed > limits.max_compression_ratio
            ):
                raise UnsafeArchiveError("DOCX archive exceeds safe compression ratio")

            if not has_document_xml:
                raise UnsupportedFormatError("ZIP archive is not a valid DOCX document")
    except zipfile.BadZipFile as exc:
        raise UnsupportedFormatError("Corrupt or invalid ZIP/DOCX archive") from exc


def _validate_pdf_structure(path: Path, limits: IngestionLimits) -> None:
    try:
        doc = pymupdf.open(str(path))
    except Exception as exc:
        raise InvalidDocumentError("PDF file is corrupt or unreadable") from exc
    try:
        if doc.is_encrypted or doc.needs_pass:
            raise EncryptedDocumentError("Encrypted or password-protected PDFs are not supported")
        if doc.page_count <= 0:
            raise InvalidDocumentError("PDF file contains no pages")
        if doc.page_count > limits.max_pages:
            raise InvalidDocumentError("PDF file exceeds maximum allowed page count")
        for page in doc:
            est_pixels = (page.rect.width * (200.0 / 72.0)) * (page.rect.height * (200.0 / 72.0))
            if est_pixels > limits.max_page_pixels:
                raise InvalidDocumentError("PDF page dimensions exceed maximum safe pixel limit")
    finally:
        doc.close()


def _validate_image_bounds(path: Path, limits: IngestionLimits) -> None:
    try:
        with Image.open(path) as img:
            w, h = img.size
            if w <= 0 or h <= 0 or (w * h) > limits.max_image_pixels:
                raise InvalidDocumentError("Image dimensions exceed maximum safe pixel limit")
    except (UnidentifiedImageError, Image.DecompressionBombError, OSError) as exc:
        raise InvalidDocumentError("Image file is corrupt or exceeds decompression bounds") from exc


def _detect_type(path: Path, header: bytes, limits: IngestionLimits) -> DocumentType:
    if header.startswith(_PDF_MAGIC):
        _validate_pdf_structure(path, limits)
        return DocumentType.PDF
    if (
        header.startswith(_PNG_MAGIC)
        or header.startswith(_JPEG_MAGIC)
        or header.startswith(_TIFF_MAGICS)
        or _is_webp(header)
    ):
        _validate_image_bounds(path, limits)
        return DocumentType.IMAGE
    if header.startswith(_ZIP_MAGIC):
        _validate_docx_archive(path, limits)
        return DocumentType.DOCX
    raise UnsupportedFormatError("Unsupported or unrecognized document binary signature")


def validate_document(
    path: Path,
    limits: IngestionLimits | None = None,
) -> ValidatedDocument:
    """Validate an input document by path safety, size bounds, and magic bytes."""
    active_limits = limits or IngestionLimits()
    if not path.exists() and not path.is_symlink():
        raise DocumentNotFoundError(f"Document not found: {path.name}")
    assert_no_symlink_in_path(path, allow_symlinks=active_limits.allow_symlinks)
    if not path.is_file():
        raise InvalidDocumentError("Input path must be a regular file")

    size_bytes = path.stat().st_size
    if size_bytes <= 0:
        raise InvalidDocumentError("Input file is empty")
    if size_bytes > active_limits.max_file_bytes:
        raise FileTooLargeError("Input file exceeds maximum allowed size")

    with path.open("rb") as fh:
        header = fh.read(32)

    doc_type = _detect_type(path, header, active_limits)
    return ValidatedDocument(
        path=path.resolve(),
        doc_type=doc_type,
        size_bytes=size_bytes,
        sha256_hex=sha256_file(path),
    )
