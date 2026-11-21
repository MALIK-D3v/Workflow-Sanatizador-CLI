"""Fail-closed document ingestion validator (magic bytes, zip-bomb, encryption)."""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

import pymupdf

from opsec_sanitizer.domain.errors import (
    DocumentNotFoundError,
    EncryptedDocumentError,
    FileTooLargeError,
    InvalidDocumentError,
    UnsafeArchiveError,
    UnsupportedFormatError,
)
from opsec_sanitizer.domain.models import DocumentType, IngestionLimits, ValidatedDocument

_PDF_MAGIC = b"%PDF-"
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_JPEG_MAGIC = b"\xff\xd8\xff"
_TIFF_MAGICS = (b"II*\x00", b"MM\x00*")
_ZIP_MAGIC = b"PK\x03\x04"
_CHUNK_SIZE = 65_536


def _is_webp(header: bytes) -> bool:
    return len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WEBP"


def _compute_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(_CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_docx_archive(path: Path, limits: IngestionLimits) -> None:
    try:
        with zipfile.ZipFile(path, "r") as zf:
            infos = zf.infolist()
            if len(infos) > limits.max_archive_entries:
                raise UnsafeArchiveError("DOCX archive exceeds maximum entry count")

            total_uncompressed = 0
            total_compressed = 0
            has_document_xml = False

            for info in infos:
                if ".." in Path(info.filename).parts or info.filename.startswith("/"):
                    raise UnsafeArchiveError("DOCX archive contains unsafe member path")
                if info.filename == "word/document.xml":
                    has_document_xml = True
                total_uncompressed += info.file_size
                total_compressed += max(info.compress_size, 1)
                if total_uncompressed > limits.max_uncompressed_docx_bytes:
                    raise UnsafeArchiveError("DOCX archive exceeds uncompressed size limit")

            if total_compressed > 0:
                ratio = total_uncompressed / total_compressed
                if ratio > limits.max_compression_ratio:
                    raise UnsafeArchiveError("DOCX archive exceeds safe compression ratio")

            if not has_document_xml:
                raise UnsupportedFormatError("ZIP archive is not a valid DOCX document")
    except zipfile.BadZipFile as exc:
        raise UnsupportedFormatError("Corrupt or invalid ZIP/DOCX archive") from exc


def _validate_pdf_unencrypted(path: Path) -> None:
    try:
        doc = pymupdf.open(str(path))
    except Exception as exc:
        raise InvalidDocumentError("PDF file is corrupt or unreadable") from exc
    try:
        if doc.is_encrypted or doc.needs_pass:
            raise EncryptedDocumentError("Encrypted or password-protected PDFs are not supported")
    finally:
        doc.close()


def _detect_type(path: Path, header: bytes, limits: IngestionLimits) -> DocumentType:
    if header.startswith(_PDF_MAGIC):
        _validate_pdf_unencrypted(path)
        return DocumentType.PDF
    if (
        header.startswith(_PNG_MAGIC)
        or header.startswith(_JPEG_MAGIC)
        or header.startswith(_TIFF_MAGICS)
        or _is_webp(header)
    ):
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
    if path.is_symlink() and not active_limits.allow_symlinks:
        raise InvalidDocumentError("Symbolic links are disallowed by OPSEC policy")
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
    sha256_hex = _compute_sha256(path)
    return ValidatedDocument(
        path=path.resolve(),
        doc_type=doc_type,
        size_bytes=size_bytes,
        sha256_hex=sha256_hex,
    )
