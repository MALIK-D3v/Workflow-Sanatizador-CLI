"""Unit tests for safe document ingestion and magic-byte validation."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pymupdf
import pytest
from PIL import Image

from opsec_sanitizer.domain.errors import (
    DocumentNotFoundError,
    EncryptedDocumentError,
    FileTooLargeError,
    InvalidDocumentError,
    UnsafeArchiveError,
    UnsupportedFormatError,
)
from opsec_sanitizer.domain.models import DocumentType, IngestionLimits
from opsec_sanitizer.ingestion.validator import validate_document


def _make_pdf_bytes(password: str | None = None) -> bytes:
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Documento de prueba")
    if password:
        data = doc.tobytes(
            encryption=pymupdf.PDF_ENCRYPT_AES_256,
            user_pw=password,
            owner_pw=password,
        )
    else:
        data = doc.tobytes()
    doc.close()
    return data


def _make_png_bytes() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (16, 16), color=(255, 255, 255)).save(buf, format="PNG")
    return buf.getvalue()


def _make_jpeg_bytes() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (16, 16), color=(200, 200, 200)).save(buf, format="JPEG")
    return buf.getvalue()


def _make_minimal_docx_bytes(payload_size: int = 100) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr(
            "word/document.xml",
            "<w:document>" + ("A" * payload_size) + "</w:document>",
        )
    return buf.getvalue()


class TestValidateDocument:
    def test_detects_pdf_by_magic_bytes_ignoring_extension(self, tmp_path: Path) -> None:
        file_path = tmp_path / "leak.bin"
        file_path.write_bytes(_make_pdf_bytes())

        result = validate_document(file_path)

        assert result.doc_type == DocumentType.PDF
        assert result.size_bytes == file_path.stat().st_size
        assert len(result.sha256_hex) == 64

    def test_detects_png_and_jpeg_by_magic_bytes(self, tmp_path: Path) -> None:
        png_path = tmp_path / "scan.unknown"
        png_path.write_bytes(_make_png_bytes())
        jpg_path = tmp_path / "photo.dat"
        jpg_path.write_bytes(_make_jpeg_bytes())

        assert validate_document(png_path).doc_type == DocumentType.IMAGE
        assert validate_document(jpg_path).doc_type == DocumentType.IMAGE

    def test_detects_docx_by_zip_structure_ignoring_extension(self, tmp_path: Path) -> None:
        docx_path = tmp_path / "memo.bin"
        docx_path.write_bytes(_make_minimal_docx_bytes())

        result = validate_document(docx_path)

        assert result.doc_type == DocumentType.DOCX

    def test_rejects_spoofed_pdf_extension(self, tmp_path: Path) -> None:
        fake_pdf = tmp_path / "malicious.pdf"
        fake_pdf.write_bytes(b"#!/bin/sh\necho not a pdf\n")

        with pytest.raises(UnsupportedFormatError):
            validate_document(fake_pdf)

    def test_rejects_plain_zip_without_docx_structure(self, tmp_path: Path) -> None:
        plain_zip = tmp_path / "fake.docx"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("hello.txt", "world")
        plain_zip.write_bytes(buf.getvalue())

        with pytest.raises(UnsupportedFormatError):
            validate_document(plain_zip)

    def test_rejects_missing_file_and_empty_file(self, tmp_path: Path) -> None:
        with pytest.raises(DocumentNotFoundError):
            validate_document(tmp_path / "does_not_exist.pdf")

        empty = tmp_path / "empty.pdf"
        empty.write_bytes(b"")
        with pytest.raises(InvalidDocumentError):
            validate_document(empty)

    def test_rejects_directory_and_symlink_by_default(self, tmp_path: Path) -> None:
        with pytest.raises(InvalidDocumentError):
            validate_document(tmp_path)

        real_pdf = tmp_path / "real.pdf"
        real_pdf.write_bytes(_make_pdf_bytes())
        link_pdf = tmp_path / "link.pdf"
        link_pdf.symlink_to(real_pdf)

        with pytest.raises(InvalidDocumentError):
            validate_document(link_pdf)

    def test_rejects_file_exceeding_max_size(self, tmp_path: Path) -> None:
        pdf_path = tmp_path / "large.pdf"
        pdf_path.write_bytes(_make_pdf_bytes())
        limits = IngestionLimits(max_file_bytes=10)

        with pytest.raises(FileTooLargeError):
            validate_document(pdf_path, limits=limits)

    def test_rejects_docx_zip_bomb(self, tmp_path: Path) -> None:
        bomb = tmp_path / "bomb.docx"
        # Highly compressible 2MB payload compresses down to ~2KB (~1000x ratio)
        bomb.write_bytes(_make_minimal_docx_bytes(payload_size=2_000_000))
        limits = IngestionLimits(max_uncompressed_docx_bytes=1_000_000, max_compression_ratio=50.0)

        with pytest.raises(UnsafeArchiveError):
            validate_document(bomb, limits=limits)

    def test_rejects_encrypted_pdf(self, tmp_path: Path) -> None:
        locked = tmp_path / "locked.pdf"
        locked.write_bytes(_make_pdf_bytes(password="secret123"))

        with pytest.raises(EncryptedDocumentError):
            validate_document(locked)

    def test_validated_document_is_immutable(self, tmp_path: Path) -> None:
        pdf_path = tmp_path / "doc.pdf"
        pdf_path.write_bytes(_make_pdf_bytes())

        doc = validate_document(pdf_path)

        with pytest.raises(AttributeError):
            doc.size_bytes = 0  # type: ignore[misc]
