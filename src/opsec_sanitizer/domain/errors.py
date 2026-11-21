"""Typed domain exceptions for fail-closed OPSEC processing."""

from __future__ import annotations


class SanitizerError(Exception):
    """Base error for all OPSEC sanitizer failures."""


class DocumentNotFoundError(SanitizerError):
    """Input document path does not exist."""


class InvalidDocumentError(SanitizerError):
    """Input path is empty, a directory, a disallowed symlink, or unreadable."""


class UnsupportedFormatError(SanitizerError):
    """File magic bytes do not match a supported document format."""


class FileTooLargeError(SanitizerError):
    """Input file exceeds configured byte size limits."""


class UnsafeArchiveError(SanitizerError):
    """Archive exhibits zip-bomb, path traversal, or unsafe compression ratios."""


class EncryptedDocumentError(SanitizerError):
    """Input document is encrypted or password-protected."""


class ForensicLeakError(SanitizerError):
    """Post-sanitization forensic verification detected residual metadata or PII."""
