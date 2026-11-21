"""Deterministic Mexican PII detectors (CURP, RFC, email, phone)."""

from __future__ import annotations

import datetime
import re

from opsec_sanitizer.domain.models import PiiCategory, PiiSpan

_CURP_ALPHABET = "0123456789ABCDEFGHIJKLMNÑOPQRSTUVWXYZ"
_CURP_STATES = frozenset(
    {
        "AS", "BC", "BS", "CC", "CL", "CM", "CS", "CH", "DF", "DG", "GT",
        "GR", "HG", "JC", "MC", "MN", "MS", "NT", "NL", "OC", "PL", "QT",
        "QR", "SP", "SL", "SR", "TC", "TS", "TL", "VZ", "YN", "ZS", "NE",
    }
)

_CURP_PATTERN = re.compile(
    r"\b([A-Z][AEIOUX][A-Z]{2}\d{6}[HMX][A-Z]{2}[B-DF-HJ-NP-TV-Z]{3}[0-9A-Z]\d)\b"
)
_RFC_PATTERN = re.compile(
    r"(?<![A-Z0-9Ñ&])([A-ZÑ&]{3,4}\d{6}[A-Z0-9]{2}[0-9A])(?![A-Z0-9Ñ&])"
)
_EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
_PHONE_PATTERN = re.compile(
    r"(?<!\d)(?:\+52[\s.-]?(?:1[\s.-]?)?)?"
    r"(?:\(\d{2,3}\)[\s.-]?\d{3,4}[\s.-]?\d{4}|\d{2,3}[\s.-]\d{3,4}[\s.-]\d{4})(?!\d)"
)


def _is_valid_yymmdd(yymmdd: str) -> bool:
    if len(yymmdd) != 6 or not yymmdd.isdigit():
        return False
    yy, mm, dd = int(yymmdd[0:2]), int(yymmdd[2:4]), int(yymmdd[4:6])
    try:
        datetime.date(2000 + yy, mm, dd)
    except ValueError:
        return False
    return True


def compute_curp_check_digit(curp_prefix_17: str) -> str:
    """Compute official RENAPO check digit (position 18) for a 17-char CURP prefix."""
    normalized = curp_prefix_17.upper()
    if len(normalized) != 17:
        raise ValueError("CURP prefix must be exactly 17 characters")
    total = 0
    for idx, ch in enumerate(normalized):
        pos = _CURP_ALPHABET.find(ch)
        if pos < 0:
            raise ValueError(f"Unsupported character in CURP prefix: {ch!r}")
        total += pos * (18 - idx)
    digit = (10 - (total % 10)) % 10
    return str(digit)


def is_valid_curp(candidate: str) -> bool:
    """Return True if candidate matches CURP format, state, date, and check digit."""
    upper = candidate.upper()
    if len(upper) != 18 or not _CURP_PATTERN.fullmatch(upper):
        return False
    if not _is_valid_yymmdd(upper[4:10]):
        return False
    if upper[11:13] not in _CURP_STATES:
        return False
    return compute_curp_check_digit(upper[:17]) == upper[17]


def is_valid_rfc(candidate: str) -> bool:
    """Return True if candidate matches Mexican RFC (12 or 13 chars) with valid date."""
    upper = candidate.upper()
    if len(upper) not in (12, 13) or not _RFC_PATTERN.fullmatch(upper):
        return False
    date_offset = 3 if len(upper) == 12 else 4
    return _is_valid_yymmdd(upper[date_offset : date_offset + 6])


def detect_regex_pii(text: str) -> tuple[PiiSpan, ...]:
    """Detect CURP, RFC, email, and Mexican phone spans in text without mutating it."""
    if not text:
        return ()

    spans: list[PiiSpan] = []
    occupied: list[tuple[int, int]] = []

    def _overlaps(start: int, end: int) -> bool:
        return any(not (end <= s or start >= e) for s, e in occupied)

    for match in _CURP_PATTERN.finditer(text):
        if is_valid_curp(match.group(1)):
            s, e = match.span(1)
            spans.append(PiiSpan(start=s, end=e, category=PiiCategory.CURP, confidence=1.0))
            occupied.append((s, e))

    for match in _RFC_PATTERN.finditer(text):
        s, e = match.span(1)
        if not _overlaps(s, e) and is_valid_rfc(match.group(1)):
            spans.append(PiiSpan(start=s, end=e, category=PiiCategory.RFC, confidence=0.98))
            occupied.append((s, e))

    for match in _EMAIL_PATTERN.finditer(text):
        s, e = match.span()
        if not _overlaps(s, e):
            spans.append(PiiSpan(start=s, end=e, category=PiiCategory.EMAIL, confidence=0.99))
            occupied.append((s, e))

    for match in _PHONE_PATTERN.finditer(text):
        s, e = match.span()
        digits = "".join(ch for ch in match.group() if ch.isdigit())
        if len(digits) in (10, 12, 13) and not _overlaps(s, e):
            spans.append(PiiSpan(start=s, end=e, category=PiiCategory.PHONE, confidence=0.9))
            occupied.append((s, e))

    spans.sort(key=lambda sp: (sp.start, sp.end))
    return tuple(spans)
