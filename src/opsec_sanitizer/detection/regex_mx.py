"""Deterministic Mexican PII & network detectors (CURP, RFC, CLABE, NSS, INE, IP, email, phone)."""

from __future__ import annotations

import datetime
import ipaddress
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
_INE_STATES = frozenset({f"{i:02d}" for i in range(1, 33)} | {"87"})
_CLABE_WEIGHTS = (3, 7, 1)

_CURP_PATTERN = re.compile(
    r"\b([A-Z][AEIOUX][A-Z]{2}\d{6}[HMX][A-Z]{2}[B-DF-HJ-NP-TV-Z]{3}[0-9A-Z]\d)\b",
    re.IGNORECASE,
)
_INE_CLAVE_PATTERN = re.compile(
    r"\b([B-DF-HJ-NP-TV-Z]{6}\d{6}(?:0[1-9]|[12]\d|3[0-2]|87)[HM]\d{3})\b",
    re.IGNORECASE,
)
_INE_IDMEX_PATTERN = re.compile(r"\b(IDMEX\d{10,13})\b", re.IGNORECASE)
_RFC_PATTERN = re.compile(
    r"(?<![A-Z0-9Ñ&])([A-ZÑ&]{3,4}-?\d{6}-?[A-Z0-9]{2}[0-9A])(?![A-Z0-9Ñ&])",
    re.IGNORECASE,
)
_CLABE_PATTERN = re.compile(r"(?<!\d)(\d{18})(?!\d)")
_NSS_HYPHEN_PATTERN = re.compile(r"(?<!\d)(\d{2}-\d{2}-\d{2}-\d{4}-\d)(?!\d)")
_NSS_LABELED_PATTERN = re.compile(
    r"\b(?:NSS|IMSS|Seguro\s+Social|Seguridad\s+Social)\s*(?::|No\.?|#)?\s*(\d{11})(?!\d)",
    re.IGNORECASE,
)
_EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
_IPV4_PATTERN = re.compile(
    r"(?<![A-Za-z0-9._])"
    r"((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})"
    r"(?![.\d])"
)
_IPV6_CANDIDATE_PATTERN = re.compile(r"(?<![A-Za-z0-9:])([0-9A-Fa-f:]{4,39})(?![A-Za-z0-9:])")
_PHONE_PATTERN = re.compile(
    r"(?<!\d)(?:"
    r"\+52[\s.-]?(?:1[\s.-]?)?\d{10}"
    r"|(?:\+52[\s.-]?(?:1[\s.-]?)?)?"
    r"(?:\(\d{2,3}\)[\s.-]?\d{3,4}[\s.-]?\d{4}"
    r"|\d{2,3}[\s.-]\d{3,4}[\s.-]\d{4}"
    r"|\d{2}[\s.-]\d{2}[\s.-]\d{2}[\s.-]\d{2}[\s.-]\d{2}"
    r"|\d{2,3}-\d{7,8})"
    r")(?!\d)"
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
    return str((10 - (total % 10)) % 10)


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
    """Return True if candidate matches Mexican RFC (12 or 13 chars, optional hyphens)."""
    compact = candidate.replace("-", "").upper()
    if len(compact) not in (12, 13) or not _RFC_PATTERN.fullmatch(compact):
        return False
    date_offset = 3 if len(compact) == 12 else 4
    return _is_valid_yymmdd(compact[date_offset : date_offset + 6])


def compute_clabe_check_digit(clabe_prefix_17: str) -> str:
    """Compute Banxico CLABE check digit (position 18) for a 17-digit prefix."""
    if len(clabe_prefix_17) != 17 or not clabe_prefix_17.isdigit():
        raise ValueError("CLABE prefix must be exactly 17 digits")
    total = 0
    for idx, ch in enumerate(clabe_prefix_17):
        weight = _CLABE_WEIGHTS[idx % 3]
        total += (int(ch) * weight) % 10
    return str((10 - (total % 10)) % 10)


def is_valid_clabe(candidate: str) -> bool:
    """Return True if candidate is a valid 18-digit Mexican CLABE with Banxico check digit."""
    if len(candidate) != 18 or not candidate.isdigit():
        return False
    return compute_clabe_check_digit(candidate[:17]) == candidate[17]


def compute_nss_check_digit(nss_prefix_10: str) -> str:
    """Compute IMSS modified-Luhn check digit (position 11) for a 10-digit NSS prefix."""
    if len(nss_prefix_10) != 10 or not nss_prefix_10.isdigit():
        raise ValueError("NSS prefix must be exactly 10 digits")
    total = 0
    for idx, ch in enumerate(nss_prefix_10):
        weight = 1 if idx % 2 == 0 else 2
        prod = int(ch) * weight
        total += (prod // 10) + (prod % 10)
    return str((10 - (total % 10)) % 10)


def is_valid_nss(candidate: str) -> bool:
    """Return True if candidate is a valid 11-digit IMSS NSS (optional hyphens)."""
    compact = candidate.replace("-", "")
    if len(compact) != 11 or not compact.isdigit():
        return False
    if compact[:2] == "00":
        return False
    return compute_nss_check_digit(compact[:10]) == compact[10]


def is_valid_ine_clave(candidate: str) -> bool:
    """Return True if candidate matches Mexican INE Clave de Elector (18 chars)."""
    upper = candidate.upper()
    if len(upper) != 18 or not _INE_CLAVE_PATTERN.fullmatch(upper):
        return False
    if not _is_valid_yymmdd(upper[6:12]):
        return False
    return upper[12:14] in _INE_STATES


def _is_valid_ipv6(candidate: str) -> bool:
    if candidate.count(":") < 2:
        return False
    try:
        ipaddress.IPv6Address(candidate)
    except ValueError:
        return False
    return True


def detect_regex_pii(text: str) -> tuple[PiiSpan, ...]:
    """Detect CURP, RFC, CLABE, NSS, INE, IP, email, and Mexican phone spans in text."""
    if not text:
        return ()

    spans: list[PiiSpan] = []
    occupied: list[tuple[int, int]] = []

    def _overlaps(start: int, end: int) -> bool:
        return any(not (end <= s or start >= e) for s, e in occupied)

    def _add(start: int, end: int, category: PiiCategory, confidence: float) -> None:
        if not _overlaps(start, end):
            spans.append(PiiSpan(start=start, end=end, category=category, confidence=confidence))
            occupied.append((start, end))

    for m in _CURP_PATTERN.finditer(text):
        if is_valid_curp(m.group(1)):
            _add(*m.span(1), PiiCategory.CURP, 1.0)

    for m in _INE_CLAVE_PATTERN.finditer(text):
        if is_valid_ine_clave(m.group(1)):
            _add(*m.span(1), PiiCategory.INE, 0.98)

    for m in _INE_IDMEX_PATTERN.finditer(text):
        _add(*m.span(1), PiiCategory.INE, 0.99)

    for m in _RFC_PATTERN.finditer(text):
        if is_valid_rfc(m.group(1)):
            _add(*m.span(1), PiiCategory.RFC, 0.98)

    for m in _CLABE_PATTERN.finditer(text):
        if is_valid_clabe(m.group(1)):
            _add(*m.span(1), PiiCategory.CLABE, 0.99)

    for m in _NSS_HYPHEN_PATTERN.finditer(text):
        if is_valid_nss(m.group(1)):
            _add(*m.span(1), PiiCategory.NSS, 0.98)

    for m in _NSS_LABELED_PATTERN.finditer(text):
        if is_valid_nss(m.group(1)):
            _add(*m.span(1), PiiCategory.NSS, 0.97)

    for m in _EMAIL_PATTERN.finditer(text):
        _add(*m.span(), PiiCategory.EMAIL, 0.99)

    for m in _IPV4_PATTERN.finditer(text):
        _add(*m.span(1), PiiCategory.IP_ADDRESS, 0.95)

    for m in _IPV6_CANDIDATE_PATTERN.finditer(text):
        if _is_valid_ipv6(m.group(1)):
            _add(*m.span(1), PiiCategory.IP_ADDRESS, 0.96)

    for m in _PHONE_PATTERN.finditer(text):
        digits = "".join(ch for ch in m.group() if ch.isdigit())
        if len(digits) in (10, 12, 13):
            _add(*m.span(), PiiCategory.PHONE, 0.9)

    spans.sort(key=lambda sp: (sp.start, sp.end))
    return tuple(spans)
