"""Hybrid PII detector combining deterministic regex, offline NER, and allow/deny lists."""

from __future__ import annotations

import re
from collections.abc import Sequence

from opsec_sanitizer.detection.regex_mx import detect_regex_pii
from opsec_sanitizer.domain.models import PiiCategory, PiiSpan
from opsec_sanitizer.domain.ports import NerEngine

_SOURCE_PRIORITY: dict[str, int] = {
    "deny_list": 3,
    "regex": 2,
    "ner": 1,
}


def _find_deny_list_spans(text: str, deny_list: frozenset[str]) -> list[PiiSpan]:
    spans: list[PiiSpan] = []
    for raw_term in sorted(deny_list, key=len, reverse=True):
        term = raw_term.strip()
        if not term:
            continue
        left = r"(?<!\w)" if term[0].isalnum() or term[0] == "_" else ""
        right = r"(?!\w)" if term[-1].isalnum() or term[-1] == "_" else ""
        pattern = re.compile(rf"{left}{re.escape(term)}{right}", re.IGNORECASE)
        for match in pattern.finditer(text):
            spans.append(
                PiiSpan(
                    start=match.start(),
                    end=match.end(),
                    category=PiiCategory.DENY_LIST,
                    confidence=1.0,
                    source="deny_list",
                )
            )
    return spans


def _pick_higher_priority(a: PiiSpan, b: PiiSpan) -> PiiSpan:
    pa = _SOURCE_PRIORITY.get(a.source, 0)
    pb = _SOURCE_PRIORITY.get(b.source, 0)
    if pa != pb:
        return a if pa > pb else b
    return a if a.confidence >= b.confidence else b


def _resolve_overlaps(candidates: Sequence[PiiSpan]) -> tuple[PiiSpan, ...]:
    """Monotonically merge overlapping spans into their union, keeping highest priority label."""
    valid = sorted(
        (sp for sp in candidates if sp.end > sp.start),
        key=lambda sp: (sp.start, -sp.end),
    )
    if not valid:
        return ()

    merged: list[PiiSpan] = [valid[0]]
    for current in valid[1:]:
        prev = merged[-1]
        if current.start < prev.end:
            winner = _pick_higher_priority(prev, current)
            merged[-1] = PiiSpan(
                start=min(prev.start, current.start),
                end=max(prev.end, current.end),
                category=winner.category,
                confidence=max(prev.confidence, current.confidence),
                source=winner.source,
            )
        else:
            merged.append(current)
    return tuple(merged)


class HybridPiiDetector:
    """Combines Mexican regex detectors, offline NER, and explicit allow/deny lists."""

    def __init__(
        self,
        ner_engine: NerEngine | None = None,
        allow_list: frozenset[str] = frozenset(),
        deny_list: frozenset[str] = frozenset(),
    ) -> None:
        self._ner_engine = ner_engine
        self._allow_normalized = frozenset(t.strip().casefold() for t in allow_list if t.strip())
        self._deny_list = deny_list

    def detect(self, text: str) -> tuple[PiiSpan, ...]:
        """Return sorted, non-overlapping PII spans found in text."""
        if not text:
            return ()

        candidates: list[PiiSpan] = []
        candidates.extend(_find_deny_list_spans(text, self._deny_list))
        candidates.extend(detect_regex_pii(text))
        if self._ner_engine is not None:
            candidates.extend(self._ner_engine.detect_persons(text))

        filtered = [
            sp
            for sp in candidates
            if sp.source == "deny_list"
            or text[sp.start : sp.end].strip().casefold() not in self._allow_normalized
        ]
        return _resolve_overlaps(filtered)


def anonymize_text(text: str, spans: Sequence[PiiSpan]) -> str:
    """Replace detected PII spans with deterministic, non-reversible placeholders."""
    if not spans:
        return text

    ordered = sorted(spans, key=lambda sp: sp.start)
    counters: dict[PiiCategory, int] = {}
    token_map: dict[tuple[PiiCategory, str], str] = {}
    chunks: list[str] = []
    cursor = 0

    for span in ordered:
        if span.start < cursor:
            continue
        chunks.append(text[cursor : span.start])
        raw_val = text[span.start : span.end].strip().casefold()
        key = (span.category, raw_val)
        if key not in token_map:
            next_idx = counters.get(span.category, 0) + 1
            counters[span.category] = next_idx
            token_map[key] = f"[{span.category.value}_{next_idx}]"
        chunks.append(token_map[key])
        cursor = span.end

    chunks.append(text[cursor:])
    return "".join(chunks)
