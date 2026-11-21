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
        pattern = re.compile(rf"(?<!\w){re.escape(term)}(?!\w)", re.IGNORECASE)
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


def _resolve_overlaps(candidates: Sequence[PiiSpan]) -> tuple[PiiSpan, ...]:
    ordered = sorted(
        candidates,
        key=lambda sp: (
            -_SOURCE_PRIORITY.get(sp.source, 0),
            -(sp.end - sp.start),
            -sp.confidence,
            sp.start,
        ),
    )
    accepted: list[PiiSpan] = []
    for span in ordered:
        if span.end <= span.start:
            continue
        overlaps = any(not (span.end <= a.start or span.start >= a.end) for a in accepted)
        if not overlaps:
            accepted.append(span)
    accepted.sort(key=lambda sp: (sp.start, sp.end))
    return tuple(accepted)


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
