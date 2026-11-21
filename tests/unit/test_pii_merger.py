"""Unit tests for hybrid PII detection, span merging, and offline NER."""

from __future__ import annotations

from opsec_sanitizer.detection.merger import HybridPiiDetector, anonymize_text
from opsec_sanitizer.detection.ner_offline import HeuristicSpanishNerEngine
from opsec_sanitizer.detection.regex_mx import compute_curp_check_digit
from opsec_sanitizer.domain.models import PiiCategory, PiiSpan


class _FakeNerEngine:
    def __init__(self, spans: tuple[PiiSpan, ...]) -> None:
        self._spans = spans

    def detect_persons(self, text: str) -> tuple[PiiSpan, ...]:
        return self._spans


class TestHybridPiiDetector:
    def test_merges_overlapping_spans_preferring_regex_over_ner(self) -> None:
        text = "Correo de juan.perez@correo.mx enviado hoy."
        email_start = text.index("juan.perez@correo.mx")
        email_end = email_start + len("juan.perez@correo.mx")
        # Simulate NER mistakenly tagging "juan.perez" inside the email
        ner = _FakeNerEngine(
            spans=(
                PiiSpan(
                    start=email_start,
                    end=email_start + 10,
                    category=PiiCategory.PERSON,
                    confidence=0.75,
                    source="ner",
                ),
            )
        )
        detector = HybridPiiDetector(ner_engine=ner)

        spans = detector.detect(text)

        assert len(spans) == 1
        assert spans[0].category == PiiCategory.EMAIL
        assert (spans[0].start, spans[0].end) == (email_start, email_end)

    def test_respects_allow_list_and_deny_list(self) -> None:
        text = "Secretaría de Hacienda notificó a Alias Halcón y a María López."
        sec_start = text.index("Secretaría de Hacienda")
        ner = _FakeNerEngine(
            spans=(
                PiiSpan(
                    start=sec_start,
                    end=sec_start + len("Secretaría de Hacienda"),
                    category=PiiCategory.PERSON,
                    confidence=0.6,
                    source="ner",
                ),
            )
        )
        detector = HybridPiiDetector(
            ner_engine=ner,
            allow_list=frozenset({"Secretaría de Hacienda"}),
            deny_list=frozenset({"Alias Halcón"}),
        )

        spans = detector.detect(text)

        matched = [(s.category, text[s.start : s.end]) for s in spans]
        assert (PiiCategory.DENY_LIST, "Alias Halcón") in matched
        assert all(val != "Secretaría de Hacienda" for _, val in matched)

    def test_handles_empty_text_and_unicode_offsets(self) -> None:
        prefix = "GOPA850714HDFLRN0"
        curp = f"{prefix}{compute_curp_check_digit(prefix)}"
        text = f"Año 2026 — Señalización de Ñandú — CURP: {curp}"
        detector = HybridPiiDetector(ner_engine=_FakeNerEngine(spans=()))

        assert detector.detect("") == ()
        spans = detector.detect(text)
        assert len(spans) == 1
        assert text[spans[0].start : spans[0].end] == curp

    def test_anonymize_text_replaces_spans_with_stable_tokens(self) -> None:
        text = "De: ana@ejemplo.mx Para: ana@ejemplo.mx RFC ABC9912319Z0"
        detector = HybridPiiDetector(ner_engine=_FakeNerEngine(spans=()))
        spans = detector.detect(text)

        sanitized = anonymize_text(text, spans)

        assert "ana@ejemplo.mx" not in sanitized
        assert "ABC9912319Z0" not in sanitized
        assert "[EMAIL_1]" in sanitized
        assert "[RFC_1]" in sanitized
        # Same email gets the same consistent token within the document
        assert sanitized.count("[EMAIL_1]") == 2


class TestHeuristicSpanishNerEngine:
    def test_detects_mexican_names_with_honorifics_and_given_names(self) -> None:
        engine = HeuristicSpanishNerEngine()
        text = (
            "El oficio fue firmado por Lic. Carlos Mendoza Hernández y revisado por "
            "María Guadalupe Torres en la Secretaría de Finanzas."
        )

        spans = engine.detect_persons(text)
        names = [text[s.start : s.end] for s in spans]

        assert "Carlos Mendoza Hernández" in names
        assert "María Guadalupe Torres" in names
        assert all("Secretaría" not in n for n in names)

    def test_detects_name_after_label_prompt(self) -> None:
        engine = HeuristicSpanishNerEngine()
        text = "Nombre: Roberto Castillo Vega\nCargo: Subdirector"

        spans = engine.detect_persons(text)
        names = [text[s.start : s.end] for s in spans]

        assert "Roberto Castillo Vega" in names
