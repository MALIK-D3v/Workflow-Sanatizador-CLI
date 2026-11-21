"""100% offline Spanish NER engines (heuristic built-in + optional local spaCy)."""

from __future__ import annotations

import re

from opsec_sanitizer.domain.models import PiiCategory, PiiSpan

_CAP_WORD = r"[A-ZÁÉÍÓÚÑÜ][a-záéíóúñü]{1,24}"
_HSPACE = r"[ \t]+"
_PARTICLE = rf"(?:de(?:{_HSPACE}la|{_HSPACE}los)?|del)"
_NAME_SEQ = rf"(?P<name>{_CAP_WORD}(?:{_HSPACE}(?:{_PARTICLE}{_HSPACE})?{_CAP_WORD}){{1,3}})"

_HONORIFIC_PATTERN = re.compile(
    rf"\b(?:Lic\.|Ing\.|Dr\.|Dra\.|Mtro\.|Mtra\.|Arq\.|C\.P\.|C\.|Sr\.|Sra\.|Prof\.|Profa\.)"
    rf"{_HSPACE}{_NAME_SEQ}"
)
_LABEL_PATTERN = re.compile(
    rf"\b(?:Nombre|Firmado{_HSPACE}por|Atentamente|Remitente|Destinatario|Denunciante|Testigo)"
    rf"[ \t]*:[ \t]*{_NAME_SEQ}"
)
_STANDALONE_NAME_PATTERN = re.compile(rf"\b{_NAME_SEQ}\b")

_COMMON_GIVEN_NAMES = frozenset(
    {
        "alejandro", "alfonso", "alicia", "ana", "andrea", "andrés", "ángel", "antonio",
        "arturo", "beatriz", "carlos", "carmen", "carolina", "claudia", "cristina", "daniel",
        "david", "diego", "eduardo", "elena", "elizabeth", "enrique", "ernesto", "esteban",
        "fernando", "francisco", "gabriel", "gabriela", "gerardo", "guadalupe", "guillermo",
        "gustavo", "héctor", "hugo", "ignacio", "isabel", "iván", "jaime", "javier", "jesús",
        "jorge", "josé", "juan", "juana", "julia", "julio", "laura", "leticia", "lorenzo",
        "lucía", "luis", "luisa", "manuel", "marco", "marcos", "margarita", "maría", "mariana",
        "mario", "martha", "martín", "miguel", "mónica", "norma", "óscar", "pablo", "patricia",
        "pedro", "rafael", "ramón", "raúl", "ricardo", "roberto", "rocío", "rodrigo", "rosa",
        "rubén", "salvador", "sandra", "santiago", "sergio", "silvia", "sofía", "susana",
        "teresa", "verónica", "víctor", "yolanda",
    }
)

_INSTITUTION_STOPWORDS = frozenset(
    {
        "secretaría", "gobierno", "comisión", "instituto", "dirección", "subdirección",
        "coordinación", "fiscalía", "procuraduría", "tribunal", "consejo", "banco",
        "república", "estado", "municipio", "ayuntamiento", "ciudad", "méxico", "nacional",
        "federal", "pública", "público", "finanzas", "hacienda", "crédito", "salud",
        "educación", "oficio", "expediente", "contrato", "anexo", "capítulo", "artículo",
        "cargo", "asunto", "fecha", "enero", "febrero", "marzo", "abril", "mayo", "junio",
        "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre",
    }
)


def _contains_institution_word(phrase: str) -> bool:
    tokens = {tok.casefold() for tok in phrase.split()}
    return bool(tokens & _INSTITUTION_STOPWORDS)


class HeuristicSpanishNerEngine:
    """Zero-dependency offline Spanish personal-name NER for Mexican documents."""

    def detect_persons(self, text: str) -> tuple[PiiSpan, ...]:
        if not text:
            return ()

        found: list[PiiSpan] = []

        for pattern, conf in ((_HONORIFIC_PATTERN, 0.92), (_LABEL_PATTERN, 0.92)):
            for match in pattern.finditer(text):
                name = match.group("name")
                if not _contains_institution_word(name):
                    found.append(
                        PiiSpan(
                            start=match.start("name"),
                            end=match.end("name"),
                            category=PiiCategory.PERSON,
                            confidence=conf,
                            source="ner",
                        )
                    )

        for match in _STANDALONE_NAME_PATTERN.finditer(text):
            name = match.group("name")
            first_token = name.split()[0].casefold()
            if first_token in _COMMON_GIVEN_NAMES and not _contains_institution_word(name):
                found.append(
                    PiiSpan(
                        start=match.start("name"),
                        end=match.end("name"),
                        category=PiiCategory.PERSON,
                        confidence=0.82,
                        source="ner",
                    )
                )

        return tuple(found)


class SpacyNerEngine:
    """Offline spaCy NER adapter; loads pre-installed local model only (never downloads)."""

    def __init__(self, model_name: str = "es_core_news_md") -> None:
        try:
            import spacy
        except ImportError as exc:
            raise RuntimeError("spaCy is not installed; install optional extra [spacy]") from exc
        try:
            self._nlp = spacy.load(model_name)
        except OSError as exc:
            raise RuntimeError(
                f"Local spaCy model {model_name!r} is not installed offline"
            ) from exc

    def detect_persons(self, text: str) -> tuple[PiiSpan, ...]:
        if not text:
            return ()
        doc = self._nlp(text)
        return tuple(
            PiiSpan(
                start=ent.start_char,
                end=ent.end_char,
                category=PiiCategory.PERSON,
                confidence=0.88,
                source="ner",
            )
            for ent in doc.ents
            if ent.label_ == "PER"
        )
