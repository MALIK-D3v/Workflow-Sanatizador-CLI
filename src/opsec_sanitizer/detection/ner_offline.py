"""100% offline Spanish NER engines (heuristic built-in + optional local spaCy)."""

from __future__ import annotations

import re
import unicodedata

from opsec_sanitizer.domain.models import PiiCategory, PiiSpan

_TITLE_WORD = r"[A-ZÁÉÍÓÚÑÜ][a-záéíóúñü]{1,24}"
_UPPER_WORD = r"[A-ZÁÉÍÓÚÑÜ]{2,24}"
_NAME_WORD = rf"(?:{_TITLE_WORD}|{_UPPER_WORD})"
_HSPACE = r"[ \t]+"
_PARTICLE = rf"(?:(?:de|DE)(?:{_HSPACE}(?:la|LA|los|LOS))?|del|DEL)"
_NAME_SEQ = rf"(?P<name>{_NAME_WORD}(?:{_HSPACE}(?:{_PARTICLE}{_HSPACE})?{_NAME_WORD}){{1,3}})"

_HONORIFIC_PATTERN = re.compile(
    rf"\b(?:Lic\.|Ing\.|Dr\.|Dra\.|Mtro\.|Mtra\.|Arq\.|C\.P\.|C\.|Sr\.|Sra\.|Prof\.|Profa\.)"
    rf"{_HSPACE}{_NAME_SEQ}",
    re.IGNORECASE,
)
_LABEL_PATTERN = re.compile(
    rf"\b(?:Nombre|Firmado{_HSPACE}por|Atentamente|Remitente|Destinatario|Denunciante|Testigo)"
    rf"[ \t]*:[ \t]*{_NAME_SEQ}",
    re.IGNORECASE,
)
_STANDALONE_NAME_PATTERN = re.compile(rf"\b{_NAME_SEQ}\b")


def _fold_accents(value: str) -> str:
    nfkd = unicodedata.normalize("NFKD", value.casefold())
    return "".join(ch for ch in nfkd if not unicodedata.combining(ch))


_COMMON_GIVEN_NAMES = frozenset(
    _fold_accents(n)
    for n in (
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
    )
)

_INSTITUTION_STOPWORDS = frozenset(
    _fold_accents(w)
    for w in (
        "secretaría", "gobierno", "comisión", "instituto", "dirección", "subdirección",
        "coordinación", "fiscalía", "procuraduría", "tribunal", "consejo", "banco",
        "república", "estado", "municipio", "ayuntamiento", "ciudad", "méxico", "nacional",
        "federal", "pública", "público", "finanzas", "hacienda", "crédito", "salud",
        "educación", "oficio", "expediente", "contrato", "anexo", "capítulo", "artículo",
        "cargo", "asunto", "fecha", "curp", "rfc", "correo", "email", "teléfono", "tel",
        "enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto",
        "septiembre", "octubre", "noviembre", "diciembre",
    )
)


def _trim_at_stopword(text: str, start: int, end: int) -> tuple[int, int] | None:
    """Trim candidate name span at the first institutional stopword; require >=2 name tokens."""
    segment = text[start:end]
    tokens = list(re.finditer(r"\S+", segment))
    valid_end = 0
    kept_tokens = 0
    for tok in tokens:
        folded = _fold_accents(tok.group())
        if folded in _INSTITUTION_STOPWORDS:
            break
        valid_end = tok.end()
        if folded not in ("de", "la", "los", "del"):
            kept_tokens += 1
    if kept_tokens < 2 or valid_end <= 0:
        return None
    return start, start + valid_end


class HeuristicSpanishNerEngine:
    """Zero-dependency offline Spanish personal-name NER for Mexican documents."""

    def detect_persons(self, text: str) -> tuple[PiiSpan, ...]:
        if not text:
            return ()

        found: list[PiiSpan] = []

        for pattern, conf in ((_HONORIFIC_PATTERN, 0.92), (_LABEL_PATTERN, 0.92)):
            for match in pattern.finditer(text):
                trimmed = _trim_at_stopword(text, match.start("name"), match.end("name"))
                if trimmed is not None:
                    s, e = trimmed
                    found.append(
                        PiiSpan(
                            start=s,
                            end=e,
                            category=PiiCategory.PERSON,
                            confidence=conf,
                            source="ner",
                        )
                    )

        for match in _STANDALONE_NAME_PATTERN.finditer(text):
            trimmed = _trim_at_stopword(text, match.start("name"), match.end("name"))
            if trimmed is None:
                continue
            s, e = trimmed
            first_token = _fold_accents(text[s:e].split()[0])
            if first_token in _COMMON_GIVEN_NAMES:
                found.append(
                    PiiSpan(
                        start=s,
                        end=e,
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
