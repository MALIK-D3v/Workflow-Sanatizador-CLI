"""Domain port protocols for dependency inversion (NER, OCR, DOCX rendering)."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from PIL import Image

from opsec_sanitizer.domain.models import OcrWord, PiiSpan


class NerEngine(Protocol):
    """Offline Named Entity Recognition engine detecting personal names."""

    def detect_persons(self, text: str) -> tuple[PiiSpan, ...]: ...


class OcrEngine(Protocol):
    """Offline Optical Character Recognition engine returning word-level boxes."""

    def extract_words(self, image: Image.Image) -> tuple[OcrWord, ...]: ...


class DocxRenderer(Protocol):
    """Converts a pre-cleaned DOCX file into a temporary PDF for flattening."""

    def render_to_pdf(self, docx_path: Path, output_dir: Path) -> Path: ...
