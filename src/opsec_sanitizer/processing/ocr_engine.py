"""Offline OCR engine adapters (bundled ONNX RapidOCR + optional local Tesseract)."""

from __future__ import annotations

import os
import shutil
import tempfile
from typing import Any

import numpy as np
from PIL import Image

from opsec_sanitizer.domain.models import BBox, OcrWord
from opsec_sanitizer.domain.ports import OcrEngine
from opsec_sanitizer.io_utils import ram_tmp_root


def _split_line_to_words(text: str, box: BBox, confidence: float) -> list[OcrWord]:
    stripped = text.strip()
    if not stripped:
        return []
    tokens = stripped.split()
    if len(tokens) == 1:
        return [OcrWord(text=tokens[0], bbox=box, confidence=confidence, line_bbox=box)]

    total_chars = max(len(stripped), 1)
    width = box.x1 - box.x0
    words: list[OcrWord] = []
    cursor = 0
    for token in tokens:
        idx = stripped.find(token, cursor)
        if idx < 0:
            idx = cursor
        wx0 = box.x0 + width * (idx / total_chars)
        wx1 = box.x0 + width * ((idx + len(token)) / total_chars)
        words.append(
            OcrWord(
                text=token,
                bbox=BBox(x0=wx0, y0=box.y0, x1=wx1, y1=box.y1),
                confidence=confidence,
                line_bbox=box,
            )
        )
        cursor = idx + len(token)
    return words


class RapidOcrEngine:
    """100% offline OCR engine using bundled ONNX Runtime models (no network calls)."""

    def __init__(self) -> None:
        from rapidocr_onnxruntime import RapidOCR

        self._engine: Any = RapidOCR()

    def extract_words(self, image: Image.Image) -> tuple[OcrWord, ...]:
        rgb = image.convert("RGB")
        arr = np.asarray(rgb)
        results, _ = self._engine(arr)
        if not results:
            return ()

        words: list[OcrWord] = []
        for entry in results:
            quad, text, score = entry[0], str(entry[1]), float(entry[2])
            xs = [float(pt[0]) for pt in quad]
            ys = [float(pt[1]) for pt in quad]
            line_box = BBox(x0=min(xs), y0=min(ys), x1=max(xs), y1=max(ys))
            words.extend(_split_line_to_words(text, line_box, score))
        return tuple(words)


class TesseractOcrEngine:
    """Offline OCR adapter backed by local Tesseract CLI using RAM tmpdir when available."""

    def __init__(self, lang: str = "spa+eng") -> None:
        if shutil.which("tesseract") is None:
            raise RuntimeError("Local 'tesseract' binary not found on PATH")
        self._lang = lang

    def extract_words(self, image: Image.Image) -> tuple[OcrWord, ...]:
        import pytesseract

        prev_tmpdir = os.environ.get("TMPDIR")
        with tempfile.TemporaryDirectory(prefix="opsec_ocr_", dir=ram_tmp_root()) as tmp_dir:
            os.environ["TMPDIR"] = tmp_dir
            try:
                data: dict[str, list[Any]] = pytesseract.image_to_data(
                    image.convert("RGB"),
                    lang=self._lang,
                    output_type=pytesseract.Output.DICT,
                )
            finally:
                if prev_tmpdir is None:
                    os.environ.pop("TMPDIR", None)
                else:
                    os.environ["TMPDIR"] = prev_tmpdir

        words: list[OcrWord] = []
        count = len(data.get("text", []))
        for i in range(count):
            text = str(data["text"][i]).strip()
            if not text or float(data["conf"][i]) < 0:
                continue
            x, y = float(data["left"][i]), float(data["top"][i])
            w, h = float(data["width"][i]), float(data["height"][i])
            words.append(
                OcrWord(
                    text=text,
                    bbox=BBox(x0=x, y0=y, x1=x + w, y1=y + h),
                    confidence=float(data["conf"][i]) / 100.0,
                )
            )
        return tuple(words)


def create_default_ocr_engine(preferred: str = "auto") -> OcrEngine:
    """Create an offline OCR engine without any network dependency."""
    if preferred == "tesseract":
        return TesseractOcrEngine()
    if preferred == "rapidocr":
        return RapidOcrEngine()
    if preferred == "auto":
        try:
            return RapidOcrEngine()
        except Exception:
            return TesseractOcrEngine()
    raise ValueError(f"Unknown OCR engine preference: {preferred!r}")
