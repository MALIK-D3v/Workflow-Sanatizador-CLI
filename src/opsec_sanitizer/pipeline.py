"""End-to-end OPSEC document sanitization pipeline with fail-closed staging."""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opsec_sanitizer.detection.merger import HybridPiiDetector
from opsec_sanitizer.detection.ner_offline import HeuristicSpanishNerEngine, SpacyNerEngine
from opsec_sanitizer.domain.errors import InvalidDocumentError, SanitizerError
from opsec_sanitizer.domain.models import BBox, DocumentType, IngestionLimits, PiiCategory
from opsec_sanitizer.domain.ports import DocxRenderer, NerEngine, OcrEngine
from opsec_sanitizer.ingestion.validator import validate_document
from opsec_sanitizer.processing.docx_sanitizer import sanitize_docx_to_pdf
from opsec_sanitizer.processing.image_sanitizer import redact_image_boxes, strip_image_to_clean_rgb
from opsec_sanitizer.processing.ocr_engine import create_default_ocr_engine
from opsec_sanitizer.processing.pdf_flattener import (
    FlattenOptions,
    FlattenResult,
    build_pdf_from_clean_images,
    flatten_pdf,
    map_spans_to_word_boxes,
)
from opsec_sanitizer.verification.forensic_gate import (
    verify_image_forensically,
    verify_pdf_forensically,
)

_CHUNK_SIZE = 65_536


@dataclass(frozen=True)
class SanitizeConfig:
    """Immutable configuration for an OPSEC sanitization run."""

    dpi: int = 200
    padding_px: int = 4
    enable_ocr: bool = True
    paranoid_denoise: bool = False
    dry_run: bool = False
    allow_list: frozenset[str] = field(default_factory=frozenset)
    deny_list: frozenset[str] = field(default_factory=frozenset)
    limits: IngestionLimits = field(default_factory=IngestionLimits)
    ocr_preference: str = "auto"
    ner_mode: str = "heuristic"


@dataclass(frozen=True)
class AuditReport:
    """OPSEC-safe audit summary (strictly free of raw PII values)."""

    input_name: str
    doc_type: DocumentType
    input_sha256: str
    output_sha256: str
    page_count: int
    metadata_keys_removed: tuple[str, ...]
    attachments_removed: int
    annotations_removed: int
    pii_counts: dict[PiiCategory, int]
    forensic_verified: bool
    dry_run: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_name": self.input_name,
            "doc_type": self.doc_type.value,
            "input_sha256": self.input_sha256,
            "output_sha256": self.output_sha256,
            "page_count": self.page_count,
            "metadata_keys_removed": list(self.metadata_keys_removed),
            "attachments_removed": self.attachments_removed,
            "annotations_removed": self.annotations_removed,
            "pii_counts": {k.value: v for k, v in sorted(self.pii_counts.items())},
            "forensic_verified": self.forensic_verified,
            "dry_run": self.dry_run,
        }


@dataclass(frozen=True)
class BatchFailure:
    """Isolated failure entry for a single document in a batch run."""

    file: str
    error_type: str
    message: str


@dataclass(frozen=True)
class BatchReport:
    """Aggregated audit report for a directory batch run."""

    succeeded: tuple[AuditReport, ...]
    failed: tuple[BatchFailure, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "succeeded": [r.to_dict() for r in self.succeeded],
            "failed": [
                {"file": f.file, "error_type": f.error_type, "message": f.message}
                for f in self.failed
            ],
        }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(_CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def _ram_tmp_root() -> str | None:
    shm = Path("/dev/shm")  # noqa: S108
    if shm.is_dir() and os.access(shm, os.W_OK):
        return str(shm)
    return None


def _build_ner_engine(mode: str) -> NerEngine | None:
    if mode == "none":
        return None
    if mode == "heuristic":
        return HeuristicSpanishNerEngine()
    if mode == "spacy":
        return SpacyNerEngine()
    raise ValueError(f"Unsupported ner_mode: {mode!r}")


def _process_image_document(
    source_path: Path,
    staged_output: Path,
    *,
    detector: HybridPiiDetector,
    ocr_engine: OcrEngine | None,
    config: SanitizeConfig,
) -> FlattenResult:
    clean_img, removed_keys = strip_image_to_clean_rgb(
        source_path, paranoid_denoise=config.paranoid_denoise
    )
    pii_counts: dict[PiiCategory, int] = {}
    pixel_boxes: tuple[BBox, ...] = ()

    if ocr_engine is not None:
        ocr_words = ocr_engine.extract_words(clean_img)
        word_pairs = [(w.text, w.bbox) for w in ocr_words]
        if word_pairs:
            joined = " ".join(w for w, _ in word_pairs)
            spans = detector.detect(joined)
            for sp in spans:
                pii_counts[sp.category] = pii_counts.get(sp.category, 0) + 1
            pixel_boxes = map_spans_to_word_boxes(word_pairs, spans)

    redacted_img = redact_image_boxes(clean_img, pixel_boxes, padding_px=config.padding_px)

    if staged_output.suffix.lower() == ".pdf":
        inv_scale = 72.0 / float(config.dpi)
        width_pt = float(redacted_img.width) * inv_scale
        height_pt = float(redacted_img.height) * inv_scale
        build_pdf_from_clean_images(
            [(redacted_img, width_pt, height_pt)],
            staged_output,
            dpi=config.dpi,
            ocr_engine=ocr_engine,
            enable_ocr=config.enable_ocr,
        )
    else:
        staged_output.parent.mkdir(parents=True, exist_ok=True)
        redacted_img.save(staged_output, format="PNG", optimize=True)

    return FlattenResult(
        page_count=1,
        metadata_keys_removed=removed_keys,
        attachments_removed=0,
        annotations_removed=0,
        pii_counts=pii_counts,
    )


def sanitize_document(
    input_path: Path,
    output_path: Path | None,
    *,
    config: SanitizeConfig | None = None,
    ocr_engine: OcrEngine | None = None,
    docx_renderer: DocxRenderer | None = None,
    custom_verifier: Callable[[Path], Any] | None = None,
) -> AuditReport:
    """Validate, flatten, redact, forensically verify, and deliver a sanitized document."""
    cfg = config or SanitizeConfig()
    validated = validate_document(input_path, limits=cfg.limits)

    if not cfg.dry_run:
        if output_path is None:
            raise InvalidDocumentError("Output path is required unless dry_run=True")
        if output_path.is_symlink():
            raise InvalidDocumentError("Refusing to write to a symbolic link target")

    detector = HybridPiiDetector(
        ner_engine=_build_ner_engine(cfg.ner_mode),
        allow_list=cfg.allow_list,
        deny_list=cfg.deny_list,
    )
    active_ocr = ocr_engine
    if active_ocr is None and cfg.enable_ocr:
        active_ocr = create_default_ocr_engine(cfg.ocr_preference)

    flatten_opts = FlattenOptions(
        dpi=cfg.dpi,
        padding_px=cfg.padding_px,
        enable_ocr=cfg.enable_ocr,
        paranoid_denoise=cfg.paranoid_denoise,
    )

    is_image_png_out = (
        validated.doc_type == DocumentType.IMAGE
        and output_path is not None
        and output_path.suffix.lower() != ".pdf"
    )
    staged_ext = ".png" if is_image_png_out else ".pdf"

    with tempfile.TemporaryDirectory(prefix="opsec_stage_", dir=_ram_tmp_root()) as tmp_dir:
        staged_path = Path(tmp_dir) / f"staged{staged_ext}"
        if validated.doc_type == DocumentType.PDF:
            res = flatten_pdf(
                validated.path,
                staged_path,
                detector=detector,
                ocr_engine=active_ocr,
                options=flatten_opts,
            )
        elif validated.doc_type == DocumentType.DOCX:
            res = sanitize_docx_to_pdf(
                validated.path,
                staged_path,
                detector=detector,
                renderer=docx_renderer,
                ocr_engine=active_ocr,
                options=flatten_opts,
            )
        else:
            res = _process_image_document(
                validated.path,
                staged_path,
                detector=detector,
                ocr_engine=active_ocr,
                config=cfg,
            )

        if cfg.dry_run:
            return AuditReport(
                input_name=input_path.name,
                doc_type=validated.doc_type,
                input_sha256=validated.sha256_hex,
                output_sha256="",
                page_count=res.page_count,
                metadata_keys_removed=res.metadata_keys_removed,
                attachments_removed=res.attachments_removed,
                annotations_removed=res.annotations_removed,
                pii_counts=res.pii_counts,
                forensic_verified=False,
                dry_run=True,
            )

        # Fail-closed forensic verification BEFORE delivering output_path
        if custom_verifier is not None:
            custom_verifier(staged_path)
        elif staged_ext == ".png":
            verify_image_forensically(staged_path)
        else:
            verify_pdf_forensically(staged_path, detector=detector)

        out_sha256 = _sha256_file(staged_path)
        assert output_path is not None
        output_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(staged_path, output_path)

    return AuditReport(
        input_name=input_path.name,
        doc_type=validated.doc_type,
        input_sha256=validated.sha256_hex,
        output_sha256=out_sha256,
        page_count=res.page_count,
        metadata_keys_removed=res.metadata_keys_removed,
        attachments_removed=res.attachments_removed,
        annotations_removed=res.annotations_removed,
        pii_counts=res.pii_counts,
        forensic_verified=True,
        dry_run=False,
    )


def _default_batch_output_name(entry: Path) -> str:
    ext = entry.suffix.lower()
    if ext in (".jpg", ".jpeg", ".png", ".tif", ".tiff", ".webp"):
        return f"{entry.stem}.sanitized.png"
    return f"{entry.stem}.sanitized.pdf"


def sanitize_batch(
    input_dir: Path,
    output_dir: Path,
    *,
    config: SanitizeConfig | None = None,
) -> BatchReport:
    """Sanitize all regular non-hidden files in input_dir, isolating failures per file."""
    if not input_dir.is_dir():
        raise InvalidDocumentError(f"Input directory does not exist: {input_dir.name}")
    cfg = config or SanitizeConfig()
    if not cfg.dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)

    succeeded: list[AuditReport] = []
    failed: list[BatchFailure] = []

    for entry in sorted(input_dir.iterdir()):
        if entry.name.startswith(".") or entry.is_dir():
            continue
        target = output_dir / _default_batch_output_name(entry)
        try:
            report = sanitize_document(entry, target, config=cfg)
            succeeded.append(report)
        except SanitizerError as exc:
            failed.append(
                BatchFailure(
                    file=entry.name,
                    error_type=type(exc).__name__,
                    message=str(exc),
                )
            )

    return BatchReport(succeeded=tuple(succeeded), failed=tuple(failed))
