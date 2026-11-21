"""End-to-end OPSEC document sanitization pipeline with fail-closed staging."""

from __future__ import annotations

import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any

from opsec_sanitizer.detection.merger import HybridPiiDetector
from opsec_sanitizer.detection.ner_offline import HeuristicSpanishNerEngine, SpacyNerEngine
from opsec_sanitizer.domain.errors import InvalidDocumentError, SanitizerError
from opsec_sanitizer.domain.models import BBox, DocumentType, IngestionLimits, PiiCategory
from opsec_sanitizer.domain.ports import DocxRenderer, NerEngine, OcrEngine
from opsec_sanitizer.ingestion.validator import validate_document
from opsec_sanitizer.io_utils import (
    assert_no_symlink_in_path,
    atomic_copy_file,
    ram_tmp_root,
    sha256_file,
)
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


@dataclass(frozen=True)
class SanitizeConfig:
    """Immutable configuration for an OPSEC sanitization run."""

    dpi: int = 200
    padding_px: int = 4
    enable_ocr: bool = True  # Embed searchable post-redaction OCR text layer
    ocr_scan_inputs: bool = True  # Scan images & scanned/hybrid PDFs for PII via OCR
    paranoid_denoise: bool = False
    dry_run: bool = False
    redact_filenames: bool = False
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
    pii_counts: Mapping[PiiCategory, int]
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


def _build_ner_engine(mode: str) -> NerEngine | None:
    if mode == "none":
        return None
    if mode == "heuristic":
        return HeuristicSpanishNerEngine()
    if mode == "spacy":
        try:
            return SpacyNerEngine()
        except RuntimeError as exc:
            raise SanitizerError(str(exc)) from exc
    raise InvalidDocumentError(f"Unsupported ner_mode: {mode!r}")


def _validate_output_target(input_resolved: Path, output_path: Path | None, dry_run: bool) -> None:
    if dry_run:
        return
    if output_path is None:
        raise InvalidDocumentError("Output path is required unless dry_run=True")
    assert_no_symlink_in_path(output_path, allow_symlinks=False)
    if output_path.exists() and output_path.is_dir():
        raise InvalidDocumentError("Output path cannot be an existing directory")
    if output_path.resolve() == input_resolved:
        raise InvalidDocumentError("Refusing to overwrite input document in place")


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
        word_pairs = [(w.text, w.line_bbox or w.bbox) for w in ocr_words]
        if word_pairs:
            line_keys = [(0, int(round((w.line_bbox or w.bbox).y0 / 12.0))) for w in ocr_words]
            joined = " ".join(w for w, _ in word_pairs)
            spans = detector.detect(joined)
            for sp in spans:
                pii_counts[sp.category] = pii_counts.get(sp.category, 0) + 1
            pixel_boxes = map_spans_to_word_boxes(word_pairs, spans, line_keys=line_keys)

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
        pii_counts=MappingProxyType(pii_counts),
    )


def _dispatch_sanitization(
    doc_type: DocumentType,
    source_path: Path,
    staged_path: Path,
    *,
    detector: HybridPiiDetector,
    ocr_engine: OcrEngine | None,
    docx_renderer: DocxRenderer | None,
    config: SanitizeConfig,
) -> FlattenResult:
    opts = FlattenOptions(
        dpi=config.dpi,
        padding_px=config.padding_px,
        enable_ocr=config.enable_ocr,
        paranoid_denoise=config.paranoid_denoise,
    )
    if doc_type == DocumentType.PDF:
        return flatten_pdf(
            source_path, staged_path, detector=detector, ocr_engine=ocr_engine, options=opts
        )
    if doc_type == DocumentType.DOCX:
        return sanitize_docx_to_pdf(
            source_path,
            staged_path,
            detector=detector,
            renderer=docx_renderer,
            ocr_engine=ocr_engine,
            options=opts,
        )
    return _process_image_document(
        source_path, staged_path, detector=detector, ocr_engine=ocr_engine, config=config
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
    """Validate, flatten, redact, forensically verify, and atomically deliver sanitized output."""
    cfg = config or SanitizeConfig()
    validated = validate_document(input_path, limits=cfg.limits)
    _validate_output_target(validated.path, output_path, cfg.dry_run)

    detector = HybridPiiDetector(
        ner_engine=_build_ner_engine(cfg.ner_mode),
        allow_list=cfg.allow_list,
        deny_list=cfg.deny_list,
    )
    needs_ocr_engine = cfg.enable_ocr or (
        cfg.ocr_scan_inputs and validated.doc_type in (DocumentType.IMAGE, DocumentType.PDF)
    )
    active_ocr = ocr_engine
    if active_ocr is None and needs_ocr_engine:
        active_ocr = create_default_ocr_engine(cfg.ocr_preference)

    is_image_png_out = (
        validated.doc_type == DocumentType.IMAGE
        and output_path is not None
        and output_path.suffix.lower() != ".pdf"
    )
    staged_ext = ".png" if is_image_png_out else ".pdf"
    display_name = (
        f"sha256:{validated.sha256_hex[:12]}" if cfg.redact_filenames else input_path.name
    )

    with tempfile.TemporaryDirectory(prefix="opsec_stage_", dir=ram_tmp_root()) as tmp_dir:
        staged_path = Path(tmp_dir) / f"staged{staged_ext}"
        res = _dispatch_sanitization(
            validated.doc_type,
            validated.path,
            staged_path,
            detector=detector,
            ocr_engine=active_ocr,
            docx_renderer=docx_renderer,
            config=cfg,
        )
        if cfg.dry_run:
            return AuditReport(
                input_name=display_name,
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

        if custom_verifier is not None:
            custom_verifier(staged_path)
        elif staged_ext == ".png":
            verify_image_forensically(staged_path, detector=detector, ocr_engine=active_ocr)
        else:
            verify_pdf_forensically(staged_path, detector=detector, ocr_engine=active_ocr)

        out_sha256 = sha256_file(staged_path)
        assert output_path is not None
        atomic_copy_file(staged_path, output_path)

    return AuditReport(
        input_name=display_name,
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


def _batch_output_name(entry: Path, doc_type: DocumentType, used_names: set[str]) -> str:
    out_ext = "png" if doc_type == DocumentType.IMAGE else "pdf"
    base_candidate = f"{entry.stem}.sanitized.{out_ext}"
    if base_candidate not in used_names:
        used_names.add(base_candidate)
        return base_candidate
    orig_ext = entry.suffix.lstrip(".").lower() or "raw"
    disambiguated = f"{entry.stem}_{orig_ext}.sanitized.{out_ext}"
    counter = 2
    while disambiguated in used_names:
        disambiguated = f"{entry.stem}_{orig_ext}_{counter}.sanitized.{out_ext}"
        counter += 1
    used_names.add(disambiguated)
    return disambiguated


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
        assert_no_symlink_in_path(output_dir, allow_symlinks=False)
        output_dir.mkdir(parents=True, exist_ok=True)

    shared_ocr = (
        create_default_ocr_engine(cfg.ocr_preference)
        if (cfg.enable_ocr or cfg.ocr_scan_inputs)
        else None
    )
    succeeded: list[AuditReport] = []
    failed: list[BatchFailure] = []
    used_names: set[str] = set()

    for entry in sorted(input_dir.iterdir()):
        if entry.name.startswith(".") or entry.is_dir():
            continue
        file_label = "redacted" if cfg.redact_filenames else entry.name
        try:
            validated = validate_document(entry, limits=cfg.limits)
            out_name = _batch_output_name(entry, validated.doc_type, used_names)
            report = sanitize_document(
                entry,
                output_dir / out_name,
                config=cfg,
                ocr_engine=shared_ocr,
            )
            succeeded.append(report)
        except SanitizerError as exc:
            failed.append(
                BatchFailure(file=file_label, error_type=type(exc).__name__, message=str(exc))
            )
        except Exception as exc:
            failed.append(
                BatchFailure(
                    file=file_label,
                    error_type=type(exc).__name__,
                    message="Unexpected internal processing failure",
                )
            )

    return BatchReport(succeeded=tuple(succeeded), failed=tuple(failed))
