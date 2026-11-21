"""Offline OPSEC Document Sanitizer CLI (Typer)."""

from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from opsec_sanitizer.domain.errors import ForensicLeakError, InvalidDocumentError, SanitizerError
from opsec_sanitizer.io_utils import assert_no_symlink_in_path, atomic_write_bytes
from opsec_sanitizer.pipeline import AuditReport, SanitizeConfig, sanitize_batch, sanitize_document

app = typer.Typer(
    name="opsec-sanitize",
    help="Offline OPSEC sanitizer: strips hidden metadata, redacts Mexican PII, and flattens docs.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)


class NerMode(StrEnum):
    HEURISTIC = "heuristic"
    SPACY = "spacy"
    NONE = "none"


def _load_term_list(inline: list[str] | None, file_path: Path | None) -> frozenset[str]:
    terms: set[str] = {t.strip() for t in (inline or ()) if t.strip()}
    if file_path is not None:
        assert_no_symlink_in_path(file_path, allow_symlinks=False)
        if not file_path.is_file():
            raise InvalidDocumentError(f"Term list file not found: {file_path.name}")
        for line in file_path.read_text(encoding="utf-8").splitlines():
            cleaned = line.strip()
            if cleaned and not cleaned.startswith("#"):
                terms.add(cleaned)
    return frozenset(terms)


def _format_summary(report: AuditReport) -> str:
    pii_summary = (
        ", ".join(f"{k.value}={v}" for k, v in sorted(report.pii_counts.items())) or "none"
    )
    mode = "DRY-RUN" if report.dry_run else "SANITIZED"
    verified = "PASS" if report.forensic_verified else "SKIPPED(dry-run)"
    return (
        f"[{mode}] {report.input_name} ({report.doc_type.value}, pages={report.page_count}) "
        f"| metadata_removed={len(report.metadata_keys_removed)} "
        f"| pii=({pii_summary}) | forensic={verified}"
    )


def _write_json_report(report_path: Path, payload: dict[str, object]) -> None:
    encoded = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
    atomic_write_bytes(report_path, encoded)


@app.command("sanitize")
def sanitize_cmd(
    input_path: Annotated[Path, typer.Argument(help="Sensitive document (PDF, DOCX, or image).")],
    output: Annotated[
        Path | None,
        typer.Option("-o", "--output", help="Destination path for sanitized document."),
    ] = None,
    dpi: Annotated[int, typer.Option("--dpi", min=72, max=600, help="Flattening DPI.")] = 200,
    no_ocr: Annotated[
        bool,
        typer.Option("--no-ocr", help="Omit searchable OCR text layer on output PDF."),
    ] = False,
    skip_ocr_pii: Annotated[
        bool,
        typer.Option(
            "--skip-ocr-pii",
            help="Skip OCR PII scanning on scanned PDFs/images (faster, lower OPSEC).",
        ),
    ] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Inspect and report counts without writing output.")
    ] = False,
    paranoid_denoise: Annotated[
        bool,
        typer.Option(
            "--paranoid-denoise",
            help="Convert pages to grayscale + median filter to attenuate scanner/MIC patterns.",
        ),
    ] = False,
    redact_filenames: Annotated[
        bool,
        typer.Option("--redact-filenames", help="Replace input filenames with SHA-256 prefixes."),
    ] = False,
    ner: Annotated[
        NerMode,
        typer.Option("--ner", help="Offline NER mode: heuristic, spacy, or none."),
    ] = NerMode.HEURISTIC,
    deny_list: Annotated[
        list[str] | None,
        typer.Option("--deny-list", help="Sensitive term that must always be redacted."),
    ] = None,
    deny_list_file: Annotated[
        Path | None,
        typer.Option("--deny-list-file", help="Newline-separated file of sensitive terms."),
    ] = None,
    allow_list: Annotated[
        list[str] | None,
        typer.Option("--allow-list", help="Non-sensitive term excluded from redaction."),
    ] = None,
    allow_list_file: Annotated[
        Path | None,
        typer.Option("--allow-list-file", help="Newline-separated file of allowed terms."),
    ] = None,
    report_json: Annotated[
        Path | None,
        typer.Option("--report-json", help="Write OPSEC-safe JSON audit report to this path."),
    ] = None,
) -> None:
    """Sanitize a single sensitive document offline with fail-closed verification."""
    try:
        cfg = SanitizeConfig(
            dpi=dpi,
            enable_ocr=not no_ocr,
            ocr_scan_inputs=not skip_ocr_pii,
            dry_run=dry_run,
            paranoid_denoise=paranoid_denoise,
            redact_filenames=redact_filenames,
            ner_mode=ner.value,
            deny_list=_load_term_list(deny_list, deny_list_file),
            allow_list=_load_term_list(allow_list, allow_list_file),
        )
        report = sanitize_document(input_path, output, config=cfg)
        typer.echo(_format_summary(report))
        if report_json is not None:
            _write_json_report(report_json, report.to_dict())
    except ForensicLeakError as exc:
        typer.echo(f"[FORENSIC ABORT] {exc}", err=True)
        raise typer.Exit(code=2) from None
    except SanitizerError as exc:
        typer.echo(f"[ERROR] {exc}", err=True)
        raise typer.Exit(code=1) from None
    except Exception:
        typer.echo("[ERROR] Unexpected internal failure (details scrubbed for OPSEC)", err=True)
        raise typer.Exit(code=1) from None


@app.command("batch")
def batch_cmd(
    input_dir: Annotated[Path, typer.Argument(help="Directory of documents to sanitize.")],
    output_dir: Annotated[
        Path, typer.Option("-o", "--output-dir", help="Destination directory for clean outputs.")
    ],
    dpi: Annotated[int, typer.Option("--dpi", min=72, max=600)] = 200,
    no_ocr: Annotated[bool, typer.Option("--no-ocr")] = False,
    skip_ocr_pii: Annotated[bool, typer.Option("--skip-ocr-pii")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
    paranoid_denoise: Annotated[bool, typer.Option("--paranoid-denoise")] = False,
    redact_filenames: Annotated[bool, typer.Option("--redact-filenames")] = False,
    ner: Annotated[NerMode, typer.Option("--ner")] = NerMode.HEURISTIC,
    deny_list: Annotated[list[str] | None, typer.Option("--deny-list")] = None,
    deny_list_file: Annotated[Path | None, typer.Option("--deny-list-file")] = None,
    allow_list: Annotated[list[str] | None, typer.Option("--allow-list")] = None,
    allow_list_file: Annotated[Path | None, typer.Option("--allow-list-file")] = None,
    report_json: Annotated[Path | None, typer.Option("--report-json")] = None,
) -> None:
    """Sanitize a directory of leaked documents with per-file error isolation."""
    try:
        cfg = SanitizeConfig(
            dpi=dpi,
            enable_ocr=not no_ocr,
            ocr_scan_inputs=not skip_ocr_pii,
            dry_run=dry_run,
            paranoid_denoise=paranoid_denoise,
            redact_filenames=redact_filenames,
            ner_mode=ner.value,
            deny_list=_load_term_list(deny_list, deny_list_file),
            allow_list=_load_term_list(allow_list, allow_list_file),
        )
        batch_report = sanitize_batch(input_dir, output_dir, config=cfg)
        for item in batch_report.succeeded:
            typer.echo(_format_summary(item))
        for failure in batch_report.failed:
            typer.echo(
                f"[FAILED] {failure.file}: {failure.error_type}: {failure.message}", err=True
            )
        if report_json is not None:
            _write_json_report(report_json, batch_report.to_dict())
    except SanitizerError as exc:
        typer.echo(f"[ERROR] {exc}", err=True)
        raise typer.Exit(code=1) from None
    except Exception:
        typer.echo("[ERROR] Unexpected internal failure (details scrubbed for OPSEC)", err=True)
        raise typer.Exit(code=1) from None

    if batch_report.failed:
        raise typer.Exit(code=1)
