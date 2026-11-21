"""Offline OPSEC Document Sanitizer CLI (Typer)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from opsec_sanitizer.domain.errors import ForensicLeakError, SanitizerError
from opsec_sanitizer.pipeline import AuditReport, SanitizeConfig, sanitize_batch, sanitize_document

app = typer.Typer(
    name="opsec-sanitize",
    help="Offline OPSEC sanitizer: strips hidden metadata, redacts Mexican PII, and flattens docs.",
    no_args_is_help=True,
)


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
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


@app.command("sanitize")
def sanitize_cmd(
    input_path: Annotated[Path, typer.Argument(help="Sensitive document (PDF, DOCX, or image).")],
    output: Annotated[
        Path | None,
        typer.Option("-o", "--output", help="Destination path for sanitized document."),
    ] = None,
    dpi: Annotated[int, typer.Option("--dpi", min=72, max=600, help="Flattening DPI.")] = 200,
    no_ocr: Annotated[
        bool, typer.Option("--no-ocr", help="Disable OCR (image-only PDF without text layer).")
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
    ner: Annotated[
        str,
        typer.Option("--ner", help="Offline NER mode: heuristic, spacy, or none."),
    ] = "heuristic",
    deny_list: Annotated[
        list[str] | None,
        typer.Option("--deny-list", help="Sensitive term that must always be redacted."),
    ] = None,
    allow_list: Annotated[
        list[str] | None,
        typer.Option("--allow-list", help="Non-sensitive term excluded from redaction."),
    ] = None,
    report_json: Annotated[
        Path | None,
        typer.Option("--report-json", help="Write OPSEC-safe JSON audit report to this path."),
    ] = None,
) -> None:
    """Sanitize a single sensitive document offline with fail-closed verification."""
    cfg = SanitizeConfig(
        dpi=dpi,
        enable_ocr=not no_ocr,
        dry_run=dry_run,
        paranoid_denoise=paranoid_denoise,
        ner_mode=ner,
        deny_list=frozenset(deny_list or ()),
        allow_list=frozenset(allow_list or ()),
    )
    try:
        report = sanitize_document(input_path, output, config=cfg)
    except ForensicLeakError as exc:
        typer.echo(f"[FORENSIC ABORT] {exc}", err=True)
        raise typer.Exit(code=2) from None
    except SanitizerError as exc:
        typer.echo(f"[ERROR] {exc}", err=True)
        raise typer.Exit(code=1) from None

    typer.echo(_format_summary(report))
    if report_json is not None:
        _write_json_report(report_json, report.to_dict())


@app.command("batch")
def batch_cmd(
    input_dir: Annotated[Path, typer.Argument(help="Directory of documents to sanitize.")],
    output_dir: Annotated[
        Path, typer.Option("-o", "--output-dir", help="Destination directory for clean outputs.")
    ],
    dpi: Annotated[int, typer.Option("--dpi", min=72, max=600)] = 200,
    no_ocr: Annotated[bool, typer.Option("--no-ocr")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
    paranoid_denoise: Annotated[bool, typer.Option("--paranoid-denoise")] = False,
    ner: Annotated[str, typer.Option("--ner")] = "heuristic",
    report_json: Annotated[Path | None, typer.Option("--report-json")] = None,
) -> None:
    """Sanitize a directory of leaked documents with per-file error isolation."""
    cfg = SanitizeConfig(
        dpi=dpi,
        enable_ocr=not no_ocr,
        dry_run=dry_run,
        paranoid_denoise=paranoid_denoise,
        ner_mode=ner,
    )
    try:
        batch_report = sanitize_batch(input_dir, output_dir, config=cfg)
    except SanitizerError as exc:
        typer.echo(f"[ERROR] {exc}", err=True)
        raise typer.Exit(code=1) from None

    for item in batch_report.succeeded:
        typer.echo(_format_summary(item))
    for failure in batch_report.failed:
        typer.echo(f"[FAILED] {failure.file}: {failure.error_type}: {failure.message}", err=True)

    if report_json is not None:
        _write_json_report(report_json, batch_report.to_dict())

    if batch_report.failed:
        raise typer.Exit(code=1)
