"""End-to-end CLI and pipeline tests verifying OPSEC guarantees."""

from __future__ import annotations

import json
from pathlib import Path

import pymupdf
import pytest
from PIL import Image
from typer.testing import CliRunner

from opsec_sanitizer.cli import app
from opsec_sanitizer.detection.regex_mx import compute_curp_check_digit
from opsec_sanitizer.domain.errors import ForensicLeakError
from opsec_sanitizer.pipeline import SanitizeConfig, sanitize_document

runner = CliRunner()

_CURP_17 = "GOPA850714HDFLRN0"
_VALID_CURP = f"{_CURP_17}{compute_curp_check_digit(_CURP_17)}"


def _make_sample_pdf(path: Path) -> None:
    doc = pymupdf.open()
    page = doc.new_page(width=595, height=400)
    page.insert_text((72, 80), "Reporte de Auditoria Publica", fontsize=14)
    page.insert_text((72, 130), f"CURP: {_VALID_CURP}", fontsize=14)
    page.insert_text((72, 170), "Email: fuente.anonima@investigacion.mx", fontsize=14)
    doc.set_metadata({"author": "FuenteOriginal", "title": "Leak"})
    doc.save(str(path))
    doc.close()


def _make_sample_jpeg(path: Path) -> None:
    img = Image.new("RGB", (100, 60), color=(245, 245, 245))
    exif = Image.Exif()
    exif[271] = "SecretPhoneModel"
    img.save(path, format="JPEG", exif=exif.tobytes())


@pytest.mark.e2e
class TestCliE2E:
    def test_sanitize_pdf_end_to_end_and_report_never_exposes_raw_pii(
        self, tmp_path: Path
    ) -> None:
        src = tmp_path / "leak.pdf"
        dst = tmp_path / "clean.pdf"
        report_file = tmp_path / "audit.json"
        _make_sample_pdf(src)

        result = runner.invoke(
            app,
            [
                "sanitize",
                str(src),
                "-o",
                str(dst),
                "--no-ocr",
                "--dpi",
                "150",
                "--report-json",
                str(report_file),
            ],
        )

        assert result.exit_code == 0, result.output
        assert dst.exists()
        assert report_file.exists()

        # Neither CLI output nor JSON report may contain raw PII or source author
        combined_logs = result.output + report_file.read_text(encoding="utf-8")
        assert _VALID_CURP not in combined_logs
        assert "fuente.anonima@investigacion.mx" not in combined_logs
        assert "FuenteOriginal" not in combined_logs

        report_data = json.loads(report_file.read_text(encoding="utf-8"))
        assert report_data["forensic_verified"] is True
        assert report_data["pii_counts"]["CURP"] == 1
        assert report_data["pii_counts"]["EMAIL"] == 1
        assert "author" in report_data["metadata_keys_removed"]

    def test_dry_run_does_not_create_output_file_and_reports_counts(
        self, tmp_path: Path
    ) -> None:
        src = tmp_path / "leak.pdf"
        dst = tmp_path / "should_not_exist.pdf"
        _make_sample_pdf(src)

        result = runner.invoke(
            app,
            ["sanitize", str(src), "-o", str(dst), "--dry-run", "--no-ocr"],
        )

        assert result.exit_code == 0, result.output
        assert not dst.exists()
        assert _VALID_CURP not in result.output
        assert "CURP" in result.output

    def test_rejects_spoofed_file_with_nonzero_exit_code(self, tmp_path: Path) -> None:
        fake = tmp_path / "fake.pdf"
        fake.write_bytes(b"NOT A REAL PDF FILE")
        dst = tmp_path / "out.pdf"

        result = runner.invoke(app, ["sanitize", str(fake), "-o", str(dst), "--no-ocr"])

        assert result.exit_code != 0
        assert not dst.exists()

    def test_fail_closed_when_forensic_gate_rejects_output(self, tmp_path: Path) -> None:
        src = tmp_path / "leak.pdf"
        dst = tmp_path / "never_written.pdf"
        _make_sample_pdf(src)

        def _failing_verifier(path: Path) -> None:
            raise ForensicLeakError("simulated residual leak")

        with pytest.raises(ForensicLeakError):
            sanitize_document(
                src,
                dst,
                config=SanitizeConfig(dpi=150, enable_ocr=False),
                custom_verifier=_failing_verifier,
            )

        assert not dst.exists()

    def test_batch_processes_mixed_directory_isolating_invalid_files(
        self, tmp_path: Path
    ) -> None:
        in_dir = tmp_path / "inbox"
        out_dir = tmp_path / "outbox"
        in_dir.mkdir()
        _make_sample_pdf(in_dir / "doc1.pdf")
        _make_sample_jpeg(in_dir / "photo1.jpg")
        (in_dir / "corrupt.pdf").write_bytes(b"corrupted bytes")
        report_file = tmp_path / "batch_report.json"

        result = runner.invoke(
            app,
            [
                "batch",
                str(in_dir),
                "-o",
                str(out_dir),
                "--no-ocr",
                "--dpi",
                "150",
                "--report-json",
                str(report_file),
            ],
        )

        # Batch returns non-zero when any file failed, yet succeeds for valid files
        assert result.exit_code == 1
        assert (out_dir / "doc1.sanitized.pdf").exists()
        assert (out_dir / "photo1.sanitized.png").exists()
        assert not (out_dir / "corrupt.sanitized.pdf").exists()

        data = json.loads(report_file.read_text(encoding="utf-8"))
        assert len(data["succeeded"]) == 2
        assert len(data["failed"]) == 1
        assert data["failed"][0]["file"] == "corrupt.pdf"
