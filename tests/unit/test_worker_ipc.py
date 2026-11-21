"""Unit tests for the strict JSON stdin/stdout IPC worker used by the Rust orchestrator."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pymupdf

from opsec_sanitizer.detection.regex_mx import compute_curp_check_digit
from opsec_sanitizer.worker import handle_ipc_stream

_CURP_17 = "GOPA850714HDFLRN0"
_VALID_CURP = f"{_CURP_17}{compute_curp_check_digit(_CURP_17)}"


def _make_pdf(path: Path) -> None:
    doc = pymupdf.open()
    page = doc.new_page(width=595, height=400)
    page.insert_text((72, 80), "Documento IPC", fontsize=14)
    page.insert_text((72, 130), f"CURP: {_VALID_CURP}", fontsize=14)
    doc.set_metadata({"author": "FuenteIPC"})
    doc.save(str(path))
    doc.close()


class TestWorkerIpcContract:
    def test_processes_valid_request_and_emits_scrubbed_json_response(
        self, tmp_path: Path
    ) -> None:
        src = tmp_path / "in.pdf"
        dst = tmp_path / "staged.pdf"
        _make_pdf(src)

        req = json.dumps(
            {
                "protocol_version": 1,
                "input_path": str(src),
                "output_path": str(dst),
                "dpi": 150,
                "enable_ocr": False,
                "ocr_scan_inputs": False,
                "paranoid_denoise": False,
                "dry_run": False,
                "redact_filenames": False,
                "ner_mode": "heuristic",
                "deny_list": [],
                "allow_list": [],
            }
        )
        out = io.StringIO()

        exit_code = handle_ipc_stream(io.StringIO(req), out)

        assert exit_code == 0
        assert dst.exists()
        raw_response = out.getvalue()
        assert _VALID_CURP not in raw_response
        assert "FuenteIPC" not in raw_response
        resp = json.loads(raw_response)
        assert resp["protocol_version"] == 1
        assert resp["ok"] is True
        assert resp["report"]["pii_counts"]["CURP"] == 1
        assert resp["report"]["forensic_verified"] is True

    def test_rejects_malformed_json_and_unsupported_protocol_version(self) -> None:
        out_bad = io.StringIO()
        assert handle_ipc_stream(io.StringIO("{not valid json"), out_bad) == 1
        resp_bad = json.loads(out_bad.getvalue())
        assert resp_bad["ok"] is False
        assert resp_bad["error_code"] == "PROTOCOL_ERROR"

        out_ver = io.StringIO()
        req = json.dumps({"protocol_version": 99, "input_path": "/a", "output_path": "/b"})
        assert handle_ipc_stream(io.StringIO(req), out_ver) == 1
        resp_ver = json.loads(out_ver.getvalue())
        assert resp_ver["ok"] is False
        assert resp_ver["error_code"] == "PROTOCOL_ERROR"

    def test_returns_structured_error_for_invalid_input_without_traceback(
        self, tmp_path: Path
    ) -> None:
        fake = tmp_path / "fake.pdf"
        fake.write_bytes(b"NOT_A_PDF")
        dst = tmp_path / "out.pdf"
        req = json.dumps(
            {
                "protocol_version": 1,
                "input_path": str(fake),
                "output_path": str(dst),
                "enable_ocr": False,
                "ocr_scan_inputs": False,
            }
        )
        out = io.StringIO()

        code = handle_ipc_stream(io.StringIO(req), out)

        assert code == 1
        assert not dst.exists()
        resp = json.loads(out.getvalue())
        assert resp["ok"] is False
        assert resp["error_code"] == "SANITIZER_ERROR"
        assert "Traceback" not in out.getvalue()
