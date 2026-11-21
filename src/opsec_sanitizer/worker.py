"""Sandboxed Python JSON-over-stdin/stdout IPC worker for the Rust orchestrator."""

from __future__ import annotations

import contextlib
import json
import os
import sys
from pathlib import Path
from typing import Any, TextIO

from opsec_sanitizer.domain.errors import ForensicLeakError, SanitizerError
from opsec_sanitizer.pipeline import SanitizeConfig, sanitize_document

PROTOCOL_VERSION = 1
_MAX_REQUEST_BYTES = 1_048_576
_VALID_NER_MODES = frozenset({"heuristic", "spacy", "none"})
_ALLOWED_KEYS = frozenset(
    {
        "protocol_version",
        "input_path",
        "output_path",
        "dpi",
        "padding_px",
        "enable_ocr",
        "ocr_scan_inputs",
        "paranoid_denoise",
        "dry_run",
        "redact_filenames",
        "ner_mode",
        "deny_list",
        "allow_list",
    }
)


def _emit(out_stream: TextIO, payload: dict[str, Any]) -> None:
    out_stream.write(json.dumps(payload, ensure_ascii=False) + "\n")
    out_stream.flush()


def _require_bool(data: dict[str, Any], key: str, default: bool) -> bool:
    val = data.get(key, default)
    if not isinstance(val, bool):
        raise ValueError(f"Field {key!r} must be a JSON boolean")
    return val


def _require_int(data: dict[str, Any], key: str, default: int, lo: int, hi: int) -> int:
    val = data.get(key, default)
    if isinstance(val, bool) or not isinstance(val, int):
        raise ValueError(f"Field {key!r} must be a JSON integer")
    if not (lo <= val <= hi):
        raise ValueError(f"Field {key!r} must be between {lo} and {hi}")
    return val


def _parse_request(raw: str) -> tuple[Path, Path | None, SanitizeConfig]:
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("IPC payload must be a JSON object")
    unknown = set(data) - _ALLOWED_KEYS
    if unknown:
        raise ValueError(f"Unknown IPC request fields: {sorted(unknown)}")
    if data.get("protocol_version") != PROTOCOL_VERSION or isinstance(
        data.get("protocol_version"), bool
    ):
        raise ValueError(f"Unsupported protocol_version: {data.get('protocol_version')!r}")

    input_raw = data.get("input_path")
    if not isinstance(input_raw, str) or not input_raw.strip():
        raise ValueError("Missing required string field: input_path")

    output_raw = data.get("output_path")
    output_path: Path | None = None
    if output_raw is not None:
        if not isinstance(output_raw, str) or not output_raw.strip():
            raise ValueError("output_path must be a non-empty string or null")
        output_path = Path(output_raw)

    dpi = _require_int(data, "dpi", 200, 72, 600)
    padding_px = _require_int(data, "padding_px", 4, 0, 64)

    ner_mode = data.get("ner_mode", "heuristic")
    if not isinstance(ner_mode, str) or ner_mode not in _VALID_NER_MODES:
        raise ValueError(f"Invalid ner_mode: {ner_mode!r}")

    deny_raw = data.get("deny_list", [])
    allow_raw = data.get("allow_list", [])
    if not isinstance(deny_raw, list) or not isinstance(allow_raw, list):
        raise ValueError("deny_list and allow_list must be JSON arrays of strings")
    if not all(isinstance(x, str) for x in deny_raw) or not all(
        isinstance(x, str) for x in allow_raw
    ):
        raise ValueError("deny_list and allow_list entries must be strings")

    cfg = SanitizeConfig(
        dpi=dpi,
        padding_px=padding_px,
        enable_ocr=_require_bool(data, "enable_ocr", True),
        ocr_scan_inputs=_require_bool(data, "ocr_scan_inputs", True),
        paranoid_denoise=_require_bool(data, "paranoid_denoise", False),
        dry_run=_require_bool(data, "dry_run", False),
        redact_filenames=_require_bool(data, "redact_filenames", False),
        ner_mode=ner_mode,
        deny_list=frozenset(x.strip() for x in deny_raw if x.strip()),
        allow_list=frozenset(x.strip() for x in allow_raw if x.strip()),
    )
    return Path(input_raw), output_path, cfg


def handle_ipc_stream(in_stream: TextIO, out_stream: TextIO) -> int:
    """Read one JSON request from in_stream, execute sanitization, emit one JSON response."""
    raw = in_stream.read(_MAX_REQUEST_BYTES + 1)
    if len(raw) > _MAX_REQUEST_BYTES:
        _emit(
            out_stream,
            {
                "protocol_version": PROTOCOL_VERSION,
                "ok": False,
                "error_code": "PROTOCOL_ERROR",
                "message": "IPC request exceeds maximum allowed size",
            },
        )
        return 1

    try:
        input_path, output_path, cfg = _parse_request(raw)
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        _emit(
            out_stream,
            {
                "protocol_version": PROTOCOL_VERSION,
                "ok": False,
                "error_code": "PROTOCOL_ERROR",
                "message": str(exc),
            },
        )
        return 1

    try:
        with contextlib.redirect_stdout(sys.stderr):
            report = sanitize_document(input_path, output_path, config=cfg)
    except ForensicLeakError as exc:
        _emit(
            out_stream,
            {
                "protocol_version": PROTOCOL_VERSION,
                "ok": False,
                "error_code": "FORENSIC_LEAK",
                "message": str(exc),
            },
        )
        return 2
    except SanitizerError as exc:
        _emit(
            out_stream,
            {
                "protocol_version": PROTOCOL_VERSION,
                "ok": False,
                "error_code": "SANITIZER_ERROR",
                "message": str(exc),
            },
        )
        return 1
    except Exception:
        _emit(
            out_stream,
            {
                "protocol_version": PROTOCOL_VERSION,
                "ok": False,
                "error_code": "INTERNAL_ERROR",
                "message": "Unexpected worker internal failure (scrubbed for OPSEC)",
            },
        )
        return 1

    _emit(
        out_stream,
        {
            "protocol_version": PROTOCOL_VERSION,
            "ok": True,
            "report": report.to_dict(),
        },
    )
    return 0


def main() -> None:
    """Isolate OS FD 1 so C-extensions/subprocesses cannot poison the JSON IPC channel."""
    ipc_fd = os.dup(1)
    os.dup2(2, 1)
    with os.fdopen(ipc_fd, "w", encoding="utf-8") as ipc_out:
        code = handle_ipc_stream(sys.stdin, ipc_out)
    raise SystemExit(code)


if __name__ == "__main__":
    main()
