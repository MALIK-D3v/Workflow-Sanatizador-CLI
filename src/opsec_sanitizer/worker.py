"""Sandboxed Python JSON-over-stdin/stdout IPC worker for the Rust orchestrator."""

from __future__ import annotations

import contextlib
import json
import sys
from pathlib import Path
from typing import Any, TextIO

from opsec_sanitizer.domain.errors import ForensicLeakError, SanitizerError
from opsec_sanitizer.pipeline import SanitizeConfig, sanitize_document

PROTOCOL_VERSION = 1
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


def _parse_request(raw: str) -> tuple[Path, Path | None, SanitizeConfig]:
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("IPC payload must be a JSON object")
    unknown = set(data) - _ALLOWED_KEYS
    if unknown:
        raise ValueError(f"Unknown IPC request fields: {sorted(unknown)}")
    if data.get("protocol_version") != PROTOCOL_VERSION:
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

    dpi = int(data.get("dpi", 200))
    if not (72 <= dpi <= 600):
        raise ValueError("dpi must be between 72 and 600")

    padding_px = int(data.get("padding_px", 4))
    if not (0 <= padding_px <= 64):
        raise ValueError("padding_px must be between 0 and 64")

    deny_raw = data.get("deny_list", [])
    allow_raw = data.get("allow_list", [])
    if not isinstance(deny_raw, list) or not isinstance(allow_raw, list):
        raise ValueError("deny_list and allow_list must be JSON arrays of strings")

    cfg = SanitizeConfig(
        dpi=dpi,
        padding_px=padding_px,
        enable_ocr=bool(data.get("enable_ocr", True)),
        ocr_scan_inputs=bool(data.get("ocr_scan_inputs", True)),
        paranoid_denoise=bool(data.get("paranoid_denoise", False)),
        dry_run=bool(data.get("dry_run", False)),
        redact_filenames=bool(data.get("redact_filenames", False)),
        ner_mode=str(data.get("ner_mode", "heuristic")),
        deny_list=frozenset(str(x).strip() for x in deny_raw if str(x).strip()),
        allow_list=frozenset(str(x).strip() for x in allow_raw if str(x).strip()),
    )
    return Path(input_raw), output_path, cfg


def handle_ipc_stream(in_stream: TextIO, out_stream: TextIO) -> int:
    """Read one JSON request from in_stream, execute sanitization, emit one JSON response."""
    raw = in_stream.read(1_048_576)
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
    """CLI entrypoint invoked by the Rust orchestrator inside the network-isolated sandbox."""
    raise SystemExit(handle_ipc_stream(sys.stdin, sys.stdout))


if __name__ == "__main__":
    main()
