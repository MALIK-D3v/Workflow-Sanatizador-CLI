"""Contract tests for the air-gapped Containerfile and hardened container runner script."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_CONTAINERFILE = _PROJECT_ROOT / "Containerfile"
_RUNNER_SCRIPT = _PROJECT_ROOT / "scripts" / "run-airgapped.sh"


class TestContainerfileInvariants:
    def test_containerfile_exists_and_enforces_multistage_nonroot_offline_runtime(self) -> None:
        assert _CONTAINERFILE.is_file(), "Containerfile is missing"
        text = _CONTAINERFILE.read_text(encoding="utf-8")

        assert "AS rust-builder" in text
        assert "cargo build --release" in text
        assert "USER 10001:10001" in text
        assert 'ENTRYPOINT ["/usr/local/bin/opsec-orchestrator"]' in text
        assert "PYTHONDONTWRITEBYTECODE=1" in text
        assert "PYTHONNOUSERSITE=1" in text


class TestAirgappedRunnerScript:
    def test_script_has_valid_bash_syntax_and_no_eval(self) -> None:
        assert _RUNNER_SCRIPT.is_file(), "scripts/run-airgapped.sh is missing"
        body = _RUNNER_SCRIPT.read_text(encoding="utf-8")
        assert "eval " not in body
        proc = subprocess.run(
            ["bash", "-n", str(_RUNNER_SCRIPT)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, proc.stderr

    def test_dry_run_emits_strict_airgapped_container_flags(self, tmp_path: Path) -> None:
        src = tmp_path / "leak.pdf"
        src.write_bytes(b"%PDF-1.7\n%%EOF\n")
        out = tmp_path / "out" / "clean.pdf"
        deny = tmp_path / "deny.txt"
        deny.write_text("AliasHalcon\n", encoding="utf-8")

        proc = subprocess.run(
            [
                str(_RUNNER_SCRIPT),
                "--dry-run-cmd",
                "--engine",
                "podman",
                "--deny-list-file",
                str(deny),
                str(src),
                str(out),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

        assert proc.returncode == 0, proc.stderr
        cmd = proc.stdout
        for required_flag in (
            "--rm",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--pids-limit=256",
            "--tmpfs /dev/shm:rw,noexec,nosuid,size=512m",
            ":/in/document:ro",
            ":/in/deny.txt:ro",
            ":/out:rw",
            "--worker-bin /opt/opsec-venv/bin/opsec-sanitize-worker",
        ):
            assert required_flag in cmd, f"Missing required OPSEC flag {required_flag!r} in:\n{cmd}"

    def test_rejects_symlink_input_before_launching_container(self, tmp_path: Path) -> None:
        real = tmp_path / "real.pdf"
        real.write_bytes(b"%PDF-1.7\n%%EOF\n")
        link = tmp_path / "link.pdf"
        link.symlink_to(real)
        out = tmp_path / "clean.pdf"

        proc = subprocess.run(
            [str(_RUNNER_SCRIPT), "--dry-run-cmd", "--engine", "podman", str(link), str(out)],
            check=False,
            capture_output=True,
            text=True,
        )

        assert proc.returncode != 0
        assert "symlink" in proc.stderr.lower()

    @pytest.mark.parametrize("bad_engine", ["rm -rf /", "sh", "python3"])
    def test_rejects_untrusted_container_engine_name(
        self, tmp_path: Path, bad_engine: str
    ) -> None:
        src = tmp_path / "doc.pdf"
        src.write_bytes(b"%PDF-1.7\n%%EOF\n")
        out = tmp_path / "out.pdf"

        proc = subprocess.run(
            [str(_RUNNER_SCRIPT), "--dry-run-cmd", "--engine", bad_engine, str(src), str(out)],
            check=False,
            capture_output=True,
            text=True,
        )

        assert proc.returncode != 0
