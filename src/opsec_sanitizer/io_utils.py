"""Shared OPSEC-safe filesystem and hashing utilities."""

from __future__ import annotations

import hashlib
import os
import secrets
from pathlib import Path

from opsec_sanitizer.domain.errors import InvalidDocumentError

_CHUNK_SIZE = 65_536


def sha256_file(path: Path) -> str:
    """Compute SHA-256 hex digest of a file in bounded chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(_CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def ram_tmp_root() -> str | None:
    """Return writable RAM tmpdir (preferring sandboxed TMPDIR under /dev/shm if set)."""
    env_tmp = os.environ.get("TMPDIR")
    if env_tmp:
        env_path = Path(env_tmp)
        if env_path.is_dir() and os.access(env_path, os.W_OK):
            return str(env_path)
    shm = Path("/dev/shm")  # noqa: S108
    if shm.is_dir() and os.access(shm, os.W_OK):
        return str(shm)
    return None


def assert_no_symlink_in_path(path: Path, *, allow_symlinks: bool = False) -> None:
    """Reject symlinks on the target path or any existing ancestor directory."""
    if allow_symlinks:
        return
    if path.is_symlink():
        raise InvalidDocumentError("Symbolic links are disallowed by OPSEC policy")
    for ancestor in path.parents:
        if ancestor.is_symlink():
            raise InvalidDocumentError("Symbolic links in ancestor path are disallowed")


def atomic_write_bytes(target: Path, data: bytes) -> None:
    """Atomically write bytes with 0o600 permissions, refusing symlink targets."""
    assert_no_symlink_in_path(target, allow_symlinks=False)
    if target.exists() and target.is_dir():
        raise InvalidDocumentError("Output target cannot be an existing directory")
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp_name = f".{target.name}.{secrets.token_hex(8)}.tmp"
    tmp_path = target.parent / tmp_name
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(tmp_path), flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, target)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise


def atomic_copy_file(src: Path, target: Path) -> None:
    """Atomically copy a staged file to target with 0o600 permissions and no symlink follow."""
    assert_no_symlink_in_path(target, allow_symlinks=False)
    if target.exists() and target.is_dir():
        raise InvalidDocumentError("Output target cannot be an existing directory")
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp_name = f".{target.name}.{secrets.token_hex(8)}.tmp"
    tmp_path = target.parent / tmp_name
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(tmp_path), flags, 0o600)
    try:
        with src.open("rb") as rfh, os.fdopen(fd, "wb") as wfh:
            while chunk := rfh.read(_CHUNK_SIZE):
                wfh.write(chunk)
            wfh.flush()
            os.fsync(wfh.fileno())
        os.replace(tmp_path, target)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
