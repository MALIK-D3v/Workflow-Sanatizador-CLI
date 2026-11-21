"""OPSEC DOCX structural sanitizer (strips metadata, comments, revisions, hidden text)."""

from __future__ import annotations

import os
import shutil
import subprocess  # noqa: S404
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

import pymupdf
from lxml import etree

from opsec_sanitizer.detection.merger import HybridPiiDetector
from opsec_sanitizer.domain.errors import SanitizerError
from opsec_sanitizer.domain.ports import DocxRenderer, OcrEngine
from opsec_sanitizer.processing.pdf_flattener import FlattenOptions, FlattenResult, flatten_pdf

_W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_W_PREFIX = f"{{{_W_NS}}}"

_DROP_EXACT_PARTS = frozenset(
    {
        "docProps/custom.xml",
        "word/comments.xml",
        "word/commentsExtended.xml",
        "word/commentsIds.xml",
        "word/commentsExtensible.xml",
        "word/people.xml",
        "word/vbaProject.bin",
    }
)
_DROP_PREFIXES = ("docProps/thumbnail", "word/embeddings/", "customXml/")

_CLEAN_CORE_XML = (
    b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    b'<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"/>'
)
_CLEAN_APP_XML = (
    b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    b'<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"/>'
)

_REMOVE_TAGS = frozenset(
    {
        f"{_W_PREFIX}del",
        f"{_W_PREFIX}moveFrom",
        f"{_W_PREFIX}commentRangeStart",
        f"{_W_PREFIX}commentRangeEnd",
        f"{_W_PREFIX}commentReference",
    }
)
_UNWRAP_TAGS = frozenset({f"{_W_PREFIX}ins", f"{_W_PREFIX}moveTo"})


@dataclass(frozen=True)
class DocxCleanSummary:
    """Audit summary of hidden DOCX artifacts removed prior to rendering."""

    parts_removed: tuple[str, ...]
    revisions_removed: int
    hidden_runs_removed: int


def _safe_xml_parser() -> etree.XMLParser:
    return etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)


def _should_drop_part(name: str) -> bool:
    return name in _DROP_EXACT_PARTS or any(name.startswith(p) for p in _DROP_PREFIXES)


def _is_word_content_xml(name: str) -> bool:
    if not name.startswith("word/") or not name.endswith(".xml"):
        return False
    base = Path(name).name
    return base in ("document.xml", "footnotes.xml", "endnotes.xml") or base.startswith(
        ("header", "footer")
    )


def _clean_word_xml(xml_bytes: bytes) -> tuple[bytes, int, int]:
    root = etree.fromstring(xml_bytes, parser=_safe_xml_parser())
    revisions_removed = 0
    hidden_runs_removed = 0

    # Remove deletions, moveFrom, and comment anchors
    for elem in list(root.iter()):
        if elem.tag in _REMOVE_TAGS:
            parent = elem.getparent()
            if parent is not None:
                parent.remove(elem)
                revisions_removed += 1

    # Remove runs marked vanish / webHidden
    for run in list(root.iter(f"{_W_PREFIX}r")):
        rpr = run.find(f"{_W_PREFIX}rPr")
        if rpr is not None and (
            rpr.find(f"{_W_PREFIX}vanish") is not None
            or rpr.find(f"{_W_PREFIX}webHidden") is not None
        ):
            parent = run.getparent()
            if parent is not None:
                parent.remove(run)
                hidden_runs_removed += 1

    # Unwrap insertions keeping accepted children without author/date metadata
    for elem in list(root.iter()):
        if elem.tag in _UNWRAP_TAGS:
            parent = elem.getparent()
            if parent is not None:
                idx = list(parent).index(elem)
                for offset, child in enumerate(list(elem)):
                    parent.insert(idx + offset, child)
                parent.remove(elem)
                revisions_removed += 1

    # Strip session fingerprinting rsid* attributes everywhere
    for elem in root.iter():
        for attr in list(elem.attrib):
            local = attr.rsplit("}", 1)[-1]
            if local.startswith("rsid"):
                del elem.attrib[attr]

    cleaned_bytes = etree.tostring(root, xml_declaration=True, encoding="UTF-8")
    return cleaned_bytes, revisions_removed, hidden_runs_removed


def strip_docx_metadata_and_revisions(
    source_docx: Path,
    cleaned_docx: Path,
) -> DocxCleanSummary:
    """Write a structurally cleaned DOCX removing metadata, comments, revisions, and vanish text."""
    parts_removed: list[str] = []
    revisions_total = 0
    hidden_total = 0

    cleaned_docx.parent.mkdir(parents=True, exist_ok=True)
    with (
        zipfile.ZipFile(source_docx, "r") as zin,
        zipfile.ZipFile(cleaned_docx, "w", compression=zipfile.ZIP_DEFLATED) as zout,
    ):
        for info in zin.infolist():
            name = info.filename
            if _should_drop_part(name):
                parts_removed.append(name)
                continue
            raw = zin.read(name)
            if name == "docProps/core.xml":
                parts_removed.append(name)
                zout.writestr(name, _CLEAN_CORE_XML)
                continue
            if name == "docProps/app.xml":
                parts_removed.append(name)
                zout.writestr(name, _CLEAN_APP_XML)
                continue
            if _is_word_content_xml(name):
                cleaned, revs, hidden = _clean_word_xml(raw)
                revisions_total += revs
                hidden_total += hidden
                zout.writestr(name, cleaned)
                continue
            zout.writestr(name, raw)

    return DocxCleanSummary(
        parts_removed=tuple(sorted(set(parts_removed))),
        revisions_removed=revisions_total,
        hidden_runs_removed=hidden_total,
    )


class PurePythonDocxRenderer:
    """Offline fallback DOCX-to-PDF renderer using cleaned WordprocessingML text."""

    def render_to_pdf(self, docx_path: Path, output_dir: Path) -> Path:
        with zipfile.ZipFile(docx_path, "r") as zf:
            xml_bytes = zf.read("word/document.xml")
        root = etree.fromstring(xml_bytes, parser=_safe_xml_parser())

        paragraphs: list[str] = []
        for para in root.iter(f"{_W_PREFIX}p"):
            texts = [t.text for t in para.iter(f"{_W_PREFIX}t") if t.text]
            line = "".join(texts).strip()
            if line:
                paragraphs.append(line)

        out_pdf = output_dir / f"{docx_path.stem}.pdf"
        doc = pymupdf.open()
        try:
            page = doc.new_page(width=595, height=842)
            y = 72.0
            for paragraph in paragraphs:
                rect = pymupdf.Rect(54, y, 541, 790)
                rem = page.insert_textbox(rect, paragraph, fontsize=11)
                if rem < 0:
                    page = doc.new_page(width=595, height=842)
                    y = 72.0
                    page.insert_textbox(pymupdf.Rect(54, y, 541, 790), paragraph, fontsize=11)
                y += 28.0
                if y > 740:
                    page = doc.new_page(width=595, height=842)
                    y = 72.0
            doc.save(str(out_pdf))
        finally:
            doc.close()
        return out_pdf


class LibreOfficeDocxRenderer:
    """Renders cleaned DOCX to PDF using headless LibreOffice with isolated user profile."""

    def __init__(self, timeout_seconds: int = 60) -> None:
        binary = shutil.which("soffice") or shutil.which("libreoffice")
        if binary is None:
            raise RuntimeError("LibreOffice ('soffice') not found on PATH")
        self._binary = binary
        self._timeout = timeout_seconds

    def render_to_pdf(self, docx_path: Path, output_dir: Path) -> Path:
        profile_dir = output_dir / "lo_profile"
        profile_dir.mkdir(parents=True, exist_ok=True)
        cmd = [
            self._binary,
            "--headless",
            "--nologo",
            "--nodefault",
            "--nofirststartwizard",
            f"-env:UserInstallation=file://{profile_dir.resolve()}",
            "--convert-to",
            "pdf",
            "--outdir",
            str(output_dir.resolve()),
            str(docx_path.resolve()),
        ]
        proc = subprocess.run(  # noqa: S603
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=self._timeout,
        )
        expected_pdf = output_dir / f"{docx_path.stem}.pdf"
        if proc.returncode != 0 or not expected_pdf.exists():
            raise SanitizerError("Headless LibreOffice conversion to PDF failed")
        return expected_pdf


def create_default_docx_renderer() -> DocxRenderer:
    """Prefer headless LibreOffice when available; fall back to pure-Python renderer."""
    if shutil.which("soffice") or shutil.which("libreoffice"):
        return LibreOfficeDocxRenderer()
    return PurePythonDocxRenderer()


def _ram_tmp_root() -> str | None:
    shm = Path("/dev/shm")  # noqa: S108
    if shm.is_dir() and os.access(shm, os.W_OK):
        return str(shm)
    return None


def sanitize_docx_to_pdf(
    source_docx: Path,
    output_pdf: Path,
    *,
    detector: HybridPiiDetector,
    renderer: DocxRenderer | None = None,
    ocr_engine: OcrEngine | None = None,
    options: FlattenOptions | None = None,
) -> FlattenResult:
    """Pre-clean DOCX XML, render to temp PDF in RAM, flatten, redact, and remove temps."""
    active_renderer = renderer or create_default_docx_renderer()
    with tempfile.TemporaryDirectory(prefix="opsec_docx_", dir=_ram_tmp_root()) as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        cleaned_docx = tmp_dir / "cleaned.docx"
        summary = strip_docx_metadata_and_revisions(source_docx, cleaned_docx)
        temp_pdf = active_renderer.render_to_pdf(cleaned_docx, tmp_dir)
        pdf_result = flatten_pdf(
            temp_pdf,
            output_pdf,
            detector=detector,
            ocr_engine=ocr_engine,
            options=options,
        )

    merged_meta = tuple(sorted(set(pdf_result.metadata_keys_removed) | set(summary.parts_removed)))
    return FlattenResult(
        page_count=pdf_result.page_count,
        metadata_keys_removed=merged_meta,
        attachments_removed=pdf_result.attachments_removed,
        annotations_removed=pdf_result.annotations_removed + summary.revisions_removed,
        pii_counts=pdf_result.pii_counts,
    )
