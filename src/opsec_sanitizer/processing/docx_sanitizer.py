"""OPSEC DOCX structural sanitizer (strips metadata, external rels, fields, revisions)."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess  # noqa: S404
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

import pymupdf
from lxml import etree

from opsec_sanitizer.detection.merger import HybridPiiDetector
from opsec_sanitizer.domain.errors import InvalidDocumentError, SanitizerError
from opsec_sanitizer.domain.ports import DocxRenderer, OcrEngine
from opsec_sanitizer.io_utils import ram_tmp_root
from opsec_sanitizer.processing.pdf_flattener import FlattenOptions, FlattenResult, flatten_pdf

_W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_W14_NS = "http://schemas.microsoft.com/office/word/2010/wordml"
_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
_W_PREFIX = f"{{{_W_NS}}}"

_DROP_EXACT_LOWER = frozenset(
    {
        "docprops/custom.xml",
        "word/comments.xml",
        "word/commentsextended.xml",
        "word/commentsids.xml",
        "word/commentsextensible.xml",
        "word/people.xml",
        "word/vbaproject.bin",
        "word/vbadata.xml",
    }
)
_DROP_PREFIXES_LOWER = (
    "docprops/thumbnail",
    "word/embeddings/",
    "word/printersettings/",
    "word/activex/",
    "word/ink/",
    "_xmlsignatures/",
    "customxml/",
)

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
        f"{_W_PREFIX}rPrChange",
        f"{_W_PREFIX}pPrChange",
        f"{_W_PREFIX}sectPrChange",
        f"{_W_PREFIX}tblPrChange",
        f"{_W_PREFIX}trPrChange",
        f"{_W_PREFIX}tcPrChange",
        f"{_W_PREFIX}tblGridChange",
        f"{_W_PREFIX}instrText",
        f"{_W_PREFIX}fldSimple",
        f"{_W_PREFIX}fldChar",
    }
)
_UNWRAP_TAGS = frozenset({f"{_W_PREFIX}ins", f"{_W_PREFIX}moveTo"})
_SETTINGS_REMOVE_TAGS = frozenset(
    {
        f"{_W_PREFIX}attachedTemplate",
        f"{_W_PREFIX}mailMerge",
        f"{_W_PREFIX}rsids",
        f"{_W_PREFIX}trackRevisions",
    }
)
_STRIP_ATTR_LOCALS = frozenset({"author", "date", "initials", "paraId", "textId"})


@dataclass(frozen=True)
class DocxCleanSummary:
    """Audit summary of hidden DOCX artifacts removed prior to rendering."""

    parts_removed: tuple[str, ...]
    revisions_removed: int
    hidden_runs_removed: int


def _safe_xml_parser() -> etree.XMLParser:
    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        huge_tree=False,
        load_dtd=False,
        dtd_validation=False,
        collect_ids=False,
        remove_comments=True,
        remove_pis=True,
    )


def _should_drop_part(name: str) -> bool:
    low = name.lower()
    return low in _DROP_EXACT_LOWER or any(low.startswith(p) for p in _DROP_PREFIXES_LOWER)


def _is_word_content_xml(name: str) -> bool:
    low = name.lower()
    if not low.startswith("word/") or not low.endswith(".xml"):
        return False
    base = Path(low).name
    return base in ("document.xml", "footnotes.xml", "endnotes.xml") or base.startswith(
        ("header", "footer")
    )


def _is_truthy_word_flag(elem: etree._Element | None) -> bool:
    if elem is None:
        return False
    val = elem.attrib.get(f"{_W_PREFIX}val") or elem.attrib.get("val")
    if val is None:
        return True
    return str(val).strip().lower() not in ("0", "false", "off")


def _clean_rels_xml(xml_bytes: bytes) -> bytes:
    """Strip all TargetMode='External' relationships and references to dropped parts."""
    root = etree.fromstring(xml_bytes, parser=_safe_xml_parser())
    for rel in list(root.iter(f"{{{_REL_NS}}}Relationship")):
        target_mode = str(rel.attrib.get("TargetMode", "")).strip().lower()
        target = str(rel.attrib.get("Target", "")).strip().lower()
        if (
            target_mode == "external"
            or target.startswith(("http://", "https://", "file://", "ftp://", "mailto:", "\\\\"))
            or any(
                drop in target
                for drop in (
                    "comments",
                    "people.xml",
                    "custom.xml",
                    "printersettings",
                    "embeddings",
                    "vbaproject",
                )
            )
        ):
            parent = rel.getparent()
            if parent is not None:
                parent.remove(rel)
    return bytes(etree.tostring(root, xml_declaration=True, encoding="UTF-8"))


def _clean_settings_xml(xml_bytes: bytes) -> bytes:
    """Remove attachedTemplate, mailMerge, and editing session rsids from word/settings.xml."""
    root = etree.fromstring(xml_bytes, parser=_safe_xml_parser())
    for elem in list(root.iter()):
        if elem.tag in _SETTINGS_REMOVE_TAGS:
            parent = elem.getparent()
            if parent is not None:
                parent.remove(elem)
    return bytes(etree.tostring(root, xml_declaration=True, encoding="UTF-8"))


def _clean_word_xml(xml_bytes: bytes) -> tuple[bytes, int, int]:
    root = etree.fromstring(xml_bytes, parser=_safe_xml_parser())
    revisions_removed = 0
    hidden_runs_removed = 0

    for elem in list(root.iter()):
        if elem.tag in _REMOVE_TAGS:
            parent = elem.getparent()
            if parent is not None:
                parent.remove(elem)
                revisions_removed += 1

    for run in list(root.iter(f"{_W_PREFIX}r")):
        rpr = run.find(f"{_W_PREFIX}rPr")
        if rpr is not None and (
            _is_truthy_word_flag(rpr.find(f"{_W_PREFIX}vanish"))
            or _is_truthy_word_flag(rpr.find(f"{_W_PREFIX}webHidden"))
        ):
            parent = run.getparent()
            if parent is not None:
                parent.remove(run)
                hidden_runs_removed += 1

    for elem in list(root.iter()):
        if elem.tag in _UNWRAP_TAGS:
            parent = elem.getparent()
            if parent is not None:
                idx = list(parent).index(elem)
                for offset, child in enumerate(list(elem)):
                    parent.insert(idx + offset, child)
                parent.remove(elem)
                revisions_removed += 1

    for elem in root.iter():
        for attr in list(elem.attrib):
            local = attr.rsplit("}", 1)[-1]
            if local.startswith("rsid") or local in _STRIP_ATTR_LOCALS:
                del elem.attrib[attr]

    cleaned_bytes = bytes(etree.tostring(root, xml_declaration=True, encoding="UTF-8"))
    return cleaned_bytes, revisions_removed, hidden_runs_removed


def strip_docx_metadata_and_revisions(
    source_docx: Path,
    cleaned_docx: Path,
) -> DocxCleanSummary:
    """Write a structurally cleaned DOCX removing metadata, external rels, fields, and revisions."""
    parts_removed: list[str] = []
    revisions_total = 0
    hidden_total = 0

    cleaned_docx.parent.mkdir(parents=True, exist_ok=True)
    try:
        with (
            zipfile.ZipFile(source_docx, "r") as zin,
            zipfile.ZipFile(cleaned_docx, "w", compression=zipfile.ZIP_DEFLATED) as zout,
        ):
            for info in zin.infolist():
                name = info.filename
                low = name.lower()
                if _should_drop_part(name):
                    parts_removed.append(name)
                    continue
                raw = zin.read(info)
                if low == "docprops/core.xml":
                    parts_removed.append(name)
                    zout.writestr(name, _CLEAN_CORE_XML)
                elif low == "docprops/app.xml":
                    parts_removed.append(name)
                    zout.writestr(name, _CLEAN_APP_XML)
                elif low.endswith(".rels"):
                    zout.writestr(name, _clean_rels_xml(raw))
                elif low == "word/settings.xml":
                    zout.writestr(name, _clean_settings_xml(raw))
                elif _is_word_content_xml(name):
                    cleaned, revs, hidden = _clean_word_xml(raw)
                    revisions_total += revs
                    hidden_total += hidden
                    zout.writestr(name, cleaned)
                else:
                    zout.writestr(name, raw)
    except (etree.XMLSyntaxError, zipfile.BadZipFile, OSError) as exc:
        raise InvalidDocumentError("Malformed or unreadable DOCX XML content") from exc

    return DocxCleanSummary(
        parts_removed=tuple(sorted(set(parts_removed))),
        revisions_removed=revisions_total,
        hidden_runs_removed=hidden_total,
    )


def _extract_docx_paragraphs(docx_path: Path) -> list[str]:
    paragraphs: list[str] = []
    with zipfile.ZipFile(docx_path, "r") as zf:
        xml_names = sorted(n for n in zf.namelist() if _is_word_content_xml(n))
        # Render document.xml first, then headers/footers/footnotes
        ordered = [n for n in xml_names if n.lower() == "word/document.xml"] + [
            n for n in xml_names if n.lower() != "word/document.xml"
        ]
        for part in ordered:
            root = etree.fromstring(zf.read(part), parser=_safe_xml_parser())
            for para in root.iter(f"{_W_PREFIX}p"):
                line = "".join(t.text for t in para.iter(f"{_W_PREFIX}t") if t.text).strip()
                if line:
                    paragraphs.append(line)
    return paragraphs


def _chunk_text(text: str, max_chars: int = 2_000) -> list[str]:
    if len(text) <= max_chars:
        return [text]
    chunks: list[str] = []
    words = text.split()
    buf: list[str] = []
    size = 0
    for word in words:
        if size + len(word) + 1 > max_chars and buf:
            chunks.append(" ".join(buf))
            buf = [word]
            size = len(word)
        else:
            buf.append(word)
            size += len(word) + 1
    if buf:
        chunks.append(" ".join(buf))
    return chunks


class PurePythonDocxRenderer:
    """Offline fallback DOCX-to-PDF renderer with accurate dynamic line spacing."""

    def render_to_pdf(self, docx_path: Path, output_dir: Path) -> Path:
        paragraphs = _extract_docx_paragraphs(docx_path)
        out_pdf = output_dir / f"{docx_path.stem}.pdf"
        doc = pymupdf.open()
        try:
            page = doc.new_page(width=595, height=842)
            y = 54.0
            bottom_limit = 788.0
            for paragraph in paragraphs:
                for chunk in _chunk_text(paragraph):
                    rect = pymupdf.Rect(54, y, 541, bottom_limit)
                    rem = float(page.insert_textbox(rect, chunk, fontsize=11))
                    if rem < 0:
                        page = doc.new_page(width=595, height=842)
                        y = 54.0
                        rect = pymupdf.Rect(54, y, 541, bottom_limit)
                        rem = float(page.insert_textbox(rect, chunk, fontsize=11))
                    consumed = max(16.0, rect.height - max(0.0, rem))
                    y += consumed + 14.0
                    if y > bottom_limit - 24.0:
                        page = doc.new_page(width=595, height=842)
                        y = 54.0
            doc.save(str(out_pdf))
        finally:
            doc.close()
        return out_pdf


class LibreOfficeDocxRenderer:
    """Renders cleaned DOCX to PDF via headless LibreOffice with scrubbed RAM environment."""

    def __init__(self, timeout_seconds: int = 60) -> None:
        binary = shutil.which("soffice") or shutil.which("libreoffice")
        if binary is None:
            raise RuntimeError("LibreOffice ('soffice') not found on PATH")
        self._binary = binary
        self._timeout = timeout_seconds

    def render_to_pdf(self, docx_path: Path, output_dir: Path) -> Path:
        profile_dir = output_dir / "lo_profile"
        profile_dir.mkdir(parents=True, exist_ok=True)
        scrubbed_env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(profile_dir.resolve()),
            "TMPDIR": str(output_dir.resolve()),
            "XDG_CONFIG_HOME": str(profile_dir.resolve()),
            "XDG_CACHE_HOME": str(profile_dir.resolve()),
            "XDG_DATA_HOME": str(profile_dir.resolve()),
            "LANG": "C.UTF-8",
        }
        cmd = [
            self._binary,
            "--headless",
            "--invisible",
            "--nologo",
            "--nodefault",
            "--norestore",
            "--nolockcheck",
            "--nofirststartwizard",
            f"-env:UserInstallation={profile_dir.resolve().as_uri()}",
            "--convert-to",
            "pdf",
            "--outdir",
            str(output_dir.resolve()),
            str(docx_path.resolve()),
        ]
        proc = subprocess.Popen(  # noqa: S603
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=scrubbed_env,
            start_new_session=True,
        )
        try:
            proc.communicate(timeout=self._timeout)
        except subprocess.TimeoutExpired as exc:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                proc.kill()
            proc.communicate()
            raise SanitizerError("Headless LibreOffice conversion timed out") from exc

        expected_pdf = output_dir / f"{docx_path.stem}.pdf"
        if proc.returncode != 0 or not expected_pdf.exists():
            raise SanitizerError("Headless LibreOffice conversion to PDF failed")
        return expected_pdf


def create_default_docx_renderer() -> DocxRenderer:
    """Prefer headless LibreOffice when available; fall back to pure-Python renderer."""
    if shutil.which("soffice") or shutil.which("libreoffice"):
        return LibreOfficeDocxRenderer()
    return PurePythonDocxRenderer()


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
    with tempfile.TemporaryDirectory(prefix="opsec_docx_", dir=ram_tmp_root()) as tmp_dir_str:
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
