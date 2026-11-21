use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use opsec_orchestrator::error::OrchestratorError;
use opsec_orchestrator::orchestrator::{orchestrate_sanitize, OrchestratorConfig};
use opsec_orchestrator::sandbox::SandboxBackend;
use tempfile::tempdir;

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| unreachable!())
}

fn venv_python() -> PathBuf {
    project_root().join(".venv/bin/python")
}

fn worker_bin() -> PathBuf {
    project_root().join(".venv/bin/opsec-sanitize-worker")
}

fn generate_trapped_fixtures(dir: &Path) -> (PathBuf, PathBuf, PathBuf, String) {
    let pdf_path = dir.join("trapped.pdf");
    let jpg_path = dir.join("trapped.jpg");
    let docx_path = dir.join("trapped.docx");

    let script = format!(
        r#"
import zipfile, pymupdf
from PIL import Image
from opsec_sanitizer.detection.regex_mx import compute_curp_check_digit

curp17 = "GOPA850714HDFLRN0"
curp = curp17 + compute_curp_check_digit(curp17)

# 1. Trapped PDF
doc = pymupdf.open()
p = doc.new_page(width=595, height=400)
p.insert_text((72, 80), "Auditoria Publica 2026", fontsize=14)
p.insert_text((72, 130), f"CURP: {{curp}}", fontsize=14)
p.insert_text((72, 170), "Email: fuente.hibrida@redaccion.mx", fontsize=14)
p.insert_text((72, 220), "TEXTO_BAJO_TACHADO", fontsize=14)
p.draw_rect(pymupdf.Rect(68, 204, 300, 228), color=(0,0,0), fill=(0,0,0))
doc.set_metadata({{"author": "InformanteHibrido", "title": "Secreto"}})
doc.save({pdf:?})
doc.close()

# 2. Trapped JPEG
img = Image.new("RGB", (80, 50), (240, 240, 240))
exif = Image.Exif()
exif[271] = "SecretHybridCam"
img.save({jpg:?}, format="JPEG", exif=exif.tobytes())
with open({jpg:?}, "ab") as fh:
    fh.write(b"TRAILING_HYBRID_LEAK")

# 3. Trapped DOCX with external canary relationship
w_ns = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
with zipfile.ZipFile({docx:?}, "w") as zf:
    zf.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
    zf.writestr("_rels/.rels", '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
    zf.writestr("word/_rels/document.xml.rels", '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="https://canary.invalid/pixel.png" TargetMode="External"/></Relationships>')
    zf.writestr("word/document.xml", f'<w:document xmlns:w="{{w_ns}}"><w:body><w:p><w:r><w:t>Oficio limpio RFC ABC9912319Z0</w:t></w:r><w:del><w:r><w:delText>BORRADO_SECRETO</w:delText></w:r></w:del></w:p></w:body></w:document>')

print(curp)
"#,
        pdf = pdf_path.to_string_lossy(),
        jpg = jpg_path.to_string_lossy(),
        docx = docx_path.to_string_lossy(),
    );

    let out = Command::new(venv_python())
        .args(["-c", &script])
        .output()
        .ok();
    assert!(out.is_some());
    let output = out.unwrap_or_else(|| unreachable!());
    assert!(
        output.status.success(),
        "fixture script failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let curp = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (pdf_path, jpg_path, docx_path, curp)
}

#[test]
fn end_to_end_rust_bwrap_python_worker_sanitizes_pdf_jpeg_and_docx() {
    let dir = tempdir().ok();
    assert!(dir.is_some());
    let root = dir.as_ref().map(|d| d.path()).unwrap_or_else(|| unreachable!());
    let (pdf_in, jpg_in, docx_in, curp) = generate_trapped_fixtures(root);

    let cfg = OrchestratorConfig {
        worker_bin: worker_bin(),
        dpi: 150,
        enable_ocr: false,
        ocr_scan_inputs: false,
        sandbox_override: Some(SandboxBackend::Bubblewrap),
        ..OrchestratorConfig::default()
    };

    // 1. PDF through Rust -> bwrap -> Python worker -> independent Rust forensic gate
    let pdf_out = root.join("clean.pdf");
    let pdf_rep = orchestrate_sanitize(&pdf_in, Some(&pdf_out), &cfg);
    assert!(pdf_rep.is_ok(), "pdf orchestration failed: {pdf_rep:?}");
    if let Ok(rep) = pdf_rep {
        assert_eq!(rep.sandbox_backend, "bubblewrap");
        assert!(rep.rust_forensic_verified);
        assert!(pdf_out.exists());
        let mode = std::fs::metadata(&pdf_out)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0);
        assert_eq!(mode, 0o600);
        let raw = std::fs::read(&pdf_out).unwrap_or_default();
        assert!(!raw.windows(curp.len()).any(|w| w == curp.as_bytes()));
        assert!(!raw.windows(17).any(|w| w == b"InformanteHibrido"));
        assert!(!raw.windows(18).any(|w| w == b"TEXTO_BAJO_TACHADO"));
        assert!(!raw.windows(5).any(|w| w == b"MuPDF"));
    }

    // 2. JPEG through Rust -> bwrap -> Python worker -> independent Rust PNG chunk verifier
    let jpg_out = root.join("clean.png");
    let jpg_rep = orchestrate_sanitize(&jpg_in, Some(&jpg_out), &cfg);
    assert!(jpg_rep.is_ok(), "jpeg orchestration failed: {jpg_rep:?}");
    let jpg_raw = std::fs::read(&jpg_out).unwrap_or_default();
    assert!(!jpg_raw.windows(15).any(|w| w == b"SecretHybridCam"));
    assert!(!jpg_raw.windows(20).any(|w| w == b"TRAILING_HYBRID_LEAK"));

    // 3. DOCX with external canary URL inside --unshare-net Bubblewrap sandbox!
    let docx_out = root.join("clean_docx.pdf");
    let docx_rep = orchestrate_sanitize(&docx_in, Some(&docx_out), &cfg);
    assert!(docx_rep.is_ok(), "docx orchestration failed: {docx_rep:?}");
    let docx_raw = std::fs::read(&docx_out).unwrap_or_default();
    assert!(!docx_raw.windows(15).any(|w| w == b"BORRADO_SECRETO"));
    assert!(!docx_raw.windows(12).any(|w| w == b"ABC9912319Z0"));
}

#[test]
fn rust_forensic_gate_blocks_compromised_worker_that_lies_about_clean_output() {
    let dir = tempdir().ok();
    assert!(dir.is_some());
    let root = dir.as_ref().map(|d| d.path()).unwrap_or_else(|| unreachable!());
    let (pdf_in, _, _, _) = generate_trapped_fixtures(root);

    // Build a rogue fake worker script that writes a PDF with /Author(LEAKED) and returns ok=true
    let rogue_worker = root.join("rogue_worker.sh");
    let script = r#"#!/usr/bin/env python3
import json, sys
req = json.loads(sys.stdin.read())
with open(req["output_path"], "wb") as fh:
    fh.write(b"%PDF-1.7\n1 0 obj\n<</Author(COMPROMISED_WORKER_LEAK)>>\nendobj\n%%EOF\n")
print(json.dumps({"protocol_version": 1, "ok": True, "report": {
    "input_name": "x", "doc_type": "pdf", "input_sha256": "a"*64, "output_sha256": "b"*64,
    "page_count": 1, "metadata_keys_removed": [], "attachments_removed": 0,
    "annotations_removed": 0, "pii_counts": {}, "forensic_verified": True, "dry_run": False
}}))
"#;
    let _ = std::fs::write(&rogue_worker, script);
    let _ = std::fs::set_permissions(&rogue_worker, std::fs::Permissions::from_mode(0o755));

    let pdf_out = root.join("must_never_exist.pdf");
    let cfg = OrchestratorConfig {
        worker_bin: rogue_worker,
        sandbox_override: Some(SandboxBackend::Bubblewrap),
        ..OrchestratorConfig::default()
    };

    let res = orchestrate_sanitize(&pdf_in, Some(&pdf_out), &cfg);

    assert!(matches!(res, Err(OrchestratorError::ForensicLeak(_))));
    assert!(!pdf_out.exists());
}
