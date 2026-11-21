use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use flate2::write::ZlibEncoder;
use flate2::Compression;
use opsec_orchestrator::error::OrchestratorError;
use opsec_orchestrator::forensic::{verify_pdf_bytes, verify_png_bytes};
use opsec_orchestrator::orchestrator::{orchestrate_sanitize, OrchestratorConfig};
use opsec_orchestrator::sandbox::{run_in_sandbox, SandboxBackend, SandboxPolicy};
use tempfile::tempdir;

fn make_valid_crc_png(iend_payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"\x89PNG\r\n\x1a\n");

    let push_chunk = |buf: &mut Vec<u8>, ctype: &[u8; 4], data: &[u8]| {
        buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
        buf.extend_from_slice(ctype);
        buf.extend_from_slice(data);
        let mut crc_input = Vec::with_capacity(4 + data.len());
        crc_input.extend_from_slice(ctype);
        crc_input.extend_from_slice(data);
        buf.extend_from_slice(&crc32fast::hash(&crc_input).to_be_bytes());
    };

    push_chunk(&mut out, b"IHDR", &[0u8; 13]);
    push_chunk(&mut out, b"IDAT", &[1, 2, 3, 4]);
    push_chunk(&mut out, b"IEND", iend_payload);
    out
}

#[test]
fn bwrap_hides_host_run_sockets_and_home_directory() {
    let staging = tempdir().ok();
    assert!(staging.is_some());
    let staging_path = staging
        .as_ref()
        .map(|d| d.path())
        .unwrap_or_else(|| unreachable!());

    let host_home = std::env::var("HOME").unwrap_or_else(|_| "/home".to_string());
    let policy = SandboxPolicy {
        backend: SandboxBackend::Bubblewrap,
        writable_dir: staging_path.to_path_buf(),
        ro_extra_binds: Vec::new(),
        timeout: Duration::from_secs(10),
    };

    let probe = format!(
        "import os, sys\n\
run_entries = os.listdir('/run') if os.path.isdir('/run') else []\n\
home_exists = os.path.exists({home:?})\n\
print(f'run={{len(run_entries)}} home={{home_exists}}')\n\
sys.exit(0 if (len(run_entries) == 0 and not home_exists) else 7)\n",
        home = host_home,
    );

    let out = run_in_sandbox(Path::new("/usr/bin/python3"), &["-c", &probe], b"", &policy);
    assert!(out.is_ok(), "sandbox run failed: {out:?}");
    if let Ok(res) = out {
        assert_eq!(res.exit_code, 0, "stdout={} stderr={}", res.stdout, res.stderr);
        assert!(res.stdout.contains("run=0 home=False"));
    }
}

#[test]
fn rust_pdf_verifier_blocks_stream_comment_desync_objstm_and_compressed_deny_stream() {
    // 1. Comment-embedded "stream\n" MUST NOT blind the scanner to /JavaScript
    let desync_pdf = b"%PDF-1.7\n\
% stream\n\
1 0 obj\n<</Type/Catalog/OpenAction<</S/JavaScript/JS(1)>>/Pages 2 0 R>>\nendobj\n\
% endstream\n\
%%EOF\n";
    assert!(matches!(
        verify_pdf_bytes(desync_pdf, &[]),
        Err(OrchestratorError::ForensicLeak(_))
    ));

    // 2. /ObjStm MUST be rejected outright
    let objstm_pdf = b"%PDF-1.7\n\
1 0 obj\n<</Type/ObjStm/N 1/First 5/Length 2>>\nstream\n()\nendstream\nendobj\n\
%%EOF\n";
    assert!(matches!(
        verify_pdf_bytes(objstm_pdf, &[]),
        Err(OrchestratorError::ForensicLeak(_))
    ));

    // 3. Compressed FlateDecode non-image content stream containing deny-list term MUST be caught
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    let _ = enc.write_all(b"BT /F1 12 Tf (SecretSourceAlias) Tj ET");
    let compressed = enc.finish().unwrap_or_default();

    let mut content_pdf = Vec::new();
    content_pdf.extend_from_slice(
        format!(
            "%PDF-1.7\n1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n\
2 0 obj\n<</Filter/FlateDecode/Length {}>>\nstream\n",
            compressed.len()
        )
        .as_bytes(),
    );
    content_pdf.extend_from_slice(&compressed);
    content_pdf.extend_from_slice(b"\nendstream\nendobj\n%%EOF\n");

    assert!(matches!(
        verify_pdf_bytes(&content_pdf, &[String::from("SecretSourceAlias")]),
        Err(OrchestratorError::ForensicLeak(_))
    ));
}

#[test]
fn rust_png_verifier_rejects_nonzero_iend_payload_and_bad_crc() {
    // Valid PNG passes
    assert!(verify_png_bytes(&make_valid_crc_png(b"")).is_ok());

    // Smuggled bytes INSIDE IEND chunk MUST fail
    assert!(matches!(
        verify_png_bytes(&make_valid_crc_png(b"SMUGGLED_INSIDE_IEND")),
        Err(OrchestratorError::ForensicLeak(_))
    ));

    // Corrupted CRC MUST fail
    let mut bad_crc = make_valid_crc_png(b"");
    if let Some(last) = bad_crc.last_mut() {
        *last ^= 0xFF;
    }
    assert!(matches!(
        verify_png_bytes(&bad_crc),
        Err(OrchestratorError::ForensicLeak(_))
    ));
}

#[test]
fn orchestrator_rejects_worker_symlink_swap_on_staged_output() {
    let dir = tempdir().ok();
    assert!(dir.is_some());
    let root = dir.as_ref().map(|d| d.path()).unwrap_or_else(|| unreachable!());

    // Create minimal valid PDF input
    let pdf_in = root.join("in.pdf");
    let _ = std::fs::write(&pdf_in, b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF\n");

    // Rogue worker replaces staged output with a symlink to /etc/ld.so.cache (readable in sandbox)
    let rogue = root.join("symlink_worker.py");
    let script = r#"#!/usr/bin/env python3
import json, os, sys
req = json.loads(sys.stdin.read())
os.symlink("/usr/bin/true", req["output_path"])
print(json.dumps({"protocol_version": 1, "ok": True, "report": {
    "input_name": "x", "doc_type": "pdf", "input_sha256": "a"*64, "output_sha256": "b"*64,
    "page_count": 1, "metadata_keys_removed": [], "attachments_removed": 0,
    "annotations_removed": 0, "pii_counts": {}, "forensic_verified": True, "dry_run": False
}}))
"#;
    let _ = std::fs::write(&rogue, script);
    let _ = std::fs::set_permissions(&rogue, std::fs::Permissions::from_mode(0o755));

    let out_pdf = root.join("never.pdf");
    let cfg = OrchestratorConfig {
        worker_bin: PathBuf::from(&rogue),
        sandbox_override: Some(SandboxBackend::Bubblewrap),
        ..OrchestratorConfig::default()
    };

    let res = orchestrate_sanitize(&pdf_in, Some(&out_pdf), &cfg);
    assert!(res.is_err());
    assert!(!out_pdf.exists());
}
