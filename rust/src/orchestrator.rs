//! End-to-end Rust hybrid orchestrator: Rust validation -> RAM staging -> sandboxed worker ->
//! independent Rust binary forensic gate -> atomic 0o600 delivery.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;
use tempfile::TempDir;
use zeroize::Zeroizing;

use crate::error::OrchestratorError;
use crate::forensic::verify_staged_file;
use crate::ingestion::{
    assert_no_symlink_in_path, compute_sha256, validate_document, DocumentType, IngestionLimits,
};
use crate::ipc::{WorkerRequest, WorkerResponse, PROTOCOL_VERSION};
use crate::sandbox::{detect_sandbox_backend, run_in_sandbox, SandboxBackend, SandboxPolicy};

#[derive(Debug, Clone)]
pub struct OrchestratorConfig {
    pub worker_bin: PathBuf,
    pub dpi: u32,
    pub padding_px: u32,
    pub enable_ocr: bool,
    pub ocr_scan_inputs: bool,
    pub paranoid_denoise: bool,
    pub dry_run: bool,
    pub redact_filenames: bool,
    pub ner_mode: String,
    pub deny_list: Vec<String>,
    pub allow_list: Vec<String>,
    pub limits: IngestionLimits,
    pub timeout: Duration,
    pub allow_unsandboxed: bool,
    pub sandbox_override: Option<SandboxBackend>,
}

impl Default for OrchestratorConfig {
    fn default() -> Self {
        Self {
            worker_bin: PathBuf::from("opsec-sanitize-worker"),
            dpi: 200,
            padding_px: 4,
            enable_ocr: true,
            ocr_scan_inputs: true,
            paranoid_denoise: false,
            dry_run: false,
            redact_filenames: false,
            ner_mode: "heuristic".to_string(),
            deny_list: Vec::new(),
            allow_list: Vec::new(),
            limits: IngestionLimits::default(),
            timeout: Duration::from_secs(120),
            allow_unsandboxed: false,
            sandbox_override: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct OrchestratorReport {
    pub input_name: String,
    pub doc_type: String,
    pub input_sha256: String,
    pub output_sha256: String,
    pub sandbox_backend: String,
    pub rust_forensic_verified: bool,
    pub dry_run: bool,
    pub worker_report: Value,
}

fn create_ram_staging_dir() -> Result<TempDir, OrchestratorError> {
    let shm = Path::new("/dev/shm");
    if shm.is_dir() {
        if let Ok(dir) = tempfile::Builder::new().prefix("opsec_orch_").tempdir_in(shm) {
            let _ = fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700));
            return Ok(dir);
        }
    }
    let dir = tempfile::Builder::new()
        .prefix("opsec_orch_")
        .tempdir()
        .map_err(|e| OrchestratorError::Io(format!("unable to create staging dir: {e}")))?;
    let _ = fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700));
    Ok(dir)
}

pub fn atomic_write_secure(target: &Path, bytes: &[u8]) -> Result<(), OrchestratorError> {
    assert_no_symlink_in_path(target, false)?;
    if target.exists() && target.is_dir() {
        return Err(OrchestratorError::InvalidInput(
            "output target cannot be an existing directory".to_string(),
        ));
    }
    if let Some(parent) = target.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| {
                OrchestratorError::Io(format!("failed to create output directory: {e}"))
            })?;
        }
    }

    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let fname = target
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    let tmp_path = target.with_file_name(format!(".{fname}.{pid}.{nanos}.tmp"));

    let mut opts = OpenOptions::new();
    opts.write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc_o_nofollow());

    let write_res: Result<(), OrchestratorError> = (|| {
        let mut file = opts.open(&tmp_path).map_err(|e| {
            OrchestratorError::Io(format!("unable to create atomic temp file: {e}"))
        })?;
        file.write_all(bytes)
            .map_err(|e| OrchestratorError::Io(format!("unable to write output bytes: {e}")))?;
        file.sync_all()
            .map_err(|e| OrchestratorError::Io(format!("fsync failed on output: {e}")))?;
        Ok(())
    })();

    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    fs::rename(&tmp_path, target).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        OrchestratorError::Io(format!("atomic rename failed: {e}"))
    })?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn libc_o_nofollow() -> i32 {
    0o400000
}

#[cfg(not(target_os = "linux"))]
fn libc_o_nofollow() -> i32 {
    0
}

fn resolve_backend(cfg: &OrchestratorConfig) -> Result<SandboxBackend, OrchestratorError> {
    let backend = cfg.sandbox_override.unwrap_or_else(detect_sandbox_backend);
    if backend == SandboxBackend::UnsafeDirect && !cfg.allow_unsandboxed {
        return Err(OrchestratorError::SandboxError(
            "no kernel sandbox (bwrap/unshare) available; refusing to run unsandboxed without --allow-unsandboxed"
                .to_string(),
        ));
    }
    Ok(backend)
}

fn validate_output_path(
    input_canonical: &Path,
    output_path: Option<&Path>,
    dry_run: bool,
) -> Result<(), OrchestratorError> {
    if dry_run {
        return Ok(());
    }
    let out = output_path.ok_or_else(|| {
        OrchestratorError::InvalidInput("output path is required unless --dry-run is set".to_string())
    })?;
    assert_no_symlink_in_path(out, false)?;
    if out.exists() && out.is_dir() {
        return Err(OrchestratorError::InvalidInput(
            "output path cannot be an existing directory".to_string(),
        ));
    }
    if let Ok(out_canon) = fs::canonicalize(out) {
        if out_canon == input_canonical {
            return Err(OrchestratorError::InvalidInput(
                "refusing to overwrite input document in place".to_string(),
            ));
        }
    }
    Ok(())
}

fn stage_extension(doc_type: DocumentType, output_path: Option<&Path>) -> (&'static str, bool) {
    let wants_png = doc_type == DocumentType::Image
        && output_path
            .and_then(|p| p.extension())
            .and_then(|e| e.to_str())
            .map(|e| !e.eq_ignore_ascii_case("pdf"))
            .unwrap_or(true);
    if wants_png {
        ("png", true)
    } else {
        ("pdf", false)
    }
}

pub fn orchestrate_sanitize(
    input_path: &Path,
    output_path: Option<&Path>,
    cfg: &OrchestratorConfig,
) -> Result<OrchestratorReport, OrchestratorError> {
    let validated = validate_document(input_path, &cfg.limits)?;
    validate_output_path(&validated.path, output_path, cfg.dry_run)?;
    let backend = resolve_backend(cfg)?;

    let staging = create_ram_staging_dir()?;
    let input_ext = match validated.doc_type {
        DocumentType::Pdf => "pdf",
        DocumentType::Docx => "docx",
        DocumentType::Image => "img",
    };
    let staged_in = staging.path().join(format!("input.{input_ext}"));
    fs::copy(&validated.path, &staged_in)
        .map_err(|e| OrchestratorError::Io(format!("failed to copy input to RAM staging: {e}")))?;
    let _ = fs::set_permissions(&staged_in, fs::Permissions::from_mode(0o400));

    let (out_ext, is_png) = stage_extension(validated.doc_type, output_path);
    let staged_out = staging.path().join(format!("staged.{out_ext}"));

    let req = WorkerRequest {
        protocol_version: PROTOCOL_VERSION,
        input_path: staged_in.to_string_lossy().into_owned(),
        output_path: if cfg.dry_run {
            None
        } else {
            Some(staged_out.to_string_lossy().into_owned())
        },
        dpi: cfg.dpi,
        padding_px: cfg.padding_px,
        enable_ocr: cfg.enable_ocr,
        ocr_scan_inputs: cfg.ocr_scan_inputs,
        paranoid_denoise: cfg.paranoid_denoise,
        dry_run: cfg.dry_run,
        redact_filenames: true, // Worker never needs original host filename
        ner_mode: cfg.ner_mode.clone(),
        deny_list: cfg.deny_list.clone(),
        allow_list: cfg.allow_list.clone(),
    };
    let req_bytes = Zeroizing::new(
        serde_json::to_vec(&req)
            .map_err(|e| OrchestratorError::WorkerError(format!("IPC serialize failed: {e}")))?,
    );

    let policy = SandboxPolicy {
        backend,
        writable_dir: staging.path().to_path_buf(),
        timeout: cfg.timeout,
    };

    let sandbox_out = run_in_sandbox(&cfg.worker_bin, &[], &req_bytes, &policy)?;
    let resp: WorkerResponse = serde_json::from_str(sandbox_out.stdout.trim()).map_err(|_| {
        OrchestratorError::WorkerError(format!(
            "invalid JSON response from sandboxed worker (exit={})",
            sandbox_out.exit_code
        ))
    })?;

    if resp.protocol_version != PROTOCOL_VERSION {
        return Err(OrchestratorError::WorkerError(format!(
            "unexpected worker protocol version: {}",
            resp.protocol_version
        )));
    }
    if !resp.ok {
        let msg = resp
            .message
            .unwrap_or_else(|| "worker reported sanitization failure".to_string());
        if resp.error_code.as_deref() == Some("FORENSIC_LEAK") {
            return Err(OrchestratorError::ForensicLeak(msg));
        }
        return Err(OrchestratorError::WorkerError(msg));
    }

    let display_name = if cfg.redact_filenames {
        format!("sha256:{}", &validated.sha256_hex[..12])
    } else {
        input_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("document")
            .to_string()
    };

    if cfg.dry_run {
        return Ok(OrchestratorReport {
            input_name: display_name,
            doc_type: validated.doc_type.as_str().to_string(),
            input_sha256: validated.sha256_hex,
            output_sha256: String::new(),
            sandbox_backend: backend.as_str().to_string(),
            rust_forensic_verified: false,
            dry_run: true,
            worker_report: resp.report.unwrap_or(Value::Null),
        });
    }

    if !staged_out.is_file() {
        return Err(OrchestratorError::WorkerError(
            "worker succeeded without producing staged output file".to_string(),
        ));
    }

    // Independent Rust binary forensic verification BEFORE atomic delivery!
    verify_staged_file(&staged_out, is_png, &cfg.deny_list)?;

    let out_bytes = Zeroizing::new(
        fs::read(&staged_out)
            .map_err(|e| OrchestratorError::Io(format!("unable to read verified output: {e}")))?,
    );
    let out_sha256 = compute_sha256(&staged_out)?;
    if let Some(final_dest) = output_path {
        atomic_write_secure(final_dest, &out_bytes)?;
    }

    Ok(OrchestratorReport {
        input_name: display_name,
        doc_type: validated.doc_type.as_str().to_string(),
        input_sha256: validated.sha256_hex,
        output_sha256: out_sha256,
        sandbox_backend: backend.as_str().to_string(),
        rust_forensic_verified: true,
        dry_run: false,
        worker_report: resp.report.unwrap_or(Value::Null),
    })
}
