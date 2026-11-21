//! End-to-end Rust hybrid orchestrator: zero-TOCTOU single-open ingestion -> RAM staging ->
//! minimal-allowlist Bubblewrap sandbox -> single-open O_NOFOLLOW Rust forensic gate ->
//! atomic 0o600 delivery.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;
use tempfile::TempDir;
use zeroize::Zeroizing;

use crate::error::OrchestratorError;
use crate::forensic::{verify_pdf_bytes, verify_png_bytes};
use crate::ingestion::{
    assert_no_symlink_in_path, ingest_to_staging, sha256_bytes, DocumentType, IngestionLimits,
};
use crate::ipc::{WorkerReport, WorkerRequest, WorkerResponse, PROTOCOL_VERSION};
use crate::sandbox::{detect_sandbox_backend, run_in_sandbox, SandboxBackend, SandboxPolicy};

const MAX_STAGED_OUTPUT_BYTES: u64 = 250 * 1024 * 1024; // 250 MiB cap

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
    pub allow_unshare_fallback: bool,
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
            allow_unshare_fallback: false,
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
    pub worker_report: Option<WorkerReport>,
}

fn create_ram_staging_dir() -> Result<TempDir, OrchestratorError> {
    let shm = Path::new("/dev/shm");
    if shm.is_dir() {
        if let Ok(dir) = tempfile::Builder::new().prefix("opsec_orch_").tempdir_in(shm) {
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).map_err(|e| {
                OrchestratorError::Io(format!("failed to restrict staging dir permissions: {e}"))
            })?;
            return Ok(dir);
        }
    }
    let dir = tempfile::Builder::new()
        .prefix("opsec_orch_")
        .tempdir()
        .map_err(|e| OrchestratorError::Io(format!("unable to create staging dir: {e}")))?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).map_err(|e| {
        OrchestratorError::Io(format!("failed to restrict staging dir permissions: {e}"))
    })?;
    Ok(dir)
}

fn random_hex_8() -> Result<String, OrchestratorError> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes)
        .map_err(|e| OrchestratorError::Io(format!("CSPRNG failure: {e}")))?;
    let mut out = String::with_capacity(16);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    Ok(out)
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

    let nonce = random_hex_8()?;
    let fname = target
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    let tmp_path = target.with_file_name(format!(".{fname}.{nonce}.tmp"));

    let mut opts = OpenOptions::new();
    opts.write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);

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

fn resolve_backend(cfg: &OrchestratorConfig) -> Result<SandboxBackend, OrchestratorError> {
    let backend = cfg.sandbox_override.unwrap_or_else(detect_sandbox_backend);
    match backend {
        SandboxBackend::Bubblewrap => Ok(backend),
        SandboxBackend::UnshareNet => {
            if cfg.allow_unshare_fallback || cfg.allow_unsandboxed {
                Ok(backend)
            } else {
                Err(OrchestratorError::SandboxError(
                    "bubblewrap unavailable; refusing degraded unshare-net without --allow-unshare-fallback"
                        .to_string(),
                ))
            }
        }
        SandboxBackend::UnsafeDirect => {
            if cfg.allow_unsandboxed {
                Ok(backend)
            } else {
                Err(OrchestratorError::SandboxError(
                    "no kernel sandbox available; refusing unsandboxed run without --allow-unsandboxed"
                        .to_string(),
                ))
            }
        }
    }
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

/// Derive minimal read-only bind mounts needed for the Python venv/project ONLY (never /home).
fn derive_worker_ro_binds(worker_bin: &Path) -> Vec<PathBuf> {
    let mut binds = Vec::new();
    let Ok(canon) = fs::canonicalize(worker_bin) else {
        return binds;
    };
    // If worker lives in `<project>/.venv/bin/opsec-sanitize-worker`, bind ONLY `<project>` RO
    if let Some(bin_dir) = canon.parent() {
        if bin_dir.file_name().and_then(|s| s.to_str()) == Some("bin") {
            if let Some(venv_dir) = bin_dir.parent() {
                if venv_dir.file_name().and_then(|s| s.to_str()) == Some(".venv") {
                    if let Some(project_dir) = venv_dir.parent() {
                        binds.push(project_dir.to_path_buf());
                        return binds;
                    }
                }
                binds.push(venv_dir.to_path_buf());
                return binds;
            }
        }
        binds.push(canon);
    }
    binds
}

fn sanitize_worker_message(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .take(512)
        .collect()
}

/// Single-open O_NOFOLLOW bounded read of staged output verifying regular file & nlink == 1.
fn read_staged_output_safely(staged_out: &Path) -> Result<Zeroizing<Vec<u8>>, OrchestratorError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(staged_out)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                OrchestratorError::ForensicLeak(
                    "sandboxed worker replaced staged output with a symbolic link".to_string(),
                )
            } else {
                OrchestratorError::WorkerError(format!("staged output missing or unreadable: {e}"))
            }
        })?;

    let meta = file
        .metadata()
        .map_err(|e| OrchestratorError::Io(format!("unable to fstat staged output: {e}")))?;
    if !meta.is_file() {
        return Err(OrchestratorError::ForensicLeak(
            "staged output is not a regular file".to_string(),
        ));
    }
    if meta.nlink() != 1 {
        return Err(OrchestratorError::ForensicLeak(
            "staged output has unexpected hard-link count".to_string(),
        ));
    }
    if meta.size() > MAX_STAGED_OUTPUT_BYTES {
        return Err(OrchestratorError::ForensicLeak(
            "staged output exceeds maximum safe byte cap".to_string(),
        ));
    }

    let mut buf = Zeroizing::new(Vec::with_capacity(meta.size() as usize));
    let mut bounded = file.take(MAX_STAGED_OUTPUT_BYTES + 1);
    bounded
        .read_to_end(&mut buf)
        .map_err(|e| OrchestratorError::Io(format!("failed to read staged output: {e}")))?;
    if (buf.len() as u64) > MAX_STAGED_OUTPUT_BYTES {
        return Err(OrchestratorError::ForensicLeak(
            "staged output exceeded byte cap during read".to_string(),
        ));
    }
    Ok(buf)
}

pub fn orchestrate_sanitize(
    input_path: &Path,
    output_path: Option<&Path>,
    cfg: &OrchestratorConfig,
) -> Result<OrchestratorReport, OrchestratorError> {
    let backend = resolve_backend(cfg)?;
    let staging = create_ram_staging_dir()?;

    // Zero-TOCTOU single-open input copy + validation into private RAM staging
    let (validated, staged_in) = ingest_to_staging(input_path, staging.path(), &cfg.limits)?;
    validate_output_path(&validated.path, output_path, cfg.dry_run)?;

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
        redact_filenames: true,
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
        ro_extra_binds: derive_worker_ro_binds(&cfg.worker_bin),
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
        let msg = sanitize_worker_message(
            resp.message
                .as_deref()
                .unwrap_or("worker reported sanitization failure"),
        );
        if resp.error_code.as_deref() == Some("FORENSIC_LEAK") {
            return Err(OrchestratorError::ForensicLeak(msg));
        }
        return Err(OrchestratorError::WorkerError(msg));
    }

    let hash_prefix = validated.sha256_hex.get(..12).unwrap_or("000000000000");
    let display_name = if cfg.redact_filenames {
        format!("sha256:{hash_prefix}")
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
            worker_report: resp.report,
        });
    }

    // Zero-TOCTOU single O_NOFOLLOW read -> Rust binary forensic gate -> hash -> atomic 0o600 write
    let out_bytes = read_staged_output_safely(&staged_out)?;
    if is_png {
        verify_png_bytes(&out_bytes)?;
    } else {
        verify_pdf_bytes(&out_bytes, &cfg.deny_list)?;
    }
    let out_sha256 = sha256_bytes(&out_bytes);
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
        worker_report: resp.report,
    })
}
