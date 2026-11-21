//! CLI entrypoint for the Option C Rust Air-Gapped OPSEC Orchestrator.
#![deny(warnings)]

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use serde::Serialize;

use opsec_orchestrator::error::OrchestratorError;
use opsec_orchestrator::ingestion::{assert_no_symlink_in_path, validate_document, DocumentType};
use opsec_orchestrator::orchestrator::{
    atomic_write_secure, orchestrate_sanitize, OrchestratorConfig, OrchestratorReport,
};

#[derive(Parser)]
#[command(
    name = "opsec-orchestrator",
    version,
    about = "Option C Hybrid OPSEC Sanitizer: Rust ingestion + Bubblewrap air-gapped Python worker + Rust binary forensic verifier"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Sanitize a single sensitive document inside an air-gapped sandbox.
    Sanitize {
        /// Sensitive document (PDF, DOCX, or image).
        input: PathBuf,
        /// Destination path for sanitized output.
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[command(flatten)]
        opts: CommonOpts,
    },
    /// Sanitize a directory of leaked documents with per-file error isolation.
    Batch {
        /// Directory of documents to sanitize.
        input_dir: PathBuf,
        /// Destination directory for clean outputs.
        #[arg(short, long)]
        output_dir: PathBuf,
        #[command(flatten)]
        opts: CommonOpts,
    },
}

#[derive(Args)]
struct CommonOpts {
    /// Path to the Python IPC worker executable (defaults to sibling .venv or PATH).
    #[arg(long)]
    worker_bin: Option<PathBuf>,
    /// Flattening DPI (72-600).
    #[arg(long, default_value_t = 200)]
    dpi: u32,
    /// Omit searchable OCR text layer on output PDF.
    #[arg(long)]
    no_ocr: bool,
    /// Skip OCR PII scanning on scanned PDFs/images (faster, lower OPSEC).
    #[arg(long)]
    skip_ocr_pii: bool,
    /// Inspect and report counts without writing sanitized output.
    #[arg(long)]
    dry_run: bool,
    /// Convert pages to grayscale + median filter to attenuate scanner/MIC patterns.
    #[arg(long)]
    paranoid_denoise: bool,
    /// Replace input filenames with SHA-256 prefixes in stdout and JSON reports.
    #[arg(long)]
    redact_filenames: bool,
    /// Offline NER mode: heuristic, spacy, or none.
    #[arg(long, default_value = "heuristic")]
    ner: String,
    /// Sensitive term that must always be redacted (repeatable).
    #[arg(long)]
    deny_list: Vec<String>,
    /// Newline-separated file of sensitive terms to redact.
    #[arg(long)]
    deny_list_file: Option<PathBuf>,
    /// Non-sensitive term excluded from redaction (repeatable).
    #[arg(long)]
    allow_list: Vec<String>,
    /// Newline-separated file of allowed terms.
    #[arg(long)]
    allow_list_file: Option<PathBuf>,
    /// Write OPSEC-safe JSON audit report to this path (0o600 atomic write).
    #[arg(long)]
    report_json: Option<PathBuf>,
    /// Worker execution timeout in seconds.
    #[arg(long, default_value_t = 120)]
    timeout_secs: u64,
    /// Explicitly permit running without kernel sandbox if bwrap/unshare are unavailable.
    #[arg(long)]
    allow_unsandboxed: bool,
}

#[derive(Serialize)]
struct BatchFailure {
    file: String,
    message: String,
}

#[derive(Serialize)]
struct BatchAudit {
    succeeded: Vec<OrchestratorReport>,
    failed: Vec<BatchFailure>,
}

fn load_terms(inline: &[String], file: Option<&Path>) -> Result<Vec<String>, OrchestratorError> {
    let mut terms: Vec<String> = inline
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if let Some(path) = file {
        assert_no_symlink_in_path(path, false)?;
        let content = fs::read_to_string(path).map_err(|e| {
            OrchestratorError::InvalidInput(format!("unable to read term list file: {e}"))
        })?;
        for line in content.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                terms.push(trimmed.to_string());
            }
        }
    }
    Ok(terms)
}

fn resolve_default_worker_bin(explicit: Option<PathBuf>) -> PathBuf {
    if let Some(bin) = explicit {
        return bin;
    }
    if let Ok(exe) = std::env::current_exe() {
        for ancestor in exe.ancestors().skip(1) {
            let candidate = ancestor.join(".venv/bin/opsec-sanitize-worker");
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    PathBuf::from("opsec-sanitize-worker")
}

fn build_config(opts: &CommonOpts) -> Result<OrchestratorConfig, OrchestratorError> {
    if !(72..=600).contains(&opts.dpi) {
        return Err(OrchestratorError::InvalidInput(
            "dpi must be between 72 and 600".to_string(),
        ));
    }
    Ok(OrchestratorConfig {
        worker_bin: resolve_default_worker_bin(opts.worker_bin.clone()),
        dpi: opts.dpi,
        enable_ocr: !opts.no_ocr,
        ocr_scan_inputs: !opts.skip_ocr_pii,
        paranoid_denoise: opts.paranoid_denoise,
        dry_run: opts.dry_run,
        redact_filenames: opts.redact_filenames,
        ner_mode: opts.ner.clone(),
        deny_list: load_terms(&opts.deny_list, opts.deny_list_file.as_deref())?,
        allow_list: load_terms(&opts.allow_list, opts.allow_list_file.as_deref())?,
        timeout: Duration::from_secs(opts.timeout_secs.max(1)),
        allow_unsandboxed: opts.allow_unsandboxed,
        ..OrchestratorConfig::default()
    })
}

fn batch_output_name(entry: &Path, doc_type: DocumentType, used: &mut HashSet<String>) -> String {
    let out_ext = if doc_type == DocumentType::Image {
        "png"
    } else {
        "pdf"
    };
    let stem = entry
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("document");
    let primary = format!("{stem}.sanitized.{out_ext}");
    if used.insert(primary.clone()) {
        return primary;
    }
    let orig_ext = entry
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("raw")
        .to_lowercase();
    let mut candidate = format!("{stem}_{orig_ext}.sanitized.{out_ext}");
    let mut idx = 2u32;
    while !used.insert(candidate.clone()) {
        candidate = format!("{stem}_{orig_ext}_{idx}.sanitized.{out_ext}");
        idx += 1;
    }
    candidate
}

fn print_summary(rep: &OrchestratorReport) {
    let mode = if rep.dry_run { "DRY-RUN" } else { "SANITIZED" };
    let gate = if rep.rust_forensic_verified {
        "RUST-PASS"
    } else {
        "SKIPPED(dry-run)"
    };
    println!(
        "[{mode}] {} ({}) | sandbox={} | forensic={gate}",
        rep.input_name, rep.doc_type, rep.sandbox_backend
    );
}

fn run() -> Result<(), OrchestratorError> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Sanitize {
            input,
            output,
            opts,
        } => {
            let cfg = build_config(&opts)?;
            let rep = orchestrate_sanitize(&input, output.as_deref(), &cfg)?;
            print_summary(&rep);
            if let Some(json_path) = opts.report_json {
                let data = serde_json::to_vec_pretty(&rep).map_err(|e| {
                    OrchestratorError::Io(format!("failed to serialize audit JSON: {e}"))
                })?;
                atomic_write_secure(&json_path, &data)?;
            }
            Ok(())
        }
        Commands::Batch {
            input_dir,
            output_dir,
            opts,
        } => {
            if !input_dir.is_dir() {
                return Err(OrchestratorError::InvalidInput(
                    "input directory does not exist".to_string(),
                ));
            }
            let cfg = build_config(&opts)?;
            if !cfg.dry_run {
                assert_no_symlink_in_path(&output_dir, false)?;
                fs::create_dir_all(&output_dir).map_err(|e| {
                    OrchestratorError::Io(format!("failed to create output dir: {e}"))
                })?;
            }

            let mut entries: Vec<PathBuf> = fs::read_dir(&input_dir)
                .map_err(|e| OrchestratorError::Io(format!("unable to list input dir: {e}")))?
                .filter_map(|res| res.ok().map(|e| e.path()))
                .collect();
            entries.sort();

            let mut succeeded = Vec::new();
            let mut failed = Vec::new();
            let mut used_names = HashSet::new();

            for entry in entries {
                let name = entry
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string();
                if name.starts_with('.') || entry.is_dir() {
                    continue;
                }
                let label = if cfg.redact_filenames {
                    "redacted".to_string()
                } else {
                    name
                };
                match validate_document(&entry, &cfg.limits) {
                    Ok(validated) => {
                        let out_name =
                            batch_output_name(&entry, validated.doc_type, &mut used_names);
                        let target = output_dir.join(out_name);
                        match orchestrate_sanitize(&entry, Some(&target), &cfg) {
                            Ok(rep) => {
                                print_summary(&rep);
                                succeeded.push(rep);
                            }
                            Err(err) => {
                                eprintln!("[FAILED] {label}: {err}");
                                failed.push(BatchFailure {
                                    file: label,
                                    message: err.to_string(),
                                });
                            }
                        }
                    }
                    Err(err) => {
                        eprintln!("[FAILED] {label}: {err}");
                        failed.push(BatchFailure {
                            file: label,
                            message: err.to_string(),
                        });
                    }
                }
            }

            let had_failures = !failed.is_empty();
            if let Some(json_path) = opts.report_json {
                let audit = BatchAudit { succeeded, failed };
                let data = serde_json::to_vec_pretty(&audit).map_err(|e| {
                    OrchestratorError::Io(format!("failed to serialize batch audit JSON: {e}"))
                })?;
                atomic_write_secure(&json_path, &data)?;
            }
            if had_failures {
                return Err(OrchestratorError::InvalidInput(
                    "one or more files failed sanitization".to_string(),
                ));
            }
            Ok(())
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let prefix = match err {
                OrchestratorError::ForensicLeak(_) => "[FORENSIC ABORT]",
                _ => "[ERROR]",
            };
            eprintln!("{prefix} {err}");
            ExitCode::from(err.exit_code() as u8)
        }
    }
}
