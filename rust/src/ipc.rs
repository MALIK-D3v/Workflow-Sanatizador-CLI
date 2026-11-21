//! Strict versioned JSON IPC contract between the Rust orchestrator and Python worker.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerRequest {
    pub protocol_version: u32,
    pub input_path: String,
    pub output_path: Option<String>,
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
}

/// Strictly typed worker audit summary — rejects unexpected fields from an untrusted worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerReport {
    pub input_name: String,
    pub doc_type: String,
    pub input_sha256: String,
    pub output_sha256: String,
    pub page_count: u32,
    pub metadata_keys_removed: Vec<String>,
    pub attachments_removed: u32,
    pub annotations_removed: u32,
    pub pii_counts: BTreeMap<String, u32>,
    pub forensic_verified: bool,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerResponse {
    pub protocol_version: u32,
    pub ok: bool,
    #[serde(default)]
    pub report: Option<WorkerReport>,
    #[serde(default)]
    pub error_code: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}
