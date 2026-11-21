//! Strict versioned JSON IPC contract between the Rust orchestrator and Python worker.

use serde::{Deserialize, Serialize};
use serde_json::Value;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerResponse {
    pub protocol_version: u32,
    pub ok: bool,
    #[serde(default)]
    pub report: Option<Value>,
    #[serde(default)]
    pub error_code: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}
