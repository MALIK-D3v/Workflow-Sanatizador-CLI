//! Typed OPSEC orchestrator errors and deterministic CLI exit codes.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum OrchestratorError {
    #[error("document not found: {0}")]
    NotFound(String),

    #[error("invalid input path or document: {0}")]
    InvalidInput(String),

    #[error("unsupported or spoofed document format: {0}")]
    UnsupportedFormat(String),

    #[error("input file exceeds size limit: {0}")]
    FileTooLarge(String),

    #[error("unsafe DOCX/ZIP archive: {0}")]
    UnsafeArchive(String),

    #[error("sandbox policy error: {0}")]
    SandboxError(String),

    #[error("worker IPC failure: {0}")]
    WorkerError(String),

    #[error("forensic verification abort: {0}")]
    ForensicLeak(String),

    #[error("I/O error: {0}")]
    Io(String),
}

impl OrchestratorError {
    /// Deterministic exit code: 2 for fail-closed forensic leaks, 1 for all other failures.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::ForensicLeak(_) => 2,
            _ => 1,
        }
    }
}
