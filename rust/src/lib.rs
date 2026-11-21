//! Rust air-gapped OPSEC orchestrator, sandbox runner, and independent binary forensic verifier.
#![deny(warnings)]

pub mod error;
pub mod forensic;
pub mod ingestion;
pub mod ipc;
pub mod orchestrator;
pub mod sandbox;
