//! Memory-safe Rust pre-sandbox ingestion validator (magic bytes, symlinks, zip-bombs).

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Seek};
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::OrchestratorError;

const PDF_MAGIC: &[u8] = b"%PDF-";
const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";
const JPEG_MAGIC: &[u8] = b"\xff\xd8\xff";
const TIFF_LE: &[u8] = b"II*\x00";
const TIFF_BE: &[u8] = b"MM\x00*";
const ZIP_MAGIC: &[u8] = b"PK\x03\x04";
const CHUNK_SIZE: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentType {
    Pdf,
    Docx,
    Image,
}

impl DocumentType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pdf => "pdf",
            Self::Docx => "docx",
            Self::Image => "image",
        }
    }
}

#[derive(Debug, Clone)]
pub struct IngestionLimits {
    pub max_file_bytes: u64,
    pub max_uncompressed_docx_bytes: u64,
    pub max_compression_ratio: f64,
    pub max_archive_entries: usize,
    pub allow_symlinks: bool,
}

impl Default for IngestionLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: 100 * 1024 * 1024,
            max_uncompressed_docx_bytes: 200 * 1024 * 1024,
            max_compression_ratio: 100.0,
            max_archive_entries: 2_000,
            allow_symlinks: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ValidatedDocument {
    pub path: PathBuf,
    pub doc_type: DocumentType,
    pub size_bytes: u64,
    pub sha256_hex: String,
}

pub fn assert_no_symlink_in_path(
    path: &Path,
    allow_symlinks: bool,
) -> Result<(), OrchestratorError> {
    if allow_symlinks {
        return Ok(());
    }
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(OrchestratorError::InvalidInput(
                "symbolic links are disallowed by OPSEC policy".to_string(),
            ));
        }
    }
    for ancestor in path.ancestors().skip(1) {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        if let Ok(meta) = fs::symlink_metadata(ancestor) {
            if meta.file_type().is_symlink() {
                return Err(OrchestratorError::InvalidInput(
                    "symbolic links in ancestor directory are disallowed".to_string(),
                ));
            }
        }
    }
    Ok(())
}

pub fn compute_sha256(path: &Path) -> Result<String, OrchestratorError> {
    let mut file = File::open(path)
        .map_err(|e| OrchestratorError::Io(format!("unable to read file for hashing: {e}")))?;
    let mut hasher = Sha256::new();
    let mut buf = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| OrchestratorError::Io(format!("read error while hashing: {e}")))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn is_webp(header: &[u8]) -> bool {
    header.len() >= 12 && &header[0..4] == b"RIFF" && &header[8..12] == b"WEBP"
}

fn validate_member_name(name: &str, seen: &mut HashSet<String>) -> Result<(), OrchestratorError> {
    if !seen.insert(name.to_string()) {
        return Err(OrchestratorError::UnsafeArchive(
            "DOCX archive contains duplicate member names".to_string(),
        ));
    }
    if name.contains('\\') || name.starts_with('/') {
        return Err(OrchestratorError::UnsafeArchive(
            "DOCX archive contains unsafe member path".to_string(),
        ));
    }
    for comp in Path::new(name).components() {
        if matches!(
            comp,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ) {
            return Err(OrchestratorError::UnsafeArchive(
                "DOCX archive contains path traversal entry".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_docx_archive<R: Read + Seek>(
    reader: R,
    limits: &IngestionLimits,
) -> Result<(), OrchestratorError> {
    let mut archive = zip::ZipArchive::new(reader).map_err(|_| {
        OrchestratorError::UnsupportedFormat("corrupt or invalid ZIP/DOCX archive".to_string())
    })?;

    if archive.len() > limits.max_archive_entries {
        return Err(OrchestratorError::UnsafeArchive(
            "DOCX archive exceeds maximum entry count".to_string(),
        ));
    }

    let mut seen = HashSet::with_capacity(archive.len());
    let mut total_uncompressed: u64 = 0;
    let mut total_compressed: u64 = 0;
    let mut has_document_xml = false;
    let mut buf = Zeroizing::new(vec![0u8; CHUNK_SIZE]);

    for idx in 0..archive.len() {
        let mut entry = archive.by_index(idx).map_err(|e| match e {
            zip::result::ZipError::UnsupportedArchive(_) => {
                OrchestratorError::UnsafeArchive("encrypted or unsupported DOCX entry".to_string())
            }
            _ => OrchestratorError::UnsupportedFormat("unreadable DOCX entry".to_string()),
        })?;

        let name = entry.name().to_string();
        validate_member_name(&name, &mut seen)?;
        if entry.encrypted() {
            return Err(OrchestratorError::UnsafeArchive(
                "encrypted DOCX entry is not supported".to_string(),
            ));
        }
        if name == "word/document.xml" {
            has_document_xml = true;
        }

        // Bounded streaming read to defeat spoofed ZIP central directory headers
        let mut actual_size: u64 = 0;
        loop {
            let n = entry
                .read(&mut buf)
                .map_err(|_| OrchestratorError::UnsafeArchive("corrupt ZIP stream".to_string()))?;
            if n == 0 {
                break;
            }
            actual_size = actual_size.saturating_add(n as u64);
            if total_uncompressed.saturating_add(actual_size) > limits.max_uncompressed_docx_bytes {
                return Err(OrchestratorError::UnsafeArchive(
                    "DOCX archive exceeds uncompressed size limit".to_string(),
                ));
            }
        }

        let comp_size = entry.compressed_size().max(1);
        if actual_size > 4_096 && (actual_size as f64 / comp_size as f64) > limits.max_compression_ratio
        {
            return Err(OrchestratorError::UnsafeArchive(
                "DOCX entry exceeds safe compression ratio".to_string(),
            ));
        }
        total_uncompressed = total_uncompressed.saturating_add(actual_size);
        total_compressed = total_compressed.saturating_add(comp_size);
    }

    if total_compressed > 0
        && (total_uncompressed as f64 / total_compressed as f64) > limits.max_compression_ratio
    {
        return Err(OrchestratorError::UnsafeArchive(
            "DOCX archive exceeds aggregate compression ratio".to_string(),
        ));
    }
    if !has_document_xml {
        return Err(OrchestratorError::UnsupportedFormat(
            "ZIP archive is not a valid DOCX document".to_string(),
        ));
    }
    Ok(())
}

pub fn validate_document(
    path: &Path,
    limits: &IngestionLimits,
) -> Result<ValidatedDocument, OrchestratorError> {
    if fs::symlink_metadata(path).is_err() {
        return Err(OrchestratorError::NotFound(
            path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("<unknown>")
                .to_string(),
        ));
    }
    assert_no_symlink_in_path(path, limits.allow_symlinks)?;

    let meta = fs::metadata(path)
        .map_err(|e| OrchestratorError::InvalidInput(format!("unable to stat input: {e}")))?;
    if !meta.is_file() {
        return Err(OrchestratorError::InvalidInput(
            "input path must be a regular file".to_string(),
        ));
    }
    let size_bytes = meta.len();
    if size_bytes == 0 {
        return Err(OrchestratorError::InvalidInput(
            "input file is empty".to_string(),
        ));
    }
    if size_bytes > limits.max_file_bytes {
        return Err(OrchestratorError::FileTooLarge(format!(
            "{size_bytes} bytes > {} byte limit",
            limits.max_file_bytes
        )));
    }

    let mut file = File::open(path)
        .map_err(|e| OrchestratorError::Io(format!("unable to open input: {e}")))?;
    let mut header = [0u8; 32];
    let read_len = file
        .read(&mut header)
        .map_err(|e| OrchestratorError::Io(format!("unable to read header: {e}")))?;
    let sig = &header[..read_len];

    let doc_type = if sig.starts_with(PDF_MAGIC) {
        DocumentType::Pdf
    } else if sig.starts_with(PNG_MAGIC)
        || sig.starts_with(JPEG_MAGIC)
        || sig.starts_with(TIFF_LE)
        || sig.starts_with(TIFF_BE)
        || is_webp(sig)
    {
        DocumentType::Image
    } else if sig.starts_with(ZIP_MAGIC) {
        let zip_file = File::open(path)
            .map_err(|e| OrchestratorError::Io(format!("unable to open DOCX: {e}")))?;
        validate_docx_archive(zip_file, limits)?;
        DocumentType::Docx
    } else {
        return Err(OrchestratorError::UnsupportedFormat(
            "unrecognized binary signature".to_string(),
        ));
    };

    let canonical = fs::canonicalize(path)
        .map_err(|e| OrchestratorError::InvalidInput(format!("cannot resolve input path: {e}")))?;
    let sha256_hex = compute_sha256(&canonical)?;

    Ok(ValidatedDocument {
        path: canonical,
        doc_type,
        size_bytes,
        sha256_hex,
    })
}
