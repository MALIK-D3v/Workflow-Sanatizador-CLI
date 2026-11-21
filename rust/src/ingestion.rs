//! Memory-safe Rust pre-sandbox ingestion validator (single-open O_NOFOLLOW, magic bytes, zip-bombs).

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
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
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(OrchestratorError::InvalidInput(
                "symbolic links are disallowed by OPSEC policy".to_string(),
            ));
        }
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err(OrchestratorError::InvalidInput(format!(
                "unable to verify path symlink safety: {e}"
            )));
        }
        _ => {}
    }
    for ancestor in path.ancestors().skip(1) {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        match fs::symlink_metadata(ancestor) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(OrchestratorError::InvalidInput(
                    "symbolic links in ancestor directory are disallowed".to_string(),
                ));
            }
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(OrchestratorError::InvalidInput(format!(
                    "unable to verify ancestor symlink safety: {e}"
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn is_webp(header: &[u8]) -> bool {
    header.len() >= 12 && &header[0..4] == b"RIFF" && &header[8..12] == b"WEBP"
}

fn validate_member_name(name: &str, seen: &mut HashSet<String>) -> Result<String, OrchestratorError> {
    if name.chars().any(|c| c.is_control() || c == '\0') {
        return Err(OrchestratorError::UnsafeArchive(
            "DOCX archive contains control characters in member name".to_string(),
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
    let normalized = name.trim_start_matches("./").to_lowercase();
    if !seen.insert(normalized.clone()) {
        return Err(OrchestratorError::UnsafeArchive(
            "DOCX archive contains duplicate member names".to_string(),
        ));
    }
    Ok(normalized)
}

fn validate_docx_archive<R: Read + Seek>(
    reader: R,
    archive_file_bytes: u64,
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
    let mut has_document_xml = false;
    let mut buf = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    let bounded_archive_size = archive_file_bytes.max(1);

    for idx in 0..archive.len() {
        let mut entry = archive.by_index(idx).map_err(|e| match e {
            zip::result::ZipError::UnsupportedArchive(_) => {
                OrchestratorError::UnsafeArchive("encrypted or unsupported DOCX entry".to_string())
            }
            _ => OrchestratorError::UnsupportedFormat("unreadable DOCX entry".to_string()),
        })?;

        let raw_name = entry.name().to_string();
        let normalized = validate_member_name(&raw_name, &mut seen)?;
        if entry.encrypted() {
            return Err(OrchestratorError::UnsafeArchive(
                "encrypted DOCX entry is not supported".to_string(),
            ));
        }
        if normalized == "word/document.xml" {
            has_document_xml = true;
        }

        // Bounded streaming read defeats spoofed ZIP central directory headers
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

        // Clamp claimed compressed_size by real archive byte size so spoofed headers can't hide ratio
        let effective_comp = entry.compressed_size().min(bounded_archive_size).max(1);
        if actual_size > 4_096
            && (actual_size as f64 / effective_comp as f64) > limits.max_compression_ratio
        {
            return Err(OrchestratorError::UnsafeArchive(
                "DOCX entry exceeds safe compression ratio".to_string(),
            ));
        }
        total_uncompressed = total_uncompressed.saturating_add(actual_size);
    }

    if (total_uncompressed as f64 / bounded_archive_size as f64) > limits.max_compression_ratio {
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

fn open_input_nofollow(path: &Path, allow_symlinks: bool) -> Result<File, OrchestratorError> {
    assert_no_symlink_in_path(path, allow_symlinks)?;
    let mut opts = OpenOptions::new();
    opts.read(true);
    let mut flags = libc::O_CLOEXEC;
    if !allow_symlinks {
        flags |= libc::O_NOFOLLOW;
    }
    opts.custom_flags(flags);
    opts.open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => OrchestratorError::NotFound("input document".to_string()),
        _ if e.raw_os_error() == Some(libc::ELOOP) => {
            OrchestratorError::InvalidInput("symbolic links are disallowed by OPSEC policy".to_string())
        }
        _ => OrchestratorError::InvalidInput(format!("unable to open input file: {e}")),
    })
}

fn classify_and_validate_file(
    file: &mut File,
    size_bytes: u64,
    limits: &IngestionLimits,
) -> Result<DocumentType, OrchestratorError> {
    let mut header = [0u8; 32];
    let read_len = file
        .read(&mut header)
        .map_err(|e| OrchestratorError::Io(format!("unable to read header: {e}")))?;
    let sig = &header[..read_len];

    if sig.starts_with(PDF_MAGIC) {
        Ok(DocumentType::Pdf)
    } else if sig.starts_with(PNG_MAGIC)
        || sig.starts_with(JPEG_MAGIC)
        || sig.starts_with(TIFF_LE)
        || sig.starts_with(TIFF_BE)
        || is_webp(sig)
    {
        Ok(DocumentType::Image)
    } else if sig.starts_with(ZIP_MAGIC) {
        file.rewind()
            .map_err(|e| OrchestratorError::Io(format!("unable to rewind DOCX: {e}")))?;
        validate_docx_archive(file, size_bytes, limits)?;
        Ok(DocumentType::Docx)
    } else {
        Err(OrchestratorError::UnsupportedFormat(
            "unrecognized binary signature".to_string(),
        ))
    }
}

/// Validate an input document in place via a single O_NOFOLLOW open.
pub fn validate_document(
    path: &Path,
    limits: &IngestionLimits,
) -> Result<ValidatedDocument, OrchestratorError> {
    let mut file = open_input_nofollow(path, limits.allow_symlinks)?;
    let meta = file
        .metadata()
        .map_err(|e| OrchestratorError::InvalidInput(format!("unable to fstat input: {e}")))?;
    if !meta.is_file() {
        return Err(OrchestratorError::InvalidInput(
            "input path must be a regular file".to_string(),
        ));
    }
    let size_bytes = meta.size();
    if size_bytes == 0 {
        return Err(OrchestratorError::InvalidInput("input file is empty".to_string()));
    }
    if size_bytes > limits.max_file_bytes {
        return Err(OrchestratorError::FileTooLarge(format!(
            "{size_bytes} bytes > {} byte limit",
            limits.max_file_bytes
        )));
    }

    let doc_type = classify_and_validate_file(&mut file, size_bytes, limits)?;
    file.rewind()
        .map_err(|e| OrchestratorError::Io(format!("unable to rewind input: {e}")))?;
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
    let canonical = fs::canonicalize(path)
        .map_err(|e| OrchestratorError::InvalidInput(format!("cannot resolve input path: {e}")))?;

    Ok(ValidatedDocument {
        path: canonical,
        doc_type,
        size_bytes,
        sha256_hex: format!("{:x}", hasher.finalize()),
    })
}

/// Zero-TOCTOU single-open input ingestion: opens input ONCE with O_NOFOLLOW, copies bounded
/// bytes into the private staging dir while hashing, then validates magic bytes & ZIP archive
/// on the private staged copy itself.
pub fn ingest_to_staging(
    input_path: &Path,
    staging_dir: &Path,
    limits: &IngestionLimits,
) -> Result<(ValidatedDocument, PathBuf), OrchestratorError> {
    let mut src = open_input_nofollow(input_path, limits.allow_symlinks)?;
    let meta = src
        .metadata()
        .map_err(|e| OrchestratorError::InvalidInput(format!("unable to fstat input: {e}")))?;
    if !meta.is_file() {
        return Err(OrchestratorError::InvalidInput(
            "input path must be a regular file".to_string(),
        ));
    }

    let raw_staged = staging_dir.join("input.staged");
    let mut dst = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&raw_staged)
        .map_err(|e| OrchestratorError::Io(format!("unable to create staged input: {e}")))?;

    let mut hasher = Sha256::new();
    let mut buf = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    let mut total_bytes: u64 = 0;

    loop {
        let n = src
            .read(&mut buf)
            .map_err(|e| OrchestratorError::Io(format!("read error during ingestion: {e}")))?;
        if n == 0 {
            break;
        }
        total_bytes = total_bytes.saturating_add(n as u64);
        if total_bytes > limits.max_file_bytes {
            return Err(OrchestratorError::FileTooLarge(format!(
                "input exceeds {} byte limit",
                limits.max_file_bytes
            )));
        }
        hasher.update(&buf[..n]);
        dst.write_all(&buf[..n])
            .map_err(|e| OrchestratorError::Io(format!("write error during staging: {e}")))?;
    }
    if total_bytes == 0 {
        return Err(OrchestratorError::InvalidInput("input file is empty".to_string()));
    }

    dst.rewind()
        .map_err(|e| OrchestratorError::Io(format!("rewind failed on staged input: {e}")))?;
    let doc_type = classify_and_validate_file(&mut dst, total_bytes, limits)?;
    drop(dst);

    let ext = match doc_type {
        DocumentType::Pdf => "pdf",
        DocumentType::Docx => "docx",
        DocumentType::Image => "img",
    };
    let final_staged = staging_dir.join(format!("input.{ext}"));
    fs::rename(&raw_staged, &final_staged)
        .map_err(|e| OrchestratorError::Io(format!("failed to rename staged input: {e}")))?;
    fs::set_permissions(&final_staged, fs::Permissions::from_mode(0o400))
        .map_err(|e| OrchestratorError::Io(format!("failed to lock staged input permissions: {e}")))?;

    let canonical = fs::canonicalize(input_path)
        .map_err(|e| OrchestratorError::InvalidInput(format!("cannot resolve input path: {e}")))?;

    Ok((
        ValidatedDocument {
            path: canonical,
            doc_type,
            size_bytes: total_bytes,
            sha256_hex: format!("{:x}", hasher.finalize()),
        },
        final_staged,
    ))
}
