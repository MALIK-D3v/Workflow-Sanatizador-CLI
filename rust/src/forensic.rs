//! Independent Rust fail-closed binary forensic verifier for PDF and PNG outputs.

use std::fs;
use std::path::Path;

use regex::Regex;
use zeroize::Zeroizing;

use crate::error::OrchestratorError;

const PNG_SIG: &[u8] = b"\x89PNG\r\n\x1a\n";
const ALLOWED_PNG_CHUNKS: [&[u8; 4]; 3] = [b"IHDR", b"IDAT", b"IEND"];
const EPOCH_DATE: &str = "D:19700101000000Z";

fn decode_pdf_hex_names(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'#' && i + 2 < bytes.len() {
            let h1 = (bytes[i + 1] as char).to_digit(16);
            let h2 = (bytes[i + 2] as char).to_digit(16);
            if let (Some(a), Some(b)) = (h1, h2) {
                let code = ((a << 4) | b) as u8;
                if code.is_ascii_graphic() {
                    out.push(code as char);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Remove binary `stream...endstream` bodies so compressed image pixels never cause token false positives.
fn extract_pdf_structure_text(raw: &[u8]) -> String {
    let mut cleaned = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i..].starts_with(b"stream")
            && (i == 0 || matches!(raw[i - 1], b'\n' | b'\r' | b' ' | b'>'))
        {
            let mut body_start = i + 6;
            if body_start < raw.len() && raw[body_start] == b'\r' {
                body_start += 1;
            }
            if body_start < raw.len() && raw[body_start] == b'\n' {
                body_start += 1;
                if let Some(rel_end) = raw[body_start..]
                    .windows(9)
                    .position(|w| w == b"endstream")
                {
                    cleaned.extend_from_slice(b"stream\nendstream");
                    i = body_start + rel_end + 9;
                    continue;
                }
            }
        }
        cleaned.push(raw[i]);
        i += 1;
    }
    String::from_utf8_lossy(&cleaned).into_owned()
}

fn find_eof_positions(raw: &[u8]) -> Vec<usize> {
    raw.windows(5)
        .enumerate()
        .filter_map(|(idx, w)| if w == b"%%EOF" { Some(idx) } else { None })
        .collect()
}

fn check_pdf_metadata_tokens(decoded: &str, violations: &mut Vec<String>) -> Result<(), OrchestratorError> {
    let non_empty_meta_re = Regex::new(
        r"/(Author|Title|Subject|Keywords|Creator|Producer)\s*(?:\(([^)]+)\)|<([0-9A-Fa-f]+)>)",
    )
    .map_err(|e| OrchestratorError::ForensicLeak(format!("regex init error: {e}")))?;

    for cap in non_empty_meta_re.captures_iter(decoded) {
        let key = cap.get(1).map(|m| m.as_str()).unwrap_or("unknown");
        let val = cap
            .get(2)
            .or_else(|| cap.get(3))
            .map(|m| m.as_str().trim())
            .unwrap_or("");
        if !val.is_empty() {
            violations.push(format!("residual non-empty PDF metadata field: /{key}"));
        }
    }

    let date_re = Regex::new(r"/(CreationDate|ModDate)\s*\(([^)]*)\)")
        .map_err(|e| OrchestratorError::ForensicLeak(format!("regex init error: {e}")))?;
    for cap in date_re.captures_iter(decoded) {
        let key = cap.get(1).map(|m| m.as_str()).unwrap_or("Date");
        let val = cap.get(2).map(|m| m.as_str().trim()).unwrap_or("");
        if !val.is_empty() && val != EPOCH_DATE {
            violations.push(format!("non-epoch PDF date field: /{key}"));
        }
    }
    Ok(())
}

pub fn verify_pdf_bytes(raw: &[u8], deny_terms: &[String]) -> Result<(), OrchestratorError> {
    let mut violations: Vec<String> = Vec::new();
    if !raw.starts_with(b"%PDF-") {
        return Err(OrchestratorError::ForensicLeak(
            "output does not begin with %PDF- signature".to_string(),
        ));
    }

    let eofs = find_eof_positions(raw);
    if eofs.len() != 1 {
        violations.push(format!(
            "unexpected PDF %%EOF count (incremental updates?): {}",
            eofs.len()
        ));
    } else if let Some(&eof_idx) = eofs.first() {
        let tail = &raw[eof_idx + 5..];
        let non_ws = tail.iter().filter(|b| !b.is_ascii_whitespace()).count();
        if non_ws > 0 {
            violations.push(format!("trailing bytes after PDF %%EOF: {non_ws} bytes"));
        }
    }

    let structure_raw = extract_pdf_structure_text(raw);
    if structure_raw.contains("Written by MuPDF") || structure_raw.contains("/Producer(MuPDF") {
        violations.push("residual MuPDF fingerprint banner or Producer".to_string());
    }

    let decoded = decode_pdf_hex_names(&structure_raw);

    let dangerous_re = Regex::new(
        r"/(?:JavaScript|JS|OpenAction|AA|URI|GoToR|GoToE|SubmitForm|ImportData|AcroForm|XFA|Filespec|EF|EmbeddedFiles|EmbeddedFile|PieceInfo|OCProperties|RichMedia|Launch|Sound|Movie|3D|Metadata|Annots|Annot)(?:[\s/<>(\[\]{}%]|$)",
    )
    .map_err(|e| OrchestratorError::ForensicLeak(format!("regex init error: {e}")))?;

    for m in dangerous_re.find_iter(&decoded) {
        let token = m.as_str().trim_end_matches(|c: char| !c.is_alphanumeric() && c != '/');
        violations.push(format!("dangerous PDF structural token: {token}"));
    }

    check_pdf_metadata_tokens(&decoded, &mut violations)?;

    let lower_struct = decoded.to_lowercase();
    for term in deny_terms {
        let trimmed = term.trim();
        if !trimmed.is_empty() && lower_struct.contains(&trimmed.to_lowercase()) {
            violations.push("residual deny-list term detected in PDF structure".to_string());
            break;
        }
    }

    if !violations.is_empty() {
        return Err(OrchestratorError::ForensicLeak(violations.join("; ")));
    }
    Ok(())
}

pub fn verify_png_bytes(raw: &[u8]) -> Result<(), OrchestratorError> {
    if !raw.starts_with(PNG_SIG) {
        return Err(OrchestratorError::ForensicLeak(
            "output does not begin with PNG signature".to_string(),
        ));
    }

    let mut violations: Vec<String> = Vec::new();
    let mut pos = PNG_SIG.len();
    let mut saw_iend = false;

    while pos + 12 <= raw.len() {
        let len_bytes: [u8; 4] = [raw[pos], raw[pos + 1], raw[pos + 2], raw[pos + 3]];
        let length = u32::from_be_bytes(len_bytes) as usize;
        let ctype: [u8; 4] = [raw[pos + 4], raw[pos + 5], raw[pos + 6], raw[pos + 7]];
        let chunk_end = pos.saturating_add(12).saturating_add(length);
        if chunk_end > raw.len() {
            violations.push("truncated PNG chunk structure".to_string());
            break;
        }
        if !ALLOWED_PNG_CHUNKS.contains(&&ctype) {
            let name = String::from_utf8_lossy(&ctype);
            violations.push(format!("disallowed PNG chunk: {name}"));
        }
        pos = chunk_end;
        if &ctype == b"IEND" {
            saw_iend = true;
            if pos < raw.len() {
                violations.push(format!(
                    "trailing bytes after PNG IEND: {} bytes",
                    raw.len() - pos
                ));
            }
            break;
        }
    }

    if !saw_iend {
        violations.push("missing PNG IEND chunk".to_string());
    }
    if !violations.is_empty() {
        return Err(OrchestratorError::ForensicLeak(violations.join("; ")));
    }
    Ok(())
}

pub fn verify_staged_file(path: &Path, is_png: bool, deny_terms: &[String]) -> Result<(), OrchestratorError> {
    let raw = Zeroizing::new(
        fs::read(path)
            .map_err(|e| OrchestratorError::Io(format!("unable to read staged output: {e}")))?,
    );
    if is_png {
        verify_png_bytes(&raw)
    } else {
        verify_pdf_bytes(&raw, deny_terms)
    }
}
