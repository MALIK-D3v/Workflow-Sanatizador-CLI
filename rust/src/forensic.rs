//! Independent Rust fail-closed binary forensic verifier for PDF and PNG outputs.

use std::io::Read;
use std::sync::OnceLock;

use flate2::read::ZlibDecoder;
use regex::Regex;

use crate::error::OrchestratorError;

const PNG_SIG: &[u8] = b"\x89PNG\r\n\x1a\n";
const ALLOWED_PNG_CHUNKS: [&[u8; 4]; 3] = [b"IHDR", b"IDAT", b"IEND"];
const EPOCH_DATE: &str = "D:19700101000000Z";
const MAX_DECOMPRESSED_STREAM: u64 = 16 * 1024 * 1024; // 16 MiB cap per content stream

fn dangerous_pdf_regex() -> Result<&'static Regex, OrchestratorError> {
    static RE: OnceLock<Result<Regex, String>> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"/(?:JavaScript|JS|OpenAction|AA|URI|URL|GoToR|GoToE|SubmitForm|ImportData|AcroForm|XFA|Filespec|EF|EmbeddedFiles|EmbeddedFile|PieceInfo|OCProperties|RichMedia|Launch|Sound|Movie|3D|Metadata|Annots|Annot|ObjStm|Encrypt|Action|UF)(?:[\s/<>(\)\[\]{}%\x00]|$)",
        )
        .map_err(|e| e.to_string())
    })
    .as_ref()
    .map_err(|e| OrchestratorError::ForensicLeak(format!("regex init error: {e}")))
}

fn metadata_value_regex() -> Result<&'static Regex, OrchestratorError> {
    static RE: OnceLock<Result<Regex, String>> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"/(Author|Title|Subject|Keywords|Creator|Producer)\s*(?:\(([^)]+)\)|<([0-9A-Fa-f\s]+)>|(\d+\s+\d+\s+R))",
        )
        .map_err(|e| e.to_string())
    })
    .as_ref()
    .map_err(|e| OrchestratorError::ForensicLeak(format!("regex init error: {e}")))
}

fn date_value_regex() -> Result<&'static Regex, OrchestratorError> {
    static RE: OnceLock<Result<Regex, String>> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"/(CreationDate|ModDate)\s*(?:\(([^)]*)\)|<([0-9A-Fa-f\s]+)>|(\d+\s+\d+\s+R))",
        )
        .map_err(|e| e.to_string())
    })
    .as_ref()
    .map_err(|e| OrchestratorError::ForensicLeak(format!("regex init error: {e}")))
}

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

fn preceded_by_dict_close(raw: &[u8], stream_pos: usize) -> Option<usize> {
    let mut j = stream_pos;
    while j > 0 && raw[j - 1].is_ascii_whitespace() {
        j -= 1;
    }
    if j >= 2 && &raw[j - 2..j] == b">>" {
        Some(j - 2)
    } else {
        None
    }
}

fn dict_window_is_image(raw: &[u8], dict_end: usize) -> bool {
    let start = dict_end.saturating_sub(512);
    let dict_str = String::from_utf8_lossy(&raw[start..dict_end + 2]);
    let decoded = decode_pdf_hex_names(&dict_str);
    decoded.contains("/Subtype/Image") || decoded.contains("/Subtype /Image")
}

fn dict_window_is_flate(raw: &[u8], dict_end: usize) -> bool {
    let start = dict_end.saturating_sub(512);
    let dict_str = String::from_utf8_lossy(&raw[start..dict_end + 2]);
    let decoded = decode_pdf_hex_names(&dict_str);
    decoded.contains("/FlateDecode")
}

/// Separate PDF structure text from binary image streams while decompressing non-image streams
/// for deny-list scanning. Only recognizes `stream` immediately following a real dictionary `>>`,
/// preventing `% stream\n` comment-desynchronization attacks.
fn partition_pdf_structure_and_text_streams(raw: &[u8]) -> (String, Vec<String>) {
    let mut structure = Vec::with_capacity(raw.len());
    let mut decoded_streams: Vec<String> = Vec::new();
    let mut i = 0;

    while i < raw.len() {
        if raw[i..].starts_with(b"stream") {
            if let Some(dict_end) = preceded_by_dict_close(raw, i) {
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
                        let body = &raw[body_start..body_start + rel_end];
                        let is_image = dict_window_is_image(raw, dict_end);
                        if !is_image {
                            if dict_window_is_flate(raw, dict_end) {
                                let mut dec = ZlibDecoder::new(body).take(MAX_DECOMPRESSED_STREAM);
                                let mut plain = Vec::new();
                                if dec.read_to_end(&mut plain).is_ok() {
                                    decoded_streams
                                        .push(String::from_utf8_lossy(&plain).into_owned());
                                }
                            } else {
                                decoded_streams.push(String::from_utf8_lossy(body).into_owned());
                            }
                        }
                        structure.extend_from_slice(b"stream\nendstream");
                        i = body_start + rel_end + 9;
                        continue;
                    }
                }
            }
        }
        structure.push(raw[i]);
        i += 1;
    }

    (
        String::from_utf8_lossy(&structure).into_owned(),
        decoded_streams,
    )
}

fn find_eof_positions(raw: &[u8]) -> Vec<usize> {
    raw.windows(5)
        .enumerate()
        .filter_map(|(idx, w)| if w == b"%%EOF" { Some(idx) } else { None })
        .collect()
}

fn check_pdf_metadata_tokens(
    decoded: &str,
    violations: &mut Vec<String>,
) -> Result<(), OrchestratorError> {
    let meta_re = metadata_value_regex()?;
    for cap in meta_re.captures_iter(decoded) {
        let key = cap.get(1).map(|m| m.as_str()).unwrap_or("unknown");
        if cap.get(4).is_some() {
            violations.push(format!("indirect metadata reference disallowed: /{key}"));
            continue;
        }
        let val = cap
            .get(2)
            .or_else(|| cap.get(3))
            .map(|m| m.as_str().trim())
            .unwrap_or("");
        if !val.is_empty() {
            violations.push(format!("residual non-empty PDF metadata field: /{key}"));
        }
    }

    let date_re = date_value_regex()?;
    for cap in date_re.captures_iter(decoded) {
        let key = cap.get(1).map(|m| m.as_str()).unwrap_or("Date");
        if cap.get(3).is_some() || cap.get(4).is_some() {
            violations.push(format!("non-literal PDF date encoding disallowed: /{key}"));
            continue;
        }
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

    let (structure_raw, text_streams) = partition_pdf_structure_and_text_streams(raw);
    if structure_raw.contains("Written by MuPDF") || structure_raw.contains("/Producer(MuPDF") {
        violations.push("residual MuPDF fingerprint banner or Producer".to_string());
    }

    let decoded = decode_pdf_hex_names(&structure_raw);
    let dangerous_re = dangerous_pdf_regex()?;
    for m in dangerous_re.find_iter(&decoded) {
        let token = m
            .as_str()
            .trim_end_matches(|c: char| !c.is_alphanumeric() && c != '/');
        violations.push(format!("dangerous PDF structural token: {token}"));
    }

    check_pdf_metadata_tokens(&decoded, &mut violations)?;

    if !deny_terms.is_empty() {
        let lower_struct = decoded.to_lowercase();
        let lower_streams: Vec<String> = text_streams.iter().map(|s| s.to_lowercase()).collect();
        for term in deny_terms {
            let needle = term.trim().to_lowercase();
            if needle.is_empty() {
                continue;
            }
            if lower_struct.contains(&needle) || lower_streams.iter().any(|s| s.contains(&needle)) {
                violations.push("residual deny-list term detected in PDF output".to_string());
                break;
            }
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
    let mut chunk_index: usize = 0;
    let mut saw_idat = false;
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

        if chunk_index == 0 && (&ctype != b"IHDR" || length != 13) {
            violations.push("first PNG chunk must be 13-byte IHDR".to_string());
        }
        if !ALLOWED_PNG_CHUNKS.contains(&&ctype) {
            let name = String::from_utf8_lossy(&ctype);
            violations.push(format!("disallowed PNG chunk: {name}"));
        }

        let crc_start = pos + 8 + length;
        let stored_crc = u32::from_be_bytes([
            raw[crc_start],
            raw[crc_start + 1],
            raw[crc_start + 2],
            raw[crc_start + 3],
        ]);
        let computed_crc = crc32fast::hash(&raw[pos + 4..crc_start]);
        if stored_crc != computed_crc {
            violations.push("PNG chunk CRC-32 mismatch".to_string());
        }

        if &ctype == b"IDAT" {
            saw_idat = true;
        }
        pos = chunk_end;
        chunk_index += 1;

        if &ctype == b"IEND" {
            saw_iend = true;
            if length != 0 {
                violations.push(format!("non-empty PNG IEND chunk: {length} bytes"));
            }
            if pos < raw.len() {
                violations.push(format!(
                    "trailing bytes after PNG IEND: {} bytes",
                    raw.len() - pos
                ));
            }
            break;
        }
    }

    if !saw_idat {
        violations.push("missing PNG IDAT image data chunk".to_string());
    }
    if !saw_iend {
        violations.push("missing PNG IEND chunk".to_string());
    }
    if !violations.is_empty() {
        return Err(OrchestratorError::ForensicLeak(violations.join("; ")));
    }
    Ok(())
}
