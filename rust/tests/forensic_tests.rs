use opsec_orchestrator::error::OrchestratorError;
use opsec_orchestrator::forensic::{verify_pdf_bytes, verify_png_bytes};

fn build_minimal_clean_pdf() -> Vec<u8> {
    b"%PDF-1.7\n\
1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n\
2 0 obj\n<</Type/Pages/Count 1/Kids[3 0 R]>>\nendobj\n\
3 0 obj\n<</Type/Page/Parent 2 0 R/MediaBox[0 0 595 842]>>\nendobj\n\
4 0 obj\n<</Author()/Title()/Producer()/CreationDate(D:19700101000000Z)/ModDate(D:19700101000000Z)>>\nendobj\n\
trailer\n<</Size 5/Root 1 0 R/Info 4 0 R/ID[<00000000000000000000000000000000><00000000000000000000000000000000>]>>\n\
startxref\n0\n%%EOF\n"
        .to_vec()
}

fn build_minimal_png(extra_chunk: Option<(&[u8; 4], &[u8])>, trailing: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"\x89PNG\r\n\x1a\n");
    // IHDR (13 bytes dummy)
    let ihdr_data = [0u8; 13];
    out.extend_from_slice(&(ihdr_data.len() as u32).to_be_bytes());
    out.extend_from_slice(b"IHDR");
    out.extend_from_slice(&ihdr_data);
    out.extend_from_slice(&[0u8; 4]);
    if let Some((ctype, data)) = extra_chunk {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(ctype);
        out.extend_from_slice(data);
        out.extend_from_slice(&[0u8; 4]);
    }
    // IDAT
    out.extend_from_slice(&4u32.to_be_bytes());
    out.extend_from_slice(b"IDAT");
    out.extend_from_slice(&[1, 2, 3, 4]);
    out.extend_from_slice(&[0u8; 4]);
    // IEND
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(b"IEND");
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(trailing);
    out
}

#[test]
fn approves_clean_pdf_and_clean_png() {
    let pdf = build_minimal_clean_pdf();
    assert!(verify_pdf_bytes(&pdf, &[]).is_ok());

    let png = build_minimal_png(None, b"");
    assert!(verify_png_bytes(&png).is_ok());
}

#[test]
fn rejects_pdf_with_obfuscated_js_author_trailing_bytes_incremental_eof_or_deny_term() {
    // 1. Hex-escaped /J#61vaScript
    let mut js_pdf = build_minimal_clean_pdf();
    let idx = js_pdf.windows(6).position(|w| w == b"endobj").unwrap_or(0);
    js_pdf.splice(idx..idx, b"/OpenAction<</S/J#61vaScript/JS(1)>>".iter().copied());
    assert!(matches!(
        verify_pdf_bytes(&js_pdf, &[]),
        Err(OrchestratorError::ForensicLeak(_))
    ));

    // 2. Non-empty /Author
    let author_pdf = String::from_utf8_lossy(&build_minimal_clean_pdf())
        .replace("/Author()", "/Author(Informante)")
        .into_bytes();
    assert!(matches!(
        verify_pdf_bytes(&author_pdf, &[]),
        Err(OrchestratorError::ForensicLeak(_))
    ));

    // 3. Trailing bytes after %%EOF
    let mut trailing_pdf = build_minimal_clean_pdf();
    trailing_pdf.extend_from_slice(b"COVERT_TRAILER");
    assert!(matches!(
        verify_pdf_bytes(&trailing_pdf, &[]),
        Err(OrchestratorError::ForensicLeak(_))
    ));

    // 4. Incremental update (two %%EOF)
    let mut inc_pdf = build_minimal_clean_pdf();
    inc_pdf.extend_from_slice(b"%%EOF\n");
    assert!(matches!(
        verify_pdf_bytes(&inc_pdf, &[]),
        Err(OrchestratorError::ForensicLeak(_))
    ));

    // 5. Residual deny-list term must abort WITHOUT leaking term in error message
    let mut deny_pdf = build_minimal_clean_pdf();
    let idx2 = deny_pdf.windows(6).position(|w| w == b"endobj").unwrap_or(0);
    deny_pdf.splice(idx2..idx2, b"% AliasHalcon\n".iter().copied());
    let err = verify_pdf_bytes(&deny_pdf, &[String::from("AliasHalcon")]);
    assert!(matches!(err, Err(OrchestratorError::ForensicLeak(_))));
    if let Err(e) = err {
        assert!(!e.to_string().contains("AliasHalcon"));
    }
}

#[test]
fn rejects_png_with_ancillary_text_chunk_or_trailing_bytes() {
    let dirty_chunk = build_minimal_png(Some((b"tEXt", b"Author\0Fuente")), b"");
    assert!(matches!(
        verify_png_bytes(&dirty_chunk),
        Err(OrchestratorError::ForensicLeak(_))
    ));

    let trailing = build_minimal_png(None, b"STEGO_PAYLOAD");
    assert!(matches!(
        verify_png_bytes(&trailing),
        Err(OrchestratorError::ForensicLeak(_))
    ));
}
