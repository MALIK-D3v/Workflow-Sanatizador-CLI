use std::io::Write;
use std::os::unix::fs::symlink;

use opsec_orchestrator::error::OrchestratorError;
use opsec_orchestrator::ingestion::{validate_document, DocumentType, IngestionLimits};
use tempfile::tempdir;
use zip::write::SimpleFileOptions;
use zip::CompressionMethod;

fn make_docx_bytes(payload_len: usize) -> Vec<u8> {
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut zw = zip::ZipWriter::new(&mut cursor);
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        zw.start_file("[Content_Types].xml", opts).ok();
        let _ = zw.write_all(b"<Types></Types>");
        zw.start_file("word/document.xml", opts).ok();
        let mut body = Vec::with_capacity(payload_len + 32);
        body.extend_from_slice(b"<w:document>");
        body.extend(std::iter::repeat_n(b'A', payload_len));
        body.extend_from_slice(b"</w:document>");
        let _ = zw.write_all(&body);
        let _ = zw.finish();
    }
    cursor.into_inner()
}

#[test]
fn detects_pdf_png_jpeg_and_docx_by_magic_bytes_ignoring_extension() {
    let dir = tempdir().ok();
    assert!(dir.is_some());
    let root = dir.as_ref().map(|d| d.path()).unwrap_or_else(|| unreachable!());

    let pdf = root.join("leak.bin");
    let _ = std::fs::write(&pdf, b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF\n");
    let res = validate_document(&pdf, &IngestionLimits::default());
    assert!(res.is_ok());
    if let Ok(doc) = res {
        assert_eq!(doc.doc_type, DocumentType::Pdf);
        assert_eq!(doc.sha256_hex.len(), 64);
    }

    let png = root.join("scan.dat");
    let _ = std::fs::write(&png, b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR");
    assert!(matches!(
        validate_document(&png, &IngestionLimits::default()).map(|d| d.doc_type),
        Ok(DocumentType::Image)
    ));

    let jpg = root.join("photo.unknown");
    let _ = std::fs::write(&jpg, b"\xff\xd8\xff\xe0\x00\x10JFIF");
    assert!(matches!(
        validate_document(&jpg, &IngestionLimits::default()).map(|d| d.doc_type),
        Ok(DocumentType::Image)
    ));

    let docx = root.join("memo.raw");
    let _ = std::fs::write(&docx, make_docx_bytes(128));
    assert!(matches!(
        validate_document(&docx, &IngestionLimits::default()).map(|d| d.doc_type),
        Ok(DocumentType::Docx)
    ));
}

#[test]
fn rejects_spoofed_pdf_symlinks_oversized_and_zip_bomb() {
    let dir = tempdir().ok();
    assert!(dir.is_some());
    let root = dir.as_ref().map(|d| d.path()).unwrap_or_else(|| unreachable!());

    let spoofed = root.join("fake.pdf");
    let _ = std::fs::write(&spoofed, b"#!/bin/sh\necho nope\n");
    assert!(matches!(
        validate_document(&spoofed, &IngestionLimits::default()),
        Err(OrchestratorError::UnsupportedFormat(_))
    ));

    let real_pdf = root.join("real.pdf");
    let _ = std::fs::write(&real_pdf, b"%PDF-1.7\n%%EOF\n");
    let link = root.join("link.pdf");
    let _ = symlink(&real_pdf, &link);
    assert!(matches!(
        validate_document(&link, &IngestionLimits::default()),
        Err(OrchestratorError::InvalidInput(_))
    ));

    let tight = IngestionLimits {
        max_file_bytes: 8,
        ..IngestionLimits::default()
    };
    assert!(matches!(
        validate_document(&real_pdf, &tight),
        Err(OrchestratorError::FileTooLarge(_))
    ));

    let bomb = root.join("bomb.docx");
    let _ = std::fs::write(&bomb, make_docx_bytes(2_000_000));
    let zip_limits = IngestionLimits {
        max_uncompressed_docx_bytes: 500_000,
        max_compression_ratio: 50.0,
        ..IngestionLimits::default()
    };
    assert!(matches!(
        validate_document(&bomb, &zip_limits),
        Err(OrchestratorError::UnsafeArchive(_))
    ));
}
