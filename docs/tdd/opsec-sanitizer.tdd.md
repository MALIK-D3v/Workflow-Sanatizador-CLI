# TDD Evidence Report: Sanitizador de Filtraciones y Metadatos (OPSEC — Opción C Híbrida)

## 1. Source Plan & Architecture
- Plan aprobado: `/home/malik/.gemini/antigravity/brain/63498088-cb19-46ef-af7d-2da22645f184/opsec_sanitizer_tdd_plan.md`
- Arquitectura final: **Opción C — Híbrida Air-Gapped (Orquestador/Verificador en Rust + Worker Python en Sandbox Bubblewrap sin Red)**
  - **Capa Rust (`rust/`)**: Ingesta binaria zero-TOCTOU (`O_NOFOLLOW` + `Zeroizing`), staging en RAM (`/dev/shm`), sandbox Linux Bubblewrap con *allowlist* mínima solo-lectura (`--unshare-all --new-session --cap-drop ALL --tmpfs /run --tmpfs /tmp`), verificador forense binario independiente (PDF estructural + descompresión FlateDecode de streams no-imagen + PNG CRC-32/chunks) y entrega atómica `0o600`.
  - **Worker Python (`src/opsec_sanitizer/`)**: Motor de sanitización PDF/DOCX/Imágenes, detección híbrida Regex MX + NER offline, *flattening* irreversible y OCR offline (`RapidOcrEngine` ONNX), aislado detrás de IPC JSON v1 con duplicación de descriptor OS FD 1.
- Repositorio: `/home/malik/.gemini/antigravity/scratch/opsec-sanitizer` (rama `master`)

## 2. User Journeys
- **UJ-1**: Periodista sanitiza PDFs filtrados con metadatos `/Author`, XMP, adjuntos, anotaciones, texto oculto bajo tachados falsos, páginas rotadas o híbridas (texto + escaneo embebido).
- **UJ-2**: Periodista sanitiza documentos `.docx` eliminando `docProps/*`, comentarios, control de cambios (`w:del`, `*PrChange`), texto oculto (`w:vanish`), relaciones externas (`TargetMode="External"`) y campos peligrosos (`INCLUDEPICTURE`/`DDE`), ejecutando LibreOffice dentro de un sandbox Bubblewrap sin red.
- **UJ-3**: Editor anonimiza PII mexicano (CURP con dígito verificador, RFC física/moral, correos, teléfonos) y nombres propios mediante Regex + NER offline y re-aplica OCR únicamente sobre el contenido visible seguro.
- **UJ-4**: Responsable OPSEC usa `--dry-run`, `--report-json`, `--deny-list-file` y `--redact-filenames` sin exponer PII crudo en terminal, logs ni dejar temporales en disco.
- **UJ-5**: Defensa en profundidad *fail-closed*: archivos hostiles son bloqueados en Rust antes de tocar Python, el worker no tiene acceso a red ni a `/run` ni a `$HOME`, y el verificador binario independiente en Rust bloquea incluso un worker comprometido que intente entregar archivos contaminados o symlinks.

## 3. Task Execution Summary (RED → GREEN Checkpoints)

### Núcleo Worker Python (Iteraciones 1–9)
| Iteración | Resumen | Checkpoint RED | Checkpoint GREEN |
|---|---|---|---|
| **1. Ingesta segura** | Magic bytes, límites, anti-zip-bomb, rechazo de cifrado/symlinks | `1b37fda` | `8a72984` (`11 passed`) |
| **2. Regex PII México** | CURP (RENAPO), RFC 12/13, correos y teléfonos MX | `38671fe` | `0089eba` (`16 passed`) |
| **3. Motor Híbrido + NER** | Fusión de spans, allow/deny lists y NER offline en español | `9cecfc8` | `c184bd5` (`6 passed`) |
| **4. Sanitizador Imágenes** | Buffer RGB puro (cero EXIF/XMP/trailing bytes) y redacción opaca | `355883a` | `2de1872` (`4 passed`) |
| **5. Flattening PDF** | Rasterizado sin anotaciones, redacción de píxeles y PDF limpio | `dcf42fe` | `f8c404f` (`2 passed`) |
| **6. OCR + Compuerta Forense** | `RapidOcrEngine` ONNX offline + compuerta *fail-closed* | `708727d` | `5118464` (`7 passed`) |
| **7. Sanitizador DOCX** | Limpieza XML anti-XXE/SSRF + renderizado aislado | `855216c` | `7e212d3` (`3 passed`) |
| **8. Pipeline y CLI Python** | Staging `/dev/shm`, `0o600`, CLI Typer y lote | `c98b342` | `3485cbb` (`5 passed`) |
| **9. Hardening Python** | Remediación de hallazgos CRITICAL/HIGH (`security-reviewer` + `code-reviewer`) | `1dbf743` | `8a6edf4` (`68 passed`) |

### Capa Híbrida Opción C — Orquestador Rust + Sandbox Bubblewrap + IPC (Iteraciones C0–C5)
| Iteración | Resumen | Checkpoint RED | Checkpoint GREEN | Comando validado |
|---|---|---|---|---|
| **C0. Worker IPC Python** | Contrato JSON v1 stdin/stdout sin trazas | `99ed9a3` | `a651bb8` (`3 passed`) | `.venv/bin/pytest tests/unit/test_worker_ipc.py` |
| **C1. Ingesta Binaria Rust** | Magic bytes, symlinks, límites y anti-zip-bomb en Rust con `Zeroizing` | `37048b2` | `3883bdb` (`2 passed`) | `cargo test --test ingestion_tests` |
| **C2. Verificador Forense Rust** | Verificador binario PDF/PNG independiente (sin dependencias Python) | `eabeef9` | `ba77282` (`3 passed`) | `cargo test --test forensic_tests` |
| **C3. Sandbox Bubblewrap + IPC** | Pruebas reales de bloqueo de red, FS solo-lectura y timeout | `416b95f` | `a1554c7` (`3 passed`) | `cargo test --test sandbox_ipc_tests` |
| **C4. Orquestador E2E + CLI Rust** | Flujo completo Rust → Bubblewrap → Python → Verificador Rust → `0o600` (PDF/JPG/DOCX + worker comprometido) | `47bb39c` | `bde460f` (`10 passed`) | `cargo test` |
| **C5. Hardening Opción C** | Allowlist RO mínima (oculta `/run` y `$HOME`), zero-TOCTOU `O_NOFOLLOW`, PDF desync/`/ObjStm`/FlateDecode, PNG CRC-32/`IEND==0`, OS FD 1 aislado | `74de3c3` | `91255e8` (`14 Rust + 71 Python passed`) | `cargo test && .venv/bin/pytest --cov=src/opsec_sanitizer` |

## 4. Test Specification Matrix (Resumen Consolidado)

| # | Garantía verificada | Suite / Archivo | Tipo | Resultado |
|---|---|---|---|---|
| 1 | Ingesta binaria y anti-zip-bomb (Python y Rust zero-TOCTOU `O_NOFOLLOW`) | `tests/unit/test_ingestion.py`, `rust/tests/ingestion_tests.rs` | unit | PASS |
| 2 | Detección determinista CURP/RFC/email/teléfono + NER offline en español | `tests/unit/test_regex_mx.py`, `tests/unit/test_pii_merger.py` | unit | PASS |
| 3 | Flattening PDF (rotados, híbridos, `annots=False`), imágenes RGBA y DOCX sin metadatos/canaries | `tests/integration/test_*.py`, `tests/unit/test_security_hardening.py` | integration | PASS |
| 4 | Aislamiento real Bubblewrap: sin red, sin `/run` ni `$HOME`, sin escritura fuera del staging, timeout con `killpg` | `rust/tests/sandbox_ipc_tests.rs`, `rust/tests/security_hardening_c_tests.rs` | integration | PASS |
| 5 | Verificador forense binario independiente en Rust (PDF desync/`/ObjStm`/FlateDecode, PNG CRC-32/`IEND==0`, rechazo de worker comprometido o symlink swap) | `rust/tests/forensic_tests.rs`, `rust/tests/e2e_hybrid_tests.rs`, `rust/tests/security_hardening_c_tests.rs` | integration/e2e | PASS |
| 6 | Flujo completo CLI Python y Orquestador Rust release (`0o600`, reportes sin PII, `dry-run`, `batch`) | `tests/e2e/test_cli_e2e.py`, `rust/tests/e2e_hybrid_tests.rs` | e2e | PASS |

## 5. Coverage, Lint, Typecheck & Known Gaps
- **Python**: `71 passed` (`0 failed`, `0 skipped`), **83.68%** cobertura líneas+ramas (`>= 80%`), `ruff check src tests` (0 errores), `mypy src tests --strict` (0 errores en 33 archivos).
- **Rust**: `14 passed` (`0 failed`, `0 skipped`), compilación `debug` y `release` con `#![deny(warnings)]`, `unwrap_used = "deny"`, `expect_used = "deny"` y `0` bloques `unsafe`.
- **Known Gaps**:
  - `TesseractOcrEngine` y `SpacyNerEngine` son adaptadores opcionales (el host usa `RapidOcrEngine` ONNX incluido y `HeuristicSpanishNerEngine` 100% offline).
  - `cargo-clippy` no está instalado en este sistema Fedora, por lo que los lints del compilador se aplican con `#![deny(warnings)]` en todos los crates/binarios.
