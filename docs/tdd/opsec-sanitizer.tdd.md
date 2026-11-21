# TDD Evidence Report: Sanitizador de Filtraciones y Metadatos (OPSEC)

## 1. Source Plan
- Plan aprobado: `/home/malik/.gemini/antigravity/brain/63498088-cb19-46ef-af7d-2da22645f184/opsec_sanitizer_tdd_plan.md`
- Arquitectura seleccionada: **Opción A — Python 3.12+ Modular (Puertos y Adaptadores, 100% Offline, Fail-Closed)**
- Repositorio: `/home/malik/.gemini/antigravity/scratch/opsec-sanitizer` (rama `master`)

## 2. User Journeys
- **UJ-1**: Periodista sanitiza PDFs filtrados con metadatos `/Author`, XMP, adjuntos, anotaciones, texto oculto bajo tachados falsos, páginas rotadas o híbridas (texto + escaneo embebido).
- **UJ-2**: Periodista sanitiza documentos `.docx` eliminando `docProps/*`, comentarios, control de cambios (`w:del`, `*PrChange`), texto oculto (`w:vanish`), relaciones externas (`TargetMode="External"`) y campos peligrosos (`INCLUDEPICTURE`/`DDE`), generando un PDF plano.
- **UJ-3**: Editor anonimiza PII mexicano (CURP con dígito verificador, RFC física/moral, correos, teléfonos) y nombres propios mediante Regex + NER offline y re-aplica OCR únicamente sobre el contenido visible seguro.
- **UJ-4**: Responsable OPSEC usa `--dry-run`, `--report-json`, `--deny-list-file` y `--redact-filenames` sin exponer PII crudo en terminal, logs ni dejar temporales en disco.
- **UJ-5**: Comportamiento *fail-closed* ante archivos corruptos, cifrados, extensiones falsificadas, *zip-bombs*, symlinks o fugas detectadas por la compuerta forense final.

## 3. Task Execution Summary (RED → GREEN Checkpoints)

| Iteración | Resumen | Checkpoint RED | Checkpoint GREEN | Comando validado |
|---|---|---|---|---|
| **1. Ingesta segura** | Validación por *magic bytes*, límites de tamaño/páginas, anti-zip-bomb y rechazo de cifrado/symlinks | `1b37fda` (`ModuleNotFoundError: opsec_sanitizer.domain`) | `8a72984` (`11 passed`) | `.venv/bin/pytest tests/unit/test_ingestion.py` |
| **2. Regex PII México** | Detectores deterministas de CURP (dígito verificador RENAPO), RFC 12/13, correos y teléfonos | `38671fe` (`ModuleNotFoundError: opsec_sanitizer.detection`) | `0089eba` (`16 passed`) | `.venv/bin/pytest tests/unit/test_regex_mx.py` |
| **3. Motor Híbrido + NER** | Fusión de spans, `allow_list`/`deny_list`, anonimización estable y NER offline en español | `9cecfc8` (`ModuleNotFoundError: detection.merger`) | `c184bd5` (`6 passed`) | `.venv/bin/pytest tests/unit/test_pii_merger.py` |
| **4. Sanitizador de Imágenes** | Reconstrucción desde píxeles RGB puros (cero EXIF/XMP/trailing bytes) y redacción opaca | `355883a` (`ModuleNotFoundError: processing`) | `2de1872` (`4 passed`) | `.venv/bin/pytest tests/integration/test_image_sanitizer.py` |
| **5. Flattening PDF** | Rasterizado sin anotaciones, redacción de píxeles y reconstrucción PDF limpia sin huellas | `dcf42fe` (`ModuleNotFoundError: pdf_flattener`) | `f8c404f` (`2 passed`) | `.venv/bin/pytest tests/integration/test_pdf_flattener.py` |
| **6. OCR + Compuerta Forense** | OCR offline (`RapidOcrEngine` ONNX + `TesseractOcrEngine`) y verificación *fail-closed* | `708727d` (`ModuleNotFoundError: verification / ocr_engine`) | `5118464` (`7 passed`) | `.venv/bin/pytest tests/unit/test_forensic_gate.py tests/integration/test_ocr_roundtrip.py` |
| **7. Sanitizador DOCX** | Limpieza XML anti-XXE/SSRF + renderizado aislado (`LibreOffice` headless / fallback puro) | `855216c` (`ModuleNotFoundError: docx_sanitizer`) | `7e212d3` (`3 passed`) | `.venv/bin/pytest tests/integration/test_docx_sanitizer.py` |
| **8. Pipeline y CLI E2E** | Staging en `/dev/shm`, escritura atómica `0o600`, CLI Typer (`sanitize`, `batch`) y reportes sin PII | `c98b342` (`ModuleNotFoundError: cli`) | `3485cbb` (`5 passed`) | `.venv/bin/pytest tests/e2e/test_cli_e2e.py` |
| **9. Hardening OPSEC & Review** | Remediación de todos los hallazgos CRITICAL/HIGH de `security-reviewer` y `code-reviewer` | `1dbf743` (`13 failed, 1 passed`) | `8a6edf4` (`68 passed`) | `.venv/bin/pytest --cov=src/opsec_sanitizer --cov-report=term-missing` |

## 4. Test Specification Matrix

| # | Garantía verificada | Archivo de prueba | Tipo | Resultado | Evidencia |
|---|---|---|---|---|---|
| 1 | Detecta PDF/DOCX/Imagen por *magic bytes*, rechaza spoofed/cifrados/symlinks/zip-bombs/páginas excesivas | `tests/unit/test_ingestion.py`, `tests/unit/test_security_hardening.py` | unit | PASS | `pytest` (11 + 1 tests) |
| 2 | Valida dígito verificador RENAPO de CURP, fechas válidas de RFC (con/sin guiones), emails y teléfonos MX | `tests/unit/test_regex_mx.py`, `tests/unit/test_security_hardening.py` | unit | PASS | `pytest` (16 + 1 tests) |
| 3 | Fusión monotónica de spans solapados, listas allow/deny y NER offline en español (incl. MAYÚSCULAS) | `tests/unit/test_pii_merger.py`, `tests/unit/test_security_hardening.py` | unit | PASS | `pytest` (6 + 2 tests) |
| 4 | Elimina EXIF/GPS/XMP/trailing bytes, compone RGBA sobre blanco y pinta cajas opacas en píxeles | `tests/integration/test_image_sanitizer.py`, `tests/unit/test_security_hardening.py` | integration | PASS | `pytest` (4 + 1 tests) |
| 5 | Destruye adjuntos, anotaciones (`annots=False`), falsos tachados, páginas rotadas, híbridas y huellas MuPDF | `tests/integration/test_pdf_flattener.py`, `tests/unit/test_security_hardening.py` | integration | PASS | `pytest` (2 + 4 tests) |
| 6 | Re-aplica OCR offline solo sobre texto visible y aborta *fail-closed* ante fugas o trailing bytes | `tests/integration/test_ocr_roundtrip.py`, `tests/unit/test_forensic_gate.py`, `tests/unit/test_security_hardening.py` | unit/int | PASS | `pytest` (1 + 6 + 2 tests) |
| 7 | Elimina `docProps`, comentarios, `w:del`, `w:vanish`, relaciones externas y campos peligrosos en DOCX | `tests/integration/test_docx_sanitizer.py`, `tests/unit/test_security_hardening.py` | integration | PASS | `pytest` (3 + 2 tests) |
| 8 | CLI no filtra PII ni nombres en logs/JSON, escribe atómicamente `0o600`, protege contra sobrescritura in-place y aísla errores en lote | `tests/e2e/test_cli_e2e.py`, `tests/unit/test_security_hardening.py` | e2e | PASS | `pytest` (5 + 1 tests) |

## 5. Coverage, Lint, Typecheck & Known Gaps
- **Tests**: `68 passed` (`0 failed`, `0 skipped`) en `10.14s`.
- **Coverage**: `84.84%` combinado líneas + ramas (`fail_under = 80%`), con `94%` en `merger.py`, `97%` en `image_sanitizer.py`, `90%` en `forensic_gate.py`, `88%` en `pdf_flattener.py`, `87%` en `regex_mx.py` y `86%` en `validator.py`.
- **Static checks**:
  - `.venv/bin/ruff check src tests` → `All checks passed!`
  - `.venv/bin/mypy src tests` (`--strict`) → `Success: no issues found in 31 source files`
- **Known Gaps (documentados explícitamente)**:
  - `TesseractOcrEngine` (en `ocr_engine.py`, 62% de cobertura del módulo) y `SpacyNerEngine` (en `ner_offline.py`) son adaptadores opcionales que no se ejecutan en este host porque el binario `tesseract` y el paquete opcional `spacy` no están instalados en el sistema; el flujo 100% offline por defecto se verifica de extremo a extremo con `RapidOcrEngine` (ONNX incluido) y `HeuristicSpanishNerEngine`.
  - El aislamiento de red a nivel de namespace del kernel (`unshare -n` / contenedor `--network=none`) para LibreOffice debe aplicarse a nivel de despliegue/OS en redacciones de alto riesgo (como complemento a la eliminación de relaciones externas ya aplicada en el XML).

## 6. Merge / Checkpoint Evidence
Rama `master` contiene la secuencia completa de checkpoints RED → GREEN desde `aaddce4` hasta `8a6edf4` (19 commits verificables con `git log --oneline`).
