# OPSEC Document Sanitizer — Arquitectura Híbrida Air-Gapped (Opción C)

Herramienta CLI **100% offline, aislada con Bubblewrap y *fail-closed*** para redacciones de periodismo de investigación. Combina un **orquestador y verificador forense binario en Rust** (`opsec-orchestrator`) con un **worker Python aislado sin red** (`opsec-sanitize-worker`) para eliminar metadatos ocultos, redactar PII mexicano (CURP, RFC, correos, teléfonos y nombres propios) y aplicar *flattening* irreversible con OCR limpio.

## Arquitectura Híbrida (Defensa en Profundidad)

```text
[Documento hostil]
        │
        ▼
┌──────────────────────────────────────────────────────────┐
│ 1. Orquestador Rust (opsec-orchestrator)                 │
│    • Apertura única O_NOFOLLOW (zero-TOCTOU)             │
│    • Magic bytes, límites, anti-zip-bomb en memoria      │
│    • Staging en RAM (/dev/shm, 0o700, entrada 0o400)     │
└───────────────────────────┬──────────────────────────────┘
                            │ IPC JSON v1 (stdin / OS FD 1 aislado)
                            ▼
┌──────────────────────────────────────────────────────────┐
│ 2. Sandbox Linux Bubblewrap (bwrap)                      │
│    • --unshare-all --new-session --cap-drop ALL          │
│    • SIN red, SIN /run (sockets D-Bus/SSH), SIN $HOME    │
│    • Allowlist RO mínima + SOLO staging dir escribible   │
│    • Worker Python: PDF/DOCX/IMG + Regex/NER + OCR ONNX  │
└───────────────────────────┬──────────────────────────────┘
                            │ Archivo staged (O_NOFOLLOW, nlink==1)
                            ▼
┌──────────────────────────────────────────────────────────┐
│ 3. Verificador Forense Binario Independiente (Rust)      │
│    • PDF: 1 %%EOF, 0 trailing, sin /ObjStm ni /JS/#XX,   │
│      sin MuPDF banner, descompresión FlateDecode         │
│    • PNG: IHDR(13) -> IDAT -> IEND(0) + CRC-32 exacto    │
│    • Aborto fail-closed (exit 2) si falla                │
│    • Entrega atómica 0o600 con CSPRNG + fsync + rename   │
└──────────────────────────────────────────────────────────┘
```

## Compilación e instalación local

```bash
# 1. Entorno Python (worker de análisis/NER/OCR/flattening)
python3 -m venv .venv
.venv/bin/pip install -e .

# 2. Orquestador y verificador binario en Rust (release)
cargo build --release --manifest-path rust/Cargo.toml
```

## Uso recomendado (Orquestador Rust + Sandbox Bubblewrap)

```bash
# Sanitizar un PDF/DOCX/imagen dentro del sandbox Bubblewrap sin red
./rust/target/release/opsec-orchestrator sanitize filtracion.pdf -o limpio.pdf \
  --deny-list-file terminos.txt \
  --redact-filenames \
  --report-json auditoria.json

# Modo dry-run (solo auditoría sin escribir salida)
./rust/target/release/opsec-orchestrator sanitize filtracion.pdf --dry-run

# PDF solo imagen (sin capa de texto OCR en salida) + filtro denoise
./rust/target/release/opsec-orchestrator sanitize escaneo.pdf -o limpio.pdf \
  --no-ocr --paranoid-denoise

# Procesamiento por lotes con aislamiento de errores por archivo
./rust/target/release/opsec-orchestrator batch ./carpeta_entrada -o ./carpeta_limpia \
  --report-json lote.json
```

> También sigue disponible el CLI directo de Python (`.venv/bin/opsec-sanitize`), aunque para documentos de origen hostil en redacciones se recomienda siempre usar `opsec-orchestrator` con aislamiento Bubblewrap.

### Códigos de salida
- `0`: Sanitización completada y aprobada por ambos verificadores forenses (Python + Rust independiente).
- `1`: Error de validación, formato no soportado, sandbox no disponible o fallo en lote.
- `2`: Aborto *fail-closed* por detección de fuga residual (`ForensicLeak`).

## Verificación de pruebas (85 pruebas totales)

```bash
# Suite Rust (ingesta, verificador binario, aislamiento Bubblewrap y E2E híbrido)
cargo test --manifest-path rust/Cargo.toml

# Suite Python (unit, integration, E2E + cobertura >= 80%, lint y strict types)
.venv/bin/pytest --cov=src/opsec_sanitizer --cov-report=term-missing
.venv/bin/ruff check src tests
.venv/bin/mypy src tests
```

Ver evidencia completa de cada ciclo TDD (RED → GREEN) en `docs/tdd/opsec-sanitizer.tdd.md`.
