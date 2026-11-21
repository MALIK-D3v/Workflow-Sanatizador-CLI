# OPSEC Document Sanitizer (`opsec-sanitize`)

Herramienta CLI **100% offline y *fail-closed*** para redacciones de periodismo de investigación. Elimina metadatos ocultos, destruye capas de texto y falsos tachados mediante *flattening* irreversible, detecta y redacta datos personales mexicanos (CURP, RFC, correos, teléfonos y nombres propios) y re-aplica OCR únicamente sobre el texto visible seguro.

## Capacidades OPSEC

- **Ingesta segura**: validación por *magic bytes* (ignora extensiones falsificadas), rechazo de symlinks, PDFs cifrados, límites de tamaño/páginas y detección anti-*zip-bomb* en DOCX.
- **Limpieza estructural total**:
  - **PDF**: rasterizado sin anotaciones (`annots=False`), manejo de páginas rotadas y páginas híbridas (texto nativo + escaneos embebidos), reconstrucción desde cero sin adjuntos/XMP/JS y limpieza de huellas del generador.
  - **DOCX**: eliminación de `docProps/*`, comentarios, `w:del`, `*PrChange`, texto oculto (`w:vanish`), relaciones externas (`TargetMode="External"` anti-canary/SSRF), `w:attachedTemplate`, campos peligrosos (`INCLUDEPICTURE`/`DDE`) y `rsid*`, seguido de conversión a PDF y *flattening*.
  - **Imágenes (PNG/JPEG/TIFF/WEBP)**: composición de transparencia RGBA sobre fondo blanco, decodificación a buffer RGB puro (cero EXIF/GPS/XMP/IPTC/ICC/trailing bytes) y modo opcional `--paranoid-denoise`.
- **Detección híbrida de PII (100% offline)**: CURP con dígito verificador RENAPO, RFC (persona física/moral con y sin guiones), correos electrónicos, teléfonos mexicanos, NER offline en español y listas `--deny-list-file` / `--allow-list-file`.
- **Compuerta forense *fail-closed***: antes de entregar el archivo final (escrito atómicamente con permisos `0o600`), verifica de forma independiente ausencia de metadatos, chunks PNG anómalos, trailing bytes, tokens PDF activos y PII residual. Si falla, aborta con código de salida `2` y no entrega salida.

## Instalación local

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
```

## Uso rápido

```bash
# Sanitizar un PDF filtrado con flattening + OCR limpio + reporte JSON sin PII crudo
.venv/bin/opsec-sanitize sanitize filtracion.pdf -o limpio.pdf --report-json auditoria.json

# Modo dry-run (solo auditoría, sin escribir salida) con lista de términos sensibles en archivo
.venv/bin/opsec-sanitize sanitize filtracion.pdf --dry-run --deny-list-file terminos.txt --redact-filenames

# PDF solo imagen (sin capa de texto OCR en la salida) + filtro denoise
.venv/bin/opsec-sanitize sanitize escaneo.pdf -o limpio.pdf --no-ocr --paranoid-denoise

# Procesamiento por lotes con aislamiento de errores por archivo
.venv/bin/opsec-sanitize batch ./carpeta_entrada -o ./carpeta_limpia --report-json lote.json
```

### Códigos de salida
- `0`: Sanitización completada y aprobada por la compuerta forense.
- `1`: Error de validación, formato no soportado, o uno o más fallos en modo `batch`.
- `2`: Aborto *fail-closed* de la compuerta forense (`ForensicLeakError`).

## Verificación de calidad (TDD)

```bash
.venv/bin/pytest --cov=src/opsec_sanitizer --cov-report=term-missing
.venv/bin/ruff check src tests
.venv/bin/mypy src tests
```

Ver evidencia completa de cada ciclo RED → GREEN en `docs/tdd/opsec-sanitizer.tdd.md`.

## Recomendación de despliegue OPSEC
Para documentos DOCX de origen hostil en redacciones de alto riesgo, ejecute la herramienta dentro de un entorno aislado sin red (por ejemplo, `unshare -n` o contenedor `--network=none`) y en una máquina dedicada o Tails OS.
