#!/usr/bin/env bash
# Hardened air-gapped launcher for opsec-sanitizer container (Podman or Docker).
# Enforces --network=none, --read-only, --cap-drop=ALL, no-new-privileges, RAM-only tmpfs,
# read-only single-file input mount, and refuses symbolic links.

set -euo pipefail

IMAGE="${OPSEC_IMAGE:-opsec-sanitizer:airgapped}"
ENGINE="${OPSEC_ENGINE:-}"
DRY_RUN_CMD=0
DENY_LIST_FILE=""
REPORT_JSON=""
EXTRA_ARGS=()

usage() {
    cat <<'EOF' >&2
Usage: run-airgapped.sh [OPTIONS] <input_file> <output_file>

Options:
  --engine <podman|docker>   Container runtime (default: auto-detect podman then docker)
  --image <ref>              Container image tag (default: opsec-sanitizer:airgapped)
  --deny-list-file <path>    Optional newline-separated sensitive terms file (mounted :ro)
  --report-json <path>       Write OPSEC-safe audit JSON inside output directory
  --no-ocr                   Omit searchable OCR text layer on output PDF
  --paranoid-denoise         Convert pages to grayscale + median filter
  --redact-filenames         Replace filenames with SHA-256 prefixes
  --dry-run-cmd              Print the exact container command without executing
  -h, --help                 Show this help
EOF
}

POSITIONAL=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --engine)
            [[ $# -ge 2 ]] || { echo "[ERROR] --engine requires an argument" >&2; exit 1; }
            ENGINE="$2"
            shift 2
            ;;
        --image)
            [[ $# -ge 2 ]] || { echo "[ERROR] --image requires an argument" >&2; exit 1; }
            IMAGE="$2"
            shift 2
            ;;
        --deny-list-file)
            [[ $# -ge 2 ]] || { echo "[ERROR] --deny-list-file requires an argument" >&2; exit 1; }
            DENY_LIST_FILE="$2"
            shift 2
            ;;
        --report-json)
            [[ $# -ge 2 ]] || { echo "[ERROR] --report-json requires an argument" >&2; exit 1; }
            REPORT_JSON="$2"
            shift 2
            ;;
        --no-ocr|--paranoid-denoise|--redact-filenames)
            EXTRA_ARGS+=("$1")
            shift
            ;;
        --dry-run-cmd)
            DRY_RUN_CMD=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            POSITIONAL+=("$@")
            break
            ;;
        -*)
            echo "[ERROR] Unknown option: $1" >&2
            exit 1
            ;;
        *)
            POSITIONAL+=("$1")
            shift
            ;;
    esac
done

if [[ ${#POSITIONAL[@]} -ne 2 ]]; then
    usage
    exit 1
fi

INPUT_FILE="${POSITIONAL[0]}"
OUTPUT_FILE="${POSITIONAL[1]}"

if [[ -z "$ENGINE" ]]; then
    if command -v podman >/dev/null 2>&1; then
        ENGINE="podman"
    elif command -v docker >/dev/null 2>&1; then
        ENGINE="docker"
    else
        echo "[ERROR] Neither podman nor docker found on PATH" >&2
        exit 1
    fi
fi

# Strictly allowlist container engine binary name (prevent command injection)
case "$ENGINE" in
    podman|docker) ;;
    *)
        echo "[ERROR] Untrusted container engine: $ENGINE (allowed: podman, docker)" >&2
        exit 1
        ;;
esac

# Fail-closed symlink and regular-file validation on host
if [[ -L "$INPUT_FILE" ]]; then
    echo "[ERROR] Input path is a symlink (disallowed by OPSEC policy)" >&2
    exit 1
fi
if [[ ! -f "$INPUT_FILE" ]]; then
    echo "[ERROR] Input file does not exist or is not a regular file" >&2
    exit 1
fi
if [[ -L "$OUTPUT_FILE" ]]; then
    echo "[ERROR] Output path is a symlink (disallowed by OPSEC policy)" >&2
    exit 1
fi

INPUT_ABS="$(realpath --no-symlinks "$INPUT_FILE")"
OUT_DIR_RAW="$(dirname "$OUTPUT_FILE")"
OUT_NAME="$(basename "$OUTPUT_FILE")"
mkdir -p "$OUT_DIR_RAW"
OUT_DIR_ABS="$(realpath "$OUT_DIR_RAW")"

CMD=(
    "$ENGINE" run
    --rm
    --network=none
    --read-only
    --cap-drop=ALL
    --security-opt=no-new-privileges:true
    --pids-limit=256
    --memory=2g
    --tmpfs /tmp:rw,noexec,nosuid,size=256m
    --tmpfs /dev/shm:rw,noexec,nosuid,size=512m
    -v "${INPUT_ABS}:/in/document:ro"
    -v "${OUT_DIR_ABS}:/out:rw"
)

CONTAINER_ARGS=(
    sanitize /in/document
    -o "/out/${OUT_NAME}"
    --worker-bin /opt/opsec-venv/bin/opsec-sanitize-worker
    --allow-unsandboxed
)

if [[ -n "$DENY_LIST_FILE" ]]; then
    if [[ -L "$DENY_LIST_FILE" || ! -f "$DENY_LIST_FILE" ]]; then
        echo "[ERROR] Invalid or symlinked --deny-list-file" >&2
        exit 1
    fi
    DENY_ABS="$(realpath --no-symlinks "$DENY_LIST_FILE")"
    CMD+=(-v "${DENY_ABS}:/in/deny.txt:ro")
    CONTAINER_ARGS+=(--deny-list-file /in/deny.txt)
fi

if [[ -n "$REPORT_JSON" ]]; then
    REPORT_NAME="$(basename "$REPORT_JSON")"
    CONTAINER_ARGS+=(--report-json "/out/${REPORT_NAME}")
fi

if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then
    CONTAINER_ARGS+=("${EXTRA_ARGS[@]}")
fi

CMD+=("$IMAGE" "${CONTAINER_ARGS[@]}")

if [[ "$DRY_RUN_CMD" -eq 1 ]]; then
    printf '%s\n' "${CMD[*]}"
    exit 0
fi

exec "${CMD[@]}"
