# syntax=docker/dockerfile:1
# Multi-stage air-gapped OPSEC Document Sanitizer (Option C Hybrid: Rust + Python Worker)
# Build: podman build -f Containerfile -t opsec-sanitizer:airgapped .
# Run:   ./scripts/run-airgapped.sh input.pdf output.pdf

FROM docker.io/library/rust:1.86-slim-bookworm AS rust-builder

WORKDIR /build/rust
COPY rust/Cargo.toml rust/Cargo.lock ./
COPY rust/src ./src

RUN cargo build --release --locked

FROM docker.io/library/python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONNOUSERSITE=1 \
    HOME=/dev/shm \
    TMPDIR=/dev/shm \
    XDG_CONFIG_HOME=/dev/shm \
    XDG_CACHE_HOME=/dev/shm \
    PATH="/opt/opsec-venv/bin:/usr/local/bin:/usr/bin:/bin"

RUN apt-get update && apt-get install -y --no-install-recommends \
        fonts-dejavu-core \
        libgl1 \
        libglib2.0-0 \
        libreoffice-writer-nogui \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

WORKDIR /opt/opsec-sanitizer
COPY pyproject.toml ./
COPY src ./src

RUN python3 -m venv /opt/opsec-venv \
    && /opt/opsec-venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/opsec-venv/bin/pip install --no-cache-dir . \
    && rm -rf /root/.cache /tmp/*

COPY --from=rust-builder /build/rust/target/release/opsec-orchestrator /usr/local/bin/opsec-orchestrator

RUN groupadd --gid 10001 opsec \
    && useradd --uid 10001 --gid 10001 --home-dir /dev/shm --no-create-home --shell /usr/sbin/nologin opsec \
    && mkdir -p /in /out \
    && chown 10001:10001 /in /out

USER 10001:10001

ENTRYPOINT ["/usr/local/bin/opsec-orchestrator"]
CMD ["--help"]
