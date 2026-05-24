# Multi-stage Dockerfile for blackwire.
#
# Stage 1 (builder): Compiles the Rust binary in a full Rust environment.
# Stage 2 (runtime): Copies only the compiled binary into a minimal image.
#
# The final image is ~10 MB (distroless/cc) instead of ~1 GB (full Rust image).
# This minimises the attack surface and download time.
#
# Build (linux/amd64 for Hetzner x86_64 VPS; on Apple Silicon pass --platform explicitly):
#   docker build --platform linux/amd64 -t blackwire:latest .
#
# Run:
#   docker run -v /path/to/config.json:/etc/blackwire/config.json \
#              -p 443:443 blackwire:latest

# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM rust:1.83-slim AS builder

WORKDIR /build

# Copy the workspace manifests first so that cargo can cache the dependency
# download step. If only source files change (not Cargo.toml/Cargo.lock),
# the dependency layer is reused from Docker cache, speeding up rebuilds.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/proxy-cli/Cargo.toml    crates/proxy-cli/
COPY crates/proxy-core/Cargo.toml   crates/proxy-core/
COPY crates/proxy-common/Cargo.toml crates/proxy-common/
COPY crates/proxy-config/Cargo.toml crates/proxy-config/
COPY crates/proxy-transport/Cargo.toml crates/proxy-transport/
COPY crates/proxy-protocol/Cargo.toml crates/proxy-protocol/
COPY crates/proxy-app/Cargo.toml    crates/proxy-app/
COPY crates/proxy-tls/Cargo.toml    crates/proxy-tls/
COPY crates/proxy-api/Cargo.toml    crates/proxy-api/
COPY tests/Cargo.toml               tests/

# Create stub lib/main.rs files so cargo can resolve dependencies.
# These will be replaced by the full source copy below.
RUN for d in proxy-common proxy-config proxy-app proxy-transport proxy-protocol proxy-core proxy-tls proxy-api; do \
        mkdir -p crates/$d/src && echo "// stub" > crates/$d/src/lib.rs; \
    done && \
    mkdir -p crates/proxy-cli/src && echo "fn main(){}" > crates/proxy-cli/src/main.rs

# Download and compile all dependencies (cached if Cargo.toml unchanged).
RUN cargo fetch

# Copy the full source.
COPY crates/ crates/
COPY tests/ tests/
COPY fingerprints/ fingerprints/

# Build the release binary with maximum optimisations.
RUN cargo build --release --bin blackwire

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
# debian:bookworm-slim has libc and TLS certs but no unnecessary packages.
FROM debian:bookworm-slim

# Install CA certificates for TLS outbound verification.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy only the compiled binary from the builder stage.
COPY --from=builder /build/target/release/blackwire /usr/local/bin/blackwire

# Copy GeoIP/GeoSite data files if they are present in the build context.
# These are optional — the router works without them in Phase 1-3.
COPY --from=builder /build/fingerprints/ /usr/local/share/blackwire/fingerprints/

# The config file is mounted at runtime via a Docker volume or bind mount.
# Example: docker run -v /host/config.json:/etc/blackwire/config.json blackwire
VOLUME ["/etc/blackwire"]

# Expose proxy port and metrics port.
EXPOSE 443 8080

ENTRYPOINT ["/usr/local/bin/blackwire"]
CMD ["run", "-c", "/etc/blackwire/config.json"]
