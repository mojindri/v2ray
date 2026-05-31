# Multi-stage Dockerfile for blackwire.
#
# Stage 1 (builder): Compiles the Rust binary in a full Rust environment.
# Stage 2 (runtime): Copies only the compiled binary into a minimal image.
#
# The final image is ~10 MB (distroless/cc) instead of ~1 GB (full Rust image).
# This minimises the attack surface and download time.
#
# Local interop (native arch):
#   docker build -t blackwire:latest .
# Hetzner x86_64 VPS:
#   docker build --platform linux/amd64 -t blackwire:latest .
# Or: make -C labs/realistic build-amd64
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
COPY crates/blackwire-cli/Cargo.toml    crates/blackwire-cli/
COPY crates/blackwire-core/Cargo.toml   crates/blackwire-core/
COPY crates/blackwire-common/Cargo.toml crates/blackwire-common/
COPY crates/blackwire-config/Cargo.toml crates/blackwire-config/
COPY crates/blackwire-transport/Cargo.toml crates/blackwire-transport/
COPY crates/blackwire-protocol/Cargo.toml crates/blackwire-protocol/
COPY crates/blackwire-app/Cargo.toml    crates/blackwire-app/
COPY crates/blackwire-tls/Cargo.toml    crates/blackwire-tls/
COPY crates/blackwire-api/Cargo.toml    crates/blackwire-api/
COPY black-ui/server/Cargo.toml     black-ui/server/
COPY tests/Cargo.toml               tests/
COPY benches/Cargo.toml             benches/
COPY benches/benches/               benches/benches/

# Create stub lib/main.rs files so cargo can resolve dependencies.
# These will be replaced by the full source copy below.
RUN for d in blackwire-common blackwire-config blackwire-app blackwire-transport blackwire-protocol blackwire-core blackwire-tls blackwire-api; do \
        mkdir -p crates/$d/src && echo "// stub" > crates/$d/src/lib.rs; \
    done && \
    mkdir -p crates/blackwire-cli/src && echo "fn main(){}" > crates/blackwire-cli/src/main.rs && \
    mkdir -p black-ui/server/src && echo "fn main(){}" > black-ui/server/src/main.rs

# Download and compile all dependencies (cached if Cargo.toml unchanged).
RUN cargo fetch

# Copy the full source.
COPY crates/ crates/
COPY tests/ tests/
COPY benches/ benches/
COPY fingerprints/ fingerprints/
COPY black-ui/server/ black-ui/server/

# Build the release binary with maximum optimisations.
RUN cargo build --release --bin blackwire

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
# debian:bookworm-slim has libc and TLS certs but no unnecessary packages.
FROM debian:bookworm-slim

# Install CA certificates for TLS outbound verification.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Copy only the compiled binary from the builder stage.
COPY --from=builder /build/target/release/blackwire /usr/local/bin/blackwire

# Copy GeoIP/GeoSite data files if they are present in the build context.
# These are optional — the router works without them.
COPY --from=builder /build/fingerprints/ /usr/local/share/blackwire/fingerprints/

# The config file is mounted at runtime via a Docker volume or bind mount.
# Example: docker run -v /host/config.json:/etc/blackwire/config.json blackwire
VOLUME ["/etc/blackwire"]

# Expose proxy port and metrics port.
EXPOSE 443 8080

ENTRYPOINT ["/usr/local/bin/blackwire"]
CMD ["run", "-c", "/etc/blackwire/config.json"]
