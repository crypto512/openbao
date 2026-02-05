# Build stage - Rust client for device attestation
FROM rust:1.88-bookworm AS builder

WORKDIR /build

# Install build dependencies for tss-esapi and tpm2-tss
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    protobuf-compiler \
    autoconf \
    autoconf-archive \
    automake \
    libtool \
    libssl-dev \
    libcurl4-openssl-dev \
    libjson-c-dev \
    uuid-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Build and install tpm2-tss 4.1.3 (required by rust-tss-esapi main branch)
RUN git clone --depth 1 --branch 4.1.3 https://github.com/tpm2-software/tpm2-tss.git /tmp/tpm2-tss && \
    cd /tmp/tpm2-tss && \
    ./bootstrap && \
    ./configure --prefix=/usr --enable-tcti-device --enable-tcti-swtpm --enable-tcti-cmd --disable-static && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    rm -rf /tmp/tpm2-tss

# Layer 1: Create workspace and copy dependency files (for caching)
COPY client-rust/Cargo.toml client-rust/Cargo.lock ./client-rust/
COPY client-rust/da-common/Cargo.toml ./client-rust/da-common/
COPY client-rust/dar-fingerprint/Cargo.toml ./client-rust/dar-fingerprint/
COPY client-rust/dar-init/Cargo.toml ./client-rust/dar-init/
COPY client-rust/dar-lak/Cargo.toml ./client-rust/dar-lak/
COPY client-rust/dar-agent/Cargo.toml ./client-rust/dar-agent/
COPY client-rust/dar-gen/Cargo.toml ./client-rust/dar-gen/

# Copy proto files for build.rs
COPY proto/ ./proto/

# Create minimal source files to cache dependencies
RUN mkdir -p client-rust/da-common/src && \
    echo 'pub fn dummy() {}' > client-rust/da-common/src/lib.rs && \
    mkdir -p client-rust/dar-fingerprint/src && \
    echo 'fn main() {}' > client-rust/dar-fingerprint/src/main.rs && \
    mkdir -p client-rust/dar-init/src && \
    echo 'fn main() {}' > client-rust/dar-init/src/main.rs && \
    mkdir -p client-rust/dar-lak/src && \
    echo 'fn main() {}' > client-rust/dar-lak/src/main.rs && \
    mkdir -p client-rust/dar-agent/src && \
    echo 'fn main() {}' > client-rust/dar-agent/src/main.rs && \
    mkdir -p client-rust/dar-gen/src && \
    echo 'fn main() {}' > client-rust/dar-gen/src/main.rs

# Create da-common build.rs
COPY client-rust/da-common/build.rs ./client-rust/da-common/

# Layer 2: Build dependencies (cached)
WORKDIR /build/client-rust
RUN cargo build --release || true

# Layer 3: Copy actual source code
WORKDIR /build
COPY client-rust/da-common/src ./client-rust/da-common/src
COPY client-rust/dar-fingerprint/src ./client-rust/dar-fingerprint/src
COPY client-rust/dar-init/src ./client-rust/dar-init/src
COPY client-rust/dar-lak/src ./client-rust/dar-lak/src
COPY client-rust/dar-agent/src ./client-rust/dar-agent/src
COPY client-rust/dar-gen/src ./client-rust/dar-gen/src

# Touch source files to ensure rebuild
RUN find client-rust -name "*.rs" -exec touch {} \;

# Layer 4: Build all binaries
WORKDIR /build/client-rust
RUN cargo build --release

# Copy binaries to /bin
RUN cp target/release/dar-fingerprint /bin/ && \
    cp target/release/dar-init /bin/ && \
    cp target/release/dar-lak /bin/ && \
    cp target/release/dar-agent /bin/ && \
    cp target/release/dar-gen /bin/

# Final runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libcurl4 \
    libjson-c5 \
    uuid-runtime \
    socat \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Copy tpm2-tss libraries from builder stage
COPY --from=builder /usr/lib/libtss2* /usr/lib/
RUN ldconfig

# Create directories for da.json and certificates
RUN mkdir -p /certs /etc/da && chmod 755 /etc/da

# Copy binaries
COPY --from=builder /bin/dar-fingerprint /bin/dar-fingerprint
COPY --from=builder /bin/dar-init /bin/dar-init
COPY --from=builder /bin/dar-lak /bin/dar-lak
COPY --from=builder /bin/dar-agent /bin/dar-agent
COPY --from=builder /bin/dar-gen /bin/dar-gen

# Copy entrypoint for swtpm proxy setup
COPY --chmod=755 client-rust/entrypoint.sh /entrypoint.sh

WORKDIR /

# Use entrypoint to set up socat proxy for swtpm
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/bin/sh"]
