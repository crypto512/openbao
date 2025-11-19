# SWTPM Dockerfile with Manufacturer CA Integration (Optimized Multi-Stage Build)
# This container provides a software TPM 2.0 with proper manufacturer EK certificates
# Optimized to reduce image size from ~1.5-2GB to ~100-200MB

# =============================================================================
# Stage 1: Builder - Build all TPM components from source
# =============================================================================
FROM alpine:3.19 AS builder

# Install build dependencies
RUN apk add --no-cache \
    # Build toolchain
    build-base \
    gcc \
    g++ \
    make \
    automake \
    autoconf \
    autoconf-archive \
    libtool \
    pkgconfig \
    git \
    curl \
    bash \
    expect \
    gawk \
    socat \
    net-tools \
    # Development libraries
    gnutls-dev \
    gnutls-utils \
    openssl-dev \
    libtasn1-dev \
    json-c-dev \
    json-glib-dev \
    curl-dev \
    libseccomp-dev \
    linux-headers \
    util-linux-dev \
    glib-dev

# Create build staging directory
RUN mkdir -p /app

# Install tpm2-tss (TPM2 Software Stack)
RUN git clone https://github.com/tpm2-software/tpm2-tss /tmp/tpm2-tss && \
    cd /tmp/tpm2-tss && \
    git checkout 4.1.3 && \
    ./bootstrap && \
    ./configure --prefix=/app && \
    make -j$(nproc) && \
    make install && \
    cd / && rm -rf /tmp/tpm2-tss

# Install tpm2-tools
ENV PKG_CONFIG_PATH="/app/lib/pkgconfig:${PKG_CONFIG_PATH}"
ENV LD_LIBRARY_PATH="/app/lib:${LD_LIBRARY_PATH}"
RUN git clone https://github.com/tpm2-software/tpm2-tools /tmp/tpm2-tools && \
    cd /tmp/tpm2-tools && \
    git checkout 5.7 && \
    ./bootstrap && \
    ./configure --prefix=/app && \
    make -j$(nproc) && \
    make install && \
    cd / && rm -rf /tmp/tpm2-tools

# Install libtpms (TPM library implementation)
RUN git clone https://github.com/stefanberger/libtpms /tmp/libtpms && \
    cd /tmp/libtpms && \
    git checkout v0.10.0 && \
    ./autogen.sh --with-tpm2 --with-openssl --prefix=/app && \
    make -j$(nproc) && \
    make install && \
    cd / && rm -rf /tmp/libtpms

# Install swtpm (Software TPM Emulator)
RUN git clone https://github.com/stefanberger/swtpm /tmp/swtpm && \
    cd /tmp/swtpm && \
    git checkout v0.10.0 && \
    ./autogen.sh --with-openssl --with-gnutls --prefix=/app && \
    make -j$(nproc) && \
    make install && \
    cd / && rm -rf /tmp/swtpm

# =============================================================================
# Stage 2: Runtime - Minimal Alpine image with only runtime dependencies
# =============================================================================
FROM alpine:3.19

# Install ONLY runtime dependencies (no build tools)
RUN apk add --no-cache \
    # Essential runtime
    bash \
    openssl \
    gnutls \
    gnutls-utils \
    libtasn1 \
    json-c \
    json-glib \
    curl \
    libseccomp \
    util-linux \
    glib \
    # Utilities needed by entrypoint script
    grep \
    coreutils \
    procps \
    socat \
    # CA certificates
    ca-certificates && \
    # Create necessary directories
    mkdir -p /app /var/lib/swtpm-localca /root/.config

# Copy compiled binaries and libraries from builder stage
COPY --from=builder /app /usr/local/

# Create library configuration for musl linker and add swtpm library path
RUN mkdir -p /etc/ld.so.conf.d && \
    echo "/usr/local/lib" >> /etc/ld-musl-x86_64.path && \
    echo "/usr/local/lib/swtpm" >> /etc/ld-musl-x86_64.path && \
    echo "/lib" >> /etc/ld-musl-x86_64.path && \
    echo "/usr/lib" >> /etc/ld-musl-x86_64.path && \
    # Create symlinks for swtpm to find its binaries and config files
    ln -s /usr/local/etc /app/etc && \
    ln -s /usr/local/bin /app/bin

# Set library path explicitly including swtpm subdirectory
ENV LD_LIBRARY_PATH="/lib:/usr/lib:/usr/local/lib:/usr/local/lib/swtpm"
ENV PATH="/usr/local/bin:/usr/local/sbin:${PATH}"

WORKDIR /app

# Copy entrypoint script and CA configuration
COPY --chmod=770 entrypoint.sh /app/
COPY swtpm-localca.conf /root/.config/swtpm-localca.conf
COPY swtpm-localca.options /root/.config/swtpm-localca.options

# Expose TPM ports
# Port 2321: TPM command/response port
# Port 2322: TPM control port
EXPOSE 2321 2322

ENTRYPOINT ["/app/entrypoint.sh"]
