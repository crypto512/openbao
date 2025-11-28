# OpenBao Dockerfile - Multi-stage build with optimized build context
# Stage 1: Build OpenBao binary from source
FROM golang:1.25.3 AS builder

WORKDIR /workspace

# Copy OpenBao source tree from parent directory
# .dockerignore excludes .git/, deviceattestpoc/, ui/ to reduce context from 1GB+ to ~50MB
COPY .. .

# Download dependencies and build OpenBao binary with CGO disabled for static linking
# Note: Can't separate go mod download due to local module replacements (./helper/stubbolt)
RUN go mod download && \
    CGO_ENABLED=0 go build -o /bao

# =============================================================================
# Stage 2: Runtime - Minimal Alpine image
# =============================================================================
FROM alpine:3.22

# Install runtime dependencies
RUN apk add --no-cache bash curl jq ca-certificates

# Copy OpenBao binary from builder
COPY --from=builder /bao /bin/bao

# Create data and config directories
RUN mkdir -p /openbao/data /openbao/config

# Create configuration file inline (avoids .dockerignore issue)
RUN cat > /openbao/config/config.hcl << 'EOF'
# OpenBao configuration for persistent mode
storage "file" {
  path = "/openbao/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

disable_mlock = true
api_addr = "http://openbao:8200"
ui = false
EOF

WORKDIR /openbao

# Expose OpenBao port
EXPOSE 8200

# Run OpenBao in server mode with config file
CMD ["bao", "server", "-config=/openbao/config/config.hcl"]
