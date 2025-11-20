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

# Create data directory
RUN mkdir -p /openbao/data

WORKDIR /openbao

# Expose OpenBao port
EXPOSE 8200

# Default command runs OpenBao in dev mode
CMD ["bao", "server", "-dev", "-dev-root-token-id=root", "-dev-listen-address=0.0.0.0:8200"]
