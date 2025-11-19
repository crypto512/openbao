# OpenBao Dockerfile - Multi-stage build
# Stage 1: Build OpenBao binary from source
FROM golang:1.25.3 AS builder

WORKDIR /workspace

# Copy entire OpenBao source tree from parent directory
COPY .. .

# Build OpenBao binary with CGO disabled for static linking
RUN CGO_ENABLED=0 go build -o /bao

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
