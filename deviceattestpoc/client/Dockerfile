# Copyright (c) OpenBao a Series of LF Projects, LLC
# SPDX-License-Identifier: MPL-2.0

# Build stage - Optimized for Docker layer caching
FROM golang:1.23-alpine AS builder

WORKDIR /build

# Layer 1: Install build tools (rarely changes, cached)
RUN apk add --no-cache protobuf-dev git gcc musl-dev

# Layer 2: Install Go code generators (rarely changes, cached)
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Layer 3: Generate proto code (only re-runs if proto files change)
COPY proto/ ./proto/
RUN mkdir -p proto && \
    protoc --go_out=. --go_opt=paths=source_relative \
           --go-grpc_out=. --go-grpc_opt=paths=source_relative \
           proto/certservice.proto

# Layer 4: Download Go dependencies (only re-runs if go.mod changes)
COPY client/go.mod client/go.sum ./client/
WORKDIR /build/client
RUN go mod download

# Layer 5: Copy source and build (re-runs on every code change)
COPY client/ .
RUN CGO_ENABLED=1 GOOS=linux go build -o /client .

# Runtime stage
FROM alpine:3.22

# Install runtime dependencies
RUN apk add --no-cache ca-certificates libc6-compat socat

# Create directories
RUN mkdir -p /certs

# Copy client binary and entrypoint
COPY --from=builder /client /client
COPY --chmod=755 client/entrypoint.sh /entrypoint.sh

WORKDIR /

# Use entrypoint to set up socat proxy for swtpm
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/client"]
