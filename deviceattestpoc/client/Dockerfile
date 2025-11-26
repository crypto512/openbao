# Copyright (c) OpenBao a Series of LF Projects, LLC
# SPDX-License-Identifier: MPL-2.0

# Build stage - Optimized for Docker layer caching
FROM golang:1.25-alpine AS builder

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

# Layer 4: Download Go dependencies for client library
COPY client/go.mod client/go.sum ./client/
WORKDIR /build/client
RUN go mod download

# Layer 5: Copy source files
WORKDIR /build
COPY client/*.go ./client/
COPY cmd/ ./cmd/

# Build da-fingerprint (standalone - no proto dependency)
# Static build with musl for portability across Linux distributions
RUN mkdir -p /build/bin/da-fingerprint && \
    cp cmd/da-fingerprint/main.go /build/bin/da-fingerprint/ && \
    cd /build/bin/da-fingerprint && \
    go mod init da-fingerprint && \
    go mod edit -require=github.com/google/go-tpm@v0.9.7 && \
    go mod edit -require=github.com/google/go-tpm-tools@v0.4.4 && \
    go mod tidy && \
    CGO_ENABLED=1 GOOS=linux go build -ldflags='-linkmode external -extldflags "-static"' -o /bin/da-fingerprint .

# Build da-lak (needs client library + proto)
# Static build with musl for portability across Linux distributions
RUN mkdir -p /build/bin/da-lak/proto && \
    cp client/*.go /build/bin/da-lak/ && \
    cp cmd/da-lak/main.go /build/bin/da-lak/lak_main.go && \
    cp -r /build/proto/* /build/bin/da-lak/proto/ && \
    cd /build/bin/da-lak && \
    cp /build/client/go.mod . && \
    cp /build/client/go.sum . && \
    sed -i 's|=> \.\./proto|=> ./proto|g' go.mod && \
    go mod tidy && \
    CGO_ENABLED=1 GOOS=linux go build -ldflags='-linkmode external -extldflags "-static"' -o /bin/da-lak .

# Build da-gen (needs client library + proto)
# Static build with musl for portability across Linux distributions
RUN mkdir -p /build/bin/da-gen/proto && \
    cp client/*.go /build/bin/da-gen/ && \
    cp cmd/da-gen/main.go /build/bin/da-gen/gen_main.go && \
    cp -r /build/proto/* /build/bin/da-gen/proto/ && \
    cd /build/bin/da-gen && \
    cp /build/client/go.mod . && \
    cp /build/client/go.sum . && \
    sed -i 's|=> \.\./proto|=> ./proto|g' go.mod && \
    go mod tidy && \
    CGO_ENABLED=1 GOOS=linux go build -ldflags='-linkmode external -extldflags "-static"' -o /bin/da-gen .

# Runtime stage
FROM alpine:3.22

# Install runtime dependencies
RUN apk add --no-cache ca-certificates libc6-compat socat

# Create directories for da.json and certificates
RUN mkdir -p /certs /etc/da && chmod 755 /etc/da

# Copy binaries
COPY --from=builder /bin/da-fingerprint /bin/da-fingerprint
COPY --from=builder /bin/da-lak /bin/da-lak
COPY --from=builder /bin/da-gen /bin/da-gen

# Copy entrypoint for swtpm proxy setup
COPY --chmod=755 client/entrypoint.sh /entrypoint.sh

WORKDIR /

# Use entrypoint to set up socat proxy for swtpm
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/bin/sh"]
