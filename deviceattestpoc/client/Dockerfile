# Copyright (c) OpenBao a Series of LF Projects, LLC
# SPDX-License-Identifier: MPL-2.0

# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /build

# Install dependencies
RUN apk add --no-cache protobuf-dev git gcc musl-dev

# Install protoc-gen-go and protoc-gen-go-grpc
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Copy proto files and generate code
COPY proto/ ./proto/
RUN mkdir -p proto && \
    protoc --go_out=. --go_opt=paths=source_relative \
           --go-grpc_out=. --go-grpc_opt=paths=source_relative \
           proto/certservice.proto

# Copy client source
COPY client/ ./client/

# Download dependencies
WORKDIR /build/client
RUN go mod download
RUN go mod tidy

# Build client binary
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
