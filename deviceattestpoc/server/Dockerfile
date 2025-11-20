# Copyright (c) OpenBao a Series of LF Projects, LLC
# SPDX-License-Identifier: MPL-2.0

# Build stage - Optimized for Docker layer caching
FROM golang:1.23-alpine AS builder

WORKDIR /build

# Layer 1: Install build tools (rarely changes, cached)
RUN apk add --no-cache protobuf-dev git

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
COPY server/go.mod server/go.sum ./server/
WORKDIR /build/server
RUN go mod download

# Layer 5: Copy source and build (re-runs on every code change)
COPY server/ .
RUN CGO_ENABLED=0 GOOS=linux go build -o /server .

# Runtime stage
FROM alpine:3.22

RUN apk add --no-cache ca-certificates

COPY --from=builder /server /server

EXPOSE 50051

ENTRYPOINT ["/server"]
