# Copyright (c) OpenBao a Series of LF Projects, LLC
# SPDX-License-Identifier: MPL-2.0

# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /build

# Install protoc and protoc-gen-go plugins
RUN apk add --no-cache protobuf-dev git

# Install protoc-gen-go and protoc-gen-go-grpc
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Copy proto files and generate code
COPY proto/ ./proto/
RUN mkdir -p proto && \
    protoc --go_out=. --go_opt=paths=source_relative \
           --go-grpc_out=. --go-grpc_opt=paths=source_relative \
           proto/certservice.proto

# Copy server source
COPY server/ ./server/

# Download dependencies
WORKDIR /build/server
RUN go mod download
RUN go mod tidy

# Build server binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /server .

# Runtime stage
FROM alpine:3.22

RUN apk add --no-cache ca-certificates

COPY --from=builder /server /server

EXPOSE 50051

ENTRYPOINT ["/server"]
