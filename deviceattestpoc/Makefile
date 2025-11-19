# Makefile for ACME Device Attestation PoC

.PHONY: help build-client build-server clean run-server run-client-swtpm-iak run-client-swtpm-ak run-client-hw-iak run-client-hw-ak run-test-swtpm-ak

help:
	@echo "ACME Device Attestation PoC - Make targets:"
	@echo ""
	@echo "  make build-client         - Build standalone client binary"
	@echo "  make build-server         - Build server binary"
	@echo "  make clean                - Clean built binaries and containers"
	@echo ""
	@echo "  make run-server           - Start server infrastructure (OpenBao + gRPC server + swtpm)"
	@echo "  make run-client-swtpm-iak - Run client with SWTPM in IAK mode"
	@echo "  make run-client-swtpm-ak  - Run client with SWTPM in AK mode"
	@echo "  make run-client-hw-iak    - Run client with HARDWARE TPM in IAK mode (requires sudo)"
	@echo "  make run-client-hw-ak     - Run client with HARDWARE TPM in AK mode (requires sudo)"
	@echo ""
	@echo "  make run-test-swtpm-ak    - Run automated end-to-end test with swtpm in AK mode"
	@echo ""

# Detect host OS and architecture
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Darwin)
	GOOS := darwin
	ifeq ($(UNAME_M),arm64)
		GOARCH := arm64
	else
		GOARCH := amd64
	endif
else ifeq ($(UNAME_S),Linux)
	GOOS := linux
	ifeq ($(UNAME_M),aarch64)
		GOARCH := arm64
	else ifeq ($(UNAME_M),arm64)
		GOARCH := arm64
	else
		GOARCH := amd64
	endif
else
	GOOS := linux
	GOARCH := amd64
endif

# Build standalone client binary using Docker (cross-compile for host OS)
build-client:
	@echo "Building standalone client binary for $(GOOS)/$(GOARCH)..."
	@mkdir -p bin
ifeq ($(GOOS),darwin)
	@echo "Cross-compiling for macOS requires osxcross toolchain..."
	@echo "Building with CGO disabled for macOS (TPM simulation only)"
	@docker run --rm \
		-v $(PWD):/workspace \
		-w /workspace/client \
		-e GOOS=$(GOOS) \
		-e GOARCH=$(GOARCH) \
		-e CGO_ENABLED=0 \
		golang:1.25 \
		sh -c "go mod tidy && go build -o ../bin/tpm-acme-client ."
	@echo "⚠️  Built without CGO - hardware TPM not supported on macOS anyway"
else
	@docker run --rm \
		-v $(PWD):/workspace \
		-w /workspace/client \
		-e GOOS=$(GOOS) \
		-e GOARCH=$(GOARCH) \
		-e CGO_ENABLED=1 \
		golang:1.25-bookworm \
		sh -c "apt-get update -qq && apt-get install -y -qq gcc libc6-dev && go mod tidy && go build -o ../bin/tpm-acme-client ."
endif
	@echo "✓ Client binary built: bin/tpm-acme-client ($(GOOS)/$(GOARCH))"
	@echo ""
	@echo "Usage:"
	@echo "  ./bin/tpm-acme-client -help                      # Show help"
ifeq ($(GOOS),linux)
	@echo "  sudo ./bin/tpm-acme-client -attest-mode iak      # Hardware TPM (IAK mode)"
	@echo "  sudo ./bin/tpm-acme-client -attest-mode ak       # Hardware TPM (AK mode)"
	@echo "  TPM2TOOLS_TCTI=swtpm:host=tpm1,port=2321 \\"
	@echo "    ./bin/tpm-acme-client -attest-mode ak          # Use swtpm from docker"
endif
	@echo ""

# Build server binary using Docker
build-server:
	@echo "Building server binary (using Docker)..."
	@mkdir -p bin
	@docker run --rm \
		-v $(PWD):/workspace \
		-w /workspace/server \
		golang:1.25-alpine \
		sh -c "go mod tidy && CGO_ENABLED=0 go build -o ../bin/tpm-acme-server ."
	@echo "✓ Server binary built: bin/tpm-acme-server"

# Clean built binaries
clean:
	@echo "Cleaning binaries..."
	@rm -rf bin/
	@docker compose down -v 2>/dev/null || true
	@echo "✓ Cleaned"

# Run only server infrastructure (for use with standalone client)
run-server:
	@echo "Starting server infrastructure..."
	@echo "This will start:"
	@echo "  - OpenBao server with ACME support"
	@echo "  - gRPC certificate server"
	@echo "  - Software TPM 2.0 (swtpm) with manufacturer CA"
	@echo ""
	@echo "Press Ctrl+C to stop when done testing"
	@echo ""
	@docker compose up --build openbao init server tpm1

# Run client with SWTPM in IAK mode (uses Docker client container)
run-client-swtpm-iak:
	@echo "Running client with SWTPM in IAK mode..."
	@echo "Note: Server infrastructure must be running (make run-server)"
	@echo "Mode: Using manufacturer-provisioned IAK certificate"
	@echo ""
	@docker compose run --rm client /client -attest-mode iak

# Run client with SWTPM in AK mode (uses Docker client container)
run-client-swtpm-ak:
	@echo "Running client with SWTPM in AK mode..."
	@echo "Note: Server infrastructure must be running (make run-server)"
	@echo "Mode: Using NewAK with OpenBao-issued IAK certificate"
	@echo ""
	@docker compose run --rm client /client -attest-mode ak

# Run standalone client with HARDWARE TPM in IAK mode
run-client-hw-iak: build-client
	@echo "Running client with HARDWARE TPM in IAK mode..."
	@echo "Note: This requires sudo for TPM device access"
	@echo "Mode: Using manufacturer-provisioned IAK certificate"
	@echo ""
	@sudo ./bin/tpm-acme-client -attest-mode iak

# Run standalone client with HARDWARE TPM in AK mode
run-client-hw-ak: build-client
	@echo "Running client with HARDWARE TPM in AK mode..."
	@echo "Note: This requires sudo for TPM device access"
	@echo "Mode: Using NewAK with OpenBao-issued IAK certificate"
	@echo ""
	@sudo ./bin/tpm-acme-client -attest-mode ak

# Automated end-to-end test with SWTPM in AK mode
run-test-swtpm-ak:
	@echo "Running automated end-to-end test with SWTPM in AK mode..."
	@docker compose up --build -d
	@sleep 20
	@echo ""
	@echo "=== Client logs ==="
	@docker logs cert-client 2>&1 | grep -E "(Step|✓|Error|Failed|ACME)"
	@echo ""
	@docker compose down
	@echo "✓ Test completed"
