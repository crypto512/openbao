# Makefile for ACME Device Attestation PoC

.PHONY: help build-client build-server clean test run-docker run-server run-client-sim run-client-hw

help:
	@echo "ACME Device Attestation PoC - Make targets:"
	@echo ""
	@echo "  make build-client      - Build standalone client binary"
	@echo "  make build-server      - Build server binary"
	@echo "  make clean            - Clean built binaries"
	@echo ""
	@echo "  make run-server       - Start server infrastructure only"
	@echo "  make run-client-sim   - Run client in SIMULATION mode"
	@echo "  make run-client-hw    - Run client with HARDWARE TPM (requires sudo)"
	@echo ""
	@echo "  make run-docker       - Run full PoC in Docker (simulated TPM)"
	@echo "  make test             - Run full PoC test"
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
		golang:1.25-bullseye \
		sh -c "apt-get update -qq && apt-get install -y -qq gcc libc6-dev && go mod tidy && go build -o ../bin/tpm-acme-client ."
endif
	@echo "✓ Client binary built: bin/tpm-acme-client ($(GOOS)/$(GOARCH))"
	@echo ""
	@echo "Usage:"
	@echo "  ./bin/tpm-acme-client -help                  # Show help"
	@echo "  ./bin/tpm-acme-client -simulate              # Simulation mode"
ifeq ($(GOOS),linux)
	@echo "  sudo ./bin/tpm-acme-client                   # Hardware TPM mode"
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
	@docker-compose down -v 2>/dev/null || true
	@echo "✓ Cleaned"

# Run full PoC in Docker (simulated TPM)
run-docker:
	@echo "Starting PoC in Docker (simulated TPM mode)..."
	@docker-compose up --build

# Run only server infrastructure (for use with standalone client)
run-server:
	@echo "Starting server infrastructure..."
	@echo "Press Ctrl+C to stop when done testing"
	@docker-compose up --build openbao init server

# Run standalone client in SIMULATION mode
run-client-sim: build-client
	@echo "Running client in SIMULATION mode..."
	@echo ""
	@./bin/tpm-acme-client -simulate

# Run standalone client with HARDWARE TPM
run-client-hw: build-client
	@echo "Running client with HARDWARE TPM..."
	@echo "Note: This requires sudo for TPM device access"
	@echo ""
	@sudo ./bin/tpm-acme-client

# Test full PoC
test:
	@echo "Running PoC test..."
	@docker-compose up --build -d
	@sleep 20
	@echo ""
	@echo "=== Client logs ==="
	@docker logs cert-client 2>&1 | grep -E "(Step|✓|Error|Failed|ACME)"
	@echo ""
	@docker-compose down
	@echo "✓ Test completed"
