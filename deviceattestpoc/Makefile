# Makefile for ACME Device Attestation PoC
# Device attestation tools: da-init, da-fingerprint, da-lak, da-agent, da-gen
# Rust client tools: dar-init, dar-fingerprint, dar-lak, dar-agent, dar-gen

.PHONY: help build build-client build-client-rust bin bin-windows bin-rust clean clean-client clean-pki clean-swtpm run-server
.PHONY: da-init da-fingerprint da-lak da-agent da-gen
.PHONY: dar-init dar-fingerprint dar-lak dar-agent dar-gen

help:
	@echo "ACME Device Attestation PoC - Make targets:"
	@echo ""
	@echo "Build targets:"
	@echo "  make build                - Build all containers (Go + Rust clients)"
	@echo "  make build-client         - Build Go client container only"
	@echo "  make build-client-rust    - Build Rust client container only"
	@echo "  make bin                  - Extract Go binaries (Linux) to ./bin/"
	@echo "  make bin-windows          - Extract Go binaries (Windows) to ./bin/windows/"
	@echo "  make bin-rust             - Extract Rust binaries to ./bin/"
	@echo "  make clean                - Clean containers, volumes, and images"
	@echo ""
	@echo "Cleanup targets (with dependencies):"
	@echo "  make clean-client         - Clean client state (LAK, certs)"
	@echo "  make clean-pki            - Clean OpenBao PKI state (requires clean-client)"
	@echo "  make clean-swtpm          - Clean SWTPM state (requires clean-client)"
	@echo ""
	@echo "  make run-server           - Start server infrastructure (OpenBao + gRPC + SWTPM)"
	@echo ""
	@echo "Go Device Attestation Tools (da-*):"
	@echo "  make da-init              - Bootstrap device trust (--force, no SPKI check)"
	@echo "  make da-init SPKI=<pin>   - Bootstrap with SPKI pin verification (TOFU mode)"
	@echo "  make da-fingerprint       - Display TPM EK fingerprint"
	@echo "  make da-lak               - Provision LAK certificate"
	@echo "  make da-agent             - Provision agent certificate (ACME device-attest-01)"
	@echo "  make da-gen USAGE=<name> [OUTPUT=<dir>] - Generate usage certificate"
	@echo ""
	@echo "Rust Device Attestation Tools (dar-*):"
	@echo "  make dar-init             - Bootstrap device trust (--force, no SPKI check)"
	@echo "  make dar-init SPKI=<pin>  - Bootstrap with SPKI pin verification (TOFU mode)"
	@echo "  make dar-fingerprint      - Display TPM EK fingerprint"
	@echo "  make dar-lak              - Provision LAK certificate"
	@echo "  make dar-agent            - Provision agent certificate (ACME device-attest-01)"
	@echo "  make dar-gen USAGE=<name> [OUTPUT=<dir>] - Generate usage certificate"
	@echo ""
	@echo "Examples:"
	@echo "  make da-init                            # Go client, uses --force (dev/testing)"
	@echo "  make dar-init                           # Rust client, uses --force (dev/testing)"
	@echo "  make da-init SPKI=sha256//abc123...     # Go client with TOFU mode"
	@echo "  make dar-init SPKI=sha256//abc123...    # Rust client with TOFU mode"
	@echo "  make da-fingerprint                     # Go client"
	@echo "  make dar-fingerprint                    # Rust client"
	@echo "  make da-gen USAGE=vpn                   # Go client, output to ./certs/"
	@echo "  make dar-gen USAGE=vpn                  # Rust client, output to ./certs/"
	@echo ""

# Build all containers
build:
	@echo "Building all containers..."
	@docker buildx create --name deviceattestpoc-builder --use 2>/dev/null || docker buildx use deviceattestpoc-builder
	@docker compose build
	@echo "✓ Build complete"

# Build Go client container only
build-client:
	@echo "Building Go client container..."
	@docker buildx create --name deviceattestpoc-builder --use 2>/dev/null || docker buildx use deviceattestpoc-builder
	@docker compose build client
	@echo "✓ Go client build complete"

# Build Rust client container only
build-client-rust:
	@echo "Building Rust client container..."
	@docker buildx create --name deviceattestpoc-builder --use 2>/dev/null || docker buildx use deviceattestpoc-builder
	@docker compose build client-rust
	@echo "✓ Rust client build complete"

# Extract Go binaries from client container to ./bin/
bin: build-client
	@echo "Extracting Go binaries to ./bin/..."
	@mkdir -p bin
	@docker create --name da-bin-extract deviceattestpoc-client true 2>/dev/null || \
		(docker rm -f da-bin-extract 2>/dev/null && docker create --name da-bin-extract deviceattestpoc-client true)
	@docker cp da-bin-extract:/bin/da-init bin/
	@docker cp da-bin-extract:/bin/da-fingerprint bin/
	@docker cp da-bin-extract:/bin/da-lak bin/
	@docker cp da-bin-extract:/bin/da-agent bin/
	@docker cp da-bin-extract:/bin/da-gen bin/
	@docker rm -f da-bin-extract
	@echo "✓ Go binaries extracted:"
	@ls -la bin/da-*

# Extract Rust binaries from client-rust container to ./bin/
bin-rust: build-client-rust
	@echo "Extracting Rust binaries to ./bin/..."
	@mkdir -p bin
	@docker create --name dar-bin-extract deviceattestpoc-client-rust true 2>/dev/null || \
		(docker rm -f dar-bin-extract 2>/dev/null && docker create --name dar-bin-extract deviceattestpoc-client-rust true)
	@docker cp dar-bin-extract:/bin/dar-init bin/
	@docker cp dar-bin-extract:/bin/dar-fingerprint bin/
	@docker cp dar-bin-extract:/bin/dar-lak bin/
	@docker cp dar-bin-extract:/bin/dar-agent bin/
	@docker cp dar-bin-extract:/bin/dar-gen bin/
	@docker rm -f dar-bin-extract
	@echo "✓ Rust binaries extracted:"
	@ls -la bin/dar-*

# Extract Windows Go binaries from client container to ./bin/windows/
bin-windows: build-client
	@echo "Extracting Windows Go binaries to ./bin/windows/..."
	@mkdir -p bin/windows
	@docker create --name da-bin-extract-win deviceattestpoc-client true 2>/dev/null || \
		(docker rm -f da-bin-extract-win 2>/dev/null && docker create --name da-bin-extract-win deviceattestpoc-client true)
	@docker cp da-bin-extract-win:/bin/windows/da-init.exe bin/windows/
	@docker cp da-bin-extract-win:/bin/windows/da-fingerprint.exe bin/windows/
	@docker cp da-bin-extract-win:/bin/windows/da-lak.exe bin/windows/
	@docker cp da-bin-extract-win:/bin/windows/da-agent.exe bin/windows/
	@docker cp da-bin-extract-win:/bin/windows/da-gen.exe bin/windows/
	@docker rm -f da-bin-extract-win
	@echo "✓ Windows binaries extracted:"
	@ls -la bin/windows/da-*.exe

# Clean containers, volumes, and images
clean:
	@echo "Cleaning containers, volumes, and images..."
	@docker compose down -v --rmi all --remove-orphans 2>/dev/null || true
	@docker buildx rm deviceattestpoc-builder 2>/dev/null || true
	@echo "✓ Cleaned"

# Clean client state (LAK, certs) - includes Go and Rust clients
clean-client:
	@echo "Cleaning client state..."
	@docker compose rm -sf client client-rust 2>/dev/null || true
	@docker ps -a --filter "name=deviceattestpoc-client-run" -q | xargs -r docker rm -f 2>/dev/null || true
	@docker ps -a --filter "name=deviceattestpoc-client-rust-run" -q | xargs -r docker rm -f 2>/dev/null || true
	@docker volume rm deviceattestpoc_client-da-config deviceattestpoc_client-hw-da-config deviceattestpoc_client-certs 2>/dev/null || true
	@echo "✓ Client state cleaned (LAK, certs removed)"

# Clean OpenBao PKI state (requires clean-client first)
clean-pki: clean-client
	@echo "Cleaning OpenBao PKI state..."
	@docker compose rm -sf openbao init server 2>/dev/null || true
	@docker ps -a --filter "name=deviceattestpoc-server-run" -q | xargs -r docker rm -f 2>/dev/null || true
	@docker volume rm deviceattestpoc_openbao-data deviceattestpoc_server-db 2>/dev/null || true
	@echo "✓ PKI state cleaned (OpenBao data, server DB removed)"
	@echo "  Note: SWTPM state preserved (EK unchanged)"

# Clean SWTPM state (requires clean-client first because EK changes)
clean-swtpm: clean-client
	@echo "Cleaning SWTPM state..."
	@docker compose rm -sf tpm1 2>/dev/null || true
	@docker volume rm deviceattestpoc_swtpm-state 2>/dev/null || true
	@echo "✓ SWTPM state cleaned (EK certificates will be regenerated)"
	@echo "  Note: Client state also cleaned (EK hash changes)"

# Run server infrastructure
run-server:
	@echo "Starting server infrastructure..."
	@echo "  - OpenBao with ACME support"
	@echo "  - gRPC certificate server"
	@echo "  - Software TPM 2.0 (SWTPM)"
	@echo ""
	@echo "Watch for the SPKI Pin in the server logs!"
	@echo ""
	@docker compose up openbao init server tpm1

# Bootstrap device trust
# Usage:
#   make da-init                     # Force mode (no SPKI verification, dev/testing)
#   make da-init SPKI=sha256//...    # TOFU mode with SPKI pin verification
SPKI ?=

da-init:
ifdef SPKI
	@echo "Bootstrapping device trust (TOFU mode with SPKI verification)..."
	@docker compose up -d openbao init server tpm1
	@sleep 3
	@docker compose run --rm client /bin/da-init server:50051 $(SPKI)
else
	@echo "Bootstrapping device trust (--force mode)..."
	@docker compose up -d openbao init server tpm1
	@sleep 3
	@docker compose run --rm client /bin/da-init --force server:50051
endif
	@echo "✓ Device initialized"

# Display TPM EK fingerprint
da-fingerprint:
	@echo "Reading TPM EK fingerprint..."
	@docker compose up -d tpm1
	@sleep 2
	@docker compose run --rm client /bin/da-fingerprint
	@echo ""

# Provision LAK certificate
da-lak:
	@echo "Provisioning LAK certificate..."
	@docker compose up -d openbao init server tpm1
	@sleep 3
	@docker compose run --rm client /bin/da-lak
	@echo "✓ LAK provisioned"

# Provision agent certificate via ACME device-attest-01
da-agent:
	@echo "Provisioning agent certificate..."
	@docker compose up -d openbao init server tpm1
	@sleep 3
	@docker compose run --rm client /bin/da-agent
	@echo "✓ Agent certificate provisioned"

# Generate usage certificate via mTLS
# Usage: make da-gen USAGE=vpn [OUTPUT=./certs]
OUTPUT ?= ./certs

da-gen:
ifndef USAGE
	$(error USAGE is required. Example: make da-gen USAGE=vpn)
endif
	@echo "Generating certificate for usage=$(USAGE)..."
	@mkdir -p $(OUTPUT)
	@docker compose up -d openbao init server tpm1
	@sleep 3
	@docker compose run --rm -v $(abspath $(OUTPUT)):/output client /bin/da-gen --usage $(USAGE) --output /output
	@echo ""
	@echo "✓ Certificate generated:"
	@ls -la $(OUTPUT)/$(USAGE)-cert.pem $(OUTPUT)/$(USAGE)-key.pem 2>/dev/null || echo "  (check $(OUTPUT) for output files)"

# ============================================================================
# Rust Client Tools (dar-*)
# ============================================================================

# Bootstrap device trust (Rust client)
# Usage:
#   make dar-init                     # Force mode (no SPKI verification, dev/testing)
#   make dar-init SPKI=sha256//...    # TOFU mode with SPKI pin verification
dar-init:
ifdef SPKI
	@echo "Bootstrapping device trust (Rust, TOFU mode with SPKI verification)..."
	@docker compose up -d openbao init server tpm1
	@sleep 3
	@docker compose run --rm client-rust /bin/dar-init server:50051 $(SPKI)
else
	@echo "Bootstrapping device trust (Rust, --force mode)..."
	@docker compose up -d openbao init server tpm1
	@sleep 3
	@docker compose run --rm client-rust /bin/dar-init --force server:50051
endif
	@echo "✓ Device initialized (Rust)"

# Display TPM EK fingerprint (Rust client)
dar-fingerprint:
	@echo "Reading TPM EK fingerprint (Rust)..."
	@docker compose up -d tpm1
	@sleep 2
	@docker compose run --rm client-rust /bin/dar-fingerprint
	@echo ""

# Provision LAK certificate (Rust client)
dar-lak:
	@echo "Provisioning LAK certificate (Rust)..."
	@docker compose up -d openbao init server tpm1
	@sleep 3
	@docker compose run --rm client-rust /bin/dar-lak
	@echo "✓ LAK provisioned (Rust)"

# Provision agent certificate via ACME device-attest-01 (Rust client)
dar-agent:
	@echo "Provisioning agent certificate (Rust)..."
	@docker compose up -d openbao init server tpm1
	@sleep 3
	@docker compose run --rm client-rust /bin/dar-agent
	@echo "✓ Agent certificate provisioned (Rust)"

# Generate usage certificate via mTLS (Rust client)
# Usage: make dar-gen USAGE=vpn [OUTPUT=./certs]
dar-gen:
ifndef USAGE
	$(error USAGE is required. Example: make dar-gen USAGE=vpn)
endif
	@echo "Generating certificate for usage=$(USAGE) (Rust)..."
	@mkdir -p $(OUTPUT)
	@docker compose up -d openbao init server tpm1
	@sleep 3
	@docker compose run --rm -v $(abspath $(OUTPUT)):/output client-rust /bin/dar-gen --usage $(USAGE) --output /output
	@echo ""
	@echo "✓ Certificate generated (Rust):"
	@ls -la $(OUTPUT)/$(USAGE)-cert.pem $(OUTPUT)/$(USAGE)-key.pem 2>/dev/null || echo "  (check $(OUTPUT) for output files)"
