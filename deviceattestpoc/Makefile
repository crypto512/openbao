# Makefile for ACME Device Attestation PoC
# Device attestation tools: da-fingerprint, da-lak, da-agent, da-gen

.PHONY: help build bin clean clean-client clean-pki clean-swtpm run-server da-fingerprint da-lak da-agent da-gen

help:
	@echo "ACME Device Attestation PoC - Make targets:"
	@echo ""
	@echo "  make build                - Build all containers"
	@echo "  make bin                  - Extract binaries to ./bin/"
	@echo "  make clean                - Clean containers, volumes, and images"
	@echo ""
	@echo "Cleanup targets (with dependencies):"
	@echo "  make clean-client         - Clean client state (LAK, certs)"
	@echo "  make clean-pki            - Clean OpenBao PKI state (requires clean-client)"
	@echo "  make clean-swtpm          - Clean SWTPM state (requires clean-client)"
	@echo ""
	@echo "  make run-server           - Start server infrastructure (OpenBao + gRPC + SWTPM)"
	@echo ""
	@echo "Device Attestation Tools:"
	@echo "  make da-fingerprint       - Display permanent identifier (EK hash)"
	@echo "  make da-lak               - Provision LAK certificate"
	@echo "  make da-agent             - Provision agent certificate (ACME device-attest-01)"
	@echo "  make da-gen USAGE=<name> [OUTPUT=<dir>] - Generate usage certificate"
	@echo ""
	@echo "Examples:"
	@echo "  make da-fingerprint"
	@echo "  make da-lak"
	@echo "  make da-agent"
	@echo "  make da-gen USAGE=vpn                   # Output to ./certs/"
	@echo "  make da-gen USAGE=vpn OUTPUT=/tmp/out   # Output to /tmp/out/"
	@echo ""

# Build all containers
build:
	@echo "Building all containers..."
	@docker buildx create --name deviceattestpoc-builder --use 2>/dev/null || docker buildx use deviceattestpoc-builder
	@docker compose build
	@echo "✓ Build complete"

# Extract binaries from client container to ./bin/
bin: build
	@echo "Extracting binaries to ./bin/..."
	@mkdir -p bin
	@docker create --name da-bin-extract deviceattestpoc-client true 2>/dev/null || \
		(docker rm -f da-bin-extract 2>/dev/null && docker create --name da-bin-extract deviceattestpoc-client true)
	@docker cp da-bin-extract:/bin/da-fingerprint bin/
	@docker cp da-bin-extract:/bin/da-lak bin/
	@docker cp da-bin-extract:/bin/da-agent bin/
	@docker cp da-bin-extract:/bin/da-gen bin/
	@docker rm -f da-bin-extract
	@echo "✓ Binaries extracted:"
	@ls -la bin/da-*

# Clean containers, volumes, and images
clean:
	@echo "Cleaning containers, volumes, and images..."
	@docker compose down -v --rmi all --remove-orphans 2>/dev/null || true
	@docker buildx rm deviceattestpoc-builder 2>/dev/null || true
	@echo "✓ Cleaned"

# Clean client state (LAK, certs)
clean-client:
	@echo "Cleaning client state..."
	@docker compose rm -sf client 2>/dev/null || true
	@docker ps -a --filter "name=deviceattestpoc-client-run" -q | xargs -r docker rm -f 2>/dev/null || true
	@docker volume rm deviceattestpoc_client-da-config deviceattestpoc_client-hw-da-config deviceattestpoc_client-certs 2>/dev/null || true
	@echo "✓ Client state cleaned (LAK, certs removed)"

# Clean OpenBao PKI state (requires clean-client first)
clean-pki: clean-client
	@echo "Cleaning OpenBao PKI state..."
	@docker compose rm -sf openbao init server 2>/dev/null || true
	@docker ps -a --filter "name=deviceattestpoc-server-run" -q | xargs -r docker rm -f 2>/dev/null || true
	@docker volume rm deviceattestpoc_openbao-data deviceattestpoc_server-acme-accounts 2>/dev/null || true
	@echo "✓ PKI state cleaned (OpenBao data, ACME accounts removed)"
	@echo "  Note: SWTPM state preserved (EK unchanged)"

# Clean SWTPM state (requires clean-client first because EK changes)
clean-swtpm: clean-client
	@echo "Cleaning SWTPM state..."
	@docker compose stop tpm1 2>/dev/null || true
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
	@docker compose up openbao init server tpm1

# Display permanent identifier (EK hash)
da-fingerprint:
	@echo "Device Permanent Identifier:"
	@docker compose run --rm client /bin/da-fingerprint

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
	@ls -la $(OUTPUT)/$(USAGE)-cert.pem $(OUTPUT)/$(USAGE)-key.blob 2>/dev/null || echo "  (check $(OUTPUT) for output files)"
