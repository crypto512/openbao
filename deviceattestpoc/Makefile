# Makefile for ACME Device Attestation PoC
# Simplified wrapper around docker-compose with optimized build caching

.PHONY: help build clean run-server run-client-swtpm-iak run-client-swtpm-ak run-client-hw-iak run-client-hw-ak run-test-swtpm-ak

help:
	@echo "ACME Device Attestation PoC - Make targets:"
	@echo ""
	@echo "  make build                - Build all containers with layer caching"
	@echo "  make clean                - Clean containers and volumes"
	@echo ""
	@echo "  make run-server           - Start server infrastructure (OpenBao + gRPC + SWTPM)"
	@echo "  make run-client-swtpm-iak - Run client with SWTPM in IAK mode"
	@echo "  make run-client-swtpm-ak  - Run client with SWTPM in AK mode"
	@echo "  make run-client-hw-iak    - Run client with HARDWARE TPM in IAK mode (requires /dev/tpm0)"
	@echo "  make run-client-hw-ak     - Run client with HARDWARE TPM in AK mode (requires /dev/tpm0)"
	@echo ""
	@echo "  make run-test-swtpm-ak    - Run automated end-to-end test with SWTPM (AK mode)"
	@echo ""
	@echo "All builds use Docker layer caching for fast incremental builds."
	@echo ""

# Build all containers with layer caching
build:
	@echo "Building all containers with layer caching..."
	@docker compose build
	@echo "✓ Build complete"

# Clean containers and volumes
clean:
	@echo "Cleaning containers and volumes..."
	@docker compose down -v 2>/dev/null || true
	@echo "✓ Cleaned"

# Run server infrastructure
run-server:
	@echo "Starting server infrastructure..."
	@echo "  - OpenBao with ACME support"
	@echo "  - gRPC certificate server"
	@echo "  - Software TPM 2.0 (SWTPM)"
	@echo ""
	@docker compose up openbao init server tpm1

# Run client with SWTPM in IAK mode
run-client-swtpm-iak:
	@echo "Running client with SWTPM in IAK mode..."
	@echo "Mode: Manufacturer-provisioned IAK certificate"
	@docker compose run --rm client /client -attest-mode iak

# Run client with SWTPM in AK mode
run-client-swtpm-ak:
	@echo "Running client with SWTPM in AK mode..."
	@echo "Mode: NewAK with OpenBao-issued IAK certificate"
	@docker compose run --rm client /client -attest-mode ak

# Run client with HARDWARE TPM in IAK mode
run-client-hw-iak:
	@echo "Running client with HARDWARE TPM in IAK mode..."
	@echo "Mode: Manufacturer-provisioned IAK certificate"
	@echo "Note: Requires /dev/tpm0 and /dev/tpmrm0 devices"
	@echo ""
	@docker compose --profile hardware run --rm client-hw /client -attest-mode iak

# Run client with HARDWARE TPM in AK mode
run-client-hw-ak:
	@echo "Running client with HARDWARE TPM in AK mode..."
	@echo "Mode: NewAK with OpenBao-issued IAK certificate"
	@echo "Note: Requires /dev/tpm0 and /dev/tpmrm0 devices"
	@echo ""
	@docker compose --profile hardware run --rm client-hw /client -attest-mode ak

# Automated end-to-end test with SWTPM in AK mode
run-test-swtpm-ak:
	@echo "Running automated end-to-end test (SWTPM AK mode)..."
	@docker compose up -d
	@sleep 20
	@echo ""
	@echo "=== Client logs ==="
	@docker logs cert-client 2>&1 | grep -E "(Step|✓|Error|Failed|ACME)" || true
	@echo ""
	@docker compose down
	@echo "✓ Test completed"
