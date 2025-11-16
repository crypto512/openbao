# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OpenBao is an open-source secrets management tool that provides secure storage, dynamic secrets generation, data encryption, and leasing/renewal capabilities. It's a fork maintained by the Linux Foundation under open governance principles.

**Critical Security Note**: This project has a strict Source-Available License Policy prohibiting any use of code from Business Source License 1.1 protected sources (specifically HashiCorp Vault). When implementing features, bug fixes, or CVEs for feature parity, use clean room methodology and ensure all deliverables are original.

## Build and Development Commands

### Using Docker for Development

**Recommended**: Use Docker for all build and test tasks to ensure consistent environment:

```bash
# Run Go commands in Docker container
docker run --rm -v $(pwd):/workspace -w /workspace golang:1.25.3 go mod tidy
docker run --rm -v $(pwd):/workspace -w /workspace golang:1.25.3 go test ./builtin/logical/pki

# Build using Docker
docker run --rm -v $(pwd):/workspace -w /workspace \
  -e CGO_ENABLED=0 \
  golang:1.25.3 \
  go build -o bin/bao

# Run make targets with dependencies
docker run --rm -v $(pwd):/workspace -w /workspace golang:1.25.3 make tidy-all
```

### Building OpenBao

```bash
# Build development binary (without UI)
make dev

# Build development binary (with UI)
make static-dist dev-ui

# Build release binaries
make bin

# Build Docker image for development
make docker-dev        # without UI
make docker-dev-ui     # with UI
```

The binary is output to `./bin/bao` and `$GOPATH/bin/bao`.

### Running Tests

```bash
# Run all unit tests (requires Docker)
make test

# Run tests for specific package
make test TEST=./vault

# Run acceptance tests for specific backend
make testacc TEST=./builtin/logical/pki

# Run tests with race detector
make testrace

# Run coverage report
./scripts/coverage.sh --html
```

**Test timeout defaults**: 45m for unit tests, 60m for extended tests, 120m for integration tests.

### Running a Single Test

```bash
# Run a specific test in a package
go test -v ./vault -run TestCore_HandleRequest

# Run with build tags
CGO_ENABLED=0 go test -tags='testonly' ./vault -run TestSpecificTest
```

### Code Quality

```bash
# Run linter (golangci-lint)
make lint

# Run linter on current commit only
make lint-new

# Check for deprecations
make deprecations

# Run vet
make vet

# Format code
make fmt

# Check formatting
make fmtcheck

# Run semgrep security checks
make semgrep
```

### UI Development

```bash
# Install UI dependencies
cd ui && yarn

# Run UI dev server (proxies to Vault on :8200)
cd ui && yarn start

# Run UI tests
cd ui && yarn run test

# Build UI for production
make ember-dist

# Build UI for development
make ember-dist-dev
```

The UI is an Ember.js application. See `ui/README.md` for detailed UI development instructions.

### Other Useful Commands

```bash
# Bootstrap development tools
make bootstrap

# Generate code (protobuf, etc.)
make prep

# Regenerate protobuf files
make proto

# Check for vulnerabilities
make vulncheck

# Tidy all go.mod files
make tidy-all

# Sync dependencies across modules
make sync-deps
```

## Architecture Overview

### Core Components

**vault/core.go** - Central orchestrator managing:
- Lifecycle operations (initialization, sealing/unsealing, shutdown)
- Security barrier, storage backends, mount tables, and router coordination
- High availability (HA) and leader election
- Plugin catalog management

**vault/router.go** - Request routing:
- Uses radix tree for O(k) path lookups
- Maps API paths to mounted backends (secrets engines and auth methods)
- Maintains mount UUID cache, accessor cache, and storage prefix mappings
- Handles path matching with wildcards and prefix support

**vault/mount.go & vault/auth.go** - Mount system:
- Manages mount tables for secrets engines and authentication methods
- Each mount has unique UUID, accessor, and configuration
- Supports local (non-replicated) and global mounts
- Stores mount configuration in encrypted storage at `core/mounts` and `core/auth`

**vault/barrier.go** - Security barrier:
- Wraps untrusted physical storage with AES-GCM encryption
- Manages encryption keyring for key rotation
- Only accessible after unsealing
- All data encrypted before writing to physical storage

### Plugin Architecture

**Builtin Plugins** (`helper/builtinplugins/registry.go`):
- Thread-safe singleton registry of builtin plugins
- Three types: credential backends, logical backends (secrets engines), database plugins
- Notable examples: approle, jwt/oidc, kubernetes, pki, transit, kv

**Plugin Loading** (`builtin/plugin/backend.go`):
- Lazy-loaded when first accessed
- Initially starts in "metadata mode" to retrieve special paths
- Actual plugin process starts on first real request
- Automatic reload if plugin process dies

**Plugin Communication**:
- External plugins use gRPC via HashiCorp's go-plugin framework
- Protocol version 4/5 supported
- Plugins implement `logical.Backend` interface from SDK
- SDK provides `framework.Backend` helper to simplify development

### Storage Architecture (Three Layers)

1. **Physical Storage** (`physical.Backend`):
   - Untrusted, persistent key-value store
   - Simple interface: Put, Get, Delete, List
   - No encryption at this layer
   - Implementations: Raft (`physical/raft/`), PostgreSQL (`physical/postgresql/`)

2. **Security Barrier** (`vault.SecurityBarrier`):
   - Encrypts all data with AES-GCM before writing to physical storage
   - Manages encryption keyring with rotation support
   - Must be unsealed to access

3. **Barrier View** (`vault.BarrierView`):
   - Namespaced view of barrier storage
   - Each mount gets unique prefix: `logical/{UUID}/` or `auth/{UUID}/`
   - Isolates storage between different mounts

**Storage Prefixes**:
- System: `sys/`
- Core: `core/mounts`, `core/auth`, `core/keyring`
- Logical backends: `logical/{mount-uuid}/`
- Auth backends: `auth/{mount-uuid}/`

### HTTP API Flow

1. HTTP request arrives at `http/handler.go`
2. `http/logical.go:buildLogicalRequestNoAuth()` parses HTTP to `logical.Request`
   - GET → Read, POST/PUT → Update, DELETE → Delete
   - `?list=true` → List operation
3. Request goes to `vault/request_handling.go:HandleRequest()`
4. Core looks up mount via Router
5. Backend processes request via `HandleRequest()`
6. Response converted to HTTP in `http/logical.go`

**API Path Structure**:
- All paths start with `/v1/`
- System paths: `/v1/sys/*`
- Mounted secrets: `/v1/{mount-path}/*`
- Auth methods: `/v1/auth/{mount-path}/*`

### Secrets Engine and Auth Method Structure

```
plugin-directory/
├── backend.go          # Factory and main backend struct
├── path_*.go          # Individual API endpoints
├── cmd/plugin-name/   # Standalone plugin binary (optional)
│   └── main.go
```

**Backend Implementation**:
- Implements `logical.Backend` interface
- Usually embeds `framework.Backend` for convenience
- Defines paths using `framework.Path` structs with operations (Create, Read, Update, Delete, List)
- Factory pattern: `func(context.Context, *logical.BackendConfig) (logical.Backend, error)`

## Key Directories

- **`vault/`** - Core server logic, request handling, routing, mount management, identity, tokens, policies, ACL evaluation, audit broker, seal/unseal, HA
- **`builtin/`** - Built-in plugins organized by type (credential/, logical/, plugin/)
- **`api/`** - Go client library published as `github.com/openbao/openbao/api/v2`
- **`sdk/`** - Plugin development kit published as `github.com/openbao/openbao/sdk/v2`
  - `sdk/logical/` - Core interfaces (Backend, Request, Response, Storage)
  - `sdk/framework/` - Helper framework for building backends
  - `sdk/plugin/` - Plugin communication layer
- **`physical/`** - Storage backend implementations (raft/, postgresql/)
- **`audit/`** - Audit logging with hash-based obfuscation
- **`http/`** - HTTP API layer, request parsing, response formatting
- **`command/`** - CLI commands for the `bao` binary
- **`ui/`** - Ember.js web UI application
- **`helper/`** - Shared utility packages
- **`scripts/`** - Build and development scripts

## Important Design Patterns

**Factory Pattern**: All plugins use factory functions registered in builtin registry or plugin catalog.

**Lazy Loading**: External plugins don't start until first request. Metadata loaded first, actual process spawned on demand.

**Radix Tree Routing**: Fast O(k) path lookups for mount routing and storage prefix mapping.

**View Pattern**: BarrierView provides scoped storage access. Each backend gets isolated storage namespace.

**Separation of Concerns**: HTTP layer handles protocol translation, Core handles orchestration and security, Router handles dispatching, Barrier handles encryption, Physical storage handles persistence.

**Audit Broker**: All requests/responses flow through audit system. Multiple audit backends can be enabled. Failure in audit fails the entire request.

## Development Guidelines

### Code Organization

- Keep main logic in `backend.go`
- Separate API endpoints into `path_*.go` files
- Use `framework.Backend` and `framework.Path` for new backends
- Follow existing patterns in similar plugins

### Testing

- Unit tests must pass before submitting PRs
- Use Docker-based testing for integration tests with external services
- Write acceptance tests for secret and auth method features (set `BAO_ACC=1`)
- Tests should be in `*_test.go` files alongside implementation

### Changelog

Include `changelog/<pr-number>.txt` in your PR:

```
```release-note:CATEGORY
COMPONENT: summary of change
```
```

CATEGORY: `security`, `change`, `feature`, `improvement`, or `bug`

### DCO Sign-off Required

All commits must include DCO sign-off:

```bash
git commit --signoff -m "commit message"
```

**IMPORTANT**: Generative AI code assistance (GitHub Copilot, Cursor, etc.) is prohibited for code generation in this project per DCO requirements. AI may be used for search and discussion only.

### Module Structure

This is a multi-module repository with separate `go.mod` files:
- Root module: `github.com/openbao/openbao`
- API module: `github.com/openbao/openbao/api/v2`
- SDK module: `github.com/openbao/openbao/sdk/v2`
- Auth API modules: `api/auth/{approle,jwt,kubernetes,ldap,userpass}`
- Tools module: `tools/`

Run `make sync-deps` to synchronize dependencies across modules.

## Common Workflows

### Adding a New Secrets Engine

1. Create directory in `builtin/logical/<name>/`
2. Implement `backend.go` with Factory function
3. Define paths in `path_*.go` files
4. Register in `helper/builtinplugins/registry.go`
5. Add tests in `*_test.go` files
6. Add changelog entry
7. Document in `website/content/`

### Adding a New Auth Method

1. Create directory in `builtin/credential/<name>/`
2. Follow same pattern as secrets engines
3. Register in `helper/builtinplugins/registry.go`
4. Implement token generation logic
5. Add integration tests

### Working with Storage

Use the `logical.Storage` interface provided to your backend:

```go
// Write
entry := &logical.StorageEntry{
    Key:   "mykey",
    Value: jsonData,
}
storage.Put(ctx, entry)

// Read
entry, err := storage.Get(ctx, "mykey")

// List
keys, err := storage.List(ctx, "prefix/")

// Delete
storage.Delete(ctx, "mykey")
```

Storage is automatically namespaced to your mount's prefix.

## Security Considerations

- Never log sensitive data (tokens, passwords, keys)
- Use the audit hash function for logging sensitive fields
- All data in physical storage is encrypted by the barrier
- Test with seal/unseal cycles to ensure data persistence
- Validate all user input thoroughly
- Follow principle of least privilege for capabilities
- Any missing must from the draft must be implemented.
- build require go 1.25