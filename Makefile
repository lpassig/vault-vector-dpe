# Makefile for vault-plugin-secrets-vector-dpe
# Following HashiCorp Vault plugin conventions

PLUGIN_NAME := vault-plugin-secrets-vector-dpe
PLUGIN_DIR := ./bin
GOFLAGS := -ldflags="-s -w"

.PHONY: all build clean test lint fmt dev-register help

# Default target
all: build

# Build the plugin binary
build:
	@echo "==> Building $(PLUGIN_NAME)..."
	@mkdir -p $(PLUGIN_DIR)
	go build $(GOFLAGS) -o $(PLUGIN_DIR)/$(PLUGIN_NAME) ./cmd/$(PLUGIN_NAME)
	@echo "==> Binary: $(PLUGIN_DIR)/$(PLUGIN_NAME)"
	@shasum -a 256 $(PLUGIN_DIR)/$(PLUGIN_NAME) | cut -d' ' -f1 > $(PLUGIN_DIR)/$(PLUGIN_NAME).sha256
	@echo "==> SHA256: $$(cat $(PLUGIN_DIR)/$(PLUGIN_NAME).sha256)"

# Clean build artifacts
clean:
	@echo "==> Cleaning..."
	rm -rf $(PLUGIN_DIR)
	go clean

# Run tests
test:
	@echo "==> Running tests..."
	go test -v -race ./...

# Run linter (requires golangci-lint)
lint:
	@echo "==> Running linter..."
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run ./...

# Format code
fmt:
	@echo "==> Formatting code..."
	go fmt ./...
	goimports -w .

# Register plugin with local Vault dev server
# Requires: VAULT_ADDR and VAULT_TOKEN environment variables
dev-register: build
	@echo "==> Registering plugin with Vault..."
	@SHA256=$$(cat $(PLUGIN_DIR)/$(PLUGIN_NAME).sha256) && \
	vault plugin register -sha256=$$SHA256 -command=$(PLUGIN_NAME) secret $(PLUGIN_NAME) && \
	vault secrets enable -path=vector $(PLUGIN_NAME) || true
	@echo "==> Plugin registered at: vector/"

# Start Vault dev server with plugin directory
dev-server: build
	@echo "==> Starting Vault dev server..."
	VAULT_DEV_ROOT_TOKEN_ID=root vault server -dev -dev-plugin-dir=$(PLUGIN_DIR)

# Run validation scripts
validate: build
	@echo "==> Running validation scripts..."
	cd scripts && python3 verify_release.py

# Show help
help:
	@echo "Available targets:"
	@echo "  build        - Build the plugin binary"
	@echo "  clean        - Remove build artifacts"
	@echo "  test         - Run unit tests"
	@echo "  lint         - Run golangci-lint"
	@echo "  fmt          - Format code"
	@echo "  dev-register - Register plugin with local Vault"
	@echo "  dev-server   - Start Vault dev server with plugin"
	@echo "  validate     - Run Python validation scripts"
	@echo "  help         - Show this help message"
