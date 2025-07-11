# Terraform SBOM Makefile
.PHONY: help build test fmt lint clean install coverage deps

# Default target
.DEFAULT_GOAL := help

# Binary name
BINARY_NAME := terraform-sbom
BUILD_DIR := .
CMD_DIR := ./cmd/terraform-sbom

# Go commands
GOCMD := go
GOBUILD := $(GOCMD) build
GOTEST := $(GOCMD) test
GOFMT := $(GOCMD) fmt
GOVET := $(GOCMD) vet
GOMOD := $(GOCMD) mod
GOINSTALL := $(GOCMD) install

# Test flags
TEST_FLAGS := -race -coverprofile=coverage.out

help: ## Display this help message
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the terraform-sbom binary
	@echo "Building $(BINARY_NAME)..."
	$(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_DIR)
	@echo "Binary built: $(BUILD_DIR)/$(BINARY_NAME)"

test: ## Run all tests with race detection and coverage
	@echo "Running tests..."
	$(GOTEST) $(TEST_FLAGS) ./...
	@echo "Tests completed. Coverage report: coverage.out"

fmt: ## Format all Go source files
	@echo "Formatting Go files..."
	$(GOFMT) ./...
	@echo "Formatting completed"

lint: ## Run linting (golangci-lint if available, otherwise go vet)
	@echo "Running linters..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		echo "Using golangci-lint..."; \
		golangci-lint run; \
	else \
		echo "golangci-lint not found, using go vet..."; \
		$(GOVET) ./...; \
	fi
	@echo "Linting completed"

clean: ## Remove build artifacts and coverage files
	@echo "Cleaning up..."
	@rm -f $(BUILD_DIR)/$(BINARY_NAME)
	@rm -f coverage.out coverage.html
	@echo "Cleanup completed"

install: build ## Install the binary to GOPATH/bin
	@echo "Installing $(BINARY_NAME)..."
	$(GOINSTALL) $(CMD_DIR)
	@echo "$(BINARY_NAME) installed"

coverage: test ## Generate and open HTML coverage report
	@echo "Generating HTML coverage report..."
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"
	@if command -v xdg-open >/dev/null 2>&1; then \
		xdg-open coverage.html; \
	elif command -v open >/dev/null 2>&1; then \
		open coverage.html; \
	else \
		echo "Open coverage.html manually to view the report"; \
	fi

deps: ## Download and tidy dependencies
	@echo "Managing dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy
	@echo "Dependencies updated"

# Validation target for CLAUDE.md requirements
validate: fmt test lint ## Run fmt, test, and lint in sequence
	@echo "All validation checks passed!"