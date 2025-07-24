# Makefile for the Goth project

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test

# Go paths - this makes the Makefile more robust
GOPATH ?= $(shell go env GOPATH)
GOBIN  ?= $(GOPATH)/bin

# Tools
# Use go install to add tools to your GOBIN path
GOLINT ?= $(GOBIN)/golangci-lint
GOFMT ?= gofmt

# Prepend GOBIN to the PATH for make commands
export PATH := $(GOBIN):$(PATH)

# Directories
BIN_DIR := ./bin
CMD_DIR := ./cmd
PKG_DIR := ./pkg
TEST_DIR := ./tests

# Application name
APP_NAME := goth

# Default target: runs style checks, linting, tests, and then builds the application.
.PHONY: all
all: style lint test build

# Help: displays help for the Makefile.
.PHONY: help
help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Run all checks, tests, and build the application (default)"
	@echo "  style      - Check code style with gofmt"
	@echo "  lint       - Lint the code with golangci-lint"
	@echo "  test       - Run unit tests"
	@echo "  test-e2e   - Start the end-to-end test environment with Docker Compose"
	@echo "  test-e2e-down - Stop the end-to-end test environment"
	@echo "  test-e2e-logs - View logs from the test environment"
	@echo "  build      - Build the application"
	@echo "  clean      - Clean up build artifacts"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "To install golangci-lint, run:"
	@echo "  go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"

# Style: checks the code style using gofmt.
.PHONY: style
style:
	@echo "Checking code style..."
	@$(GOFMT) -l -w .

# Lint: lints the code using golangci-lint.
.PHONY: lint
lint:
	@echo "Linting code..."
	@if ! command -v $(GOLINT) > /dev/null; then \
		echo "golangci-lint not found at $(GOLINT), please run: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
		exit 1; \
	fi
	@$(GOLINT) run ./...

# Test: runs unit tests for all packages.
# For verbose output, run `make test V=1`
.PHONY: test
test:
	@echo "Running unit tests..."
	@if [ "$(V)" = "1" ]; then \
		$(GOTEST) -v ./...; \
	else \
		$(GOTEST) ./...; \
	fi

# E2E Test: brings up the docker-compose environment for testing.
.PHONY: test-e2e
test-e2e: build
	@echo "Starting end-to-end test environment..."
	@sudo docker compose -f tests/docker/docker-compose.yaml up --build --force-recreate -d

# E2E Test Down: stops the docker-compose environment.
.PHONY: test-e2e-down
test-e2e-down:
	@echo "Stopping end-to-end test environment..."
	@sudo docker compose -f tests/docker/docker-compose.yaml down

# E2E Test Logs: shows logs from the docker-compose environment.
.PHONY: test-e2e-logs
test-e2e-logs:
	@echo "Showing logs from end-to-end test environment..."
	@sudo docker compose -f tests/docker/docker-compose.yaml logs -f

# Build: builds the Go application with static linking.
.PHONY: build
build:
	@echo "Building the application with static linking..."
	CGO_ENABLED=0 $(GOBUILD) -ldflags '-extldflags "-static"' -o $(BIN_DIR)/$(APP_NAME) $(CMD_DIR)/...
	CGO_ENABLED=0 $(GOBUILD) -ldflags '-extldflags "-static"' -o $(TEST_DIR)/docker/goth/bin/$(APP_NAME) $(CMD_DIR)/...

# Clean: cleans up build artifacts.
.PHONY: clean
clean:
	@echo "Cleaning up..."
	@$(GOCLEAN)
	@rm -f $(BIN_DIR)/$(APP_NAME)
