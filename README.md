# aegis

Lightweight authorization proxy project.

## ⚠️ Project Status: Work in Progress ⚠️

This project is currently in its initial development phase. The code is under active development and may change significantly. It is not yet recommended for production use.

## Features

*   **Authorization Proxy**: Validates JWT claims and fine-grained policies.
*   **Access Logging**: Logs all incoming requests with contextual information.
*   **Configurable**: Exposes configuration via flags or environment variables.
*   **Containerized**: Comes with `Dockerfile` and `docker-compose` for testing.

## Getting Started

To get started with `aegis`, you can use the provided `Makefile`.

### Prerequisites

*   Go 1.18+
*   Docker & Docker Compose
*   `golangci-lint` (for linting)

### Build & Test

*   **Style Check**: `make style`
*   **Lint**: `make lint`
*   **Test**: `make test`
*   **Build**: `make build` (creates a static binary in `bin/`)
*   **End-to-End Test**: `make test-e2e` (uses Docker Compose)
