# goth: Lightweight Authorization Proxy

**Project Status: Experimental / Work in Progress**

This project is in early development. It is not production-ready, and breaking changes are likely. Use at your own risk.

## Overview


**goth** is a simple authorization proxy for learning, prototyping, and experimentation. It supports JWT validation, basic access control, and integration with OIDC/OAuth2 providers. The codebase is evolving and not feature-complete.

## Features (Current)

- JWT validation and basic access control
- OIDC/OAuth2 provider integration
- Access logging
- Configuration via environment variables or CLI flags
- Dockerfile and Docker Compose for local testing

## Getting Started

### Prerequisites

- Go 1.18+
- Docker & Docker Compose
- `golangci-lint` (for linting)

### Quick Start

Clone the repository and use the provided Makefile:

```sh
git clone https://github.com/praserx/goth.git
cd goth
make build
```

### Build & Test

- **Style Check:** `make style`
- **Lint:** `make lint`
- **Unit Tests:** `make test`
- **Build Binary:** `make build` (outputs to `bin/`)
- **End-to-End Test:** `make test-e2e` (runs full stack with Docker Compose)

## Documentation

- [Configuration Guide](docs/configuration.md) *(coming soon)*
- [Architecture Overview](docs/architecture.md) *(coming soon)*
- [Contributing](CONTRIBUTING.md) *(coming soon)*

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Project Status

This project is under active development. It is not stable, not recommended for production, and APIs/configuration may change at any time. Feedback and contributions are welcome, but please expect rapid iteration and breaking changes.
