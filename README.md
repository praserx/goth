

# goth: Lightweight Authorization Proxy

> **⚠️ Work in Progress:**
> 
> This project is in active development. APIs, features, and configuration may change. Not recommended for production use yet.

---

## Overview

**goth** is a lightweight, extensible authorization proxy. It provides robust JWT validation, fine-grained access control, and seamless integration with identity providers. Built for security, observability, and operational excellence.

---


## Key Features

- **Authorization Proxy**: Validates JWT claims, supports custom policies, and integrates with OIDC/OAuth2 providers.
- **Access Logging**: Context-rich logs for every request, supporting audit and compliance needs.
- **Flexible Configuration**: Configure via environment variables or CLI flags for seamless CI/CD and container workflows.
- **Container-First**: Official Dockerfile and Docker Compose for rapid deployment and testing.
- **Extensible**: Modular design for custom middleware, storage backends, and provider integrations.

---

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

---

## Documentation

- [Configuration Guide](docs/configuration.md) *(coming soon)*
- [Architecture Overview](docs/architecture.md) *(coming soon)*
- [Contributing](CONTRIBUTING.md) *(coming soon)*

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## Project Status

> **Work in Progress:**
> 
> goth is under active development. Expect breaking changes and rapid iteration. Feedback and contributions are welcome!
