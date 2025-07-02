# Copilot Instructions

This project is a web authorization proxy that allows users to access protected resources by providing valid JWT with specific claims or "on-thy-fly" using fine-grained access control. The codebase is written in Go and should use primarly standard libraries and well-known packages.

## Coding Standards

- This is a Golang project.
- Use idiomatic Go (clean, readable, commented).
- The project is an authorization proxy validating JWT claims and fine-grained policies.
- Write composable, testable functions.
- Structure code with `cmd/`, `pkg/`, and `internal/` where appropriate.
- Write unit tests with `testing` package for handlers and core logic.
- Use standard libraries where possible and reliable external libraries for JWT.
- Expose configuration via flags or environment variables.
- Ensure the code is clear enough for others to contribute easily.
- Ensure `go build ./...` and `go test ./...` pass without issues.
- Include log output with context for debugging.
- Avoid premature optimization; focus on correctness first.
- Write clear commit messages describing changes logically.
- If you are unsure about a specific implementation, ask for clarification or guidance. Do not lie.
