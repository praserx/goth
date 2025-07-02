// Package logger provides a singleton, structured logger for the authorization proxy.
//
// Features:
//   - JSON ECS format logging for info, warning, error, and access logs
//   - Singleton pattern with functional options for configuration
//   - Support for custom writers (for testing or integration)
//   - Verbosity support
//   - Composable, testable, and idiomatic Go API
//
// Usage:
//
//	import (
//		"os"
//		"github.com/aegis/pkg/logger"
//	)
//
//	func main() {
//		logger.Setup(logger.WithWriter(os.Stdout), logger.WithVerbosity(1))
//		logger.Info("This is a standard info message.")
//		logger.Infov("This message appears only when verbosity is 1 or higher.", 1)
//		logger.Warning("This is a warning message.")
//	}
//
// See also: pkg/logger/logger.go for implementation and pkg/logger/logger_test.go for tests.
package logger
