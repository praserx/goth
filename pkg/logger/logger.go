package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

// Logger is a singleton logger that supports JSON ECS format.
// It provides thread-safe logging with structured fields and verbosity control.
type Logger struct {
	mu        sync.Mutex  // Mutex to ensure thread-safe access
	logger    *log.Logger // Logger instance
	verbosity int         // Verbosity level
}

var instance *Logger // Singleton instance of Logger
var once sync.Once   // Ensure that the logger is initialized only once

// Options defines configuration options for the Logger.
// Writer specifies the output destination, and Verbosity controls the logging level.
type Options struct {
	Writer    io.Writer // Custom writer for the logger
	Verbosity int       // Verbosity level for logging
}

// WithWriter returns a functional option to set a custom writer for the logger.
// This allows directing logs to different destinations, such as files or standard output.
func WithWriter(writer io.Writer) func(*Options) {
	return func(opts *Options) {
		opts.Writer = writer
	}
}

// WithVerbosity returns a functional option to set the verbosity level for the logger.
// The verbosity level controls the granularity of log messages.
func WithVerbosity(level int) func(*Options) {
	return func(opts *Options) {
		opts.Verbosity = level
	}
}

// New creates a new Logger instance with the provided options.
// It initializes the logger with a custom writer and verbosity level.
// This function is intended for use in tests or when a custom logger is needed.
func New(options ...func(*Options)) *Logger {
	opts := &Options{
		Writer:    log.Writer(), // Default to the standard log writer
		Verbosity: 0,            // Default verbosity level
	}

	for _, opt := range options {
		opt(opts)
	}

	return &Logger{
		logger:    log.New(opts.Writer, "", 0), // Remove timestamp prefix
		verbosity: opts.Verbosity,
	}
}

// Setup initializes the singleton Logger instance with custom options.
// It ensures the logger is only initialized once.
// If no options are provided, it defaults to using the standard log writer
// and a verbosity level of 0.
func Setup(options ...func(*Options)) {
	once.Do(func() {
		instance = New(options...)
	})
}

// SetLogger replaces the singleton Logger instance with a custom logger.
// This is useful for testing or custom configurations.
func SetLogger(logger *Logger) {
	instance = logger
}

// GetLogger retrieves the singleton Logger instance.
// It ensures the logger is initialized before returning it.
func GetLogger() *Logger {
	Setup()
	return instance
}

// ResetForTesting resets the singleton instance and is intended for testing purposes only.
func ResetForTesting() {
	once = sync.Once{}
	instance = nil
}

// Info logs a standard informational message.
// It is safe for concurrent use.
func Info(message string) {
	GetLogger().Info(message)
}

// InfoF logs an informational message with key-value pairs.
func Infof(format string, values ...interface{}) {
	Info(fmt.Sprintf(format, values...))
}

// Infov logs an informational message with verbosity and key-value pairs.
// The verbosity level determines when the message is logged.
func Infov(v int, message string, keysAndValues ...interface{}) {
	GetLogger().Infov(v, message, keysAndValues...)
}

// Infovf logs an informational message with verbosity and formatted values.
// The verbosity level determines when the message is logged.
func Infovf(format string, v int, values ...interface{}) {
	Infov(v, fmt.Sprintf(format, values...))
}

// Warning logs a warning message.
// Warning messages are always logged, regardless of the verbosity level.
func Warning(message string) {
	GetLogger().Warning(message)
}

func Warningf(format string, values ...interface{}) {
	Warning(fmt.Sprintf(format, values...))
}

// Warningv logs a warning message with key-value pairs.
// Structured fields provide additional context for the warning.
func Warningv(message string, keysAndValues ...interface{}) {
	GetLogger().Warningv(message, keysAndValues...)
}

// Error logs an error message in JSON ECS format.
// It supports multiple errors and structured fields.
// Error messages include details about the error and are always logged.
func Error(message string, errs ...error) {
	GetLogger().Error(message, errs...)
}

func Errorf(format string, values ...interface{}) {
	// Format the error message and pass it to the Error function.
	// This allows for structured error messages with formatting.
	GetLogger().Error(fmt.Sprintf(format, values...))
}

// Fatal logs a fatal error message and exits the program.
// Fatal messages indicate serious errors that cause premature termination.
func Fatal(message string) {
	GetLogger().Fatal(message)
}

func Fatalf(format string, values ...interface{}) {
	// Format the fatal error message and pass it to the Fatal function.
	// This allows for structured fatal messages with formatting.
	GetLogger().Fatal(fmt.Sprintf(format, values...))
}

// Info logs a standard, non-verbose informational message.
func (l *Logger) Info(message string) {
	// Default to verbosity 0 for standard info messages
	if l.verbosity >= 0 {
		l.LogError("info", message, nil)
	}
}

// Infov logs an informational message with key-value pairs for a specific verbosity level.
func (l *Logger) Infov(v int, message string, keysAndValues ...interface{}) {
	if l.verbosity >= v {
		if fields := l.parseKeysAndValues(keysAndValues...); fields != nil {
			l.LogError("info", message, fields)
		}
	}
}

// Warning logs a warning message.
func (l *Logger) Warning(message string) {
	l.LogError("warning", message, nil)
}

// Warningv logs a warning message with key-value pairs.
func (l *Logger) Warningv(message string, keysAndValues ...interface{}) {
	fields := l.parseKeysAndValues(keysAndValues...)
	l.LogError("warning", message, fields)
}

// Error logs an error message with key-value pairs.
// It supports multiple errors and structured fields.
func (l *Logger) Error(message string, errs ...error) {
	// Fast path for the common case of no errors.
	if len(errs) == 0 {
		l.LogError("error", message, nil)
		return
	}

	// Optimization for the most common case: a single error.
	// This is more ECS-compliant.
	if len(errs) == 1 && errs[0] != nil {
		fields := map[string]interface{}{
			"error": map[string]interface{}{
				"message": errs[0].Error(),
			},
		}
		l.LogError("error", message, fields)
		return
	}

	// Handle the case of multiple errors.
	var errorMessages []string
	for _, e := range errs {
		if e != nil {
			errorMessages = append(errorMessages, e.Error())
		}
	}

	if len(errorMessages) > 0 {
		fields := map[string]interface{}{
			"error": map[string]interface{}{
				"messages": errorMessages,
			},
		}
		l.LogError("error", message, fields)
	} else {
		// Case where errors were passed, but all were nil.
		l.LogError("error", message, nil)
	}
}

// Fatal logs an error message and exits.
// It indicates a serious problem that the application cannot recover from.
func (l *Logger) Fatal(message string) {
	l.LogError("fatal", "fatal error", nil)
	os.Exit(1)
}

// LogAccess logs HTTP access requests in ECS format.
// It includes details like IP, port, method, path, status code, and latency.
// This provides visibility into incoming requests and their performance.
func (l *Logger) LogAccess(r *http.Request, statusCode int, latency time.Duration) {
	ip, portStr, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr // Fallback for addresses without port
	}

	source := map[string]interface{}{"ip": ip}
	if portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err == nil {
			source["port"] = port
		}
	}

	entry := map[string]interface{}{
		"@timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"log": map[string]interface{}{
			"level":  "info",
			"logger": "goth",
		},
		"message": fmt.Sprintf(`%s %s - %d`, r.Method, r.URL.Path, statusCode),
		"http": map[string]interface{}{
			"request": map[string]interface{}{
				"method": r.Method,
			},
			"response": map[string]interface{}{
				"status_code": statusCode,
			},
		},
		"url": map[string]interface{}{
			"path": r.URL.Path,
		},
		"source":     source,
		"user_agent": map[string]interface{}{"original": r.UserAgent()},
		"event": map[string]interface{}{
			"duration": latency.Nanoseconds(),
		},
	}

	l.write(entry)
}

// LogError writes a log entry with the specified level, message, and fields.
// It merges the provided fields into the log entry and writes it to the output.
func (l *Logger) LogError(level, message string, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}

	entry := map[string]interface{}{
		"@timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"log": map[string]interface{}{
			"level":  level,
			"logger": "goth",
		},
		"message": message,
	}

	// Merge the provided fields into the log entry.
	for k, v := range fields {
		entry[k] = v
	}

	l.write(entry)
}

// write marshals the log entry to JSON and writes it to the logger's output.
// It ensures thread-safe access to the logger instance.
func (l *Logger) write(entry map[string]interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	line, err := json.Marshal(entry)
	if err != nil {
		l.logger.Printf("json marshal error: %v", err)
		return
	}

	l.logger.Println(string(line))
}

// parseKeysAndValues converts alternating keys and values into a map.
// It validates keys as strings and logs errors for invalid input.
// This ensures that structured logging fields are correctly formatted.
func (l *Logger) parseKeysAndValues(keysAndValues ...interface{}) map[string]interface{} {
	if len(keysAndValues)%2 != 0 {
		// If the number of arguments is odd, something is wrong.
		// We'll log an error and return an empty map.
		l.LogError("error", "odd number of arguments provided for structured log", map[string]interface{}{"args_count": len(keysAndValues)})
		return nil
	}

	fields := make(map[string]interface{}, len(keysAndValues)/2)
	for i := 0; i < len(keysAndValues); i += 2 {
		key, ok := keysAndValues[i].(string)
		if !ok {
			// The key is not a string, which is an error.
			l.LogError("error", fmt.Sprintf("log key at position %d is not a string: %v", i, keysAndValues[i]), nil)
			continue
		}
		fields[key] = keysAndValues[i+1]
	}
	return fields
}
