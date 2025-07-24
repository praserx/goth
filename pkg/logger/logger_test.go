package logger

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLoggerSingleton(t *testing.T) {
	Setup(WithWriter(&bytes.Buffer{})) // Initialize logger with buffer
	logger1 := GetLogger()
	logger2 := GetLogger()

	if logger1 != logger2 {
		t.Errorf("Expected singleton instance, got different instances")
	}
}

func TestLoggerInfo(t *testing.T) {
	var buf bytes.Buffer
	logger := New(WithWriter(&buf), WithVerbosity(1))

	logger.Info("test info message")

	output := buf.String()
	if !strings.Contains(output, "test info message") {
		t.Errorf("Expected log output to contain 'test info message', got %s", output)
	}
}

func TestLoggerInfoVerbosity(t *testing.T) {
	var buf bytes.Buffer
	logger := New(WithWriter(&buf), WithVerbosity(0))

	logger.Infov(1, "should not log this") // v=1 > logger verbosity=0

	output := buf.String()
	if output != "" {
		t.Errorf("Expected no log output for higher verbosity, got %s", output)
	}

	logger.Infov(0, "should log this") // v=0 == logger verbosity=0
	output = buf.String()
	if !strings.Contains(output, "should log this") {
		t.Errorf("Expected log output to contain 'should log this', got %s", output)
	}
}

func TestLoggerWarning(t *testing.T) {
	var buf bytes.Buffer
	logger := New(WithWriter(&buf), WithVerbosity(1))

	logger.Warning("test warning message")

	output := buf.String()
	if !strings.Contains(output, "test warning message") {
		t.Errorf("Expected log output to contain 'test warning message', got %s", output)
	}
}

func TestLoggerError(t *testing.T) {
	var buf bytes.Buffer
	logger := New(WithWriter(&buf), WithVerbosity(1))

	logger.Error("test error message", nil)

	output := buf.String()
	if !strings.Contains(output, "test error message") {
		t.Errorf("Expected log output to contain 'test error message', got %s", output)
	}
}

func TestLoggerAccess(t *testing.T) {
	var buf bytes.Buffer
	logger := New(WithWriter(&buf))

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	req.Header.Set("User-Agent", "go-test")

	logger.LogAccess(req, http.StatusOK, 100*time.Millisecond)

	output := buf.String()

	var logEntry map[string]interface{}
	if err := json.Unmarshal([]byte(output), &logEntry); err != nil {
		t.Fatalf("Failed to unmarshal log entry: %v", err)
	}

	// Check nested http.response.status_code
	httpVal, ok := logEntry["http"].(map[string]interface{})
	if !ok {
		t.Fatal("Log entry missing 'http' field")
	}
	respVal, ok := httpVal["response"].(map[string]interface{})
	if !ok {
		t.Fatal("Log entry missing 'http.response' field")
	}
	codeVal, ok := respVal["status_code"]
	if !ok {
		t.Fatal("Log entry missing 'http.response.status_code' field")
	}
	var code int
	switch v := codeVal.(type) {
	case float64:
		code = int(v)
	case int:
		code = v
	default:
		t.Fatalf("Unexpected type for status_code: %T", v)
	}
	if code != http.StatusOK {
		t.Errorf("Expected status code %d, got %v", http.StatusOK, code)
	}

	// Check nested source.ip
	sourceVal, ok := logEntry["source"].(map[string]interface{})
	if !ok {
		t.Fatal("Log entry missing 'source' field")
	}
	ipVal, ok := sourceVal["ip"]
	if !ok {
		t.Fatal("Log entry missing 'source.ip' field")
	}
	ip, ok := ipVal.(string)
	if !ok {
		t.Fatalf("Unexpected type for source.ip: %T", ipVal)
	}
	if ip != "192.0.2.1" {
		t.Errorf("Expected source ip %s, got %s", "192.0.2.1", ip)
	}
}
