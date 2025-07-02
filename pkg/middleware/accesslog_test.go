package middleware

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/praserx/aegis/pkg/logger"
)

// mockResponseWriter is a mock implementation of http.ResponseWriter for testing.
// It supports http.Hijacker, http.Flusher, and http.Pusher interfaces.
type mockResponseWriter struct {
	http.ResponseWriter
	HijackCalled bool
	FlushCalled  bool
	PushCalled   bool
}

func (m *mockResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	m.HijackCalled = true
	return nil, nil, nil
}

func (m *mockResponseWriter) Flush() {
	m.FlushCalled = true
}

func (m *mockResponseWriter) Push(target string, opts *http.PushOptions) error {
	m.PushCalled = true
	return nil
}

func TestAccessLogMiddleware(t *testing.T) {
	t.Cleanup(logger.ResetForTesting)

	var buf bytes.Buffer
	logger.SetLogger(logger.New(logger.WithWriter(&buf), logger.WithVerbosity(1)))

	// Create a simple handler to be wrapped by the middleware.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})

	// Create the middleware and wrap the handler.
	middleware := AccessLogMiddleware()
	wrappedHandler := middleware(handler)

	// Create a test request and response recorder.
	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()

	// Serve the request.
	wrappedHandler.ServeHTTP(rr, req)

	// Check if the log contains the expected information.
	logOutput := buf.String()
	if !strings.Contains(logOutput, `"status_code":202`) {
		t.Errorf("Expected status code 202, but log was: %s", logOutput)
	}

	if !strings.Contains(logOutput, `"method":"GET"`) {
		t.Errorf("Expected method GET, but log was: %s", logOutput)
	}
}

func TestResponseWriterInterfaces(t *testing.T) {
	// Test Hijacker
	t.Run("Hijacker", func(t *testing.T) {
		mock := &mockResponseWriter{}
		rw := newResponseWriter(mock)
		rw.Hijack()
		if !mock.HijackCalled {
			t.Error("Expected Hijack to be called")
		}
	})

	// Test Flusher
	t.Run("Flusher", func(t *testing.T) {
		mock := &mockResponseWriter{}
		rw := newResponseWriter(mock)
		rw.Flush()
		if !mock.FlushCalled {
			t.Error("Expected Flush to be called")
		}
	})

	// Test Pusher
	t.Run("Pusher", func(t *testing.T) {
		mock := &mockResponseWriter{}
		rw := newResponseWriter(mock)
		rw.Push("/test", nil)
		if !mock.PushCalled {
			t.Error("Expected Push to be called")
		}
	})
}

func TestLogMessageFormat(t *testing.T) {
	t.Cleanup(logger.ResetForTesting)

	var buf bytes.Buffer
	logger.Setup(logger.WithWriter(&buf), logger.WithVerbosity(1))

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := AccessLogMiddleware()
	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("POST", "/api/v1/resource", nil)
	rr := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rr, req)

	t.Logf("Log output: %s", buf.String())

	var logEntry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &logEntry); err != nil {
		t.Fatalf("Failed to unmarshal log entry: %v", err)
	}

	// Check top-level message field
	expectedMessage := "POST /api/v1/resource - 200"
	if logEntry["message"] != expectedMessage {
		t.Errorf("Expected message '%s', got '%s'", expectedMessage, logEntry["message"])
	}
}
