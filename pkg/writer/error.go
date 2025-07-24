package writer

import (
	"fmt"
	"net/http"
	"strings"
)

// ErrorResponse writes an error response in JSON format if the request
// accepts JSON, otherwise it writes a plain text error message.
func ErrorResponse(w http.ResponseWriter, r *http.Request, status int, msg string) {
	accept := r.Header.Get("Accept")
	if accept != "" && (accept == "application/json" || accept == "*/*" || containsJSON(accept)) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprintf(w, `{"error": "%s"}`, msg)
	} else {
		http.Error(w, msg, status)
	}
}

// containsJSON checks if the Accept header contains "application/json".
func containsJSON(accept string) bool {
	return strings.Contains(accept, "application/json")
}
