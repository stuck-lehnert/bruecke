package bruecke

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerMethodResponses(t *testing.T) {
	server := NewServer(Config{}, ServerDependencies{})
	tests := []struct {
		name    string
		handler http.HandlerFunc
		allowed string
	}{
		{"health", server.handleHealth, http.MethodGet},
		{"login", server.handleAdminLogin, http.MethodPost},
		{"logout", server.handleAdminLogout, http.MethodPost},
		{"session", server.handleAdminSession, http.MethodGet},
		{"clients", server.handleAdminClients, http.MethodGet},
		{"websocket", server.handleAdminClientsWebSocket, http.MethodGet},
		{"bootstrap", server.handleAdminWindowsBootstrap, http.MethodGet},
		{"enrollment start", server.handleEnrollStart, http.MethodPost},
		{"enrollment finish", server.handleEnrollFinish, http.MethodPost},
		{"SSH clients", server.handleAdminSSHClients, http.MethodPost},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			test.handler(response, httptest.NewRequest(http.MethodDelete, "/", nil))
			if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != test.allowed || response.Body.String() != "method not allowed\n" {
				t.Fatalf("unexpected method response: %d, %v, %q", response.Code, response.Header(), response.Body.String())
			}
		})
	}
}

func TestDecodeJSON(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
		fail bool
	}{
		{"valid", `{"password":"secret"}`, false},
		{"unknown field", `{"password":"secret","unknown":true}`, true},
		{"invalid JSON", `{"password":`, true},
		{"empty", "", true},
		{"size limit", `{"password":"` + strings.Repeat("a", maxJSONRequestBytes) + `"}`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var request adminLoginRequest
			err := decodeJSON(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", strings.NewReader(test.body)), &request)
			if (err != nil) != test.fail {
				t.Fatalf("decodeJSON error = %v, want failure = %v", err, test.fail)
			}
		})
	}
}
