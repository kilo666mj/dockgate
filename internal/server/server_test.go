package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEndpoints(t *testing.T) {
	s := New(slog.New(slog.NewTextHandler(io.Discard, nil)), "v1.2.3")
	h := s.Handler()

	tests := []struct {
		name     string
		method   string
		path     string
		ready    bool
		wantCode int
		wantBody string
	}{
		{"healthz", http.MethodGet, "/healthz", true, http.StatusOK, `"ok"`},
		{"readyz ready", http.MethodGet, "/readyz", true, http.StatusOK, `"ready"`},
		{"readyz not ready", http.MethodGet, "/readyz", false, http.StatusServiceUnavailable, `"not ready"`},
		{"version", http.MethodGet, "/version", true, http.StatusOK, `"v1.2.3"`},
		{"wrong method", http.MethodPost, "/healthz", true, http.StatusMethodNotAllowed, ""},
		{"unknown path", http.MethodGet, "/nope", true, http.StatusNotFound, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s.SetReady(tt.ready)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.path, nil))
			if rec.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantCode)
			}
			if !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Fatalf("body = %q, want it to contain %q", rec.Body.String(), tt.wantBody)
			}
		})
	}
}
